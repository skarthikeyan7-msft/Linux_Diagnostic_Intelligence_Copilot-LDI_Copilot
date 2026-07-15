"""
Per-user local accounts - the stronger, per-user alternative to the
single shared-secret Basic Auth gate (--auth-token, still available via
backend/auth.py's BasicAuthMiddleware for simpler cases).

Design choices, and why:
- Passwords are hashed with `hashlib.scrypt` - stdlib, so this adds zero
  new dependencies. scrypt is a memory-hard KDF (deliberately expensive
  to parallelize on GPU/ASIC hardware) and is an OWASP-endorsed
  alternative to bcrypt/argon2 for exactly this use case.
- The account store is a single small JSON file
  (backend/data/users.json, gitignored via the existing `backend/data/`
  rule) - {username: {salt, hash, created_at}}. Plaintext passwords are
  never written anywhere, logged, or held longer than the single
  request that verifies them.
- Every read re-parses the file from disk (no in-process caching), so
  accounts added/removed via manage_users.py while the server is
  already running in "accounts" mode take effect immediately - no
  restart needed. (A restart *is* needed the first time you go from
  zero accounts to one, since that changes which auth mode the server
  selects at startup - see backend/app.py's main().)
- Failed logins are tracked per-username with a lockout after too many
  attempts in a short window, regardless of whether those attempts came
  from one source IP or many. A lookup for a username that doesn't
  exist still does a full (fake) hash and still counts toward that
  username's lockout, so response timing and lockout behavior don't
  leak which usernames are actually registered.
"""
import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

_SCRYPT_N = 2 ** 14  # CPU/memory cost factor - tens of ms per hash on typical hardware
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_HASH_LEN = 32

_LOCKOUT_THRESHOLD = 5            # failed attempts
_LOCKOUT_WINDOW_SECONDS = 900     # attempts older than this (15 min) no longer count toward the threshold
_LOCKOUT_DURATION_SECONDS = 900   # how long a username stays locked out once the threshold is hit


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_HASH_LEN)


class UserStore:
    """Not safe to share a single instance across independently-restarted
    processes with different lockout state expectations - lockout state
    is in-memory and per-instance by design (a brute-force attempt loses
    its progress on a server restart, which is an acceptable trade-off
    for a small internal tool)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._failed_attempts = {}  # username -> [failure timestamps within the current window]
        self._locked_until = {}     # username -> unix timestamp when the lockout lifts

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self, data: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)  # atomic on both POSIX and Windows
        try:
            self.path.chmod(0o600)  # best-effort on POSIX; harmless no-op on Windows
        except OSError:
            pass

    def count(self) -> int:
        with self._lock:
            return len(self._load())

    def list_usernames(self):
        with self._lock:
            return sorted(self._load().keys())

    def add_user(self, username: str, password: str, overwrite: bool = False):
        username = username.strip()
        if not username:
            raise ValueError("username cannot be empty")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        with self._lock:
            data = self._load()
            if username in data and not overwrite:
                raise ValueError(f"user {username!r} already exists (pass overwrite=True / --overwrite to reset their password)")
            salt = secrets.token_bytes(_SALT_BYTES)
            data[username] = {
                "salt": salt.hex(),
                "hash": _hash_password(password, salt).hex(),
                "created_at": time.time(),
            }
            self._save(data)

    def remove_user(self, username: str) -> bool:
        with self._lock:
            data = self._load()
            if username not in data:
                return False
            del data[username]
            self._save(data)
            self._failed_attempts.pop(username, None)
            self._locked_until.pop(username, None)
            return True

    def _lockout_remaining_seconds(self, username: str) -> float:
        remaining = self._locked_until.get(username, 0) - time.time()
        return max(0.0, remaining)

    def _record_failure(self, username: str):
        now = time.time()
        attempts = [t for t in self._failed_attempts.get(username, []) if now - t < _LOCKOUT_WINDOW_SECONDS]
        attempts.append(now)
        if len(attempts) >= _LOCKOUT_THRESHOLD:
            self._locked_until[username] = now + _LOCKOUT_DURATION_SECONDS
            attempts = []
        self._failed_attempts[username] = attempts

    def verify(self, username: str, password: str):
        """Returns (ok: bool, message: str). `message` is always safe to
        return to the client - it never confirms or denies whether a
        given username exists."""
        username = (username or "").strip()
        with self._lock:
            remaining = self._lockout_remaining_seconds(username)
            if remaining > 0:
                return False, f"Too many failed attempts. Try again in {int(remaining // 60) + 1} minute(s)."

            data = self._load()
            record = data.get(username)
            if record is None:
                _hash_password(password, secrets.token_bytes(_SALT_BYTES))  # constant-time-ish: always do the expensive work
                self._record_failure(username)
                return False, "Invalid username or password."

            salt = bytes.fromhex(record["salt"])
            candidate = _hash_password(password, salt)
            if secrets.compare_digest(candidate, bytes.fromhex(record["hash"])):
                self._failed_attempts.pop(username, None)
                self._locked_until.pop(username, None)
                return True, "ok"

            self._record_failure(username)
            return False, "Invalid username or password."
