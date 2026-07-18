"""
Access audit log - a lightweight, append-only record of who
authenticated to this server, how (local account vs. Microsoft Entra ID
SSO), and whether it succeeded - so a team lead/admin sharing one
instance can answer "who has been using this, and did anyone try (and
fail) to get in" (see README.md's "Sharing with a team over the
internet" and SECURITY.md).

Every login attempt - success or failure, local account or Entra ID -
plus logout, is recorded as one JSON line to backend/data/audit.log
(gitignored, same as users.json): human-readable, grep-able, and
trivially parseable by any log-shipping tool a team might already run,
without requiring this project's own viewer ahead of time.

Uses stdlib logging.handlers.RotatingFileHandler for the actual file
I/O and rotation (5MB per file, keeps 5 rotated backups by default)
rather than hand-rolling either - correct, well-tested behavior for
concurrent appends and bounded on-disk growth, with zero new
dependencies (consistent with this project's stdlib-only philosophy
wherever a stdlib facility already does the job - see
determine_worker_count()'s memory detection, or the compression support
in analyzer_core.py, for the same principle applied elsewhere).

This log complements, but does not replace, backend/users.py's own
per-username lockout tracking - that mechanism actively blocks a
brute-force attempt in real time; this one is a durable historical
record for after-the-fact review, and also covers Entra ID sign-ins,
which users.py has no visibility into at all.
"""
import json
import logging
import logging.handlers
import threading
import time
from pathlib import Path

_MAX_BYTES = 5 * 1024 * 1024  # 5MB per file
_BACKUP_COUNT = 5             # plus up to 5 rotated backups (audit.log.1 .. .5)
_MAX_DETAIL_LEN = 500         # bound how much free-text "detail" (e.g. an error
# message) can bloat a single entry - this is an audit trail, not a full
# error log; backend/app.py's own stdout/activity-log already carries the
# complete error detail for troubleshooting.
_MAX_USER_AGENT_LEN = 200


class AuditLog:
    """Not safe to share a single instance across independently-configured
    loggers with different rotation settings - in practice this project
    only ever constructs one AuditLog (backend/app.py module level,
    mirroring the existing JOBS/USER_STORE/SESSIONS singletons), so this
    is a non-issue in normal use."""

    def __init__(self, path: Path, max_bytes: int = _MAX_BYTES, backup_count: int = _BACKUP_COUNT):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # A distinct logger name per instance/path avoids handler
        # duplication if this were ever constructed more than once
        # (e.g. across a test suite creating several AuditLog(tmp_path)
        # instances in the same process) - logging.getLogger() returns
        # the SAME logger object for a repeated name, and handlers are
        # not automatically de-duplicated, so re-adding one on every
        # construction would multiply log lines.
        self._logger = logging.getLogger(f"ldi_copilot.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False  # never let audit entries also flow to the root logger/stdout
        if not self._logger.handlers:
            handler = logging.handlers.RotatingFileHandler(
                self.path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
        self._lock = threading.Lock()
        try:
            self.path.touch(exist_ok=True)
            self.path.chmod(0o600)  # best-effort on POSIX; harmless no-op on Windows
        except OSError:
            pass

    def record(self, event, username=None, auth_method=None, ip=None, user_agent=None, detail=None):
        """event: short machine-readable label, e.g. "login_success",
        "login_failure", "logout". username may be None for a failure
        where no valid identity was ever established (e.g. Entra ID
        state/CSRF mismatch before any token exchange happened).
        auth_method: "local" or "entra". Thread-safe; a logging-layer
        failure here (disk full, permissions issue) is swallowed rather
        than ever risking the actual request the caller is handling -
        an audit-trail gap is far preferable to breaking real sign-in
        functionality over a logging problem."""
        entry = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "username": username,
            "auth_method": auth_method,
            "ip": ip,
            "user_agent": (user_agent or "")[:_MAX_USER_AGENT_LEN] or None,
        }
        if detail:
            entry["detail"] = str(detail)[:_MAX_DETAIL_LEN]
        try:
            with self._lock:
                self._logger.info(json.dumps(entry, sort_keys=True))
        except Exception:
            pass

    def tail(self, limit=200, username=None, event=None):
        """Reads the most recent `limit` matching entries from the
        CURRENT log file only (not rotated .1/.2/... backups - those
        are for offline/manual review via a text editor or `grep`, not
        this lightweight in-app viewer) for GET /api/audit. Malformed
        lines (not expected in normal operation, but not impossible if
        the file were ever manually edited) are skipped rather than
        raising, since a single bad line should never break the whole
        view."""
        if not self.path.exists():
            return []
        entries = []
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if username and parsed.get("username") != username:
                        continue
                    if event and parsed.get("event") != event:
                        continue
                    entries.append(parsed)
        except OSError:
            return []
        limit = max(1, min(int(limit), 2000))
        return entries[-limit:][::-1]  # most-recent-first, matching how a log viewer is normally read
