"""
Authentication gates for non-local exposure.

LDI Copilot is a local, single-user tool by default (binds to 127.0.0.1),
where authentication would be pure friction - only the person already
sitting at the machine can reach it. But once --host is pointed at a
real, reachable address (e.g. 0.0.0.0 so a "global support team" can use
one shared instance over the internet - see README.md's "Sharing with a
team" section), anyone who can route to that address can reach every
endpoint: upload a customer's sosreport, read back the analysis, spend
the configured AI provider's API budget, etc. This module provides two
gates, chosen automatically by backend/app.py's main() based on whether
any per-user accounts are configured (see backend/users.py):

1. **SessionCookieMiddleware + SessionStore** (recommended - "accounts"
   mode): per-user login via backend/users.py's UserStore, backed by a
   signed-nothing random session token in an HttpOnly cookie. Gives real
   per-user identity (so access for one teammate can be revoked without
   affecting anyone else) at the cost of needing an admin to provision
   accounts first (backend/manage_users.py).
2. **BasicAuthMiddleware** ("token" mode - the original v4.3.0 gate,
   still available): a single shared secret, no accounts to manage,
   automatically used as a zero-setup fallback when no accounts exist
   yet. HTTP Basic Auth means the browser prompts once and auto-attaches
   the credential to every subsequent request (including the frontend's
   own fetch() calls) with zero frontend code.

Both are enforced by a Starlette middleware wrapping every request (API
routes and the static frontend alike) except /api/health, which stays
reachable without credentials for uptime monitoring / load balancer
probes and reveals nothing sensitive (just {"status": "ok", ...}).

Neither is a substitute for real network-layer controls (VPN-only
access, a firewall rule scoped to known source IPs) when the bundles
involved are sensitive. Always combine both. See SECURITY.md.
"""
import base64
import json
import secrets
import threading
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

_UNAUTHENTICATED_PATHS = {"/api/health"}
_REALM = "LDI Copilot"


def generate_token(n_bytes: int = 18) -> str:
    """A URL-safe random shared secret, printed once at startup when no
    --auth-token is explicitly supplied and no accounts are configured.
    18 bytes -> 24 base64url chars, plenty of entropy for a secret that's
    rate-limited only by however fast an attacker can retry HTTP Basic
    Auth attempts over the network, and easy enough to read aloud/
    copy-paste to a teammate."""
    return secrets.token_urlsafe(n_bytes)


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Requires a valid HTTP Basic Auth credential (any username, this
    exact password) on every request except _UNAUTHENTICATED_PATHS.
    Uses secrets.compare_digest() for the password check so response
    timing doesn't leak how many leading characters were correct."""

    def __init__(self, app, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        if request.url.path in _UNAUTHENTICATED_PATHS:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            try:
                decoded = base64.b64decode(header[6:].strip()).decode("utf-8", errors="strict")
                _, _, supplied = decoded.partition(":")
            except Exception:
                supplied = ""
            if supplied and secrets.compare_digest(supplied, self._token):
                return await call_next(request)

        return Response(
            status_code=401,
            content="Authentication required.",
            headers={"WWW-Authenticate": f'Basic realm="{_REALM}"'},
        )


# --------------------------------------------------------------------------
# Per-user accounts ("accounts" mode) - session store + cookie middleware.
# --------------------------------------------------------------------------
SESSION_COOKIE_NAME = "ldi_session"
LOGIN_PAGE_PATH = "/login.html"
_DEFAULT_SESSION_TTL_SECONDS = 12 * 3600  # 12 hours - a support engineer's typical shift-length upper bound

# Paths reachable without a session, on top of _UNAUTHENTICATED_PATHS
# above: the login page itself and the login API call that establishes
# a session in the first place (nothing else about /api/auth/* - "me"
# and "logout" both require an existing session, which they check
# themselves rather than being globally exempted here).
_ACCOUNTS_UNAUTHENTICATED_PATHS = {LOGIN_PAGE_PATH, "/api/auth/login"}


class SessionStore:
    """In-memory session store (token -> {username, expires_at}) - mirrors
    this codebase's existing JOBS/JOBS_LOCK pattern in backend/app.py:
    simple, process-lifetime-only, appropriate for a small internal tool
    with no requirement for sessions to survive a server restart (a
    restart just signs everyone out, which is an acceptable trade-off
    here)."""

    def __init__(self, ttl_seconds: int = _DEFAULT_SESSION_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = {"username": username, "expires_at": time.time() + self.ttl_seconds}
        return token

    def get_username(self, token: str):
        if not token:
            return None
        with self._lock:
            record = self._sessions.get(token)
            if record is None:
                return None
            if record["expires_at"] < time.time():
                del self._sessions[token]
                return None
            return record["username"]

    def destroy(self, token: str):
        with self._lock:
            self._sessions.pop(token, None)


class SessionCookieMiddleware(BaseHTTPMiddleware):
    """Requires a valid session cookie (see SessionStore above) on every
    request except _UNAUTHENTICATED_PATHS/_ACCOUNTS_UNAUTHENTICATED_PATHS.
    API requests without a valid session get a plain 401 JSON body (so
    the frontend's own fetch() calls fail predictably); any other
    (non-API, i.e. page/asset) request is redirected to the login page,
    which is a small, fully self-contained HTML file
    (frontend/login.html) with no sub-resources of its own, so no other
    path needs to be exempted.

    Every response that passes through here gets `Cache-Control: no-store`
    - without it, a browser can serve the SPA shell (index.html) straight
    from its own local disk/memory cache on a later visit, bypassing this
    middleware's redirect-to-login check entirely (no network request is
    even made, so there's nothing for this code to intercept). That's not
    a data leak by itself - every actual API call the stale page then
    makes still correctly gets a fresh 401 - but it renders a confusing,
    half-broken "logged out but pretending not to be" page instead of the
    login form. Verified live: without this header, navigating back to
    `/` right after signing out reused a cached authenticated-looking
    page; with it, the login page reliably reappears."""

    def __init__(self, app, session_store: SessionStore):
        super().__init__(app)
        self._sessions = session_store

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _UNAUTHENTICATED_PATHS or path in _ACCOUNTS_UNAUTHENTICATED_PATHS:
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            return response

        token = request.cookies.get(SESSION_COOKIE_NAME)
        username = self._sessions.get_username(token)
        if username:
            request.state.username = username
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            return response

        if path.startswith("/api/"):
            return Response(
                status_code=401, content=json.dumps({"detail": "authentication required"}),
                media_type="application/json", headers={"Cache-Control": "no-store"},
            )
        return RedirectResponse(url=LOGIN_PAGE_PATH, status_code=303, headers={"Cache-Control": "no-store"})
