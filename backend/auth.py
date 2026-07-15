"""
Shared-secret authentication gate for non-local exposure.

LDI Copilot is a local, single-user tool by default (binds to 127.0.0.1),
where authentication would be pure friction - only the person already
sitting at the machine can reach it. But once --host is pointed at a
real, reachable address (e.g. 0.0.0.0 so a "global support team" can use
one shared instance over the internet - see README.md's "Sharing with a
team" section), anyone who can route to that address can reach every
endpoint: upload a customer's sosreport, read back the analysis, spend
the configured AI provider's API budget, etc. This module adds a single
shared-secret gate (HTTP Basic Auth) in front of the whole app for that
case.

Deliberately simple by design - this is a small internal tool for a
support team, not a multi-tenant product:
- One shared secret, not per-user accounts (nothing to register/manage).
- HTTP Basic Auth, not a custom login page/session/cookie - the browser
  prompts once, caches the credential for the browsing session, and
  automatically attaches it to every request (including the frontend's
  own fetch() calls), so zero frontend code is needed.
- Enforced by a Starlette middleware wrapping every request (API routes
  and the static frontend alike) except /api/health, which stays
  reachable without credentials for uptime monitoring / load balancer
  probes and reveals nothing sensitive (just {"status": "ok", ...}).

This is a basic access gate suitable for keeping a shared link from being
usable by a stranger who stumbles onto the address - it is NOT a
substitute for real network-layer controls (VPN-only access, a firewall
rule scoped to known source IPs) when the bundles involved are
sensitive. Always combine both. See SECURITY.md.
"""
import base64
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_UNAUTHENTICATED_PATHS = {"/api/health"}
_REALM = "LDI Copilot"


def generate_token(n_bytes: int = 18) -> str:
    """A URL-safe random shared secret, printed once at startup when no
    --auth-token is explicitly supplied. 18 bytes -> 24 base64url chars,
    plenty of entropy for a secret that's rate-limited only by however
    fast an attacker can retry HTTP Basic Auth attempts over the network,
    and easy enough to read aloud/copy-paste to a teammate."""
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
