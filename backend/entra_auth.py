"""
Microsoft Entra ID single sign-on (SSO) for signing IN to this server -
i.e. deciding which human is allowed to use this tool, via the
interactive OAuth2 Authorization Code flow with PKCE (RFC 7636). This is
a different use case, and a different OAuth2 grant type, from
backend/ai/providers.py's get_entra_id_token(): that one is a
machine-to-machine client-credentials token used to CALL Azure OpenAI on
the analysis side. Both talk to the same Microsoft identity platform,
but this module authenticates a real person through a browser, not a
service calling an API.

On successful sign-in, this creates exactly the SAME kind of session
(backend/auth.py's SessionStore/SessionCookieMiddleware) that local
accounts (backend/users.py) use - Entra ID sign-in and local accounts
are simply two different ways to establish the identical session
cookie, so every other part of this app (the auth gate, /api/auth/me,
audit logging) treats a session from either path uniformly rather than
needing separate downstream code.

Security properties (read before treating this as "just an HTTP
redirect dance"):
- **PKCE** - even though this is a confidential client (it holds a
  client secret), PKCE is included anyway as defense-in-depth against
  authorization-code interception, and because it's a Microsoft- and
  IETF-recommended best practice for all app types under current
  guidance, not just public/mobile clients.
- **`state` parameter** - single-use (popped on first use, never
  reusable), time-limited (10 minutes), cryptographically random -
  prevents CSRF on the callback (an attacker tricking a victim's
  browser into completing an OAuth flow the attacker initiated for
  their OWN account, which would otherwise let the attacker's identity
  get attached to the victim's browser session).
- **ID token signature verification via the tenant's own published
  JWKS** (JSON Web Key Set, fetched from Entra ID's own discovery
  endpoint, not hardcoded) using PyJWT - this is the one piece
  deliberately NOT hand-rolled with stdlib alone (unlike the rest of
  this project): correctly verifying an RS256 JWT signature against a
  rotating remote key set is exactly the kind of security-critical,
  easy-to-get-subtly-wrong logic that belongs in an audited library,
  not a bespoke implementation. Without this, anyone could send a
  self-signed "ID token" claiming to be any user, and this module would
  have no way to know it was never actually issued by Microsoft.
- **`iss` (issuer) and `aud` (audience) claim checks** - a validly
  SIGNED token for a different tenant, a different app registration, or
  the wrong token version, is still rejected. PyJWT's own issuer/
  audience checks are exact string matches, not fuzzy ones.

Deliberately implemented with only the Python standard library
(urllib.request) for the HTTP calls, same as backend/ai/providers.py -
the one new dependency this module needs is PyJWT[crypto]
(backend/requirements.txt), specifically for that signature
verification piece above.
"""
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt
from jwt import PyJWKClient

_AUTHORIZE_PATH = "oauth2/v2.0/authorize"
_TOKEN_PATH = "oauth2/v2.0/token"
_JWKS_PATH = "discovery/v2.0/keys"
DEFAULT_SCOPE = "openid profile email"

_STATE_TTL_SECONDS = 600  # 10 minutes - generous for a human to complete an
# interactive sign-in (read a prompt, maybe do MFA), while still short
# enough that a `state` value captured from a log/browser history well
# after the fact is useless long before anyone could realistically try to
# replay it.


class EntraAuthError(Exception):
    """Raised for any problem completing Entra ID sign-in (bad/expired
    state, token exchange failure, ID token validation failure, ...)
    with a message safe to show the end user - never includes the
    client secret or raw token contents."""
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce_pair():
    """Returns (code_verifier, code_challenge) per RFC 7636: a random
    43-128 character verifier, and its SHA-256 "S256" challenge. The
    verifier is held server-side (in _StateStore below) between the
    authorize redirect and the callback; only the challenge - not the
    verifier - is ever sent to Entra ID up front, so intercepting the
    authorize request alone gives an attacker nothing usable."""
    verifier = _b64url(secrets.token_bytes(48))  # 64 chars, well within the 43-128 range RFC 7636 requires
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class _StateStore:
    """Single-use, time-limited store for the OAuth `state` value and
    its matching PKCE code_verifier, keyed by state - mirrors
    backend/auth.py's SessionStore pattern (in-memory, process-lifetime
    only; a server restart mid-flow just means the user's in-progress
    sign-in fails and they retry from scratch, an acceptable trade-off
    for a small internal tool that isn't expected to restart mid-login
    in practice). pop() deliberately CONSUMES the entry - a given state
    value can only ever complete the flow once, closing a replay window
    even if a callback URL were somehow captured/logged/bookmarked."""

    def __init__(self, ttl_seconds: int = _STATE_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._entries = {}
        self._lock = threading.Lock()

    def create(self, code_verifier: str) -> str:
        state = secrets.token_urlsafe(32)
        with self._lock:
            self._prune_locked()
            self._entries[state] = {"code_verifier": code_verifier, "expires_at": time.time() + self.ttl_seconds}
        return state

    def pop(self, state: str):
        """Returns the stored code_verifier and removes the entry, or
        None if state is unknown, expired, or already consumed."""
        with self._lock:
            entry = self._entries.pop(state, None)
        if entry is None or entry["expires_at"] < time.time():
            return None
        return entry["code_verifier"]

    def _prune_locked(self):
        now = time.time()
        expired = [s for s, e in self._entries.items() if e["expires_at"] < now]
        for s in expired:
            del self._entries[s]


STATE_STORE = _StateStore()


def build_authorize_url(tenant_id, client_id, redirect_uri, scope=DEFAULT_SCOPE):
    """Returns the full Microsoft identity platform authorize URL to send
    the user's browser to. The returned `state` is embedded in that URL
    already (Entra ID echoes it back verbatim on the callback) - callers
    don't need to separately remember it themselves; the state store
    already holds the matching code_verifier, keyed by this same value."""
    code_verifier, code_challenge = generate_pkce_pair()
    state = STATE_STORE.create(code_verifier)
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"https://login.microsoftonline.com/{tenant_id}/{_AUTHORIZE_PATH}?" + urllib.parse.urlencode(params)
    return url


def exchange_code_for_tokens(tenant_id, client_id, client_secret, redirect_uri, code, code_verifier):
    """Authorization Code -> tokens (POST to the v2 token endpoint).
    Returns the parsed JSON response dict (contains id_token,
    access_token, ...). Raises EntraAuthError on failure - mirrors
    backend/ai/providers.py's get_entra_id_token() error-handling
    pattern closely (same identity platform, same error-response
    shape), including reusing its AADSTS error-code plain-English
    hints when available."""
    url = f"https://login.microsoftonline.com/{tenant_id}/{_TOKEN_PATH}"
    form = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(detail).get("error_description", detail)
        except (json.JSONDecodeError, AttributeError):
            pass
        detail = detail[:500]
        try:
            # Reuses providers.py's AADSTS hint dictionary (Conditional
            # Access blocks, expired/invalid secret, etc.) rather than
            # duplicating it - the exact same error codes can occur
            # here, since it's the exact same token endpoint.
            from ai.providers import _explain_aadsts_error
            detail = _explain_aadsts_error(detail)
        except Exception:
            pass
        raise EntraAuthError(f"token exchange failed (HTTP {e.code}): {detail}") from e
    except urllib.error.URLError as e:
        raise EntraAuthError(f"token exchange connection error: {e.reason}") from e
    except TimeoutError as e:
        raise EntraAuthError(f"token exchange timed out: {e}") from e


_jwks_clients = {}
_jwks_clients_lock = threading.Lock()


def _get_jwks_client(tenant_id):
    """PyJWKClient caches fetched signing keys internally and only
    re-fetches the JWKS on a signing-key-ID cache miss (e.g. after
    Microsoft rotates their keys) - one client per tenant is built once
    and reused across every sign-in, rather than re-fetching Entra ID's
    JWKS on every single login."""
    with _jwks_clients_lock:
        client = _jwks_clients.get(tenant_id)
        if client is None:
            jwks_url = f"https://login.microsoftonline.com/{tenant_id}/{_JWKS_PATH}"
            client = PyJWKClient(jwks_url)
            _jwks_clients[tenant_id] = client
        return client


def validate_id_token(id_token, tenant_id, client_id):
    """Verifies the ID token's signature against Entra ID's own
    published JWKS for this tenant, AND its iss/aud/exp claims, then
    returns the decoded claims dict. Raises EntraAuthError on ANY
    validation failure - this function never returns claims from a
    token that failed any check, since its entire purpose is to be the
    one place that decides whether an ID token is genuinely
    trustworthy; every caller downstream trusts its return value
    completely.

    `iss` is checked against the exact v2.0 tenant-specific issuer
    Entra ID actually uses (https://login.microsoftonline.com/{tenant_id}/v2.0) -
    a validly-signed token for a DIFFERENT tenant is still rejected even
    though the signature alone would pass, since PyJWT's issuer check
    is an exact string match, not a fuzzy one."""
    try:
        jwks_client = _get_jwks_client(tenant_id)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        expected_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        claims = jwt.decode(
            id_token, signing_key.key, algorithms=["RS256"],
            audience=client_id, issuer=expected_issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        return claims
    except jwt.ExpiredSignatureError as e:
        raise EntraAuthError("ID token has expired - please sign in again.") from e
    except jwt.InvalidAudienceError as e:
        raise EntraAuthError("ID token was not issued for this application (audience mismatch) - check the configured Client (application) ID.") from e
    except jwt.InvalidIssuerError as e:
        raise EntraAuthError("ID token was not issued by the expected tenant (issuer mismatch) - check the configured Tenant (directory) ID.") from e
    except jwt.PyJWTError as e:
        raise EntraAuthError(f"ID token validation failed: {e}") from e
    except Exception as e:
        raise EntraAuthError(f"could not verify ID token against Entra ID's signing keys: {e}") from e


def extract_username_from_claims(claims):
    """Picks the best human-readable identifier from the ID token's
    claims for use as this session's "username" (shown in the UI,
    recorded in the audit log). preferred_username is Microsoft's own
    recommended display identifier (usually the UPN/email) - falls back
    to email, then the immutable `oid` (object ID) if somehow neither
    text claim is present, so a session is never left with no
    identifier at all."""
    return claims.get("preferred_username") or claims.get("email") or claims.get("oid") or "unknown"
