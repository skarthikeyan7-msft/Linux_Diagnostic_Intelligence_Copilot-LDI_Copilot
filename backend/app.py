"""
Linux Diagnostic Intelligence Copilot - LDI Copilot backend
=============================================================
AI-powered analysis of sosreport, supportconfig, and cluster diagnostics
(crm_report/hb_report) to deliver automated issue detection, root cause
analysis, and remediation guidance.

Local FastAPI server that wraps the analysis engine (backend/engine) and
the pluggable AI provider clients (backend/ai) behind a small REST API,
and serves the browser frontend (frontend/) as static files.

Run with:  python backend/app.py
Then open: http://127.0.0.1:8756

Binds to 127.0.0.1 (localhost only) by default - this tool processes
sosreport/supportconfig/crm_report bundles that routinely contain
hostnames, internal IPs, and configuration data, so it deliberately
does not listen on all interfaces unless you explicitly opt in (see
--host in the CLI args below). When --host is pointed at a non-loopback
address, an auth gate turns on automatically - per-user accounts
(recommended - see backend/users.py, backend/manage_users.py) if any are
configured, else a single shared secret (backend/auth.py) - see
--auth-token/--no-auth/--require-auth below.
"""
import argparse
import json
import os
import shutil
import socket
import sys
import threading
import time
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, Form, File, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent))  # allow `import engine`, `import ai` when run directly

from engine import run_analysis, AnalysisError, determine_worker_count, _get_available_memory_mb, _DEFAULT_MAX_WORKERS, _ABSOLUTE_MAX_WORKERS
from ai import (
    PROVIDERS, stream_chat, ProviderError, build_messages, list_models,
    collect_known_hostnames, redact_text, build_redaction_summary, ollama_manager,
)
from auth import SESSION_COOKIE_NAME, SessionStore
from users import UserStore
from audit import AuditLog
import entra_auth

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "backend" / "data" / "jobs"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="LDI Copilot", version="4.10.0")

USERS_PATH = BASE_DIR / "backend" / "data" / "users.json"
USER_STORE = UserStore(USERS_PATH)
SESSIONS = SessionStore()
AUDIT_LOG = AuditLog(BASE_DIR / "backend" / "data" / "audit.log")

# Auth gate (backend/auth.py), wired here at module level rather than
# inside main(). uvicorn.run("app:app", ...) resolves that string by
# re-importing this file under the module name "app" - a SEPARATE module
# object from the "__main__" copy actually executing main() (this
# supports --reload's ability to re-import fresh on file changes). Any
# mutation main() made directly on ITS OWN `app` reference (e.g. calling
# app.add_middleware() there) would silently apply to a FastAPI instance
# that's never actually served. Reading an environment variable here
# instead works correctly for both copies, since os.environ is shared
# process-wide rather than per-module state: main() sets these variables
# before calling uvicorn.run(), and this code then runs again - and
# picks them up - during uvicorn's fresh re-import.
#
# Exactly one of the two gates below is ever active - main() decides
# which (or neither, for --no-auth/loopback) and sets the env vars
# accordingly. "Session" mode (SessionCookieMiddleware - local accounts
# and/or Entra ID SSO, see backend/auth.py/backend/entra_auth.py) takes
# priority over "token" (single shared secret) whenever local accounts
# exist OR Entra ID is configured; see main()'s auth_mode selection for
# the exact precedence rules and why.
_LDI_AUTH_TOKEN_ENV = "LDI_COPILOT_AUTH_TOKEN"
_LDI_SESSION_AUTH_ENV = "LDI_COPILOT_SESSION_AUTH"
_LDI_COOKIE_SECURE_ENV = "LDI_COPILOT_COOKIE_SECURE"

# Entra ID SSO configuration (v4.10.0) - these double as BOTH the same
# main()-to-reimported-module handoff mechanism as the vars above, AND a
# direct, user-facing way to supply this config without it ever
# appearing in a CLI argument list (visible in shell history / `ps`/Task
# Manager's process list otherwise) - main() reads any of these that are
# already set in the real environment as its default, letting the
# matching --entra-* CLI flag override on a given run. All four must be
# present together for Entra ID SSO to activate; see main().
LDI_ENTRA_TENANT_ID_ENV = "LDI_COPILOT_ENTRA_TENANT_ID"
LDI_ENTRA_CLIENT_ID_ENV = "LDI_COPILOT_ENTRA_CLIENT_ID"
LDI_ENTRA_CLIENT_SECRET_ENV = "LDI_COPILOT_ENTRA_CLIENT_SECRET"
LDI_ENTRA_REDIRECT_URI_ENV = "LDI_COPILOT_ENTRA_REDIRECT_URI"

# Whether the login endpoint marks the session cookie Secure (HTTPS-only)
# - mirrors whatever --https resolved to at startup, read the same
# environment-variable way as the auth mode itself, for the same reason.
COOKIE_SECURE = os.environ.get(_LDI_COOKIE_SECURE_ENV) == "1"

_auth_token = os.environ.get(_LDI_AUTH_TOKEN_ENV)
_session_auth_enabled = os.environ.get(_LDI_SESSION_AUTH_ENV) == "1"

ENTRA_TENANT_ID = os.environ.get(LDI_ENTRA_TENANT_ID_ENV) or None
ENTRA_CLIENT_ID = os.environ.get(LDI_ENTRA_CLIENT_ID_ENV) or None
ENTRA_CLIENT_SECRET = os.environ.get(LDI_ENTRA_CLIENT_SECRET_ENV) or None
ENTRA_REDIRECT_URI = os.environ.get(LDI_ENTRA_REDIRECT_URI_ENV) or None
ENTRA_ENABLED = bool(ENTRA_TENANT_ID and ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET and ENTRA_REDIRECT_URI)

if _session_auth_enabled:
    from auth import SessionCookieMiddleware
    app.add_middleware(SessionCookieMiddleware, session_store=SESSIONS)
elif _auth_token:
    from auth import BasicAuthMiddleware
    app.add_middleware(BasicAuthMiddleware, token=_auth_token)

# --------------------------------------------------------------------------
# In-memory job store. This is a local, single-user tool - jobs live for
# the lifetime of the server process; each job's uploaded archive and
# analysis output is kept on disk under backend/data/jobs/<job_id>/ until
# explicitly deleted (DELETE /api/jobs/{id}) or the folder is removed
# manually.
# --------------------------------------------------------------------------
JOBS = {}
JOBS_LOCK = threading.Lock()


def _new_job(name, focus_text=None):
    job_id = uuid.uuid4().hex[:12]
    job_dir = DATA_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "name": name,
            "status": "queued",
            "progress": [],
            "error": None,
            "result_summary": None,
            "created_at": datetime.utcnow().isoformat(),
            "dir": job_dir,
            "ai_report": "",
            "focus_text": focus_text,
            "conversation": [],  # [{role, content}, ...] - system+digest+report turn, then follow-up chat exchanges
            "redaction": None,  # {"summary": str, "legend": [{"token", "original"}, ...]} from the most recent synthesize() call, or None if that call didn't redact anything
        }
    return job_id


def _append_progress(job_id, msg):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is not None:
            job["progress"].append(msg)


def _run_job(job_id, input_path, kwargs):
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
    try:
        result = run_analysis(
            str(input_path),
            output_dir=str(JOBS[job_id]["dir"] / "analysis"),
            progress_cb=lambda m: _append_progress(job_id, m),
            **kwargs,
        )
        with JOBS_LOCK:
            job = JOBS[job_id]
            job["status"] = "done"
            job["result"] = result
            job["result_summary"] = {
                "kind": result["kind"],
                "root": result["root"],
                "num_findings": len(result["findings"]),
                "num_files": result["stats"]["files_scanned"],
                "num_lines": result["stats"]["lines_scanned"],
                "elapsed_seconds": result["elapsed_seconds"],
                "focus": result["facts"].get("focus"),
            }
    except AnalysisError as e:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = str(e)
    except Exception as e:  # noqa: BLE001 - surface unexpected errors to the UI rather than a bare 500 with no message
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"
            JOBS[job_id]["error"] = f"unexpected error: {e}"


def _get_job_or_404(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


# --------------------------------------------------------------------------
# API: authentication - two ways to establish the same kind of session
# (backend/auth.py's SessionStore/SessionCookieMiddleware): local
# accounts (backend/users.py, backend/manage_users.py) and Microsoft
# Entra ID SSO (v4.10.0, backend/entra_auth.py). These routes always
# exist regardless of which auth mode main() actually enforces for this
# run (harmless if unused - a session cookie that nothing ever checks
# doesn't grant anything), which keeps the login flow testable/usable
# even without a non-loopback --host. Every login attempt (either path)
# and logout is recorded to AUDIT_LOG (backend/audit.py) - see also
# GET /api/audit below.
# --------------------------------------------------------------------------
def _client_ip(request: Request) -> str | None:
    """request.client.host only - deliberately does NOT trust an
    X-Forwarded-For header. This project's documented deployment model
    is a direct bind (optionally --https with its own cert), not behind
    a trusted reverse proxy - trusting a client-suppliable header for
    an audit trail's IP field would let anyone log in and have their
    real IP silently replaced with whatever they put in that header. If
    you do put a trusted proxy in front of this server yourself, that
    proxy's own access log is the right place to capture the true
    client IP; this field will show the proxy's address in that setup."""
    return request.client.host if request.client else None


@app.post("/api/auth/login")
async def login(payload: dict, request: Request, response: Response):
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    ok, message = USER_STORE.verify(username, password)
    ip, ua = _client_ip(request), request.headers.get("user-agent")
    if not ok:
        AUDIT_LOG.record("login_failure", username=username or None, auth_method="local", ip=ip, user_agent=ua, detail=message)
        raise HTTPException(status_code=401, detail=message)
    AUDIT_LOG.record("login_success", username=username, auth_method="local", ip=ip, user_agent=ua)
    token = SESSIONS.create(username, auth_method="local")
    resp = JSONResponse({"username": username})
    resp.set_cookie(
        SESSION_COOKIE_NAME, token, httponly=True, samesite="lax",
        secure=COOKIE_SECURE, max_age=SESSIONS.ttl_seconds, path="/",
    )
    return resp


@app.post("/api/auth/logout")
async def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        session = SESSIONS.get_session(token)
        if session:
            AUDIT_LOG.record("logout", username=session["username"], auth_method=session["auth_method"], ip=_client_ip(request), user_agent=request.headers.get("user-agent"))
        SESSIONS.destroy(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth/me")
async def whoami(request: Request):
    """Lets the frontend show "logged in as <username>" plus a logout
    button when session-based auth is active - 401 (silently ignored by
    the frontend) whenever there's no session, whether that's because
    the user isn't logged in yet or because this instance isn't using
    session-based auth at all (e.g. --auth-token/--no-auth/loopback)."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    session = SESSIONS.get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="not authenticated")
    return session


@app.get("/api/auth/entra/enabled")
async def entra_enabled():
    """Lets the login page decide whether to show a "Sign in with
    Microsoft" button, and whether to show the local username/password
    form at all (hidden when zero local accounts are configured AND
    Entra ID is - no point offering a form that can never succeed)."""
    return {"entra_enabled": ENTRA_ENABLED, "accounts_configured": USER_STORE.count() > 0}


@app.get("/api/auth/entra/login")
async def entra_login():
    """Redirects the browser to the Microsoft identity platform's
    authorize endpoint to begin an interactive sign-in - see
    backend/entra_auth.py's module docstring for the full OAuth2/PKCE
    flow this kicks off. A plain browser navigation (not a fetch()
    call), so this returns an HTTP redirect rather than JSON."""
    if not ENTRA_ENABLED:
        raise HTTPException(status_code=404, detail="Microsoft Entra ID sign-in is not configured on this server")
    url = entra_auth.build_authorize_url(ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_REDIRECT_URI)
    return RedirectResponse(url=url, status_code=307)


@app.get("/api/auth/entra/callback")
async def entra_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None):
    """Completes the interactive sign-in Microsoft redirected the
    browser back to after the user authenticated (and consented, on
    first use) - exchanges the authorization code for tokens,
    cryptographically validates the ID token against Entra ID's own
    published signing keys, then creates a session identical in every
    way to a local-account login (same SESSIONS.create(), same cookie).
    Always ends in a browser REDIRECT (never a raw error status/JSON) -
    unlike the local-login POST, this is a plain browser navigation the
    frontend's own JS never sees the response of, so a failure has to
    be communicated via a redirect the user actually lands on, not a
    response body nothing reads."""
    ip, ua = _client_ip(request), request.headers.get("user-agent")
    if not ENTRA_ENABLED:
        raise HTTPException(status_code=404, detail="Microsoft Entra ID sign-in is not configured on this server")

    if error:
        # The user declined consent, or Entra ID itself rejected the
        # request (e.g. a misconfigured redirect URI) - Microsoft
        # reports this as query params rather than ever reaching our
        # code+state handling below.
        detail = error_description or error
        AUDIT_LOG.record("login_failure", auth_method="entra", ip=ip, user_agent=ua, detail=detail)
        return RedirectResponse(url=f"/login.html?error={urllib.parse.quote(detail[:300])}", status_code=303)

    code_verifier = entra_auth.STATE_STORE.pop(state) if state else None
    if not code or not code_verifier:
        AUDIT_LOG.record("login_failure", auth_method="entra", ip=ip, user_agent=ua, detail="missing or expired/invalid state (possible CSRF attempt, or sign-in took too long)")
        return RedirectResponse(url="/login.html?error=" + urllib.parse.quote("Sign-in session expired or is invalid - please try again."), status_code=303)

    try:
        tokens = entra_auth.exchange_code_for_tokens(ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET, ENTRA_REDIRECT_URI, code, code_verifier)
        id_token = tokens.get("id_token")
        if not id_token:
            raise entra_auth.EntraAuthError("token response did not contain an id_token")
        claims = entra_auth.validate_id_token(id_token, ENTRA_TENANT_ID, ENTRA_CLIENT_ID)
        username = entra_auth.extract_username_from_claims(claims)
    except entra_auth.EntraAuthError as e:
        AUDIT_LOG.record("login_failure", auth_method="entra", ip=ip, user_agent=ua, detail=str(e))
        return RedirectResponse(url=f"/login.html?error={urllib.parse.quote(str(e)[:300])}", status_code=303)

    AUDIT_LOG.record("login_success", username=username, auth_method="entra", ip=ip, user_agent=ua)
    token = SESSIONS.create(username, auth_method="entra")
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        SESSION_COOKIE_NAME, token, httponly=True, samesite="lax",
        secure=COOKIE_SECURE, max_age=SESSIONS.ttl_seconds, path="/",
    )
    return resp


@app.get("/api/audit")
async def get_audit(limit: int = 200, username: str | None = None, event: str | None = None):
    """Recent sign-in activity (local accounts AND Entra ID alike) for
    an in-app "who has been using this" view - see backend/audit.py.
    Gated by whatever auth mode is already active (this route is behind
    the same middleware as every other /api/* route; no separate
    permission check exists, consistent with this project's documented
    no-RBAC design - see SECURITY.md's "What this doesn't provide")."""
    return {"entries": AUDIT_LOG.tail(limit=limit, username=username, event=event)}


# --------------------------------------------------------------------------
# API: analysis jobs
# --------------------------------------------------------------------------
@app.post("/api/analyze")
async def analyze(
    file: UploadFile | None = File(None),
    server_path: str | None = Form(None),
    focus: str | None = Form(None),
    min_severity: str = Form("WARNING"),
    top_per_category: int = Form(25),
    start: str | None = Form(None),
    end: str | None = Form(None),
    around: str | None = Form(None),
    window: float = Form(60.0),
    focus_areas: str | None = Form(None),
    pcap_file: UploadFile | None = File(None),
    workers: int | None = Form(None),
):
    """Start a new analysis job. Accepts EITHER an uploaded archive/file
    (drag-and-drop from the browser) OR a server_path already on disk
    (handy for re-analyzing a large bundle you've already downloaded,
    without uploading it a second time). `focus` is optional free text
    describing what the engineer is actually investigating (e.g. "find
    root cause of NC and IP cluster resource restart issue") - when
    given, both the mechanical scan (keyword-tagged findings) and the
    later AI synthesis for this job are steered around answering that
    specific question instead of a generic exhaustive report. Returns
    immediately with a job_id; poll GET /api/jobs/{job_id} for progress.

    `focus_areas` is an optional comma-separated subset of
    engine.ALL_FOCUS_AREAS ("sar,crash,boot,security,packages,cascade,
    containers,network") narrowing which v4.0.0 analyzer sections appear
    in the digest (every check still runs regardless - this only
    controls what gets rendered/sent to the AI). Omit entirely (or leave
    blank) to keep every section, the default and pre-v4.0.0 behavior.

    `pcap_file` is an optional standalone packet capture (.pcap/.pcapng)
    to analyze alongside the bundle - pcaps are essentially never
    embedded inside a sosreport/supportconfig/crm_report archive itself,
    so this is a second, independent upload slot. Analyzed as METADATA
    ONLY (packet/byte counts, top talkers, protocol mix, TCP/DNS
    summaries) - raw payload content is never parsed or stored; see
    SECURITY.md.

    `workers` (v4.9.0) optionally overrides the auto-detected parallel
    worker-process count for the line-scanning pass - omit/leave blank
    to auto-detect from CPU count/available memory/bundle size (the
    default and recommended setting), or pass 1 to force the original
    single-process sequential scan."""
    if not file and not server_path:
        raise HTTPException(status_code=400, detail="provide either a file upload or a server_path")

    focus = (focus or "").strip() or None
    focus_areas_list = [a.strip() for a in focus_areas.split(",") if a.strip()] if focus_areas is not None else None

    if server_path:
        input_path = Path(server_path)
        if not input_path.exists():
            raise HTTPException(status_code=400, detail=f"server_path does not exist on this machine: {server_path}")
        job_id = _new_job(input_path.name, focus_text=focus)
    else:
        job_id = _new_job(file.filename, focus_text=focus)
        job_dir = JOBS[job_id]["dir"]
        upload_path = job_dir / "upload" / file.filename
        upload_path.parent.mkdir(parents=True, exist_ok=True)
        with open(upload_path, "wb") as fh:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
        input_path = upload_path

    pcap_path = None
    if pcap_file is not None and pcap_file.filename:
        job_dir = JOBS[job_id]["dir"]
        pcap_path = job_dir / "upload" / pcap_file.filename
        pcap_path.parent.mkdir(parents=True, exist_ok=True)
        with open(pcap_path, "wb") as fh:
            while True:
                chunk = await pcap_file.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)

    kwargs = dict(
        min_severity=min_severity, top_per_category=top_per_category,
        start=start or None, end=end or None, around=around or None, window=window,
        focus=focus, focus_areas=focus_areas_list, pcap_path=str(pcap_path) if pcap_path else None,
        workers=workers,
    )
    thread = threading.Thread(target=_run_job, args=(job_id, input_path, kwargs), daemon=True)
    thread.start()
    return {"job_id": job_id}


@app.get("/api/jobs")
def list_jobs():
    with JOBS_LOCK:
        return [
            {"id": j["id"], "name": j["name"], "status": j["status"],
             "created_at": j["created_at"], "summary": j["result_summary"],
             "focus_text": j.get("focus_text")}
            for j in sorted(JOBS.values(), key=lambda x: x["created_at"], reverse=True)
        ]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = _get_job_or_404(job_id)
    return {
        "id": job["id"], "name": job["name"], "status": job["status"],
        "progress": job["progress"], "error": job["error"],
        "summary": job["result_summary"], "focus_text": job.get("focus_text"),
    }


@app.get("/api/jobs/{job_id}/digest")
def get_digest(job_id: str):
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")
    return PlainTextResponse(job["result"]["digest_markdown"])


@app.get("/api/jobs/{job_id}/findings")
def get_findings(job_id: str):
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")
    return job["result"]["findings"]


@app.get("/api/jobs/{job_id}/facts")
def get_facts(job_id: str):
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")
    return JSONResponse(json.loads(json.dumps(job["result"]["facts"], default=str)))


@app.get("/api/jobs/{job_id}/inventory")
def get_inventory(job_id: str):
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")
    return job["result"]["inventory"]


@app.get("/api/jobs/{job_id}/timeline")
def get_timeline(job_id: str):
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")
    return sorted(job["result"]["timeline"], key=lambda e: e["ts"])


@app.get("/api/jobs/{job_id}/sar_series")
def get_sar_series(job_id: str):
    """Structured SAR time-series data (CPU/memory/disk/network/load),
    backing the Performance sub-tab's client-side charts - a narrower,
    purpose-built slice of facts.json so the chart code doesn't need to
    fetch/parse the entire (potentially large) structured-facts payload
    just to plot a handful of metrics. Returns {} (not 404) when the
    bundle had no parseable SAR data - that's an expected, common case,
    not an error."""
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")
    sar = job["result"]["facts"].get("sar_performance") or {}
    return JSONResponse(json.loads(json.dumps(sar, default=str)))


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    job = _get_job_or_404(job_id)
    job_dir = job["dir"]
    with JOBS_LOCK:
        del JOBS[job_id]
    shutil.rmtree(job_dir, ignore_errors=True)
    return {"deleted": job_id}


# --------------------------------------------------------------------------
# API: AI synthesis
# --------------------------------------------------------------------------
@app.get("/api/providers")
def get_providers():
    return PROVIDERS


def _validate_provider_auth(payload):
    """Shared validation for endpoints that need a fully-specified
    provider + auth_type + credentials payload (synthesize,
    test-connection). Raises HTTPException(400) with a clear message on
    any problem; returns (provider, auth_type, auth_cfg) on success."""
    provider = payload.get("provider")
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"unknown provider: {provider!r}")
    provider_cfg = PROVIDERS[provider]
    auth_type = payload.get("auth_type") or provider_cfg["default_auth_type"]
    if auth_type not in provider_cfg["auth_types"]:
        raise HTTPException(status_code=400, detail=f"unknown auth_type {auth_type!r} for provider {provider}")
    auth_cfg = provider_cfg["auth_types"][auth_type]
    missing = [f for f in auth_cfg["fields"] if not payload.get(f)]
    if missing:
        raise HTTPException(status_code=400, detail=f"missing required field(s) for {provider} ({auth_cfg['label']}): {', '.join(missing)}")
    return provider, auth_type, auth_cfg


@app.post("/api/models")
def list_available_models(payload: dict):
    """Best-effort live model-availability check backing the model
    picker's "grey out unavailable models" behavior. Always returns
    HTTP 200 with {available, error} rather than raising - a failed or
    not-yet-possible check (e.g. no credentials entered yet, offline,
    invalid key) must never block manual model selection; the frontend
    falls back to showing every known_models entry as selectable when
    available is null."""
    provider = payload.get("provider")
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"unknown provider: {provider!r}")
    try:
        available = list_models(provider, **{k: v for k, v in payload.items() if k != "provider"})
        return {"available": available, "error": None}
    except ProviderError as e:
        return {"available": None, "error": str(e)}
    except KeyError as e:
        return {"available": None, "error": f"missing required field: {e}"}


# A tiny, fixed, synthetic prompt - never any bundle/job data - used only
# to confirm a provider + its credentials/model/endpoint actually work
# end-to-end before running a full analysis. Deliberately static so this
# endpoint carries zero privacy considerations of its own.
_CONNECTIVITY_TEST_MESSAGES = [
    {"role": "system", "content": "This is a connectivity test, not a real request. Reply with exactly one word: OK"},
    {"role": "user", "content": "ping"},
]


@app.post("/api/test-connection")
def test_connection(payload: dict):
    """Lightweight connectivity/authentication check for the currently
    configured AI provider - especially useful for cloud ("public AI
    model") providers, where a support engineer wants to confirm their
    API key/endpoint/deployment actually works before running a full
    analysis. Sends the tiny static prompt above (never job/bundle
    data) and reads back a few characters of a real response, then
    closes the connection early rather than waiting for a full
    completion. For paid providers this consumes a negligible number of
    tokens - not a full synthesis worth. Always returns HTTP 200 with
    {ok, sample, error}; never raises for a provider-side failure."""
    provider, auth_type, _ = _validate_provider_auth(payload)
    provider_kwargs = {k: v for k, v in payload.items() if k not in ("provider", "extra_context", "focus_text", "redact")}

    gen = stream_chat(provider, _CONNECTIVITY_TEST_MESSAGES, **provider_kwargs)
    sample = ""
    try:
        for chunk in gen:
            sample += chunk
            if len(sample) >= 40:
                break
        return {"ok": True, "sample": sample.strip(), "error": None}
    except ProviderError as e:
        return {"ok": False, "sample": None, "error": str(e)}
    finally:
        gen.close()


@app.post("/api/jobs/{job_id}/synthesize")
async def synthesize(job_id: str, payload: dict):
    """Stream an AI-generated root-cause report for a completed job via
    Server-Sent Events. `payload` carries the provider choice and its
    credentials (api_key/endpoint/deployment/model/base_url as required
    by that provider) plus optional free-text extra_context and an
    optional focus_text override. If focus_text is omitted, the focus
    text supplied at analysis time (Step 1) is reused automatically, so
    the AI report stays steered around the same question the mechanical
    scan was steered around. Credentials are used only for this one
    request and are never written to disk or to the job store.

    `redact` (bool, default True) - when the selected provider is not
    local (i.e. not Ollama), the evidence digest has its known
    hostnames/node names, IPv4/IPv6 addresses, and email addresses
    replaced with stable, meaningless tokens (HOST-1, IP-1, IPV6-1,
    EMAIL-1, ...) before it's sent externally - see
    backend/ai/redaction.py for exactly what is/isn't covered. A
    "legend" SSE event is emitted first (local-only - this mapping is
    never part of the outbound request) so the browser can show what
    was redacted."""
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")

    provider, auth_type, _ = _validate_provider_auth(payload)
    provider_cfg = PROVIDERS[provider]

    focus_text = payload.get("focus_text")
    if focus_text is None:
        focus_text = job.get("focus_text")

    digest_markdown = job["result"]["digest_markdown"]
    redact_legend = []
    should_redact = bool(payload.get("redact", True)) and not provider_cfg.get("local")
    if should_redact:
        hostnames = collect_known_hostnames(job["result"].get("facts") or {})
        digest_markdown, redact_legend = redact_text(digest_markdown, hostnames)

    # Persisted immediately (not just streamed) so the Results page still
    # shows what was redacted after a page reload or a return visit via
    # "Recent analyses" - overwrites any redaction info from a previous
    # generate/regenerate call on this job, since that's the one now
    # reflected by job["ai_report"].
    redaction_info = (
        {"summary": build_redaction_summary(redact_legend), "legend": redact_legend}
        if should_redact else None
    )
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id]["redaction"] = redaction_info

    messages = build_messages(
        job["result"]["kind"], digest_markdown,
        extra_context=payload.get("extra_context"), focus_text=focus_text,
    )
    provider_kwargs = {k: v for k, v in payload.items() if k not in ("provider", "extra_context", "focus_text", "redact")}

    def event_stream():
        if redaction_info:
            yield f"data: {json.dumps({'redaction': redaction_info})}\n\n"
        accumulated = []
        try:
            for chunk in stream_chat(provider, messages, **provider_kwargs):
                accumulated.append(chunk)
                yield f"data: {json.dumps({'delta': chunk})}\n\n"
        except ProviderError as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        else:
            reply = "".join(accumulated)
            with JOBS_LOCK:
                if job_id in JOBS:
                    JOBS[job_id]["ai_report"] = reply
                    # Seeds the interactive-chat conversation with this
                    # report as the first "assistant" turn, so a follow-up
                    # question via /chat continues from exactly what the
                    # engineer just read rather than needing its own
                    # separate context.
                    JOBS[job_id]["conversation"] = messages + [{"role": "assistant", "content": reply}]
            yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# --------------------------------------------------------------------------
# API: interactive follow-up chat on a generated report. The initial
# Generate/Regenerate call above seeds JOBS[id]["conversation"] with the
# system+digest+report turn; every /chat call appends to and replays that
# same history (not just the newest message) so the model keeps full
# context of what it already told the engineer, exactly like a real
# back-and-forth conversation rather than N independent one-shot asks.
# --------------------------------------------------------------------------
_CHAT_MAX_FOLLOWUP_TURNS = 12  # user+assistant exchange pairs, beyond the initial report turn


@app.post("/api/jobs/{job_id}/chat")
async def chat(job_id: str, payload: dict):
    """Send a free-text follow-up instruction to the AI about a report
    that's already been generated for this job - e.g. "focus more on the
    network side", "explain the timeline gap between 14:02 and 14:05",
    "give me a shorter executive summary for my manager". Requires
    Generate/Regenerate to have completed at least once first (that call
    seeds the conversation this endpoint continues). Streams the reply
    via SSE exactly like /synthesize. Conversation history is capped
    (see _CHAT_MAX_FOLLOWUP_TURNS) so an extended back-and-forth doesn't
    let the request payload/cost/latency grow unbounded - the original
    system+digest+report turn is always preserved regardless."""
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")

    message = (payload.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    provider, auth_type, _ = _validate_provider_auth(payload)
    provider_kwargs = {k: v for k, v in payload.items() if k not in ("provider", "message", "redact")}

    with JOBS_LOCK:
        conversation = list(job.get("conversation") or [])
    if not conversation:
        raise HTTPException(status_code=409, detail="generate a report first (Generate log analysis), then ask follow-up questions here")

    head, tail = conversation[:2], conversation[2:]
    if len(tail) > _CHAT_MAX_FOLLOWUP_TURNS * 2:
        tail = tail[-(_CHAT_MAX_FOLLOWUP_TURNS * 2):]
    conversation = head + tail + [{"role": "user", "content": message}]

    def event_stream():
        accumulated = []
        try:
            for chunk in stream_chat(provider, conversation, **provider_kwargs):
                accumulated.append(chunk)
                yield f"data: {json.dumps({'delta': chunk})}\n\n"
        except ProviderError as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        else:
            reply = "".join(accumulated)
            with JOBS_LOCK:
                if job_id in JOBS:
                    JOBS[job_id]["conversation"] = conversation + [{"role": "assistant", "content": reply}]
            yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}/chat")
def get_chat_history(job_id: str):
    """Returns the follow-up exchanges only (not the initial system
    prompt/digest turn - the frontend already has the report itself from
    /synthesize) so a page refresh can restore an in-progress chat
    thread."""
    job = _get_job_or_404(job_id)
    with JOBS_LOCK:
        conversation = list(job.get("conversation") or [])
    return {"messages": conversation[3:]}  # skip system(0)/digest-user(1)/report-assistant(2)


@app.delete("/api/jobs/{job_id}/chat")
def reset_chat(job_id: str):
    """Clears follow-up exchanges only, restoring the conversation to
    "just the report that's already displayed" rather than wiping it
    entirely - a re-generated report (via /synthesize) always resets this
    completely anyway."""
    job = _get_job_or_404(job_id)
    with JOBS_LOCK:
        if job_id in JOBS:
            conv = JOBS[job_id].get("conversation") or []
            JOBS[job_id]["conversation"] = conv[:3]
    return {"reset": True}


# --------------------------------------------------------------------------
# API: Ollama lifecycle control - lets "Generate root-cause report" (or the
# activity terminal's toolbar) start a local `ollama serve` process on
# demand instead of requiring the user to remember to start it themselves
# first. See backend/ai/ollama_manager.py for the full design notes -
# in short: never spawns a duplicate if Ollama is already reachable, and
# will only ever stop a process this app itself spawned.
# --------------------------------------------------------------------------
@app.post("/api/ollama/start")
def start_ollama_endpoint(payload: dict = None):
    base_url = (payload or {}).get("base_url") or "http://localhost:11434"
    return ollama_manager.start_ollama(base_url)


@app.post("/api/ollama/stop")
def stop_ollama_endpoint():
    return ollama_manager.stop_ollama()


@app.get("/api/ollama/status")
def ollama_status_endpoint():
    return ollama_manager.get_ollama_status()


@app.post("/api/ollama/install")
async def install_ollama_endpoint(payload: dict = None):
    """Explicit, user-confirmed installation of Ollama itself (when
    is_ollama_installed() is False - see the "install?" confirmation
    modal in the frontend, triggered from the Start button and from the
    auto-start path before Generate/chat) plus pulling one model
    afterward, streamed as Server-Sent Events so a multi-minute
    download shows live progress in the activity terminal instead of a
    silent spinner. `payload.model` defaults to "llama3.1" (the same
    default the model dropdown itself defaults to) - pass whichever
    model the user actually has selected so the pulled model matches
    what they're about to use.

    Declining this (the user clicks Cancel in the frontend's
    confirmation modal, which never calls this endpoint at all) is a
    complete no-op - nothing here remembers "the user said no" anywhere,
    so the next Start click / auto-start attempt asks again."""
    model = ((payload or {}).get("model") or "llama3.1").strip() or "llama3.1"

    def event_stream():
        yield f"data: {json.dumps({'log': f'Installing Ollama and pulling {model!r}…'})}\n\n"
        install_failed = False
        for ok, line in ollama_manager.install_ollama_stream():
            yield f"data: {json.dumps({'log': line, 'ok': ok})}\n\n"
            if not ok:
                install_failed = True
        if install_failed:
            yield f"data: {json.dumps({'done': True, 'error': 'Ollama installation did not complete - see the log above.'})}\n\n"
            return

        start_result = ollama_manager.start_ollama()
        if start_result["status"] == "error":
            yield f"data: {json.dumps({'log': start_result['error'], 'ok': False})}\n\n"
            yield f"data: {json.dumps({'done': True, 'error': start_result['error']})}\n\n"
            return
        # start_ollama() itself only kicks off background readiness
        # polling (see ollama_manager._wait_until_ready_thread) - wait
        # here for it to actually finish before attempting a pull,
        # since `ollama pull` needs a reachable server.
        deadline = time.time() + ollama_manager.READY_POLL_TIMEOUT_SECONDS + 5
        while time.time() < deadline:
            status = ollama_manager.get_ollama_status()
            if status["status"] == "running":
                break
            if status["status"] == "error":
                yield f"data: {json.dumps({'log': status['error'], 'ok': False})}\n\n"
                yield f"data: {json.dumps({'done': True, 'error': status['error']})}\n\n"
                return
            time.sleep(1)
        else:
            err = "Timed out waiting for Ollama to become reachable after installation."
            yield f"data: {json.dumps({'log': err, 'ok': False})}\n\n"
            yield f"data: {json.dumps({'done': True, 'error': err})}\n\n"
            return

        pull_failed = False
        for ok, line in ollama_manager.pull_model_stream(model):
            yield f"data: {json.dumps({'log': line, 'ok': ok})}\n\n"
            if not ok:
                pull_failed = True
        if pull_failed:
            yield f"data: {json.dumps({'done': True, 'error': f'Failed to pull model {model!r} - see the log above. Ollama itself is installed and running.'})}\n\n"
            return

        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}/ai_report")
def get_ai_report(job_id: str):
    job = _get_job_or_404(job_id)
    return PlainTextResponse(job.get("ai_report", ""))


@app.get("/api/jobs/{job_id}/redaction")
def get_redaction(job_id: str):
    """Local-only record of what the most recent Generate/Regenerate call
    on this job redacted before sending the digest to a non-local AI
    provider - or null if that call used a local provider (Ollama) or had
    redaction turned off. Never reflects data actually sent anywhere;
    it's purely for the engineer to see what would be hidden from a
    third-party AI provider."""
    job = _get_job_or_404(job_id)
    return job.get("redaction")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/api/system-info")
def system_info():
    """Exposes this machine's detected CPU/memory capacity and the
    resulting default (auto-detected, zero-bundle) worker-count ceilings
    (v4.9.1) - lets the frontend's "Parallel scanning workers" dropdown
    show real, machine-specific numbers (e.g. "Auto (this machine: 8 CPU
    cores)") instead of guessing, so a choice like 16/32/64/128 can be
    made with actual context about whether it's within, or well beyond,
    this machine's real core count."""
    cpu_count = os.cpu_count() or 1
    avail_mb = _get_available_memory_mb()
    return {
        "cpu_count": cpu_count,
        "available_memory_mb": round(avail_mb) if avail_mb is not None else None,
        "default_max_workers": min(cpu_count, _DEFAULT_MAX_WORKERS),
        "absolute_max_workers": _ABSOLUTE_MAX_WORKERS,
    }


@app.post("/api/shutdown")
def shutdown_endpoint():
    """Stops the whole LDI Copilot server process itself - the in-app
    equivalent of running stop.sh/stop.bat/stop.ps1 (see those scripts
    for the out-of-process version, needed when the server isn't
    reachable to ask nicely). Frontend gating: the "⏹ Stop Project"
    topbar button always confirms via the same themed modal used for
    the Ollama install flow before ever calling this - there is no
    "undo" once this responds, so a stray click must not be enough to
    take the server down.

    Sequencing matters here: any Ollama instance this app is managing
    is stopped first (mirrors stop.*'s own best-effort step, reusing
    the exact same "never touch an externally-started instance"
    safeguard in ollama_manager.stop_ollama()), then the actual process
    exit is scheduled on a short delay on a background thread so this
    response has time to actually reach the browser before the process
    disappears - an immediate os._exit() here would race the response
    write and could leave the frontend with nothing but a dropped
    connection instead of a clean acknowledgement.

    os._exit() (not sys.exit()) is deliberate: this is a synchronous
    request handler running on uvicorn's event loop, and sys.exit()
    there would only raise SystemExit inside a worker context asyncio
    would just log and swallow - it would never actually stop the
    process. os._exit() unconditionally terminates the process
    immediately. This app has no buffered, not-yet-flushed state that
    a normal interpreter shutdown would need to clean up (every job's
    files are written as they're produced, not held in memory until
    exit), so skipping normal interpreter teardown is safe here."""
    try:
        ollama_manager.stop_ollama()
    except Exception:
        pass  # best-effort - a stuck Ollama stop must never block the server from shutting down when asked to

    def _delayed_exit():
        time.sleep(0.4)
        os._exit(0)

    threading.Thread(target=_delayed_exit, daemon=True).start()
    return {"stopping": True}


# Static frontend - mounted last so it acts as a catch-all fallback
# behind the /api/* routes registered above (Starlette matches routes
# in registration order).
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


def _preflight_check_host(host, scheme="http"):
    """Proactively verifies `host` is actually bindable on THIS machine
    before starting uvicorn at all, so a bad --host value fails with an
    immediately actionable message instead of the raw OS error
    ("[Errno 99] Cannot assign requested address" on Linux, similar on
    Windows/macOS) that uvicorn would otherwise surface with no context.

    By far the most common cause (reported directly from a real Azure
    RHEL 8 VM): passing a cloud VM's PUBLIC IP to --host. Public cloud
    IPs (Azure/AWS/GCP) are NAT'd at the platform's network edge and are
    never actually assigned to the VM's own network interface - `ip addr
    show` on the VM itself will never list it - so the OS can never bind
    a listening socket to it directly, no matter what. This is expected
    cloud networking behavior, not a bug in this tool.

    Skips the check entirely for 0.0.0.0/127.0.0.1/localhost/::/::1,
    which are always valid regardless of the machine's actual interface
    configuration, so this never adds any overhead or false positives
    for the overwhelmingly common (and recommended) case.
    """
    if host in ("0.0.0.0", "127.0.0.1", "localhost", "::", "::1"):
        return
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.bind((host, 0))  # port 0 = OS picks an ephemeral port; only the address itself is under test
    except OSError as e:
        print(f"\nERROR: cannot bind to --host {host} on this machine ({e}).\n", file=sys.stderr)
        print(
            "This almost always means the address isn't actually configured on any\n"
            "network interface here. The single most common cause: passing a CLOUD\n"
            "VM's PUBLIC IP (Azure/AWS/GCP) to --host. Public cloud IPs are NAT'd at\n"
            "the platform's edge and are never assigned to the VM's own network card,\n"
            "so the OS can never bind to them directly - this is expected cloud\n"
            "networking behavior, not a bug in this tool.\n\n"
            "Fix: use --host 0.0.0.0 (binds every local interface) or the default\n"
            "127.0.0.1 (localhost only, safest), then either:\n"
            "  - reach it via an SSH tunnel from your own machine (no exposed port\n"
            "    at all): ssh -L 8756:127.0.0.1:8756 user@<vm-public-ip>\n"
            f"    then browse to {scheme}://127.0.0.1:8756 locally, or\n"
            "  - open the port in your cloud firewall (scoped to your own IP, not\n"
            f"    0.0.0.0/0) and browse to {scheme}://<vm-public-ip>:<port> from outside.\n"
            "See README.md's Quick start section and SECURITY.md before exposing\n"
            "this beyond localhost, especially with real customer bundle data.\n",
            file=sys.stderr,
        )
        sys.exit(1)


def main():
    import uvicorn
    ap = argparse.ArgumentParser(description="LDI Copilot local server")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1 = localhost only; use 0.0.0.0 to allow LAN access - not recommended for sensitive bundles)")
    ap.add_argument("--port", type=int, default=8756, help="Port (default 8756)")
    ap.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development only)")
    ap.add_argument("--https", action="store_true", help="Serve over HTTPS/TLS instead of plain HTTP. Without --ssl-certfile/--ssl-keyfile, auto-generates and reuses a self-signed certificate under ../certs (browsers show a one-time trust warning for it - see README.md's HTTPS section).")
    ap.add_argument("--ssl-certfile", default=None, help="Path to a PEM certificate file - supply your own trusted cert instead of the auto-generated self-signed one (use together with --ssl-keyfile)")
    ap.add_argument("--ssl-keyfile", default=None, help="Path to the PEM private key matching --ssl-certfile")
    ap.add_argument("--auth-token", default=None, help="Shared secret required (as an HTTP Basic Auth password, any username) to reach this server. Takes priority over per-user accounts/Entra ID SSO if any are present - use this for quick/simple sharing without provisioning individual accounts. If --host is non-loopback and none of --auth-token/accounts/Entra ID is configured, a random token is generated and printed once at startup. Use --no-auth to disable all auth gates instead.")
    ap.add_argument("--no-auth", action="store_true", help="Disable all auth gates (accounts, Entra ID SSO, and shared-token alike) even when --host is non-loopback. Only safe when something else already restricts who can reach this address (VPN, firewall rule scoped to known IPs).")
    ap.add_argument("--require-auth", action="store_true", help="Force whichever auth gate would apply on a non-loopback host to also apply here, even though --host is loopback. Useful for testing the login flow locally before deploying.")
    ap.add_argument("--entra-tenant-id", default=None, help="Microsoft Entra ID SSO (v4.10.0): your Azure AD Directory (tenant) ID - enables a 'Sign in with Microsoft' option on the login page, in addition to (not instead of) any local accounts. All four --entra-* values are required together (or set the matching LDI_COPILOT_ENTRA_* environment variable instead of a CLI flag, to avoid the client secret appearing in shell history / `ps`/Task Manager's process list). See README.md's 'Sharing with a team' section for the Azure Portal app-registration steps.")
    ap.add_argument("--entra-client-id", default=None, help="Microsoft Entra ID SSO: the app registration's Application (client) ID.")
    ap.add_argument("--entra-client-secret", default=None, help="Microsoft Entra ID SSO: the app registration's client secret VALUE (not the secret ID). Prefer the LDI_COPILOT_ENTRA_CLIENT_SECRET environment variable over this flag to keep it out of shell history/process list.")
    ap.add_argument("--entra-redirect-uri", default=None, help="Microsoft Entra ID SSO: the exact redirect URI registered on the app registration, e.g. https://your-server-address:8756/api/auth/entra/callback - must match EXACTLY (scheme/host/port/path) what's configured in Azure Portal, since Entra ID rejects any mismatch.")
    args = ap.parse_args()
    scheme = "https" if args.https else "http"
    _preflight_check_host(args.host, scheme=scheme)

    if args.no_auth and args.auth_token:
        print("ERROR: --auth-token and --no-auth are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    # Entra ID config: an explicit --entra-* flag overrides whatever the
    # matching LDI_COPILOT_ENTRA_* environment variable already holds;
    # otherwise the environment variable (if any) is used as-is - this
    # lets a user avoid ever putting the client secret on the command
    # line at all, by exporting it once in their shell/service-unit
    # environment instead.
    entra_tenant_id = args.entra_tenant_id or os.environ.get(LDI_ENTRA_TENANT_ID_ENV) or None
    entra_client_id = args.entra_client_id or os.environ.get(LDI_ENTRA_CLIENT_ID_ENV) or None
    entra_client_secret = args.entra_client_secret or os.environ.get(LDI_ENTRA_CLIENT_SECRET_ENV) or None
    entra_redirect_uri = args.entra_redirect_uri or os.environ.get(LDI_ENTRA_REDIRECT_URI_ENV) or None
    entra_values = {"--entra-tenant-id": entra_tenant_id, "--entra-client-id": entra_client_id, "--entra-client-secret": entra_client_secret, "--entra-redirect-uri": entra_redirect_uri}
    entra_present = [k for k, v in entra_values.items() if v]
    entra_configured = len(entra_present) == 4
    if 0 < len(entra_present) < 4:
        missing = [k for k, v in entra_values.items() if not v]
        print(f"ERROR: Microsoft Entra ID SSO requires all four --entra-* values (or their LDI_COPILOT_ENTRA_* environment variable equivalents) together. Missing: {', '.join(missing)}.", file=sys.stderr)
        sys.exit(1)

    is_loopback = args.host in ("127.0.0.1", "localhost", "::1")
    enforce = args.require_auth or not is_loopback
    n_users = USER_STORE.count()
    session_auth_available = n_users > 0 or entra_configured

    # Precedence: --no-auth always wins (gate off). An explicit
    # --auth-token always wins next, regardless of accounts/Entra ID, so
    # a quick shared-password setup is still available even if either is
    # configured too. Otherwise: no enforcement needed (loopback, no
    # --require-auth) -> gate off; enforcement needed and EITHER local
    # accounts OR Entra ID is configured (or both - the login page offers
    # whichever is actually available) -> the stronger session-based
    # gate; otherwise (enforcement needed, nothing configured) -> the
    # same auto-generated shared-token fallback introduced in v4.3.0.
    if args.no_auth:
        auth_mode, auth_token = "none", None
    elif args.auth_token:
        auth_mode, auth_token = "token", args.auth_token
    elif not enforce:
        auth_mode, auth_token = "none", None
    elif session_auth_available:
        auth_mode, auth_token = "session", None
    else:
        from auth import generate_token
        auth_mode, auth_token = "token", generate_token()

    if auth_mode == "session":
        os.environ[_LDI_SESSION_AUTH_ENV] = "1"
        os.environ.pop(_LDI_AUTH_TOKEN_ENV, None)
        lines = ["Auth gate ENABLED (session-based sign-in)."]
        if n_users > 0:
            usernames = ", ".join(USER_STORE.list_usernames())
            lines.append(f"  Local accounts ({n_users} configured: {usernames}) - manage with:")
            lines.append("    python backend/manage_users.py add <username>")
            lines.append("    python backend/manage_users.py remove <username>")
            lines.append("    python backend/manage_users.py list")
        if entra_configured:
            lines.append(f"  Microsoft Entra ID SSO ENABLED (tenant {entra_tenant_id}) - teammates can sign in with")
            lines.append("    their existing organizational Microsoft account, no separate password to manage.")
            lines.append("    Restrict who can sign in via Entra ID's own app registration ('Assignment")
            lines.append("    required?' under Enterprise applications), not a setting in this app.")
        lines.append("Every sign-in (either method) and logout is recorded to backend/data/audit.log -")
        lines.append("view recent activity at GET /api/audit, or read the file directly.")
        lines.append("To fall back to a single shared password instead, pass --auth-token.")
        lines.append("See SECURITY.md before exposing this beyond localhost.")
        print("\n".join(lines) + "\n")
    elif auth_mode == "token":
        os.environ[_LDI_AUTH_TOKEN_ENV] = auth_token
        os.environ.pop(_LDI_SESSION_AUTH_ENV, None)
        print(
            "Auth gate ENABLED - every request needs an HTTP Basic Auth credential.\n"
            "  Username: (anything, e.g. \"ldi\")\n"
            f"  Password: {auth_token}\n"
            "Share this password only with your team, over a channel you trust (not\n"
            "in a public chat/ticket). Your browser will prompt for it once and cache\n"
            "it for the session. To pin a stable password instead of a random one each\n"
            "restart, pass --auth-token yourself. For stronger, per-user access\n"
            "instead of one shared password, provision accounts with\n"
            "backend/manage_users.py and/or configure Microsoft Entra ID SSO\n"
            "(--entra-tenant-id/--entra-client-id/--entra-client-secret/--entra-redirect-uri)\n"
            "and restart without --auth-token. To disable all auth gates (only if\n"
            "something else already restricts access, e.g. VPN), pass --no-auth.\n"
            "See SECURITY.md before exposing this beyond localhost.\n"
        )
    else:
        os.environ.pop(_LDI_AUTH_TOKEN_ENV, None)
        os.environ.pop(_LDI_SESSION_AUTH_ENV, None)
        if enforce:
            print(
                "WARNING: auth gate DISABLED (--no-auth) while bound to a non-loopback\n"
                f"address ({args.host}). Anyone who can reach this address can use this\n"
                "tool and any customer data uploaded to it. Make sure network-level\n"
                "access (VPN/firewall) is already locked down. See SECURITY.md.\n"
            )

    # Entra ID config is handed off to the re-imported app:app module the
    # same environment-variable way as the auth mode/token above (see
    # that block's comment for why) - set regardless of auth_mode, since
    # a user could otherwise still reach the Entra endpoints directly
    # even under --auth-token/--no-auth; ENTRA_ENABLED (computed from
    # these at import time) is what actually gates whether the login
    # page offers the button, independent of which OTHER gate is active.
    if entra_configured:
        os.environ[LDI_ENTRA_TENANT_ID_ENV] = entra_tenant_id
        os.environ[LDI_ENTRA_CLIENT_ID_ENV] = entra_client_id
        os.environ[LDI_ENTRA_CLIENT_SECRET_ENV] = entra_client_secret
        os.environ[LDI_ENTRA_REDIRECT_URI_ENV] = entra_redirect_uri
    else:
        for var in (LDI_ENTRA_TENANT_ID_ENV, LDI_ENTRA_CLIENT_ID_ENV, LDI_ENTRA_CLIENT_SECRET_ENV, LDI_ENTRA_REDIRECT_URI_ENV):
            os.environ.pop(var, None)

    os.environ[_LDI_COOKIE_SECURE_ENV] = "1" if args.https else "0"

    ssl_certfile, ssl_keyfile = args.ssl_certfile, args.ssl_keyfile
    if args.https and not (ssl_certfile and ssl_keyfile):
        from certs import ensure_self_signed_cert
        cert_dir = Path(__file__).resolve().parent.parent / "certs"
        ssl_certfile, ssl_keyfile = ensure_self_signed_cert(cert_dir, args.host)
        print(
            f"Using auto-generated self-signed certificate ({cert_dir}).\n"
            "Browsers will show a one-time trust warning (e.g. \"Your connection isn't\n"
            "private\") for it - this is expected for a self-signed cert; proceed past\n"
            "it (\"Advanced\" -> \"Continue\"), or supply a certificate your team already\n"
            "trusts via --ssl-certfile/--ssl-keyfile instead. To make the warning go away\n"
            "permanently for Chrome/Edge (Safari/Chrome on macOS, most Linux distros'\n"
            "Chrome), run .\\trust-cert.ps1 / .\\trust-cert.bat / ./trust-cert.sh once - it\n"
            "trusts this exact certificate only, on this machine, for this user (never a\n"
            "general-purpose CA). See README.md's HTTPS section for details, including\n"
            "the separate manual step Firefox always needs.\n"
        )
    elif args.https:
        print(f"Using certificate {ssl_certfile} (key: {ssl_keyfile})\n")

    print(f"LDI Copilot starting at {scheme}://{args.host}:{args.port}")
    uvicorn.run(
        "app:app", host=args.host, port=args.port, reload=args.reload,
        ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile,
    )


if __name__ == "__main__":
    main()
