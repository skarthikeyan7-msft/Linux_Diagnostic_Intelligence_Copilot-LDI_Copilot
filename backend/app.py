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
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, Form, File, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent))  # allow `import engine`, `import ai` when run directly

from engine import run_analysis, AnalysisError
from ai import (
    PROVIDERS, stream_chat, ProviderError, build_messages, list_models,
    collect_known_hostnames, redact_text, build_redaction_summary, ollama_manager,
)
from auth import SESSION_COOKIE_NAME, SessionStore
from users import UserStore

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "backend" / "data" / "jobs"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="LDI Copilot", version="4.8.0")

USERS_PATH = BASE_DIR / "backend" / "data" / "users.json"
USER_STORE = UserStore(USERS_PATH)
SESSIONS = SessionStore()

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
# which (or neither, for --no-auth/loopback) and sets ONE of these two
# env vars accordingly, never both. "Accounts" (per-user, backend/users.py)
# takes priority over "token" (single shared secret) whenever at least
# one account is configured; see main()'s auth_mode selection for the
# exact precedence rules and why.
_LDI_AUTH_TOKEN_ENV = "LDI_COPILOT_AUTH_TOKEN"
_LDI_ACCOUNTS_AUTH_ENV = "LDI_COPILOT_ACCOUNTS_AUTH"
_LDI_COOKIE_SECURE_ENV = "LDI_COPILOT_COOKIE_SECURE"

# Whether the login endpoint marks the session cookie Secure (HTTPS-only)
# - mirrors whatever --https resolved to at startup, read the same
# environment-variable way as the auth mode itself, for the same reason.
COOKIE_SECURE = os.environ.get(_LDI_COOKIE_SECURE_ENV) == "1"

_auth_token = os.environ.get(_LDI_AUTH_TOKEN_ENV)
_accounts_auth_enabled = os.environ.get(_LDI_ACCOUNTS_AUTH_ENV) == "1"

if _accounts_auth_enabled:
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
# API: per-user account authentication ("accounts" auth mode - see
# backend/auth.py, backend/users.py, backend/manage_users.py). These
# routes always exist regardless of which auth mode main() actually
# enforces for this run (harmless if unused - a session cookie that
# nothing ever checks doesn't grant anything), which keeps the login
# flow testable/usable even without a non-loopback --host.
# --------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(payload: dict, response: Response):
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    ok, message = USER_STORE.verify(username, password)
    if not ok:
        raise HTTPException(status_code=401, detail=message)
    token = SESSIONS.create(username)
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
        SESSIONS.destroy(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth/me")
async def whoami(request: Request):
    """Lets the frontend show "logged in as <username>" plus a logout
    button when accounts mode is active - 401 (silently ignored by the
    frontend) whenever there's no session, whether that's because the
    user isn't logged in yet or because this instance isn't using
    accounts mode at all (e.g. --auth-token/--no-auth/loopback)."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    username = SESSIONS.get_username(token)
    if not username:
        raise HTTPException(status_code=401, detail="not authenticated")
    return {"username": username}


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
    SECURITY.md."""
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
    hostnames/node names and IPv4 addresses replaced with stable,
    meaningless tokens (HOST-1, IP-1, ...) before it's sent externally.
    A "legend" SSE event is emitted first (local-only - this mapping is
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
    ap.add_argument("--auth-token", default=None, help="Shared secret required (as an HTTP Basic Auth password, any username) to reach this server. Takes priority over per-user accounts if both are present - use this for quick/simple sharing without provisioning individual accounts. If --host is non-loopback and neither this nor any account (see backend/manage_users.py) exists, a random token is generated and printed once at startup. Use --no-auth to disable all auth gates instead.")
    ap.add_argument("--no-auth", action="store_true", help="Disable all auth gates (accounts and shared-token alike) even when --host is non-loopback. Only safe when something else already restricts who can reach this address (VPN, firewall rule scoped to known IPs).")
    ap.add_argument("--require-auth", action="store_true", help="Force whichever auth gate would apply on a non-loopback host to also apply here, even though --host is loopback. Useful for testing the login flow locally before deploying.")
    args = ap.parse_args()
    scheme = "https" if args.https else "http"
    _preflight_check_host(args.host, scheme=scheme)

    if args.no_auth and args.auth_token:
        print("ERROR: --auth-token and --no-auth are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    is_loopback = args.host in ("127.0.0.1", "localhost", "::1")
    enforce = args.require_auth or not is_loopback
    n_users = USER_STORE.count()

    # Precedence: --no-auth always wins (gate off). An explicit
    # --auth-token always wins next, regardless of accounts, so a quick
    # shared-password setup is still available even if accounts happen
    # to be configured too. Otherwise: no enforcement needed (loopback,
    # no --require-auth) -> gate off; enforcement needed and at least one
    # account exists -> the stronger per-user "accounts" gate; otherwise
    # (enforcement needed, zero accounts, no explicit token) -> the same
    # auto-generated shared-token fallback introduced in v4.3.0.
    if args.no_auth:
        auth_mode, auth_token = "none", None
    elif args.auth_token:
        auth_mode, auth_token = "token", args.auth_token
    elif not enforce:
        auth_mode, auth_token = "none", None
    elif n_users > 0:
        auth_mode, auth_token = "accounts", None
    else:
        from auth import generate_token
        auth_mode, auth_token = "token", generate_token()

    if auth_mode == "accounts":
        os.environ[_LDI_ACCOUNTS_AUTH_ENV] = "1"
        os.environ.pop(_LDI_AUTH_TOKEN_ENV, None)
        usernames = ", ".join(USER_STORE.list_usernames())
        print(
            f"Auth gate ENABLED (per-user accounts, {n_users} configured: {usernames}).\n"
            "Each teammate signs in at the login page with their own username and\n"
            "password - nothing to share over chat/email. Manage accounts with:\n"
            "    python backend/manage_users.py add <username>\n"
            "    python backend/manage_users.py remove <username>\n"
            "    python backend/manage_users.py list\n"
            "To fall back to a single shared password instead, pass --auth-token.\n"
            "See SECURITY.md before exposing this beyond localhost.\n"
        )
    elif auth_mode == "token":
        os.environ[_LDI_AUTH_TOKEN_ENV] = auth_token
        os.environ.pop(_LDI_ACCOUNTS_AUTH_ENV, None)
        print(
            "Auth gate ENABLED - every request needs an HTTP Basic Auth credential.\n"
            "  Username: (anything, e.g. \"ldi\")\n"
            f"  Password: {auth_token}\n"
            "Share this password only with your team, over a channel you trust (not\n"
            "in a public chat/ticket). Your browser will prompt for it once and cache\n"
            "it for the session. To pin a stable password instead of a random one each\n"
            "restart, pass --auth-token yourself. For stronger, per-user access\n"
            "instead of one shared password, provision accounts with\n"
            "backend/manage_users.py and restart without --auth-token. To disable\n"
            "all auth gates (only if something else already restricts access, e.g.\n"
            "VPN), pass --no-auth. See SECURITY.md before exposing this beyond\n"
            "localhost.\n"
        )
    else:
        os.environ.pop(_LDI_AUTH_TOKEN_ENV, None)
        os.environ.pop(_LDI_ACCOUNTS_AUTH_ENV, None)
        if enforce:
            print(
                "WARNING: auth gate DISABLED (--no-auth) while bound to a non-loopback\n"
                f"address ({args.host}). Anyone who can reach this address can use this\n"
                "tool and any customer data uploaded to it. Make sure network-level\n"
                "access (VPN/firewall) is already locked down. See SECURITY.md.\n"
            )

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
