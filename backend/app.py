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
--host in the CLI args below).
"""
import argparse
import json
import shutil
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, UploadFile, Form, File, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent))  # allow `import engine`, `import ai` when run directly

from engine import run_analysis, AnalysisError
from ai import PROVIDERS, stream_chat, ProviderError, build_messages, list_models

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "backend" / "data" / "jobs"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="LDI Copilot", version="2.1.1")

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
    immediately with a job_id; poll GET /api/jobs/{job_id} for progress."""
    if not file and not server_path:
        raise HTTPException(status_code=400, detail="provide either a file upload or a server_path")

    focus = (focus or "").strip() or None

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

    kwargs = dict(
        min_severity=min_severity, top_per_category=top_per_category,
        start=start or None, end=end or None, around=around or None, window=window,
        focus=focus,
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
    request and are never written to disk or to the job store."""
    job = _get_job_or_404(job_id)
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job status is {job['status']}, not done yet")

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

    focus_text = payload.get("focus_text")
    if focus_text is None:
        focus_text = job.get("focus_text")
    messages = build_messages(
        job["result"]["kind"], job["result"]["digest_markdown"],
        extra_context=payload.get("extra_context"), focus_text=focus_text,
    )
    provider_kwargs = {k: v for k, v in payload.items() if k not in ("provider", "extra_context", "focus_text")}

    def event_stream():
        accumulated = []
        try:
            for chunk in stream_chat(provider, messages, **provider_kwargs):
                accumulated.append(chunk)
                yield f"data: {json.dumps({'delta': chunk})}\n\n"
        except ProviderError as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        else:
            with JOBS_LOCK:
                if job_id in JOBS:
                    JOBS[job_id]["ai_report"] = "".join(accumulated)
            yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}/ai_report")
def get_ai_report(job_id: str):
    job = _get_job_or_404(job_id)
    return PlainTextResponse(job.get("ai_report", ""))


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


# Static frontend - mounted last so it acts as a catch-all fallback
# behind the /api/* routes registered above (Starlette matches routes
# in registration order).
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


def main():
    import uvicorn
    ap = argparse.ArgumentParser(description="LDI Copilot local server")
    ap.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1 = localhost only; use 0.0.0.0 to allow LAN access - not recommended for sensitive bundles)")
    ap.add_argument("--port", type=int, default=8756, help="Port (default 8756)")
    ap.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development only)")
    args = ap.parse_args()
    print(f"LDI Copilot starting at http://{args.host}:{args.port}")
    uvicorn.run("app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
