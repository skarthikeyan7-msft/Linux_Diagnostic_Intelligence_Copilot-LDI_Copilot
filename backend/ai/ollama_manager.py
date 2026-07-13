"""
Ollama lifecycle manager - lets the app itself start (and, if it started
it, stop) a local `ollama serve` process, so choosing Ollama as the AI
provider doesn't require a separate manual "remember to start Ollama
first" step. This is what backs the "Generate root-cause report" button
auto-starting Ollama when needed, and the Start/Stop buttons in the
activity terminal's toolbar.

Design notes:
- Only ONE thing is ever managed: a single `ollama serve` subprocess
  spawned by this module. If Ollama is already reachable on the target
  base_url when start_ollama() is called (e.g. the user already has it
  running via the Ollama desktop app, or started it manually), nothing
  is spawned - we simply report it as already running. This module
  will never spawn a second, redundant server process.
- stop_ollama() will ONLY terminate a process THIS module spawned in
  this server session. It deliberately will not attempt to find and
  kill some other "ollama" process by name - that could kill an
  instance the user relies on for something else entirely.
- All state lives in-memory (STATE dict below, guarded by STATE_LOCK) -
  nothing here is persisted to disk, consistent with the rest of the
  app's job store.
- The stdout/stderr reader thread is a daemon thread so it never blocks
  server shutdown.
"""
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

MAX_LOG_LINES = 300
READY_POLL_TIMEOUT_SECONDS = 60  # cold starts can be slow: GPU discovery + model-list
                                  # hydration on the very first request has been observed
                                  # to take 15-30+ seconds even though the TCP listener
                                  # itself comes up almost instantly.
READY_POLL_INTERVAL_SECONDS = 1

STATE_LOCK = threading.Lock()
STATE = {
    "status": "stopped",     # stopped | starting | running | error
    "process": None,         # subprocess.Popen if we spawned it, else None
    "log_lines": [],
    "error": None,
    "base_url": "http://localhost:11434",
}


def _append_log(line):
    with STATE_LOCK:
        STATE["log_lines"].append(line)
        if len(STATE["log_lines"]) > MAX_LOG_LINES:
            STATE["log_lines"] = STATE["log_lines"][-MAX_LOG_LINES:]


def is_ollama_reachable(base_url="http://localhost:11434", timeout=6):
    """Quick check: is something already answering Ollama's API at
    base_url? Used both to avoid spawning a redundant process and to
    detect when a just-spawned process has finished starting up."""
    try:
        req = urllib.request.Request(f"{base_url.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


def _reader_thread(proc):
    try:
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\n")
            if line:
                _append_log(line)
    except Exception as e:  # defensive - a logging thread must never crash the server
        _append_log(f"[log reader stopped: {e}]")


def _wait_until_ready_thread(base_url):
    deadline = time.time() + READY_POLL_TIMEOUT_SECONDS
    while time.time() < deadline:
        with STATE_LOCK:
            proc = STATE["process"]
        process_exited = proc is not None and proc.poll() is not None
        # Check reachability BEFORE concluding failure, even if our own
        # spawned process already exited - on machines where Ollama also
        # runs as a background app/service (e.g. the Windows tray app),
        # our process can lose a startup race for the port to that other
        # instance and exit with a bind error, while Ollama itself is
        # perfectly reachable a moment later via that other instance.
        # That's a success from the user's point of view, not a failure.
        if is_ollama_reachable(base_url):
            with STATE_LOCK:
                STATE["status"] = "running"
                STATE["error"] = None
            if process_exited:
                _append_log(f"Our own 'ollama serve' process exited (code {proc.returncode}), but Ollama is reachable via another already-running instance (e.g. the Ollama desktop app) - treating as running.")
            else:
                _append_log(f"Ollama is now reachable at {base_url}")
            return
        if process_exited:
            with STATE_LOCK:
                STATE["status"] = "error"
                STATE["error"] = f"ollama serve exited early (code {proc.returncode}) and Ollama is still not reachable - see log for details"
            _append_log(f"ollama serve exited with code {proc.returncode}")
            return
        time.sleep(READY_POLL_INTERVAL_SECONDS)
    with STATE_LOCK:
        STATE["status"] = "error"
        STATE["error"] = f"Timed out after {READY_POLL_TIMEOUT_SECONDS}s waiting for Ollama to become reachable at {base_url}"
    _append_log(STATE["error"])


def start_ollama(base_url="http://localhost:11434"):
    """Idempotent, non-blocking: kicks off startup in background threads
    and returns immediately with the current status. Callers should
    poll get_ollama_status() to watch progress (mirrors the existing
    analysis-job polling pattern elsewhere in this app)."""
    with STATE_LOCK:
        if STATE["status"] == "starting":
            return dict(STATE, log_lines=list(STATE["log_lines"]))
        STATE["base_url"] = base_url

    if is_ollama_reachable(base_url):
        with STATE_LOCK:
            STATE["status"] = "running"
            STATE["error"] = None
        _append_log(f"Ollama already reachable at {base_url} - not starting a new instance.")
        return get_ollama_status()

    with STATE_LOCK:
        STATE["status"] = "starting"
        STATE["error"] = None
    _append_log("Starting 'ollama serve'…")

    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )
    except FileNotFoundError:
        with STATE_LOCK:
            STATE["status"] = "error"
            STATE["error"] = "'ollama' executable not found on PATH. Install it from https://ollama.com, then try again (or pick a different AI provider)."
            STATE["process"] = None
        _append_log(STATE["error"])
        return get_ollama_status()
    except OSError as e:
        with STATE_LOCK:
            STATE["status"] = "error"
            STATE["error"] = f"Failed to start 'ollama serve': {e}"
            STATE["process"] = None
        _append_log(STATE["error"])
        return get_ollama_status()

    with STATE_LOCK:
        STATE["process"] = proc
    threading.Thread(target=_reader_thread, args=(proc,), daemon=True).start()
    threading.Thread(target=_wait_until_ready_thread, args=(base_url,), daemon=True).start()
    return get_ollama_status()


def stop_ollama():
    """Only terminates a process this module itself spawned. Returns a
    dict describing what happened - never raises."""
    with STATE_LOCK:
        proc = STATE["process"]
    if proc is None or proc.poll() is not None:
        _append_log("Stop requested, but Ollama is not currently managed by this app (either not running, or running externally) - nothing to stop.")
        return {"stopped": False, "reason": "Not managed by this app (not running, or started outside LDI Copilot)."}
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    with STATE_LOCK:
        STATE["status"] = "stopped"
        STATE["process"] = None
        STATE["error"] = None
    _append_log("Ollama stopped.")
    return {"stopped": True, "reason": None}


def get_ollama_status():
    with STATE_LOCK:
        proc = STATE["process"]
        managed = proc is not None and proc.poll() is None
        return {
            "status": STATE["status"],
            "managed": managed,
            "pid": proc.pid if managed else None,
            "log_lines": list(STATE["log_lines"]),
            "error": STATE["error"],
            "base_url": STATE["base_url"],
        }
