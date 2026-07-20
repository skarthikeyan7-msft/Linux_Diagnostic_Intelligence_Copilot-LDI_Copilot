"""
Ollama lifecycle manager - lets the app itself start (and, if it started
it, stop) a local `ollama serve` process, so choosing Ollama as the AI
provider doesn't require a separate manual "remember to start Ollama
first" step. This is what backs the "Generate root-cause report" button
auto-starting Ollama when needed, and the Start/Stop buttons in the
activity terminal's toolbar.

Also handles the case where Ollama isn't installed on this machine at
all (common on a freshly-provisioned VM - see README.md's Ollama
section): is_ollama_installed()/install_ollama_stream()/
pull_model_stream() below let the UI offer to install Ollama itself and
pull a model, with the user's explicit confirmation, instead of just
surfacing a dead-end "not found on PATH" error.

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
- Installation is always driven by an explicit user click (never
  automatic) and always runs the *official* install path for the
  detected OS (Ollama's own install.sh on Linux, winget/the official
  Windows installer on Windows, Homebrew/manual on macOS) - this module
  never bundles or downloads Ollama's binary itself.
"""
import os
import platform
import shutil
import subprocess
import sys
import tempfile
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
    "not_installed": False,  # True specifically when the last start attempt failed because
                              # the `ollama` executable itself isn't on PATH - lets the UI
                              # offer to install it instead of just showing a dead-end error.
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


def _extra_search_paths():
    """A few well-known install locations that a *freshly installed*
    Ollama might not yet be visible at via shutil.which() in THIS
    already-running Python process - PATH changes made by an installer
    (especially on Windows, where installers commonly update the
    registry-backed user PATH) aren't picked up by os.environ in a
    process that started before the install happened. Checked as a
    fallback, never as the primary lookup."""
    home = os.path.expanduser("~")
    candidates = []
    if sys.platform == "win32":
        localappdata = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        candidates.append(os.path.join(localappdata, "Programs", "Ollama", "ollama.exe"))
    elif sys.platform == "darwin":
        candidates += ["/usr/local/bin/ollama", "/opt/homebrew/bin/ollama", "/Applications/Ollama.app/Contents/Resources/ollama"]
    else:
        candidates += ["/usr/local/bin/ollama", "/usr/bin/ollama", os.path.join(home, ".local", "bin", "ollama")]
    return candidates


def find_ollama_executable():
    """Resolves the `ollama` executable's path if it's available by any
    means (PATH, or one of the fallback locations above) - or None."""
    found = shutil.which("ollama")
    if found:
        return found
    for candidate in _extra_search_paths():
        if os.path.isfile(candidate):
            return candidate
    return None


def is_ollama_installed():
    return find_ollama_executable() is not None


def detect_os_label():
    system = platform.system()
    return {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}.get(system, "other")


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
        STATE["not_installed"] = False

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

    ollama_exe = find_ollama_executable() or "ollama"
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            [ollama_exe, "serve"],
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
            STATE["not_installed"] = True
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
            "installed": is_ollama_installed(),
            "not_installed": STATE["not_installed"],
        }


# --------------------------------------------------------------------------
# Installation + model pulling - both explicitly user-initiated (the "Ollama
# isn't installed - install it now?" confirmation in the UI, or the
# equivalent interactive prompt in run.sh/run.bat/run.ps1), and both stream
# their progress as plain text lines via the generator functions below so
# the caller (an SSE endpoint in backend/app.py) can forward them to the
# activity terminal live instead of the browser just spinning silently for
# however many minutes a real download takes.
# --------------------------------------------------------------------------
def _run_streaming(cmd, cwd=None, shell=False, input_text=None):
    """Runs `cmd`, yielding its combined stdout/stderr as it's produced.
    Splits on '\\r' as well as '\\n' because some tools (notably `ollama
    pull`'s own download progress bar) rewrite a single line in place
    with carriage returns rather than emitting newline-terminated lines -
    without this, the entire multi-minute download would arrive as one
    giant buffered chunk right at the end instead of live progress.
    Yields (ok: bool, line: str) - ok is only False for the final
    "process exited with code N" line on a nonzero exit."""
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, shell=shell,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except (FileNotFoundError, OSError) as e:
        yield False, f"Failed to run {cmd!r}: {e}"
        return

    if input_text is not None:
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except Exception:
            pass

    buffer = ""
    last_emit = 0.0
    while True:
        chunk = proc.stdout.read(1024)
        if not chunk:
            break
        buffer += chunk
        while True:
            cut = min((i for i in (buffer.find("\n"), buffer.find("\r")) if i != -1), default=-1)
            if cut == -1:
                break
            line, buffer = buffer[:cut], buffer[cut + 1:]
            line = line.strip()
            now = time.time()
            # Throttle: a download progress line repeats many times a
            # second - forwarding every single one would flood the
            # activity terminal for no benefit. Always forward non-empty
            # lines at most ~3/sec; never drop a blank-to-content
            # transition since that's usually a genuinely new stage
            # ("pulling manifest" -> "verifying sha256 digest" etc.).
            if line and (now - last_emit > 0.33):
                yield True, line
                last_emit = now
    if buffer.strip():
        yield True, buffer.strip()

    code = proc.wait()
    if code != 0:
        yield False, f"Command exited with code {code}: {' '.join(cmd) if isinstance(cmd, list) else cmd}"


def _run_capture(cmd, shell=False, timeout=20):
    """Runs `cmd` to completion (not streamed - for quick, non-interactive
    checks like 'apt-get update'), returning (returncode, combined output).
    Never raises; a timeout or launch failure is reported as a nonzero
    "synthetic" return code with a descriptive message instead."""
    try:
        proc = subprocess.run(
            cmd, shell=shell, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except (FileNotFoundError, OSError) as e:
        return -1, str(e)


# Ollama's own official Linux installer (verified directly against its
# real source - ollama/ollama on GitHub, scripts/install.sh - rather than
# guessed) requires curl/awk/grep/sed/tee/xargs (base tools, virtually
# always already present) AND, for every current release, `zstd` to
# extract the modern .tar.zst release asset it downloads - a tool that is
# routinely MISSING on minimal/container Linux base images and freshly
# provisioned VMs, and one Ollama's own installer only reports as an
# error rather than installing itself. This is the exact, real gap this
# closes: proactively detect and auto-install whatever's missing, via
# whichever package manager is actually on the system, BEFORE handing off
# to Ollama's installer - so the common case (just missing zstd) resolves
# itself with zero manual steps instead of a dead-end error message.
_OLLAMA_LINUX_INSTALLER_DEPS = ["curl", "awk", "grep", "sed", "tee", "xargs", "zstd"]

# (package_manager_binary, update_cmd_or_None, install_cmd_template) -
# checked in this order (most to least common on a general-purpose
# server distro first); update_cmd runs once, best-effort, before the
# install (only apt-get strictly needs a fresh index on a freshly
# provisioned image - the others resolve from an already-current local
# cache/database without one).
_LINUX_PKG_MANAGERS = [
    ("apt-get", ["apt-get", "update", "-qq"], ["apt-get", "install", "-y"]),
    ("dnf", None, ["dnf", "install", "-y"]),
    ("yum", None, ["yum", "install", "-y"]),
    ("zypper", None, ["zypper", "--non-interactive", "install"]),
    ("pacman", None, ["pacman", "-S", "--noconfirm"]),
    ("apk", ["apk", "update"], ["apk", "add"]),
]


def _ensure_ollama_linux_deps():
    """Generator yielding (ok, line) progress lines while checking for and
    auto-installing any of Ollama's own installer's system-level
    dependencies that are missing (see _OLLAMA_LINUX_INSTALLER_DEPS above)
    - called right before running Ollama's install.sh on Linux. Yields
    True (no failure) even when nothing needed installing, or when
    installation genuinely can't proceed (e.g. no supported package
    manager, no sudo) - the caller treats this as best-effort and always
    still attempts Ollama's own installer afterward, which will surface
    its own clear error if a dependency is still genuinely missing."""
    missing = [tool for tool in _OLLAMA_LINUX_INSTALLER_DEPS if not shutil.which(tool)]
    if not missing:
        yield True, "All of Ollama installer's system dependencies (curl/awk/grep/sed/tee/xargs/zstd) are already present."
        return
    yield True, f"Ollama's installer needs the following tool(s) not currently on PATH: {', '.join(missing)}. Attempting to install automatically…"

    sudo_prefix = []
    if getattr(os, "geteuid", lambda: 0)() != 0:
        if shutil.which("sudo"):
            sudo_prefix = ["sudo"]
        else:
            yield True, "Not running as root and 'sudo' isn't available - can't auto-install these. Continuing anyway; Ollama's own installer will report clearly if something is still missing."
            return

    for name, update_cmd, install_cmd_tpl in _LINUX_PKG_MANAGERS:
        if not shutil.which(name):
            continue
        if update_cmd is not None:
            yield True, f"Refreshing {name}'s package index…"
            _run_capture(sudo_prefix + update_cmd, timeout=60)  # best-effort - a stale/offline index still lets install proceed for already-cached packages
        full_cmd = sudo_prefix + install_cmd_tpl + missing
        yield True, f"Detected {name} - running: {' '.join(full_cmd)}"
        ok_all = True
        for ok, line in _run_streaming(full_cmd):
            yield ok, line
            if not ok:
                ok_all = False
        still_missing = [tool for tool in missing if not shutil.which(tool)]
        if ok_all and not still_missing:
            yield True, "Dependencies installed successfully."
        elif still_missing:
            yield True, f"{', '.join(still_missing)} still not found on PATH after the install attempt - continuing anyway; Ollama's own installer will report clearly if this is still a problem."
        return

    yield True, "No supported package manager found (checked apt-get/dnf/yum/zypper/pacman/apk) - continuing anyway; install " + ", ".join(missing) + " manually if Ollama's own installer below reports it's still missing."


def install_ollama_stream():
    """Generator yielding (ok: bool, line: str) progress lines while
    installing Ollama for the detected OS via its OWN official install
    path - this module never bundles or hosts the Ollama binary itself:
    - Linux: _ensure_ollama_linux_deps() first auto-resolves the
      installer's OWN system-level dependencies (curl/awk/grep/sed/tee/
      xargs/zstd - most commonly just zstd, missing on many minimal/
      container images), then the official install script (curl -fsSL
      https://ollama.com/install.sh | sh)
    - macOS: Homebrew (`brew install ollama`) if available, else a
      manual-download pointer (a .dmg/GUI app install can't be safely
      driven headlessly from here)
    - Windows: winget if available, else downloads the official
      installer and launches it for the user to click through (silent
      CLI flags for that installer aren't officially documented/stable
      enough to rely on)
    Stops (returns) as soon as a step fails - never raises."""
    if is_ollama_installed():
        yield True, "Ollama is already installed - skipping installation."
        return

    os_label = detect_os_label()
    yield True, f"Detected OS: {os_label}. Starting Ollama installation…"

    if os_label == "linux":
        if not (shutil.which("curl") and shutil.which("sh")):
            yield False, "Neither 'curl' nor 'sh' is available to run Ollama's official installer. Install curl (e.g. `sudo dnf install curl` / `sudo apt install curl`) and try again, or install Ollama manually from https://ollama.com/download/linux."
            return
        # v4.14.2: proactively resolve Ollama's installer's OWN system
        # dependencies (curl/awk/grep/sed/tee/xargs/zstd - verified
        # against its real source, see _ensure_ollama_linux_deps()'s
        # docstring) before running it - closes a real, reported gap
        # where a missing `zstd` (routinely absent on minimal/container
        # Linux images) made the installer fail with a manual-install
        # instruction instead of this project resolving it automatically.
        for ok, line in _ensure_ollama_linux_deps():
            yield ok, line
        yield True, "Running Ollama's official installer (curl -fsSL https://ollama.com/install.sh | sh) - this needs internet access and may take a few minutes…"
        ok_all = True
        for ok, line in _run_streaming("curl -fsSL https://ollama.com/install.sh | sh", shell=True):
            yield ok, line
            if not ok:
                ok_all = False
        if not ok_all:
            return

    elif os_label == "macos":
        if shutil.which("brew"):
            yield True, "Homebrew found - running `brew install ollama`…"
            ok_all = True
            for ok, line in _run_streaming(["brew", "install", "ollama"]):
                yield ok, line
                if not ok:
                    ok_all = False
            if not ok_all:
                return
        else:
            yield False, "Homebrew isn't installed, so this can't install Ollama automatically on macOS. Install Homebrew (https://brew.sh) and try again, or download Ollama directly from https://ollama.com/download/mac."
            return

    elif os_label == "windows":
        if shutil.which("winget"):
            yield True, "winget found - running `winget install --id Ollama.Ollama -e --silent`…"
            ok_all = True
            for ok, line in _run_streaming([
                "winget", "install", "--id", "Ollama.Ollama", "-e",
                "--silent", "--accept-package-agreements", "--accept-source-agreements",
            ]):
                yield ok, line
                if not ok:
                    ok_all = False
            if not ok_all:
                yield True, "winget install reported an error - falling back to downloading the official installer directly…"
            else:
                # winget updates the machine/user PATH registry key, but
                # this already-running Python process's os.environ won't
                # see that change - find_ollama_executable()'s fallback
                # search paths cover the common winget/installer target,
                # so a later is_ollama_installed() check still succeeds
                # without needing to restart the server process.
                pass
        if not is_ollama_installed():
            yield True, "Downloading the official Ollama installer (OllamaSetup.exe)…"
            installer_path = os.path.join(tempfile.gettempdir(), "OllamaSetup.exe")
            try:
                urllib.request.urlretrieve("https://ollama.com/download/OllamaSetup.exe", installer_path)
            except Exception as e:
                yield False, f"Failed to download the Ollama installer: {e}. Download and run it manually from https://ollama.com/download/windows."
                return
            yield True, "Download complete. Launching the installer - please complete the setup wizard that just opened, then this will continue automatically once it detects Ollama is installed…"
            try:
                subprocess.Popen([installer_path])
            except OSError as e:
                yield False, f"Failed to launch the downloaded installer: {e}. Run {installer_path} manually."
                return
            deadline = time.time() + 600  # up to 10 minutes for the user to click through the GUI wizard
            while time.time() < deadline:
                if is_ollama_installed():
                    break
                time.sleep(3)
            else:
                yield False, "Timed out waiting for the installer to finish. If you completed the setup wizard, try clicking Start again."
                return
    else:
        yield False, f"Automatic installation isn't supported on this OS ({platform.system()}). Install Ollama manually from https://ollama.com, then try again."
        return

    if is_ollama_installed():
        yield True, "Ollama installed successfully."
    else:
        yield False, "Installation finished, but the 'ollama' executable still couldn't be found. You may need to open a new terminal/restart this server for a PATH update to take effect, or install manually from https://ollama.com."


def pull_model_stream(model_name):
    """Generator yielding (ok: bool, line: str) progress lines while
    running `ollama pull <model_name>` - the exact CLI command a user
    would otherwise have to run by hand after installing Ollama. Assumes
    the caller has already confirmed Ollama itself is installed/running;
    yields a clear error and returns immediately if not."""
    ollama_exe = find_ollama_executable()
    if not ollama_exe:
        yield False, "Ollama is not installed - install it first."
        return
    model_name = (model_name or "").strip() or "llama3.1"
    yield True, f"Pulling model '{model_name}' (this can take a while for larger models - it's a multi-gigabyte download)…"
    ok_all = True
    for ok, line in _run_streaming([ollama_exe, "pull", model_name]):
        yield ok, line
        if not ok:
            ok_all = False
    if ok_all:
        yield True, f"Model '{model_name}' is ready to use."
