#!/usr/bin/env bash
# Linux Diagnostic Intelligence Copilot - LDI Copilot
# Stop script (bash) - the counterpart to run.sh/run.bat/run.ps1: stops
# the backend server, and (best-effort, via its own API) any Ollama
# instance THAT SERVER started and is managing. Mirrors run.sh's
# cross-platform design; use whichever matches the shell you're
# already in - stop.sh (bash), stop.bat (Command Prompt), stop.ps1
# (PowerShell) all do the same thing.
set -uo pipefail  # deliberately not -e: "nothing found"/"already stopped" are expected non-fatal outcomes here, not errors

# Git Bash/MSYS2 automatically rewrites any bare argument that LOOKS like
# a Unix absolute path (e.g. "/PID", "/FI") into a Windows path before
# handing it to a native .exe - which silently corrupts Windows-style
# single-slash switches like `taskkill.exe /PID 1234` into nonsense
# (verified directly: it becomes "C:/Program Files/Git/PID", causing
# taskkill to reject it as an invalid argument, so the process was
# never actually killed even though this script went on to report
# success). MSYS_NO_PATHCONV=1 disables that conversion for this whole
# script - harmless on real Linux/macOS/WSL, where it's simply unused.
export MSYS_NO_PATHCONV=1

HOST_ADDRESS="127.0.0.1"
PORT="8756"
SCHEME="http"
AUTH_TOKEN=""
FORCE=0
KILL_OLLAMA=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST_ADDRESS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --https) SCHEME="https"; shift ;;
    --auth-token) AUTH_TOKEN="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --kill-ollama) KILL_OLLAMA=1; shift ;;
    -h|--help)
      echo "Usage: ./stop.sh [--host ADDRESS] [--port PORT] [--https] [--auth-token TOKEN] [--force] [--kill-ollama]"
      echo ""
      echo "  --host/--port/--https  must match how you started the server (run.sh's own"
      echo "                         --host/--port/--https), so this script can find it."
      echo "  --auth-token           needed only if the server is running with an auth gate"
      echo "                         (--auth-token mode) - lets this script's best-effort"
      echo "                         'ask the server to stop its own managed Ollama' step"
      echo "                         succeed. Not needed for per-user accounts mode or the"
      echo "                         default no-auth loopback case; the actual process-kill"
      echo "                         step below never needs it either way."
      echo "  --force                also stop whatever's listening on --port even if it"
      echo "                         doesn't look like LDI Copilot's own server process -"
      echo "                         use only if you're sure --port isn't shared with"
      echo "                         something unrelated."
      echo "  --kill-ollama          also force-stop EVERY 'ollama serve' process on this"
      echo "                         machine, including ones LDI Copilot didn't start"
      echo "                         itself (e.g. the Ollama desktop app, or an instance"
      echo "                         you started manually). Off by default - mirrors the"
      echo "                         app's own Stop button, which never touches an"
      echo "                         Ollama instance it doesn't own unless you ask here."
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

BASE_URL="${SCHEME}://${HOST_ADDRESS}:${PORT}"
STOPPED_ANYTHING=0
CURL_AUTH=()
[[ -n "$AUTH_TOKEN" ]] && CURL_AUTH=(-u "ldi:$AUTH_TOKEN")

_get_cmdline() {
  # /proc/<pid>/cmdline (Linux) is NUL-separated and never truncated -
  # far more reliable than `ps -o args=`, which some distros/terminal
  # widths truncate. Falls back to `ps` on macOS, which has no /proc.
  # On Git Bash/MSYS2 (Windows), neither of those can see a genuine
  # Windows process's real command line at all - ps there is a
  # from-scratch reimplementation, not a view into procfs - so as a
  # last resort, ask PowerShell (always on PATH on Windows, even from
  # Git Bash) via WMI/CIM instead.
  local pid="$1"
  local cmdline=""
  if [[ -r "/proc/$pid/cmdline" ]]; then
    cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
  fi
  if [[ -z "$cmdline" ]]; then
    cmdline="$(ps -p "$pid" -o command= 2>/dev/null)"
  fi
  if [[ -z "$cmdline" ]] && command -v powershell.exe >/dev/null 2>&1; then
    cmdline="$(powershell.exe -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\" -ErrorAction SilentlyContinue).CommandLine" 2>/dev/null | tr -d '\r')"
  fi
  echo "$cmdline"
}

# A real Windows process not spawned from within this MSYS/Git-Bash
# session's own process tree has no corresponding entry under /proc -
# MSYS bash's `kill`/`kill -0` builtins can't actually deliver a signal
# to (or even query) it at all in that case, silently no-op'ing instead
# of erroring, which is what made an earlier version of this script
# falsely report success without the server actually stopping. Detect
# that case via the same /proc check _get_cmdline() uses, and fall back
# to taskkill.exe/tasklist.exe (always on PATH on Windows, and correct
# regardless of which subsystem started the target process) there.
_pid_alive() {
  local pid="$1"
  if [[ -d "/proc/$pid" ]]; then
    kill -0 "$pid" 2>/dev/null
  elif command -v tasklist.exe >/dev/null 2>&1; then
    tasklist.exe /FI "PID eq $pid" 2>/dev/null | grep -qE "[[:space:]]$pid[[:space:]]"
  else
    kill -0 "$pid" 2>/dev/null
  fi
}

_kill_pid() {
  local pid="$1" force="${2:-0}"
  if [[ -d "/proc/$pid" ]]; then
    if [[ "$force" -eq 1 ]]; then kill -9 "$pid" 2>/dev/null; else kill "$pid" 2>/dev/null; fi
  elif command -v taskkill.exe >/dev/null 2>&1; then
    if [[ "$force" -eq 1 ]]; then taskkill.exe /PID "$pid" /F >/dev/null 2>&1; else taskkill.exe /PID "$pid" >/dev/null 2>&1; fi
  else
    if [[ "$force" -eq 1 ]]; then kill -9 "$pid" 2>/dev/null; else kill "$pid" 2>/dev/null; fi
  fi
}

echo "Checking for a running LDI Copilot server at $BASE_URL ..."

# Best-effort, in-band: if the server is reachable, ask IT to stop any
# Ollama instance it manages via its own POST /api/ollama/stop. This
# reuses backend/ai/ollama_manager.py's existing safeguard - it only
# ever stops an Ollama instance the app itself started, never an
# externally-running one (e.g. the Ollama desktop app) - so this step
# alone can never do anything more aggressive than the app's own Stop
# button already would. See --kill-ollama above for the more aggressive,
# opt-in alternative.
if curl -fsS -m 5 "${CURL_AUTH[@]}" "$BASE_URL/api/health" >/dev/null 2>&1; then
  echo "Server is up - asking it to stop any Ollama instance it manages..."
  OLLAMA_STOP_RESULT="$(curl -fsS -m 10 -X POST "${CURL_AUTH[@]}" "$BASE_URL/api/ollama/stop" 2>/dev/null || echo '{}')"
  if echo "$OLLAMA_STOP_RESULT" | grep -q '"stopped": *true'; then
    echo "  Ollama (managed by this app) stopped."
    STOPPED_ANYTHING=1
  else
    echo "  No Ollama instance managed by this app was running (or this call needed --auth-token - the process-kill step below will still work either way)."
  fi
else
  echo "Server did not respond at $BASE_URL - it may already be stopped, or running on a different host/port (pass --host/--port to match how you started it)."
fi

# Find whatever process is bound to $PORT - this is how we locate the
# backend/app.py process itself, regardless of how it was launched
# (run.sh directly, one of the other two launchers, or a bare `python
# backend/app.py`). Priority: ss (present by default on RHEL/CentOS/
# Fedora, this project's own documented deployment target) -> lsof
# (common on Debian/Ubuntu/macOS) -> fuser -> netstat (Windows' own
# netstat.exe, reachable on PATH from Git Bash/MSYS2, which has none
# of the above three - this is what makes stop.sh actually work when
# run via Git Bash on Windows, not just "real" Linux/macOS/WSL).
PIDS=""
if command -v ss >/dev/null 2>&1; then
  PIDS="$(ss -ltnp 2>/dev/null | grep -E ":${PORT}[[:space:]]" | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)"
fi
if [[ -z "$PIDS" ]] && command -v lsof >/dev/null 2>&1; then
  PIDS="$(lsof -ti tcp:"$PORT" 2>/dev/null || true)"
fi
if [[ -z "$PIDS" ]] && command -v fuser >/dev/null 2>&1; then
  PIDS="$(fuser "$PORT"/tcp 2>&1 | grep -oE '[0-9]+' || true)"
fi
if [[ -z "$PIDS" ]] && command -v netstat >/dev/null 2>&1; then
  # Windows netstat -ano columns: Proto  Local Address  Foreign Address  State  PID
  # - only ever matches TCP+LISTENING lines (UDP has no State column at
  # all, so it can never match "LISTENING"), so the last field really
  # is the PID here. Assumes an English-language Windows install (the
  # STATE text is localized on some non-English Windows builds) - a
  # reasonable, documented limitation rather than solving every locale.
  PIDS="$(netstat -ano 2>/dev/null | grep -E ":${PORT}[[:space:]]" | grep -i LISTENING | awk '{print $NF}' | sort -u)"
fi

if [[ -n "$PIDS" ]]; then
  for pid in $PIDS; do
    CMDLINE="$(_get_cmdline "$pid")"
    if [[ "$CMDLINE" == *"app.py"* ]] || [[ "$CMDLINE" == *"uvicorn"* ]]; then
      echo "Stopping LDI Copilot server process (PID $pid: $CMDLINE)..."
    elif [[ "$FORCE" -eq 1 ]]; then
      echo "WARNING: PID $pid on port $PORT doesn't look like LDI Copilot's server (cmdline: $CMDLINE) - stopping anyway because --force was passed."
    else
      echo "WARNING: PID $pid is listening on port $PORT but doesn't look like LDI Copilot's server (cmdline: $CMDLINE)."
      echo "  NOT stopping it - pass --force to stop it anyway, or double-check --port matches how you started the server."
      continue
    fi
    _kill_pid "$pid" 0
    for _ in 1 2 3 4 5; do
      _pid_alive "$pid" || break
      sleep 1
    done
    if _pid_alive "$pid"; then
      echo "  Still running after 5s - force-killing..."
      _kill_pid "$pid" 1
    fi
    STOPPED_ANYTHING=1
  done
else
  echo "No process found listening on port $PORT."
fi

if [[ "$KILL_OLLAMA" -eq 1 ]]; then
  echo "Stopping ALL 'ollama serve' processes on this machine (--kill-ollama)..."
  OLLAMA_PIDS=""
  if command -v pgrep >/dev/null 2>&1; then
    OLLAMA_PIDS="$(pgrep -f "ollama serve" 2>/dev/null || true)"
  elif command -v tasklist.exe >/dev/null 2>&1; then
    # Git Bash/MSYS2 has no pgrep - tasklist's CSV output includes the
    # image name and PID as the first two fields, which is enough to
    # find every "ollama.exe" process (Windows doesn't distinguish
    # "ollama serve" from other subcommands at the process-list level,
    # so this matches the same set --kill-ollama's own help text already
    # documents: ALL ollama processes, not just ones started by serve).
    OLLAMA_PIDS="$(tasklist.exe /FI "IMAGENAME eq ollama.exe" /FO CSV 2>/dev/null | tail -n +2 | awk -F',' '{gsub(/"/,"",$2); print $2}')"
  fi
  if [[ -n "$OLLAMA_PIDS" ]]; then
    for pid in $OLLAMA_PIDS; do
      echo "  Stopping ollama serve (PID $pid)..."
      _kill_pid "$pid" 0
    done
    STOPPED_ANYTHING=1
  else
    echo "  No 'ollama serve' process found."
  fi
fi

echo ""
if [[ "$STOPPED_ANYTHING" -eq 1 ]]; then
  echo "Done - LDI Copilot has been stopped."
else
  echo "Nothing appeared to be running."
fi
