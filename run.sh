#!/usr/bin/env bash
# Linux Diagnostic Intelligence Copilot - LDI Copilot
# One-command local launcher for bash (Linux / macOS / WSL / Git Bash):
# creates/uses a local venv, installs dependencies if needed, then starts
# the server and opens the browser. Mirrors run.ps1 (Windows PowerShell /
# pwsh) and run.bat (Command Prompt) - pick whichever launcher matches the
# shell you're already in; all three do the same thing.
set -euo pipefail

HOST_ADDRESS="127.0.0.1"
PORT="8756"
OPEN_BROWSER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST_ADDRESS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --no-browser) OPEN_BROWSER=0; shift ;;
    -h|--help)
      echo "Usage: ./run.sh [--host ADDRESS] [--port PORT] [--no-browser]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

# venv layout differs by platform: POSIX venvs (Linux/macOS/WSL) put the
# interpreter under bin/python; a venv created against a Windows Python
# (e.g. this same repo also used from PowerShell on the same machine)
# uses Scripts/python.exe instead - check both rather than assuming.
VENV_PYTHON=""
if [[ -f "$VENV_DIR/bin/python" ]]; then
  VENV_PYTHON="$VENV_DIR/bin/python"
elif [[ -f "$VENV_DIR/Scripts/python.exe" ]]; then
  VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
fi

PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "Python 3.10+ not found on PATH (tried python3, python). Install it, or set \$PYTHON to its full path." >&2
    exit 1
  fi
fi

if [[ -z "$VENV_PYTHON" ]]; then
  echo "Creating virtual environment (.venv)..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  if [[ -f "$VENV_DIR/bin/python" ]]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
  else
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
  fi
fi

echo "Installing/checking dependencies..."
"$VENV_PYTHON" -m pip install --quiet --disable-pip-version-check -r "$ROOT_DIR/backend/requirements.txt"

URL="http://${HOST_ADDRESS}:${PORT}"
echo ""
echo "Starting LDI Copilot at $URL"
echo "Press Ctrl+C to stop."
echo ""

if [[ "$OPEN_BROWSER" -eq 1 ]]; then
  (
    sleep 2
    if command -v xdg-open >/dev/null 2>&1; then
      xdg-open "$URL" >/dev/null 2>&1 || true
    elif command -v open >/dev/null 2>&1; then
      open "$URL" >/dev/null 2>&1 || true
    elif command -v wslview >/dev/null 2>&1; then
      wslview "$URL" >/dev/null 2>&1 || true
    elif command -v powershell.exe >/dev/null 2>&1; then
      powershell.exe -NoProfile -Command "Start-Process '$URL'" >/dev/null 2>&1 || true
    fi
  ) &
fi

cd "$ROOT_DIR/backend"
exec "$VENV_PYTHON" app.py --host "$HOST_ADDRESS" --port "$PORT"
