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
HTTPS=0
SSL_CERTFILE=""
SSL_KEYFILE=""
AUTH_TOKEN=""
NO_AUTH=0
REQUIRE_AUTH=0
MIN_PY_MAJOR=3
MIN_PY_MINOR=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST_ADDRESS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --no-browser) OPEN_BROWSER=0; shift ;;
    --https) HTTPS=1; shift ;;
    --ssl-certfile) SSL_CERTFILE="$2"; shift 2 ;;
    --ssl-keyfile) SSL_KEYFILE="$2"; shift 2 ;;
    --auth-token) AUTH_TOKEN="$2"; shift 2 ;;
    --no-auth) NO_AUTH=1; shift ;;
    --require-auth) REQUIRE_AUTH=1; shift ;;
    -h|--help)
      echo "Usage: ./run.sh [--host ADDRESS] [--port PORT] [--no-browser] [--https] [--ssl-certfile FILE] [--ssl-keyfile FILE] [--auth-token TOKEN] [--no-auth] [--require-auth]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

_py_version_ok() {
  "$1" -c "import sys; sys.exit(0 if sys.version_info[:2] >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1)" 2>/dev/null
}

_py_version_str() {
  "$1" -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>/dev/null || echo "unknown"
}

_python_not_found_help() {
  echo "" >&2
  echo "No Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ interpreter found on PATH." >&2
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      echo "  - found '$candidate' -> Python $(_py_version_str "$candidate") (too old)" >&2
    fi
  done
  echo "" >&2
  echo "This most commonly happens on RHEL/CentOS/Alma/Rocky 8, whose default" >&2
  echo "python3 is Python 3.6 - long past upstream end-of-life and too old for" >&2
  echo "this project's dependencies (FastAPI/Pydantic need 3.8+; this codebase's" >&2
  echo "own type hints need 3.10+). A newer interpreter is usually just a" >&2
  echo "package install away, without touching the system default python3:" >&2
  echo "    RHEL/CentOS/Alma/Rocky/Fedora:  sudo dnf install python3.11" >&2
  echo "    Debian/Ubuntu:                  sudo apt install python3.11" >&2
  echo "    macOS (Homebrew):                brew install python@3.11" >&2
  echo "  or via https://www.python.org/downloads/ / pyenv." >&2
  echo "" >&2
  echo "Once installed, either rerun (this script auto-detects python3.10/" >&2
  echo "3.11/3.12/3.13 on PATH ahead of a too-old bare python3/python), or" >&2
  echo "point at it explicitly:" >&2
  echo "    PYTHON=/path/to/python3.11 ./run.sh" >&2
}

# Resolve a Python interpreter meeting the minimum version, in priority
# order: an explicit $PYTHON override (respected even if it turns out too
# old - the user asked for it explicitly, so fail loudly rather than
# silently substitute something else) - then versioned binaries newest-
# first (RHEL/CentOS/Fedora commonly ship these ALONGSIDE an old default
# python3/python, e.g. RHEL 8's default python3 is 3.6 while python3.11
# is one `dnf install` away and already satisfies this project's
# requirements) - then the bare python3/python names last.
PYTHON_BIN="${PYTHON:-}"
if [[ -n "$PYTHON_BIN" ]]; then
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "\$PYTHON is set to '$PYTHON_BIN' but that's not an executable on PATH." >&2
    exit 1
  fi
  if ! _py_version_ok "$PYTHON_BIN"; then
    echo "\$PYTHON ('$PYTHON_BIN', version $(_py_version_str "$PYTHON_BIN")) is older than the required Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+. Point \$PYTHON at a newer interpreter and try again." >&2
    exit 1
  fi
else
  for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && _py_version_ok "$candidate"; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [[ -z "$PYTHON_BIN" ]]; then
  _python_not_found_help
  exit 1
fi

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

# A venv from a previous run against a too-old Python (e.g. RHEL 8's
# default python3=3.6, before a newer interpreter was installed) would
# otherwise be silently reused as-is - self-heal by recreating it rather
# than making the user manually `rm -rf .venv` first.
if [[ -n "$VENV_PYTHON" ]] && ! _py_version_ok "$VENV_PYTHON"; then
  echo "Existing .venv was built with Python $(_py_version_str "$VENV_PYTHON") (too old) - recreating it with $PYTHON_BIN ($(_py_version_str "$PYTHON_BIN"))..."
  rm -rf "$VENV_DIR"
  VENV_PYTHON=""
fi

if [[ -z "$VENV_PYTHON" ]]; then
  echo "Creating virtual environment (.venv) with $PYTHON_BIN ($(_py_version_str "$PYTHON_BIN"))..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
  if [[ -f "$VENV_DIR/bin/python" ]]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
  else
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
  fi
fi

echo "Installing/checking dependencies..."
"$VENV_PYTHON" -m pip install --quiet --disable-pip-version-check -r "$ROOT_DIR/backend/requirements.txt"

APP_ARGS=(--host "$HOST_ADDRESS" --port "$PORT")
SCHEME="http"
if [[ "$HTTPS" -eq 1 ]]; then
  SCHEME="https"
  APP_ARGS+=(--https)
  [[ -n "$SSL_CERTFILE" ]] && APP_ARGS+=(--ssl-certfile "$SSL_CERTFILE")
  [[ -n "$SSL_KEYFILE" ]] && APP_ARGS+=(--ssl-keyfile "$SSL_KEYFILE")
fi
[[ -n "$AUTH_TOKEN" ]] && APP_ARGS+=(--auth-token "$AUTH_TOKEN")
[[ "$NO_AUTH" -eq 1 ]] && APP_ARGS+=(--no-auth)
[[ "$REQUIRE_AUTH" -eq 1 ]] && APP_ARGS+=(--require-auth)

URL="${SCHEME}://${HOST_ADDRESS}:${PORT}"
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
exec "$VENV_PYTHON" app.py "${APP_ARGS[@]}"
