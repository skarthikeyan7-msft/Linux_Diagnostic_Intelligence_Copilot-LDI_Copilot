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
SKIP_OLLAMA_CHECK=0
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
    --skip-ollama-check) SKIP_OLLAMA_CHECK=1; shift ;;
    -h|--help)
      echo "Usage: ./run.sh [--host ADDRESS] [--port PORT] [--no-browser] [--https] [--ssl-certfile FILE] [--ssl-keyfile FILE] [--auth-token TOKEN] [--no-auth] [--require-auth] [--skip-ollama-check]"
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

# Installs Ollama via its OWN official install path for the detected OS -
# this script never bundles or downloads the Ollama binary itself. Only
# ever called after the user has explicitly confirmed via _check_ollama
# below.
_install_ollama() {
  case "$(uname -s)" in
    Linux)
      if command -v curl >/dev/null 2>&1; then
        _ensure_ollama_linux_deps
        echo "Running Ollama's official installer (curl -fsSL https://ollama.com/install.sh | sh)..."
        curl -fsSL https://ollama.com/install.sh | sh
      else
        echo "curl isn't available, so this can't run Ollama's installer automatically." >&2
        echo "Install curl (e.g. 'sudo dnf install curl' / 'sudo apt install curl') and rerun," >&2
        echo "or install Ollama manually from https://ollama.com/download/linux." >&2
        return 1
      fi
      ;;
    Darwin)
      if command -v brew >/dev/null 2>&1; then
        echo "Running 'brew install ollama'..."
        brew install ollama
      else
        echo "Homebrew isn't installed, so this can't install Ollama automatically on macOS." >&2
        echo "Install Homebrew (https://brew.sh) and rerun, or download Ollama manually" >&2
        echo "from https://ollama.com/download/mac." >&2
        return 1
      fi
      ;;
    *)
      echo "Automatic Ollama installation isn't supported on this OS ($(uname -s))." >&2
      echo "Install it manually from https://ollama.com." >&2
      return 1
      ;;
  esac
}

# Ollama's own official Linux installer (verified directly against its
# real source - ollama/ollama on GitHub, scripts/install.sh - rather than
# guessed) requires curl/awk/grep/sed/tee/xargs (base tools, virtually
# always already present) AND, for every current release, `zstd` to
# extract the modern .tar.zst release asset it downloads - a tool that
# is routinely MISSING on minimal/container Linux base images and
# freshly provisioned VMs, and one Ollama's own installer only reports
# as an error rather than installing itself (the exact real-world gap
# this closes: "ERROR: This version requires zstd for extraction..."
# with no automatic recovery). Proactively detects and auto-installs
# whatever's missing via whichever package manager is actually on the
# system, BEFORE handing off to Ollama's installer - best-effort: if
# nothing can be auto-installed (no supported package manager, no sudo
# when needed), this just logs why and continues anyway, so Ollama's
# own installer still gets a chance to run and report its own clear
# error if a dependency turns out to still be missing.
_ensure_ollama_linux_deps() {
  local missing=()
  for tool in curl awk grep sed tee xargs zstd; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  echo "Ollama's installer needs the following tool(s), not currently on PATH: ${missing[*]}. Attempting to install automatically..."

  local sudo_cmd=()
  if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo_cmd=(sudo)
    else
      echo "Not running as root and 'sudo' isn't available - can't auto-install ${missing[*]}." >&2
      echo "Continuing anyway; Ollama's own installer below will report clearly if this is still a problem." >&2
      return 0
    fi
  fi

  local pkg_mgr="" install_cmd=()
  if command -v apt-get >/dev/null 2>&1; then
    pkg_mgr="apt-get"
    "${sudo_cmd[@]}" apt-get update -qq || true
    install_cmd=("${sudo_cmd[@]}" apt-get install -y "${missing[@]}")
  elif command -v dnf >/dev/null 2>&1; then
    pkg_mgr="dnf"; install_cmd=("${sudo_cmd[@]}" dnf install -y "${missing[@]}")
  elif command -v yum >/dev/null 2>&1; then
    pkg_mgr="yum"; install_cmd=("${sudo_cmd[@]}" yum install -y "${missing[@]}")
  elif command -v zypper >/dev/null 2>&1; then
    pkg_mgr="zypper"; install_cmd=("${sudo_cmd[@]}" zypper --non-interactive install "${missing[@]}")
  elif command -v pacman >/dev/null 2>&1; then
    pkg_mgr="pacman"; install_cmd=("${sudo_cmd[@]}" pacman -S --noconfirm "${missing[@]}")
  elif command -v apk >/dev/null 2>&1; then
    pkg_mgr="apk"
    "${sudo_cmd[@]}" apk update || true
    install_cmd=("${sudo_cmd[@]}" apk add "${missing[@]}")
  else
    echo "No supported package manager found (checked apt-get/dnf/yum/zypper/pacman/apk)." >&2
    echo "Continuing anyway; install ${missing[*]} manually if Ollama's installer below reports it's still missing." >&2
    return 0
  fi

  echo "Detected $pkg_mgr - running: ${install_cmd[*]}"
  if "${install_cmd[@]}"; then
    local still_missing=()
    for tool in "${missing[@]}"; do
      command -v "$tool" >/dev/null 2>&1 || still_missing+=("$tool")
    done
    if [[ ${#still_missing[@]} -gt 0 ]]; then
      echo "${still_missing[*]} still not found on PATH after the install attempt - continuing anyway." >&2
    else
      echo "Dependencies installed successfully."
    fi
  else
    echo "Automatic install of ${missing[*]} via $pkg_mgr failed - continuing anyway; Ollama's own installer below will report clearly if this is still a problem." >&2
  fi
  return 0
}

# Ollama is this project's default, fully-offline AI provider - most
# users will want it, but it's a separate download this script doesn't
# bundle. Prompts once per run (only when interactive - a non-TTY
# session, e.g. CI or a background/detached launch, skips the prompt
# entirely rather than hanging forever waiting for input that will
# never arrive). Declining here is never remembered anywhere: the
# browser's own Start button (and the auto-start before Generate/chat)
# independently offers to install it again any time it's still missing,
# exactly like a fresh ask.
_check_ollama() {
  if [[ "$SKIP_OLLAMA_CHECK" -eq 1 ]]; then
    return 0
  fi
  if command -v ollama >/dev/null 2>&1; then
    return 0
  fi
  echo ""
  echo "Ollama (this project's default, fully-offline AI provider) was not found on PATH."
  if [[ ! -t 0 ]]; then
    echo "Non-interactive session - skipping the install prompt. You can still install it" >&2
    echo "later: rerun this script interactively, use the browser's Ollama 'Start' button" >&2
    echo "(it will offer to install it too), or install manually from https://ollama.com." >&2
    return 0
  fi
  read -r -p "Install Ollama now? [y/N] " _ollama_reply || _ollama_reply=""
  case "$_ollama_reply" in
    [yY]|[yY][eE][sS])
      if _install_ollama; then
        echo "Ollama installed. Pull a model any time with: ollama pull llama3.1"
      else
        echo "Ollama installation did not complete - you can still pick a different AI" >&2
        echo "provider in the UI, or try again later (rerun this script, or use the" >&2
        echo "browser's Ollama 'Start' button, which offers to install it too)." >&2
      fi
      ;;
    *)
      echo "Skipping Ollama installation. Pick a different AI provider in the UI, or" >&2
      echo "install it later - the browser's Ollama 'Start' button will offer to" >&2
      echo "install it again whenever you're ready." >&2
      ;;
  esac
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

_check_ollama

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
