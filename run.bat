@echo off
setlocal enabledelayedexpansion
rem Linux Diagnostic Intelligence Copilot - LDI Copilot
rem One-command local launcher for plain Windows Command Prompt (no
rem PowerShell required). Mirrors run.ps1 (PowerShell/pwsh) and run.sh
rem (bash) - pick whichever launcher matches the shell you're already in;
rem all three do the same thing.

set "HOSTADDR=127.0.0.1"
set "PORT=8756"
set "NOBROWSER=0"
set "HTTPS=0"
set "SSLCERTFILE="
set "SSLKEYFILE="
set "AUTHTOKEN="
set "NOAUTH=0"
set "REQUIREAUTH=0"
set "SKIPOLLAMACHECK=0"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--host" (
    set "HOSTADDR=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--port" (
    set "PORT=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--no-browser" (
    set "NOBROWSER=1"
    shift
    goto parse_args
)
if /i "%~1"=="--https" (
    set "HTTPS=1"
    shift
    goto parse_args
)
if /i "%~1"=="--ssl-certfile" (
    set "SSLCERTFILE=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--ssl-keyfile" (
    set "SSLKEYFILE=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--auth-token" (
    set "AUTHTOKEN=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--no-auth" (
    set "NOAUTH=1"
    shift
    goto parse_args
)
if /i "%~1"=="--require-auth" (
    set "REQUIREAUTH=1"
    shift
    goto parse_args
)
if /i "%~1"=="--skip-ollama-check" (
    set "SKIPOLLAMACHECK=1"
    shift
    goto parse_args
)
if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
echo Unknown option: %~1
exit /b 1

:usage
echo Usage: run.bat [--host ADDRESS] [--port PORT] [--no-browser] [--https] [--ssl-certfile FILE] [--ssl-keyfile FILE] [--auth-token TOKEN] [--no-auth] [--require-auth] [--skip-ollama-check]
exit /b 0

:args_done

set "ROOT=%~dp0"
set "VENVDIR=%ROOT%.venv"
set "VENVPY=%VENVDIR%\Scripts\python.exe"
set "VERCHECK=import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)"
set "VERSTR=import sys; print('.'.join(map(str, sys.version_info[:3])))"

rem Resolve a Python interpreter meeting the minimum version (3.10+).
rem Priority: an explicit %PYTHON% override (respected even if too old -
rem fail loudly rather than silently substitute something else); then
rem the official "py" launcher's version-selection flags (the standard
rem way multiple installed Python versions coexist on Windows); then
rem bare python3/python on PATH.
set "PYEXE="
set "PYARG="

if defined PYTHON (
    where "%PYTHON%" >nul 2>nul
    if errorlevel 1 (
        echo %PYTHON% is set but that's not an executable on PATH.
        exit /b 1
    )
    "%PYTHON%" -c "%VERCHECK%" >nul 2>nul
    if errorlevel 1 (
        for /f "delims=" %%V in ('"%PYTHON%" -c "%VERSTR%" 2^>nul') do set "FOUNDVER=%%V"
        echo %PYTHON% ^(version !FOUNDVER!^) is older than the required Python 3.10+. Set PYTHON to a newer interpreter and try again.
        exit /b 1
    )
    set "PYEXE=%PYTHON%"
) else (
    where py >nul 2>nul
    if not errorlevel 1 (
        for %%V in (-3.13 -3.12 -3.11 -3.10) do (
            if not defined PYEXE (
                py %%V -c "%VERCHECK%" >nul 2>nul
                if not errorlevel 1 (
                    set "PYEXE=py"
                    set "PYARG=%%V"
                )
            )
        )
    )
    if not defined PYEXE (
        for %%C in (python3 python) do (
            if not defined PYEXE (
                where %%C >nul 2>nul
                if not errorlevel 1 (
                    %%C -c "%VERCHECK%" >nul 2>nul
                    if not errorlevel 1 set "PYEXE=%%C"
                )
            )
        )
    )
)

if not defined PYEXE (
    echo.
    echo No Python 3.10+ interpreter found.
    where python3 >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%V in ('python3 -c "%VERSTR%" 2^>nul') do echo   - found 'python3' -^> Python %%V ^(too old^)
    )
    where python >nul 2>nul
    if not errorlevel 1 (
        for /f "delims=" %%V in ('python -c "%VERSTR%" 2^>nul') do echo   - found 'python' -^> Python %%V ^(too old^)
    )
    echo.
    echo Install a newer Python from https://www.python.org/downloads/ - the installer
    echo registers itself with the "py" launcher, which this script prefers ^(or, if you
    echo already have multiple versions installed via the launcher, this script
    echo auto-detects "py -3.10" through "py -3.13"^).
    echo Or point at a specific interpreter explicitly:
    echo     set PYTHON=C:\path\to\python.exe ^&^& run.bat
    exit /b 1
)
for /f "delims=" %%V in ('%PYEXE% %PYARG% -c "%VERSTR%" 2^>nul') do set "PYVER=%%V"

rem A venv from a previous run against a too-old Python would otherwise
rem be silently reused as-is - self-heal by recreating it rather than
rem making the user manually delete .venv first.
if exist "%VENVPY%" (
    "%VENVPY%" -c "%VERCHECK%" >nul 2>nul
    if errorlevel 1 (
        for /f "delims=" %%V in ('"%VENVPY%" -c "%VERSTR%" 2^>nul') do set "STALEVER=%%V"
        echo Existing .venv was built with Python !STALEVER! ^(too old^) - recreating it with %PYEXE% %PYARG% ^(!PYVER!^)...
        rmdir /s /q "%VENVDIR%"
    )
)

if not exist "%VENVPY%" (
    echo Creating virtual environment ^(.venv^) with %PYEXE% %PYARG% ^(!PYVER!^)...
    %PYEXE% %PYARG% -m venv "%VENVDIR%"
)

echo Installing/checking dependencies...
"%VENVPY%" -m pip install --quiet --disable-pip-version-check -r "%ROOT%backend\requirements.txt"

call :check_ollama

set "URL=http://%HOSTADDR%:%PORT%"
set "APPARGS=--host %HOSTADDR% --port %PORT%"
if "%HTTPS%"=="1" (
    set "URL=https://%HOSTADDR%:%PORT%"
    set "APPARGS=%APPARGS% --https"
    if defined SSLCERTFILE set "APPARGS=%APPARGS% --ssl-certfile %SSLCERTFILE%"
    if defined SSLKEYFILE set "APPARGS=%APPARGS% --ssl-keyfile %SSLKEYFILE%"
)
if defined AUTHTOKEN set "APPARGS=%APPARGS% --auth-token %AUTHTOKEN%"
if "%NOAUTH%"=="1" set "APPARGS=%APPARGS% --no-auth"
if "%REQUIREAUTH%"=="1" set "APPARGS=%APPARGS% --require-auth"
echo.
echo Starting LDI Copilot at %URL%
echo Press Ctrl+C to stop.
echo.

if "%NOBROWSER%"=="0" (
    start "" /b cmd /c "ping -n 3 127.0.0.1 >nul & start "" "%URL%""
)

pushd "%ROOT%backend"
"%VENVPY%" app.py %APPARGS%
popd
exit /b 0

rem ---------------------------------------------------------------------
rem Ollama is this project's default, fully-offline AI provider - most
rem users will want it, but it's a separate download this script doesn't
rem bundle. Prompts once per run (skipped entirely with --skip-ollama-check).
rem Declining here is never remembered anywhere: the browser's own Start
rem button (and the auto-start before Generate/chat) independently offers
rem to install it again any time it's still missing, exactly like a fresh
rem ask. Installs via Ollama's OWN official path for Windows - this script
rem never bundles or downloads the Ollama binary itself: winget if
rem available, else the official installer (downloaded and launched for
rem the user to click through - silent CLI flags for that installer
rem aren't officially documented/stable enough to rely on).
rem ---------------------------------------------------------------------
:check_ollama
if "%SKIPOLLAMACHECK%"=="1" exit /b 0
where ollama >nul 2>nul
if not errorlevel 1 exit /b 0
echo.
echo Ollama ^(this project's default, fully-offline AI provider^) was not found on PATH.
set "OLLAMAREPLY="
set /p "OLLAMAREPLY=Install Ollama now? [y/N]: "
if /i "%OLLAMAREPLY%"=="y" goto install_ollama
if /i "%OLLAMAREPLY%"=="yes" goto install_ollama
echo Skipping Ollama installation. Pick a different AI provider in the UI, or
echo install it later - the browser's Ollama 'Start' button will offer to
echo install it again whenever you're ready.
exit /b 0

:install_ollama
where winget >nul 2>nul
if errorlevel 1 goto ollama_download_installer
echo winget found - running "winget install --id Ollama.Ollama"...
winget install --id Ollama.Ollama -e --silent --accept-package-agreements --accept-source-agreements
where ollama >nul 2>nul
if not errorlevel 1 (
    echo Ollama installed. Pull a model any time with: ollama pull llama3.1
    exit /b 0
)
echo winget install did not result in 'ollama' being available - falling back to a direct download...

:ollama_download_installer
echo Downloading the official Ollama installer ^(OllamaSetup.exe^)...
set "OLLAMAINSTALLER=%TEMP%\OllamaSetup.exe"
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'https://ollama.com/download/OllamaSetup.exe' -OutFile '%OLLAMAINSTALLER%' } catch { exit 1 }"
if errorlevel 1 (
    echo Failed to download the Ollama installer. Download and run it manually from
    echo https://ollama.com/download/windows.
    exit /b 0
)
echo Download complete. Launching the installer - complete the setup wizard that just opened...
start /wait "" "%OLLAMAINSTALLER%"
where ollama >nul 2>nul
if not errorlevel 1 (
    echo Ollama installed. Pull a model any time with: ollama pull llama3.1
) else (
    echo Ollama installation did not complete - you can still pick a different AI
    echo provider in the UI, or try again later ^(rerun this script, or use the
    echo browser's Ollama 'Start' button, which offers to install it too^).
)
exit /b 0
