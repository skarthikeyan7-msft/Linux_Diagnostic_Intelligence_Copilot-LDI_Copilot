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
if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
echo Unknown option: %~1
exit /b 1

:usage
echo Usage: run.bat [--host ADDRESS] [--port PORT] [--no-browser]
exit /b 0

:args_done

set "ROOT=%~dp0"
set "VENVDIR=%ROOT%.venv"
set "VENVPY=%VENVDIR%\Scripts\python.exe"

if not exist "%VENVPY%" (
    echo Creating virtual environment ^(.venv^)...
    where python >nul 2>nul
    if errorlevel 1 (
        echo Python 3.10+ not found on PATH. Install it from https://python.org and try again.
        exit /b 1
    )
    python -m venv "%VENVDIR%"
)

echo Installing/checking dependencies...
"%VENVPY%" -m pip install --quiet --disable-pip-version-check -r "%ROOT%backend\requirements.txt"

set "URL=http://%HOSTADDR%:%PORT%"
echo.
echo Starting LDI Copilot at %URL%
echo Press Ctrl+C to stop.
echo.

if "%NOBROWSER%"=="0" (
    start "" /b cmd /c "ping -n 3 127.0.0.1 >nul & start "" "%URL%""
)

pushd "%ROOT%backend"
"%VENVPY%" app.py --host %HOSTADDR% --port %PORT%
popd
