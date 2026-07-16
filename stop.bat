@echo off
setlocal enabledelayedexpansion
rem Linux Diagnostic Intelligence Copilot - LDI Copilot
rem Stop script for plain Windows Command Prompt (no PowerShell
rem knowledge required to use it) - the counterpart to
rem run.bat/run.ps1/run.sh. Delegates the actual port-lookup/
rem process-kill/API-call logic to stop.ps1 (same approach run.bat
rem already uses for downloading the Ollama installer) since reliably
rem parsing netstat/find-PID-by-port output in raw batch is fragile
rem across locales/Windows versions - PowerShell's Get-NetTCPConnection
rem and Invoke-RestMethod are not.

set "HOSTADDR=127.0.0.1"
set "PORT=8756"
set "HTTPS=0"
set "AUTHTOKEN="
set "FORCE=0"
set "KILLOLLAMA=0"

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
if /i "%~1"=="--https" (
    set "HTTPS=1"
    shift
    goto parse_args
)
if /i "%~1"=="--auth-token" (
    set "AUTHTOKEN=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--force" (
    set "FORCE=1"
    shift
    goto parse_args
)
if /i "%~1"=="--kill-ollama" (
    set "KILLOLLAMA=1"
    shift
    goto parse_args
)
if /i "%~1"=="-h" goto usage
if /i "%~1"=="--help" goto usage
echo Unknown option: %~1
exit /b 1

:usage
echo Usage: stop.bat [--host ADDRESS] [--port PORT] [--https] [--auth-token TOKEN] [--force] [--kill-ollama]
exit /b 0

:args_done

set "ROOT=%~dp0"
set "PSARGS=-HostAddress "%HOSTADDR%" -Port %PORT%"
if "%HTTPS%"=="1" set "PSARGS=%PSARGS% -Https"
if defined AUTHTOKEN set "PSARGS=%PSARGS% -AuthToken "%AUTHTOKEN%""
if "%FORCE%"=="1" set "PSARGS=%PSARGS% -Force"
if "%KILLOLLAMA%"=="1" set "PSARGS=%PSARGS% -KillOllama"

powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%stop.ps1" %PSARGS%
exit /b %ERRORLEVEL%
