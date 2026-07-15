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
