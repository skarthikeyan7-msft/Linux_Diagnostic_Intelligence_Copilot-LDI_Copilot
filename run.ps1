# Linux Diagnostic Intelligence Copilot - LDI Copilot
# One-command local launcher: creates/uses a local venv, installs
# dependencies if needed, then starts the server and opens the browser.
# Works under both Windows PowerShell 5.1 and PowerShell 7+ (pwsh) - the
# latter also runs on Linux/macOS, so this script is portable there too.
# Prefer run.sh (bash) or run.bat (Command Prompt) if you'd rather not use
# PowerShell at all - all three launchers do the same thing.
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8756,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvDir = Join-Path $root ".venv"

# $IsWindows/$IsLinux/$IsMacOS are automatic variables in PowerShell 6+
# (pwsh) and don't exist in Windows PowerShell 5.1 - which only ever runs
# on Windows anyway, so default to true there. venv layout differs by
# platform: Windows puts the interpreter under Scripts\python.exe, POSIX
# (Linux/macOS) under bin/python.
$onWindows = $true
if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) {
    $onWindows = $IsWindows
}
$venvPython = if ($onWindows) { Join-Path $venvDir "Scripts\python.exe" } else { Join-Path $venvDir "bin/python" }

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment (.venv)..." -ForegroundColor Cyan
    $pythonCmd = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" } else { "python" }
    & $pythonCmd -m venv $venvDir
}

Write-Host "Installing/checking dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --disable-pip-version-check -r (Join-Path $root "backend/requirements.txt")

$url = "http://${HostAddress}:${Port}"
Write-Host ""
Write-Host "Starting LDI Copilot at $url" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
        param($u, $onWin)
        Start-Sleep -Seconds 2
        if ($onWin) {
            Start-Process $u
        } elseif (Get-Command xdg-open -ErrorAction SilentlyContinue) {
            & xdg-open $u
        } elseif (Get-Command open -ErrorAction SilentlyContinue) {
            & open $u
        }
    } -ArgumentList $url, $onWindows | Out-Null
}

Push-Location (Join-Path $root "backend")
try {
    & $venvPython app.py --host $HostAddress --port $Port
} finally {
    Pop-Location
}
