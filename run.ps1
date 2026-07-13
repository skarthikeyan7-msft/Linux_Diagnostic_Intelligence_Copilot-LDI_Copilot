# LDI Copilot (Linux Diagnostic Intelligence Copilot)
# One-command local launcher: creates/uses a local venv, installs
# dependencies if needed, then starts the server and opens the browser.
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8756,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvDir = Join-Path $root ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment (.venv)..." -ForegroundColor Cyan
    python -m venv $venvDir
}

Write-Host "Installing/checking dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --disable-pip-version-check -r (Join-Path $root "backend\requirements.txt")

$url = "http://${HostAddress}:${Port}"
Write-Host ""
Write-Host "Starting LDI Copilot at $url" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

if (-not $NoBrowser) {
    Start-Job -ScriptBlock {
        param($u)
        Start-Sleep -Seconds 2
        Start-Process $u
    } -ArgumentList $url | Out-Null
}

Push-Location (Join-Path $root "backend")
try {
    & $venvPython app.py --host $HostAddress --port $Port
} finally {
    Pop-Location
}
