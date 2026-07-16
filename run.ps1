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
    [switch]$NoBrowser,
    [switch]$Https,
    [string]$SslCertFile,
    [string]$SslKeyFile,
    [string]$AuthToken,
    [switch]$NoAuth,
    [switch]$RequireAuth,
    [switch]$SkipOllamaCheck
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvDir = Join-Path $root ".venv"
$minPyMajor = 3
$minPyMinor = 10

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

function Test-PyVersionOk {
    param([string]$Exe, [string[]]$ExtraArgs = @())
    try {
        & $Exe @ExtraArgs -c "import sys; sys.exit(0 if sys.version_info[:2] >= ($minPyMajor, $minPyMinor) else 1)" 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Get-PyVersionStr {
    param([string]$Exe, [string[]]$ExtraArgs = @())
    try {
        $v = & $Exe @ExtraArgs -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
        if ($LASTEXITCODE -eq 0 -and $v) { return $v.Trim() }
    } catch {}
    return "unknown"
}

# Resolve a Python interpreter meeting the minimum version. Priority:
# an explicit $env:PYTHON override (respected even if too old - fail
# loudly rather than silently substitute something else); then, on
# Windows, the official "py" launcher's version-selection flags (the
# standard way multiple installed Python versions coexist on Windows,
# unlike Linux/macOS's versioned-binary-name convention which run.sh
# handles instead); then bare python3/python on PATH.
$pythonExe = $null
$pythonArgs = @()
$envPython = $env:PYTHON
if ($envPython) {
    $resolved = Get-Command $envPython -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Write-Error "`$env:PYTHON is set to '$envPython' but that's not an executable on PATH."
        exit 1
    }
    if (-not (Test-PyVersionOk -Exe $envPython)) {
        $foundVer = Get-PyVersionStr -Exe $envPython
        Write-Error "`$env:PYTHON ('$envPython', version $foundVer) is older than the required Python $minPyMajor.$minPyMinor+. Point `$env:PYTHON at a newer interpreter and try again."
        exit 1
    }
    $pythonExe = $envPython
} else {
    if ($onWindows -and (Get-Command py -ErrorAction SilentlyContinue)) {
        foreach ($v in @("-3.13", "-3.12", "-3.11", "-3.10")) {
            if (Test-PyVersionOk -Exe "py" -ExtraArgs @($v)) {
                $pythonExe = "py"; $pythonArgs = @($v)
                break
            }
        }
    }
    if (-not $pythonExe) {
        foreach ($c in @("python3", "python")) {
            $cmd = Get-Command $c -ErrorAction SilentlyContinue
            if ($cmd -and (Test-PyVersionOk -Exe $c)) {
                $pythonExe = $c
                break
            }
        }
    }
}

if (-not $pythonExe) {
    Write-Host ""
    Write-Host "No Python $minPyMajor.$minPyMinor+ interpreter found." -ForegroundColor Red
    foreach ($c in @("python3", "python")) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Host "  - found '$c' -> Python $(Get-PyVersionStr -Exe $c) (too old)" -ForegroundColor Red
        }
    }
    Write-Host ""
    Write-Host "Install a newer Python from https://www.python.org/downloads/ (the installer" -ForegroundColor Yellow
    Write-Host "registers itself with the 'py' launcher, which this script prefers - or, if" -ForegroundColor Yellow
    Write-Host "you already have multiple versions installed via the launcher, this script" -ForegroundColor Yellow
    Write-Host "auto-detects 'py -3.10' through 'py -3.13')." -ForegroundColor Yellow
    Write-Host "Or point at a specific interpreter explicitly:" -ForegroundColor Yellow
    Write-Host "    `$env:PYTHON = 'C:\path\to\python.exe'; .\run.ps1" -ForegroundColor Yellow
    exit 1
}
$pythonVerStr = Get-PyVersionStr -Exe $pythonExe -ExtraArgs $pythonArgs

# A venv from a previous run against a too-old Python would otherwise be
# silently reused as-is - self-heal by recreating it rather than making
# the user manually delete .venv first.
if ((Test-Path $venvPython) -and -not (Test-PyVersionOk -Exe $venvPython)) {
    $staleVer = Get-PyVersionStr -Exe $venvPython
    Write-Host "Existing .venv was built with Python $staleVer (too old) - recreating it with $pythonExe $pythonArgs ($pythonVerStr)..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force $venvDir
}

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment (.venv) with $pythonExe $pythonArgs ($pythonVerStr)..." -ForegroundColor Cyan
    & $pythonExe @pythonArgs -m venv $venvDir
}

Write-Host "Installing/checking dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --disable-pip-version-check -r (Join-Path $root "backend/requirements.txt")

# Installs Ollama via its OWN official install path for the detected
# platform - this script never bundles or downloads the Ollama binary
# itself. Only ever called after the user has explicitly confirmed via
# Invoke-OllamaCheck below.
function Install-Ollama {
    if ($onWindows -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "winget found - running 'winget install --id Ollama.Ollama'..." -ForegroundColor Cyan
        try {
            winget install --id Ollama.Ollama -e --silent --accept-package-agreements --accept-source-agreements
            if (Get-Command ollama -ErrorAction SilentlyContinue) { return $true }
        } catch {
            Write-Host "winget install failed ($($_.Exception.Message)) - falling back to a direct download..." -ForegroundColor Yellow
        }
    }
    if ($onWindows) {
        Write-Host "Downloading the official Ollama installer (OllamaSetup.exe)..." -ForegroundColor Cyan
        $installerPath = Join-Path $env:TEMP "OllamaSetup.exe"
        try {
            Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $installerPath
        } catch {
            Write-Host "Failed to download the Ollama installer: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Download and run it manually from https://ollama.com/download/windows." -ForegroundColor Yellow
            return $false
        }
        Write-Host "Download complete. Launching the installer - complete the setup wizard that just opened..." -ForegroundColor Cyan
        try {
            Start-Process -FilePath $installerPath -Wait
        } catch {
            Write-Host "Failed to launch the installer: $($_.Exception.Message). Run $installerPath manually." -ForegroundColor Red
            return $false
        }
        return [bool](Get-Command ollama -ErrorAction SilentlyContinue)
    }
    if (Get-Command brew -ErrorAction SilentlyContinue) {
        Write-Host "Homebrew found - running 'brew install ollama'..." -ForegroundColor Cyan
        try {
            brew install ollama
            return [bool](Get-Command ollama -ErrorAction SilentlyContinue)
        } catch {
            Write-Host "brew install failed: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    Write-Host "Automatic Ollama installation isn't supported on this platform without winget or Homebrew." -ForegroundColor Yellow
    Write-Host "Install it manually from https://ollama.com." -ForegroundColor Yellow
    return $false
}

# Ollama is this project's default, fully-offline AI provider - most
# users will want it, but it's a separate download this script doesn't
# bundle. Prompts once per run (only when interactive - a non-interactive
# session, e.g. CI or a redirected/background launch, skips the prompt
# entirely rather than hanging forever waiting for input that will never
# arrive). Declining here is never remembered anywhere: the browser's
# own Start button (and the auto-start before Generate/chat) independently
# offers to install it again any time it's still missing, exactly like a
# fresh ask.
function Invoke-OllamaCheck {
    if ($SkipOllamaCheck) { return }
    if (Get-Command ollama -ErrorAction SilentlyContinue) { return }
    Write-Host ""
    Write-Host "Ollama (this project's default, fully-offline AI provider) was not found on PATH." -ForegroundColor Yellow
    if ([Console]::IsInputRedirected) {
        Write-Host "Non-interactive session - skipping the install prompt. You can still install it" -ForegroundColor Yellow
        Write-Host "later: rerun this script interactively, use the browser's Ollama 'Start' button" -ForegroundColor Yellow
        Write-Host "(it will offer to install it too), or install manually from https://ollama.com." -ForegroundColor Yellow
        return
    }
    $reply = Read-Host "Install Ollama now? [y/N]"
    if ($reply -match '^(y|yes)$') {
        if (Install-Ollama) {
            Write-Host "Ollama installed. Pull a model any time with: ollama pull llama3.1" -ForegroundColor Green
        } else {
            Write-Host "Ollama installation did not complete - you can still pick a different AI" -ForegroundColor Yellow
            Write-Host "provider in the UI, or try again later (rerun this script, or use the" -ForegroundColor Yellow
            Write-Host "browser's Ollama 'Start' button, which offers to install it too)." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipping Ollama installation. Pick a different AI provider in the UI, or" -ForegroundColor DarkGray
        Write-Host "install it later - the browser's Ollama 'Start' button will offer to" -ForegroundColor DarkGray
        Write-Host "install it again whenever you're ready." -ForegroundColor DarkGray
    }
}

Invoke-OllamaCheck

$url = if ($Https) { "https://${HostAddress}:${Port}" } else { "http://${HostAddress}:${Port}" }
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

$appArgs = @("--host", $HostAddress, "--port", $Port)
if ($Https) {
    $appArgs += "--https"
    if ($SslCertFile) { $appArgs += @("--ssl-certfile", $SslCertFile) }
    if ($SslKeyFile) { $appArgs += @("--ssl-keyfile", $SslKeyFile) }
}
if ($AuthToken) { $appArgs += @("--auth-token", $AuthToken) }
if ($NoAuth) { $appArgs += "--no-auth" }
if ($RequireAuth) { $appArgs += "--require-auth" }

Push-Location (Join-Path $root "backend")
try {
    & $venvPython app.py @appArgs
} finally {
    Pop-Location
}
