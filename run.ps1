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
    [switch]$NoAuth
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

Push-Location (Join-Path $root "backend")
try {
    & $venvPython app.py @appArgs
} finally {
    Pop-Location
}
