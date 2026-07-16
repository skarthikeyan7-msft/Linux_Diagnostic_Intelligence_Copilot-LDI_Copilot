# Linux Diagnostic Intelligence Copilot - LDI Copilot
# Stop script (PowerShell) - the counterpart to run.ps1/run.bat/run.sh:
# stops the backend server, and (best-effort, via its own API) any
# Ollama instance THAT SERVER started and is managing. Works under both
# Windows PowerShell 5.1 and PowerShell 7+. Prefer stop.sh (bash) or
# stop.bat (Command Prompt) if you'd rather not use PowerShell at all -
# all three do the same thing.
param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8756,
    [switch]$Https,
    [string]$AuthToken,
    [switch]$Force,
    [switch]$KillOllama
)

$scheme = if ($Https) { "https" } else { "http" }
$baseUrl = "${scheme}://${HostAddress}:${Port}"
$stoppedAnything = $false

# -SkipCertificateCheck only exists on Invoke-WebRequest/Invoke-RestMethod
# in PowerShell 6+ (pwsh) - Windows PowerShell 5.1 doesn't recognize it
# at all, which throws before the request is even attempted. Try with it
# first (needed for a self-signed --https server); fall back without it
# on ANY failure from that first attempt, so this works unmodified on
# both 5.1 and 7+, and against both a plain-http and self-signed-https
# server, without needing to pin an exact exception type.
function Invoke-LdiRequest {
    param([string]$Uri, [string]$Method = "Get", [hashtable]$Headers = @{})
    try {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -TimeoutSec 10 -SkipCertificateCheck -ErrorAction Stop
    } catch {
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
    }
}

$authHeaders = @{}
if ($AuthToken) {
    $cred = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("ldi:$AuthToken"))
    $authHeaders["Authorization"] = "Basic $cred"
}

Write-Host "Checking for a running LDI Copilot server at $baseUrl ..." -ForegroundColor Cyan

$serverUp = $false
try {
    Invoke-LdiRequest -Uri "$baseUrl/api/health" -Headers $authHeaders | Out-Null
    $serverUp = $true
} catch {
    $serverUp = $false
}

# Best-effort, in-band: if the server is reachable, ask IT to stop any
# Ollama instance it manages via its own POST /api/ollama/stop. This
# reuses backend/ai/ollama_manager.py's existing safeguard - it only
# ever stops an Ollama instance the app itself started, never an
# externally-running one (e.g. the Ollama desktop app) - so this step
# alone can never do anything more aggressive than the app's own Stop
# button already would. See -KillOllama below for the more aggressive,
# opt-in alternative.
if ($serverUp) {
    Write-Host "Server is up - asking it to stop any Ollama instance it manages..." -ForegroundColor Cyan
    try {
        $resp = Invoke-LdiRequest -Uri "$baseUrl/api/ollama/stop" -Method Post -Headers $authHeaders
    } catch {
        $resp = $null
    }
    if ($resp -and $resp.stopped) {
        Write-Host "  Ollama (managed by this app) stopped." -ForegroundColor Green
        $stoppedAnything = $true
    } else {
        Write-Host "  No Ollama instance managed by this app was running (or this call needed -AuthToken - the process-kill step below will still work either way)." -ForegroundColor DarkGray
    }
} else {
    Write-Host "Server did not respond at $baseUrl - it may already be stopped, or running on a different host/port (pass -HostAddress/-Port to match how you started it)." -ForegroundColor Yellow
}

# Find whatever process is bound to $Port - this is how we locate the
# backend/app.py process itself, regardless of how it was launched.
$connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($connections) {
    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($p in $pids) {
        $commandLine = $null
        try {
            $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $p" -ErrorAction Stop).CommandLine
        } catch {
            $commandLine = $null
        }
        $looksLikeOurs = $commandLine -and ($commandLine -match "app\.py" -or $commandLine -match "uvicorn")

        if ($looksLikeOurs) {
            Write-Host "Stopping LDI Copilot server process (PID $p): $commandLine" -ForegroundColor Cyan
        } elseif ($Force) {
            Write-Host "WARNING: PID $p on port $Port doesn't look like LDI Copilot's server (command line: $commandLine) - stopping anyway because -Force was passed." -ForegroundColor Yellow
        } else {
            Write-Host "WARNING: PID $p is listening on port $Port but doesn't look like LDI Copilot's server (command line: $commandLine)." -ForegroundColor Yellow
            Write-Host "  NOT stopping it - pass -Force to stop it anyway, or double-check -Port matches how you started the server." -ForegroundColor Yellow
            continue
        }

        Stop-Process -Id $p -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        if (Get-Process -Id $p -ErrorAction SilentlyContinue) {
            Start-Sleep -Seconds 2
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        }
        $stoppedAnything = $true
    }
} else {
    Write-Host "No process found listening on port $Port." -ForegroundColor DarkGray
}

if ($KillOllama) {
    Write-Host "Stopping ALL Ollama processes on this machine (-KillOllama)..." -ForegroundColor Cyan
    $ollamaProcs = Get-Process -Name "ollama" -ErrorAction SilentlyContinue
    if ($ollamaProcs) {
        foreach ($proc in $ollamaProcs) {
            Write-Host "  Stopping ollama (PID $($proc.Id))..." -ForegroundColor Cyan
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
        $stoppedAnything = $true
    } else {
        Write-Host "  No 'ollama' process found." -ForegroundColor DarkGray
    }
}

Write-Host ""
if ($stoppedAnything) {
    Write-Host "Done - LDI Copilot has been stopped." -ForegroundColor Green
} else {
    Write-Host "Nothing appeared to be running." -ForegroundColor DarkGray
}
