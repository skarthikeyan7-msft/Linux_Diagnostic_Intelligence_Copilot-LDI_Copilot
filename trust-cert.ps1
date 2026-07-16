# Linux Diagnostic Intelligence Copilot - LDI Copilot
# Trusts the auto-generated self-signed TLS certificate (backend/certs.py,
# used by run.ps1/run.bat/run.sh's --https) so browsers stop showing the
# "connection isn't private" warning for it - the counterpart to clicking
# through that warning every time.
#
# What this does and does NOT do:
# - Imports the certificate into the CURRENT USER's trusted root store
#   (Cert:\CurrentUser\Root) - no administrator privileges needed.
# - This is a LEAF certificate (not a Certificate Authority - see
#   backend/certs.py's BasicConstraints(ca=False)), so trusting it only
#   ever lets THIS EXACT certificate be accepted without a warning - it
#   cannot be used to impersonate any other site, unlike installing a
#   real (CA-capable) root certificate would risk.
# - Covers Chrome/Edge on Windows (they use the Windows certificate
#   store). Firefox uses its own separate certificate store on every
#   platform and needs a manual one-time import instead - see the
#   printed instructions below.
# - Only trusts the certificate on THIS machine, for THIS user. Anyone
#   else reaching the same server (e.g. a teammate on a shared instance -
#   see README.md's "Sharing with a team" section) needs to run this
#   themselves, or just keep clicking through the warning - both are
#   fine, this script is a convenience, not a requirement.
param(
    [string]$CertPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $CertPath) {
    $CertPath = Join-Path $root "certs\ldi-copilot-selfsigned.crt"
}

if (-not (Test-Path $CertPath)) {
    Write-Host "No certificate found at $CertPath." -ForegroundColor Red
    Write-Host "Start the server with --https at least once first (e.g. .\run.ps1 -Https) to generate it," -ForegroundColor Yellow
    Write-Host "or pass -CertPath to point at a different certificate file." -ForegroundColor Yellow
    exit 1
}

Write-Host "Importing $CertPath into your CURRENT USER trusted root store..." -ForegroundColor Cyan
try {
    # certutil.exe (not the Import-Certificate cmdlet) deliberately -
    # Import-Certificate triggers Windows' native interactive "Security
    # Warning: do you want to install this certificate?" dialog for any
    # write to the Root store, every single time, with no supported way
    # to suppress it from a script. certutil's -addstore performs the
    # exact same underlying store write without that dialog, since it's
    # a plain console tool rather than going through the shell's
    # certificate-wizard UI path. Verified directly: after using
    # certutil here, a real browser (Playwright/Chromium) navigated to
    # the HTTPS server and rendered the page with zero warning - not
    # just "the API reports success" but a genuinely trusted connection.
    $out = & certutil.exe -user -addstore -f "Root" "$CertPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($out -join "`n")
    }
    Write-Host "Done." -ForegroundColor Green
} catch {
    Write-Host "Failed to import the certificate: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Chrome/Edge on this Windows account will now trust https://127.0.0.1 (and whatever" -ForegroundColor Green
Write-Host "--host/hostname the certificate was generated for) without a warning. Close and" -ForegroundColor Green
Write-Host "reopen any already-open tab pointed at it for the change to take effect." -ForegroundColor Green
Write-Host ""
Write-Host "Firefox uses its own separate certificate store and isn't covered by this script." -ForegroundColor Yellow
Write-Host "To trust it there too: open Firefox -> Settings -> Privacy & Security -> Certificates" -ForegroundColor Yellow
Write-Host "-> View Certificates -> Authorities tab -> Import... -> select:" -ForegroundColor Yellow
Write-Host "    $CertPath" -ForegroundColor Yellow
Write-Host "-> check 'Trust this CA to identify websites' -> OK." -ForegroundColor Yellow
Write-Host ""
Write-Host "To undo this later: Cert:\CurrentUser\Root in certmgr.msc, or:" -ForegroundColor DarkGray
Write-Host "    Get-ChildItem Cert:\CurrentUser\Root | Where-Object Subject -like '*LDI Copilot*' | Remove-Item" -ForegroundColor DarkGray
