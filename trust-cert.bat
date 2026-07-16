@echo off
rem Linux Diagnostic Intelligence Copilot - LDI Copilot
rem Trusts the auto-generated self-signed TLS certificate for plain
rem Windows Command Prompt users - delegates to trust-cert.ps1 (same
rem approach stop.bat uses for stop.ps1), since importing into the
rem Windows certificate store is a PowerShell (Import-Certificate)
rem operation with no raw batch equivalent.

set "ROOT=%~dp0"
set "CERTPATH=%~1"

if "%CERTPATH%"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%trust-cert.ps1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%trust-cert.ps1" -CertPath "%CERTPATH%"
)
exit /b %ERRORLEVEL%
