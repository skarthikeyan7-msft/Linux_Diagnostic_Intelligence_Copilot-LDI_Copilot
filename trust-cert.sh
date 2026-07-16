#!/usr/bin/env bash
# Linux Diagnostic Intelligence Copilot - LDI Copilot
# Trusts the auto-generated self-signed TLS certificate (backend/certs.py,
# used by run.sh/run.bat/run.ps1's --https) so browsers stop showing the
# "connection isn't private" warning for it.
#
# What this does and does NOT do:
# - This is a LEAF certificate (not a Certificate Authority - see
#   backend/certs.py's BasicConstraints(ca=False)), so trusting it only
#   ever lets THIS EXACT certificate be accepted without a warning - it
#   cannot be used to impersonate any other site, unlike installing a
#   real (CA-capable) root certificate would risk.
# - Linux: adds it to the SYSTEM trust store (update-ca-certificates on
#   Debian/Ubuntu, update-ca-trust on RHEL/CentOS/Fedora/SUSE) - needs
#   sudo, covers most system tools and Chrome (which on most distros
#   reads the system store via NSS/p11-kit integration).
# - macOS: adds it to your LOGIN keychain (no sudo needed) - covers
#   Safari and Chrome, which both use the OS keychain there.
# - Firefox uses its own separate certificate store on every platform
#   and needs a manual one-time import instead - see the printed
#   instructions below.
# - Only trusts the certificate on THIS machine, for THIS user/system.
#   Anyone else reaching the same server (e.g. a teammate on a shared
#   instance - see README.md's "Sharing with a team" section) needs to
#   run this themselves, or just keep clicking through the warning -
#   both are fine, this script is a convenience, not a requirement.
set -uo pipefail
export MSYS_NO_PATHCONV=1  # see stop.sh's comment on this - same Git-Bash-on-Windows path-mangling issue applies to any Windows .exe this script might shell out to

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_PATH="${1:-$ROOT_DIR/certs/ldi-copilot-selfsigned.crt}"

if [[ ! -f "$CERT_PATH" ]]; then
  echo "No certificate found at $CERT_PATH." >&2
  echo "Start the server with --https at least once first (e.g. ./run.sh --https) to generate it," >&2
  echo "or pass a path as the first argument to point at a different certificate file." >&2
  exit 1
fi

case "$(uname -s)" in
  Linux)
    if command -v update-ca-certificates >/dev/null 2>&1; then
      echo "Debian/Ubuntu-style system detected - copying into /usr/local/share/ca-certificates/ (needs sudo)..."
      sudo cp "$CERT_PATH" /usr/local/share/ca-certificates/ldi-copilot-selfsigned.crt
      sudo update-ca-certificates
    elif command -v update-ca-trust >/dev/null 2>&1; then
      echo "RHEL/CentOS/Fedora/SUSE-style system detected - copying into /etc/pki/ca-trust/source/anchors/ (needs sudo)..."
      sudo cp "$CERT_PATH" /etc/pki/ca-trust/source/anchors/ldi-copilot-selfsigned.crt
      sudo update-ca-trust extract
    else
      echo "Neither update-ca-certificates nor update-ca-trust was found - don't know how to" >&2
      echo "update this distro's system trust store automatically. Import $CERT_PATH manually" >&2
      echo "via your distro's own certificate-trust tooling." >&2
      exit 1
    fi
    echo "Done. Chrome (which reads the system trust store on most Linux distros) should now"
    echo "trust it without a warning - restart Chrome for the change to take effect."
    ;;
  Darwin)
    echo "Adding to your login keychain (no sudo needed - covers Safari and Chrome on macOS)..."
    security add-trusted-cert -r trustRoot -k "$HOME/Library/Keychains/login.keychain-db" "$CERT_PATH"
    echo "Done. Restart Safari/Chrome for the change to take effect."
    ;;
  *)
    echo "Unrecognized OS ($(uname -s)) - if this is Git Bash/MSYS2 on Windows, use trust-cert.ps1" >&2
    echo "or trust-cert.bat instead (they cover the Windows certificate store, which this" >&2
    echo "script's Linux/macOS logic can't reach)." >&2
    exit 1
    ;;
esac

echo ""
echo "Firefox uses its own separate certificate store and isn't covered by this script."
echo "To trust it there too: open Firefox -> Settings -> Privacy & Security -> Certificates"
echo "-> View Certificates -> Authorities tab -> Import... -> select:"
echo "    $CERT_PATH"
echo "-> check 'Trust this CA to identify websites' -> OK."
