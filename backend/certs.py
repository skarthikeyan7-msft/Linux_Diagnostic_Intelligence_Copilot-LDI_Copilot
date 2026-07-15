"""
Self-signed TLS certificate management for --https.

LDI Copilot has no public DNS name by design - it's meant to be reached
directly by IP (localhost, LAN, or a cloud VM's address), so there's no
certificate authority that can issue a browser-trusted certificate for it
out of the box. When --https is passed without an explicit
--ssl-certfile/--ssl-keyfile, this module generates and caches a
self-signed certificate covering localhost/127.0.0.1/::1 plus whatever
--host address was requested, so the connection is still encrypted even
though the browser will show a one-time "not private"/self-signed warning
(expected - see README.md's HTTPS section for how to avoid it with a real
certificate instead).
"""
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

_CERT_VALID_DAYS = 825  # historical CA/Browser Forum max leaf lifetime; plenty for a self-signed internal cert
_RENEW_WITHIN_DAYS = 7  # regenerate proactively rather than let it expire mid-use

_CERT_FILENAME = "ldi-copilot-selfsigned.crt"
_KEY_FILENAME = "ldi-copilot-selfsigned.key"


def ensure_self_signed_cert(cert_dir: Path, host: str):
    """Returns (certfile_path, keyfile_path) as strings, generating a new
    self-signed cert/key pair under cert_dir if one doesn't already exist
    or is expired/near-expiry. Reused across restarts so a browser (or an
    engineer) only has to be told to trust it once per machine, rather
    than regenerating - and re-triggering a new trust prompt - every time
    the server starts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_dir = Path(cert_dir)
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / _CERT_FILENAME
    key_path = cert_dir / _KEY_FILENAME

    if cert_path.exists() and key_path.exists():
        try:
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if existing.not_valid_after_utc - datetime.now(timezone.utc) > timedelta(days=_RENEW_WITHIN_DAYS):
                return str(cert_path), str(key_path)
        except Exception:
            pass  # unreadable/corrupt existing file - fall through and regenerate

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LDI Copilot (self-signed)")])

    san_entries = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    if host not in ("0.0.0.0", "::", "localhost", "127.0.0.1", "::1"):
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_entries.append(x509.DNSName(host))  # a real hostname, not an IP literal

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=_CERT_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        key_path.chmod(0o600)  # best-effort private-key permission lockdown on POSIX; harmless no-op on Windows
    except OSError:
        pass

    return str(cert_path), str(key_path)
