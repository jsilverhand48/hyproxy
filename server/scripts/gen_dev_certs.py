"""Self-signed dev TLS cert for idp.localhost (mkcert is nicer if installed).

Secure cookies and WebAuthn require a secure context; uvicorn serves these via
`make run-idp`. Browsers will warn on the self-signed cert; accept it for dev.
"""

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).resolve().parent.parent / ".dev" / "certs"
NAMES = ["idp.localhost", "localhost", "admin.localhost"]


def _san_entries() -> list[x509.GeneralName]:
    """Build the SAN list: the fixed dev names, loopback, plus any extra hosts
    from DEV_CERT_EXTRA (comma-separated). Extras that parse as an IP become
    IPAddress SANs, otherwise DNSName; this lets a LAN address serve the dev
    IdP with a cert the browser accepts for background fetch()."""
    entries: list[x509.GeneralName] = [x509.DNSName(n) for n in NAMES]
    entries.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    for extra in os.environ.get("DEV_CERT_EXTRA", "").split(","):
        extra = extra.strip()
        if not extra or extra in NAMES:
            continue
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(extra)))
        except ValueError:
            entries.append(x509.DNSName(extra))
    return entries


def main() -> int:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAMES[0])])
    now = datetime.datetime.now(datetime.UTC)
    san = _san_entries()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path = CERT_DIR / "idp.localhost-key.pem"
    cert_path = CERT_DIR / "idp.localhost.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    san_names = ", ".join(str(getattr(n, "value", n)) for n in san)
    print(f"wrote {cert_path} and {key_path} (valid 365 days, SANs: {san_names})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
