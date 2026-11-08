"""Lab only: write a self-signed certificate that expired 30 days ago into /certs (a volume)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = Path("/certs")
if not (out / "expired.crt").exists():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab-tls.vulnex.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now - timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("lab-tls.vulnex.test")]), False)
        .sign(key, hashes.SHA256())
    )
    (out / "expired.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out / "expired.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (out / "expired.key").chmod(0o644)  # nginx workers read it; lab only
