"""Worker PKI (ADR-0006 §1): the worker CA that issues short-lived client certificates, the
scope-signing key, and the TLS material for the worker endpoint.

Three separate keys with separate jobs:

- `worker-ca.key` signs worker client certificates (7 days, SAN `urn:vulnex:worker:<id>`).
  Held only by the worker API process.
- `scope-signing.key` (Ed25519) signs scope leases. Held only by the worker API process.
- `server-ca.key` issues the TLS certificate of the worker endpoint (the gateway). Workers pin
  `server-ca.crt` from their enrollment bundle.

The main (user-facing) API holds no private key; it only reads `server-ca.crt` to build
enrollment bundles.
"""

import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

WORKER_CERT_LIFETIME = timedelta(days=7)
CA_LIFETIME = timedelta(days=5 * 365)
SERVER_CERT_LIFETIME = timedelta(days=365)


class CsrError(ValueError):
    """The certificate request is not acceptable. The message is safe to return."""


def fingerprint(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 of the DER certificate, as the gateway reports it."""
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def pem_sha256(pem: str) -> str:
    return fingerprint(x509.load_pem_x509_certificate(pem.encode()))


def scope_kid(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "scope-" + hashlib.sha256(raw).hexdigest()[:12]


@dataclass(frozen=True)
class WorkerPki:
    ca_cert: x509.Certificate
    ca_key: ec.EllipticCurvePrivateKey
    scope_key: Ed25519PrivateKey  # gitleaks:allow (type annotation, not a secret)

    @property
    def scope_kid(self) -> str:
        return scope_kid(self.scope_key)

    @classmethod
    def load(cls, directory: Path) -> "WorkerPki":
        ca_key = serialization.load_pem_private_key(
            (directory / "worker-ca.key").read_bytes(), None
        )
        scope_key = serialization.load_pem_private_key(
            (directory / "scope-signing.key").read_bytes(), None
        )
        if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
            raise ValueError("worker-ca.key must be an EC key")
        if not isinstance(scope_key, Ed25519PrivateKey):
            raise ValueError("scope-signing.key must be an Ed25519 key")
        ca_cert = x509.load_pem_x509_certificate((directory / "worker-ca.crt").read_bytes())
        return cls(ca_cert, ca_key, scope_key)

    def sign_worker_csr(
        self, csr_pem: str, worker_id: uuid.UUID, now: datetime | None = None
    ) -> x509.Certificate:
        """Issue a client certificate for `worker_id`. Only the CSR's public key is used."""
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except ValueError:
            raise CsrError("not a PEM certificate signing request") from None
        if not csr.is_signature_valid:
            raise CsrError("the request's signature does not verify")
        key = csr.public_key()
        if not (isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1"):
            raise CsrError("the key must be ECDSA P-256")
        now = now or datetime.now(UTC)
        return (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"worker {worker_id}")])
            )
            .issuer_name(self.ca_cert.subject)
            .public_key(key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + WORKER_CERT_LIFETIME)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"urn:vulnex:worker:{worker_id}")]
                ),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )


def _key_usage(*, digital_signature: bool = False, cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _ca(name: str, now: datetime) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + CA_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(cert_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _write(path: Path, data: bytes, *, secret: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # never overwrite existing key material
    fd = os.open(path, flags, 0o600 if secret else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _key_pem(key: ec.EllipticCurvePrivateKey | Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def init_pki(directory: Path, server_names: list[str]) -> None:
    """Create all worker PKI files in `directory`. Fails if any of them already exists."""
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    worker_ca, worker_ca_key = _ca("VULNEX worker CA", now)
    server_ca, server_ca_key = _ca("VULNEX worker endpoint CA", now)
    server_key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for name in server_names:
        try:
            sans.append(x509.IPAddress(ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_names[0])]))
        .issuer_name(server_ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + SERVER_CERT_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        # Python 3.13+ verifies strictly (VERIFY_X509_STRICT) and requires these.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(server_ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False
        )
        .sign(server_ca_key, hashes.SHA256())
    )
    files = {
        "worker-ca.crt": (_cert_pem(worker_ca), False),
        "worker-ca.key": (_key_pem(worker_ca_key), True),
        "server-ca.crt": (_cert_pem(server_ca), False),
        "server-ca.key": (_key_pem(server_ca_key), True),
        "server.crt": (_cert_pem(server_cert) + _cert_pem(server_ca), False),
        "server.key": (_key_pem(server_key), True),
        "scope-signing.key": (_key_pem(Ed25519PrivateKey.generate()), True),
    }
    existing = [name for name in files if (directory / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite {', '.join(existing)} in {directory}")
    for name, (data, secret) in files.items():
        _write(directory / name, data, secret=secret)
