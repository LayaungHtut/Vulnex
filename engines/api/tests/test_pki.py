"""Worker PKI (ADR-0006 §1): issued certificates and generated files. No database needed."""

import ssl
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import verification
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from vulnex.pki import WORKER_CERT_LIFETIME, CsrError, WorkerPki, fingerprint, init_pki


def csr(key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey, cn: str = "anything") -> str:
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("evil.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return req.public_bytes(serialization.Encoding.PEM).decode()


def test_worker_certificate_identity_comes_from_the_server_not_the_request(pki_dir: Path) -> None:
    pki = WorkerPki.load(pki_dir)
    key = ec.generate_private_key(ec.SECP256R1())
    worker = uuid.uuid4()
    cert = pki.sign_worker_csr(csr(key, cn="admin"), worker)

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:vulnex:worker:{worker}"
    ]
    assert san.get_values_for_type(x509.DNSName) == []  # requested SANs are ignored
    assert str(worker) in cert.subject.rfc4514_string()
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert lifetime == WORKER_CERT_LIFETIME + timedelta(minutes=1)  # backdated 1 min for skew
    cert.verify_directly_issued_by(pki.ca_cert)
    assert len(fingerprint(cert)) == 64


@pytest.mark.parametrize(
    "bad",
    [
        "not a csr",
        csr(ec.generate_private_key(ec.SECP384R1())),
        csr(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ],
)
def test_unacceptable_requests_are_refused(pki_dir: Path, bad: str) -> None:
    with pytest.raises(CsrError):
        WorkerPki.load(pki_dir).sign_worker_csr(bad, uuid.uuid4())


def test_init_pki_never_overwrites_key_material(pki_dir: Path) -> None:
    before = (pki_dir / "worker-ca.key").read_bytes()
    with pytest.raises(FileExistsError):
        init_pki(pki_dir, ["localhost"])
    assert (pki_dir / "worker-ca.key").read_bytes() == before


def test_endpoint_certificate_chains_to_the_endpoint_ca_not_the_worker_ca(pki_dir: Path) -> None:
    server = x509.load_pem_x509_certificates((pki_dir / "server.crt").read_bytes())[0]
    server_ca = x509.load_pem_x509_certificate((pki_dir / "server-ca.crt").read_bytes())
    server.verify_directly_issued_by(server_ca)
    worker_ca = WorkerPki.load(pki_dir).ca_cert
    assert worker_ca.subject != server_ca.subject
    names = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["localhost"]


def test_endpoint_certificate_passes_strict_verification(pki_dir: Path) -> None:
    """Python 3.13 clients verify with VERIFY_X509_STRICT; a missing AKI fails the handshake."""
    server_pem = (pki_dir / "server.crt").read_bytes()
    ctx = ssl.create_default_context(cafile=pki_dir / "server-ca.crt")
    assert ctx.verify_flags & ssl.VERIFY_X509_STRICT
    store = verification.Store(
        [x509.load_pem_x509_certificate((pki_dir / "server-ca.crt").read_bytes())]
    )
    leaf, *chain = x509.load_pem_x509_certificates(server_pem)
    verifier = (
        verification.PolicyBuilder().store(store).build_server_verifier(x509.DNSName("localhost"))
    )
    verifier.verify(leaf, chain)  # rustls-webpki rules: as strict as OpenSSL's strict mode
