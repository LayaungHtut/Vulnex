"""Enrollment, local credential state, and the worker loop (ADR-0006 §1-4).

State directory (keep it private; the key never leaves it):

    worker.key        ECDSA P-256 private key, mode 0600, generated here
    worker.crt        client certificate from the control plane (7 days, renewed at < 2 days)
    endpoint-ca.crt   pinned CA of the worker endpoint, from the enrollment bundle
    worker.json       identity, endpoint URL and scope-signing public keys
"""

import hashlib
import json
import logging
import os
import ssl
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vulnex_scanner import __version__
from vulnex_scanner.check import scope_check
from vulnex_worker_protocol.lease import (
    MAX_CLOCK_SKEW,
    LeaseError,
    SignedLease,
    load_public_key,
    verify,
)
from vulnex_worker_protocol.messages import (
    Credentials,
    EnrollmentBundle,
    EnrollRequest,
    HeartbeatResponse,
    LeaseResponse,
    Task,
)
from vulnex_worker_protocol.targets import ScopeEntry

log = logging.getLogger("vulnex.scanner")

KEY, CERT, CA, CONFIG = "worker.key", "worker.crt", "endpoint-ca.crt", "worker.json"
RENEW_BEFORE = timedelta(days=2)
POLL_EVERY_S = 5.0


class ScannerError(Exception):
    """A condition the operator must see. The message is safe to print."""


class Revoked(ScannerError):
    """The control plane revoked this worker; its keys have been deleted."""


def _new_csr() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vulnex-scanner")]))
        .sign(key, hashes.SHA256())
    )
    return key, req.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _write(path: Path, data: bytes, mode: int) -> None:
    """Write via a temporary file and rename, so a crash never leaves half a key."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _ca_sha256(ca_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(ca_pem.encode())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _detail(r: httpx.Response) -> str:
    try:
        return str(r.json().get("detail") or r.reason_phrase)
    except ValueError:
        return r.reason_phrase


def _save_credentials(state: Path, creds: Credentials, key: ec.EllipticCurvePrivateKey) -> None:
    _write(state / KEY, _key_pem(key), 0o600)
    _write(state / CERT, creds.certificate_pem.encode(), 0o644)
    config = json.loads((state / CONFIG).read_text()) if (state / CONFIG).exists() else {}
    config |= creds.model_dump(mode="json", exclude={"certificate_pem"})
    _write(state / CONFIG, json.dumps(config, indent=2).encode(), 0o600)


def enroll(state: Path, bundle: EnrollmentBundle, http: httpx.Client | None = None) -> Credentials:
    """Create a key here, send only its CSR, and store the issued identity."""
    if _ca_sha256(bundle.ca_pem) != bundle.ca_sha256.lower():
        raise ScannerError("the bundle's CA does not match its fingerprint; get a new bundle")
    if (state / KEY).exists():
        raise ScannerError(f"{state} already holds a worker identity")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    key, csr_pem = _new_csr()
    if http is None:
        ctx = ssl.create_default_context(cadata=bundle.ca_pem)  # only this CA is trusted
        http = httpx.Client(base_url=bundle.control_plane_url, verify=ctx, timeout=15)
    r = http.post(
        "/worker/v1/enroll", json=EnrollRequest(token=bundle.token, csr_pem=csr_pem).model_dump()
    )
    if not r.is_success:
        raise ScannerError(f"enrollment refused: {_detail(r)}")
    creds = Credentials.model_validate(r.json())
    _write(state / CA, bundle.ca_pem.encode(), 0o644)
    _write(
        state / CONFIG,
        json.dumps({"control_plane_url": bundle.control_plane_url}).encode(),
        0o600,
    )
    _save_credentials(state, creds, key)
    return creds


class Agent:
    """One enrolled worker. `http` is injectable for tests; by default it is an mTLS client that
    trusts only the pinned endpoint CA."""

    def __init__(
        self,
        state: Path,
        *,
        ceiling: list[ScopeEntry] | None = None,
        http: httpx.Client | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not (state / KEY).exists():
            raise ScannerError(f"{state} holds no worker identity; run `vulnex-scanner enroll`")
        self.state = state
        self.ceiling = ceiling or []
        self.clock = clock
        self._own_http = http is None
        self.http = http or self._client()
        self._load()

    def _load(self) -> None:
        self.config: dict[str, Any] = json.loads((self.state / CONFIG).read_text())
        self.keys = {kid: load_public_key(k) for kid, k in self.config["scope_keys"].items()}

    def _client(self) -> httpx.Client:
        ctx = ssl.create_default_context(cafile=self.state / CA)
        ctx.load_cert_chain(self.state / CERT, self.state / KEY)
        config = json.loads((self.state / CONFIG).read_text())
        return httpx.Client(base_url=config["control_plane_url"], verify=ctx, timeout=15)

    def _post(self, path: str, body: dict[str, Any]) -> Any:
        r = self.http.post(path, json=body)
        if r.status_code == 401 and _detail(r) == "revoked":
            self.forget()
            raise Revoked("this worker was revoked; its key and certificate were deleted")
        if not r.is_success:
            raise ScannerError(f"{path}: {r.status_code} {_detail(r)}")
        return r.json()

    def forget(self) -> None:
        for name in (KEY, CERT):
            (self.state / name).unlink(missing_ok=True)

    def heartbeat(self) -> HeartbeatResponse:
        hb = HeartbeatResponse.model_validate(
            self._post("/worker/v1/heartbeat", {"version": __version__})
        )
        skew = abs(hb.server_time - self.clock())
        if skew > MAX_CLOCK_SKEW:
            raise ScannerError(f"clock differs from the control plane by {skew}; fix NTP")
        return hb

    def renew_if_due(self) -> bool:
        not_after = datetime.fromisoformat(self.config["certificate_not_after"])
        if not_after - self.clock() > RENEW_BEFORE:
            return False
        key, csr_pem = _new_csr()
        creds = Credentials.model_validate(self._post("/worker/v1/renew", {"csr_pem": csr_pem}))
        _save_credentials(self.state, creds, key)
        self._load()
        if self._own_http:
            self.http.close()
            self.http = self._client()
        log.info("certificate renewed, valid until %s", creds.certificate_not_after)
        return True

    def handle(self, task: Task) -> dict[str, Any]:
        """Verify the lease, run the task, submit the final result. Returns what was sent."""
        base = {"job_id": str(task.job_id), "lease_id": str(task.lease_id), "attempt": task.attempt}
        try:
            lease = verify(
                SignedLease.model_validate(task.lease),
                self.keys,
                worker_id=uuid.UUID(self.config["worker_id"]),
                tenant_id=uuid.UUID(self.config["tenant_id"]),
                job_id=task.job_id,
                lease_id=task.lease_id,
                attempt=task.attempt,
                now=self.clock(),
            )
        except LeaseError as e:
            log.warning("lease refused: %s", e)
            result: tuple[dict[str, Any], str, str | None] = (
                {"lease_error": str(e)},
                "refused",
                f"worker refused the lease: {e}",
            )
        else:
            if lease.kind == "scope.check":
                result = scope_check(lease, self.ceiling), "succeeded", None
            else:
                result = {}, "refused", f"this worker does not run {lease.kind!r} tasks"
        payload, outcome, error = result
        body = base | {"seq": 0, "payload": payload, "outcome": outcome, "error": error}
        self._post("/worker/v1/tasks/submit", body)
        return body

    def run_once(self) -> int:
        """Heartbeat, renew if due, lease and run tasks. Returns the number of tasks handled."""
        self.heartbeat()
        self.renew_if_due()
        leased = LeaseResponse.model_validate(self._post("/worker/v1/lease", {"max_tasks": 1}))
        for task in leased.tasks:
            self.handle(task)
        return len(leased.tasks)

    def run(self, stop: threading.Event) -> None:
        """Poll until `stop` is set. Transient errors back off; revocation ends the loop."""
        delay = POLL_EVERY_S
        while not stop.is_set():
            try:
                busy = self.run_once()
                delay = 0.0 if busy else POLL_EVERY_S
            except Revoked:
                raise
            except (ScannerError, httpx.HTTPError) as e:
                log.warning("cycle failed: %s", e)
                delay = min(max(delay * 2, POLL_EVERY_S), 300.0)
            stop.wait(delay)
