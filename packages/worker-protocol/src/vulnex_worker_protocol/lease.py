"""Signed scope leases (ADR-0006 §4).

The control plane signs the exact JSON bytes of a lease with Ed25519. The worker checks the
signature over those bytes *before* parsing them, then checks that the lease is for this worker,
this tenant and this job attempt, inside its time window, and that the scope entries it carries
still match the digest the organization authorized. There is no JSON canonicalization step to
get wrong: the signed bytes are the bytes that are parsed.
"""

import base64
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnex_worker_protocol.targets import Kind, ScopeEntry, scope_digest

MAX_CLOCK_SKEW = timedelta(minutes=2)


class LeaseError(Exception):
    """The lease must not be acted on. The message is safe to report to the control plane."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class LeaseScopeEntry(_Model):
    kind: Literal["cidr", "hostname", "hostname_wildcard"]
    value: str
    exclude: bool


class Limits(_Model):
    max_addresses: int = Field(ge=1, le=65_536)
    task_timeout_s: int = Field(ge=1, le=86_400)
    probe_timeout_s: float = Field(gt=0, le=60)
    max_concurrency: int = Field(ge=1, le=1024)


class ScopeLease(_Model):
    v: Literal[1] = 1
    kid: str
    job_id: uuid.UUID
    lease_id: uuid.UUID
    attempt: int = Field(ge=1)
    tenant_id: uuid.UUID
    worker_id: uuid.UUID
    scope_group_id: uuid.UUID
    not_before: datetime
    expires_at: datetime
    kind: str  # task kind, such as "scope.check"
    targets: list[str] = Field(max_length=10_000)
    scope: list[LeaseScopeEntry] = Field(max_length=10_000)
    scope_digest: str
    ports: list[int] = Field(default_factory=list, max_length=65_535)
    limits: Limits

    def scope_entries(self) -> list[ScopeEntry]:
        return [ScopeEntry(Kind(e.kind), e.value, e.exclude) for e in self.scope]


class SignedLease(_Model):
    kid: str
    payload_b64: str
    sig_b64: str


def public_key_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:  # gitleaks:allow (signature)
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def load_public_key(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64, validate=True))


def sign(lease: ScopeLease, key: Ed25519PrivateKey) -> SignedLease:
    payload = lease.model_dump_json().encode()
    return SignedLease(
        kid=lease.kid,
        payload_b64=base64.b64encode(payload).decode(),
        sig_b64=base64.b64encode(key.sign(payload)).decode(),
    )


def verify(
    signed: SignedLease,
    keys: dict[str, Ed25519PublicKey],
    *,
    worker_id: uuid.UUID,
    tenant_id: uuid.UUID,
    job_id: uuid.UUID,
    lease_id: uuid.UUID,
    attempt: int,
    now: datetime | None = None,
) -> ScopeLease:
    """Return the lease only if every ADR-0006 §4 check passes; raise LeaseError otherwise."""
    key = keys.get(signed.kid)
    if key is None:
        raise LeaseError(f"unknown signing key {signed.kid!r}")
    try:
        payload = base64.b64decode(signed.payload_b64, validate=True)
        key.verify(base64.b64decode(signed.sig_b64, validate=True), payload)
    except (InvalidSignature, ValueError):
        raise LeaseError("signature does not verify") from None
    try:
        lease = ScopeLease.model_validate_json(payload)
    except ValidationError:
        raise LeaseError("signed payload is not a valid lease") from None

    if lease.kid != signed.kid:
        raise LeaseError("key id inside the lease does not match")
    if lease.worker_id != worker_id or lease.tenant_id != tenant_id:
        raise LeaseError("lease is for another worker or tenant")
    if (lease.job_id, lease.lease_id, lease.attempt) != (job_id, lease_id, attempt):
        raise LeaseError("lease does not match the task it came with")
    now = now or datetime.now(UTC)
    if now < lease.not_before - MAX_CLOCK_SKEW:
        raise LeaseError("lease is not valid yet")
    if now > lease.expires_at + MAX_CLOCK_SKEW:
        raise LeaseError("lease has expired")
    if scope_digest(lease.scope_entries()) != lease.scope_digest:
        raise LeaseError("scope entries do not match the authorized digest")
    return lease
