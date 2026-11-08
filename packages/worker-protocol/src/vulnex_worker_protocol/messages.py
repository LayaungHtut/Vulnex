"""Request and response bodies of the worker protocol (`/worker/v1`, ADR-0006)."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from vulnex_worker_protocol.lease import SignedLease

PROTOCOL_VERSION = 1


class EnrollmentBundle(BaseModel):
    """What an owner or administrator hands to the person installing a worker (one file)."""

    control_plane_url: str
    ca_pem: str = Field(description="CA of the worker endpoint's TLS certificate (pinned)")
    ca_sha256: str
    token: str


class EnrollRequest(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    csr_pem: str = Field(max_length=10_000)


class Credentials(BaseModel):
    worker_id: uuid.UUID
    tenant_id: uuid.UUID
    scope_group_id: uuid.UUID
    certificate_pem: str
    certificate_not_after: datetime
    scope_keys: dict[str, str] = Field(description="Ed25519 public keys by key id (base64, raw)")
    protocol_versions: list[int]


class RenewRequest(BaseModel):
    csr_pem: str = Field(max_length=10_000)


class HeartbeatRequest(BaseModel):
    version: str = Field(max_length=50)


class HeartbeatResponse(BaseModel):
    worker_id: uuid.UUID
    status: Literal["active", "disabled"]
    server_time: datetime


class LeaseRequest(BaseModel):
    max_tasks: int = Field(default=1, ge=1, le=10)


class Task(BaseModel):
    job_id: uuid.UUID
    lease_id: uuid.UUID
    attempt: int
    lease: SignedLease


class LeaseResponse(BaseModel):
    tasks: list[Task]


class ExtendRequest(BaseModel):
    job_id: uuid.UUID
    lease_id: uuid.UUID


class ExtendResponse(BaseModel):
    """`ok` false: the lease is gone (expired, revoked or reassigned); stop the task."""

    ok: bool
    cancel_requested: bool
    lease_expires_at: datetime | None


class Submission(BaseModel):
    """One batch of results. With `outcome`, it is the final batch and completes the task."""

    job_id: uuid.UUID
    lease_id: uuid.UUID
    attempt: int = Field(ge=1)
    seq: int = Field(ge=0, le=1_000_000)
    payload: dict[str, Any]
    outcome: Literal["succeeded", "failed", "refused", "cancelled"] | None = None
    error: str | None = Field(default=None, max_length=1000)


class SubmissionResponse(BaseModel):
    status: Literal["accepted", "duplicate"]
