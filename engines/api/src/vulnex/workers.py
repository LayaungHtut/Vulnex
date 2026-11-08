"""Scanner workers as the organization sees them (M4, ADR-0006 §1-3): enrollment tokens,
the worker list with connection state, and revocation.

The worker side of the protocol (enroll, heartbeat, lease, results) is a separate app,
`vulnex.worker_api`, reachable only through the mTLS gateway.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import Connection, RowMapping, text

from vulnex import audit, security
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, engine_of, require, settings_of
from vulnex.pki import pem_sha256
from vulnex.scope import group_row
from vulnex_worker_protocol.messages import EnrollmentBundle

router = APIRouter(prefix="/api/v1/workers", tags=["workers"])

Reader = Annotated[Principal, Depends(require(Permission.WORKERS_READ))]
Manager = Annotated[Principal, Depends(require(Permission.WORKERS_MANAGE))]

# A worker heartbeats every 10 s; three missed beats and a margin make it "stale".
ONLINE_WITHIN = timedelta(seconds=60)


class EnrollmentIn(BaseModel):
    scope_group_id: uuid.UUID
    name: str = Field(min_length=1, max_length=100, examples=["lab-scanner-1"])
    ttl_hours: int = Field(default=24, ge=1, le=24)


class EnrollmentOut(BaseModel):
    id: uuid.UUID
    scope_group_id: uuid.UUID
    name: str
    created_at: datetime
    expires_at: datetime
    status: Literal["pending", "used", "expired", "revoked"]
    worker_id: uuid.UUID | None


class EnrollmentCreated(BaseModel):
    id: uuid.UUID
    expires_at: datetime
    bundle: EnrollmentBundle = Field(
        description="Shown once. Give it to the scanner: `vulnex-scanner enroll --bundle FILE`"
    )


class WorkerOut(BaseModel):
    id: uuid.UUID
    name: str
    scope_group_id: uuid.UUID
    scope_group_name: str
    status: Literal["active", "disabled", "revoked"]
    connection: Literal["online", "stale", "never_connected"]
    last_seen_at: datetime | None
    version: str | None
    created_at: datetime
    revoked_at: datetime | None


def _workers(conn: Connection, only: uuid.UUID | None = None) -> list[WorkerOut]:
    rows = conn.execute(
        text(
            "SELECT w.id, w.name, w.scope_group_id, g.name AS scope_group_name, w.status, "
            "w.last_seen_at, w.version, w.created_at, w.revoked_at, "
            "CASE WHEN w.last_seen_at IS NULL THEN 'never_connected' "
            "     WHEN w.last_seen_at > now() - CAST(:online AS interval) THEN 'online' "
            "     ELSE 'stale' END AS connection "
            "FROM app.worker w JOIN app.scope_group g "
            "  ON g.tenant_id = w.tenant_id AND g.id = w.scope_group_id "
            "WHERE w.tenant_id = app.current_tenant() "
            "AND (CAST(:w AS uuid) IS NULL OR w.id = CAST(:w AS uuid)) "
            "ORDER BY w.status = 'revoked', w.name"
        ),
        {"online": ONLINE_WITHIN, "w": only},
    ).mappings()
    return [WorkerOut(**r) for r in rows]


def _enrollment_status(
    r: RowMapping, now: datetime
) -> Literal["pending", "used", "expired", "revoked"]:
    if r["revoked_at"]:
        return "revoked"
    if r["used_at"]:
        return "used"
    return "expired" if r["expires_at"] <= now else "pending"


@router.get("")
def list_workers(request: Request, principal: Reader) -> list[WorkerOut]:
    with tenant_tx(engine_of(request), principal) as conn:
        return _workers(conn)


@router.post("/{worker_id}/revoke")
def revoke_worker(worker_id: uuid.UUID, request: Request, principal: Manager) -> WorkerOut:
    """Revoke at once: certificates stop working, held leases are released (the jobs follow the
    normal retry rules), and anything the worker sends afterwards is refused or quarantined.
    Revoking an already revoked worker changes nothing."""
    with tenant_tx(engine_of(request), principal) as conn:
        row = conn.execute(
            text(
                "SELECT status FROM app.worker WHERE tenant_id = app.current_tenant() "
                "AND id = :w FOR UPDATE"
            ),
            {"w": worker_id},
        ).first()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Worker not found")
        if row.status != "revoked":
            conn.execute(
                text(
                    "UPDATE app.worker SET status = 'revoked', revoked_at = now() "
                    "WHERE tenant_id = app.current_tenant() AND id = :w"
                ),
                {"w": worker_id},
            )
            certificates = conn.execute(
                text("SELECT auth.revoke_worker_certificates(:w)"), {"w": worker_id}
            ).scalar_one()
            released = conn.execute(
                text("SELECT queue.release_worker_leases(:w)"), {"w": worker_id}
            ).scalar_one()
            audit.record(
                conn,
                principal,
                "worker.revoked",
                target_type="worker",
                target_id=str(worker_id),
                ip=client_ip(request),
                detail={"certificates_revoked": certificates, "leases_released": released},
            )
        return _workers(conn, worker_id)[0]


@router.get("/enrollments")
def list_enrollments(request: Request, principal: Manager) -> list[EnrollmentOut]:
    now = datetime.now(UTC)
    with tenant_tx(engine_of(request), principal) as conn:
        rows = conn.execute(text("SELECT * FROM auth.tenant_worker_enrollments()")).mappings()
        return [
            EnrollmentOut(
                id=r["id"],
                scope_group_id=r["scope_group_id"],
                name=r["name"],
                created_at=r["created_at"],
                expires_at=r["expires_at"],
                status=_enrollment_status(r, now),
                worker_id=r["worker_id"],
            )
            for r in rows
        ]


@router.post("/enrollments", status_code=status.HTTP_201_CREATED)
def create_enrollment(
    body: EnrollmentIn, request: Request, principal: Manager
) -> EnrollmentCreated:
    """A single-use token for one new worker, bound to this organization and one scope group.

    Only the token's SHA-256 is stored; the token itself appears in this response and nowhere
    else. The worker may scan only inside the scope group, and only once it is authorized.
    """
    settings = settings_of(request)
    ca_file = settings.worker_endpoint_ca_file
    if not (settings.worker_endpoint_url and ca_file and ca_file.is_file()):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Scanner enrollment is not configured on this server",
        )
    ca_pem = ca_file.read_text()
    token = security.new_session_token()  # 256 bits from secrets
    name = body.name.strip()
    with tenant_tx(engine_of(request), principal) as conn:
        group_row(conn, body.scope_group_id)  # 404 for unknown or another tenant's group
        taken = conn.execute(
            text("SELECT 1 FROM app.worker WHERE tenant_id = app.current_tenant() AND name = :n"),
            {"n": name},
        ).first()
        if taken:
            raise HTTPException(status.HTTP_409_CONFLICT, "A worker with that name exists")
        row = conn.execute(
            text("SELECT * FROM auth.create_worker_enrollment(:g, :n, :h, :ttl, :by)"),
            {
                "g": body.scope_group_id,
                "n": name,
                "h": security.token_digest(token),
                "ttl": timedelta(hours=body.ttl_hours),
                "by": principal.user_id,
            },
        ).one()
        audit.record(
            conn,
            principal,
            "worker_enrollment.created",
            target_type="scope_group",
            target_id=str(body.scope_group_id),
            ip=client_ip(request),
            detail={"enrollment_id": str(row.id), "name": name, "ttl_hours": body.ttl_hours},
        )
    return EnrollmentCreated(
        id=row.id,
        expires_at=row.expires_at,
        bundle=EnrollmentBundle(
            control_plane_url=settings.worker_endpoint_url,
            ca_pem=ca_pem,
            ca_sha256=pem_sha256(ca_pem),
            token=token,
        ),
    )


@router.delete("/enrollments/{enrollment_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_enrollment(enrollment_id: uuid.UUID, request: Request, principal: Manager) -> Response:
    """Withdraw an unused token. Used, expired-and-revoked or unknown tokens give 404."""
    with tenant_tx(engine_of(request), principal) as conn:
        if not conn.execute(
            text("SELECT auth.revoke_worker_enrollment(:e)"), {"e": enrollment_id}
        ).scalar_one():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No unused enrollment with that ID")
        audit.record(
            conn,
            principal,
            "worker_enrollment.revoked",
            target_type="worker_enrollment",
            target_id=str(enrollment_id),
            ip=client_ip(request),
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
