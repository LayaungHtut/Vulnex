"""Scan runs (M4): request, list, inspect and cancel. Execution is a `queue.job` (ADR-0003)
leased by a worker of the same scope group, which re-checks scope itself (ADR-0006 §4).

M4 has one profile, `scope_check`: the worker expands each target against the signed scope and
reports which addresses it would be allowed to touch. It sends no packets to targets. Network
probing arrives in M5, after the Astra 6 review of ADR-0006.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import Connection, text

from vulnex import audit
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, engine_of, require
from vulnex.scope import entries_by_group, group_row, is_authorized
from vulnex_worker_protocol.targets import Kind, Target, scope_problem

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

Reader = Annotated[Principal, Depends(require(Permission.SCANS_READ))]
Runner = Annotated[Principal, Depends(require(Permission.SCANS_RUN))]

TASK_KIND = "scope.check"
# Users see scan states; queue vocabulary ("leased", "dead") stays internal.
_STATE = {
    "queued": "queued",
    "leased": "running",
    "succeeded": "completed",
    "failed": "failed",
    "dead": "failed",
    "cancelled": "cancelled",
}
ScanState = Literal["queued", "running", "completed", "failed", "cancelled"]


class ScanIn(BaseModel):
    asset_ids: list[uuid.UUID] = Field(min_length=1, max_length=1000)


class ScanOut(BaseModel):
    id: uuid.UUID
    scope_group_id: uuid.UUID
    scope_group_name: str
    profile: Literal["scope_check"]
    asset_ids: list[uuid.UUID]
    targets: list[str]
    requested_by_email: str | None
    created_at: datetime
    state: ScanState
    attempt: int
    max_attempts: int
    last_error: str | None
    cancel_requested: bool
    finished_at: datetime | None
    result: dict[str, Any] | None = Field(
        default=None, description="The worker's final report (detail view only)"
    )


class ScanPage(BaseModel):
    items: list[ScanOut]
    total: int


def _scans(
    conn: Connection,
    *,
    only: uuid.UUID | None = None,
    limit: int = 1,
    offset: int = 0,
    with_result: bool = False,
) -> list[ScanOut]:
    rows = (
        conn.execute(
            text(
                "SELECT s.*, g.name AS scope_group_name FROM app.scan s "
                "JOIN app.scope_group g ON g.tenant_id = s.tenant_id AND g.id = s.scope_group_id "
                "WHERE s.tenant_id = app.current_tenant() "
                "AND (CAST(:s AS uuid) IS NULL OR s.id = CAST(:s AS uuid)) "
                "ORDER BY s.created_at DESC, s.id LIMIT :limit OFFSET :offset"
            ),
            {"s": only, "limit": limit, "offset": offset},
        )
        .mappings()
        .all()
    )
    if not rows:
        return []
    jobs = {
        j["id"]: j
        for j in conn.execute(
            text("SELECT * FROM queue.tenant_jobs(:ids)"), {"ids": [r["job_id"] for r in rows]}
        ).mappings()
    }
    emails = {r.user_id: r.email for r in conn.execute(text("SELECT * FROM auth.tenant_members()"))}
    out = []
    for r in rows:
        job = jobs[r["job_id"]]
        result = None
        if with_result:
            final = conn.execute(
                text("SELECT payload FROM queue.job_final_result(:j)"), {"j": r["job_id"]}
            ).first()
            result = final.payload if final else None
        out.append(
            ScanOut(
                id=r["id"],
                scope_group_id=r["scope_group_id"],
                scope_group_name=r["scope_group_name"],
                profile=r["profile"],
                asset_ids=r["asset_ids"],
                targets=r["targets"],
                requested_by_email=emails.get(r["requested_by"]),
                created_at=r["created_at"],
                state=_STATE[job["state"]],
                attempt=job["attempt"],
                max_attempts=job["max_attempts"],
                last_error=job["last_error"],
                cancel_requested=job["cancel_requested"],
                finished_at=job["finished_at"],
                result=result,
            )
        )
    return out


def _one(conn: Connection, scan_id: uuid.UUID) -> ScanOut:
    found = _scans(conn, only=scan_id, with_result=True)
    if not found:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return found[0]


@router.get("")
def list_scans(
    request: Request,
    principal: Reader,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> ScanPage:
    """Newest first."""
    with tenant_tx(engine_of(request), principal) as conn:
        total = conn.execute(
            text("SELECT count(*) FROM app.scan WHERE tenant_id = app.current_tenant()")
        ).scalar_one()
        return ScanPage(items=_scans(conn, limit=limit, offset=offset), total=total)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_scan(
    body: ScanIn,
    request: Request,
    response: Response,
    principal: Runner,
    idempotency_key: Annotated[
        str | None, Header(alias="Idempotency-Key", pattern=r"^[A-Za-z0-9._:-]{8,100}$")
    ] = None,
) -> ScanOut:
    """Scan active assets of one authorized scope group.

    Refused unless the scope group's authorization covers its current entries and every asset
    is inside that scope now. With `Idempotency-Key`, a retry returns the original scan (200).
    """
    asset_ids = sorted(set(body.asset_ids))
    with tenant_tx(engine_of(request), principal) as conn:
        assets = (
            conn.execute(
                text(
                    "SELECT id, scope_group_id, kind, target, status FROM app.asset "
                    "WHERE tenant_id = app.current_tenant() AND id = ANY(:ids) ORDER BY id"
                ),
                {"ids": asset_ids},
            )
            .mappings()
            .all()
        )
        if len(assets) != len(asset_ids):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
        if any(a["status"] != "active" for a in assets):
            raise HTTPException(status.HTTP_409_CONFLICT, "Retired assets cannot be scanned")
        groups = {a["scope_group_id"] for a in assets}
        if len(groups) != 1:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "All assets in one scan must belong to the same scope group",
            )
        group_id = groups.pop()
        group = group_row(conn, group_id, lock=True)  # serializes with (re)authorization
        entries = entries_by_group(conn).get(group_id, [])
        if not is_authorized(group["attested_digest"], entries):  # type: ignore[arg-type]
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "The scope group is not authorized for its current entries; an owner or "
                "administrator must authorize it first",
            )
        targets = [str(a["target"]) for a in assets]
        for a in assets:
            problem = scope_problem(Target(Kind(a["kind"]), str(a["target"])), entries)
            if problem:
                raise HTTPException(status.HTTP_409_CONFLICT, f"{a['target']}: {problem}")

        job = conn.execute(
            text(
                "SELECT * FROM queue.enqueue_scan_task(:g, :kind, CAST(:payload AS jsonb), "
                ":key, CAST(0 AS smallint), 3)"
            ),
            {
                "g": group_id,
                "kind": TASK_KIND,
                "payload": ScanPayload(asset_ids=asset_ids, targets=targets).model_dump_json(),
                "key": f"scan:{idempotency_key}" if idempotency_key else None,
            },
        ).one()
        if not job.created:
            existing = conn.execute(
                text(
                    "SELECT id, asset_ids FROM app.scan "
                    "WHERE tenant_id = app.current_tenant() AND job_id = :j"
                ),
                {"j": job.job_id},
            ).one()
            if sorted(existing.asset_ids) != asset_ids:
                raise HTTPException(
                    status.HTTP_409_CONFLICT, "Idempotency-Key was already used for another scan"
                )
            response.status_code = status.HTTP_200_OK
            return _one(conn, existing.id)

        scan_id = conn.execute(
            text(
                "INSERT INTO app.scan (tenant_id, scope_group_id, profile, asset_ids, targets, "
                "job_id, requested_by) VALUES (app.current_tenant(), :g, 'scope_check', :a, "
                ":t, :j, :by) RETURNING id"
            ),
            {"g": group_id, "a": asset_ids, "t": targets, "j": job.job_id, "by": principal.user_id},
        ).scalar_one()
        audit.record(
            conn,
            principal,
            "scan.requested",
            target_type="scan",
            target_id=str(scan_id),
            ip=client_ip(request),
            detail={"scope_group_id": str(group_id), "assets": len(asset_ids)},
        )
        return _one(conn, scan_id)


@router.get("/{scan_id}")
def get_scan(scan_id: uuid.UUID, request: Request, principal: Reader) -> ScanOut:
    with tenant_tx(engine_of(request), principal) as conn:
        return _one(conn, scan_id)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: uuid.UUID, request: Request, principal: Runner) -> ScanOut:
    """A queued scan is cancelled at once; a running one when its worker next checks in.
    Cancelling a finished scan changes nothing."""
    with tenant_tx(engine_of(request), principal) as conn:
        before = _one(conn, scan_id)
        if before.state in ("queued", "running") and not before.cancel_requested:
            job_id = conn.execute(
                text(
                    "SELECT job_id FROM app.scan WHERE tenant_id = app.current_tenant() AND id = :s"
                ),
                {"s": scan_id},
            ).scalar_one()
            conn.execute(text("SELECT queue.request_cancel(:j)"), {"j": job_id})
            audit.record(
                conn,
                principal,
                "scan.cancel_requested",
                target_type="scan",
                target_id=str(scan_id),
                ip=client_ip(request),
                detail={"state": before.state},
            )
        return _one(conn, scan_id)


class ScanPayload(BaseModel):
    """The job payload the worker API turns into a signed scope lease."""

    profile: Literal["scope_check"] = "scope_check"
    asset_ids: list[uuid.UUID]
    targets: list[str]
