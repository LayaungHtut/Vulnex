"""Service inventory and evidence (M5): what scans observed, per asset.

Services are the current state of each (asset, address, port) a scan found open; evidence is
the raw, bounded observation a worker submitted, kept as received. Both are tenant data behind
FORCE row-level security; these routes add the permission checks.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import text

from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import engine_of, require

router = APIRouter(prefix="/api/v1", tags=["inventory"])

AssetReader = Annotated[Principal, Depends(require(Permission.ASSETS_READ))]


class ServiceOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_target: str
    asset_name: str
    address: str
    port: int
    transport: str
    state: Literal["open", "closed"]
    name: str | None
    product: str | None
    version: str | None
    tls: bool
    detail: dict[str, Any]
    fingerprint_method: str | None
    rules_version: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    last_scan_id: uuid.UUID
    last_evidence_id: uuid.UUID | None


class ServicePage(BaseModel):
    items: list[ServiceOut]
    total: int


class EvidenceOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    kind: Literal["dns", "service"]
    address: str | None
    port: int | None
    data: dict[str, Any]
    observed_at: datetime
    scanner_version: str
    worker_id: uuid.UUID | None


_SERVICES = (
    "FROM app.service s JOIN app.asset a ON a.tenant_id = s.tenant_id AND a.id = s.asset_id "
    "WHERE s.tenant_id = app.current_tenant() "
    "AND (CAST(:asset AS uuid) IS NULL OR s.asset_id = CAST(:asset AS uuid)) "
    "AND (CAST(:state AS text) IS NULL OR s.state = CAST(:state AS text)) "
    "AND (CAST(:port AS integer) IS NULL OR s.port = CAST(:port AS integer)) "
    "AND (CAST(:q AS text) IS NULL OR s.product ILIKE '%' || CAST(:q AS text) || '%' "
    "     OR s.name ILIKE '%' || CAST(:q AS text) || '%' "
    "     OR host(s.address) = CAST(:q AS text)) "
)


@router.get("/services")
def list_services(
    request: Request,
    principal: AssetReader,
    asset_id: uuid.UUID | None = None,
    state: Literal["open", "closed"] | None = "open",
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> ServicePage:
    """Services by address and port. `q` matches product, service name or an exact address."""
    params = {"asset": asset_id, "state": state, "port": port, "q": q or None}
    with tenant_tx(engine_of(request), principal) as conn:
        total = conn.execute(text("SELECT count(*) " + _SERVICES), params).scalar_one()
        rows = conn.execute(
            text(
                "SELECT s.*, host(s.address) AS address, a.target AS asset_target, "
                "a.name AS asset_name " + _SERVICES + "ORDER BY s.address, s.port "
                "LIMIT :limit OFFSET :offset"
            ),
            params | {"limit": limit, "offset": offset},
        ).mappings()
        return ServicePage(items=[ServiceOut.model_validate(dict(r)) for r in rows], total=total)


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: uuid.UUID, request: Request, principal: AssetReader) -> EvidenceOut:
    with tenant_tx(engine_of(request), principal) as conn:
        row = (
            conn.execute(
                text(
                    "SELECT e.*, host(e.address) AS address FROM app.evidence e "
                    "WHERE e.tenant_id = app.current_tenant() AND e.id = :e"
                ),
                {"e": evidence_id},
            )
            .mappings()
            .first()
        )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    return EvidenceOut.model_validate(dict(row))


@router.get("/scans/{scan_id}/evidence")
def scan_evidence(
    scan_id: uuid.UUID,
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.SCANS_READ))],
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> list[EvidenceOut]:
    """What one scan observed, by address and port."""
    with tenant_tx(engine_of(request), principal) as conn:
        found = conn.execute(
            text("SELECT 1 FROM app.scan WHERE tenant_id = app.current_tenant() AND id = :s"),
            {"s": scan_id},
        ).first()
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
        rows = conn.execute(
            text(
                "SELECT e.*, host(e.address) AS address FROM app.evidence e "
                "WHERE e.tenant_id = app.current_tenant() AND e.scan_id = :s "
                "ORDER BY e.kind, e.address NULLS FIRST, e.port LIMIT :limit OFFSET :offset"
            ),
            {"s": scan_id, "limit": limit, "offset": offset},
        ).mappings()
        return [EvidenceOut.model_validate(dict(r)) for r in rows]
