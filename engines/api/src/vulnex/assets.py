# ruff: noqa: S608  -- queries join constant SQL fragments; every user value is a bound parameter
"""Asset inventory (M3): registered targets inside a scope group. Retired, never deleted.

An asset must lie inside its scope group when it is registered or reactivated. Scope can change
afterwards, so every read recomputes `in_scope` and `authorized`; M4 scans only assets for which
both are true, and the worker re-checks every address at connection time (ADR-0006).
"""

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import Connection, text

from vulnex import audit
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, engine_of, require
from vulnex.scope import entries_by_group, group_row, is_authorized
from vulnex_worker_protocol.targets import (
    ASSET_MIN_PREFIX,
    Kind,
    Target,
    TargetError,
    parse,
    scope_problem,
)

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])

Criticality = Literal["low", "medium", "high", "critical"]


class AssetIn(BaseModel):
    scope_group_id: uuid.UUID
    target: str = Field(min_length=1, max_length=260, examples=["10.0.4.0/24", "app.example.com"])
    name: str = Field(default="", max_length=100)
    criticality: Criticality = "medium"
    notes: str = Field(default="", max_length=2000)


class AssetPatch(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    criticality: Criticality | None = None
    notes: str | None = Field(default=None, max_length=2000)


class ScopeStatus(BaseModel):
    in_scope: bool
    problem: str | None
    authorized: bool = Field(description="In scope, and the scope group's authorization is current")


class AssetOut(BaseModel):
    id: uuid.UUID
    scope_group_id: uuid.UUID
    scope_group_name: str
    kind: Literal["ip", "cidr", "hostname"]
    target: str
    name: str
    criticality: Criticality
    notes: str
    source: Literal["user", "discovered"]
    status: Literal["active", "retired"]
    created_at: datetime
    updated_at: datetime
    retired_at: datetime | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    scope: ScopeStatus


class AssetPage(BaseModel):
    items: list[AssetOut]
    total: int


_SELECT = (
    "SELECT a.*, g.name AS scope_group_name, g.attested_digest FROM app.asset a "
    "JOIN app.scope_group g ON g.tenant_id = a.tenant_id AND g.id = a.scope_group_id "
    "WHERE a.tenant_id = app.current_tenant() "
)


def _out(rows: list[dict[str, Any]], conn: Connection) -> list[AssetOut]:
    entries = entries_by_group(conn)
    out = []
    for r in rows:
        group_entries = entries.get(r["scope_group_id"], [])
        problem = scope_problem(Target(Kind(r["kind"]), str(r["target"])), group_entries)
        authorized = problem is None and is_authorized(r["attested_digest"], group_entries)
        out.append(
            AssetOut.model_validate(
                {
                    **r,
                    "scope": ScopeStatus(
                        in_scope=problem is None, problem=problem, authorized=authorized
                    ),
                }
            )
        )
    return out


def _get(conn: Connection, asset_id: uuid.UUID, *, lock: bool = False) -> dict[str, Any]:
    row = (
        conn.execute(
            text(_SELECT + "AND a.id = :a" + (" FOR UPDATE OF a" if lock else "")), {"a": asset_id}
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return dict(row)


def _require_in_scope(conn: Connection, scope_group_id: uuid.UUID, target: Target) -> None:
    problem = scope_problem(target, entries_by_group(conn).get(scope_group_id, []))
    if problem:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, problem)


def _record(
    conn: Connection,
    principal: Principal,
    request: Request,
    action: str,
    asset_id: uuid.UUID,
    **detail: object,
) -> None:
    audit.record(
        conn,
        principal,
        action,
        target_type="asset",
        target_id=str(asset_id),
        ip=client_ip(request),
        detail=detail,
    )


Reader = Annotated[Principal, Depends(require(Permission.ASSETS_READ))]
Manager = Annotated[Principal, Depends(require(Permission.ASSETS_MANAGE))]


@router.get("")
def list_assets(
    request: Request,
    principal: Reader,
    status_: Annotated[Literal["active", "retired", "all"], Query(alias="status")] = "active",
    scope_group_id: uuid.UUID | None = None,
    criticality: Criticality | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AssetPage:
    where = (
        "AND (:status = 'all' OR a.status = :status) "
        "AND (CAST(:g AS uuid) IS NULL OR a.scope_group_id = CAST(:g AS uuid)) "
        "AND (CAST(:c AS text) IS NULL OR a.criticality = :c) "
        "AND (CAST(:q AS text) IS NULL OR "
        "strpos(lower(a.target || ' ' || a.name), lower(CAST(:q AS text))) > 0) "
    )
    params = {"status": status_, "g": scope_group_id, "c": criticality, "q": q or None}
    with tenant_tx(engine_of(request), principal) as conn:
        total = conn.execute(
            text("SELECT count(*) FROM (" + _SELECT + where + ") s"), params
        ).scalar_one()
        rows = (
            conn.execute(
                text(
                    _SELECT + where + "ORDER BY a.created_at DESC, a.id LIMIT :limit OFFSET :offset"
                ),
                {**params, "limit": limit, "offset": offset},
            )
            .mappings()
            .all()
        )
        return AssetPage(items=_out([dict(r) for r in rows], conn), total=total)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_asset(body: AssetIn, request: Request, principal: Manager) -> AssetOut:
    try:
        target = parse(body.target, min_prefix=ASSET_MIN_PREFIX)
    except TargetError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    with tenant_tx(engine_of(request), principal) as conn:
        group_row(conn, body.scope_group_id, lock=True)  # 404 for another tenant's group
        _require_in_scope(conn, body.scope_group_id, target)
        asset_id = conn.execute(
            text(
                "INSERT INTO app.asset (tenant_id, scope_group_id, kind, target, name, "
                "criticality, notes, created_by) VALUES (app.current_tenant(), :g, :kind, "
                ":target, :name, :criticality, :notes, :by) "
                "ON CONFLICT (tenant_id, scope_group_id, kind, target) DO NOTHING RETURNING id"
            ),
            {
                "g": body.scope_group_id,
                "kind": target.kind.value,
                "target": target.value,
                "name": body.name.strip(),
                "criticality": body.criticality,
                "notes": body.notes,
                "by": principal.user_id,
            },
        ).scalar()
        if asset_id is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{target.value} is already registered in this scope group (it may be retired)",
            )
        _record(
            conn,
            principal,
            request,
            "asset.created",
            asset_id,
            target=target.value,
            criticality=body.criticality,
        )
        return _out([_get(conn, asset_id)], conn)[0]


@router.get("/{asset_id}")
def get_asset(asset_id: uuid.UUID, request: Request, principal: Reader) -> AssetOut:
    with tenant_tx(engine_of(request), principal) as conn:
        return _out([_get(conn, asset_id)], conn)[0]


@router.patch("/{asset_id}")
def update_asset(
    asset_id: uuid.UUID, body: AssetPatch, request: Request, principal: Manager
) -> AssetOut:
    changes = body.model_dump(exclude_none=True)
    with tenant_tx(engine_of(request), principal) as conn:
        _get(conn, asset_id, lock=True)
        if changes:
            conn.execute(
                text(
                    "UPDATE app.asset SET name = coalesce(:name, name), "
                    "criticality = coalesce(:criticality, criticality), "
                    "notes = coalesce(:notes, notes), updated_at = now() "
                    "WHERE tenant_id = app.current_tenant() AND id = :a"
                ),
                {
                    "name": changes["name"].strip() if "name" in changes else None,
                    "criticality": changes.get("criticality"),
                    "notes": changes.get("notes"),
                    "a": asset_id,
                },
            )
            _record(conn, principal, request, "asset.updated", asset_id, **changes)
        return _out([_get(conn, asset_id)], conn)[0]


@router.post("/{asset_id}/retire")
def retire_asset(asset_id: uuid.UUID, request: Request, principal: Manager) -> AssetOut:
    """Stop assessing the asset. Its history stays; reactivate to resume."""
    with tenant_tx(engine_of(request), principal) as conn:
        if _get(conn, asset_id, lock=True)["status"] == "active":
            conn.execute(
                text(
                    "UPDATE app.asset SET status = 'retired', retired_at = now(), "
                    "updated_at = now() WHERE tenant_id = app.current_tenant() AND id = :a"
                ),
                {"a": asset_id},
            )
            _record(conn, principal, request, "asset.retired", asset_id)
        return _out([_get(conn, asset_id)], conn)[0]


@router.post("/{asset_id}/reactivate")
def reactivate_asset(asset_id: uuid.UUID, request: Request, principal: Manager) -> AssetOut:
    with tenant_tx(engine_of(request), principal) as conn:
        row = _get(conn, asset_id, lock=True)
        if row["status"] == "retired":
            _require_in_scope(
                conn,
                row["scope_group_id"],
                Target(Kind(row["kind"]), str(row["target"])),
            )
            conn.execute(
                text(
                    "UPDATE app.asset SET status = 'active', retired_at = NULL, "
                    "updated_at = now() WHERE tenant_id = app.current_tenant() AND id = :a"
                ),
                {"a": asset_id},
            )
            _record(conn, principal, request, "asset.reactivated", asset_id)
        return _out([_get(conn, asset_id)], conn)[0]
