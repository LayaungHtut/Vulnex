"""Authorized scope: scope groups, their entries, and the owner/admin authorization (M3).

A scope group is the boundary a scan may ever touch (ADR-0006 §4: `authorized_cidrs`,
`exclusions`). Its authorization is an attestation by an owner or administrator that covers
exactly the entries present at that moment: the stored digest must equal the digest of the
current entries, so adding, removing or changing any entry leaves the group "changed since
authorization" until someone re-attests. M4 will refuse to scan a group that is not authorized.
"""

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from vulnex import audit
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, engine_of, require
from vulnex.targets import Kind, ScopeEntry, TargetError, parse_scope_entry, scope_digest

router = APIRouter(prefix="/api/v1/scope-groups", tags=["scope"])

STATEMENT = (
    "I confirm that {org} owns, or has explicit written permission to assess, every address and "
    "hostname included in this scope, and that assessing them does not breach any agreement or law."
)


class EntryIn(BaseModel):
    value: str = Field(min_length=1, max_length=260, examples=["10.0.0.0/16", "*.corp.example"])
    exclude: bool = False
    note: str = Field(default="", max_length=200)


class EntryOut(BaseModel):
    id: uuid.UUID
    kind: Kind
    value: str
    exclude: bool
    note: str
    created_at: datetime


class AuthorizationOut(BaseModel):
    status: Literal["authorized", "changed_since_authorization", "not_authorized"]
    authorized_at: datetime | None
    authorized_by_email: str | None
    statement: str | None


class ScopeGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)


class ScopeGroupPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=1000)


class AuthorizeIn(BaseModel):
    confirm: Literal[True] = Field(description="Must be true: the caller accepts the statement")


class ScopeGroupOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    created_at: datetime
    entries: list[EntryOut]
    authorization: AuthorizationOut
    active_assets: int
    retired_assets: int


# ---- shared helpers (also used by assets.py) ----


def entries_by_group(conn: Connection) -> dict[uuid.UUID, list[ScopeEntry]]:
    out: dict[uuid.UUID, list[ScopeEntry]] = defaultdict(list)
    for r in conn.execute(
        text(
            "SELECT scope_group_id, kind, value, exclude FROM app.scope_entry "
            "WHERE tenant_id = app.current_tenant()"
        )
    ):
        out[r.scope_group_id].append(ScopeEntry(Kind(r.kind), r.value, r.exclude))
    return out


def is_authorized(attested_digest: str | None, entries: list[ScopeEntry]) -> bool:
    return attested_digest is not None and attested_digest == scope_digest(entries)


def group_row(conn: Connection, group_id: uuid.UUID, *, lock: bool = False) -> dict[str, object]:
    """The group in the caller's tenant, or 404 (also for another tenant's ID)."""
    row = (
        conn.execute(
            text(
                "SELECT * FROM app.scope_group "  # noqa: S608  (constant fragments)
                "WHERE tenant_id = app.current_tenant() AND id = :g"
                + (" FOR UPDATE" if lock else "")
            ),
            {"g": group_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope group not found")
    return dict(row)


def _groups_out(conn: Connection, only: uuid.UUID | None = None) -> list[ScopeGroupOut]:
    emails = {r.user_id: r.email for r in conn.execute(text("SELECT * FROM auth.tenant_members()"))}
    groups = (
        conn.execute(
            text(
                "SELECT * FROM app.scope_group WHERE tenant_id = app.current_tenant() "
                "AND (CAST(:g AS uuid) IS NULL OR id = CAST(:g AS uuid)) ORDER BY name"
            ),
            {"g": only},
        )
        .mappings()
        .all()
    )
    entries: dict[uuid.UUID, list[EntryOut]] = defaultdict(list)
    for r in (
        conn.execute(
            text(
                "SELECT id, scope_group_id, kind, value, exclude, note, created_at "
                "FROM app.scope_entry WHERE tenant_id = app.current_tenant() "
                "ORDER BY exclude, kind, value"
            )
        )
        .mappings()
        .all()
    ):
        entries[r["scope_group_id"]].append(
            EntryOut(**{k: v for k, v in r.items() if k != "scope_group_id"})
        )
    counts = {
        r.scope_group_id: (r.active, r.retired)
        for r in conn.execute(
            text(
                "SELECT scope_group_id, count(*) FILTER (WHERE status = 'active') AS active, "
                "count(*) FILTER (WHERE status = 'retired') AS retired FROM app.asset "
                "WHERE tenant_id = app.current_tenant() GROUP BY scope_group_id"
            )
        )
    }
    out = []
    for g in groups:
        group_entries = entries[g["id"]]
        plain = [ScopeEntry(e.kind, e.value, e.exclude) for e in group_entries]
        if g["attested_digest"] is None:
            state: Literal["authorized", "changed_since_authorization", "not_authorized"] = (
                "not_authorized"
            )
        elif is_authorized(g["attested_digest"], plain):
            state = "authorized"
        else:
            state = "changed_since_authorization"
        active, retired = counts.get(g["id"], (0, 0))
        out.append(
            ScopeGroupOut(
                id=g["id"],
                name=g["name"],
                description=g["description"],
                created_at=g["created_at"],
                entries=group_entries,
                authorization=AuthorizationOut(
                    status=state,
                    authorized_at=g["attested_at"],
                    authorized_by_email=emails.get(g["attested_by"]) if g["attested_by"] else None,
                    statement=g["attestation_statement"],
                ),
                active_assets=active,
                retired_assets=retired,
            )
        )
    return out


def _one(conn: Connection, group_id: uuid.UUID) -> ScopeGroupOut:
    groups = _groups_out(conn, group_id)
    if not groups:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope group not found")
    return groups[0]


Reader = Annotated[Principal, Depends(require(Permission.SCOPE_READ))]
Manager = Annotated[Principal, Depends(require(Permission.SCOPE_MANAGE))]


# ---- routes ----


@router.get("")
def list_groups(request: Request, principal: Reader) -> list[ScopeGroupOut]:
    with tenant_tx(engine_of(request), principal) as conn:
        return _groups_out(conn)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_group(body: ScopeGroupIn, request: Request, principal: Manager) -> ScopeGroupOut:
    with tenant_tx(engine_of(request), principal) as conn:
        group_id = conn.execute(
            text(
                "INSERT INTO app.scope_group (tenant_id, name, description, created_by) "
                "VALUES (app.current_tenant(), :name, :description, :by) "
                "ON CONFLICT (tenant_id, name) DO NOTHING RETURNING id"
            ),
            {"name": body.name.strip(), "description": body.description, "by": principal.user_id},
        ).scalar()
        if group_id is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "A scope group with that name exists")
        audit.record(
            conn,
            principal,
            "scope_group.created",
            target_type="scope_group",
            target_id=str(group_id),
            ip=client_ip(request),
            detail={"name": body.name.strip()},
        )
        return _one(conn, group_id)


@router.get("/{group_id}")
def get_group(group_id: uuid.UUID, request: Request, principal: Reader) -> ScopeGroupOut:
    with tenant_tx(engine_of(request), principal) as conn:
        return _one(conn, group_id)


@router.patch("/{group_id}")
def update_group(
    group_id: uuid.UUID, body: ScopeGroupPatch, request: Request, principal: Manager
) -> ScopeGroupOut:
    with tenant_tx(engine_of(request), principal) as conn:
        group_row(conn, group_id, lock=True)
        changes = body.model_dump(exclude_none=True)
        if "name" in changes:
            changes["name"] = changes["name"].strip()
            clash = conn.execute(
                text(
                    "SELECT 1 FROM app.scope_group WHERE tenant_id = app.current_tenant() "
                    "AND name = :n AND id <> :g"
                ),
                {"n": changes["name"], "g": group_id},
            ).first()
            if clash:
                raise HTTPException(status.HTTP_409_CONFLICT, "A scope group with that name exists")
        if changes:
            conn.execute(
                text(
                    "UPDATE app.scope_group SET name = coalesce(:name, name), "
                    "description = coalesce(:description, description) "
                    "WHERE tenant_id = app.current_tenant() AND id = :g"
                ),
                {
                    "name": changes.get("name"),
                    "description": changes.get("description"),
                    "g": group_id,
                },
            )
            audit.record(
                conn,
                principal,
                "scope_group.updated",
                target_type="scope_group",
                target_id=str(group_id),
                ip=client_ip(request),
                detail=changes,
            )
        return _one(conn, group_id)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(group_id: uuid.UUID, request: Request, principal: Manager) -> Response:
    with tenant_tx(engine_of(request), principal) as conn:
        group = group_row(conn, group_id, lock=True)
        has_assets = conn.execute(
            text(
                "SELECT 1 FROM app.asset WHERE tenant_id = app.current_tenant() "
                "AND scope_group_id = :g LIMIT 1"
            ),
            {"g": group_id},
        ).first()
        if has_assets:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "This scope group has assets (active or retired); their history depends on it",
            )
        try:
            conn.execute(
                text(
                    "DELETE FROM app.scope_group WHERE tenant_id = app.current_tenant() AND id = :g"
                ),
                {"g": group_id},
            )
        except IntegrityError:  # workers or scan jobs still reference it (RESTRICT keys)
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "This scope group is used by scanner workers or scan jobs",
            ) from None
        audit.record(
            conn,
            principal,
            "scope_group.deleted",
            target_type="scope_group",
            target_id=str(group_id),
            ip=client_ip(request),
            detail={"name": group["name"]},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{group_id}/entries", status_code=status.HTTP_201_CREATED)
def add_entry(
    group_id: uuid.UUID, body: EntryIn, request: Request, principal: Manager
) -> ScopeGroupOut:
    try:
        entry = parse_scope_entry(body.value, exclude=body.exclude)
    except TargetError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    with tenant_tx(engine_of(request), principal) as conn:
        group_row(conn, group_id, lock=True)
        entry_id = conn.execute(
            text(
                "INSERT INTO app.scope_entry "
                "(tenant_id, scope_group_id, kind, value, exclude, note, created_by) "
                "VALUES (app.current_tenant(), :g, :kind, :value, :exclude, :note, :by) "
                "ON CONFLICT (tenant_id, scope_group_id, kind, value, exclude) DO NOTHING "
                "RETURNING id"
            ),
            {
                "g": group_id,
                "kind": entry.kind.value,
                "value": entry.value,
                "exclude": entry.exclude,
                "note": body.note,
                "by": principal.user_id,
            },
        ).scalar()
        if entry_id is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "That entry is already in this scope")
        audit.record(
            conn,
            principal,
            "scope_entry.added",
            target_type="scope_group",
            target_id=str(group_id),
            ip=client_ip(request),
            detail={"value": entry.value, "kind": entry.kind.value, "exclude": entry.exclude},
        )
        return _one(conn, group_id)


@router.delete("/{group_id}/entries/{entry_id}")
def remove_entry(
    group_id: uuid.UUID, entry_id: uuid.UUID, request: Request, principal: Manager
) -> ScopeGroupOut:
    with tenant_tx(engine_of(request), principal) as conn:
        group_row(conn, group_id, lock=True)
        removed = (
            conn.execute(
                text(
                    "DELETE FROM app.scope_entry WHERE tenant_id = app.current_tenant() "
                    "AND scope_group_id = :g AND id = :e RETURNING kind, value, exclude"
                ),
                {"g": group_id, "e": entry_id},
            )
            .mappings()
            .first()
        )
        if removed is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scope entry not found")
        audit.record(
            conn,
            principal,
            "scope_entry.removed",
            target_type="scope_group",
            target_id=str(group_id),
            ip=client_ip(request),
            detail=dict(removed),
        )
        return _one(conn, group_id)


@router.post("/{group_id}/authorization")
def authorize(
    group_id: uuid.UUID, body: AuthorizeIn, request: Request, principal: Manager
) -> ScopeGroupOut:
    """Attest that the organization may assess everything in this scope, as it is now."""
    with tenant_tx(engine_of(request), principal) as conn:
        group_row(conn, group_id, lock=True)
        entries = entries_by_group(conn).get(group_id, [])
        if not any(not e.exclude for e in entries):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Add at least one included entry before authorizing"
            )
        statement = STATEMENT.format(org=principal.tenant_name)
        digest = scope_digest(entries)
        conn.execute(
            text(
                "UPDATE app.scope_group SET attested_at = now(), attested_by = :by, "
                "attested_digest = :d, attestation_statement = :s "
                "WHERE tenant_id = app.current_tenant() AND id = :g"
            ),
            {"by": principal.user_id, "d": digest, "s": statement, "g": group_id},
        )
        audit.record(
            conn,
            principal,
            "scope.authorized",
            target_type="scope_group",
            target_id=str(group_id),
            ip=client_ip(request),
            detail={"entries": len(entries), "digest": digest, "statement": statement},
        )
        return _one(conn, group_id)


@router.delete("/{group_id}/authorization")
def revoke_authorization(
    group_id: uuid.UUID, request: Request, principal: Manager
) -> ScopeGroupOut:
    """Withdraw the authorization immediately (for example, when a permission letter expires)."""
    with tenant_tx(engine_of(request), principal) as conn:
        group = group_row(conn, group_id, lock=True)
        if group["attested_at"] is not None:
            conn.execute(
                text(
                    "UPDATE app.scope_group SET attested_at = NULL, attested_by = NULL, "
                    "attested_digest = NULL, attestation_statement = NULL "
                    "WHERE tenant_id = app.current_tenant() AND id = :g"
                ),
                {"g": group_id},
            )
            audit.record(
                conn,
                principal,
                "scope.authorization_revoked",
                target_type="scope_group",
                target_id=str(group_id),
                ip=client_ip(request),
            )
        return _one(conn, group_id)
