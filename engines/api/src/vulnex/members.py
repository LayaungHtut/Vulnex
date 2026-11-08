"""Organization details and membership management (PRD §10).

Rules enforced here, on top of the permission check:
- only an owner may grant the owner role, or change or remove an owner (admins cannot alter owners);
- an organization always keeps at least one owner (owner rows are locked while checking, so two
  concurrent demotions cannot both succeed);
- a member of another organization is indistinguishable from a non-existent one (404).
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import Connection, text

from vulnex import audit, security
from vulnex.authz import Permission, Principal, Role
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, engine_of, require

router = APIRouter(prefix="/api/v1", tags=["organization"])


class OrganizationDetail(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    is_active: bool
    role: Role
    joined_at: datetime


class MemberCreate(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    display_name: str = Field(min_length=1, max_length=100)
    role: Role
    password: str = Field(
        min_length=security.PASSWORD_MIN,
        max_length=security.PASSWORD_MAX,
        description="Initial password for a new account. If the email already has an account, "
        "that account keeps its existing password.",
    )


class MemberUpdate(BaseModel):
    role: Role


@router.get("/organization")
def get_organization(
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.ORGANIZATION_READ))],
) -> OrganizationDetail:
    with tenant_tx(engine_of(request), principal) as conn:
        row = (
            conn.execute(
                text("SELECT id, name, created_at FROM app.tenant WHERE id = app.current_tenant()")
            )
            .mappings()
            .one()
        )
    return OrganizationDetail(**row)


def _member(conn: Connection, user_id: uuid.UUID) -> MemberOut | None:
    row = (
        conn.execute(text("SELECT * FROM auth.tenant_members() WHERE user_id = :u"), {"u": user_id})
        .mappings()
        .first()
    )
    return MemberOut(**row) if row else None


def _existing_member(conn: Connection, user_id: uuid.UUID) -> MemberOut:
    member = _member(conn, user_id)
    if member is None:  # only if the row vanished inside our own transaction
        raise HTTPException(status.HTTP_409_CONFLICT, "Membership changed concurrently")
    return member


def _lock_member(conn: Connection, user_id: uuid.UUID) -> tuple[Role | None, set[uuid.UUID]]:
    """The target's role in this tenant (None if not a member) and the set of owners.

    All owner rows and the target row are locked until commit, so concurrent role changes
    cannot leave the organization without an owner.
    """
    owners = set(
        conn.execute(
            text(
                "SELECT user_id FROM app.membership WHERE tenant_id = app.current_tenant() "
                "AND role = 'owner' FOR UPDATE"
            )
        ).scalars()
    )
    role = conn.execute(
        text(
            "SELECT role FROM app.membership WHERE tenant_id = app.current_tenant() "
            "AND user_id = :u FOR UPDATE"
        ),
        {"u": user_id},
    ).scalar()
    return (Role(role) if role else None), owners


def _keep_an_owner(owners: set[uuid.UUID], leaving: uuid.UUID) -> None:
    if owners <= {leaving}:
        raise HTTPException(status.HTTP_409_CONFLICT, "An organization needs at least one owner")


def _guard_owner_change(principal: Principal, *roles: Role) -> None:
    if Role.OWNER in roles and principal.role != Role.OWNER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an owner can change owner access")


@router.get("/members")
def list_members(
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_READ))],
) -> list[MemberOut]:
    with tenant_tx(engine_of(request), principal) as conn:
        rows = conn.execute(text("SELECT * FROM auth.tenant_members()")).mappings().all()
    return [MemberOut(**r) for r in rows]


@router.post("/members", status_code=status.HTTP_201_CREATED)
def add_member(
    body: MemberCreate,
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
) -> MemberOut:
    _guard_owner_change(principal, body.role)
    password_hash = security.hash_password(body.password)  # before the transaction: ~0.1 s
    with tenant_tx(engine_of(request), principal) as conn:
        user_id = conn.execute(
            text("SELECT user_id FROM auth.create_user(:email, :name, :hash)"),
            {"email": body.email.strip().lower(), "name": body.display_name, "hash": password_hash},
        ).scalar_one()
        if _member(conn, user_id):
            raise HTTPException(status.HTTP_409_CONFLICT, "Already a member")
        conn.execute(
            text(
                "INSERT INTO app.membership (tenant_id, user_id, role) "
                "VALUES (app.current_tenant(), :u, :role)"
            ),
            {"u": user_id, "role": body.role.value},
        )
        audit.record(
            conn,
            principal,
            "member.added",
            target_type="user",
            target_id=str(user_id),
            ip=client_ip(request),
            detail={"role": body.role.value},
        )
        return _existing_member(conn, user_id)


@router.patch("/members/{user_id}")
def update_member(
    user_id: uuid.UUID,
    body: MemberUpdate,
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
) -> MemberOut:
    with tenant_tx(engine_of(request), principal) as conn:
        current, owners = _lock_member(conn, user_id)
        if current is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
        _guard_owner_change(principal, current, body.role)
        if current == Role.OWNER and body.role != Role.OWNER:
            _keep_an_owner(owners, user_id)
        if current != body.role:
            conn.execute(
                text(
                    "UPDATE app.membership SET role = :role "
                    "WHERE tenant_id = app.current_tenant() AND user_id = :u"
                ),
                {"u": user_id, "role": body.role.value},
            )
            audit.record(
                conn,
                principal,
                "member.role_changed",
                target_type="user",
                target_id=str(user_id),
                ip=client_ip(request),
                detail={"from": current.value, "to": body.role.value},
            )
        return _existing_member(conn, user_id)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    user_id: uuid.UUID,
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
) -> Response:
    with tenant_tx(engine_of(request), principal) as conn:
        current, owners = _lock_member(conn, user_id)
        if current is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
        _guard_owner_change(principal, current)
        if current == Role.OWNER:
            _keep_an_owner(owners, user_id)
        conn.execute(
            text(
                "DELETE FROM app.membership WHERE tenant_id = app.current_tenant() AND user_id = :u"
            ),
            {"u": user_id},
        )
        audit.record(
            conn,
            principal,
            "member.removed",
            target_type="user",
            target_id=str(user_id),
            ip=client_ip(request),
            detail={"role": current.value},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
