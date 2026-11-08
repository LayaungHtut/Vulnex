"""Authentication: password login, opaque bearer sessions, logout (M2).

Session model. The API accepts sessions only as `Authorization: Bearer <token>`, never from a
cookie. Browsers never attach that header on their own, so the API is not exposed to CSRF. The
console is a backend-for-frontend: it keeps the token in its own HttpOnly cookie, and SvelteKit
checks the Origin of form posts. The token is 256 random bits; the database stores only its
SHA-256. Sessions have an absolute lifetime and an idle timeout, and role and membership are
re-read on every request.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from vulnex import audit, security
from vulnex.authz import Permission, Principal, Role
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, current_principal, engine_of, resolve_token, settings_of

log = logging.getLogger("vulnex.auth")
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

INVALID_LOGIN = "Invalid email or password"


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=1, max_length=security.PASSWORD_MAX)
    organization_id: uuid.UUID | None = Field(
        default=None, description="Organization to sign in to; defaults to the oldest membership"
    )


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str


class OrganizationOut(BaseModel):
    id: uuid.UUID
    name: str


class MembershipOut(BaseModel):
    organization: OrganizationOut
    role: Role


class SessionOut(BaseModel):
    user: UserOut
    organization: OrganizationOut
    role: Role
    permissions: list[Permission]
    expires_at: datetime
    memberships: list[MembershipOut]


class LoginResponse(BaseModel):
    token: str = Field(description="Bearer token. Keep it server-side (HttpOnly cookie).")
    session: SessionOut


def session_out(engine: Engine, p: Principal) -> SessionOut:
    with tenant_tx(engine, p) as conn:
        rows = conn.execute(
            text(
                "SELECT t.id, t.name, m.role FROM app.membership m "
                "JOIN app.tenant t ON t.id = m.tenant_id "
                "WHERE m.user_id = app.current_user_id() ORDER BY m.created_at, t.name"
            )
        ).all()
    return SessionOut(
        user=UserOut(id=p.user_id, email=p.email, display_name=p.display_name),
        organization=OrganizationOut(id=p.tenant_id, name=p.tenant_name),
        role=p.role,
        permissions=sorted(p.permissions),
        expires_at=p.expires_at,
        memberships=[
            MembershipOut(organization=OrganizationOut(id=r.id, name=r.name), role=Role(r.role))
            for r in rows
        ],
    )


@router.post(
    "/login",
    responses={
        401: {"description": INVALID_LOGIN},
        403: {"description": "Correct password, but no access to the requested organization"},
        429: {"description": "Too many failed attempts for this email or address"},
    },
)
def login(body: LoginRequest, request: Request) -> LoginResponse:
    engine, settings = engine_of(request), settings_of(request)
    ip = client_ip(request)
    email = body.email.strip().lower()

    def record_attempt(succeeded: bool) -> None:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT auth.record_login_attempt(:email, CAST(:ip AS inet), :ok)"),
                {"email": email, "ip": ip, "ok": succeeded},
            )

    with engine.begin() as conn:
        by_email, by_ip = conn.execute(
            text("SELECT * FROM auth.login_failures(:email, CAST(:ip AS inet), :window)"),
            {"email": email, "ip": ip, "window": timedelta(minutes=settings.login_window_minutes)},
        ).one()
        if (
            by_email >= settings.login_max_failures_per_email
            or by_ip >= settings.login_max_failures_per_ip
        ):
            log.warning("login throttled", extra={"fields": {"ip": ip}})
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many failed sign-in attempts. Try again later.",
                {"Retry-After": str(settings.login_window_minutes * 60)},
            )
        account = (
            conn.execute(text("SELECT * FROM auth.login_lookup(:email)"), {"email": email})
            .mappings()
            .first()
        )

    # Always verify (against a dummy hash for unknown emails) so timing does not reveal accounts.
    stored: str | None = account["password_hash"] if account else None
    if not security.verify_password(stored, body.password) or not (
        account and account["is_active"] and stored
    ):
        record_attempt(False)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_LOGIN)

    user_id: uuid.UUID = account["user_id"]
    token = security.new_session_token()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.user_id', :u, true)"), {"u": str(user_id)})
        tenants = list(
            conn.execute(
                text("SELECT tenant_id FROM app.membership WHERE user_id = :u ORDER BY created_at"),
                {"u": user_id},
            ).scalars()
        )
        if body.organization_id is not None:
            tenants = [t for t in tenants if t == body.organization_id]
        if not tenants:
            # The password was correct, so saying why reveals nothing to an attacker.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "No access to that organization")
        try:
            conn.execute(
                text(
                    "SELECT * FROM auth.create_session(:u, :t, :digest, :ttl, "
                    "CAST(:ip AS inet), :ua)"
                ),
                {
                    "u": user_id,
                    "t": tenants[0],
                    "digest": security.token_digest(token),
                    "ttl": timedelta(hours=settings.session_ttl_hours),
                    "ip": ip,
                    "ua": request.headers.get("user-agent", "")[:256],
                },
            )
        except DBAPIError:
            # Membership or account changed between the checks above and here.
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_LOGIN) from None
        if security.needs_rehash(stored):
            conn.execute(
                text("SELECT auth.update_password_hash(:u, :h)"),
                {"u": user_id, "h": security.hash_password(body.password)},
            )
    record_attempt(True)

    # Resolve through the normal path, so the response shows exactly what later requests see.
    principal = resolve_token(engine, settings, token)
    if principal is None:  # pragma: no cover - only if the session vanished in between
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_LOGIN)
    with tenant_tx(engine, principal) as conn:
        audit.record(conn, principal, "auth.login", ip=ip)
    return LoginResponse(token=token, session=session_out(engine, principal))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request, principal: Annotated[Principal, Depends(current_principal)]
) -> Response:
    with tenant_tx(engine_of(request), principal) as conn:
        conn.execute(text("SELECT auth.revoke_session(:d)"), {"d": principal.token_digest})
        audit.record(conn, principal, "auth.logout", ip=client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/session")
def get_session(
    request: Request, principal: Annotated[Principal, Depends(current_principal)]
) -> SessionOut:
    """The caller's identity, organization, role, permissions and other memberships."""
    return session_out(engine_of(request), principal)
