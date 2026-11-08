"""Request dependencies shared by all routers: database engine, settings, caller identity."""

import ipaddress
from collections.abc import Callable
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import Engine, text

from vulnex import security
from vulnex.authz import Permission, Principal, Role
from vulnex.settings import Settings

_bearer = HTTPBearer(auto_error=False, description="Session token from POST /api/v1/auth/login")


def engine_of(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


def settings_of(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip()) if value else None
    except ValueError:
        return None


def resolve_client_ip(
    peer: str | None,
    forwarded_for: str | None,
    trusted: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str | None:
    """The client address, believing X-Forwarded-For only as far as trusted proxies vouch for it.

    Walks the header right to left (nearest hop first) while each hop is a trusted proxy, and
    returns the first untrusted address. A client cannot spoof its address by sending its own
    X-Forwarded-For, because only entries appended by trusted proxies are reached.
    """
    addr = _ip(peer)
    if addr is None:
        return None
    hops = [h for h in (forwarded_for or "").split(",") if h.strip()]
    while hops and any(addr in net for net in trusted):
        nxt = _ip(hops.pop())
        if nxt is None:
            break
        addr = nxt
    return str(addr)


def client_ip(request: Request) -> str | None:
    return resolve_client_ip(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        settings_of(request).trusted_proxy_networks,
    )


def unauthorized() -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Authentication required", {"WWW-Authenticate": "Bearer"}
    )


def resolve_token(engine: Engine, settings: Settings, token: str) -> Principal | None:
    """The live session behind `token`, or None if unknown, revoked, expired or idle."""
    if not 20 <= len(token) <= 100:
        return None
    digest = security.token_digest(token)
    with engine.begin() as conn:
        row = (
            conn.execute(
                text("SELECT * FROM auth.resolve_session(:digest, :idle)"),
                {"digest": digest, "idle": timedelta(minutes=settings.session_idle_minutes)},
            )
            .mappings()
            .first()
        )
    if row is None:
        return None
    return Principal(
        session_id=row["session_id"],
        user_id=row["user_id"],
        email=row["email"],
        display_name=row["display_name"],
        tenant_id=row["tenant_id"],
        tenant_name=row["tenant_name"],
        role=Role(row["role"]),
        expires_at=row["expires_at"],
        token_digest=digest,
    )


def current_principal(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    principal = (
        resolve_token(engine_of(request), settings_of(request), creds.credentials)
        if creds
        else None
    )
    if principal is None:
        raise unauthorized()
    return principal


def require(permission: Permission) -> Callable[[Principal], Principal]:
    """Route dependency: an authenticated principal holding `permission`, else 401/403."""

    def check(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if not principal.can(permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return principal

    return check
