"""Append-only audit events, written in the same transaction as the change they describe."""

import json
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import Connection, text

from vulnex import logs
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import engine_of, require

router = APIRouter(prefix="/api/v1/audit-events", tags=["audit"])


def record(
    conn: Connection,
    principal: Principal,
    action: str,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    ip: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Insert one event for the principal's tenant. `conn` must come from `tenant_tx`."""
    conn.execute(
        text(
            "INSERT INTO app.audit_event (tenant_id, actor_user_id, action, target_type, "
            "target_id, ip, request_id, detail) VALUES (app.current_tenant(), :actor, :action, "
            ":target_type, :target_id, CAST(:ip AS inet), :rid, CAST(:detail AS jsonb))"
        ),
        {
            "actor": principal.user_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "ip": ip,
            "rid": logs.request_id.get(),
            "detail": json.dumps(detail or {}),
        },
    )


class AuditEventOut(BaseModel):
    id: int
    occurred_at: datetime
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    request_id: str | None
    detail: dict[str, Any]


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_before_id: int | None


@router.get("")
def list_events(
    request: Request,
    principal: Annotated[Principal, Depends(require(Permission.AUDIT_READ))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
) -> AuditPage:
    """Newest first. For the next page pass `before_id` = this page's `next_before_id`."""
    with tenant_tx(engine_of(request), principal) as conn:
        emails = {
            r.user_id: r.email
            for r in conn.execute(text("SELECT user_id, email FROM auth.tenant_members()"))
        }
        rows = (
            conn.execute(
                text(
                    "SELECT id, occurred_at, actor_user_id, action, target_type, target_id, "
                    "host(ip) AS ip, request_id, detail FROM app.audit_event "
                    "WHERE tenant_id = app.current_tenant() "
                    "AND (CAST(:before AS bigint) IS NULL OR id < CAST(:before AS bigint)) "
                    "ORDER BY id DESC LIMIT :limit"
                ),
                {"before": before_id, "limit": limit + 1},
            )
            .mappings()
            .all()
        )
    items = [AuditEventOut(**r, actor_email=emails.get(r["actor_user_id"])) for r in rows[:limit]]
    return AuditPage(items=items, next_before_id=items[-1].id if len(rows) > limit else None)
