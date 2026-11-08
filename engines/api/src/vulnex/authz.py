"""Roles and permissions (PRD §10). Deny by default; checked server-side on every route."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    REMEDIATION_CONTRIBUTOR = "remediation_contributor"
    VIEWER = "viewer"


class Permission(StrEnum):
    ORGANIZATION_READ = "organization.read"
    MEMBERS_READ = "members.read"
    MEMBERS_MANAGE = "members.manage"
    AUDIT_READ = "audit.read"


_EVERYONE = {Permission.ORGANIZATION_READ}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(Permission),  # owner-only restrictions are enforced in members.py
    Role.ANALYST: frozenset(_EVERYONE | {Permission.MEMBERS_READ}),
    Role.REMEDIATION_CONTRIBUTOR: frozenset(_EVERYONE),
    Role.VIEWER: frozenset(_EVERYONE),
}


@dataclass(frozen=True)
class Principal:
    """The authenticated caller: one user acting in exactly one tenant."""

    session_id: uuid.UUID
    user_id: uuid.UUID
    email: str
    display_name: str
    tenant_id: uuid.UUID
    tenant_name: str
    role: Role
    expires_at: datetime
    token_digest: bytes = field(repr=False)

    @property
    def permissions(self) -> frozenset[Permission]:
        return ROLE_PERMISSIONS[self.role]

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions
