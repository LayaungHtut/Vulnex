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
    SCOPE_READ = "scope.read"
    SCOPE_MANAGE = "scope.manage"
    ASSETS_READ = "assets.read"
    ASSETS_MANAGE = "assets.manage"
    WORKERS_READ = "workers.read"
    WORKERS_MANAGE = "workers.manage"
    SCANS_READ = "scans.read"
    SCANS_RUN = "scans.run"
    FINDINGS_READ = "findings.read"  # every finding in the tenant
    FINDINGS_WORK = "findings.work"  # comment and report progress on findings assigned to you
    FINDINGS_TRIAGE = "findings.triage"  # status, assignment, due dates, false positives
    FINDINGS_ACCEPT = "findings.accept"  # approve risk acceptance (PRD §10)
    INTEL_READ = "intel.read"


_EVERYONE = {Permission.ORGANIZATION_READ, Permission.INTEL_READ}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(Permission),  # owner-only restrictions are enforced in members.py
    # Managing scope, targets and scanners is owner/admin only (PRD §10). Analysts run scans,
    # but only inside scope an owner or admin has authorized.
    Role.ANALYST: frozenset(
        _EVERYONE
        | {
            Permission.MEMBERS_READ,
            Permission.SCOPE_READ,
            Permission.ASSETS_READ,
            Permission.WORKERS_READ,
            Permission.SCANS_READ,
            Permission.SCANS_RUN,
            Permission.FINDINGS_READ,
            Permission.FINDINGS_WORK,
            Permission.FINDINGS_TRIAGE,
        }
    ),
    # Remediation contributors see and work only the findings assigned to them (PRD §10).
    Role.REMEDIATION_CONTRIBUTOR: frozenset(_EVERYONE | {Permission.FINDINGS_WORK}),
    Role.VIEWER: frozenset(
        _EVERYONE | {Permission.ASSETS_READ, Permission.SCANS_READ, Permission.FINDINGS_READ}
    ),
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
