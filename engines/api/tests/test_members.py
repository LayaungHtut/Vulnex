"""Role-based authorization and membership rules (PRD §10), through the API."""

from collections.abc import Callable

import pytest
from conftest import PASSWORD, Org, bearer, login, needs_db, unique_email
from fastapi.testclient import TestClient

pytestmark = needs_db


def add(client: TestClient, token: str, role: str, email: str | None = None) -> tuple[str, str]:
    email = email or unique_email(role)
    r = client.post(
        "/api/v1/members",
        headers=bearer(token),
        json={"email": email, "display_name": role.title(), "role": role, "password": PASSWORD},
    )
    assert r.status_code == 201, r.text
    return r.json()["user_id"], email


@pytest.fixture
def org_with_roles(client: TestClient, make_org: Callable[..., Org]) -> dict[str, tuple[str, str]]:
    """{role: (user_id, token)} for every role in one fresh organization."""
    org = make_org()
    owner = login(client, org.owner_email)
    out = {"owner": (str(org.owner_id), owner)}
    for role in ("admin", "analyst", "remediation_contributor", "viewer"):
        uid, email = add(client, owner, role)
        out[role] = (uid, login(client, email))
    return out


@pytest.mark.parametrize(
    ("role", "members_read", "members_manage", "audit_read"),
    [
        ("owner", 200, 201, 200),
        ("admin", 200, 201, 200),
        ("analyst", 200, 403, 403),
        ("remediation_contributor", 403, 403, 403),
        ("viewer", 403, 403, 403),
    ],
)
def test_permission_matrix(
    client: TestClient,
    org_with_roles: dict[str, tuple[str, str]],
    role: str,
    members_read: int,
    members_manage: int,
    audit_read: int,
) -> None:
    h = bearer(org_with_roles[role][1])
    assert client.get("/api/v1/organization", headers=h).status_code == 200
    assert client.get("/api/v1/members", headers=h).status_code == members_read
    r = client.post(
        "/api/v1/members",
        headers=h,
        json={"email": unique_email(), "display_name": "N", "role": "viewer", "password": PASSWORD},
    )
    assert r.status_code == members_manage
    assert client.get("/api/v1/audit-events", headers=h).status_code == audit_read


def test_admin_cannot_alter_or_create_owners(
    client: TestClient, org_with_roles: dict[str, tuple[str, str]]
) -> None:
    owner_id, _ = org_with_roles["owner"]
    viewer_id, _ = org_with_roles["viewer"]
    h = bearer(org_with_roles["admin"][1])
    assert (
        client.patch(f"/api/v1/members/{owner_id}", headers=h, json={"role": "viewer"}).status_code
        == 403
    )
    assert client.delete(f"/api/v1/members/{owner_id}", headers=h).status_code == 403
    assert (
        client.patch(f"/api/v1/members/{viewer_id}", headers=h, json={"role": "owner"}).status_code
        == 403
    )
    r = client.post(
        "/api/v1/members",
        headers=h,
        json={"email": unique_email(), "display_name": "N", "role": "owner", "password": PASSWORD},
    )
    assert r.status_code == 403
    # ...but can manage non-owners.
    r = client.patch(f"/api/v1/members/{viewer_id}", headers=h, json={"role": "analyst"})
    assert r.status_code == 200 and r.json()["role"] == "analyst"


def test_last_owner_cannot_leave_or_be_demoted(
    client: TestClient, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    token = login(client, org.owner_email)
    h = bearer(token)
    assert (
        client.patch(
            f"/api/v1/members/{org.owner_id}", headers=h, json={"role": "admin"}
        ).status_code
        == 409
    )
    assert client.delete(f"/api/v1/members/{org.owner_id}", headers=h).status_code == 409

    second, _ = add(client, token, "owner")
    assert (
        client.patch(
            f"/api/v1/members/{org.owner_id}", headers=h, json={"role": "admin"}
        ).status_code
        == 200
    )
    # The demoted user is now an admin and cannot touch the remaining owner.
    assert client.delete(f"/api/v1/members/{second}", headers=h).status_code == 403


def test_duplicate_member_and_validation(client: TestClient, make_org: Callable[..., Org]) -> None:
    org = make_org()
    h = bearer(login(client, org.owner_email))
    _, email = add(client, h["Authorization"].split()[1], "viewer")
    dup = client.post(
        "/api/v1/members",
        headers=h,
        json={"email": email, "display_name": "x", "role": "viewer", "password": PASSWORD},
    )
    assert dup.status_code == 409
    short = client.post(
        "/api/v1/members",
        headers=h,
        json={"email": unique_email(), "display_name": "x", "role": "viewer", "password": "short"},
    )
    assert short.status_code == 422
    bad_role = client.post(
        "/api/v1/members",
        headers=h,
        json={"email": unique_email(), "display_name": "x", "role": "root", "password": PASSWORD},
    )
    assert bad_role.status_code == 422


def test_membership_changes_are_audited(client: TestClient, make_org: Callable[..., Org]) -> None:
    org = make_org()
    token = login(client, org.owner_email)
    h = bearer(token)
    uid, _ = add(client, token, "viewer")
    client.patch(f"/api/v1/members/{uid}", headers=h, json={"role": "analyst"})
    client.delete(f"/api/v1/members/{uid}", headers=h)

    page = client.get("/api/v1/audit-events?limit=3", headers=h).json()
    actions = [e["action"] for e in page["items"]]
    assert actions == ["member.removed", "member.role_changed", "member.added"]
    changed = page["items"][1]
    assert changed["detail"] == {"from": "viewer", "to": "analyst"}
    assert changed["actor_email"] == org.owner_email
    assert changed["target_id"] == uid
    assert changed["request_id"]

    rest = client.get(f"/api/v1/audit-events?before_id={page['next_before_id']}", headers=h).json()
    assert [e["action"] for e in rest["items"]] == ["auth.login", "organization.created"]
    assert rest["next_before_id"] is None
