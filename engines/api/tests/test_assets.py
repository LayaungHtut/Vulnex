"""Authorized scope and asset inventory (M3) through the API: lifecycle, scope enforcement,
authorization drift, retirement and the role matrix."""

from collections.abc import Callable
from typing import Any

import pytest
from conftest import PASSWORD, Org, bearer, login, needs_db, unique_email
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

pytestmark = needs_db


@pytest.fixture
def owner(client: TestClient, make_org: Callable[..., Org]) -> dict[str, str]:
    return bearer(login(client, make_org().owner_email))


def new_group(client: TestClient, h: dict[str, str], *values: str, name: str = "Lab") -> str:
    r = client.post("/api/v1/scope-groups", headers=h, json={"name": name})
    assert r.status_code == 201, r.text
    g: str = r.json()["id"]
    for v in values:
        exclude = v.startswith("!")
        r = client.post(
            f"/api/v1/scope-groups/{g}/entries",
            headers=h,
            json={"value": v.lstrip("!"), "exclude": exclude},
        )
        assert r.status_code == 201, r.text
    return g


def group(client: TestClient, h: dict[str, str], g: str) -> dict[str, Any]:
    r = client.get(f"/api/v1/scope-groups/{g}", headers=h)
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def authorize(client: TestClient, h: dict[str, str], g: str) -> Any:
    return client.post(f"/api/v1/scope-groups/{g}/authorization", headers=h, json={"confirm": True})


def add_asset(client: TestClient, h: dict[str, str], g: str, target: str, **extra: str) -> Any:
    return client.post(
        "/api/v1/assets", headers=h, json={"scope_group_id": g, "target": target, **extra}
    )


def test_authorization_covers_exactly_the_attested_entries(
    client: TestClient, owner: dict[str, str]
) -> None:
    g = new_group(client, owner)
    assert authorize(client, owner, g).status_code == 409  # nothing included yet
    r = client.post(
        f"/api/v1/scope-groups/{g}/entries", headers=owner, json={"value": "10.1.0.0/16"}
    )
    assert r.json()["authorization"]["status"] == "not_authorized"

    r = authorize(client, owner, g)
    auth = r.json()["authorization"]
    assert r.status_code == 200 and auth["status"] == "authorized"
    assert "owns, or has explicit written permission" in auth["statement"]
    assert auth["authorized_by_email"]

    # Any change to the entries leaves the old authorization behind.
    r = client.post(
        f"/api/v1/scope-groups/{g}/entries", headers=owner, json={"value": "10.2.0.0/16"}
    )
    assert r.json()["authorization"]["status"] == "changed_since_authorization"
    added = next(e for e in r.json()["entries"] if e["value"] == "10.2.0.0/16")
    r = client.delete(f"/api/v1/scope-groups/{g}/entries/{added['id']}", headers=owner)
    assert r.json()["authorization"]["status"] == "authorized"  # back to exactly what was attested

    r = client.delete(f"/api/v1/scope-groups/{g}/authorization", headers=owner)
    assert r.json()["authorization"]["status"] == "not_authorized"

    actions = [
        e["action"]
        for e in client.get(
            f"/api/v1/audit-events?target_type=scope_group&target_id={g}", headers=owner
        ).json()["items"]
    ]
    assert actions == [
        "scope.authorization_revoked",
        "scope_entry.removed",
        "scope_entry.added",
        "scope.authorized",
        "scope_entry.added",
        "scope_group.created",
    ]


@pytest.mark.parametrize(
    ("value", "status", "message"),
    [
        ("127.0.0.0/8", 422, "never scans"),
        ("10.0.0.0/7", 422, "wider than /8"),
        ("2130706433", 422, "dotted-decimal"),
        ("::1", 422, "IPv6"),
        ("10.0.0.1/8", 422, "did you mean 10.0.0.0/8"),
    ],
)
def test_unsafe_scope_entries_are_refused(
    client: TestClient, owner: dict[str, str], value: str, status: int, message: str
) -> None:
    g = new_group(client, owner)
    r = client.post(f"/api/v1/scope-groups/{g}/entries", headers=owner, json={"value": value})
    assert r.status_code == status and message in r.json()["detail"]


def test_duplicate_names_and_entries_conflict(client: TestClient, owner: dict[str, str]) -> None:
    g = new_group(client, owner, "10.0.0.5")
    assert (
        client.post("/api/v1/scope-groups", headers=owner, json={"name": "Lab"}).status_code == 409
    )
    r = client.post(
        f"/api/v1/scope-groups/{g}/entries", headers=owner, json={"value": "10.0.0.5/32"}
    )
    assert r.status_code == 409  # same canonical entry
    other = new_group(client, owner, name="Other")
    r = client.patch(f"/api/v1/scope-groups/{other}", headers=owner, json={"name": "Lab"})
    assert r.status_code == 409


def test_assets_must_be_inside_their_scope_group(client: TestClient, owner: dict[str, str]) -> None:
    g = new_group(client, owner, "10.20.0.0/16", "!10.20.9.0/24", "*.lab.example")
    assert add_asset(client, owner, g, "10.20.1.0/24").status_code == 201
    assert add_asset(client, owner, g, "Web.Lab.Example", name="Web").status_code == 201
    for target, message in [
        ("10.21.0.1", "not inside any included range"),
        ("10.20.9.7", "excluded"),
        ("lab.example", "does not match"),
        ("10.20.0.0/16", "wider than /20"),
        ("0x0a.20.0.1", "dotted-decimal"),
    ]:
        r = add_asset(client, owner, g, target)
        assert r.status_code == 422 and message in r.json()["detail"], (target, r.text)
    r = add_asset(client, owner, g, "web.lab.example")
    assert r.status_code == 409  # canonical form already registered


def test_scope_status_is_recomputed_when_scope_changes(
    client: TestClient, owner: dict[str, str]
) -> None:
    g = new_group(client, owner, "10.30.0.0/16")
    asset = add_asset(client, owner, g, "10.30.1.1").json()
    assert asset["scope"] == {"in_scope": True, "problem": None, "authorized": False}

    authorize(client, owner, g)
    r = client.get(f"/api/v1/assets/{asset['id']}", headers=owner)
    assert r.json()["scope"]["authorized"] is True

    client.post(
        f"/api/v1/scope-groups/{g}/entries",
        headers=owner,
        json={"value": "10.30.1.0/24", "exclude": True},
    )
    scope = client.get(f"/api/v1/assets/{asset['id']}", headers=owner).json()["scope"]
    assert scope["in_scope"] is False and scope["authorized"] is False
    assert "excluded" in scope["problem"]


def test_retire_and_reactivate(client: TestClient, owner: dict[str, str]) -> None:
    g = new_group(client, owner, "10.40.0.0/16")
    a = add_asset(client, owner, g, "10.40.0.9", criticality="high").json()

    r = client.post(f"/api/v1/assets/{a['id']}/retire", headers=owner)
    assert r.json()["status"] == "retired" and r.json()["retired_at"]
    assert client.get("/api/v1/assets", headers=owner).json()["total"] == 0
    assert client.get("/api/v1/assets?status=retired", headers=owner).json()["total"] == 1

    # A retired asset still blocks deleting its scope group: its history depends on it.
    assert client.delete(f"/api/v1/scope-groups/{g}", headers=owner).status_code == 409

    # Reactivation re-checks scope.
    entry = group(client, owner, g)["entries"][0]["id"]
    client.delete(f"/api/v1/scope-groups/{g}/entries/{entry}", headers=owner)
    r = client.post(f"/api/v1/assets/{a['id']}/reactivate", headers=owner)
    assert r.status_code == 422
    client.post(f"/api/v1/scope-groups/{g}/entries", headers=owner, json={"value": "10.40.0.0/20"})
    r = client.post(f"/api/v1/assets/{a['id']}/reactivate", headers=owner)
    assert (
        r.status_code == 200 and r.json()["status"] == "active" and r.json()["retired_at"] is None
    )

    history = client.get(
        f"/api/v1/audit-events?target_type=asset&target_id={a['id']}", headers=owner
    ).json()["items"]
    assert [e["action"] for e in history] == ["asset.reactivated", "asset.retired", "asset.created"]


def test_update_list_filter_and_delete_empty_group(
    client: TestClient, owner: dict[str, str]
) -> None:
    g = new_group(client, owner, "10.50.0.0/16", "db.corp.example")
    a = add_asset(client, owner, g, "10.50.0.1").json()
    add_asset(client, owner, g, "db.corp.example", name="Billing DB", criticality="critical")

    r = client.patch(
        f"/api/v1/assets/{a['id']}", headers=owner, json={"name": "Gateway", "criticality": "low"}
    )
    assert r.json()["name"] == "Gateway" and r.json()["criticality"] == "low"
    assert r.json()["notes"] == ""  # untouched fields keep their values

    def targets(query: str) -> list[str]:
        page = client.get(f"/api/v1/assets{query}", headers=owner).json()
        return sorted(item["target"] for item in page["items"])

    assert targets("") == ["10.50.0.1", "db.corp.example"]
    assert targets("?q=billing") == ["db.corp.example"]
    assert targets("?q=%25") == []  # LIKE wildcards are literal text
    assert targets("?criticality=low") == ["10.50.0.1"]
    assert targets(f"?scope_group_id={g}&limit=1&offset=1") == ["10.50.0.1"]

    empty = new_group(client, owner, name="Empty")
    assert client.delete(f"/api/v1/scope-groups/{empty}", headers=owner).status_code == 204
    assert client.get(f"/api/v1/scope-groups/{empty}", headers=owner).status_code == 404


@pytest.mark.parametrize(
    ("role", "scope_read", "scope_manage", "assets_read", "assets_manage"),
    [
        ("owner", 200, 201, 200, 201),
        ("admin", 200, 201, 200, 201),
        ("analyst", 200, 403, 200, 403),
        ("remediation_contributor", 403, 403, 403, 403),
        ("viewer", 403, 403, 200, 403),
    ],
)
def test_role_matrix(
    client: TestClient,
    make_org: Callable[..., Org],
    role: str,
    scope_read: int,
    scope_manage: int,
    assets_read: int,
    assets_manage: int,
) -> None:
    org = make_org()
    owner = bearer(login(client, org.owner_email))
    g = new_group(client, owner, "10.60.0.0/16")
    email = unique_email(role)
    if role != "owner":
        r = client.post(
            "/api/v1/members",
            headers=owner,
            json={"email": email, "display_name": role, "role": role, "password": PASSWORD},
        )
        assert r.status_code == 201
    h = owner if role == "owner" else bearer(login(client, email))

    assert client.get("/api/v1/scope-groups", headers=h).status_code == scope_read
    r = client.post("/api/v1/scope-groups", headers=h, json={"name": f"{role} group"})
    assert r.status_code == scope_manage
    expected_authorize = 200 if scope_manage == 201 else 403
    assert authorize(client, h, g).status_code == expected_authorize
    assert client.get("/api/v1/assets", headers=h).status_code == assets_read
    assert add_asset(client, h, g, "10.60.0.1").status_code == assets_manage


def test_scope_group_used_by_a_worker_cannot_be_deleted(
    client: TestClient, app_engine: Engine, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    h = bearer(login(client, org.owner_email))
    g = new_group(client, h, name="Worker site")
    with app_engine.begin() as c:
        c.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(org.id)})
        c.execute(
            text("INSERT INTO app.worker (tenant_id, scope_group_id, name) VALUES (:t, :g, 'w1')"),
            {"t": org.id, "g": g},
        )
    r = client.delete(f"/api/v1/scope-groups/{g}", headers=h)
    assert r.status_code == 409 and "scanner workers" in r.json()["detail"]
    assert client.get(f"/api/v1/scope-groups/{g}", headers=h).status_code == 200
