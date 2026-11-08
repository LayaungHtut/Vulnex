"""ADR-0005 §6 route matrix and pool-leakage gates.

Every /api/v1 route must either be public (listed in PUBLIC) or have a two-tenant probe in
PROBES: tenant B's credentials aimed at tenant A's data must see nothing and change nothing.
A new route without a probe fails `test_every_route_is_in_the_matrix`.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, cast

import pytest
from conftest import PASSWORD, Org, api_operations, bearer, login, needs_db, unique_email
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

pytestmark = needs_db

PUBLIC = {("POST", "/api/v1/auth/login")}


@dataclass
class Pair:
    a: Org
    b: Org
    token_a: str
    token_b: str


@pytest.fixture
def pair(client: TestClient, make_org: Callable[..., Org]) -> Pair:
    a, b = make_org("Tenant A"), make_org("Tenant B")
    return Pair(a, b, login(client, a.owner_email), login(client, b.owner_email))


def a_members(client: TestClient, p: Pair) -> list[dict[str, object]]:
    r = client.get("/api/v1/members", headers=bearer(p.token_a))
    assert r.status_code == 200
    members: list[dict[str, object]] = r.json()
    return members


def probe_session(client: TestClient, p: Pair) -> None:
    body = client.get("/api/v1/auth/session", headers=bearer(p.token_b)).text
    assert str(p.a.id) not in body and p.a.owner_email not in body


def probe_logout(client: TestClient, p: Pair) -> None:
    assert client.post("/api/v1/auth/logout", headers=bearer(p.token_b)).status_code == 204
    assert client.get("/api/v1/auth/session", headers=bearer(p.token_a)).status_code == 200


def probe_organization(client: TestClient, p: Pair) -> None:
    r = client.get("/api/v1/organization", headers=bearer(p.token_b))
    assert r.json()["id"] == str(p.b.id)


def probe_list_members(client: TestClient, p: Pair) -> None:
    body = client.get("/api/v1/members", headers=bearer(p.token_b)).text
    assert p.a.owner_email not in body and str(p.a.owner_id) not in body


def probe_add_member(client: TestClient, p: Pair) -> None:
    before = a_members(client, p)
    email = unique_email()
    r = client.post(
        "/api/v1/members",
        headers=bearer(p.token_b),
        json={"email": email, "display_name": "x", "role": "owner", "password": PASSWORD},
    )
    assert r.status_code == 201  # lands in B, the caller's own tenant
    assert a_members(client, p) == before


def probe_update_member(client: TestClient, p: Pair) -> None:
    r = client.patch(
        f"/api/v1/members/{p.a.owner_id}", headers=bearer(p.token_b), json={"role": "viewer"}
    )
    assert r.status_code == 404
    assert [m["role"] for m in a_members(client, p)] == ["owner"]


def probe_remove_member(client: TestClient, p: Pair) -> None:
    assert (
        client.delete(f"/api/v1/members/{p.a.owner_id}", headers=bearer(p.token_b)).status_code
        == 404
    )
    assert len(a_members(client, p)) == 1


def probe_audit(client: TestClient, p: Pair) -> None:
    r = client.get("/api/v1/audit-events?limit=200", headers=bearer(p.token_b))
    body = r.text
    assert r.status_code == 200
    assert str(p.a.owner_id) not in body and p.a.owner_email not in body


# ---- M3: scope groups and assets. A's objects, attacked with B's (owner) token. ----


@dataclass
class AData:
    group: str
    entry: str
    asset: str


def a_data(client: TestClient, p: Pair) -> AData:
    h = bearer(p.token_a)
    g = client.post("/api/v1/scope-groups", headers=h, json={"name": "A scope"}).json()["id"]
    r = client.post(f"/api/v1/scope-groups/{g}/entries", headers=h, json={"value": "10.9.0.0/16"})
    entry = r.json()["entries"][0]["id"]
    r = client.post("/api/v1/assets", headers=h, json={"scope_group_id": g, "target": "10.9.0.5"})
    return AData(g, entry, r.json()["id"])


def a_group(client: TestClient, p: Pair, d: AData) -> dict[str, Any]:
    r = client.get(f"/api/v1/scope-groups/{d.group}", headers=bearer(p.token_a))
    assert r.status_code == 200
    group: dict[str, Any] = r.json()
    return group


def a_asset(client: TestClient, p: Pair, d: AData) -> dict[str, Any]:
    r = client.get(f"/api/v1/assets/{d.asset}", headers=bearer(p.token_a))
    assert r.status_code == 200
    asset: dict[str, Any] = r.json()
    return asset


def probe_list_groups(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    body = client.get("/api/v1/scope-groups", headers=bearer(p.token_b)).text
    assert d.group not in body and "10.9.0.0" not in body


def probe_create_group(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.post("/api/v1/scope-groups", headers=bearer(p.token_b), json={"name": "A scope"})
    assert r.status_code == 201  # the same name is fine: it lands in B, not A
    assert r.json()["id"] != d.group
    assert a_group(client, p, d)["name"] == "A scope"


def probe_get_group(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.get(f"/api/v1/scope-groups/{d.group}", headers=bearer(p.token_b))
    assert r.status_code == 404


def probe_update_group(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.patch(
        f"/api/v1/scope-groups/{d.group}", headers=bearer(p.token_b), json={"name": "pwned"}
    )
    assert r.status_code == 404
    assert a_group(client, p, d)["name"] == "A scope"


def probe_delete_group(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.delete(f"/api/v1/scope-groups/{d.group}", headers=bearer(p.token_b))
    assert r.status_code == 404
    a_group(client, p, d)


def probe_add_entry(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.post(
        f"/api/v1/scope-groups/{d.group}/entries",
        headers=bearer(p.token_b),
        json={"value": "198.51.100.0/24"},
    )
    assert r.status_code == 404
    assert len(a_group(client, p, d)["entries"]) == 1


def probe_remove_entry(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    # Also through B's own group with A's entry ID: the entry must stay unreachable.
    own = client.post("/api/v1/scope-groups", headers=bearer(p.token_b), json={"name": "b"})
    for g in (d.group, own.json()["id"]):
        r = client.delete(f"/api/v1/scope-groups/{g}/entries/{d.entry}", headers=bearer(p.token_b))
        assert r.status_code == 404
    assert len(a_group(client, p, d)["entries"]) == 1


def probe_authorize(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.post(
        f"/api/v1/scope-groups/{d.group}/authorization",
        headers=bearer(p.token_b),
        json={"confirm": True},
    )
    assert r.status_code == 404
    assert a_group(client, p, d)["authorization"]["status"] == "not_authorized"


def probe_revoke(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    client.post(
        f"/api/v1/scope-groups/{d.group}/authorization",
        headers=bearer(p.token_a),
        json={"confirm": True},
    )
    r = client.delete(f"/api/v1/scope-groups/{d.group}/authorization", headers=bearer(p.token_b))
    assert r.status_code == 404
    assert a_group(client, p, d)["authorization"]["status"] == "authorized"


def probe_list_assets(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    for query in ("", "?status=all", f"?scope_group_id={d.group}", "?q=10.9"):
        r = client.get(f"/api/v1/assets{query}", headers=bearer(p.token_b))
        assert r.status_code == 200
        assert r.json()["total"] == 0 and d.asset not in r.text


def probe_create_asset(client: TestClient, p: Pair) -> None:
    """IDOR: B names A's scope group in the request body."""
    d = a_data(client, p)
    r = client.post(
        "/api/v1/assets",
        headers=bearer(p.token_b),
        json={"scope_group_id": d.group, "target": "10.9.0.6"},
    )
    assert r.status_code == 404
    r = client.get("/api/v1/assets?status=all", headers=bearer(p.token_a))
    assert r.json()["total"] == 1


def probe_get_asset(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    assert client.get(f"/api/v1/assets/{d.asset}", headers=bearer(p.token_b)).status_code == 404


def probe_update_asset(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.patch(f"/api/v1/assets/{d.asset}", headers=bearer(p.token_b), json={"name": "x"})
    assert r.status_code == 404
    assert a_asset(client, p, d)["name"] == ""


def probe_retire_asset(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    r = client.post(f"/api/v1/assets/{d.asset}/retire", headers=bearer(p.token_b))
    assert r.status_code == 404
    assert a_asset(client, p, d)["status"] == "active"


def probe_reactivate_asset(client: TestClient, p: Pair) -> None:
    d = a_data(client, p)
    client.post(f"/api/v1/assets/{d.asset}/retire", headers=bearer(p.token_a))
    r = client.post(f"/api/v1/assets/{d.asset}/reactivate", headers=bearer(p.token_b))
    assert r.status_code == 404
    assert a_asset(client, p, d)["status"] == "retired"


def test_audit_target_filter_stays_in_tenant(client: TestClient, pair: Pair) -> None:
    d = a_data(client, pair)
    url = f"/api/v1/audit-events?target_type=asset&target_id={d.asset}"
    assert len(client.get(url, headers=bearer(pair.token_a)).json()["items"]) == 1
    r = client.get(url, headers=bearer(pair.token_b))
    assert r.status_code == 200 and r.json()["items"] == []


M3_PROBES: dict[tuple[str, str], Callable[[TestClient, Pair], None]] = {
    ("GET", "/api/v1/scope-groups"): probe_list_groups,
    ("POST", "/api/v1/scope-groups"): probe_create_group,
    ("GET", "/api/v1/scope-groups/{group_id}"): probe_get_group,
    ("PATCH", "/api/v1/scope-groups/{group_id}"): probe_update_group,
    ("DELETE", "/api/v1/scope-groups/{group_id}"): probe_delete_group,
    ("POST", "/api/v1/scope-groups/{group_id}/entries"): probe_add_entry,
    ("DELETE", "/api/v1/scope-groups/{group_id}/entries/{entry_id}"): probe_remove_entry,
    ("POST", "/api/v1/scope-groups/{group_id}/authorization"): probe_authorize,
    ("DELETE", "/api/v1/scope-groups/{group_id}/authorization"): probe_revoke,
    ("GET", "/api/v1/assets"): probe_list_assets,
    ("POST", "/api/v1/assets"): probe_create_asset,
    ("GET", "/api/v1/assets/{asset_id}"): probe_get_asset,
    ("PATCH", "/api/v1/assets/{asset_id}"): probe_update_asset,
    ("POST", "/api/v1/assets/{asset_id}/retire"): probe_retire_asset,
    ("POST", "/api/v1/assets/{asset_id}/reactivate"): probe_reactivate_asset,
}


@dataclass
class M4Data:
    group: str
    asset: str
    scan: str
    enrollment: str
    worker: str


def a_m4(client: TestClient, p: Pair) -> M4Data:
    """Tenant A with an authorized group, a queued scan, an unused enrollment and a worker."""
    d = a_data(client, p)
    h = bearer(p.token_a)
    r = client.post(
        f"/api/v1/scope-groups/{d.group}/authorization", headers=h, json={"confirm": True}
    )
    assert r.status_code == 200
    scan = client.post("/api/v1/scans", headers=h, json={"asset_ids": [d.asset]}).json()["id"]
    r = client.post(
        "/api/v1/workers/enrollments", headers=h, json={"scope_group_id": d.group, "name": "a-e"}
    )
    engine: Engine = cast(FastAPI, client.app).state.engine
    with engine.begin() as c:
        c.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(p.a.id)})
        worker = c.execute(
            text(
                "INSERT INTO app.worker (tenant_id, scope_group_id, name) "
                "VALUES (:t, :g, 'a-worker') RETURNING id"
            ),
            {"t": p.a.id, "g": d.group},
        ).scalar_one()
    return M4Data(d.group, d.asset, scan, r.json()["id"], str(worker))


def a_get(client: TestClient, p: Pair, path: str) -> Any:
    r = client.get(path, headers=bearer(p.token_a))
    assert r.status_code == 200
    return r.json()


def probe_list_workers(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    r = client.get("/api/v1/workers", headers=bearer(p.token_b))
    assert r.status_code == 200 and r.json() == [] and d.worker not in r.text


def probe_revoke_worker(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    r = client.post(f"/api/v1/workers/{d.worker}/revoke", headers=bearer(p.token_b))
    assert r.status_code == 404
    assert a_get(client, p, "/api/v1/workers")[0]["status"] == "active"


def probe_list_enrollments(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    r = client.get("/api/v1/workers/enrollments", headers=bearer(p.token_b))
    assert r.status_code == 200 and r.json() == [] and d.enrollment not in r.text


def probe_create_enrollment(client: TestClient, p: Pair) -> None:
    """IDOR: B names A's scope group."""
    d = a_m4(client, p)
    r = client.post(
        "/api/v1/workers/enrollments",
        headers=bearer(p.token_b),
        json={"scope_group_id": d.group, "name": "b-e"},
    )
    assert r.status_code == 404
    assert len(a_get(client, p, "/api/v1/workers/enrollments")) == 1


def probe_revoke_enrollment(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    r = client.delete(f"/api/v1/workers/enrollments/{d.enrollment}", headers=bearer(p.token_b))
    assert r.status_code == 404
    assert a_get(client, p, "/api/v1/workers/enrollments")[0]["status"] == "pending"


def probe_list_scans(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    r = client.get("/api/v1/scans", headers=bearer(p.token_b))
    assert r.status_code == 200 and r.json()["total"] == 0 and d.scan not in r.text


def probe_create_scan(client: TestClient, p: Pair) -> None:
    """IDOR: B names A's asset."""
    d = a_m4(client, p)
    r = client.post("/api/v1/scans", headers=bearer(p.token_b), json={"asset_ids": [d.asset]})
    assert r.status_code == 404
    assert a_get(client, p, "/api/v1/scans")["total"] == 1


def probe_get_scan(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    assert client.get(f"/api/v1/scans/{d.scan}", headers=bearer(p.token_b)).status_code == 404


def probe_cancel_scan(client: TestClient, p: Pair) -> None:
    d = a_m4(client, p)
    r = client.post(f"/api/v1/scans/{d.scan}/cancel", headers=bearer(p.token_b))
    assert r.status_code == 404
    assert a_get(client, p, f"/api/v1/scans/{d.scan}")["state"] == "queued"


M4_PROBES: dict[tuple[str, str], Callable[[TestClient, Pair], None]] = {
    ("GET", "/api/v1/workers"): probe_list_workers,
    ("POST", "/api/v1/workers/{worker_id}/revoke"): probe_revoke_worker,
    ("GET", "/api/v1/workers/enrollments"): probe_list_enrollments,
    ("POST", "/api/v1/workers/enrollments"): probe_create_enrollment,
    ("DELETE", "/api/v1/workers/enrollments/{enrollment_id}"): probe_revoke_enrollment,
    ("GET", "/api/v1/scans"): probe_list_scans,
    ("POST", "/api/v1/scans"): probe_create_scan,
    ("GET", "/api/v1/scans/{scan_id}"): probe_get_scan,
    ("POST", "/api/v1/scans/{scan_id}/cancel"): probe_cancel_scan,
}


PROBES: dict[tuple[str, str], Callable[[TestClient, Pair], None]] = {
    ("GET", "/api/v1/auth/session"): probe_session,
    ("POST", "/api/v1/auth/logout"): probe_logout,
    ("GET", "/api/v1/organization"): probe_organization,
    ("GET", "/api/v1/members"): probe_list_members,
    ("POST", "/api/v1/members"): probe_add_member,
    ("PATCH", "/api/v1/members/{user_id}"): probe_update_member,
    ("DELETE", "/api/v1/members/{user_id}"): probe_remove_member,
    ("GET", "/api/v1/audit-events"): probe_audit,
    **M3_PROBES,
    **M4_PROBES,
}


def test_every_route_is_in_the_matrix(client: TestClient) -> None:
    assert api_operations(client.app) == set(PROBES) | PUBLIC  # type: ignore[arg-type]


@pytest.mark.parametrize("route", sorted(PROBES), ids=lambda r: f"{r[0]} {r[1]}")
def test_cross_tenant_probe(client: TestClient, pair: Pair, route: tuple[str, str]) -> None:
    PROBES[route](client, pair)


def test_concurrent_requests_never_see_the_other_tenant(client: TestClient, pair: Pair) -> None:
    """Interleave both tenants across the pool; transaction-local context must never leak."""
    jobs = [(pair.token_a, pair.a), (pair.token_b, pair.b)] * 40

    def call(job: tuple[str, Org]) -> tuple[Org, str, str]:
        token, org = job
        org_body = client.get("/api/v1/organization", headers=bearer(token)).text
        members_body = client.get("/api/v1/members", headers=bearer(token)).text
        return org, org_body, members_body

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(call, jobs))
    for org, org_body, members_body in results:
        other = pair.b if org is pair.a else pair.a
        assert str(org.id) in org_body and str(other.id) not in org_body
        assert org.owner_email in members_body and other.owner_email not in members_body
