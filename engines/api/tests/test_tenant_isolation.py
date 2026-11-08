"""ADR-0005 §6 route matrix and pool-leakage gates.

Every /api/v1 route must either be public (listed in PUBLIC) or have a two-tenant probe in
PROBES: tenant B's credentials aimed at tenant A's data must see nothing and change nothing.
A new route without a probe fails `test_every_route_is_in_the_matrix`.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest
from conftest import PASSWORD, Org, api_operations, bearer, login, needs_db, unique_email
from fastapi.testclient import TestClient

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


PROBES: dict[tuple[str, str], Callable[[TestClient, Pair], None]] = {
    ("GET", "/api/v1/auth/session"): probe_session,
    ("POST", "/api/v1/auth/logout"): probe_logout,
    ("GET", "/api/v1/organization"): probe_organization,
    ("GET", "/api/v1/members"): probe_list_members,
    ("POST", "/api/v1/members"): probe_add_member,
    ("PATCH", "/api/v1/members/{user_id}"): probe_update_member,
    ("DELETE", "/api/v1/members/{user_id}"): probe_remove_member,
    ("GET", "/api/v1/audit-events"): probe_audit,
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
