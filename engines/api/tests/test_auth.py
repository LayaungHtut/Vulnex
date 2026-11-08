"""Login, sessions, logout, throttling and session invalidation (M2)."""

import hashlib
from collections.abc import Callable

from conftest import PASSWORD, Org, bearer, login, needs_db, unique_email
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

pytestmark = needs_db


def test_login_returns_session_with_role_and_permissions(
    client: TestClient, make_org: Callable[..., Org]
) -> None:
    org = make_org("Acme")
    r = client.post(
        "/api/v1/auth/login", json={"email": org.owner_email.upper(), "password": PASSWORD}
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["token"]) >= 40
    s = body["session"]
    assert s["user"]["email"] == org.owner_email
    assert s["organization"] == {"id": str(org.id), "name": "Acme"}
    assert s["role"] == "owner"
    assert "members.manage" in s["permissions"]
    assert s["memberships"] == [
        {"organization": {"id": str(org.id), "name": "Acme"}, "role": "owner"}
    ]

    me = client.get("/api/v1/auth/session", headers=bearer(body["token"]))
    assert me.status_code == 200 and me.json()["user"]["id"] == str(org.owner_id)


def test_wrong_password_and_unknown_email_look_identical(
    client: TestClient, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    wrong = client.post("/api/v1/auth/login", json={"email": org.owner_email, "password": "nope"})
    unknown = client.post("/api/v1/auth/login", json={"email": unique_email(), "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert (
        wrong.json()
        == unknown.json()
        == {
            "type": "about:blank",
            "title": "Unauthorized",
            "status": 401,
            "detail": "Invalid email or password",
        }
    )


def test_repeated_failures_are_throttled_even_with_the_right_password(
    client: TestClient, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    for _ in range(5):
        r = client.post("/api/v1/auth/login", json={"email": org.owner_email, "password": "bad"})
        assert r.status_code == 401
    r = client.post("/api/v1/auth/login", json={"email": org.owner_email, "password": PASSWORD})
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) > 0


def test_session_token_is_stored_only_as_a_hash(
    client: TestClient, owner_engine: Engine, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    token = login(client, org.owner_email)
    with owner_engine.connect() as c:
        stored = (
            c.execute(
                text("SELECT token_hash FROM auth.session WHERE user_id = :u"), {"u": org.owner_id}
            )
            .scalars()
            .all()
        )
        pw = c.execute(
            text("SELECT password_hash FROM auth.user_account WHERE id = :u"), {"u": org.owner_id}
        ).scalar_one()
    assert hashlib.sha256(token.encode()).digest() in [bytes(s) for s in stored]
    assert all(token.encode() not in bytes(s) for s in stored)
    assert pw.startswith("$argon2id$")


def test_logout_revokes_only_that_session(client: TestClient, make_org: Callable[..., Org]) -> None:
    org = make_org()
    first, second = login(client, org.owner_email), login(client, org.owner_email)
    assert client.post("/api/v1/auth/logout", headers=bearer(first)).status_code == 204
    assert client.get("/api/v1/auth/session", headers=bearer(first)).status_code == 401
    assert client.get("/api/v1/auth/session", headers=bearer(second)).status_code == 200


def test_idle_and_expired_sessions_are_rejected(
    client: TestClient, owner_engine: Engine, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    idle, expired = login(client, org.owner_email), login(client, org.owner_email)
    with owner_engine.begin() as c:
        c.execute(
            text(
                "UPDATE auth.session SET last_seen_at = now() - interval '31 minutes' "
                "WHERE token_hash = :d"
            ),
            {"d": hashlib.sha256(idle.encode()).digest()},
        )
        c.execute(
            text(
                "UPDATE auth.session SET expires_at = now() - interval '1 second' "
                "WHERE token_hash = :d"
            ),
            {"d": hashlib.sha256(expired.encode()).digest()},
        )
    for token in (idle, expired):
        r = client.get("/api/v1/auth/session", headers=bearer(token))
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"


def test_removed_member_and_deactivated_account_lose_access_immediately(
    client: TestClient, owner_engine: Engine, make_org: Callable[..., Org]
) -> None:
    org = make_org()
    owner = login(client, org.owner_email)
    email = unique_email("analyst")
    added = client.post(
        "/api/v1/members",
        headers=bearer(owner),
        json={"email": email, "display_name": "An", "role": "analyst", "password": PASSWORD},
    )
    assert added.status_code == 201
    analyst = login(client, email)
    assert client.get("/api/v1/members", headers=bearer(analyst)).status_code == 200

    uid = added.json()["user_id"]
    assert client.delete(f"/api/v1/members/{uid}", headers=bearer(owner)).status_code == 204
    assert client.get("/api/v1/auth/session", headers=bearer(analyst)).status_code == 401

    with owner_engine.begin() as c:
        c.execute(
            text("UPDATE auth.user_account SET is_active = false WHERE id = :u"),
            {"u": org.owner_id},
        )
    assert client.get("/api/v1/auth/session", headers=bearer(owner)).status_code == 401
    r = client.post("/api/v1/auth/login", json={"email": org.owner_email, "password": PASSWORD})
    assert r.status_code == 401


def test_login_to_a_specific_organization_and_refusal_of_others(
    client: TestClient, make_org: Callable[..., Org]
) -> None:
    a, b = make_org("A"), make_org("B")
    owner_a = login(client, a.owner_email)
    # A's owner adds B's owner to A as a viewer (existing account keeps its password).
    r = client.post(
        "/api/v1/members",
        headers=bearer(owner_a),
        json={
            "email": b.owner_email,
            "display_name": "x",
            "role": "viewer",
            "password": "ignored-password-123",
        },
    )
    assert r.status_code == 201

    into_a = client.post(
        "/api/v1/auth/login",
        json={"email": b.owner_email, "password": PASSWORD, "organization_id": str(a.id)},
    )
    assert into_a.status_code == 200
    assert into_a.json()["session"]["organization"]["id"] == str(a.id)
    assert into_a.json()["session"]["role"] == "viewer"
    assert {m["organization"]["id"] for m in into_a.json()["session"]["memberships"]} == {
        str(a.id),
        str(b.id),
    }

    stranger = make_org("C")
    refused = client.post(
        "/api/v1/auth/login",
        json={"email": b.owner_email, "password": PASSWORD, "organization_id": str(stranger.id)},
    )
    assert refused.status_code == 403


def test_malformed_tokens_are_rejected_without_error(client: TestClient) -> None:
    for header in (
        "Bearer x",
        "Bearer " + "a" * 500,
        "Basic Zm9vOmJhcg==",
        "Bearer ' OR 1=1 --xxxxxxxxxxxxxxx",
    ):
        r = client.get("/api/v1/auth/session", headers={"Authorization": header})
        assert r.status_code == 401, header
