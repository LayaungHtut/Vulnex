"""Scanner workers and scans through the control-plane API (M4): enrollment tokens, revocation,
scan requests gated on authorized scope, idempotency, cancellation, results and the role matrix.

A worker is simulated with the queue functions directly; the worker API has its own tests."""

import hashlib
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import APP_URL, PASSWORD, Org, bearer, login, needs_db, unique_email
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, text
from test_assets import add_asset, authorize, new_group
from test_queue_db import tx

from vulnex.main import create_app
from vulnex.pki import pem_sha256
from vulnex.settings import Settings

pytestmark = needs_db

H = dict[str, str]


@pytest.fixture
def org(make_org: Callable[..., Org]) -> Org:
    return make_org()


@pytest.fixture
def owner(client: TestClient, org: Org) -> H:
    return bearer(login(client, org.owner_email))


def scannable(client: TestClient, h: H, cidr: str, *targets: str) -> tuple[str, list[str]]:
    """An authorized scope group holding `cidr`, with one active asset per target."""
    g = new_group(client, h, cidr, name=f"site {cidr}")
    assert authorize(client, h, g).status_code == 200
    assets = []
    for t in targets:
        r = add_asset(client, h, g, t)
        assert r.status_code == 201, r.text
        assets.append(r.json()["id"])
    return g, assets


def scan(client: TestClient, h: H, *assets: str, key: str | None = None) -> Any:
    headers = h | ({"Idempotency-Key": key} if key else {})
    return client.post("/api/v1/scans", headers=headers, json={"asset_ids": list(assets)})


def get_scan(client: TestClient, h: H, scan_id: str) -> dict[str, Any]:
    r = client.get(f"/api/v1/scans/{scan_id}", headers=h)
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def add_worker(engine: Engine, org: Org, group: str, name: str, *, seen: bool = True) -> str:
    with tx(engine, org.id) as c:
        w: uuid.UUID = c.execute(
            text(
                "INSERT INTO app.worker (tenant_id, scope_group_id, name, last_seen_at) "
                "VALUES (:t, :g, :n, CASE WHEN :seen THEN now() END) RETURNING id"
            ),
            {"t": org.id, "g": group, "n": name, "seen": seen},
        ).scalar_one()
    return str(w)


def claim(engine: Engine, org: Org, worker: str) -> Any:
    with tx(engine, org.id) as c:
        return (
            c.execute(
                text("SELECT * FROM queue.claim_for_worker(:w, 1, interval '5 minutes')"),
                {"w": worker},
            )
            .mappings()
            .one()
        )


def audit_actions(client: TestClient, h: H) -> list[str]:
    return [e["action"] for e in client.get("/api/v1/audit-events", headers=h).json()["items"]]


# ---- enrollment ----


def test_enrollment_token_is_shown_once_and_stored_only_as_a_hash(
    client: TestClient, owner: H, owner_engine: Engine, pki_dir: Path
) -> None:
    g = new_group(client, owner, "10.70.0.0/16")
    r = client.post(
        "/api/v1/workers/enrollments",
        headers=owner,
        json={"scope_group_id": g, "name": " lab-1 ", "ttl_hours": 2},
    )
    assert r.status_code == 201, r.text
    created = r.json()
    bundle = created["bundle"]
    token = bundle["token"]
    assert len(token) >= 40
    assert bundle["control_plane_url"] == "https://localhost:8443"
    assert bundle["ca_sha256"] == pem_sha256((pki_dir / "server-ca.crt").read_text())

    with owner_engine.connect() as c:
        row = c.execute(
            text(
                "SELECT token_hash, name, extract(epoch FROM expires_at - created_at) AS ttl "
                "FROM auth.worker_enrollment WHERE id = :e"
            ),
            {"e": created["id"]},
        ).one()
    assert bytes(row.token_hash) == hashlib.sha256(token.encode()).digest()
    assert row.name == "lab-1" and 7100 < row.ttl <= 7200

    listed = client.get("/api/v1/workers/enrollments", headers=owner)
    assert token not in listed.text
    assert [(e["name"], e["status"]) for e in listed.json()] == [("lab-1", "pending")]

    url = f"/api/v1/workers/enrollments/{created['id']}"
    assert client.delete(url, headers=owner).status_code == 204
    assert client.delete(url, headers=owner).status_code == 404
    assert client.get("/api/v1/workers/enrollments", headers=owner).json()[0]["status"] == "revoked"
    events = client.get("/api/v1/audit-events", headers=owner)
    assert token not in events.text
    assert audit_actions(client, owner)[:2] == [
        "worker_enrollment.revoked",
        "worker_enrollment.created",
    ]


def test_enrollment_refusals(
    client: TestClient, owner: H, org: Org, app_engine: Engine, make_org: Callable[..., Org]
) -> None:
    g = new_group(client, owner, "10.72.0.0/16")
    add_worker(app_engine, org, g, "taken")

    def enroll(group: str, name: str, c: TestClient = client) -> int:
        r = c.post(
            "/api/v1/workers/enrollments",
            headers=owner,
            json={"scope_group_id": group, "name": name},
        )
        return int(r.status_code)

    assert enroll(g, "taken") == 409
    assert enroll(str(uuid.uuid4()), "new") == 404
    other = bearer(login(client, make_org().owner_email))
    assert enroll(new_group(client, other, name="theirs"), "new") == 404
    assert APP_URL
    unconfigured = TestClient(create_app(Settings(database_url=SecretStr(APP_URL))))
    assert enroll(g, "new", unconfigured) == 503


# ---- workers ----


def test_revoking_a_worker_ends_its_certificates_and_leases(
    client: TestClient, owner: H, org: Org, app_engine: Engine
) -> None:
    g, (asset,) = scannable(client, owner, "10.73.0.0/16", "10.73.0.5")
    w = add_worker(app_engine, org, g, "busy")
    add_worker(app_engine, org, g, "idle", seen=False)
    fp = "ab" * 32
    with tx(app_engine, org.id) as c:
        c.execute(
            text(
                "SELECT auth.register_worker_certificate(:w, :fp, now() + interval '7 days', NULL)"
            ),
            {"w": w, "fp": fp},
        )
    workers = client.get("/api/v1/workers", headers=owner).json()
    assert [(x["name"], x["connection"]) for x in workers] == [
        ("busy", "online"),
        ("idle", "never_connected"),
    ]

    s = scan(client, owner, asset).json()["id"]
    claim(app_engine, org, w)
    assert get_scan(client, owner, s)["state"] == "running"

    r = client.post(f"/api/v1/workers/{w}/revoke", headers=owner)
    assert r.status_code == 200 and r.json()["status"] == "revoked" and r.json()["revoked_at"]
    after = get_scan(client, owner, s)
    assert after["state"] == "queued" and after["last_error"] == "worker revoked"
    with app_engine.begin() as c:
        cert = c.execute(
            text("SELECT * FROM auth.worker_by_cert_fingerprint(:fp)"), {"fp": fp}
        ).one()
    assert cert.cert_revoked

    assert client.post(f"/api/v1/workers/{w}/revoke", headers=owner).status_code == 200
    assert audit_actions(client, owner).count("worker.revoked") == 1
    assert client.post(f"/api/v1/workers/{uuid.uuid4()}/revoke", headers=owner).status_code == 404
    # The revoked worker sorts last and can no longer claim the requeued job.
    assert client.get("/api/v1/workers", headers=owner).json()[-1]["name"] == "busy"
    with tx(app_engine, org.id) as c:
        assert not c.execute(
            text("SELECT * FROM queue.claim_for_worker(:w, 1, interval '1 minute')"), {"w": w}
        ).first()


# ---- scans ----


def test_scans_need_authorized_scope_and_in_scope_active_assets(
    client: TestClient, owner: H, make_org: Callable[..., Org]
) -> None:
    g = new_group(client, owner, "10.74.0.0/16", name="drifting")
    asset = add_asset(client, owner, g, "10.74.0.5").json()["id"]
    r = scan(client, owner, asset)
    assert r.status_code == 409 and "not authorized" in r.json()["detail"]

    assert authorize(client, owner, g).status_code == 200
    r = scan(client, owner, asset)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "queued" and body["profile"] == "scope_check"
    assert body["targets"] == ["10.74.0.5"] and body["scope_group_name"] == "drifting"
    assert body["requested_by_email"] and body["result"] is None

    # Excluding the asset's range is drift: refused until re-authorized, then out of scope.
    client.post(
        f"/api/v1/scope-groups/{g}/entries",
        headers=owner,
        json={"value": "10.74.0.0/24", "exclude": True},
    )
    assert scan(client, owner, asset).status_code == 409
    assert authorize(client, owner, g).status_code == 200
    r = scan(client, owner, asset)
    assert r.status_code == 409 and r.json()["detail"].startswith("10.74.0.5:")

    _, (a1, a2) = scannable(client, owner, "10.75.0.0/16", "10.75.0.1", "10.75.0.2")
    _, (elsewhere,) = scannable(client, owner, "10.76.0.0/16", "10.76.0.1")
    assert scan(client, owner, a1, elsewhere).status_code == 422
    client.post(f"/api/v1/assets/{a2}/retire", headers=owner)
    assert scan(client, owner, a1, a2).status_code == 409
    assert scan(client, owner, a1, str(uuid.uuid4())).status_code == 404
    theirs = bearer(login(client, make_org().owner_email))
    _, (their_asset,) = scannable(client, theirs, "10.77.0.0/16", "10.77.0.1")
    assert scan(client, owner, a1, their_asset).status_code == 404

    assert client.get("/api/v1/scans", headers=owner).json()["total"] == 1
    assert "scan.requested" in audit_actions(client, owner)


def test_idempotency_key_returns_the_original_scan(client: TestClient, owner: H) -> None:
    _, (a1, a2) = scannable(client, owner, "10.78.0.0/16", "10.78.0.1", "10.78.0.2")
    first = scan(client, owner, a1, a2, key="retry-0001")
    again = scan(client, owner, a2, a1, a1, key="retry-0001")  # same set, other order
    assert (first.status_code, again.status_code) == (201, 200)
    assert first.json()["id"] == again.json()["id"]
    assert scan(client, owner, a1, key="retry-0001").status_code == 409
    assert scan(client, owner, a1, key="no").status_code == 422
    assert client.get("/api/v1/scans", headers=owner).json()["total"] == 1


def test_cancel_and_final_result(
    client: TestClient, owner: H, org: Org, app_engine: Engine
) -> None:
    g, (asset,) = scannable(client, owner, "10.79.0.0/16", "10.79.0.1")
    w = add_worker(app_engine, org, g, "w")

    queued = scan(client, owner, asset).json()["id"]
    r = client.post(f"/api/v1/scans/{queued}/cancel", headers=owner)
    assert r.status_code == 200 and r.json()["state"] == "cancelled"
    assert client.post(f"/api/v1/scans/{queued}/cancel", headers=owner).json()["state"] == (
        "cancelled"
    )

    done = scan(client, owner, asset).json()["id"]
    lease = claim(app_engine, org, w)
    with tx(app_engine, org.id) as c:
        status = c.execute(
            text("SELECT queue.complete(:j, :l, :w, :a, 0, CAST(:p AS jsonb), 'succeeded', NULL)"),
            {
                "j": lease["job_id"],
                "l": lease["lease_id"],
                "w": w,
                "a": lease["attempt"],
                "p": '{"allowed": ["10.79.0.1"], "refused": []}',
            },
        ).scalar_one()
    assert status == "accepted"
    finished = get_scan(client, owner, done)
    assert finished["state"] == "completed" and finished["finished_at"]
    assert finished["result"] == {"allowed": ["10.79.0.1"], "refused": []}

    running = scan(client, owner, asset).json()["id"]
    claim(app_engine, org, w)
    r = client.post(f"/api/v1/scans/{running}/cancel", headers=owner)
    assert r.json()["state"] == "running" and r.json()["cancel_requested"]

    page = client.get("/api/v1/scans?limit=2", headers=owner).json()
    assert page["total"] == 3 and [s["id"] for s in page["items"]] == [running, done]
    assert all(s["result"] is None for s in page["items"])  # results only in the detail view
    assert client.post(f"/api/v1/scans/{uuid.uuid4()}/cancel", headers=owner).status_code == 404


@pytest.mark.parametrize(
    ("role", "workers_read", "workers_manage", "scans_read", "scans_run"),
    [
        ("owner", 200, 201, 200, 201),
        ("admin", 200, 201, 200, 201),
        ("analyst", 200, 403, 200, 201),
        ("remediation_contributor", 403, 403, 403, 403),
        ("viewer", 403, 403, 200, 403),
    ],
)
def test_role_matrix(
    client: TestClient,
    owner: H,
    role: str,
    workers_read: int,
    workers_manage: int,
    scans_read: int,
    scans_run: int,
) -> None:
    g, (asset,) = scannable(client, owner, "10.80.0.0/16", "10.80.0.1")
    email = unique_email(role)
    if role != "owner":
        r = client.post(
            "/api/v1/members",
            headers=owner,
            json={"email": email, "display_name": role, "role": role, "password": PASSWORD},
        )
        assert r.status_code == 201
    h = owner if role == "owner" else bearer(login(client, email))

    assert client.get("/api/v1/workers", headers=h).status_code == workers_read
    r = client.post(
        "/api/v1/workers/enrollments", headers=h, json={"scope_group_id": g, "name": role}
    )
    assert r.status_code == workers_manage
    assert client.get("/api/v1/scans", headers=h).status_code == scans_read
    assert scan(client, h, asset).status_code == scans_run
