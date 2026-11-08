"""Worker API (`/worker/v1`, ADR-0006): enrollment, certificate identity, heartbeats, signed
leases, lease-time scope re-checks, results and revocation. The gateway is simulated by setting
the fingerprint header it would set after verifying the client certificate."""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from conftest import Org, bearer, login, needs_db
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from test_assets import add_asset, authorize, new_group

from vulnex.pki import fingerprint
from vulnex.worker_api import CERT_HEADER
from vulnex_worker_protocol.lease import SignedLease, load_public_key, verify

pytestmark = needs_db

H = dict[str, str]


def csr() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    req = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scanner")]))
        .sign(key, hashes.SHA256())
    )
    return req.public_bytes(serialization.Encoding.PEM).decode()


class Site:
    """An organization with an authorized scope group, one asset and one enrolled worker."""

    def __init__(self, client: TestClient, wclient: TestClient, org: Org, cidr: str, ip: str):
        self.client, self.wclient = client, wclient
        self.owner = bearer(login(client, org.owner_email))
        self.group = new_group(client, self.owner, cidr, name=f"site {cidr}")
        assert authorize(client, self.owner, self.group).status_code == 200
        self.asset = add_asset(client, self.owner, self.group, ip).json()["id"]
        self.token = self.enrollment("scanner-1")
        r = wclient.post("/worker/v1/enroll", json={"token": self.token, "csr_pem": csr()})
        assert r.status_code == 200, r.text
        self.creds: dict[str, Any] = r.json()
        cert = x509.load_pem_x509_certificate(self.creds["certificate_pem"].encode())
        self.h: H = {CERT_HEADER: fingerprint(cert)}

    def enrollment(self, name: str) -> str:
        r = self.client.post(
            "/api/v1/workers/enrollments",
            headers=self.owner,
            json={"scope_group_id": self.group, "name": name},
        )
        assert r.status_code == 201, r.text
        token: str = r.json()["bundle"]["token"]
        return token

    def scan(self) -> str:
        r = self.client.post("/api/v1/scans", headers=self.owner, json={"asset_ids": [self.asset]})
        assert r.status_code == 201, r.text
        scan_id: str = r.json()["id"]
        return scan_id

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        out: dict[str, Any] = self.client.get(f"/api/v1/scans/{scan_id}", headers=self.owner).json()
        return out

    def lease(self, n: int = 1) -> list[dict[str, Any]]:
        r = self.wclient.post("/worker/v1/lease", headers=self.h, json={"max_tasks": n})
        assert r.status_code == 200, r.text
        tasks: list[dict[str, Any]] = r.json()["tasks"]
        return tasks

    def submit(self, task: dict[str, Any], seq: int, **extra: Any) -> Any:
        body = {
            "job_id": task["job_id"],
            "lease_id": task["lease_id"],
            "attempt": task["attempt"],
            "seq": seq,
            "payload": {"seq": seq},
        }
        return self.wclient.post("/worker/v1/tasks/submit", headers=self.h, json=body | extra)


@pytest.fixture
def site(client: TestClient, wclient: TestClient, make_org: Callable[..., Org]) -> Site:
    return Site(client, wclient, make_org(), "10.90.0.0/16", "10.90.0.7")


def test_enrollment_issues_an_identity_bound_to_the_token_tenant_and_group(
    site: Site, make_org: Callable[..., Org]
) -> None:
    creds = site.creds
    workers = site.client.get("/api/v1/workers", headers=site.owner).json()
    assert [(w["id"], w["name"], w["scope_group_id"]) for w in workers] == [
        (creds["worker_id"], "scanner-1", site.group)
    ]
    cert = x509.load_pem_x509_certificate(creds["certificate_pem"].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:vulnex:worker:{creds['worker_id']}"
    ]
    assert creds["protocol_versions"] == [1] and len(creds["scope_keys"]) == 1
    enrollments = site.client.get("/api/v1/workers/enrollments", headers=site.owner).json()
    assert enrollments[0]["status"] == "used" and enrollments[0]["worker_id"] == creds["worker_id"]

    # Single use.
    r = site.wclient.post("/worker/v1/enroll", json={"token": site.token, "csr_pem": csr()})
    assert r.status_code == 401
    actions = [
        e["action"]
        for e in site.client.get("/api/v1/audit-events", headers=site.owner).json()["items"]
    ]
    assert "worker.enrolled" in actions


def test_a_failed_enrollment_leaves_the_token_usable(site: Site) -> None:
    token = site.enrollment("scanner-2")
    r = site.wclient.post("/worker/v1/enroll", json={"token": token, "csr_pem": "garbage"})
    assert r.status_code == 422
    r = site.wclient.post("/worker/v1/enroll", json={"token": token, "csr_pem": csr()})
    assert r.status_code == 200


@pytest.mark.parametrize(
    "header",
    [{}, {CERT_HEADER: "not-hex"}, {CERT_HEADER: "ab" * 32}],
    ids=["missing", "malformed", "unknown"],
)
def test_requests_without_a_known_certificate_are_refused(site: Site, header: H) -> None:
    r = site.wclient.post("/worker/v1/heartbeat", headers=header, json={"version": "t"})
    assert r.status_code == 401
    assert site.wclient.post("/worker/v1/lease", headers=header, json={}).status_code == 401


def test_heartbeat_marks_the_worker_online(site: Site) -> None:
    r = site.wclient.post("/worker/v1/heartbeat", headers=site.h, json={"version": "0.1.0"})
    assert r.status_code == 200 and r.json()["status"] == "active"
    (w,) = site.client.get("/api/v1/workers", headers=site.owner).json()
    assert w["connection"] == "online" and w["version"] == "0.1.0"


def test_a_leased_task_carries_a_lease_the_worker_can_verify(site: Site) -> None:
    assert site.lease() == []
    scan_id = site.scan()
    (task,) = site.lease(n=5)
    assert site.get_scan(scan_id)["state"] == "running"
    keys = {kid: load_public_key(k) for kid, k in site.creds["scope_keys"].items()}
    lease = verify(
        SignedLease.model_validate(task["lease"]),
        keys,
        worker_id=uuid.UUID(site.creds["worker_id"]),
        tenant_id=uuid.UUID(site.creds["tenant_id"]),
        job_id=uuid.UUID(task["job_id"]),
        lease_id=uuid.UUID(task["lease_id"]),
        attempt=task["attempt"],
    )
    assert lease.targets == ["10.90.0.7"] and lease.kind == "scope.check"
    assert [(e.kind, e.value) for e in lease.scope] == [("cidr", "10.90.0.0/16")]

    r = site.wclient.post(
        "/worker/v1/tasks/extend",
        headers=site.h,
        json={"job_id": task["job_id"], "lease_id": task["lease_id"]},
    )
    assert r.json()["ok"] and not r.json()["cancel_requested"]
    site.client.post(f"/api/v1/scans/{scan_id}/cancel", headers=site.owner)
    r = site.wclient.post(
        "/worker/v1/tasks/extend",
        headers=site.h,
        json={"job_id": task["job_id"], "lease_id": task["lease_id"]},
    )
    assert r.json()["cancel_requested"]


def test_results_are_exactly_once_and_complete_the_scan(site: Site) -> None:
    scan_id = site.scan()
    (task,) = site.lease()
    assert site.submit(task, 0).json()["status"] == "accepted"
    assert site.submit(task, 0).json()["status"] == "duplicate"
    final = site.submit(task, 1, outcome="succeeded", payload={"allowed": ["10.90.0.7"]})
    assert final.json()["status"] == "accepted"
    done = site.get_scan(scan_id)
    assert done["state"] == "completed" and done["result"] == {"allowed": ["10.90.0.7"]}
    # The lease is over: anything more is stale and quarantined.
    assert site.submit(task, 2).status_code == 409


def test_scope_changed_after_the_request_is_refused_at_lease_time(site: Site) -> None:
    scan_id = site.scan()
    r = site.client.post(
        f"/api/v1/scope-groups/{site.group}/entries",
        headers=site.owner,
        json={"value": "10.90.0.0/24", "exclude": True},
    )
    assert r.json()["authorization"]["status"] == "changed_since_authorization"
    assert site.lease() == []
    refused = site.get_scan(scan_id)
    assert refused["state"] == "failed" and "not authorized" in refused["last_error"]

    # Re-authorized, the asset is now excluded: still refused, with the target named.
    assert authorize(site.client, site.owner, site.group).status_code == 200
    r = site.client.post("/api/v1/scans", headers=site.owner, json={"asset_ids": [site.asset]})
    assert r.status_code == 409  # the control plane refuses it before it reaches a worker


def test_a_revoked_worker_is_told_so_and_loses_its_lease(site: Site) -> None:
    scan_id = site.scan()
    site.lease()
    r = site.client.post(f"/api/v1/workers/{site.creds['worker_id']}/revoke", headers=site.owner)
    assert r.status_code == 200
    r = site.wclient.post("/worker/v1/heartbeat", headers=site.h, json={"version": "t"})
    assert r.status_code == 401 and r.json()["detail"] == "revoked"
    assert site.get_scan(scan_id)["state"] == "queued"


def test_renewal_issues_a_new_working_certificate(site: Site) -> None:
    r = site.wclient.post("/worker/v1/renew", headers=site.h, json={"csr_pem": csr()})
    assert r.status_code == 200
    assert r.json()["worker_id"] == site.creds["worker_id"]
    cert = x509.load_pem_x509_certificate(r.json()["certificate_pem"].encode())
    new = {CERT_HEADER: fingerprint(cert)}
    assert new != site.h
    assert site.wclient.post("/worker/v1/heartbeat", headers=new, json={"version": "t"}).is_success
