"""Discovery scans (M5) through the worker API: signed lease carries the ports, batches and the
final summary are validated, and completion stores evidence and services in the same
transaction; later scans close services that stopped answering."""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from conftest import Org, needs_db
from fastapi.testclient import TestClient
from test_worker_api import Site

from vulnex.discovery import DEFAULT_PORTS
from vulnex_worker_protocol.lease import SignedLease, load_public_key, verify

pytestmark = needs_db

NOW = "2026-11-08T12:00:00+00:00"


@pytest.fixture
def site(client: TestClient, wclient: TestClient, make_org: Callable[..., Org]) -> Site:
    return Site(client, wclient, make_org(), "10.91.0.0/16", "10.91.0.7")


def discovery_scan(site: Site, ports: list[int] | None = None, asset: str | None = None) -> str:
    body: dict[str, Any] = {"asset_ids": [asset or site.asset], "profile": "discovery"}
    if ports is not None:
        body["ports"] = ports
    r = site.client.post("/api/v1/scans", headers=site.owner, json=body)
    assert r.status_code == 201, r.text
    scan_id: str = r.json()["id"]
    return scan_id


def ssh(address: str = "10.91.0.7", port: int = 22) -> dict[str, Any]:
    return {
        "address": address,
        "port": port,
        "observed_at": NOW,
        "connect_ms": 3,
        "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
        "banner_b64": "U1NILTIuMC1PcGVuU1NIXzkuNnAxIFVidW50dS0zdWJ1bnR1MTMuNQ0K",
    }


def report(target: str = "10.91.0.7", opened: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "target": target,
        "kind": "ip",
        "addresses": [target],
        "responding": [target],
        "open": opened if opened is not None else [ssh()],
        "closed": 1,
        "filtered": 0,
    }


def summary(**extra: Any) -> dict[str, Any]:
    return {
        "profile": "discovery",
        "scanner_version": "test",
        "started_at": NOW,
        "finished_at": NOW,
        "ports": 2,
        "probes": 2,
        "connections": 2,
        "batches": 1,
        "refused": [],
    } | extra


def run(site: Site, reports: list[dict[str, Any]], **final: Any) -> dict[str, Any]:
    (task,) = site.lease()
    batch = {"profile": "discovery", "reports": reports}
    assert site.submit(task, 1, payload=batch).status_code == 200
    r = site.submit(task, 2, payload=summary(**final), outcome="succeeded")
    assert r.status_code == 200, r.text
    return task


def test_lease_carries_kind_ports_and_discovery_limits(site: Site) -> None:
    discovery_scan(site, ports=[443, 22, 22])
    (task,) = site.lease()
    keys = {k: load_public_key(v) for k, v in site.creds["scope_keys"].items()}
    lease = verify(
        SignedLease.model_validate(task["lease"]),
        keys,
        worker_id=uuid.UUID(site.creds["worker_id"]),
        tenant_id=uuid.UUID(site.creds["tenant_id"]),
        job_id=uuid.UUID(task["job_id"]),
        lease_id=uuid.UUID(task["lease_id"]),
        attempt=task["attempt"],
    )
    assert lease.kind == "network.discover"
    assert lease.ports == [22, 443]
    assert lease.limits.task_timeout_s == 3600


def test_default_ports_and_probe_budget(site: Site) -> None:
    scan = site.get_scan(discovery_scan(site))
    assert scan["profile"] == "discovery" and scan["ports"] == DEFAULT_PORTS
    big = site.client.post(
        "/api/v1/assets",
        headers=site.owner,
        json={"scope_group_id": site.group, "target": "10.91.16.0/20"},
    ).json()["id"]
    r = site.client.post(
        "/api/v1/scans",
        headers=site.owner,
        json={"asset_ids": [big], "profile": "discovery", "ports": list(range(1, 101))},
    )
    assert r.status_code == 422 and "limit" in r.json()["detail"]


def test_completion_stores_evidence_services_and_summary(site: Site) -> None:
    scan_id = discovery_scan(site, ports=[22, 80])
    run(site, [report()])
    scan = site.get_scan(scan_id)
    assert scan["state"] == "completed"
    s = scan["summary"]
    assert (s["open_ports"], s["services_new"], s["hosts_responding"], s["dropped"]) == (1, 1, 1, 0)

    services = site.client.get(f"/api/v1/services?asset_id={site.asset}", headers=site.owner).json()
    assert services["total"] == 1
    svc = services["items"][0]
    assert (svc["address"], svc["port"], svc["name"], svc["product"], svc["version"]) == (
        "10.91.0.7",
        22,
        "ssh",
        "OpenSSH",
        "9.6p1",
    )
    assert svc["detail"]["package_revision"] == "3ubuntu13.5"
    evidence = site.client.get(f"/api/v1/scans/{scan_id}/evidence", headers=site.owner).json()
    assert len(evidence) == 1 and evidence[0]["id"] == svc["last_evidence_id"]
    one = site.client.get(f"/api/v1/evidence/{svc['last_evidence_id']}", headers=site.owner)
    assert one.status_code == 200 and one.json()["data"]["banner"].startswith("SSH-2.0")
    asset = site.client.get(f"/api/v1/assets/{site.asset}", headers=site.owner).json()
    assert asset["last_seen_at"] is not None


def test_a_later_scan_closes_ports_that_stopped_answering(site: Site) -> None:
    discovery_scan(site, ports=[22, 80])
    run(site, [report()])
    discovery_scan(site, ports=[22, 80])
    run(site, [report(opened=[])])
    url = f"/api/v1/services?asset_id={site.asset}&state=closed"
    closed = site.client.get(url, headers=site.owner).json()["items"]
    assert [(c["port"], c["state"]) for c in closed] == [(22, "closed")]


def test_an_interrupted_scan_does_not_close_anything(site: Site) -> None:
    discovery_scan(site, ports=[22])
    run(site, [report()])
    discovery_scan(site, ports=[22])
    run(site, [report(opened=[])], stopped="task time limit reached")
    open_ = site.client.get(f"/api/v1/services?asset_id={site.asset}", headers=site.owner).json()
    assert open_["total"] == 1


def test_observations_outside_the_scan_are_dropped(site: Site) -> None:
    scan_id = discovery_scan(site, ports=[22])
    run(
        site,
        [
            report(opened=[ssh("10.91.0.8"), ssh(port=2222)]),  # wrong address, unleased port
            report(target="10.91.0.99"),  # not a target of this scan
        ],
    )
    s = site.get_scan(scan_id)["summary"]
    assert s["open_ports"] == 0 and s["dropped"] == 3
    assert site.client.get("/api/v1/services", headers=site.owner).json()["total"] == 0


def test_malformed_results_are_refused_before_storage(site: Site) -> None:
    discovery_scan(site, ports=[22])
    (task,) = site.lease()
    bad = {"profile": "discovery", "reports": [{"target": "10.91.0.7", "kind": "ip", "x": 1}]}
    assert site.submit(task, 1, payload=bad).status_code == 422
    r = site.submit(task, 1, payload={"profile": "discovery"}, outcome="succeeded")
    assert r.status_code == 422
    assert site.submit(task, 1, payload=summary(), outcome="succeeded").status_code == 200


def test_unknown_evidence_is_404(site: Site) -> None:
    r = site.client.get("/api/v1/evidence/00000000-0000-0000-0000-000000000000", headers=site.owner)
    assert r.status_code == 404
