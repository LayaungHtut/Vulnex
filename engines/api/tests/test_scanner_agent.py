"""The real scanner (`vulnex_scanner`) against the real worker API, in process: enrollment from a
console bundle, a full scan cycle, local refusal of tampered leases, the local ceiling,
renewal and revocation. Only TLS and the gateway are simulated (the fingerprint header)."""

import base64
import json
import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import Org, bearer, login, needs_db
from cryptography import x509
from fastapi.testclient import TestClient
from test_assets import add_asset, authorize, new_group

from vulnex.pki import fingerprint
from vulnex.worker_api import CERT_HEADER
from vulnex_scanner.agent import CERT, CONFIG, KEY, Agent, Revoked, ScannerError, enroll
from vulnex_worker_protocol.messages import EnrollmentBundle, Task
from vulnex_worker_protocol.targets import parse_scope_entry

pytestmark = needs_db


class Lab:
    def __init__(self, client: TestClient, wclient: TestClient, org: Org, state: Path) -> None:
        self.client, self.wclient, self.state = client, wclient, state
        self.owner = bearer(login(client, org.owner_email))
        g = new_group(client, self.owner, "10.91.0.0/16", name="agent lab")
        assert authorize(client, self.owner, g).status_code == 200
        self.asset = add_asset(client, self.owner, g, "10.91.0.0/28").json()["id"]
        r = client.post(
            "/api/v1/workers/enrollments",
            headers=self.owner,
            json={"scope_group_id": g, "name": "agent-1"},
        )
        self.bundle = EnrollmentBundle.model_validate(r.json()["bundle"])
        self.creds = enroll(state, self.bundle, http=wclient)

    def http(self) -> TestClient:
        """What the gateway would forward for the certificate currently on disk."""
        cert = x509.load_pem_x509_certificate((self.state / CERT).read_bytes())
        return TestClient(self.wclient.app, headers={CERT_HEADER: fingerprint(cert)})

    def agent(self, **kw: Any) -> Agent:
        return Agent(self.state, http=self.http(), **kw)

    def scan(self) -> dict[str, Any]:
        r = self.client.post("/api/v1/scans", headers=self.owner, json={"asset_ids": [self.asset]})
        assert r.status_code == 201, r.text
        out: dict[str, Any] = r.json()
        return out

    def get(self, scan_id: str) -> dict[str, Any]:
        out: dict[str, Any] = self.client.get(f"/api/v1/scans/{scan_id}", headers=self.owner).json()
        return out


@pytest.fixture
def lab(
    client: TestClient, wclient: TestClient, make_org: Callable[..., Org], tmp_path: Path
) -> Lab:
    return Lab(client, wclient, make_org(), tmp_path / "state")


def test_enroll_then_one_cycle_completes_a_scan(lab: Lab) -> None:
    assert stat.S_IMODE((lab.state / KEY).stat().st_mode) == 0o600
    assert json.loads((lab.state / CONFIG).read_text())["worker_id"] == str(lab.creds.worker_id)
    with pytest.raises(ScannerError, match="already holds"):
        enroll(lab.state, lab.bundle, http=lab.wclient)

    scan = lab.scan()
    agent = lab.agent()
    assert agent.run_once() == 1
    done = lab.get(scan["id"])
    assert done["state"] == "completed"
    expected = [{"target": "10.91.0.0/28", "kind": "cidr", "addresses": 16}]
    assert done["result"]["allowed"] == expected
    assert agent.run_once() == 0
    (worker,) = lab.client.get("/api/v1/workers", headers=lab.owner).json()
    assert worker["connection"] == "online" and worker["version"] == "0.1.0"


def test_a_bundle_whose_ca_does_not_match_its_fingerprint_is_refused(
    lab: Lab, tmp_path: Path
) -> None:
    forged = lab.bundle.model_copy(update={"ca_sha256": "00" * 32})
    with pytest.raises(ScannerError, match="fingerprint"):
        enroll(tmp_path / "other", forged, http=lab.wclient)


def test_the_scanner_refuses_a_tampered_lease(lab: Lab) -> None:
    scan = lab.scan()
    agent = lab.agent()
    r = agent.http.post("/worker/v1/lease", json={"max_tasks": 1})
    task = Task.model_validate(r.json()["tasks"][0])
    payload = json.loads(base64.b64decode(task.lease.payload_b64))
    payload["targets"] = ["169.254.169.254"]
    raw = base64.b64encode(json.dumps(payload).encode()).decode()
    forged = task.lease.model_copy(update={"payload_b64": raw})
    sent = agent.handle(task.model_copy(update={"lease": forged}))
    assert sent["outcome"] == "refused"
    failed = lab.get(scan["id"])
    assert failed["state"] == "failed" and "signature" in failed["last_error"]


def test_the_local_ceiling_wins_over_the_lease(lab: Lab) -> None:
    scan = lab.scan()
    lab.agent(ceiling=[parse_scope_entry("192.168.0.0/16", exclude=False)]).run_once()
    result = lab.get(scan["id"])["result"]
    assert result["allowed"] == []
    assert "local scope ceiling" in result["refused"][0]["reason"]


def test_renewal_replaces_the_key_and_certificate(lab: Lab) -> None:
    before = (lab.state / KEY).read_bytes(), (lab.state / CERT).read_bytes()
    later = datetime.now(UTC) + timedelta(days=6)
    agent = lab.agent(clock=lambda: later)
    assert agent.renew_if_due()
    assert (lab.state / KEY).read_bytes() != before[0]
    assert (lab.state / CERT).read_bytes() != before[1]
    assert lab.http().post("/worker/v1/heartbeat", json={"version": "x"}).is_success
    assert not lab.agent().renew_if_due()  # 7 fresh days left


def test_revocation_deletes_the_local_identity(lab: Lab) -> None:
    agent = lab.agent()
    r = lab.client.post(f"/api/v1/workers/{lab.creds.worker_id}/revoke", headers=lab.owner)
    assert r.status_code == 200
    with pytest.raises(Revoked):
        agent.run_once()
    assert not (lab.state / KEY).exists() and not (lab.state / CERT).exists()
