"""Intelligence parsing (M6), checks, risk and the finding lifecycle (M7/M8).

The lifecycle tests drive real discovery results through the worker API, so findings are
produced by the same transaction that ingests a scan, as in production.
"""

import csv
import gzip
import io
import json
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from conftest import Org, bearer, login, needs_db
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from test_discovery import discovery_scan, report, run, ssh
from test_members import add
from test_worker_api import Site

from vulnex import checks, intel, risk

pytestmark = needs_db  # the parsing and scoring tests need no database but run in the same suite

NOW = "2026-11-08T12:00:00+00:00"

# ---- pure functions ----


def test_parse_kev_keeps_fields_and_rejects_empty_catalogs() -> None:
    raw = json.dumps(
        {
            "catalogVersion": "2026.11.06",
            "vulnerabilities": [
                {
                    "cveID": "cve-2024-6387 ",
                    "vendorProject": "OpenBSD",
                    "product": "OpenSSH",
                    "dateAdded": "2026-01-02",
                    "dueDate": "2026-01-23",
                    "knownRansomwareCampaignUse": "Unknown",
                    "requiredAction": "Patch",
                },
            ],
        }
    ).encode()
    version, entries = intel.parse_kev(raw)
    assert version == "2026.11.06"
    assert (entries[0].cve_id, entries[0].product, entries[0].due_date) == (
        "CVE-2024-6387",
        "OpenSSH",
        "2026-01-23",
    )
    with pytest.raises(intel.IntelError):
        intel.parse_kev(b'{"catalogVersion": "x", "vulnerabilities": []}')
    with pytest.raises(intel.IntelError):
        intel.parse_kev(b"<html>maintenance</html>")


def test_parse_epss_reads_metadata_and_validates_scores() -> None:
    body = "#model_version:v2026.06.15,score_date:2026-11-08T12:55:00Z\ncve,epss,percentile\n"
    good = gzip.compress((body + "CVE-2024-6387,0.93,0.998\nCVE-2020-0001,0.0001,0.01\n").encode())
    scores = intel.parse_epss(good)
    assert (scores.model_version, scores.score_date, len(scores.rows)) == (
        "v2026.06.15",
        "2026-11-08",
        2,
    )
    assert scores.rows[0] == ("CVE-2024-6387", 0.93, 0.998)
    with pytest.raises(intel.IntelError):
        intel.parse_epss(gzip.compress((body + "CVE-1,1.7,0.5\n").encode()))
    with pytest.raises(intel.IntelError):
        intel.parse_epss(b"not gzip")


def nvd_item(
    cve_id: str, configurations: list[dict[str, Any]], score: float = 8.1
) -> dict[str, Any]:
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-07-01T13:15:00.000",
            "lastModified": "2025-01-01T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Race."}],
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}],
                "cvssMetricV31": [
                    {
                        "source": "other",
                        "type": "Secondary",
                        "cvssData": {"baseScore": 9.9, "vectorString": "CVSS:3.1/X"},
                    },
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "baseScore": score,
                            "vectorString": "CVSS:3.1/AV:N",
                            "baseSeverity": "HIGH",
                        },
                    },
                ],
            },
            "weaknesses": [{"description": [{"value": "CWE-362"}, {"value": "NVD-CWE-Other"}]}],
            "references": [
                {"url": "https://example.test/a", "tags": ["Patch"]},
                {"url": "javascript:alert(1)"},
            ],
            "configurations": configurations,
        }
    }


def match(criteria: str, **bounds: str) -> dict[str, Any]:
    return {"vulnerable": True, "criteria": criteria, "matchCriteriaId": "x"} | bounds


def test_parse_nvd_prefers_primary_cvss31_and_keeps_ranges_verbatim() -> None:
    item = nvd_item(
        "CVE-2024-6387",
        [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            match(
                                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                versionStartIncluding="8.5",
                                versionEndExcluding="9.8",
                            ),
                            match("cpe:2.3:a:openbsd:openssh:9.8:p1:*:*:*:*:*:*"),
                            match("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"),
                        ],
                    }
                ]
            },
            {
                "operator": "AND",
                "nodes": [
                    {"operator": "OR", "cpeMatch": [match("cpe:2.3:a:f5:nginx:1.2:*:*:*:*:*:*:*")]},
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {"vulnerable": False, "criteria": "cpe:2.3:o:x:y:*:*:*:*:*:*:*:*"}
                        ],
                    },
                ],
            },
        ],
    )
    r = intel.parse_nvd_cve(item)
    assert (r.cvss_version, r.cvss_score, r.cvss_source) == ("3.1", 8.1, "nvd@nist.gov")
    assert r.description == "Race." and r.cwes == ["CWE-362"]
    assert [x["url"] for x in r.refs] == ["https://example.test/a"]
    ranged, exact, platform = r.matches  # the OS CPE is not an application match
    assert (ranged.start_including, ranged.end_excluding, ranged.version) == ("8.5", "9.8", None)
    assert (exact.version, exact.conditional) == ("9.8p1", False)
    assert (platform.product, platform.conditional) == ("nginx", True)
    assert len(r.raw_sha256) == 64


def m(**kw: str | None) -> dict[str, Any]:
    base: dict[str, Any] = dict.fromkeys(
        ("version", "start_including", "start_excluding", "end_including", "end_excluding")
    )
    return base | kw


@pytest.mark.parametrize(
    ("version", "bounds", "expected"),
    [
        ("9.6p1", m(start_including="8.5", end_excluding="9.8"), True),
        ("9.8p1", m(start_including="8.5", end_excluding="9.8"), False),
        ("8.4p1", m(start_including="8.5", end_excluding="9.8"), False),
        ("1.27.5", m(end_including="1.27.5"), True),
        ("1.27.5", m(start_excluding="1.27.5"), False),
        ("8.5p1", m(version="8.5p1"), True),
        ("8.5p1", m(), False),  # "every version" ranges are not reported from a banner
    ],
)
def test_version_ranges(version: str, bounds: dict[str, Any], expected: bool) -> None:
    assert checks._in_range(version, bounds) is expected


def test_risk_formula_bands_and_explanations() -> None:
    r = risk.score(
        severity=9.8,
        severity_source="cvss",
        kev=True,
        epss=0.9,
        address="203.0.113.5",
        criticality="critical",
    )
    # 203.0.113.0/24 is documentation space (not global), so exposure is 0.
    assert (r["score"], r["band"]) == (84, "urgent")
    low = risk.score(
        severity=2.0,
        severity_source="x",
        kev=True,
        epss=None,
        address="10.0.0.1",
        criticality="low",
    )
    assert (low["score"], low["band"]) == (30, "high")  # KEV floors the band at high
    public = risk.score(
        severity=None,
        severity_source="",
        kev=False,
        epss=None,
        address="8.8.8.8",
        criticality="unknown",
    )
    assert public["score"] == 25 + 15 + 10
    assert [f["provisional"] for f in public["factors"]] == [True, False, True, True]
    assert sum(f["contribution"] for f in public["factors"]) == public["score"]


# ---- lifecycle through real scans ----


def redis(auth: bool) -> dict[str, Any]:
    return {
        "address": "10.91.0.7",
        "port": 6379,
        "observed_at": NOW,
        "connect_ms": 1,
        "probe": "redis-ping",
        "probe_reply": "-NOAUTH Authentication required." if auth else "+PONG",
    }


@pytest.fixture
def site(client: TestClient, wclient: TestClient, make_org: Callable[..., Org]) -> Site:
    return Site(client, wclient, make_org(), "10.91.0.0/16", "10.91.0.7")


def findings(site: Site, query: str = "") -> list[dict[str, Any]]:
    r = site.client.get(f"/api/v1/findings?{query}", headers=site.owner)
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


def scan(site: Site, opened: list[dict[str, Any]], **final: Any) -> str:
    scan_id = discovery_scan(site, ports=[22, 6379])
    run(site, [report(opened=opened)], **final)
    return scan_id


def test_scan_creates_verifies_and_reopens_a_finding(site: Site) -> None:
    first = scan(site, [redis(auth=False)])
    (f,) = findings(site)
    assert (f["check_id"], f["confidence"], f["status"], f["severity"]) == (
        "redis.no_auth",
        "confirmed",
        "open",
        "critical",
    )
    detail = site.client.get(f"/api/v1/findings/{f['id']}", headers=site.owner).json()
    assert detail["evidence"][0]["data"]["probe_reply"] == "+PONG"
    assert detail["risk_factors"]["model"] == risk.MODEL
    assert [e["kind"] for e in detail["events"]] == ["detected"]
    assert site.get_scan(first)["summary"]["findings"]["new"] == 1

    # The port stops answering: inconclusive, the finding stays open (PRD §13).
    scan(site, [])
    (f,) = findings(site)
    assert f["status"] == "open" and f["not_observed_since"] is not None

    # The check runs again and the condition is absent: verified resolved.
    fixed = scan(site, [redis(auth=True)])
    (f,) = findings(site, "status=resolved")
    assert f["resolved_at"] is not None and findings(site, "status=active") == []
    detail = site.client.get(f"/api/v1/findings/{f['id']}", headers=site.owner).json()
    assert detail["resolved_by_scan_id"] == fixed
    assert detail["events"][0]["kind"] == "verification_passed"

    # Detected again: reopened, with the history kept.
    scan(site, [redis(auth=False)])
    (f,) = findings(site, "status=active")
    assert (f["status"], f["reopen_count"]) == ("open", 1)


def test_an_interrupted_scan_never_resolves(site: Site) -> None:
    scan(site, [redis(auth=False)])
    scan(site, [], stopped="task time limit reached")
    (f,) = findings(site)
    assert f["status"] == "open"


@pytest.fixture
def openssh_cve(owner_engine: Engine) -> Iterator[str]:
    """A synthetic CVE (clearly not a real identifier) affecting OpenSSH 8.5 to 9.8."""
    cve = f"CVE-1900-{uuid.uuid4().int % 10**8:08d}"
    record = intel.parse_nvd_cve(
        nvd_item(
            cve,
            [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                match(
                                    "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                    versionStartIncluding="8.5",
                                    versionEndExcluding="9.8",
                                )
                            ],
                        }
                    ]
                }
            ],
        )
    )
    with owner_engine.begin() as c:
        intel.store_cves(c, [record])
    yield cve
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM intel.kev WHERE cve_id = :c"), {"c": cve})
        c.execute(text("DELETE FROM intel.cve WHERE id = :c"), {"c": cve})


def test_version_match_is_potential_never_confirmed(
    site: Site, openssh_cve: str, owner_engine: Engine
) -> None:
    scan(site, [ssh()])  # OpenSSH 9.6p1 Ubuntu-3ubuntu13.5
    (f,) = findings(site)
    assert (f["check_id"], f["confidence"], f["cves"]) == (
        "cve.version_match",
        "potential",
        [openssh_cve],
    )
    assert f["severity_score"] == 8.1 and f["kev"] is False
    detail = site.client.get(f"/api/v1/findings/{f['id']}", headers=site.owner).json()
    assert (
        "(ubuntu, package revision 3ubuntu13.5)" in detail["explanation"]
        and "backported" in detail["explanation"]
    )
    assert detail["intel"][0]["id"] == openssh_cve
    assert detail["detail"]["upgrade_to"] == "9.8"
    before = f["risk_score"]

    # KEV lists it later: reassessment updates the score without a scan and resolves nothing.
    with owner_engine.begin() as c:
        c.execute(
            text("INSERT INTO intel.kev (cve_id, catalog_version) VALUES (:c, 'test')"),
            {"c": openssh_cve},
        )
    r = site.client.post("/api/v1/findings/reassess", headers=site.owner)
    assert r.status_code == 200, r.text
    (f,) = findings(site)
    assert f["kev"] is True and f["risk_score"] == before + 20 and f["status"] == "open"
    assert findings(site, "kev=true")[0]["id"] == f["id"]


def test_workflow_rules_and_role_limits(site: Site) -> None:
    scan(site, [redis(auth=False)])
    (f,) = findings(site)
    url = f"/api/v1/findings/{f['id']}"
    owner = site.owner
    patch = site.client.patch

    assert patch(url, json={"status": "resolved"}, headers=owner).status_code == 422
    assert patch(url, json={"status": "false_positive"}, headers=owner).status_code == 422
    r = patch(url, json={"status": "risk_accepted", "reason": "lab"}, headers=owner)
    assert r.status_code == 422  # needs an expiry date
    r = patch(
        url,
        json={"status": "risk_accepted", "reason": "lab", "accepted_until": "2099-01-01"},
        headers=owner,
    )
    assert r.status_code == 422  # more than a year ahead

    token = owner["Authorization"].removeprefix("Bearer ")
    analyst_id, analyst_email = add(site.client, token, "analyst")
    contrib_id, contrib_email = add(site.client, token, "remediation_contributor")
    viewer_id, viewer_email = add(site.client, token, "viewer")
    analyst = bearer(login(site.client, analyst_email))
    contrib = bearer(login(site.client, contrib_email))
    viewer = bearer(login(site.client, viewer_email))

    soon = "2027-01-01"
    r = patch(
        url,
        json={"status": "risk_accepted", "reason": "x", "accepted_until": soon},
        headers=analyst,
    )
    assert r.status_code == 403  # only owners and administrators accept risk (PRD §10)
    assert patch(url, json={"status": "triaged"}, headers=viewer).status_code == 403
    assert site.client.get(url, headers=viewer).status_code == 200

    # The contributor sees nothing until a finding is assigned to them.
    assert site.client.get("/api/v1/findings", headers=contrib).json()["total"] == 0
    assert site.client.get(url, headers=contrib).status_code == 404
    r = patch(url, json={"assignee_id": contrib_id, "due_date": "2026-11-01"}, headers=analyst)
    assert r.status_code == 200 and r.json()["assignee_email"] == contrib_email
    assert r.json()["overdue"] is True
    assert site.client.get("/api/v1/findings", headers=contrib).json()["total"] == 1
    assert (
        patch(url, json={"status": "closed_unverified", "reason": "x"}, headers=contrib).status_code
        == 403
    )
    r = patch(url, json={"status": "fix_claimed"}, headers=contrib)
    assert r.status_code == 200 and r.json()["status"] == "fix_claimed"
    r = site.client.post(f"{url}/comments", json={"text": "patched"}, headers=contrib)
    assert r.status_code == 201
    kinds = [(e["kind"], e["actor_email"]) for e in r.json()["events"]]
    assert kinds[:2] == [("comment", contrib_email), ("status_changed", contrib_email)]

    r = patch(
        url,
        json={"status": "risk_accepted", "reason": "lab only", "accepted_until": soon},
        headers=owner,
    )
    assert r.status_code == 200 and r.json()["accepted_until"] == soon
    # Detected again while accepted: stays accepted.
    scan(site, [redis(auth=False)])
    assert findings(site)[0]["status"] == "risk_accepted"
    audit = site.client.get(
        f"/api/v1/audit-events?target_type=finding&target_id={f['id']}", headers=owner
    ).json()
    assert len(audit["items"]) >= 3
    assert viewer_id and analyst_id


def test_summary_and_csv_export(site: Site) -> None:
    scan(site, [redis(auth=False)])
    s = site.client.get("/api/v1/findings/summary", headers=site.owner).json()
    assert s["active"] == 1 and s["by_severity"] == {"critical": 1} and len(s["trend_30d"]) == 30
    assert s["top_assets"][0]["id"] == site.asset
    csv_text = site.client.get("/api/v1/findings/export.csv", headers=site.owner).text
    assert csv_text.splitlines()[0].startswith("id,risk_score") and "redis.no_auth" in csv_text
    row = next(csv.DictReader(io.StringIO(csv_text)))
    assert row["cves"] == "" and row["title"].startswith("Redis")


def test_intel_sources_report_freshness(site: Site) -> None:
    r = site.client.get("/api/v1/intel/sources", headers=site.owner).json()
    assert {s["name"] for s in r["sources"]} == {"nvd", "kev", "epss"}
    assert "not endorsed or certified by the NVD" in r["notice"]
    assert all("cursor" not in s for s in r["sources"])
    missing = site.client.get("/api/v1/intel/cves/CVE-1900-00000000", headers=site.owner)
    assert missing.status_code == 404


def test_nvd_sync_keeps_products_that_succeeded(
    owner_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulnex.intel.time.sleep", lambda _s: None)
    cve = f"CVE-1900-{uuid.uuid4().int % 10**8:08d}"
    item = nvd_item(cve, [{"nodes": [{"cpeMatch": [match("cpe:2.3:a:vx-good:prod:1.0")]}]}])

    def fetch(url: str, params: dict[str, Any]) -> bytes:
        if "vx-bad" in params["virtualMatchString"]:
            raise intel.IntelError("NVD answered 503")
        page = {"format": "NVD_CVE", "resultsPerPage": 1, "totalResults": 1}
        return json.dumps(page | {"vulnerabilities": [item]}).encode()

    try:
        with pytest.raises(intel.IntelError, match="1 product"):
            intel.sync_nvd(owner_engine, fetch, products=[("vx-bad", "prod"), ("vx-good", "prod")])
        with owner_engine.begin() as c:
            assert (
                c.execute(text("SELECT count(*) FROM intel.cve WHERE id = :c"), {"c": cve}).scalar()
                == 1
            )
            src = c.execute(text("SELECT * FROM intel.source WHERE name = 'nvd'")).mappings().one()
            assert src["status"] == "error" and "vx-bad:prod" in src["error"]
            assert "vx-good:prod" in src["cursor"] and "vx-bad:prod" not in src["cursor"]
    finally:
        with owner_engine.begin() as c:
            c.execute(text("DELETE FROM intel.cve WHERE id = :c"), {"c": cve})
            c.execute(
                text("UPDATE intel.source SET cursor = cursor - 'vx-good:prod' WHERE name = 'nvd'")
            )
