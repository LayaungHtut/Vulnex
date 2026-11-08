"""The worker's own scope decision (ADR-0006 §5): it must hold even for a validly signed lease
whose targets are wrong, and it must respect the worker's local ceiling."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnex_scanner.check import scope_check
from vulnex_worker_protocol.lease import LeaseScopeEntry, Limits, ScopeLease
from vulnex_worker_protocol.targets import ScopeEntry, parse_scope_entry, scope_digest

SCOPE = [
    parse_scope_entry("10.0.0.0/16", exclude=False),
    parse_scope_entry("10.0.1.0/26", exclude=True),
    parse_scope_entry("*.lab.example", exclude=False),
]


def lease(targets: list[str], max_addresses: int = 4096) -> ScopeLease:
    now = datetime.now(UTC)
    return ScopeLease(
        kid="k",
        job_id=uuid.uuid4(),
        lease_id=uuid.uuid4(),
        attempt=1,
        tenant_id=uuid.uuid4(),
        worker_id=uuid.uuid4(),
        scope_group_id=uuid.uuid4(),
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        kind="scope.check",
        targets=targets,
        scope=[LeaseScopeEntry(kind=e.kind.value, value=e.value, exclude=e.exclude) for e in SCOPE],
        scope_digest=scope_digest(SCOPE),
        limits=Limits(
            max_addresses=max_addresses, task_timeout_s=60, probe_timeout_s=1, max_concurrency=1
        ),
    )


def run(targets: list[str], ceiling: list[ScopeEntry] | None = None, **kw: Any) -> dict[str, Any]:
    return scope_check(lease(targets, **kw), ceiling or [])


def test_in_scope_targets_are_allowed_and_exclusions_are_subtracted() -> None:
    report = run(["10.0.0.5", "10.0.1.0/24", "db.lab.example"])
    assert report["refused"] == []
    assert report["allowed"] == [
        {"target": "10.0.0.5", "kind": "ip", "addresses": 1},
        {"target": "10.0.1.0/24", "kind": "cidr", "addresses": 256 - 64},
        {"target": "db.lab.example", "kind": "hostname", "addresses": None},
    ]


def test_a_signed_lease_cannot_smuggle_targets_outside_its_scope() -> None:
    bad = ["10.1.0.1", "169.254.169.254", "10.0.1.7", "lab.example", "0x7f.1", "evil.test"]
    report = run(bad)
    assert report["allowed"] == []
    reasons = {r["target"]: r["reason"] for r in report["refused"]}
    assert set(reasons) == set(bad)
    assert "not inside any included range" in reasons["10.1.0.1"]
    assert "excluded" in reasons["10.0.1.7"]
    assert "does not match" in reasons["lab.example"]  # the wildcard covers subdomains only


def test_the_local_ceiling_narrows_what_the_lease_allows() -> None:
    ceiling = [parse_scope_entry("10.0.0.0/24", exclude=False)]
    report = run(["10.0.0.9", "10.0.2.9", "db.lab.example"], ceiling)
    assert [a["target"] for a in report["allowed"]] == ["10.0.0.9"]
    assert all("local scope ceiling" in r["reason"] for r in report["refused"])


def test_address_limit_is_enforced() -> None:
    report = run(["10.0.4.0/24"], max_addresses=100)
    assert report["allowed"] == [] and "more addresses" in report["refused"][0]["reason"]
