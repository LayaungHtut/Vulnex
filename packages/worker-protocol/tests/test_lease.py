"""Signed scope leases (ADR-0006 §4): every check the worker runs before acting on a lease."""

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnex_worker_protocol.lease import (
    LeaseError,
    LeaseScopeEntry,
    Limits,
    ScopeLease,
    SignedLease,
    load_public_key,
    public_key_b64,
    sign,
    verify,
)
from vulnex_worker_protocol.targets import Kind, ScopeEntry, scope_digest

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
KEY = Ed25519PrivateKey.generate()
KEYS = {"scope-1": load_public_key(public_key_b64(KEY))}
ENTRIES = [ScopeEntry(Kind.CIDR, "10.0.0.0/16", False), ScopeEntry(Kind.CIDR, "10.0.9.0/24", True)]


def lease(**overrides: Any) -> ScopeLease:
    fields: dict[str, Any] = {
        "kid": "scope-1",
        "job_id": uuid.uuid4(),
        "lease_id": uuid.uuid4(),
        "attempt": 1,
        "tenant_id": uuid.uuid4(),
        "worker_id": uuid.uuid4(),
        "scope_group_id": uuid.uuid4(),
        "not_before": NOW,
        "expires_at": NOW + timedelta(minutes=15),
        "kind": "scope.check",
        "targets": ["10.0.1.0/24"],
        "scope": [
            LeaseScopeEntry(kind=e.kind.value, value=e.value, exclude=e.exclude) for e in ENTRIES
        ],
        "scope_digest": scope_digest(ENTRIES),
        "limits": Limits(
            max_addresses=4096, task_timeout_s=900, probe_timeout_s=1, max_concurrency=8
        ),
    }
    return ScopeLease(**(fields | overrides))


def check(signed: SignedLease, original: ScopeLease, **overrides: Any) -> ScopeLease:
    expected: dict[str, Any] = {
        "worker_id": original.worker_id,
        "tenant_id": original.tenant_id,
        "job_id": original.job_id,
        "lease_id": original.lease_id,
        "attempt": original.attempt,
        "now": NOW,
    }
    return verify(signed, KEYS, **(expected | overrides))


def test_a_valid_lease_round_trips() -> None:
    original = lease()
    assert check(sign(original, KEY), original) == original


def tamper(signed: SignedLease, **changes: Any) -> SignedLease:
    body = json.loads(base64.b64decode(signed.payload_b64))
    body.update(changes)
    raw = json.dumps(body).encode()
    return signed.model_copy(update={"payload_b64": base64.b64encode(raw).decode()})


@pytest.mark.parametrize(
    "change",
    [
        {"targets": ["169.254.169.254"]},
        {"scope": [{"kind": "cidr", "value": "0.0.0.0/0", "exclude": False}]},
        {"expires_at": "2099-01-01T00:00:00Z"},
    ],
)
def test_any_change_to_the_signed_bytes_is_refused(change: dict[str, Any]) -> None:
    original = lease()
    with pytest.raises(LeaseError, match="signature"):
        check(tamper(sign(original, KEY), **change), original)


def test_a_lease_signed_by_another_key_is_refused() -> None:
    original = lease()
    forged = sign(original, Ed25519PrivateKey.generate())
    with pytest.raises(LeaseError, match="signature"):
        check(forged, original)
    with pytest.raises(LeaseError, match="unknown signing key"):
        check(forged.model_copy(update={"kid": "attacker"}), original)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"worker_id": uuid.uuid4()}, "another worker"),
        ({"tenant_id": uuid.uuid4()}, "another worker or tenant"),
        ({"job_id": uuid.uuid4()}, "does not match the task"),
        ({"lease_id": uuid.uuid4()}, "does not match the task"),
        ({"attempt": 2}, "does not match the task"),
        ({"now": NOW + timedelta(minutes=18)}, "expired"),
        ({"now": NOW - timedelta(minutes=3)}, "not valid yet"),
    ],
)
def test_lease_must_match_this_worker_task_and_time(override: dict[str, Any], message: str) -> None:
    original = lease()
    with pytest.raises(LeaseError, match=message):
        check(sign(original, KEY), original, **override)


def test_clock_skew_within_two_minutes_is_tolerated() -> None:
    original = lease()
    check(sign(original, KEY), original, now=NOW - timedelta(seconds=90))
    check(sign(original, KEY), original, now=original.expires_at + timedelta(seconds=90))


def test_scope_that_does_not_match_its_digest_is_refused_even_when_signed() -> None:
    """A signing bug (or a compromised signer reusing an old digest) must not widen scope."""
    original = lease(scope=[LeaseScopeEntry(kind="cidr", value="10.0.0.0/8", exclude=False)])
    with pytest.raises(LeaseError, match="digest"):
        check(sign(original, KEY), original)


def test_garbage_is_refused() -> None:
    original = lease()
    junk = SignedLease(kid="scope-1", payload_b64="!!!", sig_b64="AAAA")
    with pytest.raises(LeaseError):
        check(junk, original)
    payload = b'{"not": "a lease"}'
    unsigned_shape = SignedLease(
        kid="scope-1",
        payload_b64=base64.b64encode(payload).decode(),
        sig_b64=base64.b64encode(KEY.sign(payload)).decode(),
    )
    with pytest.raises(LeaseError, match="not a valid lease"):
        check(unsigned_shape, original)
