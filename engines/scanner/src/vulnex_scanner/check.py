"""The `scope.check` task (M4): decide, per target, what this worker would be allowed to touch.

Pure computation on the verified lease. It sends nothing to any target and resolves no names;
M5 adds probing behind the same checks (ADR-0006 §5), re-applied per address at connect time.
"""

from ipaddress import IPv4Network
from typing import Any

from vulnex_worker_protocol.lease import ScopeLease
from vulnex_worker_protocol.targets import (
    ASSET_MIN_PREFIX,
    NEVER_ALLOWED,
    Kind,
    ScopeEntry,
    TargetError,
    parse,
    scope_problem,
)


def scope_check(lease: ScopeLease, ceiling: list[ScopeEntry]) -> dict[str, Any]:
    """Report allowed and refused targets. `ceiling` is this worker's own limit (may be empty:
    no local limit). The lease scope and the ceiling must both admit a target."""
    entries = lease.scope_entries()
    excluded = [IPv4Network(e.value) for e in entries if e.exclude and e.kind == Kind.CIDR]
    allowed: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    for raw in lease.targets:
        try:
            target = parse(raw, min_prefix=ASSET_MIN_PREFIX)
        except TargetError as e:
            refused.append({"target": raw, "reason": str(e)})
            continue
        problem = scope_problem(target, entries)
        if problem is None and ceiling and scope_problem(target, ceiling):
            problem = f"{target.value} is outside this worker's local scope ceiling"
        if problem:
            refused.append({"target": raw, "reason": problem})
            continue
        network = target.network
        if network is None:  # hostname: resolved and re-checked per address in M5
            allowed.append({"target": raw, "kind": target.kind.value, "addresses": None})
            continue
        skip = [n for n in (*excluded, *NEVER_ALLOWED) if n.overlaps(network)]
        count = sum(1 for a in network if not any(a in n for n in skip))
        if count > lease.limits.max_addresses:
            refused.append({"target": raw, "reason": "more addresses than this task may cover"})
            continue
        allowed.append({"target": raw, "kind": target.kind.value, "addresses": count})
    return {"profile": "scope_check", "allowed": allowed, "refused": refused}
