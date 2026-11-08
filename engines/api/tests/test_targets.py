"""Target parsing and scope membership (ADR-0006 §5 steps 1-5). Pure functions: no database."""

import pytest
from vulnex.targets import (
    ASSET_MIN_PREFIX,
    SCOPE_MIN_PREFIX,
    Kind,
    ScopeEntry,
    Target,
    TargetError,
    parse,
    parse_scope_entry,
    scope_digest,
    scope_problem,
)


def asset(raw: str) -> Target:
    return parse(raw, min_prefix=ASSET_MIN_PREFIX)


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("192.0.2.10", Kind.IP, "192.0.2.10"),
        ("  10.0.0.1 ", Kind.IP, "10.0.0.1"),
        ("10.0.0.0/24", Kind.CIDR, "10.0.0.0/24"),
        ("10.0.0.7/32", Kind.IP, "10.0.0.7"),
        ("203.0.112.0/20", Kind.CIDR, "203.0.112.0/20"),
        ("Host.Example.COM", Kind.HOSTNAME, "host.example.com"),
        ("host.example.com.", Kind.HOSTNAME, "host.example.com"),
        ("xn--bcher-kva.example", Kind.HOSTNAME, "xn--bcher-kva.example"),
        ("cafe.de", Kind.HOSTNAME, "cafe.de"),  # hex letters only, still a hostname
        ("1password.com", Kind.HOSTNAME, "1password.com"),
        ("a-b.c-d.example", Kind.HOSTNAME, "a-b.c-d.example"),
    ],
)
def test_accepts_canonical_targets(raw: str, kind: Kind, value: str) -> None:
    assert asset(raw) == Target(kind, value)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        # Alternative IPv4 notations that resolvers or browsers may reinterpret (ADR-0006 §5.1).
        ("2130706433", "dotted-decimal"),
        ("0x7f.0.0.1", "dotted-decimal"),
        ("0x7f000001", "dotted-decimal"),
        ("0177.0.0.1", "dotted-decimal"),
        ("127.1", "dotted-decimal"),
        ("010.0.0.1", "dotted-decimal"),
        ("10.0.0.256", "dotted-decimal"),
        ("10.0.0", "dotted-decimal"),
        ("host.0x10", "dotted-decimal"),
        ("1.2.3.4.5", "dotted-decimal"),
        # Never-allowed ranges, whatever the scope says.
        ("127.0.0.1", "never scans"),
        ("169.254.169.254", "never scans"),
        ("0.0.0.0", "never scans"),
        ("224.0.0.1", "never scans"),
        ("255.255.255.255", "never scans"),
        ("169.254.0.0/20", "never scans"),
        # IPv6 in any form, including IPv4-mapped.
        ("::1", "IPv6"),
        ("::ffff:127.0.0.1", "IPv6"),
        ("[2001:db8::1]", "IPv6"),
        # CIDR shape.
        ("10.0.0.1/24", "host bits set; did you mean 10.0.0.0/24"),
        ("10.0.0.0/33", "prefix length"),
        ("10.0.0.0/08", "prefix length"),
        ("10.0.0.0/", "prefix length"),
        ("10.0.0.0/16", "wider than /20"),
        # Hostnames.
        ("localhost.localhost", "localhost"),
        ("intranet", "fully qualified"),
        ("bücher.example", "xn--"),
        ("-bad.example.com", "not a valid hostname label"),
        ("bad-.example.com", "not a valid hostname label"),
        ("a..example.com", "not a valid hostname label"),
        ("under_score.example.com", "not a valid hostname label"),
        ("*.example.com", "only allowed in scope entries"),
        ("http://example.com", "not a URL"),
        ("example.com/path", "not a URL or path"),
        ("example.com:443", "without a port"),
        ("10.0.0.1:22", "without a port"),
        ("", "Enter"),
        ("a" * 64 + ".example.com", "not a valid hostname label"),
    ],
)
def test_rejects_unsafe_or_malformed_targets(raw: str, message: str) -> None:
    with pytest.raises(TargetError, match=message.replace("(", r"\(").replace(".", r"\.")):
        asset(raw)


def test_scope_entries_allow_wider_ranges_and_wildcards_and_store_ips_as_32() -> None:
    assert parse_scope_entry("10.0.0.0/8", exclude=False) == ScopeEntry(
        Kind.CIDR, "10.0.0.0/8", False
    )
    assert parse_scope_entry("10.0.0.5", exclude=True) == ScopeEntry(Kind.CIDR, "10.0.0.5/32", True)
    assert parse_scope_entry("*.Example.com", exclude=False) == ScopeEntry(
        Kind.HOSTNAME_WILDCARD, "example.com", False
    )
    with pytest.raises(TargetError, match=f"wider than /{SCOPE_MIN_PREFIX}"):
        parse_scope_entry("10.0.0.0/7", exclude=False)
    with pytest.raises(TargetError, match="never scans"):
        parse_scope_entry("127.0.0.0/8", exclude=False)


SCOPE = [
    ScopeEntry(Kind.CIDR, "10.0.0.0/16", False),
    ScopeEntry(Kind.CIDR, "10.0.5.0/28", True),
    ScopeEntry(Kind.CIDR, "203.0.113.0/24", False),
    ScopeEntry(Kind.HOSTNAME, "app.example.com", False),
    ScopeEntry(Kind.HOSTNAME_WILDCARD, "corp.example.com", False),
    ScopeEntry(Kind.HOSTNAME, "hr.corp.example.com", True),
]


@pytest.mark.parametrize(
    ("raw", "problem"),
    [
        ("10.0.1.20", None),
        ("10.0.4.0/24", None),
        ("10.0.5.0/24", None),  # partly excluded: allowed, excluded hosts skipped at scan time
        ("203.0.113.9", None),
        ("app.example.com", None),
        ("a.corp.example.com", None),
        ("x.y.corp.example.com", None),
        ("10.0.5.3", "excluded"),
        ("10.0.5.0/28", "excluded"),
        ("10.1.0.1", "not inside any included range"),
        ("10.0.0.0/20", None),
        ("192.168.1.1", "not inside any included range"),
        ("corp.example.com", "does not match"),  # a wildcard covers subdomains only
        ("www.example.com", "does not match"),
        ("evilcorp.example.com", "does not match"),
        ("hr.corp.example.com", "excluded"),
    ],
)
def test_scope_membership(raw: str, problem: str | None) -> None:
    result = scope_problem(asset(raw), SCOPE)
    if problem is None:
        assert result is None
    else:
        assert result is not None and problem in result


def test_range_must_fit_inside_one_included_range() -> None:
    entries = [
        ScopeEntry(Kind.CIDR, "10.0.0.0/25", False),
        ScopeEntry(Kind.CIDR, "10.0.0.128/25", False),
    ]
    assert scope_problem(asset("10.0.0.0/24"), entries) is not None


def test_empty_scope_contains_nothing() -> None:
    assert scope_problem(asset("10.0.0.1"), []) is not None
    assert scope_problem(asset("a.example.com"), []) is not None


def test_digest_is_order_independent_and_sensitive_to_every_field() -> None:
    a = ScopeEntry(Kind.CIDR, "10.0.0.0/16", False)
    b = ScopeEntry(Kind.HOSTNAME, "app.example.com", False)
    assert scope_digest([a, b]) == scope_digest([b, a])
    assert scope_digest([a]) != scope_digest([a, b])
    assert scope_digest([a]) != scope_digest([ScopeEntry(Kind.CIDR, "10.0.0.0/16", True)])
