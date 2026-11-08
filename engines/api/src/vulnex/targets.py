"""Strict parsing of scan targets and scope entries, and scope membership (ADR-0006 §5 steps 1-5).

One parser for every place a target is accepted (scope definition, asset registration, and later
target expansion in the worker), so notation tricks cannot pass one check and fail another:

- IPv4 only in canonical dotted decimal. Integer, hex, octal, short and zero-padded forms
  (`2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`, `010.0.0.1`) are rejected, never reinterpreted.
- CIDRs must have host bits zero and a prefix no wider than the caller allows.
- IPv6 is rejected: v0 does not assess IPv6 (PRD §7, ADR-0006 §5.2).
- Hostnames must already be ASCII (internationalised names in their `xn--` form); labels follow
  LDH rules; a name whose last label is numeric is rejected (it is an IP in disguise).
- Never-allowed ranges (loopback, link-local incl. cloud metadata, "this network", multicast,
  reserved, broadcast) are refused whatever the scope says.
"""

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network

NEVER_ALLOWED = tuple(
    IPv4Network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, including cloud metadata 169.254.169.254
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, including broadcast 255.255.255.255
    )
)

SCOPE_MIN_PREFIX = 8  # a scope entry may authorize at most a /8
ASSET_MIN_PREFIX = 20  # a range registered as one asset holds at most 4,096 addresses

_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4 = re.compile(rf"{_OCTET}(\.{_OCTET}){{3}}")
_PREFIX = re.compile(r"[0-9]|[12][0-9]|3[0-2]")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
# WHATWG URL "ends in a number": a host whose last label is decimal or 0x-hex is an IP literal
# attempt (browsers and many resolvers would treat it as one), never a hostname.
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")


class Kind(StrEnum):
    IP = "ip"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    HOSTNAME_WILDCARD = "hostname_wildcard"  # scope entries only: *.example.com


class TargetError(ValueError):
    """The input is not an acceptable target. The message is safe to show to the user."""


@dataclass(frozen=True)
class Target:
    kind: Kind
    value: str  # canonical text, as stored

    @property
    def network(self) -> IPv4Network | None:
        if self.kind == Kind.IP:
            return IPv4Network(f"{self.value}/32")
        if self.kind == Kind.CIDR:
            return IPv4Network(self.value)
        return None


def _ipv4(text: str) -> IPv4Address:
    if not _IPV4.fullmatch(text):
        raise TargetError(
            f"'{text}' is not an IPv4 address in dotted-decimal form, such as 192.0.2.10"
        )
    return IPv4Address(text)


def _check_allowed(network: IPv4Network) -> None:
    shown = network.network_address if network.prefixlen == 32 else network
    for blocked in NEVER_ALLOWED:
        if network.overlaps(blocked):
            raise TargetError(
                f"{shown} is in {blocked}, which VULNEX never scans "
                "(loopback, link-local and cloud metadata, multicast or reserved addresses)"
            )


def _hostname(text: str, *, wildcard: bool) -> Target:
    name = text[:-1] if text.endswith(".") else text
    is_wildcard = name.startswith("*.")
    if is_wildcard:
        if not wildcard:
            raise TargetError("Wildcards (*.example.com) are only allowed in scope entries")
        name = name[2:]
    if not name.isascii():
        raise TargetError("Enter internationalised domain names in their ASCII (xn--) form")
    if len(name) > 253:
        raise TargetError("Hostnames are at most 253 characters")
    labels = name.split(".")
    if len(labels) < 2:
        raise TargetError(
            "Use a fully qualified hostname (such as host.example.com), not a single label"
        )
    for label in labels:
        if not _LABEL.fullmatch(label):
            raise TargetError(
                f"'{label}' is not a valid hostname label (letters, digits and inner hyphens, "
                "at most 63 characters)"
            )
    if labels[-1].isdigit():
        raise TargetError(f"'{text}' looks like an IP address, not a hostname")
    if labels[-1] == "localhost":
        raise TargetError("localhost names are never scanned")
    return Target(Kind.HOSTNAME_WILDCARD if is_wildcard else Kind.HOSTNAME, name)


def parse(raw: str, *, min_prefix: int, wildcard: bool = False) -> Target:
    """Parse one target. `min_prefix` bounds how wide a CIDR may be (smaller = wider)."""
    text = raw.strip().lower()
    if not text:
        raise TargetError("Enter an IP address, range or hostname")
    if len(text) > 260:
        raise TargetError("Too long")
    if "://" in text:
        raise TargetError("Enter only the host (such as host.example.com), not a URL")
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        raise TargetError("Enter the host without a port; ports belong to the scan profile")
    if ":" in text:
        raise TargetError("IPv6 is not assessed in this version; enter an IPv4 address or hostname")

    if "/" in text:
        address, _, prefix = text.partition("/")
        if not _NUMERIC_LABEL.fullmatch(address.rsplit(".", 1)[-1]):
            raise TargetError("Enter only the host (such as host.example.com), not a URL or path")
        ip = _ipv4(address)
        if not _PREFIX.fullmatch(prefix):
            raise TargetError(f"'/{prefix}' is not a prefix length between /0 and /32")
        bits = int(prefix)
        network = IPv4Network(f"{ip}/{bits}", strict=False)
        if network.network_address != ip:
            raise TargetError(f"{text} has host bits set; did you mean {network}?")
        if bits < min_prefix:
            raise TargetError(f"Ranges wider than /{min_prefix} are not accepted here")
        _check_allowed(network)
        if bits == 32:
            return Target(Kind.IP, str(ip))
        return Target(Kind.CIDR, str(network))

    last_label = text.rstrip(".").rsplit(".", 1)[-1]
    if _NUMERIC_LABEL.fullmatch(last_label):
        ip = _ipv4(text)  # raises for 127.1, 0x7f.0.0.1, 2130706433, 010.0.0.1, ...
        _check_allowed(IPv4Network(f"{ip}/32"))
        return Target(Kind.IP, str(ip))

    return _hostname(text, wildcard=wildcard)


@dataclass(frozen=True)
class ScopeEntry:
    kind: Kind  # CIDR (single addresses are stored as /32), HOSTNAME or HOSTNAME_WILDCARD
    value: str
    exclude: bool


def parse_scope_entry(raw: str, *, exclude: bool) -> ScopeEntry:
    target = parse(raw, min_prefix=SCOPE_MIN_PREFIX, wildcard=True)
    if target.kind == Kind.IP:
        return ScopeEntry(Kind.CIDR, f"{target.value}/32", exclude)
    return ScopeEntry(target.kind, target.value, exclude)


def _name_matches(name: str, entry: ScopeEntry) -> bool:
    if entry.kind == Kind.HOSTNAME:
        return name == entry.value
    if entry.kind == Kind.HOSTNAME_WILDCARD:
        return name.endswith("." + entry.value)
    return False


def scope_problem(target: Target, entries: Iterable[ScopeEntry]) -> str | None:
    """Why `target` is outside the scope formed by `entries`, or None if it is inside.

    Addresses and ranges must lie entirely within one included CIDR and must not lie entirely
    within an exclusion; a range that partly overlaps an exclusion is accepted, and the excluded
    addresses are skipped at scan time (the worker enforces exclusions per address). Hostnames
    must match an included hostname or wildcard and no excluded one; the addresses they resolve
    to are checked against the CIDRs by the worker at connection time (ADR-0006 §5.6).
    """
    entries = list(entries)
    network = target.network
    if network is not None:
        cidrs = [(IPv4Network(e.value), e.exclude) for e in entries if e.kind == Kind.CIDR]
        if not any(network.subnet_of(n) for n, excl in cidrs if not excl):
            return f"{target.value} is not inside any included range of this scope"
        for n, excl in cidrs:
            if excl and network.subnet_of(n):
                return f"{target.value} is excluded from this scope ({n})"
        return None
    if not any(_name_matches(target.value, e) for e in entries if not e.exclude):
        return f"{target.value} does not match any included hostname of this scope"
    for e in entries:
        if e.exclude and _name_matches(target.value, e):
            return f"{target.value} is excluded from this scope ({e.value})"
    return None


def scope_digest(entries: Iterable[ScopeEntry]) -> str:
    """Stable fingerprint of a scope's entries; an authorization covers exactly this set."""
    lines = sorted(f"{e.kind}|{e.value}|{int(e.exclude)}" for e in entries)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()
