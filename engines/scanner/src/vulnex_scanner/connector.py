"""The scanner's only network path to targets (ADR-0006 §5).

Every connection to a target goes through `Connector.connect`, which re-validates the exact
address and port immediately before the socket is opened:

1. the task is still running (not cancelled, lease not lost, task deadline not passed);
2. the address is IPv4 and not in a never-allowed range (loopback, link-local/metadata, ...);
3. it is not this worker's own address or the control plane's address;
4. the port is one the signed lease lists;
5. the address belongs to the target being probed (inside its range, or one of the addresses
   its hostname resolved to at the start of the task);
6. the address is inside an included CIDR of the signed scope and not excluded, so a hostname
   that resolves (or is rebound) outside the authorized ranges is refused;
7. it is inside this worker's local scope ceiling, when one is configured.

Names are resolved once per task (`resolve`); connections go to the validated address, never
back to the name, which defeats DNS rebinding between check and connect. Redirects are never
followed. Responses are read with a byte cap. Nothing else in the scanner opens sockets to
targets; tests assert this module is the only one that imports `socket`/`ssl` for that purpose.
"""

import socket
import ssl
import threading
import time
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from vulnex_worker_protocol.lease import ScopeLease
from vulnex_worker_protocol.targets import NEVER_ALLOWED, Kind, ScopeEntry, Target, scope_problem

MAX_READ = 64 * 1024  # ADR-0006 §5.8: bytes kept per probe response


class Refused(Exception):
    """The connection must not be made. The message is safe to report."""


def embedded_ipv4(addr: IPv6Address) -> IPv4Address | None:
    """IPv4 address embedded in an IPv6 transition form (mapped, compatible, NAT64, 6to4,
    Teredo), for audit and deny-list checks (ADR-0006 §5.2). Such addresses are still refused."""
    if addr.ipv4_mapped:
        return addr.ipv4_mapped
    if addr.sixtofour:
        return addr.sixtofour
    if addr.teredo:
        return addr.teredo[1]
    packed = addr.packed
    if packed[:12] == bytes.fromhex("0064ff9b0000000000000000"):  # NAT64 64:ff9b::/96
        return IPv4Address(packed[12:])
    if packed[:12] == bytes(12) and int(addr) > 1:  # IPv4-compatible ::/96 (deprecated)
        return IPv4Address(packed[12:])
    return None


@dataclass
class Resolution:
    """What one name resolved to, kept for the whole task (TTLs never extend authorization)."""

    name: str
    canonical: str | None
    ipv4: list[str]
    ipv6: list[str]
    error: str | None
    resolved_at: str

    def evidence(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "resolver": "system",
            "canonical_name": self.canonical,
            "a": self.ipv4,
            "aaaa": self.ipv6,
            "resolved_at": self.resolved_at,
        }
        if self.error:
            out["error"] = self.error
        if self.ipv6:
            out["coverage_gap"] = "IPv6 address observed, not assessed in this version"
            embedded = {
                a: str(e) for a in self.ipv6 if (e := embedded_ipv4(IPv6Address(a))) is not None
            }
            if embedded:
                out["aaaa_embedded_ipv4"] = embedded
        return out


def resolve(name: str) -> Resolution:
    now = datetime.now(UTC).isoformat()
    try:
        infos = socket.getaddrinfo(
            name, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_CANONNAME
        )
    except socket.gaierror as e:
        return Resolution(name, None, [], [], f"resolution failed: {e.strerror}", now)
    v4: list[str] = []
    v6: list[str] = []
    canonical = None
    for family, _, _, canon, sockaddr in infos:
        canonical = canonical or (canon or None)
        addr = str(sockaddr[0])
        bucket = v4 if family == socket.AF_INET else v6
        if addr not in bucket:
            bucket.append(addr)
    return Resolution(name, canonical, sorted(v4, key=IPv4Address), sorted(v6), None, now)


def local_addresses(control_plane_host: str | None) -> frozenset[IPv4Address]:
    """This host's own IPv4 addresses and the control plane's (never-allowed, ADR-0006 §5.3)."""
    found: set[IPv4Address] = set()
    names = [socket.gethostname()] + ([control_plane_host] if control_plane_host else [])
    for name in names:
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            continue
        found.update(IPv4Address(str(i[4][0])) for i in infos)
    return frozenset(found)


@dataclass
class Connector:
    """Per-task connection policy built from a verified lease."""

    lease: ScopeLease
    ceiling: list[ScopeEntry] = field(default_factory=list)
    deny: frozenset[IPv4Address] = frozenset()
    stop: threading.Event = field(default_factory=threading.Event)
    clock: Any = time.monotonic
    deadline: float = 0.0
    stop_reason: str | None = None

    def __post_init__(self) -> None:
        self.entries = self.lease.scope_entries()
        self.ports = frozenset(self.lease.ports)
        self.timeout = self.lease.limits.probe_timeout_s
        if not self.deadline:
            self.deadline = self.clock() + self.lease.limits.task_timeout_s
        self._ceiling_cidrs = [e for e in self.ceiling if e.kind == Kind.CIDR]
        self.connections = 0
        self._lock = threading.Lock()

    def check(self, target: Target, address: str, port: int, resolved: list[str] | None) -> None:
        """Raise Refused unless connecting to address:port for `target` is allowed now."""
        if self.stop.is_set():
            raise Refused("task stopped (cancelled, lease lost or worker shutting down)")
        if self.clock() > self.deadline:
            raise Refused("task time limit reached")
        try:
            addr = ip_address(address)
        except ValueError:
            raise Refused(f"{address!r} is not an IP address") from None
        if not isinstance(addr, IPv4Address):
            raise Refused(f"{address} is IPv6, which this version does not assess")
        for blocked in NEVER_ALLOWED:
            if addr in blocked:
                raise Refused(f"{address} is in {blocked}, which is never scanned")
        if addr in self.deny:
            raise Refused(f"{address} is this worker or its control plane")
        if port not in self.ports:
            raise Refused(f"port {port} is not in the signed lease")
        network = target.network
        if network is not None:
            if addr not in network:
                raise Refused(f"{address} is not part of target {target.value}")
        elif resolved is None or address not in resolved:
            raise Refused(f"{address} is not an address {target.value} resolved to")
        problem = scope_problem(Target(Kind.IP, address), self.entries)
        if problem:
            raise Refused(problem)
        if self.ceiling:
            here = Target(Kind.IP, address)
            outside = (
                scope_problem(here, self.ceiling)
                if network is not None
                else scope_problem(target, self.ceiling)
                or (self._ceiling_cidrs and scope_problem(here, self._ceiling_cidrs))
            )
            if outside:
                raise Refused(f"{address} is outside this worker's local scope ceiling")

    def connect(
        self, target: Target, address: str, port: int, resolved: list[str] | None = None
    ) -> socket.socket:
        """A connected TCP socket to the validated address (never to a name)."""
        self.check(target, address, port, resolved)
        with self._lock:
            self.connections += 1
        return socket.create_connection((address, port), timeout=self.timeout)

    def tls(
        self,
        target: Target,
        address: str,
        port: int,
        resolved: list[str] | None,
        *,
        server_name: str | None,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
    ) -> ssl.SSLSocket:
        """A TLS connection for observation only: the certificate is recorded, not trusted."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if min_version is not None or max_version is not None:
            # Legacy protocol detection needs OpenSSL's lowest security level.
            ctx.set_ciphers("ALL:@SECLEVEL=0")
            with warnings.catch_warnings():  # offering TLS 1.0/1.1 is the point of this probe
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = min_version or ssl.TLSVersion.MINIMUM_SUPPORTED
                ctx.maximum_version = max_version or ssl.TLSVersion.MAXIMUM_SUPPORTED
        raw = self.connect(target, address, port, resolved)
        try:
            return ctx.wrap_socket(raw, server_hostname=server_name)
        except BaseException:
            raw.close()
            raise

    def read(
        self, sock: socket.socket, *, limit: int = MAX_READ, wait: float | None = None
    ) -> bytes:
        """Read until the peer closes, `limit` bytes, or `wait` seconds pass."""
        end = time.monotonic() + (wait if wait is not None else self.timeout)
        chunks: list[bytes] = []
        size = 0
        while size < limit:
            left = end - time.monotonic()
            if left <= 0:
                break
            sock.settimeout(left)
            try:
                chunk = sock.recv(min(8192, limit - size))
            except TimeoutError:
                break
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
