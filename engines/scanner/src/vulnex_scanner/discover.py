"""The `network.discover` task (M5): non-intrusive TCP service discovery.

Per target address and leased port:

1. TCP connect. Refused means closed (the host answered); a timeout means filtered.
2. If it connected, wait briefly for the service to speak first (SSH, FTP, SMTP, MySQL do).
3. If it stayed silent, try a TLS handshake and record the protocol, cipher and certificate
   (not trusted, only recorded), then test which TLS versions it accepts.
4. Send one `GET /` (over TLS if the handshake worked) and record the status line, headers and
   title. Redirects are recorded, never followed.

No credentials, no exploits, no payloads beyond a handshake and one GET. All connections go
through `Connector`, which re-checks scope per address and port.
"""

import base64
import hashlib
import re
import ssl
import time
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from vulnex_scanner import __version__
from vulnex_scanner.connector import Connector, Refused, resolve
from vulnex_worker_protocol.discovery import (
    BATCH_OPEN_PORTS,
    HttpObservation,
    OpenPort,
    RefusedProbe,
    TargetReport,
    TlsCertificate,
    TlsObservation,
)
from vulnex_worker_protocol.lease import ScopeLease
from vulnex_worker_protocol.targets import (
    ASSET_MIN_PREFIX,
    NEVER_ALLOWED,
    Kind,
    ScopeEntry,
    Target,
    TargetError,
    parse,
    scope_problem,
)

BANNER_WAIT_S = 1.5
BANNER_BYTES = 4096
USER_AGENT = f"VULNEX-Scanner/{__version__} (+authorized assessment)"
TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
# Read-only protocol probes for services that wait for the client to speak, sent only on their
# registered ports and only after the service stayed silent. Each is a status query a monitoring
# tool would send; none changes server state. (name, request, expected reply prefix, follow-up)
SAFE_PROBES: dict[int, tuple[str, bytes, tuple[bytes, ...], bytes | None]] = {
    6379: ("redis-ping", b"PING\r\n", (b"+PONG", b"-NOAUTH", b"-ERR"), b"INFO server\r\n"),
    11211: ("memcached-version", b"version\r\n", (b"VERSION",), None),
}
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def certificate(der: bytes) -> TlsCertificate:
    cert = x509.load_der_x509_certificate(der)
    dns: list[str] = []
    ips: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = [str(n) for n in san.get_values_for_type(x509.DNSName)][:200]
        ips = [str(n) for n in san.get_values_for_type(x509.IPAddress)][:50]
    except x509.ExtensionNotFound:
        pass
    key = cert.public_key()
    key_type, bits = None, None
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 456
    sig = cert.signature_hash_algorithm
    return TlsCertificate(
        subject=cert.subject.rfc4514_string()[:2000],
        issuer=cert.issuer.rfc4514_string()[:2000],
        serial=format(cert.serial_number, "x")[:100],
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        dns_names=dns,
        ip_addresses=ips,
        signature_algorithm=f"{sig.name}-with-{key_type}".lower() if sig and key_type else None,
        key_type=key_type,
        key_bits=bits,
        self_signed=cert.subject == cert.issuer,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )


def parse_http(data: bytes, scheme: str, host: str) -> HttpObservation | None:
    if not data.startswith(b"HTTP/"):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    headers = []
    for line in lines[1:61]:
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip()[:100], value.strip()[:1000]))
    title = None
    if m := _TITLE.search(body):
        title = " ".join(m.group(1).decode("utf-8", "replace").split())[:300] or None
    return HttpObservation(
        scheme=scheme,
        host_header=host,
        status=int(parts[1]),
        reason=(parts[2] if len(parts) > 2 else "")[:200],
        headers=headers,
        title=title,
        body_bytes=len(body),
        body_sha256=hashlib.sha256(body).hexdigest() if body else None,
    )


@dataclass
class Probe:
    target: Target
    address: str
    resolved: list[str] | None
    server_name: str | None  # SNI and Host header: the hostname for hostname targets


@dataclass
class Tally:
    report: TargetReport
    open: list[OpenPort] = field(default_factory=list)
    responding: set[str] = field(default_factory=set)
    closed: int = 0
    filtered: int = 0
    refused: list[RefusedProbe] = field(default_factory=list)


def probe_port(conn: Connector, p: Probe, port: int) -> tuple[str, OpenPort | None]:
    """Return ("open"|"closed"|"filtered", observation)."""
    started = time.monotonic()
    try:
        sock = conn.connect(p.target, p.address, port, p.resolved)
    except ConnectionRefusedError:
        return "closed", None
    except (TimeoutError, OSError):
        return "filtered", None
    connect_ms = int((time.monotonic() - started) * 1000)
    errors: list[str] = []
    with sock:
        banner = conn.read(sock, limit=BANNER_BYTES, wait=min(BANNER_WAIT_S, conn.timeout))
    tls: TlsObservation | None = None
    http: HttpObservation | None = None
    host = p.server_name or p.address
    probe: str | None = None
    reply: bytes = b""
    if not banner and port in SAFE_PROBES:
        probe, reply = _safe_probe(conn, p, port, errors)
    if not banner and not reply:
        probe = None
        tls, http = _tls_and_http(conn, p, port, host, errors)
        if tls is None:
            http = _http(conn, p, port, host, errors)
    return "open", OpenPort(
        address=p.address,
        port=port,
        observed_at=_now(),
        connect_ms=connect_ms,
        banner=banner.decode("utf-8", "backslashreplace")[:4096] if banner else None,
        banner_b64=base64.b64encode(banner).decode() if banner else None,
        tls=tls,
        http=http,
        probe=probe,
        probe_reply=reply.decode("utf-8", "backslashreplace")[:4096] if reply else None,
        errors=errors[:10],
    )


def _safe_probe(conn: Connector, p: Probe, port: int, errors: list[str]) -> tuple[str, bytes]:
    name, request, expected, follow_up = SAFE_PROBES[port]
    try:
        with conn.connect(p.target, p.address, port, p.resolved) as sock:
            sock.sendall(request)
            reply = conn.read(sock, limit=BANNER_BYTES, wait=min(BANNER_WAIT_S, conn.timeout))
            if not reply.startswith(expected):
                return name, b""
            if follow_up and reply.startswith(expected[0]):
                sock.sendall(follow_up)
                reply += b"\n" + conn.read(sock, limit=BANNER_BYTES, wait=conn.timeout)
            return name, reply
    except Refused:
        raise
    except OSError as e:
        errors.append(f"{name}: {type(e).__name__}")
        return name, b""


def _request(host: str) -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()


def _http(
    conn: Connector, p: Probe, port: int, host: str, errors: list[str]
) -> HttpObservation | None:
    try:
        with conn.connect(p.target, p.address, port, p.resolved) as sock:
            sock.sendall(_request(host))
            return parse_http(conn.read(sock), "http", host)
    except Refused:
        raise
    except OSError as e:
        errors.append(f"http: {type(e).__name__}")
        return None


def _tls_and_http(
    conn: Connector, p: Probe, port: int, host: str, errors: list[str]
) -> tuple[TlsObservation | None, HttpObservation | None]:
    try:
        tsock = conn.tls(p.target, p.address, port, p.resolved, server_name=p.server_name)
    except Refused:
        raise
    except (ssl.SSLError, OSError):
        return None, None
    with tsock:
        der = tsock.getpeercert(binary_form=True)
        cipher = tsock.cipher()
        version = tsock.version()
        http = None
        try:
            tsock.sendall(_request(host))
            http = parse_http(conn.read(tsock), "https", host)
        except (ssl.SSLError, OSError) as e:
            errors.append(f"https: {type(e).__name__}")
    cert = None
    if der:
        try:
            cert = certificate(der)
        except ValueError as e:
            errors.append(f"certificate unreadable: {e}"[:200])
    protocols: dict[str, bool] = {}
    for name, v in TLS_VERSIONS.items():
        if name == version:
            protocols[name] = True
            continue
        try:
            conn.tls(
                p.target,
                p.address,
                port,
                p.resolved,
                server_name=p.server_name,
                min_version=v,
                max_version=v,
            ).close()
            protocols[name] = True
        except Refused:
            raise
        except ValueError:
            pass  # this OpenSSL build cannot offer that version at all: not tested
        except (ssl.SSLError, OSError):
            protocols[name] = False
    return (
        TlsObservation(
            version=version,
            cipher=cipher[0] if cipher else None,
            cipher_bits=cipher[2] if cipher else None,
            server_name=p.server_name,
            certificate=cert,
            protocols=protocols,
        ),
        http,
    )


def _expand(
    lease: ScopeLease, ceiling: list[ScopeEntry], refused: list[RefusedProbe]
) -> Iterator[tuple[Target, str, list[str], list[str] | None, dict[str, Any] | None]]:
    """Yield (target, raw, addresses, resolved, dns evidence) for every target the worker may
    touch; record the others in `refused`. Same rules as `scope.check`."""
    entries = lease.scope_entries()
    excluded = [IPv4Network(e.value) for e in entries if e.exclude and e.kind == Kind.CIDR]
    total = 0
    for raw in lease.targets:
        try:
            target = parse(raw, min_prefix=ASSET_MIN_PREFIX)
        except TargetError as e:
            refused.append(RefusedProbe(reason=f"{raw}: {e}"[:300]))
            continue
        problem = scope_problem(target, entries)
        if problem is None and ceiling and scope_problem(target, ceiling):
            problem = f"{target.value} is outside this worker's local scope ceiling"
        if problem:
            refused.append(RefusedProbe(reason=problem[:300]))
            continue
        network = target.network
        if network is None:
            res = resolve(target.value)
            addresses = res.ipv4
            yield target, raw, addresses, res.ipv4, res.evidence()
            total += len(addresses)
            continue
        addresses = [
            str(a) for a in network.hosts() if not any(a in n for n in (*excluded, *NEVER_ALLOWED))
        ]
        if total + len(addresses) > lease.limits.max_addresses:
            refused.append(RefusedProbe(reason=f"{raw}: more addresses than this task may cover"))
            continue
        total += len(addresses)
        yield target, raw, addresses, None, None


Inflight = dict[Future[tuple[str, OpenPort | None]], tuple[str, int]]


def _collect(done: set[Future[tuple[str, OpenPort | None]]], inflight: Inflight, t: Tally) -> None:
    for f in done:
        address, port = inflight.pop(f)
        try:
            state, obs = f.result()
        except Refused as e:
            if len(t.refused) < 200:
                t.refused.append(RefusedProbe(address=address, port=port, reason=str(e)[:300]))
            continue
        if state == "open" and obs is not None:
            t.open.append(obs)
            t.responding.add(address)
        elif state == "closed":
            t.closed += 1
            t.responding.add(address)
        else:
            t.filtered += 1


Submit = Callable[[list[TargetReport]], None]


def discover(
    lease: ScopeLease,
    conn: Connector,
    ceiling: list[ScopeEntry],
    submit: Submit,
) -> dict[str, Any]:
    """Run the task; stream finished target reports through `submit` in bounded batches and
    return the summary fields (without the final reports, which the caller appends)."""
    started = _now()
    refused: list[RefusedProbe] = []
    ports = sorted(set(lease.ports))
    probes = 0
    batches = 0
    pending: list[TargetReport] = []
    pending_open = 0

    def flush(force: bool = False) -> None:
        nonlocal pending, pending_open, batches
        if pending and (force or pending_open >= BATCH_OPEN_PORTS or len(pending) >= 200):
            submit(pending)
            batches += 1
            pending, pending_open = [], 0

    def emit(t: Tally) -> None:
        nonlocal pending_open
        chunks = [t.open[i : i + BATCH_OPEN_PORTS] for i in range(0, len(t.open), BATCH_OPEN_PORTS)]
        for i, chunk in enumerate(chunks or [[]]):
            first = i == 0
            report = t.report.model_copy(
                update={
                    "part": i,
                    "open": chunk,
                    "addresses": t.report.addresses if first else [],
                    "responding": sorted(t.responding, key=IPv4Address) if first else [],
                    "closed": t.closed if first else 0,
                    "filtered": t.filtered if first else 0,
                    "refused": t.refused[:200] if first else [],
                    "dns": t.report.dns if first else None,
                }
            )
            if pending_open + len(chunk) > BATCH_OPEN_PORTS:
                flush(force=True)
            pending.append(report)
            pending_open += len(chunk)
            flush()

    workers = lease.limits.max_concurrency
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="probe") as pool:
        for target, raw, addresses, resolved, dns in _expand(lease, ceiling, refused):
            if conn.stop.is_set():
                break
            kind = target.kind.value
            tally = Tally(TargetReport(target=raw, kind=kind, dns=dns, addresses=addresses))
            server_name = target.value if target.network is None else None
            inflight: Inflight = {}

            for address in addresses:
                p = Probe(target, address, resolved, server_name)
                for port in ports:
                    if conn.stop.is_set():
                        break
                    while len(inflight) >= workers * 2:
                        done, _ = wait(inflight, return_when=FIRST_COMPLETED)
                        _collect(done, inflight, tally)
                    inflight[pool.submit(probe_port, conn, p, port)] = (address, port)
                    probes += 1
            while inflight:
                done, _ = wait(inflight, return_when=FIRST_COMPLETED)
                _collect(done, inflight, tally)
            tally.open.sort(key=lambda o: (IPv4Address(o.address), o.port))
            emit(tally)
    flush(force=True)
    stopped = None
    if conn.stop.is_set():
        stopped = conn.stop_reason or "stopped"
    return {
        "scanner_version": __version__,
        "started_at": started,
        "finished_at": _now(),
        "ports": len(ports),
        "probes": probes,
        "connections": conn.connections,
        "batches": batches,
        "stopped": stopped,
        "refused": [r.model_dump() for r in refused],
    }
