"""M5 destination validation (ADR-0006 §5 "Required tests") and a live discovery run against
throwaway local services (synthetic test fixtures, bound to this host's own address)."""

import contextlib
import socket
import socketserver
import ssl
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vulnex_scanner import discover as discover_mod
from vulnex_scanner.connector import Connector, Refused, Resolution, embedded_ipv4
from vulnex_scanner.discover import discover
from vulnex_worker_protocol.discovery import TargetReport
from vulnex_worker_protocol.lease import LeaseScopeEntry, Limits, ScopeLease
from vulnex_worker_protocol.targets import Kind, ScopeEntry, Target, parse_scope_entry, scope_digest


def make_lease(
    targets: list[str], scope: list[ScopeEntry], ports: list[int], timeout: int = 60
) -> ScopeLease:
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
        kind="network.discover",
        targets=targets,
        scope=[LeaseScopeEntry(kind=e.kind.value, value=e.value, exclude=e.exclude) for e in scope],
        scope_digest=scope_digest(scope),
        ports=ports,
        limits=Limits(
            max_addresses=4096, task_timeout_s=timeout, probe_timeout_s=1, max_concurrency=4
        ),
    )


SCOPE = [
    parse_scope_entry("10.20.0.0/16", exclude=False),
    parse_scope_entry("10.20.5.0/24", exclude=True),
    parse_scope_entry("app.lab.example", exclude=False),
]
NET = Target(Kind.CIDR, "10.20.0.0/16")
HOST = Target(Kind.HOSTNAME, "app.lab.example")


@pytest.fixture
def conn() -> Connector:
    return Connector(make_lease(["10.20.0.0/16"], SCOPE, [22, 443]))


@pytest.mark.parametrize(
    ("target", "address", "port", "resolved", "reason"),
    [
        (NET, "10.20.1.1", 22, None, None),
        (NET, "127.0.0.1", 22, None, "never scanned"),
        (NET, "169.254.169.254", 443, None, "never scanned"),
        (NET, "2130706433", 22, None, "not an IP address"),
        (NET, "0x7f.1", 22, None, "not an IP address"),
        (NET, "127.1", 22, None, "not an IP address"),
        (NET, "::ffff:127.0.0.1", 22, None, "IPv6"),
        (NET, "10.20.1.1", 8080, None, "not in the signed lease"),
        (NET, "10.20.5.9", 22, None, "excluded"),
        (NET, "10.21.0.1", 22, None, "not part of target"),
        # Hostname answers must be the ones resolved at task start, and inside a CIDR entry.
        (HOST, "10.20.1.1", 22, ["10.20.1.1"], None),
        (HOST, "10.20.1.2", 22, ["10.20.1.1"], "not an address app.lab.example resolved to"),
        (HOST, "192.168.1.10", 22, ["192.168.1.10"], "not inside any included range"),
        (HOST, "127.0.0.1", 22, ["127.0.0.1"], "never scanned"),  # rebinding to loopback
    ],
)
def test_destination_fixtures(
    conn: Connector,
    target: Target,
    address: str,
    port: int,
    resolved: list[str] | None,
    reason: str | None,
) -> None:
    if reason is None:
        conn.check(target, address, port, resolved)
    else:
        with pytest.raises(Refused, match=reason):
            conn.check(target, address, port, resolved)


def test_own_and_control_plane_addresses_are_refused() -> None:
    c = Connector(
        make_lease(["10.20.0.0/16"], SCOPE, [22]), deny=frozenset({IPv4Address("10.20.0.2")})
    )
    with pytest.raises(Refused, match="this worker or its control plane"):
        c.check(NET, "10.20.0.2", 22, None)


def test_local_ceiling_narrower_than_the_lease() -> None:
    ceiling = [parse_scope_entry("10.20.1.0/24", exclude=False)]
    c = Connector(make_lease(["10.20.0.0/16"], SCOPE, [22]), ceiling=ceiling)
    c.check(NET, "10.20.1.5", 22, None)
    with pytest.raises(Refused, match="ceiling"):
        c.check(NET, "10.20.2.5", 22, None)


def test_stop_and_deadline_end_all_connections(conn: Connector) -> None:
    conn.stop.set()
    with pytest.raises(Refused, match="stopped"):
        conn.check(NET, "10.20.1.1", 22, None)
    late = Connector(make_lease(["10.20.0.0/16"], SCOPE, [22]), clock=lambda: 10.0**9, deadline=1.0)
    with pytest.raises(Refused, match="time limit"):
        late.check(NET, "10.20.1.1", 22, None)


@pytest.mark.parametrize(
    ("v6", "v4"),
    [
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("64:ff9b::a9fe:a9fe", "169.254.169.254"),
        ("2002:7f00:1::", "127.0.0.1"),
        ("::7f00:1", "127.0.0.1"),
        ("2001:db8::1", None),
    ],
)
def test_ipv6_transition_forms_reveal_the_embedded_ipv4(v6: str, v4: str | None) -> None:
    found = embedded_ipv4(IPv6Address(v6))
    assert (str(found) if found else None) == v4


def test_dns_evidence_reports_ipv6_as_a_coverage_gap() -> None:
    ev = Resolution("a.example", None, ["10.20.1.1"], ["::ffff:7f00:1"], None, "t").evidence()
    assert "IPv6 address observed" in ev["coverage_gap"]
    assert ev["aaaa_embedded_ipv4"] == {"::ffff:7f00:1": "127.0.0.1"}


def test_only_the_connector_opens_sockets() -> None:
    """ADR-0006 §5: one network path. Other scanner modules must not import socket or ssl
    (discover.py imports ssl only for version constants and exception types)."""
    src = Path(discover_mod.__file__).parent
    for path in src.glob("*.py"):
        text = path.read_text()
        if path.name == "connector.py":
            continue
        assert "import socket" not in text, path.name
        assert "create_connection" not in text and "wrap_socket" not in text, path.name


# ---- live run against local fixtures ----


def own_address() -> str | None:
    """This host's primary IPv4 address (no packet is sent: UDP connect only picks a route)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))
        except OSError:
            return None
        addr: str = s.getsockname()[0]
    return None if addr.startswith("127.") else addr


def expired_cert(tmp: Path, host: str) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab-expired.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now - timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("lab-expired.test")]), False)
        .sign(key, hashes.SHA256())
    )
    crt, pem = tmp / "c.pem", tmp / "k.pem"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return crt, pem


HTTP_OK = (
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n"
    b"Connection: close\r\n\r\n<html><title>Lab admin</title></html>"
)
HTTP_REDIRECT = (
    b"HTTP/1.1 301 Moved Permanently\r\nLocation: http://169.254.169.254/latest/\r\n"
    b"Connection: close\r\n\r\n"
)


class Lab:
    def __init__(self, host: str, tmp: Path) -> None:
        self.host = host
        self.servers: list[socketserver.ThreadingTCPServer] = []
        crt, key = expired_cert(tmp, host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.ssh = self._serve(lambda s: s.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"))
        self.https = self._serve(lambda s: self._https(s, ctx))
        self.redirect = self._serve(lambda s: self._http(s, HTTP_REDIRECT))
        with socket.socket() as probe:
            probe.bind((host, 0))
            self.closed = probe.getsockname()[1]

    def _serve(self, handle: Any) -> int:
        class H(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                with contextlib.suppress(OSError, ssl.SSLError):
                    handle(self.request)

        srv = socketserver.ThreadingTCPServer((self.host, 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)
        port: int = srv.server_address[1]
        return port

    @staticmethod
    def _http(sock: socket.socket, response: bytes) -> None:
        sock.settimeout(3)
        if sock.recv(4096).startswith(b"GET "):
            sock.sendall(response)

    @staticmethod
    def _https(sock: socket.socket, ctx: ssl.SSLContext) -> None:
        sock.settimeout(3)
        with ctx.wrap_socket(sock, server_side=True) as t:
            if t.recv(4096).startswith(b"GET "):
                t.sendall(HTTP_OK)

    def close(self) -> None:
        for s in self.servers:
            s.shutdown()
            s.server_close()


@pytest.fixture
def lab(tmp_path: Path) -> Iterator[Lab]:
    host = own_address()
    if host is None:
        pytest.skip("no non-loopback IPv4 address to bind lab services to")
    lab = Lab(host, tmp_path)
    yield lab
    lab.close()


def run(lease: ScopeLease) -> tuple[list[TargetReport], dict[str, Any], Connector]:
    conn = Connector(lease)  # no deny-list: the lab services live on this host on purpose
    reports: list[TargetReport] = []
    summary = discover(lease, conn, [], reports.extend)
    return reports, summary, conn


def test_live_discovery_against_lab_services(lab: Lab) -> None:
    ports = [lab.ssh, lab.https, lab.redirect, lab.closed]
    lease = make_lease([lab.host], [parse_scope_entry(f"{lab.host}/32", exclude=False)], ports)
    started = time.monotonic()
    reports, summary, _ = run(lease)
    assert time.monotonic() - started < 30
    (rep,) = reports
    found = {o.port: o for o in rep.open}
    assert set(found) == {lab.ssh, lab.https, lab.redirect}
    assert rep.closed == 1 and rep.responding == [lab.host]

    assert (found[lab.ssh].banner or "").startswith("SSH-2.0-OpenSSH_9.6p1")
    assert found[lab.ssh].tls is None

    tls = found[lab.https].tls
    assert tls is not None and tls.certificate is not None
    assert tls.certificate.self_signed
    assert datetime.fromisoformat(tls.certificate.not_after) < datetime.now(UTC)
    assert tls.certificate.dns_names == ["lab-expired.test"]
    assert tls.protocols.get("TLSv1.3") is True
    http = found[lab.https].http
    assert http is not None and http.status == 200 and http.title == "Lab admin"
    assert ("Server", "nginx/1.24.0") in http.headers

    redirect = found[lab.redirect].http
    assert redirect is not None and redirect.status == 301
    assert ("Location", "http://169.254.169.254/latest/") in redirect.headers  # recorded only
    assert summary["probes"] == 4 and summary["stopped"] is None


def test_hostname_answers_are_checked_per_address(
    lab: Lab, monkeypatch: pytest.MonkeyPatch
) -> None:
    answers = [lab.host, "10.255.0.1"]

    def fake_resolve(name: str) -> Resolution:
        return Resolution(name, None, answers, [], None, "t")

    monkeypatch.setattr(discover_mod, "resolve", fake_resolve)
    scope = [
        parse_scope_entry("svc.lab.example", exclude=False),
        parse_scope_entry(f"{lab.host}/32", exclude=False),
    ]
    reports, _, _ = run(make_lease(["svc.lab.example"], scope, [lab.ssh]))
    (rep,) = reports
    assert [o.address for o in rep.open] == [lab.host]
    assert [(r.address, "not inside any included range" in r.reason) for r in rep.refused] == [
        ("10.255.0.1", True)
    ]
    assert rep.dns is not None and rep.dns["a"] == answers


def test_cancel_stops_new_connections(lab: Lab) -> None:
    lease = make_lease([lab.host], [parse_scope_entry(f"{lab.host}/32", exclude=False)], [lab.ssh])
    conn = Connector(lease)
    conn.stop.set()
    conn.stop_reason = "cancelled"
    summary = discover(lease, conn, [], lambda _: None)
    assert conn.connections == 0 and summary["stopped"] == "cancelled"
