"""Service fingerprint rules and version ordering (M5)."""

import base64
from typing import Any

import pytest

from vulnex.fingerprint import compare, identify
from vulnex_worker_protocol.discovery import HttpObservation, OpenPort, TlsObservation


def port(n: int, banner: bytes = b"", **extra: Any) -> OpenPort:
    return OpenPort(
        address="10.0.0.5",
        port=n,
        observed_at="2026-11-08T00:00:00+00:00",
        connect_ms=1,
        banner=banner.decode("utf-8", "backslashreplace") or None,
        banner_b64=base64.b64encode(banner).decode() or None,
        **extra,
    )


@pytest.mark.parametrize(
    ("obs", "name", "product", "version"),
    [
        (port(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"), "ssh", "OpenSSH", "9.6p1"),
        (port(2222, b"SSH-2.0-dropbear_2022.83\r\n"), "ssh", "Dropbear SSH", "2022.83"),
        (port(21, b"220 (vsFTPd 3.0.3)\r\n"), "ftp", "vsftpd", "3.0.3"),
        (port(21, b"220 ProFTPD 1.3.8 Server ready.\r\n"), "ftp", "ProFTPD", "1.3.8"),
        (port(25, b"220 mail.example.com ESMTP Exim 4.96 Mon\r\n"), "smtp", "Exim", "4.96"),
        (port(25, b"220 mx.example.com ESMTP Postfix (Debian/GNU)\r\n"), "smtp", "Postfix", None),
        (
            port(3306, b"\x4a\x00\x00\x00\x0a8.0.36\x00\x08\x00\x00\x00abc"),
            "mysql",
            "MySQL",
            "8.0.36",
        ),
        (
            port(3306, b"\x5b\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00rest"),
            "mysql",
            "MariaDB",
            "10.11.6",
        ),
        (port(6379), "redis", None, None),
        (port(40000), None, None, None),
    ],
)
def test_banner_rules(
    obs: OpenPort, name: str | None, product: str | None, version: str | None
) -> None:
    fp = identify(obs)
    assert (fp.name, fp.product, fp.version) == (name, product, version)


def test_ssh_distribution_and_package_revision_are_kept_as_detail() -> None:
    fp = identify(port(22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"))
    assert fp.detail["distribution"] == "ubuntu"
    assert fp.detail["package_revision"] == "3ubuntu0.6"
    assert fp.method == "banner" and fp.cpes == [("openbsd", "openssh")]


def test_http_server_header_and_components() -> None:
    http = HttpObservation(
        scheme="https",
        host_header="10.0.0.5",
        status=200,
        headers=[
            ("Server", "Apache/2.4.57 (Debian) OpenSSL/3.0.11"),
            ("X-Powered-By", "PHP/8.2.7"),
        ],
        title="It works",
        body_bytes=10,
    )
    fp = identify(port(443, http=http, tls=TlsObservation(version="TLSv1.3")))
    assert (fp.name, fp.product, fp.version, fp.tls) == ("https", "Apache httpd", "2.4.57", True)
    assert fp.detail["distribution"] == "debian"
    assert fp.detail["components"] == {"OpenSSL": "3.0.11", "PHP": "8.2.7"}
    assert fp.method == "http-server-header"


def test_silent_tls_port_without_http() -> None:
    fp = identify(port(8883, tls=TlsObservation(version="TLSv1.2")))
    assert fp.name == "unknown/tls" and fp.tls and fp.method == "tls"


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("8.9p1", "9.3", -1),
        ("9.3p1", "9.3", 1),
        ("9.3p1", "9.3.1", -1),
        ("9.10", "9.3", 1),
        ("9.3", "9.3.0", 0),
        ("9.3rc1", "9.3", -1),
        ("1.24.0", "1.25.3", -1),
        ("2.4.58", "2.4.6", 1),
        ("2022.83", "2020.81", 1),
    ],
)
def test_version_ordering(a: str, b: str, expected: int) -> None:
    assert compare(a, b) == expected
    assert compare(b, a) == -expected


def test_redis_probe_reply() -> None:
    open_ = port(
        6379,
        probe="redis-ping",
        probe_reply="+PONG\r\n\n$300\r\n# Server\r\nredis_version:7.4.1\r\nos:Linux 6.6 x86_64\r\n",
    )
    fp = identify(open_)
    assert (fp.name, fp.product, fp.version, fp.method) == ("redis", "Redis", "7.4.1", "probe")
    assert fp.detail["auth_required"] is False
    locked = identify(
        port(6379, probe="redis-ping", probe_reply="-NOAUTH Authentication required.\r\n")
    )
    assert locked.detail["auth_required"] is True and locked.version is None
