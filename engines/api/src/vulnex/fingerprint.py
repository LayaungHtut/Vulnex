"""Service fingerprinting (M5): name the product and version behind an open port, from the raw
observation a worker submitted. Deterministic, versioned rules; no network access.

Every result says how it was reached (`method`): a protocol banner, an HTTP `Server` header, a
TLS handshake, or only the port number (`port`, the weakest). A version read from a banner is a
*claim by the service*: it can be hidden, faked, or (on Linux distributions) carry security
backports without changing. Correlation (M7) treats it accordingly and never as confirmation.
"""

import base64
import re
from dataclasses import dataclass, field
from typing import Any

from vulnex_worker_protocol.discovery import OpenPort

RULES_VERSION = "fp-2026.11.1"

WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "rsh", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1883: "mqtt", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 4369: "epmd", 5000: "http-alt", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch", 10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb",
}  # fmt: skip

# Product name -> NVD CPE (vendor, product) pairs used for correlation (M6/M7).
CPE = {
    "OpenSSH": [("openbsd", "openssh")],
    "Dropbear SSH": [("dropbear_ssh_project", "dropbear_ssh")],
    "Apache httpd": [("apache", "http_server")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "Microsoft IIS": [("microsoft", "internet_information_services")],
    "vsftpd": [("beasts", "vsftpd")],
    "ProFTPD": [("proftpd", "proftpd")],
    "Pure-FTPd": [("pureftpd", "pure-ftpd")],
    "Exim": [("exim", "exim")],
    "Postfix": [("postfix", "postfix")],
    "MySQL": [("oracle", "mysql")],
    "MariaDB": [("mariadb", "mariadb")],
    "PHP": [("php", "php")],
    "OpenSSL": [("openssl", "openssl")],
    "Apache Tomcat": [("apache", "tomcat")],
    "Redis": [("redis", "redis")],
    "Memcached": [("memcached", "memcached")],
    "Jetty": [("eclipse", "jetty")],
}

DISTROS = ("ubuntu", "debian", "raspbian", "centos", "rhel", "red hat", "fedora", "alpine",
           "suse", "freebsd", "amazon", "rocky", "almalinux", "oracle linux")  # fmt: skip


@dataclass
class Fingerprint:
    name: str | None
    product: str | None = None
    version: str | None = None
    method: str = "port"
    tls: bool = False
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def cpes(self) -> list[tuple[str, str]]:
        return CPE.get(self.product or "", [])


_SSH = re.compile(r"^SSH-(\d+\.\d+)-(\S+)(?:[ \t]+([^\r\n]*))?")
_SSH_SOFTWARE = [
    (re.compile(r"^OpenSSH_([0-9][\w.]*)", re.I), "OpenSSH"),
    (re.compile(r"^dropbear_([0-9][\w.]*)", re.I), "Dropbear SSH"),
]
_FTP = [
    (re.compile(r"\(vsFTPd ([0-9][\w.]*)\)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD ([0-9][\w.]*)", re.I), "ProFTPD"),
    (re.compile(r"Pure-FTPd()", re.I), "Pure-FTPd"),
    (re.compile(r"FileZilla Server ?([0-9][\w.]*)?", re.I), "FileZilla Server"),
]
_SMTP = [
    (re.compile(r"ESMTP Exim ([0-9][\w.]*)", re.I), "Exim"),
    (re.compile(r"ESMTP Postfix()", re.I), "Postfix"),
    (re.compile(r"Microsoft ESMTP MAIL Service()", re.I), "Microsoft Exchange SMTP"),
    (re.compile(r"ESMTP Sendmail ([0-9][\w./]*)", re.I), "Sendmail"),
]
_SERVER = re.compile(r"^([A-Za-z][\w.-]*)(?:/([0-9][\w.+~-]*))?\s*(?:\(([^)]*)\))?")
_SERVER_PRODUCTS = {
    "nginx": "nginx",
    "openresty": "OpenResty",
    "apache": "Apache httpd",
    "microsoft-iis": "Microsoft IIS",
    "lighttpd": "lighttpd",
    "caddy": "Caddy",
    "apache-coyote": "Apache Tomcat",
    "jetty": "Jetty",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "werkzeug": "Werkzeug",
    "envoy": "Envoy",
    "cloudflare": "Cloudflare",
}
_COMPONENT = re.compile(r"\b(OpenSSL|PHP|mod_ssl|Python|Perl)/([0-9][\w.+~-]*)", re.I)


def _distro(text: str) -> str | None:
    low = text.lower()
    return next((d for d in DISTROS if d in low), None)


def _header(headers: list[tuple[str, str]] | list[list[str]], name: str) -> str | None:
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def _ssh(banner: str) -> Fingerprint | None:
    m = _SSH.match(banner)
    if not m:
        return None
    proto, software, comment = m.group(1), m.group(2), (m.group(3) or "").strip()
    fp = Fingerprint("ssh", method="banner", detail={"protocol": proto, "software": software})
    for rx, product in _SSH_SOFTWARE:
        if sm := rx.match(software):
            fp.product, fp.version = product, sm.group(1)
            break
    else:
        fp.product = software.split("_")[0][:100]
    if comment:
        fp.detail["comment"] = comment[:200]
        if d := _distro(comment):
            fp.detail["distribution"] = d
            # Debian/Ubuntu append the package revision: "Ubuntu-3ubuntu13.5", "Debian-2+deb12u3"
            if rm := re.search(r"-(\S+)$", comment):
                fp.detail["package_revision"] = rm.group(1)
    return fp


def _mysql(raw: bytes) -> Fingerprint | None:
    # Protocol 10 handshake: 3-byte length, sequence 0, then 0x0a and a NUL-terminated version.
    if len(raw) < 10 or raw[3] != 0 or raw[4] != 0x0A:
        return None
    end = raw.find(b"\x00", 5)
    if end == -1:
        return None
    version = raw[5:end].decode("ascii", "replace")
    if m := re.search(r"([0-9][\w.]*)-MariaDB", version):
        fp = Fingerprint("mysql", "MariaDB", m.group(1).removeprefix("5.5.5-"), "banner")
    else:
        v = re.match(r"[0-9][\w.]*", version)
        fp = Fingerprint("mysql", "MySQL", v.group(0) if v else None, "banner")
    fp.detail["server_version"] = version[:100]
    if d := _distro(version):
        fp.detail["distribution"] = d
    return fp


def _from_rules(banner: str, rules: list[tuple[re.Pattern[str], str]], name: str) -> Fingerprint:
    fp = Fingerprint(name, method="banner", detail={"greeting": banner.splitlines()[0][:200]})
    for rx, product in rules:
        if m := rx.search(banner):
            fp.product = product
            fp.version = (m.group(1) or None) if m.groups() else None
            break
    if d := _distro(banner):
        fp.detail["distribution"] = d
    return fp


def _http(obs: OpenPort) -> Fingerprint | None:
    http = obs.http
    if http is None:
        return None
    tls = http.scheme == "https"
    fp = Fingerprint("https" if tls else "http", method="http", tls=tls)
    fp.detail["status"] = http.status
    if http.title:
        fp.detail["title"] = http.title
    server = _header(http.headers, "server")
    powered = _header(http.headers, "x-powered-by")
    if server:
        fp.detail["server"] = server[:200]
        if m := _SERVER.match(server):
            key = m.group(1).lower()
            fp.product = _SERVER_PRODUCTS.get(key, m.group(1)[:100])
            fp.version = m.group(2)
            fp.method = "http-server-header"
            if m.group(3) and (d := _distro(m.group(3))):
                fp.detail["distribution"] = d
    components = {}
    for text in filter(None, (server, powered)):
        for cm in _COMPONENT.finditer(text):
            name = {"openssl": "OpenSSL", "php": "PHP"}.get(cm.group(1).lower(), cm.group(1))
            components[name] = cm.group(2)
    if components:
        fp.detail["components"] = components
    if powered:
        fp.detail["x_powered_by"] = powered[:200]
    return fp


def _probe(obs: OpenPort) -> Fingerprint | None:
    reply = obs.probe_reply or ""
    if obs.probe == "redis-ping":
        fp = Fingerprint("redis", "Redis", method="probe")
        fp.detail["auth_required"] = not reply.startswith("+PONG")
        if m := re.search(r"redis_version:([0-9][\w.]*)", reply):
            fp.version = m.group(1)
        if m := re.search(r"os:([^\r\n]+)", reply):
            fp.detail["os"] = m.group(1)[:100]
        return fp
    if obs.probe == "memcached-version" and (m := re.match(r"VERSION ([0-9][\w.]*)", reply)):
        fp = Fingerprint("memcached", "Memcached", m.group(1), "probe")
        fp.detail["auth_required"] = False  # the text protocol answered without SASL
        return fp
    return None


def identify(obs: OpenPort) -> Fingerprint:
    """The best-supported identification for one open port."""
    banner = obs.banner or ""
    raw = base64.b64decode(obs.banner_b64) if obs.banner_b64 else b""
    fp: Fingerprint | None = _probe(obs) if obs.probe_reply else None
    if fp is not None:
        pass
    elif banner.startswith("SSH-"):
        fp = _ssh(banner)
    elif raw and (fp := _mysql(raw)):
        pass
    elif banner.startswith("220"):
        low = banner.lower()
        if "ftp" in low or obs.port in (21, 2121):
            fp = _from_rules(banner, _FTP, "ftp")
        elif "smtp" in low or obs.port in (25, 465, 587):
            fp = _from_rules(banner, _SMTP, "smtp")
    elif banner.startswith("+OK"):
        fp = Fingerprint("pop3", method="banner", detail={"greeting": banner[:200].strip()})
    elif banner.startswith("* OK"):
        fp = Fingerprint("imap", method="banner", detail={"greeting": banner[:200].strip()})
    if fp is None:
        fp = _http(obs)
    if fp is None and obs.tls is not None:
        fp = Fingerprint(f"{WELL_KNOWN.get(obs.port, 'unknown')}/tls", method="tls", tls=True)
    if fp is None:
        fp = Fingerprint(WELL_KNOWN.get(obs.port), method="port")
        if banner:
            fp.detail["banner"] = banner[:200]
    fp.tls = fp.tls or obs.tls is not None
    return fp


# ---- version comparison (used by correlation) ----

_TOKEN = re.compile(r"\d+|[a-z]+")


def version_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """Order upstream version strings: 8.9p1 < 9.3 < 9.3p2 < 9.10; 1.24.0 < 1.25.3.

    Numbers compare numerically; a letter suffix sorts after the bare number ("9.3p1" > "9.3")
    but before the next number ("9.3p1" < "9.3.1"); pre-release markers (alpha, beta, rc) sort
    before the bare number ("9.3rc1" < "9.3").
    """
    out: list[tuple[int, int, str]] = []
    for tok in _TOKEN.findall(version.lower()):
        if tok.isdigit():
            out.append((2, int(tok), ""))
        elif tok in ("a", "alpha", "b", "beta", "rc", "pre", "dev"):
            out.append((1, 0, tok))
        else:
            out.append((2, 0, tok))
    return tuple(out)


def compare(a: str, b: str) -> int:
    """-1, 0 or 1. Missing trailing parts count as zero, so "9.3" == "9.3.0"."""
    ka, kb = version_key(a), version_key(b)
    width = max(len(ka), len(kb))
    ka += ((2, 0, ""),) * (width - len(ka))
    kb += ((2, 0, ""),) * (width - len(kb))
    return (ka > kb) - (ka < kb)
