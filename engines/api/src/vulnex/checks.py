"""Deterministic checks (M7): turn one service's evidence into check outcomes.

Each check returns an `Outcome` with a state:

- `affected`: the condition was found; it becomes (or keeps) a finding;
- `not_affected`: the check ran and the condition is absent; this is what verifies a fix;
- no outcome at all: the check could not run (no TLS handshake, version unknown, ...). That is
  never treated as a fix (PRD §13: disappearance, timeouts and missing data cannot resolve).

Confidence follows PRD Amendment A1 and founder decision D3:

- `confirmed` only when the condition itself was observed (an expired certificate, a TLS 1.0
  handshake that succeeded, a Redis PING answered without credentials);
- a CVE matched from a remotely observed version is at most `potential`: distributions
  backport fixes without changing the upstream version, so a version string alone never
  confirms anything.

Scores for configuration checks are VULNEX's own documented values (CVSS-like 0-10 scale, see
`SEVERITY_NOTES`); CVE findings use the published CVSS score from NVD.
"""

import operator
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from vulnex.fingerprint import CPE, compare, version_key
from vulnex_worker_protocol.discovery import OpenPort

CHECKS_VERSION = "checks-2026.11.1"
EXPIRY_WARNING = timedelta(days=30)
DATABASES = {
    "mysql",
    "postgresql",
    "mongodb",
    "mssql",
    "oracle",
    "elasticsearch",
    "couchdb",
    "redis",
    "memcached",
}


@dataclass
class Outcome:
    check_id: str
    state: str  # "affected" | "not_affected"
    title: str = ""
    category: str = "misconfiguration"
    severity_score: float = 0.0
    severity_source: str = ""
    confidence: str = "confirmed"
    explanation: str = ""
    remediation: str = ""
    cves: list[str] = field(default_factory=list)
    kev: bool = False
    epss: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def severity_label(score: float) -> str:
    """CVSS v3 qualitative rating; 0 is informational."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


@dataclass
class Service:
    address: str
    port: int
    name: str | None
    product: str | None
    version: str | None
    detail: dict[str, Any]
    method: str | None


Matches = Callable[[str, str], list[dict[str, Any]]]
Details = Callable[[list[str]], dict[str, dict[str, Any]]]


def _own(score: float, why: str) -> tuple[float, str]:
    return score, f"VULNEX check score {score}: {why}"


def _tls_checks(obs: OpenPort, observed: datetime) -> list[Outcome]:
    tls = obs.tls
    if tls is None:
        return []
    out: list[Outcome] = []
    where = f"{obs.address}:{obs.port}"
    cert = tls.certificate
    if cert is not None:
        not_after = datetime.fromisoformat(cert.not_after)
        expired = not_after < observed
        s, src = _own(
            5.3, "clients cannot validate the server; invites certificate warnings to be ignored"
        )
        out.append(
            Outcome(
                "tls.certificate.expired",
                "affected" if expired else "not_affected",
                title="TLS certificate has expired",
                severity_score=s,
                severity_source=src,
                explanation=(
                    f"The certificate presented on {where} ({cert.subject}) expired on "
                    f"{not_after:%Y-%m-%d}; observed {observed:%Y-%m-%d %H:%M} UTC."
                ),
                remediation="Install a valid certificate from a trusted CA and automate renewal.",
                detail={
                    "not_after": cert.not_after,
                    "subject": cert.subject,
                    "sha256": cert.sha256,
                },
            )
        )
        soon = not expired and not_after - observed < EXPIRY_WARNING
        s, src = _own(3.1, "service disruption when the certificate expires")
        out.append(
            Outcome(
                "tls.certificate.expiring",
                "affected" if soon else "not_affected",
                title="TLS certificate expires within 30 days",
                severity_score=s,
                severity_source=src,
                explanation=f"The certificate on {where} expires on {not_after:%Y-%m-%d}.",
                remediation="Renew the certificate before it expires; automate renewal.",
                detail={"not_after": cert.not_after},
            )
        )
        s, src = _own(5.3, "clients cannot authenticate the server, enabling interception")
        out.append(
            Outcome(
                "tls.certificate.self_signed",
                "affected" if cert.self_signed else "not_affected",
                title="TLS certificate is self-signed",
                severity_score=s,
                severity_source=src,
                explanation=(
                    f"The certificate on {where} is issued by its own subject ({cert.issuer}); "
                    "no certificate authority vouches for it."
                ),
                remediation="Use a certificate issued by a CA your clients trust.",
                detail={"issuer": cert.issuer, "subject": cert.subject},
            )
        )
        weak = (
            (cert.key_type == "RSA" and (cert.key_bits or 0) < 2048)
            or (cert.key_type == "DSA")
            or (cert.key_type == "EC" and (cert.key_bits or 0) < 224)
        )
        if cert.key_type:
            s, src = _own(5.3, "keys below current minimums can be factored or forged")
            out.append(
                Outcome(
                    "tls.certificate.weak_key",
                    "affected" if weak else "not_affected",
                    title="TLS certificate uses a weak key",
                    severity_score=s,
                    severity_source=src,
                    explanation=f"The certificate key is {cert.key_type} {cert.key_bits} bits.",
                    remediation="Reissue the certificate with RSA 2048+ or ECDSA P-256+.",
                    detail={"key_type": cert.key_type, "key_bits": cert.key_bits},
                )
            )
        if tls.server_name:
            names = [n.lower() for n in cert.dns_names]
            host = tls.server_name.lower()
            ok = host in names or any(
                n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count(".")
                for n in names
            )
            s, src = _own(5.3, "clients reject or must ignore the hostname mismatch")
            out.append(
                Outcome(
                    "tls.certificate.name_mismatch",
                    "not_affected" if ok else "affected",
                    title="TLS certificate does not match the hostname",
                    severity_score=s,
                    severity_source=src,
                    explanation=(
                        f"The certificate on {where} does not list {tls.server_name} "
                        f"(names: {', '.join(names) or 'none'})."
                    ),
                    remediation=(
                        "Issue a certificate whose subject alternative names include the hostname."
                    ),
                    detail={"server_name": tls.server_name, "dns_names": names},
                )
            )
    tested = {k: v for k, v in tls.protocols.items() if k in ("TLSv1", "TLSv1.1")}
    if tested:
        legacy = sorted(k for k, v in tested.items() if v)
        s, src = _own(6.5, "TLS 1.0/1.1 are deprecated (RFC 8996) and lack modern protections")
        out.append(
            Outcome(
                "tls.protocol.legacy",
                "affected" if legacy else "not_affected",
                title="Deprecated TLS protocol versions accepted",
                severity_score=s,
                severity_source=src,
                explanation=(
                    f"{where} completed a handshake with {', '.join(legacy)}."
                    if legacy
                    else f"{where} refused TLS 1.0 and 1.1."
                ),
                remediation="Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.",
                detail={"protocols": dict(tls.protocols)},
            )
        )
    return out


def _service_checks(svc: Service, obs: OpenPort) -> list[Outcome]:
    out: list[Outcome] = []
    where = f"{svc.address}:{svc.port}"
    banner = obs.banner or ""
    if svc.name == "ssh" and svc.method == "banner":
        proto = str(svc.detail.get("protocol", ""))
        v1 = proto.startswith("1.") and proto != "1.99"
        s, src = _own(7.4, "SSH protocol 1 has known cryptographic weaknesses")
        out.append(
            Outcome(
                "ssh.protocol.v1",
                "affected" if v1 else "not_affected",
                title="SSH server supports only protocol version 1",
                severity_score=s,
                severity_source=src,
                explanation=f"{where} announced SSH protocol {proto}.",
                remediation="Upgrade the SSH server and disable protocol 1.",
                detail={"protocol": proto},
            )
        )
    if svc.name == "telnet":
        s, src = _own(6.5, "credentials and sessions travel in cleartext")
        iac = obs.banner_b64 is not None and banner.startswith("\\xff")
        out.append(
            Outcome(
                "service.cleartext.telnet",
                "affected",
                title="Telnet service exposed",
                category="exposure",
                severity_score=s,
                severity_source=src,
                confidence="confirmed" if iac else "probable",
                explanation=f"{where} accepts connections on the Telnet port"
                + (" and sent Telnet option negotiation." if iac else "."),
                remediation="Disable Telnet; use SSH.",
            )
        )
    if svc.name == "ftp" and svc.method == "banner":
        greeting = (banner.splitlines() or [""])[0][:120]
        s, src = _own(4.0, "FTP sends credentials in cleartext unless explicit TLS is enforced")
        out.append(
            Outcome(
                "service.cleartext.ftp",
                "affected",
                title="FTP service exposed",
                category="exposure",
                severity_score=s,
                severity_source=src,
                confidence="probable",
                explanation=f"{where} answered with an FTP greeting: {greeting!r}. "
                "Whether it enforces TLS was not tested.",
                remediation="Replace FTP with SFTP, or require FTPS (explicit TLS) for logins.",
            )
        )
    if svc.name == "redis" and "auth_required" in svc.detail:
        open_ = svc.detail["auth_required"] is False
        s, src = _own(
            9.0,
            "anyone who can reach it can read and change all data; often leads to code execution",
        )
        out.append(
            Outcome(
                "redis.no_auth",
                "affected" if open_ else "not_affected",
                title="Redis accepts commands without authentication",
                category="exposure",
                severity_score=s,
                severity_source=src,
                explanation=f"{where} answered PING with PONG without credentials."
                if open_
                else f"{where} requires authentication (NOAUTH).",
                remediation="Require authentication (requirepass or ACLs), bind to trusted "
                "interfaces only, and keep protected-mode on.",
                detail={"reply": (obs.probe_reply or "")[:80]},
            )
        )
    if svc.name == "memcached" and svc.detail.get("auth_required") is False:
        s, src = _own(7.5, "cached data can be read and changed without credentials")
        out.append(
            Outcome(
                "memcached.no_auth",
                "affected",
                title="Memcached accepts commands without authentication",
                category="exposure",
                severity_score=s,
                severity_source=src,
                explanation=f"{where} answered the version command without credentials.",
                remediation="Bind memcached to localhost or a private interface and enable SASL.",
            )
        )
    if svc.name in DATABASES and svc.name not in ("redis", "memcached"):
        s, src = _own(5.3, "database listeners should not be reachable outside application tiers")
        out.append(
            Outcome(
                "service.database.exposed",
                "affected",
                title=f"Database service reachable ({svc.product or svc.name})",
                category="exposure",
                severity_score=s,
                severity_source=src,
                confidence="probable" if svc.method != "port" else "potential",
                explanation=f"{where} accepted a TCP connection"
                + (f" and identified as {svc.product}." if svc.product else " on a database port."),
                remediation=(
                    "Restrict the listener to application hosts with a firewall or bind address."
                ),
            )
        )
    headers = {k.lower(): v for k, v in (obs.http.headers if obs.http else [])}
    docker = "api-version" in headers or headers.get("server", "").startswith("Docker/")
    if docker or (svc.port == 2375 and obs.tls is None):
        s, src = _own(9.8, "the Docker API without TLS gives root-equivalent control of the host")
        out.append(
            Outcome(
                "docker.api.exposed",
                "affected",
                title="Docker Engine API exposed without TLS",
                category="exposure",
                severity_score=s,
                severity_source=src,
                confidence="confirmed" if docker else "potential",
                explanation=f"{where} "
                + (
                    "answered with Docker API headers."
                    if docker
                    else "accepts connections on the Docker API port."
                ),
                remediation="Do not expose the Docker socket over TCP; if required, use TLS client "
                "authentication (port 2376) and a firewall.",
            )
        )
    return out


def _in_range(version: str, m: dict[str, Any]) -> bool:
    if m["version"]:
        return compare(version, m["version"]) == 0
    bounds = (
        (m["start_including"], operator.ge),
        (m["start_excluding"], operator.gt),
        (m["end_including"], operator.le),
        (m["end_excluding"], operator.lt),
    )
    if not any(b for b, _ in bounds):
        return False  # "any version" matches are too broad to report from a banner
    return all(ok(compare(version, b), 0) for b, ok in bounds if b)


def _cve_check(svc: Service, matches: Matches, details: Details) -> list[Outcome]:
    if not (svc.product and svc.version and svc.product in CPE):
        return []
    hits: dict[str, list[dict[str, Any]]] = {}
    skipped: set[str] = set()
    for vendor, product in CPE[svc.product]:
        for m in matches(vendor, product):
            if not _in_range(svc.version, m):
                continue
            if m["conditional"]:
                skipped.add(m["cve_id"])
                continue
            hits.setdefault(m["cve_id"], []).append(m)
    skipped -= set(hits)
    where = f"{svc.address}:{svc.port}"
    if not hits:
        return [
            Outcome("cve.version_match", "not_affected", detail={"not_evaluated": sorted(skipped)})
        ]
    info = details(sorted(hits))
    cves = []
    for cve_id in sorted(hits, key=lambda c: -(float(info.get(c, {}).get("cvss_score") or 0))):
        d = info.get(cve_id, {})
        m = hits[cve_id][0]
        cves.append(
            {
                "id": cve_id,
                "cvss": float(d["cvss_score"]) if d.get("cvss_score") is not None else None,
                "cvss_version": d.get("cvss_version"),
                "severity": d.get("cvss_severity"),
                "kev": bool(d.get("kev")),
                "epss": float(d["epss"]) if d.get("epss") is not None else None,
                "affected": _describe(m),
                "fixed_from": m["end_excluding"],
            }
        )
    top = cves[0]
    noun = "vulnerability" if len(cves) == 1 else "vulnerabilities"
    scored = [c for c in cves if c["cvss"] is not None]
    severity = max((c["cvss"] for c in scored), default=None)
    source = (
        f"CVSS {top['cvss_version']} base score of {top['id']} (NVD)"
        if severity is not None
        else ""
    )
    fixes = [c["fixed_from"] for c in cves if c["fixed_from"]]
    upgrade = max(fixes, key=version_key) if fixes else None
    distro = svc.detail.get("distribution")
    caveat = (
        f"The banner names a distribution build ({distro}"
        + (
            f", package revision {svc.detail['package_revision']}"
            if svc.detail.get("package_revision")
            else ""
        )
        + "), which may include backported fixes without a version change."
        if distro
        else "Vendors and distributions can backport fixes without changing the version."
    )
    return [
        Outcome(
            "cve.version_match",
            "affected",
            title=f"{svc.product} {svc.version}: {len(cves)} known {noun} by version",
            category="vulnerability",
            severity_score=severity if severity is not None else 5.0,
            severity_source=source or "no CVSS published (provisional 5.0)",
            confidence="potential",
            explanation=(
                f"{where} reports {svc.product} {svc.version} ({svc.method}). NVD lists "
                f"{len(cves)} CVE(s) whose affected range includes this version. This is a "
                f"version correlation, not a test of the flaw: {caveat} Classified POTENTIAL "
                "until package-level evidence (authenticated inventory, M2) confirms it."
            ),
            remediation=(
                f"Upgrade {svc.product} to {upgrade} or later"
                if upgrade
                else f"Upgrade {svc.product} to a release not affected by the listed CVEs"
            )
            + ", or confirm with the distribution's security tracker that the installed package "
            "contains the fixes.",
            cves=[c["id"] for c in cves],
            kev=any(c["kev"] for c in cves),
            epss=max((c["epss"] for c in cves if c["epss"] is not None), default=None),
            detail={
                "product": svc.product,
                "version": svc.version,
                "method": svc.method,
                "cves": cves,
                "not_evaluated": sorted(skipped),
                "upgrade_to": upgrade,
            },
        )
    ]


def _describe(m: dict[str, Any]) -> str:
    if m["version"]:
        return f"= {m['version']}"
    parts = []
    if m["start_including"]:
        parts.append(f">= {m['start_including']}")
    if m["start_excluding"]:
        parts.append(f"> {m['start_excluding']}")
    if m["end_including"]:
        parts.append(f"<= {m['end_including']}")
    if m["end_excluding"]:
        parts.append(f"< {m['end_excluding']}")
    return ", ".join(parts)


def run(
    svc: Service, obs: OpenPort, observed: datetime, matches: Matches, details: Details
) -> list[Outcome]:
    """All outcomes for one open service, from its latest evidence."""
    return [
        *_tls_checks(obs, observed),
        *_service_checks(svc, obs),
        *_cve_check(svc, matches, details),
    ]
