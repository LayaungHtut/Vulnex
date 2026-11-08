"""Ingest `network.discover` results (M5) into evidence and the service inventory.

Runs inside the worker API transaction that completes the task, so a scan is never "completed"
without its results. The worker's observations are checked again here (TM-3-3: a worker can lie
about its own tenant, but it must not write outside the scan it was given): every report must
name a target of this scan, and every address must belong to that target (inside its range, or
among the addresses its name resolved to). Anything else is dropped and counted.
"""

import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from sqlalchemy import Connection, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.expression import bindparam

from vulnex.fingerprint import RULES_VERSION, identify
from vulnex_worker_protocol.discovery import DiscoveryBatch, DiscoverySummary, TargetReport

log = logging.getLogger("vulnex.discovery")

# Ports probed when a discovery scan names none: common services and frequent exposures.
DEFAULT_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 636,
    873, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3306, 3389, 4369, 5000,
    5432, 5601, 5672, 5900, 5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9200, 9300, 9443, 10250, 11211, 15672, 27017,
})  # fmt: skip


def _ts(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


_EVIDENCE = text(
    "INSERT INTO app.evidence (tenant_id, scan_id, asset_id, kind, address, port, data, "
    "observed_at, scanner_version, worker_id) VALUES (app.current_tenant(), :scan, :asset, "
    ":kind, CAST(:address AS inet), :port, :data, :at, :sv, :worker) RETURNING id"
).bindparams(bindparam("data", type_=JSONB))

_SERVICE = text(
    "INSERT INTO app.service (tenant_id, asset_id, address, port, state, name, product, version, "
    "tls, detail, fingerprint_method, rules_version, first_seen_at, last_seen_at, last_scan_id, "
    "last_evidence_id) VALUES (app.current_tenant(), :asset, CAST(:address AS inet), :port, "
    "'open', :name, :product, :version, :tls, :detail, :method, :rules, :at, :at, :scan, :ev) "
    "ON CONFLICT (tenant_id, asset_id, address, port, transport) DO UPDATE SET state = 'open', "
    "closed_at = NULL, name = EXCLUDED.name, product = EXCLUDED.product, "
    "version = EXCLUDED.version, tls = EXCLUDED.tls, detail = EXCLUDED.detail, "
    "fingerprint_method = EXCLUDED.fingerprint_method, rules_version = EXCLUDED.rules_version, "
    "last_seen_at = greatest(app.service.last_seen_at, EXCLUDED.last_seen_at), "
    "last_scan_id = EXCLUDED.last_scan_id, last_evidence_id = EXCLUDED.last_evidence_id "
    "RETURNING id"
).bindparams(bindparam("detail", type_=JSONB))


def validate(kind: str, payload: dict[str, Any], final: bool, outcome: str | None) -> None:
    """Raise ValueError (pydantic ValidationError) if a discovery submission is malformed."""
    if kind != "network.discover":
        return
    if not final:
        DiscoveryBatch.model_validate(payload)
    elif outcome in ("succeeded", "cancelled"):
        DiscoverySummary.model_validate(payload)


def ingest(
    conn: Connection, *, job_id: uuid.UUID, attempt: int, worker_id: uuid.UUID
) -> uuid.UUID | None:
    """Store the results of a completed discovery attempt. Returns the scan id, or None when
    the job is not a discovery scan."""
    scan = (
        conn.execute(
            text(
                "SELECT id, asset_ids, ports, profile FROM app.scan "
                "WHERE tenant_id = app.current_tenant() AND job_id = :j FOR UPDATE"
            ),
            {"j": job_id},
        )
        .mappings()
        .first()
    )
    if scan is None or scan["profile"] != "discovery":
        return None
    rows = conn.execute(
        text("SELECT seq, final, payload FROM queue.job_attempt_results(:j, :a)"),
        {"j": job_id, "a": attempt},
    ).all()
    finals = [r for r in rows if r.final]
    if not finals:
        return None
    summary = DiscoverySummary.model_validate(finals[-1].payload)
    reports: list[TargetReport] = [
        rep for r in rows if not r.final for rep in DiscoveryBatch.model_validate(r.payload).reports
    ]
    reports += summary.reports

    assets = {
        str(a.target): a
        for a in conn.execute(
            text(
                "SELECT id, kind, target FROM app.asset "
                "WHERE tenant_id = app.current_tenant() AND id = ANY(:ids)"
            ),
            {"ids": scan["asset_ids"]},
        )
    }
    by_target: dict[str, list[TargetReport]] = defaultdict(list)
    for rep in reports:
        by_target[rep.target].append(rep)

    scan_id: uuid.UUID = scan["id"]
    ports = set(scan["ports"])
    complete = summary.stopped is None
    counts = {"open_ports": 0, "services_new": 0, "services_closed": 0, "dropped": 0}
    responding_total: set[str] = set()
    hosts_by_asset: dict[str, dict[str, Any]] = {}

    for target, parts in by_target.items():
        asset = assets.get(target)
        if asset is None:
            counts["dropped"] += sum(len(p.open) for p in parts) or 1
            log.warning("discovery report for a target outside the scan dropped")
            continue
        parts.sort(key=lambda p: p.part)
        head = parts[0]
        dns_answers: set[str] = set()
        if asset.kind == "hostname":
            raw_a = (head.dns or {}).get("a")
            dns_answers = {str(a) for a in raw_a} if isinstance(raw_a, list) else set()
        network = IPv4Network(str(asset.target)) if asset.kind != "hostname" else None

        def belongs(address: str, network: IPv4Network | None = network,
                    answers: set[str] = dns_answers) -> bool:  # fmt: skip
            try:
                addr = IPv4Address(address)
            except ValueError:
                return False
            return addr in network if network is not None else address in answers

        if head.dns is not None:
            conn.execute(
                _EVIDENCE,
                {
                    "scan": scan_id,
                    "asset": asset.id,
                    "kind": "dns",
                    "address": None,
                    "port": None,
                    "data": head.dns,
                    "at": _ts(str(head.dns.get("resolved_at", ""))),
                    "sv": summary.scanner_version,
                    "worker": worker_id,
                },
            )
        probed = {a for a in head.addresses if belongs(a)}
        responding = {a for a in head.responding if belongs(a)}
        responding_total |= responding
        refused = {(r.address, r.port) for p in parts for r in p.refused if r.address}
        seen_open: set[tuple[str, int]] = set()
        for part in parts:
            for obs in part.open:
                if not belongs(obs.address) or obs.port not in ports:
                    counts["dropped"] += 1
                    continue
                seen_open.add((obs.address, obs.port))
                at = _ts(obs.observed_at)
                evidence_id = conn.execute(
                    _EVIDENCE,
                    {
                        "scan": scan_id,
                        "asset": asset.id,
                        "kind": "service",
                        "address": obs.address,
                        "port": obs.port,
                        "data": obs.model_dump(mode="json"),
                        "at": at,
                        "sv": summary.scanner_version,
                        "worker": worker_id,
                    },
                ).scalar_one()
                fp = identify(obs)
                existed = conn.execute(
                    text(
                        "SELECT 1 FROM app.service WHERE tenant_id = app.current_tenant() "
                        "AND asset_id = :a AND address = CAST(:addr AS inet) AND port = :p "
                        "AND state = 'open'"
                    ),
                    {"a": asset.id, "addr": obs.address, "p": obs.port},
                ).first()
                conn.execute(
                    _SERVICE,
                    {
                        "asset": asset.id,
                        "address": obs.address,
                        "port": obs.port,
                        "name": fp.name,
                        "product": fp.product,
                        "version": fp.version,
                        "tls": fp.tls,
                        "detail": fp.detail,
                        "method": fp.method,
                        "rules": RULES_VERSION,
                        "at": at,
                        "scan": scan_id,
                        "ev": evidence_id,
                    },
                )
                counts["open_ports"] += 1
                counts["services_new"] += existed is None

        if complete:
            # A port this scan probed and found not open is closed now (unless it was refused).
            for svc in conn.execute(
                text(
                    "SELECT id, host(address) AS address, port FROM app.service "
                    "WHERE tenant_id = app.current_tenant() AND asset_id = :a AND state = 'open'"
                ),
                {"a": asset.id},
            ):
                key = (svc.address, svc.port)
                if (
                    svc.address in probed
                    and svc.port in ports
                    and key not in seen_open
                    and key not in refused
                ):
                    conn.execute(
                        text(
                            "UPDATE app.service SET state = 'closed', closed_at = now(), "
                            "last_scan_id = :s WHERE id = :id"
                        ),
                        {"s": scan_id, "id": svc.id},
                    )
                    counts["services_closed"] += 1
        if responding:
            conn.execute(
                text(
                    "UPDATE app.asset SET first_seen_at = coalesce(first_seen_at, now()), "
                    "last_seen_at = now() WHERE tenant_id = app.current_tenant() AND id = :a"
                ),
                {"a": asset.id},
            )
        hosts_by_asset[str(asset.id)] = {
            "probed": len(probed),
            "responding": len(responding),
            "open_ports": len(seen_open),
            "closed": sum(p.closed for p in parts),
            "filtered": sum(p.filtered for p in parts),
            "refused": len(refused),
        }

    record = {
        **counts,
        "hosts_probed": sum(h["probed"] for h in hosts_by_asset.values()),
        "hosts_responding": len(responding_total),
        "assets": hosts_by_asset,
        "probes": summary.probes,
        "ports": summary.ports,
        "stopped": summary.stopped,
        "refused_targets": [r.reason for r in summary.refused][:100],
        "scanner_version": summary.scanner_version,
        "started_at": summary.started_at,
        "finished_at": summary.finished_at,
    }
    conn.execute(
        text("UPDATE app.scan SET summary = :s, ingested_at = now() WHERE id = :id").bindparams(
            bindparam("s", type_=JSONB)
        ),
        {"s": record, "id": scan_id},
    )
    return scan_id
