# ruff: noqa: S608  -- queries join constant SQL fragments; every user value is a bound parameter
"""Findings and remediation (M7/M8).

`evaluate` turns each open service's latest evidence into check outcomes (`checks.run`) and
keeps one deduplicated finding per (service, check). It runs in the transaction that ingests a
discovery scan, and again when intelligence changes (`reassess`), so KEV and EPSS updates reach
existing findings without a new scan.

Lifecycle (PRD §13, Amendment A3): open -> triaged -> in_remediation -> fix_claimed ->
resolved. Only a scan can resolve: the same check ran on the same service and reported the
condition absent. A closed port, a timeout or a check that could not run never resolves a
finding; the finding is marked "not observed since" instead. Manual closure is
`closed_unverified`; `false_positive` and `risk_accepted` need a reason, and risk acceptance an
expiry date and owner/administrator approval. A resolved finding detected again is reopened.
"""

import csv
import io
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import Connection, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.expression import bindparam

from vulnex import audit, checks, intel, risk
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import client_ip, current_principal, engine_of, require
from vulnex_worker_protocol.discovery import OpenPort

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

Status = Literal[
    "open",
    "triaged",
    "in_remediation",
    "fix_claimed",
    "resolved",
    "risk_accepted",
    "false_positive",
    "closed_unverified",
]
ACTIVE = ("open", "triaged", "in_remediation", "fix_claimed")
CLOSED_BY_SCAN = ("resolved", "closed_unverified")  # detected again -> reopened
SUPPRESSED = ("false_positive", "risk_accepted")  # detected again -> stays, history records it
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "probable", "potential", "unknown"]
Band = Literal["urgent", "high", "medium", "low"]
MAX_ACCEPTANCE = timedelta(days=366)


# ---- evaluation ----


class _Intel:
    """Per-run caches over the intel tables."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn
        self._matches: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def matches(self, vendor: str, product: str) -> list[dict[str, Any]]:
        key = (vendor, product)
        if key not in self._matches:
            self._matches[key] = [
                dict(r)
                for r in self.conn.execute(
                    text("SELECT * FROM intel.cve_match WHERE vendor = :v AND product = :p"),
                    {"v": vendor, "p": product},
                ).mappings()
            ]
        return self._matches[key]

    def details(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        return intel.cve_details(self.conn, ids)


def _event(
    conn: Connection,
    finding_id: uuid.UUID,
    kind: str,
    *,
    actor: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        text(
            "INSERT INTO app.finding_event (tenant_id, finding_id, kind, actor_id, scan_id, "
            "detail) "
            "VALUES (app.current_tenant(), :f, :k, :a, :s, :d)"
        ).bindparams(bindparam("d", type_=JSONB)),
        {"f": finding_id, "k": kind, "a": actor, "s": scan_id, "d": detail or {}},
    )


_UPSERT_FIELDS = (
    "title",
    "category",
    "severity",
    "severity_score",
    "severity_source",
    "confidence",
    "cves",
    "kev",
    "epss",
    "explanation",
    "remediation",
    "evidence_ids",
    "detail",
    "risk_score",
    "risk_band",
    "risk_model",
    "risk_factors",
    "check_version",
)


def _values(o: checks.Outcome, svc: Mapping[Any, Any], criticality: str) -> dict[str, Any]:
    r = risk.score(
        severity=o.severity_score,
        severity_source=o.severity_source,
        kev=o.kev,
        epss=o.epss,
        address=svc["address"],
        criticality=criticality,
    )
    return {
        "title": o.title[:300],
        "category": o.category,
        "severity": checks.severity_label(o.severity_score),
        "severity_score": round(o.severity_score, 1),
        "severity_source": o.severity_source[:100],
        "confidence": o.confidence,
        "cves": o.cves,
        "kev": o.kev,
        "epss": o.epss,
        "explanation": o.explanation[:4000],
        "remediation": o.remediation[:4000],
        "evidence_ids": [svc["last_evidence_id"]] if svc["last_evidence_id"] else [],
        "detail": o.detail,
        "risk_score": r["score"],
        "risk_band": r["band"],
        "risk_model": r["model"],
        "risk_factors": r,
        "check_version": checks.CHECKS_VERSION,
    }


def _expire_acceptances(conn: Connection) -> None:
    expired = (
        conn.execute(
            text(
                "UPDATE app.finding SET status = 'open', accepted_until = NULL, "
                "status_changed_at = now(), updated_at = now() "
                "WHERE tenant_id = app.current_tenant() AND status = 'risk_accepted' "
                "AND accepted_until < current_date RETURNING id"
            )
        )
        .scalars()
        .all()
    )
    for fid in expired:
        _event(
            conn,
            fid,
            "status_changed",
            detail={"from": "risk_accepted", "to": "open", "reason": "risk acceptance expired"},
        )


def evaluate(
    conn: Connection, *, asset_ids: list[uuid.UUID] | None = None, scan_id: uuid.UUID | None = None
) -> dict[str, int]:
    """Re-run the checks on services of `asset_ids` (all assets when None). With `scan_id`, the
    evaluation is a fresh observation and may verify fixes; without it (intelligence changed),
    it only updates findings and never resolves one."""
    _expire_acceptances(conn)
    cache = _Intel(conn)
    counts = {"new": 0, "updated": 0, "resolved": 0, "reopened": 0}
    services = (
        conn.execute(
            text(
                "SELECT s.id, s.asset_id, host(s.address) AS address, s.port, s.state, s.name, "
                "s.product, s.version, s.detail, s.fingerprint_method, s.last_evidence_id, "
                "s.last_scan_id, a.criticality, e.data AS evidence, e.observed_at "
                "FROM app.service s JOIN app.asset a ON a.tenant_id = s.tenant_id AND a.id = "
                "s.asset_id "
                "LEFT JOIN app.evidence e ON e.tenant_id = s.tenant_id AND e.id = "
                "s.last_evidence_id "
                "WHERE s.tenant_id = app.current_tenant() "
                "AND (CAST(:assets AS uuid[]) IS NULL OR s.asset_id = ANY(CAST(:assets AS uuid[])))"
            ),
            {"assets": asset_ids},
        )
        .mappings()
        .all()
    )
    for svc in services:
        existing = {
            r["check_id"]: dict(r)
            for r in conn.execute(
                text(
                    "SELECT id, check_id, status, risk_score, cves, kev FROM app.finding "
                    "WHERE tenant_id = app.current_tenant() AND service_id = :s FOR UPDATE"
                ),
                {"s": svc["id"]},
            ).mappings()
        }
        fresh = scan_id is not None and svc["last_scan_id"] == scan_id
        if svc["state"] != "open" or svc["evidence"] is None:
            if fresh:  # the port closed in this scan: cannot verify anything (PRD §13)
                for prior in existing.values():
                    if prior["status"] in ACTIVE:
                        conn.execute(
                            text(
                                "UPDATE app.finding SET not_observed_since = "
                                "coalesce(not_observed_since, now()), updated_at = now() WHERE "
                                "id = :f"
                            ),
                            {"f": prior["id"]},
                        )
                        _event(
                            conn,
                            prior["id"],
                            "verification_inconclusive",
                            scan_id=scan_id,
                            detail={"reason": "port closed or filtered; the check could not run"},
                        )
            continue
        obs = OpenPort.model_validate(svc["evidence"])
        service = checks.Service(
            address=svc["address"],
            port=svc["port"],
            name=svc["name"],
            product=svc["product"],
            version=svc["version"],
            detail=dict(svc["detail"] or {}),
            method=svc["fingerprint_method"],
        )
        outcomes = checks.run(service, obs, svc["observed_at"], cache.matches, cache.details)
        ran = {o.check_id for o in outcomes}
        for o in outcomes:
            f = existing.get(o.check_id)
            if o.state == "affected":
                values = _values(o, svc, svc["criticality"])
                if f is None:
                    fid = conn.execute(
                        text(
                            "INSERT INTO app.finding (tenant_id, asset_id, service_id, address, "
                            "port, "
                            "check_id, dedupe_key, first_seen_at, last_seen_at, last_scan_id, "
                            + ", ".join(_UPSERT_FIELDS)
                            + ") VALUES (app.current_tenant(), :asset, :service, CAST(:address "
                            "AS inet), "
                            ":port, :check, :key, :seen, :seen, :scan, "
                            + ", ".join(f":{k}" for k in _UPSERT_FIELDS)
                            + ") RETURNING id"
                        ).bindparams(
                            bindparam("detail", type_=JSONB), bindparam("risk_factors", type_=JSONB)
                        ),
                        values
                        | {
                            "asset": svc["asset_id"],
                            "service": svc["id"],
                            "address": svc["address"],
                            "port": svc["port"],
                            "check": o.check_id,
                            "key": f"{svc['id']}:{o.check_id}",
                            "seen": svc["observed_at"],
                            "scan": svc["last_scan_id"],
                        },
                    ).scalar_one()
                    _event(
                        conn,
                        fid,
                        "detected",
                        scan_id=scan_id,
                        detail={"risk_score": values["risk_score"], "confidence": o.confidence},
                    )
                    counts["new"] += 1
                    continue
                reopen = fresh and f["status"] in CLOSED_BY_SCAN
                conn.execute(
                    text(
                        "UPDATE app.finding SET "
                        + ", ".join(f"{k} = :{k}" for k in _UPSERT_FIELDS)
                        + ", updated_at = now()"
                        + (
                            ", last_seen_at = :seen, last_scan_id = :scan, not_observed_since = "
                            "NULL"
                            if fresh
                            else ""
                        )
                        + (
                            ", status = 'open', resolved_at = NULL, resolved_by_scan_id = NULL, "
                            "reopen_count = reopen_count + 1, status_changed_at = now()"
                            if reopen
                            else ""
                        )
                        + " WHERE id = :id"
                    ).bindparams(
                        bindparam("detail", type_=JSONB), bindparam("risk_factors", type_=JSONB)
                    ),
                    values
                    | {"id": f["id"], "seen": svc["observed_at"], "scan": svc["last_scan_id"]},
                )
                counts["updated"] += 1
                if reopen:
                    _event(
                        conn,
                        f["id"],
                        "reopened",
                        scan_id=scan_id,
                        detail={"from": f["status"], "reason": "the condition was detected again"},
                    )
                    counts["reopened"] += 1
                elif fresh:
                    _event(
                        conn, f["id"], "observed", scan_id=scan_id, detail={"status": f["status"]}
                    )
                if (f["risk_score"], sorted(f["cves"]), f["kev"]) != (
                    values["risk_score"],
                    sorted(values["cves"]),
                    values["kev"],
                ):
                    _event(
                        conn,
                        f["id"],
                        "reassessed",
                        scan_id=scan_id,
                        detail={
                            "risk_score": [f["risk_score"], values["risk_score"]],
                            "kev": [f["kev"], values["kev"]],
                            "cves_added": sorted(set(values["cves"]) - set(f["cves"])),
                            "cves_removed": sorted(set(f["cves"]) - set(values["cves"])),
                        },
                    )
            elif f is not None and f["status"] not in ("resolved", "false_positive"):
                if fresh:  # the same check ran on the same service: condition absent
                    conn.execute(
                        text(
                            "UPDATE app.finding SET status = 'resolved', resolved_at = now(), "
                            "resolved_by_scan_id = :scan, status_changed_at = now(), "
                            "not_observed_since = NULL, updated_at = now() WHERE id = :id"
                        ),
                        {"id": f["id"], "scan": scan_id},
                    )
                    _event(
                        conn,
                        f["id"],
                        "verification_passed",
                        scan_id=scan_id,
                        detail={"from": f["status"], "check": o.check_id},
                    )
                    counts["resolved"] += 1
                else:
                    _event(
                        conn,
                        f["id"],
                        "reassessed",
                        detail={
                            "note": "no longer matches current intelligence; a scan must verify"
                        },
                    )
        if fresh:
            for check_id, prior in existing.items():
                if check_id not in ran and prior["status"] in ACTIVE:
                    conn.execute(
                        text(
                            "UPDATE app.finding SET not_observed_since = "
                            "coalesce(not_observed_since, now()), updated_at = now() WHERE id = :f"
                        ),
                        {"f": prior["id"]},
                    )
                    _event(
                        conn,
                        prior["id"],
                        "verification_inconclusive",
                        scan_id=scan_id,
                        detail={"reason": "the check could not run on the latest evidence"},
                    )
    return counts


# ---- API models ----


class FindingOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_target: str
    asset_name: str
    asset_criticality: str
    service_id: uuid.UUID | None
    address: str | None
    port: int | None
    service_name: str | None
    check_id: str
    check_version: str
    title: str
    category: str
    severity: Severity
    severity_score: float
    severity_source: str
    confidence: Confidence
    status: Status
    cves: list[str]
    kev: bool
    epss: float | None
    risk_score: int
    risk_band: Band
    risk_model: str
    first_seen_at: datetime
    last_seen_at: datetime
    not_observed_since: datetime | None
    resolved_at: datetime | None
    assignee_id: uuid.UUID | None
    assignee_email: str | None
    due_date: date | None
    overdue: bool
    accepted_until: date | None
    status_reason: str | None
    reopen_count: int


class FindingDetail(FindingOut):
    explanation: str
    remediation: str
    detail: dict[str, Any]
    risk_factors: dict[str, Any]
    evidence: list[dict[str, Any]]
    events: list[dict[str, Any]]
    intel: list[dict[str, Any]]
    last_scan_id: uuid.UUID | None
    resolved_by_scan_id: uuid.UUID | None


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int


class FindingPatch(BaseModel):
    status: Status | None = None
    reason: str | None = Field(default=None, max_length=1000)
    assignee_id: uuid.UUID | None = None
    unassign: bool = False
    due_date: date | None = None
    accepted_until: date | None = None


class CommentIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


Viewer = Annotated[Principal, Depends(current_principal)]


def _scope(principal: Principal) -> tuple[str, dict[str, Any]]:
    """Who may see which findings: everything with findings.read, otherwise only findings
    assigned to the caller (remediation contributors), otherwise nothing (403)."""
    if principal.can(Permission.FINDINGS_READ):
        return "", {}
    if principal.can(Permission.FINDINGS_WORK):
        return "AND f.assignee_id = :me ", {"me": principal.user_id}
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")


_FROM = (
    "FROM app.finding f JOIN app.asset a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id "
    "LEFT JOIN app.service s ON s.tenant_id = f.tenant_id AND s.id = f.service_id "
    "WHERE f.tenant_id = app.current_tenant() "
)
_COLUMNS = (
    "SELECT f.*, host(f.address) AS address, a.target AS asset_target, a.name AS asset_name, "
    "a.criticality AS asset_criticality, s.name AS service_name, "
    "coalesce(f.due_date < current_date "
    "AND f.status IN ('open','triaged','in_remediation','fix_claimed'), false)"
    " AS overdue "
)


def _filters(
    status_: Sequence[str] | None,
    severity: Sequence[str] | None,
    confidence: Sequence[str] | None,
    band: Sequence[str] | None,
    asset_id: uuid.UUID | None,
    assignee: str | None,
    kev: bool | None,
    q: str | None,
    principal: Principal,
) -> tuple[str, dict[str, Any]]:
    where, params = _scope(principal)
    if status_:
        expanded = [s for v in status_ for s in (ACTIVE if v == "active" else (v,))]
        where += "AND f.status = ANY(:status) "
        params["status"] = expanded
    if severity:
        where += "AND f.severity = ANY(:severity) "
        params["severity"] = severity
    if confidence:
        where += "AND f.confidence = ANY(:confidence) "
        params["confidence"] = confidence
    if band:
        where += "AND f.risk_band = ANY(:band) "
        params["band"] = band
    if asset_id:
        where += "AND f.asset_id = :asset "
        params["asset"] = asset_id
    if assignee == "me":
        where += "AND f.assignee_id = :assignee "
        params["assignee"] = principal.user_id
    elif assignee == "none":
        where += "AND f.assignee_id IS NULL "
    if kev is not None:
        where += "AND f.kev = :kev "
        params["kev"] = kev
    if q:
        where += (
            "AND (f.title ILIKE '%' || :q || '%' OR :qu = ANY(f.cves) "
            "OR host(f.address) = :q OR a.target ILIKE '%' || :q || '%') "
        )
        params["q"] = q
        params["qu"] = q.upper()
    return where, params


def _emails(conn: Connection) -> dict[uuid.UUID, str]:
    return {r.user_id: r.email for r in conn.execute(text("SELECT * FROM auth.tenant_members()"))}


def _out(row: dict[str, Any], emails: dict[uuid.UUID, str]) -> dict[str, Any]:
    return row | {"assignee_email": emails.get(row["assignee_id"]) if row["assignee_id"] else None}


ListParams = Annotated[list[str] | None, Query()]


@router.get("")
def list_findings(
    request: Request,
    principal: Viewer,
    status_: Annotated[list[Literal[Status, "active"]] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    confidence: Annotated[list[Confidence] | None, Query()] = None,
    band: Annotated[list[Band] | None, Query()] = None,
    asset_id: uuid.UUID | None = None,
    assignee: Literal["me", "none"] | None = None,
    kev: bool | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    sort: Literal["risk", "severity", "newest", "oldest", "due"] = "risk",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> FindingPage:
    """Findings, highest priority first. `status=active` means open, triaged, in remediation
    or fix claimed."""
    where, params = _filters(
        status_, severity, confidence, band, asset_id, assignee, kev, q or None, principal
    )
    order = {
        "risk": "f.risk_score DESC, f.severity_score DESC, f.last_seen_at DESC",
        "severity": "f.severity_score DESC, f.risk_score DESC",
        "newest": "f.first_seen_at DESC",
        "oldest": "f.first_seen_at ASC",
        "due": "f.due_date ASC NULLS LAST, f.risk_score DESC",
    }[sort]
    with tenant_tx(engine_of(request), principal) as conn:
        total = conn.execute(text("SELECT count(*) " + _FROM + where), params).scalar_one()
        rows = conn.execute(
            text(_COLUMNS + _FROM + where + f"ORDER BY {order}, f.id LIMIT :limit OFFSET :offset"),
            params | {"limit": limit, "offset": offset},
        ).mappings()
        emails = _emails(conn)
        return FindingPage(
            items=[FindingOut.model_validate(_out(dict(r), emails)) for r in rows], total=total
        )


@router.get("/summary")
def summary(request: Request, principal: Viewer) -> dict[str, Any]:
    """Counts for the overview, computed from stored findings only."""
    where, params = _scope(principal)
    active = "AND f.status IN ('open','triaged','in_remediation','fix_claimed') "
    with tenant_tx(engine_of(request), principal) as conn:

        def grouped(column: str, extra: str = active) -> dict[str, int]:
            return {
                str(k): int(v)
                for k, v in conn.execute(
                    text(
                        f"SELECT {column}, count(*) " + _FROM + where + extra + f"GROUP BY {column}"
                    ),
                    params,
                ).all()
            }

        groups = {
            "by_severity": grouped("f.severity"),
            "by_band": grouped("f.risk_band"),
            "by_confidence": grouped("f.confidence"),
            "by_status": grouped("f.status", ""),
        }
        one = (
            conn.execute(
                text(
                    "SELECT count(*) FILTER (WHERE f.kev) AS kev, "
                    "count(*) FILTER (WHERE f.due_date < current_date) AS overdue, "
                    "count(*) FILTER (WHERE f.assignee_id IS NULL) AS unassigned, "
                    "count(*) FILTER (WHERE f.not_observed_since IS NOT NULL) AS not_observed, "
                    "count(*) AS active, "
                    "coalesce(avg(extract(epoch FROM now() - f.first_seen_at) / 86400), 0) AS "
                    "mean_age " + _FROM + where + active
                ),
                params,
            )
            .mappings()
            .one()
        )
        flow = (
            conn.execute(
                text(
                    "SELECT count(*) FILTER (WHERE f.first_seen_at > now() - interval '30 days') "
                    "AS opened_30d, "
                    "count(*) FILTER (WHERE f.resolved_at > now() - interval '30 days') AS "
                    "resolved_30d " + _FROM + where
                ),
                params,
            )
            .mappings()
            .one()
        )
        top_assets = [
            dict(r)
            for r in conn.execute(
                text(
                    "SELECT a.id, a.target, a.name, a.criticality, count(*) AS findings, "
                    "max(f.risk_score) AS max_risk "
                    + _FROM
                    + where
                    + active
                    + "GROUP BY a.id, a.target, a.name, a.criticality "
                    "ORDER BY max(f.risk_score) DESC, count(*) DESC LIMIT 5"
                ),
                params,
            ).mappings()
        ]
        trend = [
            {"day": str(r.day), "opened": int(r.opened), "resolved": int(r.resolved)}
            for r in conn.execute(
                text(
                    "SELECT d::date AS day, "
                    "(SELECT count(*) "
                    + _FROM
                    + where
                    + "AND f.first_seen_at::date = d::date) AS opened, "
                    "(SELECT count(*) "
                    + _FROM
                    + where
                    + "AND f.resolved_at::date = d::date) AS resolved "
                    "FROM generate_series(current_date - 29, current_date, interval '1 day') AS d "
                    "ORDER BY d"
                ),
                params,
            )
        ]
    return {
        **groups,
        "kev": int(one["kev"]),
        "overdue": int(one["overdue"]),
        "unassigned": int(one["unassigned"]),
        "not_observed": int(one["not_observed"]),
        "active": int(one["active"]),
        "mean_age_days": round(float(one["mean_age"]), 1),
        "opened_30d": int(flow["opened_30d"]),
        "resolved_30d": int(flow["resolved_30d"]),
        "top_assets": top_assets,
        "trend_30d": trend,
        "risk_model": risk.MODEL,
    }


@router.get("/export.csv")
def export_csv(
    request: Request,
    principal: Viewer,
    status_: Annotated[list[Literal[Status, "active"]] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    confidence: Annotated[list[Confidence] | None, Query()] = None,
    asset_id: uuid.UUID | None = None,
) -> Response:
    """CSV of the filtered findings (at most 10,000 rows), for spreadsheets and ticketing."""
    where, params = _filters(
        status_, severity, confidence, None, asset_id, None, None, None, principal
    )
    with tenant_tx(engine_of(request), principal) as conn:
        rows = (
            conn.execute(
                text(_COLUMNS + _FROM + where + "ORDER BY f.risk_score DESC, f.id LIMIT 10000"),
                params,
            )
            .mappings()
            .all()
        )
        emails = _emails(conn)
        audit.record(
            conn, principal, "findings.exported", ip=client_ip(request), detail={"rows": len(rows)}
        )
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = [
        "id",
        "risk_score",
        "risk_band",
        "severity",
        "severity_score",
        "confidence",
        "status",
        "title",
        "cves",
        "kev",
        "epss",
        "asset_target",
        "asset_name",
        "address",
        "port",
        "first_seen_at",
        "last_seen_at",
        "assignee_email",
        "due_date",
        "check_id",
    ]
    w.writerow(cols)
    for r in rows:
        d = _out(dict(r), emails)
        d["cves"] = " ".join(d["cves"])
        # Neutralise spreadsheet formula injection (OWASP CSV injection).
        w.writerow(
            [
                "'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r" else v
                for v in (d[c] for c in cols)
            ]
        )
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="vulnex-findings.csv"'},
    )


def _get(
    conn: Connection, finding_id: uuid.UUID, principal: Principal, *, lock: bool = False
) -> dict[str, Any]:
    where, params = _scope(principal)
    row = (
        conn.execute(
            text(
                _COLUMNS + _FROM + where + "AND f.id = :id" + (" FOR UPDATE OF f" if lock else "")
            ),
            params | {"id": finding_id},
        )
        .mappings()
        .first()
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return dict(row)


def _detail(conn: Connection, row: dict[str, Any]) -> FindingDetail:
    evidence = [
        dict(r)
        for r in conn.execute(
            text(
                "SELECT id, scan_id, kind, host(address) AS address, port, data, observed_at, "
                "scanner_version FROM app.evidence WHERE tenant_id = app.current_tenant() "
                "AND id = ANY(:ids)"
            ),
            {"ids": row["evidence_ids"]},
        ).mappings()
    ]
    emails = _emails(conn)
    events = [
        dict(r) | {"actor_email": emails.get(r["actor_id"]) if r["actor_id"] else None}
        for r in conn.execute(
            text(
                "SELECT id, at, actor_id, kind, scan_id, detail FROM app.finding_event "
                "WHERE tenant_id = app.current_tenant() AND finding_id = :f ORDER BY at DESC, id "
                "DESC "
                "LIMIT 200"
            ),
            {"f": row["id"]},
        ).mappings()
    ]
    details = intel.cve_details(conn, list(row["cves"]))
    intel_rows = [
        {
            k: (float(v) if k in ("cvss_score", "epss", "epss_percentile") and v is not None else v)
            for k, v in details[c].items()
        }
        for c in row["cves"]
        if c in details
    ]
    return FindingDetail.model_validate(
        _out(row, emails) | {"evidence": evidence, "events": events, "intel": intel_rows}
    )


@router.get("/{finding_id}")
def get_finding(finding_id: uuid.UUID, request: Request, principal: Viewer) -> FindingDetail:
    with tenant_tx(engine_of(request), principal) as conn:
        return _detail(conn, _get(conn, finding_id, principal))


_WORKER_STATUSES = {"in_remediation", "fix_claimed"}


@router.patch("/{finding_id}")
def update_finding(
    finding_id: uuid.UUID, body: FindingPatch, request: Request, principal: Viewer
) -> FindingDetail:
    """Change status, assignment or due date. `resolved` is set only by a verifying scan."""
    triage = principal.can(Permission.FINDINGS_TRIAGE)
    with tenant_tx(engine_of(request), principal) as conn:
        row = _get(conn, finding_id, principal, lock=True)
        changes: dict[str, Any] = {}
        events: list[tuple[str, dict[str, Any]]] = []
        if body.status is not None and body.status != row["status"]:
            new = body.status
            if new == "resolved":
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT,
                    "Only a scan that no longer detects the condition can resolve a finding; "
                    "use fix_claimed to request verification or closed_unverified to close it "
                    "without verification",
                )
            if not triage and not (
                principal.can(Permission.FINDINGS_WORK) and new in _WORKER_STATUSES
            ):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
            if new in ("false_positive", "risk_accepted", "closed_unverified") and not body.reason:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, f"A reason is required for {new}"
                )
            if new == "risk_accepted":
                if not principal.can(Permission.FINDINGS_ACCEPT):
                    raise HTTPException(
                        status.HTTP_403_FORBIDDEN,
                        "Risk acceptance needs an owner or administrator",
                    )
                today = datetime.now(UTC).date()
                if body.accepted_until is None or not (
                    today < body.accepted_until <= today + MAX_ACCEPTANCE
                ):
                    raise HTTPException(
                        status.HTTP_422_UNPROCESSABLE_CONTENT,
                        "Risk acceptance needs an expiry date within the next year",
                    )
                changes["accepted_until"] = body.accepted_until
            else:
                changes["accepted_until"] = None
            if row["status"] == "resolved":
                changes["resolved_at"] = None
                changes["resolved_by_scan_id"] = None
            changes["status"] = new
            changes["status_reason"] = body.reason
            events.append(
                ("status_changed", {"from": row["status"], "to": new, "reason": body.reason})
            )
        if body.assignee_id is not None or body.unassign:
            if not triage:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
            target = None if body.unassign else body.assignee_id
            if target is not None and target not in _emails(conn):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "Assignee is not a member"
                )
            if target != row["assignee_id"]:
                changes["assignee_id"] = target
                events.append(
                    (
                        "assigned",
                        {
                            "from": str(row["assignee_id"]) if row["assignee_id"] else None,
                            "to": str(target) if target else None,
                        },
                    )
                )
        if "due_date" in body.model_fields_set:
            if not triage:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
            if body.due_date != row["due_date"]:
                changes["due_date"] = body.due_date
                events.append(
                    ("assigned", {"due_date": str(body.due_date) if body.due_date else None})
                )
        if changes:
            sets = ", ".join(f"{k} = :{k}" for k in changes)
            extra = ", status_changed_at = now()" if "status" in changes else ""
            conn.execute(
                text(f"UPDATE app.finding SET {sets}{extra}, updated_at = now() WHERE id = :id"),
                changes | {"id": finding_id},
            )
            for kind, detail in events:
                _event(conn, finding_id, kind, actor=principal.user_id, detail=detail)
            audit.record(
                conn,
                principal,
                "finding.updated",
                target_type="finding",
                target_id=str(finding_id),
                ip=client_ip(request),
                detail={k: str(v) if v is not None else None for k, v in changes.items()},
            )
        return _detail(conn, _get(conn, finding_id, principal))


@router.post("/{finding_id}/comments", status_code=status.HTTP_201_CREATED)
def comment(
    finding_id: uuid.UUID, body: CommentIn, request: Request, principal: Viewer
) -> FindingDetail:
    if not (principal.can(Permission.FINDINGS_TRIAGE) or principal.can(Permission.FINDINGS_WORK)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
    with tenant_tx(engine_of(request), principal) as conn:
        _get(conn, finding_id, principal)
        _event(conn, finding_id, "comment", actor=principal.user_id, detail={"text": body.text})
        return _detail(conn, _get(conn, finding_id, principal))


@router.post("/reassess")
def reassess(
    request: Request, principal: Annotated[Principal, Depends(require(Permission.FINDINGS_TRIAGE))]
) -> dict[str, int]:
    """Re-run the checks on stored evidence against current intelligence (no scan, so nothing
    is resolved). Runs automatically after each intelligence sync."""
    with tenant_tx(engine_of(request), principal) as conn:
        counts = evaluate(conn)
        audit.record(conn, principal, "findings.reassessed", ip=client_ip(request), detail=counts)
    return counts
