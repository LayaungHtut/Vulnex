"""Vulnerability intelligence (M6): CISA KEV, FIRST EPSS and NVD CVE records.

Sync runs as the database owner (`python -m vulnex.cli intel-sync`), never inside the API
process, which only reads `intel.*`. Each source:

- records provenance: source URL, upstream version (KEV catalog version, EPSS model and score
  date), retrieval time and, for CVEs, a SHA-256 of the raw record;
- is all-or-nothing per run: a failed download or parse keeps the last good data and marks the
  source `error` with the reason (PRD INT-04), so stale data is visible, never silently replaced;
- is idempotent: running it twice gives the same rows.

NVD is fetched only for the products the fingerprint rules can name (`fingerprint.CPE`), with
the public rate limit (5 requests per 30 s without an API key, 50 with `VULNEX_NVD_API_KEY`).
Version ranges are stored exactly as published; nothing is inferred (PRD INT-03).

Licensing and attribution (research R3, not yet verified by the founder or counsel): NVD data
requires the notice "This product uses data from the NVD API but is not endorsed or certified
by the NVD."; KEV is published by CISA; EPSS is published by FIRST with attribution requested.
"""

import csv
import gzip
import hashlib
import json
import logging
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import Connection, Engine, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.expression import bindparam

from vulnex import __version__
from vulnex.authz import Permission, Principal
from vulnex.db import tenant_tx
from vulnex.deps import engine_of, require
from vulnex.fingerprint import CPE

log = logging.getLogger("vulnex.intel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."
USER_AGENT = f"VULNEX-intel/{__version__}"
# How old a source may get before the console flags it stale (PRD INT-05: alert after 24 h).
MAX_AGE = {"kev": timedelta(hours=36), "epss": timedelta(hours=36), "nvd": timedelta(days=2)}
NVD_PAGE = 500  # large pages often time out on the NVD side
NVD_MAX_RANGE = timedelta(days=119)  # the API refuses lastMod ranges over 120 days


class IntelError(Exception):
    """A source could not be synced; the message is stored as the source's error."""


# ---- parsing (pure, tested with fixtures) ----


@dataclass
class KevEntry:
    cve_id: str
    vendor_project: str | None
    product: str | None
    name: str | None
    date_added: str | None
    due_date: str | None
    ransomware: str | None
    required_action: str | None
    short_description: str | None
    notes: str | None


def parse_kev(raw: bytes) -> tuple[str, list[KevEntry]]:
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
        version = str(doc["catalogVersion"])
        entries = [
            KevEntry(
                cve_id=str(v["cveID"]).strip().upper(),
                vendor_project=v.get("vendorProject"),
                product=v.get("product"),
                name=v.get("vulnerabilityName"),
                date_added=v.get("dateAdded"),
                due_date=v.get("dueDate"),
                ransomware=v.get("knownRansomwareCampaignUse"),
                required_action=(v.get("requiredAction") or "")[:2000] or None,
                short_description=(v.get("shortDescription") or "")[:2000] or None,
                notes=(v.get("notes") or "")[:2000] or None,
            )
            for v in doc["vulnerabilities"]
        ]
    except (ValueError, KeyError, TypeError) as e:
        raise IntelError(f"KEV feed is not in the expected format: {e}") from None
    if not entries:
        raise IntelError("KEV feed lists no vulnerabilities; keeping the previous catalog")
    return version, entries


@dataclass
class EpssScores:
    model_version: str | None
    score_date: str
    rows: list[tuple[str, float, float]]


def parse_epss(gz: bytes) -> EpssScores:
    try:
        text_ = gzip.decompress(gz).decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise IntelError(f"EPSS file is not gzip CSV: {e}") from None
    lines = text_.splitlines()
    meta: dict[str, str] = {}
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            key, _, value = part.partition(":")
            meta[key.strip()] = value.strip()
        lines = lines[1:]
    reader = csv.DictReader(lines)
    rows = []
    try:
        for r in reader:
            score, pct = float(r["epss"]), float(r["percentile"])
            if not (0 <= score <= 1 and 0 <= pct <= 1):
                raise ValueError("score out of range")
            rows.append((r["cve"].strip().upper(), score, pct))
    except (KeyError, ValueError) as e:
        raise IntelError(f"EPSS file is not in the expected format: {e}") from None
    date = meta.get("score_date", "")[:10]
    if not rows or not date:
        raise IntelError("EPSS file has no scores or no score date")
    return EpssScores(meta.get("model_version"), date, rows)


@dataclass
class Match:
    vendor: str
    product: str
    version: str | None
    start_including: str | None
    start_excluding: str | None
    end_including: str | None
    end_excluding: str | None
    criteria: str
    conditional: bool


@dataclass
class CveRecord:
    id: str
    published: str | None
    last_modified: str | None
    vuln_status: str | None
    description: str
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_severity: str | None
    cvss_source: str | None
    cwes: list[str]
    refs: list[dict[str, Any]]
    raw_sha256: str
    matches: list[Match] = field(default_factory=list)


_METRICS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)


def _cvss(
    metrics: dict[str, Any],
) -> tuple[str | None, float | None, str | None, str | None, str | None]:
    """Prefer CVSS v3.x, then v4.0, then v2; prefer the NVD 'Primary' score within a version.
    The chosen version and source are recorded (PRD §15 source-selection policy)."""
    for key, version in _METRICS:
        items = metrics.get(key) or []
        if not items:
            continue
        items = sorted(items, key=lambda m: m.get("type") != "Primary")
        m = items[0]
        data = m.get("cvssData", {})
        severity = data.get("baseSeverity") or m.get("baseSeverity")
        return version, data.get("baseScore"), data.get("vectorString"), severity, m.get("source")
    return None, None, None, None, None


def _cpe_parts(criteria: str) -> tuple[str, str, str | None] | None:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[2] != "a":
        return None  # applications only; OS and hardware CPEs are not matched remotely
    version = parts[5] if parts[5] not in ("*", "-", "") else None
    update = parts[6] if len(parts) > 6 and parts[6] not in ("*", "-", "") else ""
    # OpenSSH-style CPEs split "8.9p1" into version "8.9" and update "p1".
    return parts[3], parts[4], (version + update) if version else None


def parse_nvd_cve(item: dict[str, Any]) -> CveRecord:
    cve = item["cve"]
    raw = json.dumps(cve, sort_keys=True, separators=(",", ":")).encode()
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    version, score, vector, severity, source = _cvss(cve.get("metrics") or {})
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if str(d.get("value", "")).startswith("CWE-")
        }
    )
    refs = [
        {"url": r["url"], "tags": r.get("tags", [])[:10]}
        for r in cve.get("references", [])[:50]
        if str(r.get("url", "")).startswith(("https://", "http://"))
    ]
    record = CveRecord(
        id=cve["id"],
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        vuln_status=cve.get("vulnStatus"),
        description=desc[:4000],
        cvss_version=version,
        cvss_score=score,
        cvss_vector=vector,
        cvss_severity=severity,
        cvss_source=source,
        cwes=cwes,
        refs=refs,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )
    for config in cve.get("configurations", []):
        nodes = config.get("nodes", [])
        conditional = config.get("operator") == "AND" or len(nodes) > 1
        for node in nodes:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = _cpe_parts(m.get("criteria", ""))
                if parts is None:
                    continue
                vendor, product, exact = parts
                record.matches.append(
                    Match(
                        vendor=vendor,
                        product=product,
                        version=exact,
                        start_including=m.get("versionStartIncluding"),
                        start_excluding=m.get("versionStartExcluding"),
                        end_including=m.get("versionEndIncluding"),
                        end_excluding=m.get("versionEndExcluding"),
                        criteria=m["criteria"][:300],
                        conditional=conditional,
                    )
                )
    return record


# ---- storage ----


def _status(conn: Connection, source: str, **values: Any) -> None:
    sets = ", ".join(f"{k} = :{k}" for k in values)
    stmt = text(f"UPDATE intel.source SET {sets} WHERE name = :name")  # noqa: S608 (keys are ours)
    if "cursor" in values:
        stmt = stmt.bindparams(bindparam("cursor", type_=JSONB))
    conn.execute(stmt, values | {"name": source})


def store_kev(conn: Connection, version: str, entries: list[KevEntry]) -> int:
    conn.execute(text("DELETE FROM intel.kev"))
    conn.execute(
        text(
            "INSERT INTO intel.kev (cve_id, vendor_project, product, name, date_added, due_date, "
            "ransomware, required_action, short_description, notes, catalog_version) VALUES "
            "(:cve_id, :vendor_project, :product, :name, CAST(:date_added AS date), "
            "CAST(:due_date AS date), :ransomware, :required_action, :short_description, :notes, "
            ":v) ON CONFLICT (cve_id) DO NOTHING"
        ),
        [e.__dict__ | {"v": version} for e in entries],
    )
    return len(entries)


def store_epss(conn: Connection, scores: EpssScores) -> int:
    conn.execute(
        text("CREATE TEMP TABLE epss_load (cve_id text, score numeric, pct numeric) ON COMMIT DROP")
    )
    raw = conn.connection.dbapi_connection
    if raw is None:
        raise IntelError("database connection unavailable")
    with raw.cursor() as cur, cur.copy("COPY epss_load FROM STDIN") as copy:  # type: ignore[attr-defined]
        for row in scores.rows:
            copy.write_row(row)
    conn.execute(text("DELETE FROM intel.epss"))
    conn.execute(
        text(
            "INSERT INTO intel.epss (cve_id, score, percentile, score_date, model_version) "
            "SELECT DISTINCT ON (cve_id) cve_id, score, pct, CAST(:d AS date), :m FROM epss_load "
            "ORDER BY cve_id"
        ),
        {"d": scores.score_date, "m": scores.model_version},
    )
    return len(scores.rows)


def store_cves(conn: Connection, records: Iterable[CveRecord]) -> int:
    n = 0
    for r in records:
        conn.execute(
            text(
                "INSERT INTO intel.cve (id, published, last_modified, vuln_status, description, "
                "cvss_version, cvss_score, cvss_vector, cvss_severity, cvss_source, cwes, refs, "
                "raw_sha256, retrieved_at) VALUES (:id, :published, :last_modified, "
                ":vuln_status, :description, :cvss_version, :cvss_score, :cvss_vector, "
                ":cvss_severity, :cvss_source, :cwes, :refs, :raw_sha256, now()) "
                "ON CONFLICT (id) DO UPDATE SET published = EXCLUDED.published, "
                "last_modified = EXCLUDED.last_modified, vuln_status = EXCLUDED.vuln_status, "
                "description = EXCLUDED.description, cvss_version = EXCLUDED.cvss_version, "
                "cvss_score = EXCLUDED.cvss_score, cvss_vector = EXCLUDED.cvss_vector, "
                "cvss_severity = EXCLUDED.cvss_severity, cvss_source = EXCLUDED.cvss_source, "
                "cwes = EXCLUDED.cwes, refs = EXCLUDED.refs, raw_sha256 = EXCLUDED.raw_sha256, "
                "retrieved_at = now()"
            ).bindparams(bindparam("refs", type_=JSONB)),
            {k: v for k, v in r.__dict__.items() if k != "matches"},
        )
        conn.execute(text("DELETE FROM intel.cve_match WHERE cve_id = :id"), {"id": r.id})
        if r.matches:
            conn.execute(
                text(
                    "INSERT INTO intel.cve_match (cve_id, vendor, product, version, "
                    "start_including, start_excluding, end_including, end_excluding, criteria, "
                    "conditional) VALUES (:cve, :vendor, :product, :version, :start_including, "
                    ":start_excluding, :end_including, :end_excluding, :criteria, :conditional)"
                ),
                [m.__dict__ | {"cve": r.id} for m in r.matches],
            )
        n += 1
    return n


# ---- fetching ----


Fetch = Callable[[str, dict[str, Any]], bytes]


def http_fetcher(api_key: str | None = None, timeout: float = 120) -> Fetch:
    client = httpx.Client(
        timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    )

    def fetch(url: str, params: dict[str, Any]) -> bytes:
        headers = {"apiKey": api_key} if api_key and url.startswith(NVD_URL) else {}
        for attempt in range(4):
            try:
                r = client.get(url, params=params, headers=headers)
            except httpx.TimeoutException:
                if attempt == 3:
                    raise IntelError(f"{url} timed out repeatedly") from None
                time.sleep(10 * (attempt + 1))
                continue
            if r.status_code in (403, 429, 502, 503, 504) and attempt < 3:
                time.sleep(10 * (attempt + 1))  # NVD signals rate limiting with 403/429
                continue
            if r.status_code != 200:
                raise IntelError(f"{url} answered {r.status_code}")
            if len(r.content) > 200_000_000:
                raise IntelError(f"{url} returned an implausibly large body")
            return r.content
        raise IntelError(f"{url} kept refusing requests")

    return fetch


def _run(
    engine: Engine,
    source: str,
    work: Callable[[Connection], tuple[int, str | None, dict[str, Any] | None]],
) -> int:
    """Run one source sync in a transaction; record success or keep old data and the error."""
    started = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            records, version, cursor = work(conn)
            values: dict[str, Any] = {
                "status": "ok",
                "last_attempt_at": started,
                "last_success_at": started,
                "records": records,
                "source_version": version,
                "error": None,
            }
            if cursor is not None:
                values["cursor"] = cursor
            _status(conn, source, **values)
    except (IntelError, httpx.HTTPError) as e:
        with engine.begin() as conn:
            _status(conn, source, status="error", last_attempt_at=started, error=str(e)[:1000])
        log.warning("intel sync failed", extra={"fields": {"source": source, "error": str(e)}})
        raise IntelError(str(e)) from None
    log.info("intel sync ok", extra={"fields": {"source": source, "records": records}})
    return records


def sync_kev(engine: Engine, fetch: Fetch) -> int:
    def work(conn: Connection) -> tuple[int, str | None, dict[str, Any] | None]:
        version, entries = parse_kev(fetch(KEV_URL, {}))
        return store_kev(conn, version, entries), version, None

    return _run(engine, "kev", work)


def sync_epss(engine: Engine, fetch: Fetch) -> int:
    def work(conn: Connection) -> tuple[int, str | None, dict[str, Any] | None]:
        scores = parse_epss(fetch(EPSS_URL, {}))
        version = f"{scores.score_date} ({scores.model_version or 'model unknown'})"
        return store_epss(conn, scores), version, None

    return _run(engine, "epss", work)


def _nvd_pages(fetch: Fetch, params: dict[str, Any], pause: float) -> Iterator[dict[str, Any]]:
    start = 0
    while True:
        doc = json.loads(fetch(NVD_URL, params | {"startIndex": start, "resultsPerPage": NVD_PAGE}))
        if doc.get("format") != "NVD_CVE":
            raise IntelError("NVD answered in an unexpected format")
        yield from doc.get("vulnerabilities", [])
        start += int(doc.get("resultsPerPage", 0))
        if start >= int(doc.get("totalResults", 0)) or not doc.get("resultsPerPage"):
            return
        time.sleep(pause)


def sync_nvd(
    engine: Engine,
    fetch: Fetch,
    *,
    api_key: bool = False,
    products: Iterable[tuple[str, str]] | None = None,
) -> int:
    """CVE records for every product the fingerprint rules can name. Incremental per product
    (lastModified window since its last success, at most 119 days back; else a full fetch)."""
    pause = 0.7 if api_key else 6.5
    wanted = sorted(set(products or (p for pairs in CPE.values() for p in pairs)))

    started = datetime.now(UTC)
    total, failed = 0, []
    with engine.begin() as conn:
        cursor: dict[str, Any] = dict(
            conn.execute(text("SELECT cursor FROM intel.source WHERE name = 'nvd'")).scalar_one()
        )
    # One transaction per product: an outage halfway keeps the products already synced, and
    # each product's cursor advances only with its own data.
    for vendor, product in wanted:
        key = f"{vendor}:{product}"
        now = datetime.now(UTC)
        params: dict[str, Any] = {"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}"}
        last = cursor.get(key)
        if last and now - datetime.fromisoformat(last) < NVD_MAX_RANGE:
            since = datetime.fromisoformat(last) - timedelta(hours=1)
            params["lastModStartDate"] = since.isoformat(timespec="milliseconds")
            params["lastModEndDate"] = now.isoformat(timespec="milliseconds")
        try:
            with engine.begin() as conn:
                records = (parse_nvd_cve(item) for item in _nvd_pages(fetch, params, pause))
                total += store_cves(conn, records)
                cursor[key] = now.isoformat()
                _status(conn, "nvd", cursor=cursor)
        except (IntelError, httpx.HTTPError, ValueError, KeyError) as e:
            failed.append(f"{key}: {e}")
            log.warning(
                "nvd product sync failed", extra={"fields": {"product": key, "error": str(e)}}
            )
        time.sleep(pause)
    with engine.begin() as conn:
        held = conn.execute(text("SELECT count(*) FROM intel.cve")).scalar_one()
        synced = f"{len(wanted) - len(failed)}/{len(wanted)} products"
        if failed:
            _status(
                conn,
                "nvd",
                status="error",
                last_attempt_at=started,
                records=held,
                source_version=synced,
                error="; ".join(failed)[:1000],
            )
        else:
            _status(
                conn,
                "nvd",
                status="ok",
                last_attempt_at=started,
                last_success_at=started,
                records=held,
                source_version=synced,
                error=None,
            )
    if failed:  # raised after the commit, so the error status is kept
        raise IntelError(f"{len(failed)} product(s) failed: {failed[0]}")
    return total


# ---- reading (API and correlation, any role with SELECT) ----


def sources(conn: Connection) -> list[dict[str, Any]]:
    rows = conn.execute(text("SELECT * FROM intel.source ORDER BY name")).mappings().all()
    now = datetime.now(UTC)
    out = []
    for r in rows:
        d = dict(r)
        d.pop("cursor", None)
        last = d["last_success_at"]
        d["stale"] = last is None or now - last > MAX_AGE[d["name"]]
        d["max_age_hours"] = int(MAX_AGE[d["name"]].total_seconds() // 3600)
        out.append(d)
    return out


def cve_details(conn: Connection, ids: list[str]) -> dict[str, dict[str, Any]]:
    if not ids:
        return {}
    rows = conn.execute(
        text(
            "SELECT c.id, c.description, c.cvss_version, c.cvss_score, c.cvss_vector, "
            "c.cvss_severity, c.cvss_source, c.cwes, c.published, c.last_modified, c.vuln_status, "
            "c.refs, k.cve_id IS NOT NULL AS kev, k.date_added AS kev_added, "
            "k.due_date AS kev_due, k.ransomware AS kev_ransomware, "
            "k.required_action AS kev_action, e.score AS epss, e.percentile AS epss_percentile, "
            "e.score_date AS epss_date FROM intel.cve c "
            "LEFT JOIN intel.kev k ON k.cve_id = c.id LEFT JOIN intel.epss e ON e.cve_id = c.id "
            "WHERE c.id = ANY(:ids)"
        ),
        {"ids": ids},
    ).mappings()
    return {r["id"]: dict(r) for r in rows}


# ---- API (global reference data; any member may read it) ----

router = APIRouter(prefix="/api/v1/intel", tags=["intelligence"])
Reader = Annotated[Principal, Depends(require(Permission.INTEL_READ))]


@router.get("/sources")
def list_sources(request: Request, principal: Reader) -> dict[str, Any]:
    """Each source's freshness: last success, upstream version, record count, last error."""
    with tenant_tx(engine_of(request), principal) as conn:
        return {"sources": sources(conn), "notice": NVD_NOTICE}


@router.get("/cves")
def search_cves(
    request: Request,
    principal: Reader,
    q: Annotated[str | None, Query(max_length=100)] = None,
    kev: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, Any]:
    """CVE records held locally (only products VULNEX fingerprints are synced from NVD)."""
    where = "WHERE true "
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if q:
        where += "AND (c.id = :qu OR c.description ILIKE '%' || :q || '%') "
        params |= {"q": q, "qu": q.strip().upper()}
    if kev is not None:
        where += "AND (k.cve_id IS NOT NULL) = :kev "
        params["kev"] = kev
    base = "FROM intel.cve c LEFT JOIN intel.kev k ON k.cve_id = c.id " + where
    with tenant_tx(engine_of(request), principal) as conn:
        total = conn.execute(text("SELECT count(*) " + base), params).scalar_one()
        ids = list(
            conn.execute(
                text(
                    "SELECT c.id " + base + "ORDER BY c.published DESC NULLS LAST, c.id "
                    "LIMIT :limit OFFSET :offset"
                ),
                params,
            ).scalars()
        )
        found = cve_details(conn, ids)
    return {"items": [_plain(found[i]) for i in ids], "total": total}


@router.get("/cves/{cve_id}")
def get_cve(cve_id: str, request: Request, principal: Reader) -> dict[str, Any]:
    with tenant_tx(engine_of(request), principal) as conn:
        found = cve_details(conn, [cve_id.upper()])
        if not found:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "CVE not in the local intelligence store"
            )
        matches = [
            dict(r)
            for r in conn.execute(
                text(
                    "SELECT vendor, product, version, start_including, start_excluding, "
                    "end_including, end_excluding, criteria, conditional FROM intel.cve_match "
                    "WHERE cve_id = :id ORDER BY vendor, product, id"
                ),
                {"id": cve_id.upper()},
            ).mappings()
        ]
    return _plain(found[cve_id.upper()]) | {"matches": matches}


def _plain(d: dict[str, Any]) -> dict[str, Any]:
    return {k: float(v) if isinstance(v, Decimal) else v for k, v in d.items()}
