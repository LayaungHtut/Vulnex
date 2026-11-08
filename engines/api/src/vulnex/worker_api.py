"""Worker API, `/worker/v1` (ADR-0006 §1-5). A separate app on its own port:

    uvicorn --factory vulnex.worker_api:create_worker_app --port 8001

It must be reachable only through the mTLS gateway (Caddy), which verifies the client
certificate against the worker CA, strips any incoming `X-Vulnex-Client-Cert-Sha256`, and sets it
to the verified certificate's SHA-256. This app trusts that header and nothing else: never
expose its port directly. Enrollment is the one route without a certificate; the single-use
token is the credential there.

The app also runs the queue sweeper, which returns expired leases to the queue.
"""

import json
import logging
import re
import threading
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import SQLAlchemyError

from vulnex import __version__, logs, security
from vulnex.audit import record_worker
from vulnex.db import make_engine
from vulnex.deps import engine_of
from vulnex.main import install_common
from vulnex.pki import CsrError, WorkerPki, fingerprint
from vulnex.scans import ScanPayload
from vulnex.scope import entries_by_group, is_authorized
from vulnex.settings import Settings
from vulnex_worker_protocol.lease import (
    LeaseScopeEntry,
    Limits,
    ScopeLease,
    public_key_b64,
    sign,
)
from vulnex_worker_protocol.messages import (
    PROTOCOL_VERSION,
    Credentials,
    EnrollRequest,
    ExtendRequest,
    ExtendResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    LeaseRequest,
    LeaseResponse,
    RenewRequest,
    Submission,
    SubmissionResponse,
    Task,
)
from vulnex_worker_protocol.targets import (
    ASSET_MIN_PREFIX,
    ScopeEntry,
    TargetError,
    parse,
    scope_digest,
    scope_problem,
)

log = logging.getLogger("vulnex.worker_api")

CERT_HEADER = "X-Vulnex-Client-Cert-Sha256"
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
LEASE_TTL = timedelta(minutes=5)  # the queue caps leases at 5 minutes
SWEEP_EVERY_S = 10.0
# M4 tasks only expand targets against scope; these bound that work on the worker.
LIMITS = Limits(max_addresses=4096, task_timeout_s=300, probe_timeout_s=2.0, max_concurrency=16)

router = APIRouter(prefix="/worker/v1", tags=["worker"])


@dataclass(frozen=True)
class Worker:
    id: uuid.UUID
    tenant_id: uuid.UUID
    scope_group_id: uuid.UUID
    status: str


@contextmanager
def worker_tx(engine: Engine, tenant_id: uuid.UUID) -> Iterator[Connection]:
    """One transaction in the worker's tenant (no user). Transaction-local, like tenant_tx."""
    with engine.begin() as conn:
        _set_tenant(conn, tenant_id)
        yield conn


def _set_tenant(conn: Connection, tenant_id: uuid.UUID) -> None:
    conn.execute(
        text("SELECT set_config('app.tenant_id', :t, true), set_config('app.user_id', '', true)"),
        {"t": str(tenant_id)},
    )


def _pki(request: Request) -> WorkerPki:
    pki: WorkerPki = request.app.state.pki
    return pki


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail)


def current_worker(request: Request) -> Worker:
    """The worker whose verified client certificate the gateway reported. A revoked worker gets
    401 "revoked", which tells it to delete its keys and stop."""
    fp = request.headers.get(CERT_HEADER, "").strip().lower()
    if not _FINGERPRINT.fullmatch(fp):
        raise _unauthorized("client certificate required")
    with engine_of(request).begin() as conn:
        cert = conn.execute(
            text("SELECT * FROM auth.worker_by_cert_fingerprint(:fp)"), {"fp": fp}
        ).first()
        if cert is None:
            raise _unauthorized("unknown or expired certificate")
        _set_tenant(conn, cert.tenant_id)
        row = conn.execute(
            text("SELECT scope_group_id, status FROM app.worker WHERE id = :w"),
            {"w": cert.worker_id},
        ).one()
    if cert.cert_revoked or row.status == "revoked":
        raise _unauthorized("revoked")
    return Worker(cert.worker_id, cert.tenant_id, row.scope_group_id, row.status)


CurrentWorker = Annotated[Worker, Depends(current_worker)]


def _credentials(pki: WorkerPki, worker: Worker, cert: x509.Certificate) -> Credentials:
    return Credentials(
        worker_id=worker.id,
        tenant_id=worker.tenant_id,
        scope_group_id=worker.scope_group_id,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
        certificate_not_after=cert.not_valid_after_utc,
        scope_keys={pki.scope_kid: public_key_b64(pki.scope_key)},
        protocol_versions=[PROTOCOL_VERSION],
    )


def _issue(
    conn: Connection,
    pki: WorkerPki,
    worker_id: uuid.UUID,
    csr_pem: str,
    enrollment_id: uuid.UUID | None,
) -> x509.Certificate:
    try:
        cert = pki.sign_worker_csr(csr_pem, worker_id)
    except CsrError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(e)) from None
    conn.execute(
        text("SELECT auth.register_worker_certificate(:w, :fp, :na, :e)"),
        {
            "w": worker_id,
            "fp": fingerprint(cert),
            "na": cert.not_valid_after_utc,
            "e": enrollment_id,
        },
    )
    return cert


@router.post("/enroll")
def enroll(body: EnrollRequest, request: Request) -> Credentials:
    """Redeem a single-use enrollment token for a 7-day client certificate. All or nothing: if
    anything fails (name taken, bad CSR), the token stays unused."""
    pki = _pki(request)
    with engine_of(request).begin() as conn:
        e = conn.execute(
            text("SELECT * FROM auth.redeem_worker_enrollment(:h)"),
            {"h": security.token_digest(body.token)},
        ).first()
        if e is None:
            raise _unauthorized("invalid, used, revoked or expired enrollment token")
        _set_tenant(conn, e.tenant_id)
        worker_id = conn.execute(
            text(
                "INSERT INTO app.worker (tenant_id, scope_group_id, name) VALUES (:t, :g, :n) "
                "ON CONFLICT (tenant_id, name) DO NOTHING RETURNING id"
            ),
            {"t": e.tenant_id, "g": e.scope_group_id, "n": e.name},
        ).scalar()
        if worker_id is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "a worker with this name exists")
        cert = _issue(conn, pki, worker_id, body.csr_pem, e.enrollment_id)
        detail = {"enrollment_id": str(e.enrollment_id), "name": e.name}
        record_worker(conn, worker_id, "worker.enrolled", detail)
        worker = Worker(worker_id, e.tenant_id, e.scope_group_id, "active")
    log.info("worker enrolled", extra={"fields": {"worker_id": str(worker_id)}})
    return _credentials(pki, worker, cert)


@router.post("/renew")
def renew(body: RenewRequest, request: Request, worker: CurrentWorker) -> Credentials:
    """A new certificate for a new key, before the current one expires. The old certificate
    stays valid until its own expiry."""
    pki = _pki(request)
    with worker_tx(engine_of(request), worker.tenant_id) as conn:
        cert = _issue(conn, pki, worker.id, body.csr_pem, None)
        record_worker(conn, worker.id, "worker.certificate_renewed")
    return _credentials(pki, worker, cert)


@router.post("/heartbeat")
def heartbeat(body: HeartbeatRequest, request: Request, worker: CurrentWorker) -> HeartbeatResponse:
    with worker_tx(engine_of(request), worker.tenant_id) as conn:
        now = conn.execute(
            text(
                "UPDATE app.worker SET last_seen_at = now(), version = :v WHERE id = :w "
                "RETURNING last_seen_at"
            ),
            {"v": body.version, "w": worker.id},
        ).scalar_one()
    return HeartbeatResponse(
        worker_id=worker.id,
        status="disabled" if worker.status == "disabled" else "active",
        server_time=now,
    )


def _refusal(authorized: bool, entries: list[ScopeEntry], targets: list[str]) -> str | None:
    """Why a job must not run, re-checked at lease time (scope may have changed since the scan
    was requested), or None."""
    if not authorized:
        return "scope group is not authorized for its current entries"
    for raw in targets:
        try:
            problem = scope_problem(parse(raw, min_prefix=ASSET_MIN_PREFIX), entries)
        except TargetError as e:
            problem = str(e)
        if problem:
            return f"{raw}: {problem}"
    return None


@router.post("/lease")
def lease(body: LeaseRequest, request: Request, worker: CurrentWorker) -> LeaseResponse:
    """Claim up to `max_tasks` jobs of this worker's scope group, each with a signed scope lease.
    Jobs whose scope is no longer authorized are completed as `refused` instead of handed out."""
    if worker.status != "active":
        return LeaseResponse(tasks=[])
    pki = _pki(request)
    tasks = []
    with worker_tx(engine_of(request), worker.tenant_id) as conn:
        jobs = (
            conn.execute(
                text("SELECT * FROM queue.claim_for_worker(:w, :n, :ttl)"),
                {"w": worker.id, "n": body.max_tasks, "ttl": LEASE_TTL},
            )
            .mappings()
            .all()
        )
        if not jobs:
            return LeaseResponse(tasks=[])
        # The claim locked the jobs; lock the group too so (re)authorization cannot interleave.
        attested = conn.execute(
            text("SELECT attested_digest FROM app.scope_group WHERE id = :g FOR SHARE"),
            {"g": worker.scope_group_id},
        ).scalar()
        entries = entries_by_group(conn).get(worker.scope_group_id, [])
        authorized = is_authorized(attested, entries)
        for job in jobs:
            payload = ScanPayload.model_validate(job["payload"])
            reason = _refusal(authorized, entries, payload.targets)
            if reason:
                conn.execute(
                    text(
                        "SELECT queue.complete(:j, :l, :w, :a, 0, CAST(:p AS jsonb), 'refused', :e)"
                    ),
                    {
                        "j": job["job_id"],
                        "l": job["lease_id"],
                        "w": worker.id,
                        "a": job["attempt"],
                        "p": '{"refused_by": "control_plane"}',
                        "e": reason,
                    },
                )
                detail = {"job_id": str(job["job_id"]), "reason": reason}
                record_worker(conn, worker.id, "scan.refused", detail)
                continue
            scope_lease = ScopeLease(
                kid=pki.scope_kid,
                job_id=job["job_id"],
                lease_id=job["lease_id"],
                attempt=job["attempt"],
                tenant_id=worker.tenant_id,
                worker_id=worker.id,
                scope_group_id=worker.scope_group_id,
                not_before=datetime.now(UTC),
                # shortcut: the signed window is the first lease period; extending the queue
                # lease does not re-sign. Fine for M4 tasks (seconds); re-sign on extend in M5.
                expires_at=job["lease_expires_at"],
                kind=str(job["kind"]),
                targets=payload.targets,
                scope=[
                    LeaseScopeEntry(kind=e.kind.value, value=e.value, exclude=e.exclude)
                    for e in entries
                ],
                scope_digest=scope_digest(entries),
                limits=LIMITS,
            )
            tasks.append(
                Task(
                    job_id=job["job_id"],
                    lease_id=job["lease_id"],
                    attempt=job["attempt"],
                    lease=sign(scope_lease, pki.scope_key),
                )
            )
    return LeaseResponse(tasks=tasks)


@router.post("/tasks/extend")
def extend(body: ExtendRequest, request: Request, worker: CurrentWorker) -> ExtendResponse:
    """Keep a lease alive; the answer also carries the cancel flag."""
    with worker_tx(engine_of(request), worker.tenant_id) as conn:
        r = conn.execute(
            text("SELECT * FROM queue.extend(:j, :l, :w, :ttl)"),
            {"j": body.job_id, "l": body.lease_id, "w": worker.id, "ttl": LEASE_TTL},
        ).one()
    return ExtendResponse(
        ok=r.ok, cancel_requested=r.cancel_requested, lease_expires_at=r.lease_expires_at
    )


@router.post("/tasks/submit")
def submit(body: Submission, request: Request, worker: CurrentWorker) -> SubmissionResponse:
    """One batch of results; with `outcome` it is the final batch. Exactly-once per
    (job, attempt, seq): a repeat is "duplicate". A submission for a lease this worker no
    longer holds is quarantined and answered with 409."""
    args = {
        "j": body.job_id,
        "l": body.lease_id,
        "w": worker.id,
        "a": body.attempt,
        "s": body.seq,
        "p": json.dumps(body.payload),
    }
    with worker_tx(engine_of(request), worker.tenant_id) as conn:
        if body.outcome is None:
            result = conn.execute(
                text("SELECT queue.submit_result(:j, :l, :w, :a, :s, CAST(:p AS jsonb))"), args
            ).scalar_one()
        else:
            result = conn.execute(
                text("SELECT queue.complete(:j, :l, :w, :a, :s, CAST(:p AS jsonb), :o, :e)"),
                args | {"o": body.outcome, "e": body.error},
            ).scalar_one()
    if result == "stale":
        raise HTTPException(status.HTTP_409_CONFLICT, "stale lease")
    return SubmissionResponse(status=result)


def _sweeper(engine: Engine, stop: threading.Event) -> None:
    while not stop.wait(SWEEP_EVERY_S):
        try:
            with engine.begin() as conn:
                n = conn.execute(text("SELECT queue.sweep()")).scalar_one()
            if n:
                log.info("expired leases swept", extra={"fields": {"jobs": n}})
        except SQLAlchemyError:
            log.warning("queue sweep failed", exc_info=True)


def create_worker_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()  # pyright: ignore[reportCallIssue]  # values come from env
    if settings.worker_pki_dir is None:
        raise RuntimeError("VULNEX_WORKER_PKI_DIR must point at the worker PKI directory")
    logs.configure(settings.log_level)
    engine = make_engine(settings.database_url.get_secret_value())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        stop = threading.Event()
        thread = threading.Thread(target=_sweeper, args=(engine, stop), name="sweeper", daemon=True)
        thread.start()
        yield
        stop.set()
        thread.join(timeout=5)
        engine.dispose()

    app = FastAPI(
        title="VULNEX worker API",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.engine = engine
    app.state.settings = settings
    app.state.pki = WorkerPki.load(settings.worker_pki_dir)
    app.include_router(router)
    install_common(app, engine)
    return app
