"""ADR-0003 job queue semantics, exercised as `vulnex_app` through the queue functions.

The owner connection is used only to simulate time passing (expire a lease, make a retry due)
and to inspect rows the application role cannot read.
"""

import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import pytest
from conftest import APP_URL, Org, needs_db
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

pytestmark = needs_db


@contextmanager
def tx(engine: Engine, tenant: uuid.UUID | None) -> Iterator[Connection]:
    with engine.begin() as c:
        c.execute(
            text("SELECT set_config('app.tenant_id', :t, true)"),
            {"t": str(tenant) if tenant else ""},
        )
        yield c


@dataclass
class Site:
    """One tenant with one scope group and one active worker bound to it."""

    tenant: uuid.UUID
    group: uuid.UUID
    worker: uuid.UUID


@pytest.fixture
def make_site(app_engine: Engine, make_org: Callable[..., Org]) -> Callable[..., Site]:
    def make(org: Org | None = None, status: str = "active") -> Site:
        org = org or make_org()
        with tx(app_engine, org.id) as c:
            group = c.execute(
                text("INSERT INTO app.scope_group (tenant_id, name) VALUES (:t, :n) RETURNING id"),
                {"t": org.id, "n": f"g-{uuid.uuid4().hex[:8]}"},
            ).scalar_one()
            worker = c.execute(
                text(
                    "INSERT INTO app.worker (tenant_id, scope_group_id, name, status, revoked_at) "
                    "VALUES (:t, :g, :n, :s, CASE WHEN :s = 'revoked' THEN now() END) "
                    "RETURNING id"
                ),
                {"t": org.id, "g": group, "n": f"w-{uuid.uuid4().hex[:8]}", "s": status},
            ).scalar_one()
        return Site(org.id, group, worker)

    return make


def enqueue(engine: Engine, site: Site, key: str | None = None, attempts: int = 3) -> uuid.UUID:
    with tx(engine, site.tenant) as c:
        job: uuid.UUID = c.execute(
            text(
                "SELECT job_id FROM queue.enqueue_scan_task(:g, 'scan.discovery', "
                "CAST(:p AS jsonb), :k, CAST(0 AS smallint), :m)"
            ),
            {"g": site.group, "p": '{"targets": ["10.0.0.1"]}', "k": key, "m": attempts},
        ).scalar_one()
    return job


def claim(engine: Engine, site: Site, n: int = 1, ttl: str = "30 seconds") -> list[Any]:
    with tx(engine, site.tenant) as c:
        return list(
            c.execute(
                text("SELECT * FROM queue.claim_for_worker(:w, :n, CAST(:ttl AS interval))"),
                {"w": site.worker, "n": n, "ttl": ttl},
            ).mappings()
        )


def submit(
    engine: Engine, site: Site, lease: Any, seq: int, *, final: str | None = None, error: str = ""
) -> str:
    args = {
        "j": lease["job_id"],
        "l": lease["lease_id"],
        "w": site.worker,
        "a": lease["attempt"],
        "s": seq,
        "p": f'{{"seq": {seq}}}',
        "o": final,
        "e": error,
    }
    with tx(engine, site.tenant) as c:
        if final is None:
            sql = "SELECT queue.submit_result(:j, :l, :w, :a, :s, CAST(:p AS jsonb))"
        else:
            sql = "SELECT queue.complete(:j, :l, :w, :a, :s, CAST(:p AS jsonb), :o, :e)"
        result: str = c.execute(text(sql), args).scalar_one()
    return result


def job(owner: Engine, job_id: uuid.UUID) -> Any:
    with owner.connect() as c:
        return (
            c.execute(
                text(
                    "SELECT state, attempt, lease_id, cancel_requested_at, last_error, "
                    "extract(epoch FROM run_after - now()) AS due_in FROM queue.job WHERE id = :j"
                ),
                {"j": job_id},
            )
            .mappings()
            .one()
        )


def expire_lease(owner: Engine, job_id: uuid.UUID) -> None:
    with owner.begin() as c:
        c.execute(
            text(
                "UPDATE queue.job SET lease_expires_at = now() - interval '1 second' WHERE id = :j"
            ),
            {"j": job_id},
        )


def make_due(owner: Engine, job_id: uuid.UUID) -> None:
    with owner.begin() as c:
        c.execute(text("UPDATE queue.job SET run_after = now() WHERE id = :j"), {"j": job_id})


def sweep(engine: Engine) -> int:
    with engine.begin() as c:
        swept: int = c.execute(text("SELECT queue.sweep()")).scalar_one()
    return swept


@pytest.fixture(scope="module")
def wide_engine(migrated: None) -> Iterator[Engine]:
    """A pool large enough for concurrent claimers (the shared app engine has one connection)."""
    assert APP_URL
    engine = create_engine(APP_URL, pool_size=8, max_overflow=0)
    yield engine
    engine.dispose()


# ---- claiming ----


def test_concurrent_claimers_never_share_a_job(
    wide_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    jobs = {enqueue(wide_engine, site) for _ in range(60)}

    def drain(_: int) -> list[uuid.UUID]:
        got: list[uuid.UUID] = []
        while batch := claim(wide_engine, site, n=3):
            got += [r["job_id"] for r in batch]
        return got

    with ThreadPoolExecutor(max_workers=6) as pool:
        claimed = [j for part in pool.map(drain, range(6)) for j in part]
    assert len(claimed) == len(set(claimed)) == 60
    assert set(claimed) == jobs


def test_claims_stay_inside_the_workers_tenant_and_scope_group(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site], make_org: Any
) -> None:
    a = make_site()
    other_group = make_site(Org(a.tenant, uuid.uuid4(), ""))  # same tenant, other group
    b = make_site()
    enqueue(app_engine, other_group)
    enqueue(app_engine, b)
    assert claim(app_engine, a, n=10) == []

    mine = enqueue(app_engine, a)
    # A's worker id presented under B's tenant context finds no worker, so claims nothing.
    assert claim(app_engine, Site(b.tenant, a.group, a.worker)) == []
    assert claim(app_engine, a)[0]["job_id"] == mine


@pytest.mark.parametrize("status", ["disabled", "revoked"])
def test_disabled_or_revoked_workers_get_no_work(
    app_engine: Engine, make_site: Callable[..., Site], make_org: Any, status: str
) -> None:
    active = make_site()
    blocked = make_site(Org(active.tenant, uuid.uuid4(), ""), status=status)
    blocked = Site(active.tenant, active.group, blocked.worker)  # same group as the job
    with tx(app_engine, active.tenant) as c:
        c.execute(
            text("UPDATE app.worker SET scope_group_id = :g WHERE id = :w"),
            {"g": active.group, "w": blocked.worker},
        )
    enqueue(app_engine, active)
    assert claim(app_engine, blocked) == []
    assert len(claim(app_engine, active)) == 1


def test_claim_size_and_ttl_are_capped(app_engine: Engine, make_site: Callable[..., Site]) -> None:
    site = make_site()
    for _ in range(12):
        enqueue(app_engine, site)
    leases = claim(app_engine, site, n=1000, ttl="1 day")
    assert len(leases) == 10
    with app_engine.connect() as c:
        longest = c.execute(
            text("SELECT max(:e - now()) <= interval '5 minutes 1 second'"),
            {"e": max(r["lease_expires_at"] for r in leases)},
        ).scalar_one()
    assert longest


# ---- idempotent enqueue ----


def test_enqueue_is_idempotent_per_tenant(
    app_engine: Engine, make_site: Callable[..., Site]
) -> None:
    a, b = make_site(), make_site()
    first = enqueue(app_engine, a, key="scan-42")
    assert enqueue(app_engine, a, key="scan-42") == first
    assert enqueue(app_engine, b, key="scan-42") != first  # same key, other tenant
    assert enqueue(app_engine, a) != enqueue(app_engine, a)  # no key, no deduplication


def test_enqueue_refuses_another_tenants_scope_group_and_missing_context(
    app_engine: Engine, make_site: Callable[..., Site]
) -> None:
    a, b = make_site(), make_site()
    with pytest.raises(DBAPIError, match="scope group not found"):
        enqueue(app_engine, Site(a.tenant, b.group, a.worker))
    with pytest.raises(DBAPIError, match="no tenant context"):
        enqueue(app_engine, Site(None, a.group, a.worker))  # type: ignore[arg-type]


# ---- results ----


def test_duplicate_result_has_no_effect(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    enqueue(app_engine, site)
    lease = claim(app_engine, site)[0]
    assert submit(app_engine, site, lease, 0) == "accepted"
    assert submit(app_engine, site, lease, 0) == "duplicate"
    assert submit(app_engine, site, lease, 1, final="succeeded") == "accepted"
    assert submit(app_engine, site, lease, 1, final="succeeded") == "duplicate"
    with owner_engine.connect() as c:
        rows = c.execute(
            text("SELECT seq, final FROM queue.result WHERE job_id = :j ORDER BY seq"),
            {"j": lease["job_id"]},
        ).all()
    assert [tuple(r) for r in rows] == [(0, False), (1, True)]
    assert job(owner_engine, lease["job_id"])["state"] == "succeeded"


def test_late_result_after_re_lease_is_quarantined(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    old = claim(app_engine, site)[0]
    expire_lease(owner_engine, job_id)
    assert sweep(app_engine) >= 1
    make_due(owner_engine, job_id)
    new = claim(app_engine, site)[0]
    assert new["attempt"] == 2 and new["lease_id"] != old["lease_id"]

    assert submit(app_engine, site, old, 0) == "stale"
    assert submit(app_engine, site, old, 1, final="succeeded") == "stale"
    with owner_engine.connect() as c:
        accepted = c.execute(
            text("SELECT count(*) FROM queue.result WHERE job_id = :j"), {"j": job_id}
        ).scalar_one()
        quarantined = c.execute(
            text("SELECT count(*) FROM queue.quarantine WHERE job_id = :j"), {"j": job_id}
        ).scalar_one()
    assert (accepted, quarantined) == (0, 2)
    assert job(owner_engine, job_id)["state"] == "leased"  # the current lease is untouched
    assert submit(app_engine, site, new, 0, final="succeeded") == "accepted"


def test_results_need_the_lease_holders_identity(
    app_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    enqueue(app_engine, site)
    lease = claim(app_engine, site)[0]
    impostor = Site(site.tenant, site.group, uuid.uuid4())
    assert submit(app_engine, impostor, lease, 0) == "stale"
    forged = {**lease, "lease_id": uuid.uuid4()}
    assert submit(app_engine, site, forged, 0) == "stale"
    # A caller without the lease cannot learn that seq 0 exists, either.
    assert submit(app_engine, site, lease, 0) == "accepted"
    assert submit(app_engine, site, forged, 0) == "stale"


def test_completion_always_stores_its_final_result(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    enqueue(app_engine, site)
    lease = claim(app_engine, site)[0]
    with pytest.raises(DBAPIError, match="invalid outcome"):
        submit(app_engine, site, lease, 0, final="done")
    assert submit(app_engine, site, lease, 0, final="succeeded") == "accepted"
    with owner_engine.connect() as c:
        final = c.execute(
            text("SELECT count(*) FROM queue.result WHERE job_id = :j AND final"),
            {"j": lease["job_id"]},
        ).scalar_one()
    assert final == 1


# ---- retries, refusal, recovery ----


def test_failures_retry_with_backoff_then_die(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site, attempts=2)
    lease = claim(app_engine, site)[0]
    assert submit(app_engine, site, lease, 0, final="failed", error="timeout") == "accepted"
    state = job(owner_engine, job_id)
    assert state["state"] == "queued" and state["last_error"] == "timeout"
    assert 29 <= state["due_in"] <= 38  # 30 s base + up to 25 % jitter
    assert claim(app_engine, site) == []  # not due yet

    make_due(owner_engine, job_id)
    lease = claim(app_engine, site)[0]
    assert lease["attempt"] == 2
    submit(app_engine, site, lease, 0, final="failed", error="timeout")
    assert job(owner_engine, job_id)["state"] == "dead"


def test_refused_tasks_are_not_retried(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    lease = claim(app_engine, site)[0]
    submit(app_engine, site, lease, 0, final="refused", error="scope lease signature invalid")
    state = job(owner_engine, job_id)
    assert state["state"] == "failed" and state["attempt"] == 1


def test_killed_worker_job_is_retried_after_lease_expiry(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    claim(app_engine, site)
    sweep(app_engine)
    assert job(owner_engine, job_id)["state"] == "leased"  # a live lease survives a sweep
    expire_lease(owner_engine, job_id)
    sweep(app_engine)
    state = job(owner_engine, job_id)
    assert state["state"] == "queued" and state["lease_id"] is None
    assert state["last_error"] == "lease expired"


def test_extend_keeps_only_a_live_lease_alive(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    lease = claim(app_engine, site)[0]

    def extend(worker: uuid.UUID, lease_id: uuid.UUID) -> Any:
        with tx(app_engine, site.tenant) as c:
            return (
                c.execute(
                    text("SELECT * FROM queue.extend(:j, :l, :w, interval '30 seconds')"),
                    {"j": job_id, "l": lease_id, "w": worker},
                )
                .mappings()
                .one()
            )

    assert extend(site.worker, lease["lease_id"])["ok"] is True
    assert extend(uuid.uuid4(), lease["lease_id"])["ok"] is False
    assert extend(site.worker, uuid.uuid4())["ok"] is False
    expire_lease(owner_engine, job_id)
    assert extend(site.worker, lease["lease_id"])["ok"] is False  # expired: cannot be revived


def test_concurrent_sweepers_move_each_job_once(
    wide_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    jobs = [enqueue(wide_engine, site) for _ in range(30)]
    claim(wide_engine, site, n=10)
    claim(wide_engine, site, n=10)
    claim(wide_engine, site, n=10)
    with owner_engine.begin() as c:
        c.execute(
            text(
                "UPDATE queue.job SET lease_expires_at = now() - interval '1 second' "
                "WHERE id = ANY(:ids)"
            ),
            {"ids": jobs},
        )
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: sweep(wide_engine), range(4)))
    with owner_engine.connect() as c:
        rows = c.execute(
            text("SELECT state, attempt FROM queue.job WHERE id = ANY(:ids)"), {"ids": jobs}
        ).all()
    assert {tuple(r) for r in rows} == {("queued", 1)}


# ---- cancellation ----


def cancel(engine: Engine, tenant: uuid.UUID, job_id: uuid.UUID) -> str | None:
    with tx(engine, tenant) as c:
        state: str | None = c.execute(
            text("SELECT queue.request_cancel(:j)"), {"j": job_id}
        ).scalar_one()
    return state


def test_cancel_queued_job(app_engine: Engine, make_site: Callable[..., Site]) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    assert cancel(app_engine, site.tenant, job_id) == "cancelled"
    assert claim(app_engine, site) == []


def test_cancel_leased_job_worker_acknowledges(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    lease = claim(app_engine, site)[0]
    assert cancel(app_engine, site.tenant, job_id) == "leased"
    with tx(app_engine, site.tenant) as c:
        flag = c.execute(
            text("SELECT cancel_requested FROM queue.extend(:j, :l, :w, interval '30 seconds')"),
            {"j": job_id, "l": lease["lease_id"], "w": site.worker},
        ).scalar_one()
    assert flag is True
    assert submit(app_engine, site, lease, 0, final="cancelled") == "accepted"
    assert job(owner_engine, job_id)["state"] == "cancelled"


def test_cancel_leased_job_worker_gone(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    site = make_site()
    job_id = enqueue(app_engine, site)
    claim(app_engine, site)
    cancel(app_engine, site.tenant, job_id)
    expire_lease(owner_engine, job_id)
    sweep(app_engine)
    assert job(owner_engine, job_id)["state"] == "cancelled"  # not re-queued


def test_cancel_is_tenant_scoped(
    app_engine: Engine, owner_engine: Engine, make_site: Callable[..., Site]
) -> None:
    a, b = make_site(), make_site()
    job_id = enqueue(app_engine, a)
    assert cancel(app_engine, b.tenant, job_id) is None
    assert job(owner_engine, job_id)["state"] == "queued"


# ---- privileges ----


@pytest.mark.parametrize(
    "stmt",
    [
        "SELECT * FROM queue.job",
        "SELECT * FROM queue.result",
        "SELECT * FROM queue.quarantine",
        "UPDATE queue.job SET state = 'succeeded'",
        "INSERT INTO queue.result (job_id, attempt, seq, lease_id, final, payload) "
        "VALUES (gen_random_uuid(), 1, 0, gen_random_uuid(), true, '{}')",
        "SELECT queue.backoff(1)",
        "DELETE FROM app.worker",
    ],
)
def test_app_role_cannot_touch_queue_tables_directly(app_engine: Engine, stmt: str) -> None:
    with app_engine.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
        c.execute(text(stmt))
