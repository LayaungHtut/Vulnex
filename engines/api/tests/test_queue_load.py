"""Queue load test (INITIAL_ARCHITECTURE §7.1, ADR-0003): 10,000 jobs drained by 4 concurrent
workers. Opt-in, because it takes a while: VULNEX_LOAD_TEST=1 sh scripts/check-api.sh pytest
engines/api/tests/test_queue_load.py -s

Checks correctness under contention (every job completed exactly once, first attempt, no
quarantined or duplicate results) and prints the throughput for the record.
"""

import os
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import Org, needs_db
from sqlalchemy import Engine, text
from test_queue_db import Site, tx

pytestmark = [
    *needs_db,
    pytest.mark.skipif(not os.environ.get("VULNEX_LOAD_TEST"), reason="VULNEX_LOAD_TEST not set"),
]

JOBS = 10_000
CLAIMERS = 4
BATCH = 10


def test_ten_thousand_jobs_four_claimers(
    wide_engine: Engine, owner_engine: Engine, make_org: Callable[..., Org]
) -> None:
    tenant = make_org().id
    with tx(wide_engine, tenant) as c:
        group = c.execute(
            text("INSERT INTO app.scope_group (tenant_id, name) VALUES (:t, 'load') RETURNING id"),
            {"t": tenant},
        ).scalar_one()
        workers = [
            c.execute(
                text(
                    "INSERT INTO app.worker (tenant_id, scope_group_id, name) "
                    "VALUES (:t, :g, :n) RETURNING id"
                ),
                {"t": tenant, "g": group, "n": f"load-{i}"},
            ).scalar_one()
            for i in range(CLAIMERS)
        ]
    site = Site(tenant, group, workers[0])

    start = time.perf_counter()
    with tx(wide_engine, site.tenant) as c:
        c.execute(
            text(
                "SELECT e.job_id FROM generate_series(1, :n) AS s(i), LATERAL "
                "queue.enqueue_scan_task(:g, 'scope.check', jsonb_build_object('i', s.i), "
                "'load-' || s.i, CAST(0 AS smallint), 3) AS e"
            ),
            {"n": JOBS, "g": site.group},
        ).all()
    enqueued_s = time.perf_counter() - start

    def drain(worker: uuid.UUID) -> int:
        done = 0
        while True:
            with tx(wide_engine, site.tenant) as c:
                leases = c.execute(
                    text("SELECT * FROM queue.claim_for_worker(:w, :n, interval '1 minute')"),
                    {"w": worker, "n": BATCH},
                ).all()
            if not leases:
                return done
            with tx(wide_engine, site.tenant) as c:
                for job in leases:
                    status = c.execute(
                        text(
                            "SELECT queue.complete(:j, :l, :w, :a, 0, '{}'::jsonb, "
                            "'succeeded', NULL)"
                        ),
                        {"j": job.job_id, "l": job.lease_id, "w": worker, "a": job.attempt},
                    ).scalar_one()
                    assert status == "accepted"
                    done += 1

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CLAIMERS) as pool:
        counts = list(pool.map(drain, workers))
    drained_s = time.perf_counter() - start

    assert sum(counts) == JOBS
    with owner_engine.connect() as c:
        states: dict[str, int] = dict(
            c.execute(
                text(
                    "SELECT state, count(*) FROM queue.job WHERE scope_group_id = :g GROUP BY state"
                ),
                {"g": site.group},
            ).all()
        )
        max_attempt = c.execute(
            text("SELECT max(attempt) FROM queue.job WHERE scope_group_id = :g"),
            {"g": site.group},
        ).scalar_one()
        finals = c.execute(
            text(
                "SELECT count(*), count(DISTINCT job_id) FROM queue.result r "
                "JOIN queue.job j ON j.id = r.job_id WHERE j.scope_group_id = :g AND r.final"
            ),
            {"g": site.group},
        ).one()
        quarantined = c.execute(
            text(
                "SELECT count(*) FROM queue.quarantine q JOIN queue.job j ON j.id = q.job_id "
                "WHERE j.scope_group_id = :g"
            ),
            {"g": site.group},
        ).scalar_one()
    assert states == {"succeeded": JOBS}
    assert max_attempt == 1  # nothing was handed out twice
    assert tuple(finals) == (JOBS, JOBS)
    assert quarantined == 0
    print(
        f"\nqueue load: enqueue {JOBS} in {enqueued_s:.1f}s; drain with {CLAIMERS} claimers "
        f"(batch {BATCH}) in {drained_s:.1f}s = {JOBS / drained_s:.0f} jobs/s; "
        f"per claimer {counts}"
    )
