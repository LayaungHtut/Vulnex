"""Job queue and worker records (M4, ADR-0003).

- `app.worker`: a scanner worker, bound to one tenant and one scope group (ADR-0006 §1). Status is
  active / disabled / revoked; "stale" is derived from `last_seen_at`. Enrollment and
  certificates come in a later migration.
- Schema `queue`: jobs, accepted results and quarantined (stale) results. Like `auth` (M2), the
  application role has no table privileges here; it acts only through the SECURITY DEFINER
  functions below, which carry the queue semantics of INITIAL_ARCHITECTURE §7.1.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-08
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

IDEMPOTENCY = (
    "(coalesce(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid)), queue, idempotency_key"
)

# New state for a job whose attempt ended without success (failure or expired lease).
# Cancel wins; otherwise retry with backoff while attempts remain; otherwise dead.
RETRY_SET = """
  state = CASE WHEN j.cancel_requested_at IS NOT NULL THEN 'cancelled'
               WHEN j.attempt < j.max_attempts THEN 'queued' ELSE 'dead' END,
  run_after = CASE WHEN j.cancel_requested_at IS NULL AND j.attempt < j.max_attempts
                   THEN now() + queue.backoff(j.attempt) ELSE j.run_after END,
  finished_at = CASE WHEN j.cancel_requested_at IS NULL AND j.attempt < j.max_attempts
                     THEN NULL ELSE now() END,
  lease_id = NULL, lease_expires_at = NULL, updated_at = now()
"""

# Shared by submit_result and complete: lock the job, then classify the submission.
CHECK_SUBMISSION = """
  SELECT * INTO cur FROM queue.job WHERE id = p_job_id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM queue.result r WHERE r.job_id = p_job_id AND r.attempt = p_attempt
             AND r.seq = p_seq AND r.lease_id = p_lease_id) THEN
    RETURN 'duplicate';
  END IF;
  IF cur.id IS NULL OR cur.state <> 'leased' OR cur.lease_id <> p_lease_id
     OR cur.lease_owner <> p_worker_id::text OR cur.attempt <> p_attempt
     OR cur.lease_expires_at <= now() THEN
    INSERT INTO queue.quarantine (job_id, lease_id, worker_id, attempt, seq, reason, payload)
      VALUES (p_job_id, p_lease_id, p_worker_id, p_attempt, p_seq, 'stale lease', p_payload);
    RETURN 'stale';
  END IF;
"""

FUNCTIONS = {
    "queue.enqueue_scan_task(uuid, text, jsonb, text, smallint, integer)": f"""
        CREATE FUNCTION queue.enqueue_scan_task(
          p_scope_group_id uuid, p_kind text, p_payload jsonb, p_idempotency_key text,
          p_priority smallint DEFAULT 0, p_max_attempts integer DEFAULT 3)
          RETURNS TABLE (job_id uuid, created boolean)
          LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE t uuid := app.current_tenant(); v uuid;
          BEGIN
            IF t IS NULL THEN
              RAISE EXCEPTION 'no tenant context' USING ERRCODE = '42501';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM app.scope_group g
                           WHERE g.tenant_id = t AND g.id = p_scope_group_id) THEN
              RAISE EXCEPTION 'scope group not found' USING ERRCODE = 'P0002';
            END IF;
            INSERT INTO queue.job (tenant_id, queue, kind, scope_group_id, payload, priority,
                                   max_attempts, idempotency_key)
              VALUES (t, 'scan', p_kind, p_scope_group_id, p_payload, p_priority,
                      p_max_attempts, p_idempotency_key)
              ON CONFLICT ({IDEMPOTENCY}) WHERE idempotency_key IS NOT NULL DO NOTHING
              RETURNING id INTO v;
            IF v IS NOT NULL THEN
              RETURN QUERY SELECT v, true;
            ELSE
              RETURN QUERY SELECT j.id, false FROM queue.job j
                WHERE j.tenant_id = t AND j.queue = 'scan'
                  AND j.idempotency_key = p_idempotency_key;
            END IF;
          END $$
    """,
    "queue.claim_for_worker(uuid, integer, interval)": f"""
        CREATE FUNCTION queue.claim_for_worker(p_worker_id uuid, p_n integer, p_ttl interval)
          RETURNS TABLE (job_id uuid, tenant_id uuid, scope_group_id uuid, kind text,
                         payload jsonb, attempt integer, lease_id uuid,
                         lease_expires_at timestamptz)
          LANGUAGE sql {DEFINER}
          AS $$
            WITH w AS (
              -- Read under row-level security: the caller's tenant context must be the worker's.
              SELECT wk.tenant_id, wk.scope_group_id FROM app.worker wk
              WHERE wk.id = p_worker_id AND wk.status = 'active'),
            next AS (
              SELECT j.id FROM queue.job j, w
              WHERE j.queue = 'scan' AND j.state = 'queued' AND j.run_after <= now()
                AND j.tenant_id = w.tenant_id AND j.scope_group_id = w.scope_group_id
              ORDER BY j.priority DESC, j.run_after, j.id
              LIMIT greatest(0, least(p_n, 10))
              FOR UPDATE OF j SKIP LOCKED)
            UPDATE queue.job j
               SET state = 'leased', attempt = j.attempt + 1, lease_id = gen_random_uuid(),
                   lease_owner = p_worker_id::text,
                   lease_expires_at = now() + least(p_ttl, interval '5 minutes'),
                   updated_at = now()
              FROM next WHERE j.id = next.id
            RETURNING j.id, j.tenant_id, j.scope_group_id, j.kind, j.payload, j.attempt,
                      j.lease_id, j.lease_expires_at
          $$
    """,
    "queue.extend(uuid, uuid, uuid, interval)": f"""
        CREATE FUNCTION queue.extend(p_job_id uuid, p_lease_id uuid, p_worker_id uuid,
                                     p_ttl interval)
          RETURNS TABLE (ok boolean, cancel_requested boolean, lease_expires_at timestamptz)
          LANGUAGE sql {DEFINER}
          AS $$
            WITH u AS (
              UPDATE queue.job j
                 SET lease_expires_at = now() + least(p_ttl, interval '5 minutes'),
                     updated_at = now()
               WHERE j.id = p_job_id AND j.state = 'leased' AND j.lease_id = p_lease_id
                 AND j.lease_owner = p_worker_id::text AND j.lease_expires_at > now()
              RETURNING j.cancel_requested_at IS NOT NULL AS c, j.lease_expires_at AS e)
            SELECT true, c, e FROM u
            UNION ALL
            SELECT false, false, NULL::timestamptz WHERE NOT EXISTS (SELECT 1 FROM u)
          $$
    """,
    "queue.submit_result(uuid, uuid, uuid, integer, integer, jsonb)": f"""
        CREATE FUNCTION queue.submit_result(p_job_id uuid, p_lease_id uuid, p_worker_id uuid,
                                            p_attempt integer, p_seq integer, p_payload jsonb)
          RETURNS text LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE cur queue.job;
          BEGIN
            {CHECK_SUBMISSION}
            INSERT INTO queue.result (job_id, attempt, seq, lease_id, tenant_id, final, payload)
              VALUES (p_job_id, p_attempt, p_seq, p_lease_id, cur.tenant_id, false, p_payload);
            RETURN 'accepted';
          END $$
    """,
    "queue.complete(uuid, uuid, uuid, integer, integer, jsonb, text, text)": f"""
        CREATE FUNCTION queue.complete(p_job_id uuid, p_lease_id uuid, p_worker_id uuid,
                                       p_attempt integer, p_seq integer, p_payload jsonb,
                                       p_outcome text, p_error text DEFAULT NULL)
          RETURNS text LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE cur queue.job;
          BEGIN
            IF p_outcome NOT IN ('succeeded', 'failed', 'refused', 'cancelled') THEN
              RAISE EXCEPTION 'invalid outcome' USING ERRCODE = '22023';
            END IF;
            {CHECK_SUBMISSION}
            -- The final result and the state change commit together (§7.1).
            INSERT INTO queue.result (job_id, attempt, seq, lease_id, tenant_id, final, payload)
              VALUES (p_job_id, p_attempt, p_seq, p_lease_id, cur.tenant_id, true, p_payload);
            IF p_outcome = 'failed' THEN
              UPDATE queue.job j SET {RETRY_SET}, last_error = left(p_error, 1000)
               WHERE j.id = p_job_id;
            ELSE
              UPDATE queue.job j
                 SET state = CASE p_outcome WHEN 'refused' THEN 'failed' ELSE p_outcome END,
                     finished_at = now(), lease_id = NULL, lease_expires_at = NULL,
                     last_error = left(p_error, 1000), updated_at = now()
               WHERE j.id = p_job_id;
            END IF;
            RETURN 'accepted';
          END $$
    """,
    "queue.request_cancel(uuid)": f"""
        CREATE FUNCTION queue.request_cancel(p_job_id uuid)
          RETURNS text LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE t uuid := app.current_tenant(); s text;
          BEGIN
            UPDATE queue.job j SET state = 'cancelled', cancel_requested_at = now(),
                   finished_at = now(), updated_at = now()
             WHERE j.id = p_job_id AND j.tenant_id = t AND j.state = 'queued'
            RETURNING j.state INTO s;
            IF s IS NULL THEN
              UPDATE queue.job j
                 SET cancel_requested_at = coalesce(j.cancel_requested_at, now()),
                     updated_at = now()
               WHERE j.id = p_job_id AND j.tenant_id = t AND j.state = 'leased'
              RETURNING j.state INTO s;
            END IF;
            IF s IS NULL THEN
              SELECT j.state INTO s FROM queue.job j WHERE j.id = p_job_id AND j.tenant_id = t;
            END IF;
            RETURN s;  -- NULL: no such job in the caller's tenant
          END $$
    """,
    "queue.sweep()": f"""
        CREATE FUNCTION queue.sweep()
          RETURNS integer LANGUAGE sql {DEFINER}
          AS $$
            WITH expired AS (
              SELECT id FROM queue.job
              WHERE state = 'leased' AND lease_expires_at < now()
              ORDER BY lease_expires_at LIMIT 500
              FOR UPDATE SKIP LOCKED),
            moved AS (
              UPDATE queue.job j SET {RETRY_SET}, last_error = 'lease expired'
                FROM expired WHERE j.id = expired.id
              RETURNING 1)
            SELECT count(*)::integer FROM moved
          $$
    """,
}


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE app.worker (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          scope_group_id uuid NOT NULL,
          name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
          status text NOT NULL DEFAULT 'active'
            CHECK (status IN ('active', 'disabled', 'revoked')),
          created_at timestamptz NOT NULL DEFAULT now(),
          created_by uuid,
          last_seen_at timestamptz,
          revoked_at timestamptz,
          UNIQUE (tenant_id, id),
          UNIQUE (tenant_id, name),
          CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
          FOREIGN KEY (tenant_id, scope_group_id) REFERENCES app.scope_group (tenant_id, id)
        )
        """
    )
    op.execute("REVOKE DELETE, TRUNCATE ON app.worker FROM vulnex_app")
    op.execute("ALTER TABLE app.worker ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.worker FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON app.worker
          USING (tenant_id = app.current_tenant())
          WITH CHECK (tenant_id = app.current_tenant())
        """
    )

    op.execute("CREATE SCHEMA queue")
    op.execute("REVOKE ALL ON SCHEMA queue FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA queue TO vulnex_app")
    op.execute(
        """
        CREATE TABLE queue.job (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid REFERENCES app.tenant (id),  -- NULL only for global runner jobs
          queue text NOT NULL CHECK (queue ~ '^[a-z_]{1,32}$'),
          kind text NOT NULL CHECK (kind ~ '^[a-z_.]{1,64}$'),
          scope_group_id uuid,
          payload jsonb NOT NULL DEFAULT '{}',
          state text NOT NULL DEFAULT 'queued'
            CHECK (state IN ('queued', 'leased', 'succeeded', 'failed', 'cancelled', 'dead')),
          priority smallint NOT NULL DEFAULT 0,
          run_after timestamptz NOT NULL DEFAULT now(),
          attempt integer NOT NULL DEFAULT 0,
          max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
          lease_id uuid,
          lease_owner text,
          lease_expires_at timestamptz,
          cancel_requested_at timestamptz,
          idempotency_key text CHECK (length(idempotency_key) BETWEEN 1 AND 200),
          last_error text,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          finished_at timestamptz,
          CHECK ((state = 'leased') = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
          CHECK (queue <> 'scan' OR (tenant_id IS NOT NULL AND scope_group_id IS NOT NULL)),
          FOREIGN KEY (tenant_id, scope_group_id) REFERENCES app.scope_group (tenant_id, id)
        )
        """
    )
    # Keys are per tenant; global jobs (tenant_id NULL) share one namespace. Jobs without a key
    # are never deduplicated.
    op.execute(
        f"CREATE UNIQUE INDEX job_idempotency ON queue.job ({IDEMPOTENCY}) "
        "WHERE idempotency_key IS NOT NULL"
    )
    op.execute(
        "CREATE INDEX job_ready ON queue.job (queue, priority DESC, run_after) "
        "WHERE state = 'queued'"
    )
    op.execute("CREATE INDEX job_leased ON queue.job (lease_expires_at) WHERE state = 'leased'")
    op.execute("CREATE INDEX job_tenant ON queue.job (tenant_id, created_at DESC)")
    op.execute(
        """
        CREATE TABLE queue.result (
          job_id uuid NOT NULL REFERENCES queue.job (id) ON DELETE CASCADE,
          attempt integer NOT NULL,
          seq integer NOT NULL CHECK (seq >= 0),
          lease_id uuid NOT NULL,
          tenant_id uuid,
          final boolean NOT NULL,
          payload jsonb NOT NULL,
          received_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (job_id, attempt, seq)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE queue.quarantine (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          job_id uuid,
          lease_id uuid,
          worker_id uuid,
          attempt integer,
          seq integer,
          reason text NOT NULL,
          payload jsonb,
          received_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    # Internal helper, not granted to the application role.
    op.execute(
        """
        CREATE FUNCTION queue.backoff(p_attempt integer) RETURNS interval
          LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp
          AS $$ SELECT least(interval '15 minutes',
                             interval '30 seconds' * power(2, greatest(p_attempt, 1) - 1)
                             * (1 + random() * 0.25)) $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION queue.backoff(integer) FROM PUBLIC")

    for signature, ddl in FUNCTIONS.items():
        op.execute(ddl)
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO vulnex_app")


def downgrade() -> None:
    op.execute("DROP SCHEMA queue CASCADE")
    op.execute("DROP TABLE app.worker")
