"""Worker enrollment and certificates, scan runs (M4, ADR-0006 §1-3).

- `auth.worker_enrollment`: single-use enrollment tokens (SHA-256 only), bound to one tenant and
  one scope group, 24 h at most, revocable before use.
- `auth.worker_certificate`: issued client certificates by SHA-256 fingerprint. Lives in `auth`
  because it is looked up *before* the tenant is known (the certificate establishes it).
- `app.scan`: a scan run requested by a user; its execution is a `queue.job`.

As in 0002/0004, the application role reaches `auth` and `queue` rows only through the
SECURITY DEFINER functions below.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-08
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

FUNCTIONS = {
    "auth.create_worker_enrollment(uuid, text, bytea, interval, uuid)": f"""
        CREATE FUNCTION auth.create_worker_enrollment(
          p_scope_group_id uuid, p_name text, p_token_hash bytea, p_ttl interval, p_by uuid)
          RETURNS TABLE (id uuid, expires_at timestamptz)
          LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE t uuid := app.current_tenant();
          BEGIN
            IF t IS NULL THEN RAISE EXCEPTION 'no tenant context' USING ERRCODE = '42501'; END IF;
            IF NOT EXISTS (SELECT 1 FROM app.scope_group g
                           WHERE g.tenant_id = t AND g.id = p_scope_group_id) THEN
              RAISE EXCEPTION 'scope group not found' USING ERRCODE = 'P0002';
            END IF;
            RETURN QUERY
              WITH ins AS (
                INSERT INTO auth.worker_enrollment AS e
                  (tenant_id, scope_group_id, name, token_hash, created_by, expires_at)
                VALUES (t, p_scope_group_id, p_name, p_token_hash, p_by,
                        now() + least(p_ttl, interval '24 hours'))
                RETURNING e.id AS new_id, e.expires_at AS new_expiry)
              SELECT ins.new_id, ins.new_expiry FROM ins;
          END $$
    """,
    "auth.tenant_worker_enrollments()": f"""
        CREATE FUNCTION auth.tenant_worker_enrollments()
          RETURNS TABLE (id uuid, scope_group_id uuid, name text, created_at timestamptz,
                         expires_at timestamptz, used_at timestamptz, worker_id uuid,
                         revoked_at timestamptz)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT e.id, e.scope_group_id, e.name, e.created_at, e.expires_at, e.used_at,
                       e.worker_id, e.revoked_at
                FROM auth.worker_enrollment e WHERE e.tenant_id = app.current_tenant()
                ORDER BY e.created_at DESC LIMIT 200 $$
    """,
    "auth.revoke_worker_enrollment(uuid)": f"""
        CREATE FUNCTION auth.revoke_worker_enrollment(p_id uuid)
          RETURNS boolean LANGUAGE sql {DEFINER}
          AS $$
            WITH u AS (
              UPDATE auth.worker_enrollment e SET revoked_at = now()
               WHERE e.id = p_id AND e.tenant_id = app.current_tenant()
                 AND e.used_at IS NULL AND e.revoked_at IS NULL
              RETURNING 1)
            SELECT EXISTS (SELECT 1 FROM u)
          $$
    """,
    # Pre-tenant: the token is the only credential. Marks it used; the caller's transaction then
    # creates the worker and its certificate, or rolls everything back.
    "auth.redeem_worker_enrollment(bytea)": f"""
        CREATE FUNCTION auth.redeem_worker_enrollment(p_token_hash bytea)
          RETURNS TABLE (enrollment_id uuid, tenant_id uuid, scope_group_id uuid, name text)
          LANGUAGE sql {DEFINER}
          AS $$
            UPDATE auth.worker_enrollment e SET used_at = now()
             WHERE e.token_hash = p_token_hash AND e.used_at IS NULL
               AND e.revoked_at IS NULL AND e.expires_at > now()
            RETURNING e.id, e.tenant_id, e.scope_group_id, e.name
          $$
    """,
    "auth.register_worker_certificate(uuid, text, timestamptz, uuid)": f"""
        CREATE FUNCTION auth.register_worker_certificate(
          p_worker_id uuid, p_fingerprint text, p_not_after timestamptz, p_enrollment_id uuid)
          RETURNS void LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE t uuid := app.current_tenant();
          BEGIN
            IF NOT EXISTS (SELECT 1 FROM app.worker w
                           WHERE w.tenant_id = t AND w.id = p_worker_id
                             AND w.status <> 'revoked') THEN
              RAISE EXCEPTION 'worker not found' USING ERRCODE = 'P0002';
            END IF;
            INSERT INTO auth.worker_certificate (fingerprint, tenant_id, worker_id, not_after)
              VALUES (p_fingerprint, t, p_worker_id, p_not_after);
            UPDATE auth.worker_enrollment e SET worker_id = p_worker_id
             WHERE e.id = p_enrollment_id AND e.tenant_id = t;
          END $$
    """,
    # Pre-tenant: resolve the gateway-verified certificate to its worker. Returns revoked and
    # disabled workers too, so the API can tell a revoked worker to delete its keys.
    "auth.worker_by_cert_fingerprint(text)": f"""
        CREATE FUNCTION auth.worker_by_cert_fingerprint(p_fingerprint text)
          RETURNS TABLE (worker_id uuid, tenant_id uuid, cert_revoked boolean,
                         cert_not_after timestamptz)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT c.worker_id, c.tenant_id, c.revoked_at IS NOT NULL, c.not_after
                FROM auth.worker_certificate c
                WHERE c.fingerprint = lower(p_fingerprint) AND c.not_after > now() $$
    """,
    "auth.revoke_worker_certificates(uuid)": f"""
        CREATE FUNCTION auth.revoke_worker_certificates(p_worker_id uuid)
          RETURNS integer LANGUAGE sql {DEFINER}
          AS $$
            WITH u AS (
              UPDATE auth.worker_certificate c SET revoked_at = now()
               WHERE c.worker_id = p_worker_id AND c.tenant_id = app.current_tenant()
                 AND c.revoked_at IS NULL
              RETURNING 1)
            SELECT count(*)::integer FROM u
          $$
    """,
    # A revoked worker's leases end now; its jobs follow the normal retry rules, and anything it
    # sends later is quarantined because its lease is gone.
    "queue.release_worker_leases(uuid)": f"""
        CREATE FUNCTION queue.release_worker_leases(p_worker_id uuid)
          RETURNS integer LANGUAGE sql {DEFINER}
          AS $$
            WITH held AS (
              SELECT id FROM queue.job
              WHERE state = 'leased' AND lease_owner = p_worker_id::text
                AND tenant_id = app.current_tenant()
              FOR UPDATE),
            moved AS (
              UPDATE queue.job j SET
                state = CASE WHEN j.cancel_requested_at IS NOT NULL THEN 'cancelled'
                             WHEN j.attempt < j.max_attempts THEN 'queued' ELSE 'dead' END,
                finished_at = CASE WHEN j.cancel_requested_at IS NULL
                                    AND j.attempt < j.max_attempts THEN NULL ELSE now() END,
                lease_id = NULL, lease_expires_at = NULL, last_error = 'worker revoked',
                updated_at = now()
              FROM held WHERE j.id = held.id
              RETURNING 1)
            SELECT count(*)::integer FROM moved
          $$
    """,
    "queue.tenant_jobs(uuid[])": f"""
        CREATE FUNCTION queue.tenant_jobs(p_ids uuid[])
          RETURNS TABLE (id uuid, state text, attempt integer, max_attempts integer,
                         last_error text, cancel_requested boolean, created_at timestamptz,
                         updated_at timestamptz, finished_at timestamptz)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT j.id, j.state, j.attempt, j.max_attempts, j.last_error,
                       j.cancel_requested_at IS NOT NULL, j.created_at, j.updated_at,
                       j.finished_at
                FROM queue.job j
                WHERE j.id = ANY(p_ids) AND j.tenant_id = app.current_tenant() $$
    """,
    "queue.job_final_result(uuid)": f"""
        CREATE FUNCTION queue.job_final_result(p_job_id uuid)
          RETURNS TABLE (attempt integer, payload jsonb, received_at timestamptz)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT r.attempt, r.payload, r.received_at FROM queue.result r
                WHERE r.job_id = p_job_id AND r.final
                  AND r.tenant_id = app.current_tenant()
                ORDER BY r.attempt DESC LIMIT 1 $$
    """,
}


def upgrade() -> None:
    op.execute("ALTER TABLE app.worker ADD COLUMN version text CHECK (length(version) <= 50)")
    op.execute(
        """
        CREATE TABLE auth.worker_enrollment (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          scope_group_id uuid NOT NULL,
          name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
          token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
          created_by uuid,
          created_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL,
          used_at timestamptz,
          worker_id uuid,
          revoked_at timestamptz,
          FOREIGN KEY (tenant_id, scope_group_id)
            REFERENCES app.scope_group (tenant_id, id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE auth.worker_certificate (
          fingerprint text PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
          tenant_id uuid NOT NULL,
          worker_id uuid NOT NULL,
          not_after timestamptz NOT NULL,
          issued_at timestamptz NOT NULL DEFAULT now(),
          revoked_at timestamptz,
          FOREIGN KEY (tenant_id, worker_id) REFERENCES app.worker (tenant_id, id)
        )
        """
    )
    op.execute("CREATE INDEX worker_certificate_worker_idx ON auth.worker_certificate (worker_id)")
    op.execute(
        """
        CREATE TABLE app.scan (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          scope_group_id uuid NOT NULL,
          profile text NOT NULL CHECK (profile IN ('scope_check')),
          asset_ids uuid[] NOT NULL CHECK (cardinality(asset_ids) BETWEEN 1 AND 1000),
          targets text[] NOT NULL,
          job_id uuid NOT NULL UNIQUE REFERENCES queue.job (id),
          requested_by uuid,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (tenant_id, id),
          FOREIGN KEY (tenant_id, scope_group_id) REFERENCES app.scope_group (tenant_id, id)
        )
        """
    )
    op.execute("CREATE INDEX scan_list_idx ON app.scan (tenant_id, created_at DESC)")
    op.execute("REVOKE DELETE, TRUNCATE ON app.scan FROM vulnex_app")
    op.execute("ALTER TABLE app.scan ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.scan FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON app.scan
          USING (tenant_id = app.current_tenant())
          WITH CHECK (tenant_id = app.current_tenant())
        """
    )

    for signature, ddl in FUNCTIONS.items():
        op.execute(ddl)
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO vulnex_app")


def downgrade() -> None:
    for signature in FUNCTIONS:
        op.execute(f"DROP FUNCTION {signature}")
    op.execute("DROP TABLE app.scan, auth.worker_certificate, auth.worker_enrollment")
    op.execute("ALTER TABLE app.worker DROP COLUMN version")
