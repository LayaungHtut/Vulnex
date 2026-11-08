"""Network discovery results (M5): evidence and the service inventory.

- `app.scan` gains the `discovery` profile, its port list and an ingest summary.
- `app.evidence`: what a worker observed, stored as submitted (validated, bounded JSON), one row
  per DNS answer set and per open port. Findings (M7) cite evidence rows. Append-only for the
  application role.
- `app.service`: current state of each (asset, address, port) seen open, with the control
  plane's fingerprint (product and version) and the rules version that produced it.

Both tables carry `tenant_id` with composite foreign keys and FORCE row-level security
(ADR-0005). `queue.job_attempt_results` lets the worker API read back the batches of the
attempt it is completing, in the current tenant only.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-08
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

FUNCTIONS = {
    "queue.job_attempt_results(uuid, integer)": f"""
        CREATE FUNCTION queue.job_attempt_results(p_job_id uuid, p_attempt integer)
          RETURNS TABLE (seq integer, final boolean, payload jsonb)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT r.seq, r.final, r.payload FROM queue.result r
                WHERE r.job_id = p_job_id AND r.attempt = p_attempt
                  AND r.tenant_id = app.current_tenant()
                ORDER BY r.seq $$
    """,
    "queue.job_kind(uuid)": f"""
        CREATE FUNCTION queue.job_kind(p_job_id uuid) RETURNS text
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT j.kind FROM queue.job j
                WHERE j.id = p_job_id AND j.tenant_id = app.current_tenant() $$
    """,
}

TABLES = ("app.evidence", "app.service")


def upgrade() -> None:
    op.execute("ALTER TABLE app.scan DROP CONSTRAINT scan_profile_check")
    op.execute(
        "ALTER TABLE app.scan ADD CONSTRAINT scan_profile_check "
        "CHECK (profile IN ('scope_check', 'discovery'))"
    )
    op.execute(
        "ALTER TABLE app.scan ADD COLUMN ports integer[] NOT NULL DEFAULT '{}' "
        "CHECK (cardinality(ports) <= 1024 AND 0 < ALL(ports) AND 65536 > ALL(ports))"
    )
    op.execute("ALTER TABLE app.scan ADD COLUMN summary jsonb")
    op.execute("ALTER TABLE app.scan ADD COLUMN ingested_at timestamptz")

    op.execute(
        """
        CREATE TABLE app.evidence (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          scan_id uuid NOT NULL,
          asset_id uuid NOT NULL,
          kind text NOT NULL CHECK (kind IN ('dns', 'service')),
          address inet,
          port integer CHECK (port BETWEEN 1 AND 65535),
          data jsonb NOT NULL CHECK (octet_length(data::text) <= 200000),
          observed_at timestamptz NOT NULL,
          scanner_version text NOT NULL CHECK (length(scanner_version) <= 50),
          worker_id uuid,
          created_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (tenant_id, id),
          FOREIGN KEY (tenant_id, scan_id) REFERENCES app.scan (tenant_id, id),
          FOREIGN KEY (tenant_id, asset_id) REFERENCES app.asset (tenant_id, id)
        )
        """
    )
    op.execute("CREATE INDEX evidence_scan_idx ON app.evidence (tenant_id, scan_id)")
    op.execute(
        "CREATE INDEX evidence_asset_idx ON app.evidence (tenant_id, asset_id, observed_at DESC)"
    )

    op.execute(
        """
        CREATE TABLE app.service (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          asset_id uuid NOT NULL,
          address inet NOT NULL,
          port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
          transport text NOT NULL DEFAULT 'tcp' CHECK (transport IN ('tcp')),
          state text NOT NULL CHECK (state IN ('open', 'closed')),
          name text CHECK (length(name) <= 50),
          product text CHECK (length(product) <= 100),
          version text CHECK (length(version) <= 100),
          tls boolean NOT NULL DEFAULT false,
          detail jsonb NOT NULL DEFAULT '{}',
          fingerprint_method text CHECK (length(fingerprint_method) <= 50),
          rules_version text CHECK (length(rules_version) <= 50),
          first_seen_at timestamptz NOT NULL,
          last_seen_at timestamptz NOT NULL,
          closed_at timestamptz,
          last_scan_id uuid NOT NULL,
          last_evidence_id uuid,
          UNIQUE (tenant_id, id),
          UNIQUE (tenant_id, asset_id, address, port, transport),
          CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
          FOREIGN KEY (tenant_id, asset_id) REFERENCES app.asset (tenant_id, id),
          FOREIGN KEY (tenant_id, last_scan_id) REFERENCES app.scan (tenant_id, id),
          FOREIGN KEY (tenant_id, last_evidence_id) REFERENCES app.evidence (tenant_id, id)
        )
        """
    )
    op.execute("CREATE INDEX service_state_idx ON app.service (tenant_id, state, port)")

    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON app.evidence FROM vulnex_app")
    op.execute("REVOKE DELETE, TRUNCATE ON app.service FROM vulnex_app")
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
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
    op.execute("DROP TABLE app.service, app.evidence")
    # FORCE RLS applies to the owner too; lift it briefly so the cleanup sees every tenant.
    op.execute("ALTER TABLE app.scan NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.scan DISABLE ROW LEVEL SECURITY")
    op.execute("DELETE FROM app.scan WHERE profile <> 'scope_check'")
    op.execute("ALTER TABLE app.scan ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE app.scan FORCE ROW LEVEL SECURITY")
    op.execute(
        "ALTER TABLE app.scan DROP COLUMN ingested_at, DROP COLUMN summary, DROP COLUMN ports"
    )
    op.execute("ALTER TABLE app.scan DROP CONSTRAINT scan_profile_check")
    op.execute(
        "ALTER TABLE app.scan ADD CONSTRAINT scan_profile_check CHECK (profile IN ('scope_check'))"
    )
