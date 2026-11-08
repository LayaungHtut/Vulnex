"""Authorized scope and asset inventory (M3).

- `app.scope_group`: a named authorization boundary. An owner or administrator records an
  attestation; it covers exactly the entries whose digest it stores (`attested_digest`), so any
  later change to the entries shows as "changed since authorization" without extra bookkeeping.
- `app.scope_entry`: included or excluded CIDRs, hostnames and `*.` wildcards (canonical text,
  validated by vulnex.targets before insert).
- `app.asset`: a registered target (IP, range or hostname) inside one scope group. Retired, never
  deleted by the application (deletion is a retention decision, PRD §11).

Every reference between these tables is a composite (tenant_id, id) foreign key, so the
database itself rejects a row that points into another tenant (ADR-0005 §1).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-08
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

TABLES = ("scope_group", "scope_entry", "asset")


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE app.scope_group (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
          description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
          created_at timestamptz NOT NULL DEFAULT now(),
          created_by uuid,
          attested_at timestamptz,
          attested_by uuid,
          attested_digest text,
          attestation_statement text,
          UNIQUE (tenant_id, id),
          UNIQUE (tenant_id, name),
          CHECK ((attested_at IS NULL) = (attested_digest IS NULL))
        )
        """
    )
    op.execute(
        """
        CREATE TABLE app.scope_entry (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          scope_group_id uuid NOT NULL,
          kind text NOT NULL CHECK (kind IN ('cidr', 'hostname', 'hostname_wildcard')),
          value text NOT NULL CHECK (length(value) BETWEEN 1 AND 253),
          exclude boolean NOT NULL DEFAULT false,
          note text NOT NULL DEFAULT '' CHECK (length(note) <= 200),
          created_at timestamptz NOT NULL DEFAULT now(),
          created_by uuid,
          UNIQUE (tenant_id, id),
          UNIQUE (tenant_id, scope_group_id, kind, value, exclude),
          FOREIGN KEY (tenant_id, scope_group_id)
            REFERENCES app.scope_group (tenant_id, id) ON DELETE CASCADE
        )
        """
    )
    op.execute(
        """
        CREATE TABLE app.asset (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          scope_group_id uuid NOT NULL,
          kind text NOT NULL CHECK (kind IN ('ip', 'cidr', 'hostname')),
          target text NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
          name text NOT NULL DEFAULT '' CHECK (length(name) <= 100),
          criticality text NOT NULL DEFAULT 'medium'
            CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
          notes text NOT NULL DEFAULT '' CHECK (length(notes) <= 2000),
          source text NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'discovered')),
          status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
          created_at timestamptz NOT NULL DEFAULT now(),
          created_by uuid,
          updated_at timestamptz NOT NULL DEFAULT now(),
          retired_at timestamptz,
          first_seen_at timestamptz,  -- set by scans (M5); NULL means never observed
          last_seen_at timestamptz,
          UNIQUE (tenant_id, id),
          UNIQUE (tenant_id, scope_group_id, kind, target),
          CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
          FOREIGN KEY (tenant_id, scope_group_id) REFERENCES app.scope_group (tenant_id, id)
        )
        """
    )
    op.execute("CREATE INDEX scope_entry_group_idx ON app.scope_entry (tenant_id, scope_group_id)")
    op.execute("CREATE INDEX asset_list_idx ON app.asset (tenant_id, status, created_at DESC)")
    op.execute("CREATE INDEX asset_group_idx ON app.asset (tenant_id, scope_group_id)")
    # Per-object history (asset and scope pages).
    op.execute(
        "CREATE INDEX audit_event_target_idx "
        "ON app.audit_event (tenant_id, target_type, target_id, id DESC)"
    )

    # Assets are retired, never deleted, by the application.
    op.execute("REVOKE DELETE, TRUNCATE ON app.asset FROM vulnex_app")
    op.execute("REVOKE TRUNCATE ON app.scope_group, app.scope_entry FROM vulnex_app")

    for table in TABLES:
        op.execute(f"ALTER TABLE app.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE app.{table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON app.{table}
              USING (tenant_id = app.current_tenant())
              WITH CHECK (tenant_id = app.current_tenant())
            """
        )


def downgrade() -> None:
    op.execute("DROP INDEX app.audit_event_target_idx")
    op.execute("DROP TABLE app.asset, app.scope_entry, app.scope_group")
