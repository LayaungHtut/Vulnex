"""Baseline: tenant schema, fail-closed tenant context, application role grants (ADR-0005).

Roles are cluster-level and are created before migrations run
(deploy/compose/postgres/roles.psql). The `intel` and `queue` schemas arrive with
the milestones that first put tables in them (M6, M4).

Revision ID: 0001
Revises:
Create Date: 2026-11-07
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA app")
    op.execute("REVOKE ALL ON SCHEMA app FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA app TO vulnex_app")
    # NULL when unset or after a transaction-local set_config has ended (empty string),
    # so `tenant_id = app.current_tenant()` matches no rows: fail closed.
    op.execute(
        """
        CREATE FUNCTION app.current_tenant() RETURNS uuid
          LANGUAGE sql STABLE
          AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION app.current_tenant() FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION app.current_tenant() TO vulnex_app")
    # Tables created later by the owner get DML for the app role; append-only tables revoke it.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA app "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vulnex_app"
    )


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA app "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM vulnex_app"
    )
    op.execute("DROP SCHEMA app CASCADE")
