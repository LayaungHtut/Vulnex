"""Identity and organizations (M2): tenants, users, memberships, sessions, audit events.

Layout (ADR-0005):
- `app.tenant`, `app.membership`, `app.audit_event`: tenant data under FORCE ROW LEVEL SECURITY.
- `auth.*`: global identity data (accounts, sessions, login attempts). `vulnex_app` has no table
  rights here at all; it reaches these rows only through the SECURITY DEFINER functions below,
  each with a fixed search_path and a narrow result. So a stray application query cannot list
  every account, password hash or session.

Context variables, both transaction-local and fail-closed (NULL when unset):
- `app.tenant_id` -> `app.current_tenant()`  (M1)
- `app.user_id`   -> `app.current_user_id()` (here); lets a user see their own memberships
  in other tenants (tenant picker) without seeing anyone else's.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-08
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

ROLES = "('owner', 'admin', 'analyst', 'remediation_contributor', 'viewer')"

# Every definer function: owned by vulnex_owner, callable only by vulnex_app, fixed search_path.
DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

FUNCTIONS = {
    "auth.login_lookup(text)": f"""
        CREATE FUNCTION auth.login_lookup(p_email text)
          RETURNS TABLE (user_id uuid, password_hash text, is_active boolean)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT u.id, u.password_hash, u.is_active
                FROM auth.user_account u WHERE u.email = lower(p_email) $$
    """,
    "auth.login_failures(text, inet, interval)": f"""
        CREATE FUNCTION auth.login_failures(p_email text, p_ip inet, p_window interval)
          RETURNS TABLE (by_email bigint, by_ip bigint)
          LANGUAGE sql STABLE {DEFINER}
          AS $$ SELECT count(*) FILTER (WHERE a.email = lower(p_email)),
                       count(*) FILTER (WHERE p_ip IS NOT NULL AND a.ip = p_ip)
                FROM auth.login_attempt a
                WHERE NOT a.succeeded AND a.at > now() - p_window
                  AND (a.email = lower(p_email) OR a.ip = p_ip) $$
    """,
    "auth.record_login_attempt(text, inet, boolean)": f"""
        CREATE FUNCTION auth.record_login_attempt(p_email text, p_ip inet, p_succeeded boolean)
          RETURNS void LANGUAGE sql {DEFINER}
          AS $$
            DELETE FROM auth.login_attempt WHERE at < now() - interval '1 day';
            INSERT INTO auth.login_attempt (email, ip, succeeded)
              VALUES (left(lower(p_email), 254), p_ip, p_succeeded);
          $$
    """,
    "auth.create_user(text, text, text)": f"""
        CREATE FUNCTION auth.create_user(p_email text, p_display_name text, p_password_hash text)
          RETURNS TABLE (user_id uuid, created boolean)
          LANGUAGE plpgsql {DEFINER}
          AS $$
          BEGIN
            RETURN QUERY
              INSERT INTO auth.user_account (email, display_name, password_hash)
              VALUES (lower(p_email), p_display_name, p_password_hash)
              ON CONFLICT (email) DO NOTHING
              RETURNING id, true;
            IF NOT FOUND THEN
              RETURN QUERY SELECT u.id, false FROM auth.user_account u
                           WHERE u.email = lower(p_email);
            END IF;
          END $$
    """,
    "auth.update_password_hash(uuid, text)": f"""
        CREATE FUNCTION auth.update_password_hash(p_user_id uuid, p_password_hash text)
          RETURNS void LANGUAGE sql {DEFINER}
          AS $$ UPDATE auth.user_account SET password_hash = p_password_hash
                WHERE id = p_user_id $$
    """,
    "auth.create_session(uuid, uuid, bytea, interval, inet, text)": f"""
        CREATE FUNCTION auth.create_session(
            p_user_id uuid, p_tenant_id uuid, p_token_hash bytea, p_ttl interval,
            p_ip inet, p_user_agent text)
          RETURNS TABLE (session_id uuid, expires_at timestamptz)
          LANGUAGE plpgsql {DEFINER}
          AS $$
          BEGIN
            -- Membership rows are under FORCE RLS even for this owner-run function.
            PERFORM set_config('app.user_id', p_user_id::text, true);
            IF NOT EXISTS (SELECT 1 FROM app.membership m
                           JOIN auth.user_account u ON u.id = m.user_id
                           WHERE m.user_id = p_user_id AND m.tenant_id = p_tenant_id
                             AND u.is_active) THEN
              RAISE EXCEPTION 'no active membership' USING ERRCODE = '42501';
            END IF;
            UPDATE auth.user_account SET last_login_at = now() WHERE id = p_user_id;
            RETURN QUERY
              INSERT INTO auth.session (token_hash, user_id, tenant_id, expires_at, ip, user_agent)
              VALUES (p_token_hash, p_user_id, p_tenant_id, now() + p_ttl, p_ip,
                      left(p_user_agent, 256))
              RETURNING id, auth.session.expires_at;
          END $$
    """,
    "auth.resolve_session(bytea, interval)": f"""
        CREATE FUNCTION auth.resolve_session(p_token_hash bytea, p_idle interval)
          RETURNS TABLE (session_id uuid, user_id uuid, email text, display_name text,
                         tenant_id uuid, tenant_name text, role text, expires_at timestamptz)
          LANGUAGE plpgsql {DEFINER}
          AS $$
          DECLARE s auth.session%ROWTYPE;
          BEGIN
            SELECT * INTO s FROM auth.session x
              WHERE x.token_hash = p_token_hash AND x.revoked_at IS NULL
                AND x.expires_at > now() AND x.last_seen_at > now() - p_idle;
            IF NOT FOUND THEN RETURN; END IF;
            PERFORM set_config('app.user_id', s.user_id::text, true);
            PERFORM set_config('app.tenant_id', s.tenant_id::text, true);
            -- Role, membership and account status are read fresh on every request, so a
            -- removed member or a deactivated account loses access immediately.
            RETURN QUERY
              SELECT s.id, u.id, u.email, u.display_name, t.id, t.name, m.role, s.expires_at
              FROM auth.user_account u
              JOIN app.membership m ON m.user_id = u.id AND m.tenant_id = s.tenant_id
              JOIN app.tenant t ON t.id = s.tenant_id
              WHERE u.id = s.user_id AND u.is_active;
            IF FOUND THEN
              UPDATE auth.session SET last_seen_at = now()
                WHERE id = s.id AND last_seen_at < now() - interval '30 seconds';
            END IF;
          END $$
    """,
    "auth.revoke_session(bytea)": f"""
        CREATE FUNCTION auth.revoke_session(p_token_hash bytea)
          RETURNS void LANGUAGE sql {DEFINER}
          AS $$ UPDATE auth.session SET revoked_at = now()
                WHERE token_hash = p_token_hash AND revoked_at IS NULL $$
    """,
    "auth.tenant_members()": f"""
        CREATE FUNCTION auth.tenant_members()
          RETURNS TABLE (user_id uuid, email text, display_name text, is_active boolean,
                         role text, joined_at timestamptz)
          LANGUAGE sql STABLE {DEFINER}
          -- Scoped by the caller's tenant context; RLS on membership applies as well.
          AS $$ SELECT u.id, u.email, u.display_name, u.is_active, m.role, m.created_at
                FROM app.membership m JOIN auth.user_account u ON u.id = m.user_id
                WHERE m.tenant_id = app.current_tenant()
                ORDER BY m.created_at, u.email $$
    """,
}


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION app.current_user_id() RETURNS uuid
          LANGUAGE sql STABLE
          AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$
        """
    )
    op.execute("REVOKE ALL ON FUNCTION app.current_user_id() FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION app.current_user_id() TO vulnex_app")

    # Readiness checks the schema revision as the application role.
    op.execute("GRANT SELECT ON public.alembic_version TO vulnex_app")

    # ---- auth: global identity, no direct access for vulnex_app ----
    op.execute("CREATE SCHEMA auth")
    op.execute("REVOKE ALL ON SCHEMA auth FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA auth TO vulnex_app")
    op.execute(
        """
        CREATE TABLE auth.user_account (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          email text NOT NULL UNIQUE
            CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
          display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
          password_hash text NOT NULL,
          is_active boolean NOT NULL DEFAULT true,
          created_at timestamptz NOT NULL DEFAULT now(),
          last_login_at timestamptz
        )
        """
    )

    # ---- app: tenant data under RLS ----
    op.execute(
        """
        CREATE TABLE app.tenant (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
          created_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        f"""
        CREATE TABLE app.membership (
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          user_id uuid NOT NULL REFERENCES auth.user_account (id),
          role text NOT NULL CHECK (role IN {ROLES}),
          created_at timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (tenant_id, user_id)
        )
        """
    )
    op.execute("CREATE INDEX membership_user_idx ON app.membership (user_id)")
    op.execute(
        """
        CREATE TABLE app.audit_event (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          occurred_at timestamptz NOT NULL DEFAULT now(),
          actor_user_id uuid,            -- no FK: the record outlives the account
          action text NOT NULL CHECK (action ~ '^[a-z_]+(\\.[a-z_]+)+$'),
          target_type text,
          target_id text,
          ip inet,
          request_id text,
          detail jsonb NOT NULL DEFAULT '{}'::jsonb
        )
        """
    )
    op.execute("CREATE INDEX audit_event_tenant_idx ON app.audit_event (tenant_id, id DESC)")

    # Tenants are created by provisioning, never deleted through the app role (PRD §10).
    op.execute("REVOKE DELETE, TRUNCATE ON app.tenant FROM vulnex_app")
    # Audit history is append-only for the application.
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON app.audit_event FROM vulnex_app")

    for table in ("tenant", "membership", "audit_event"):
        op.execute(f"ALTER TABLE app.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE app.{table} FORCE ROW LEVEL SECURITY")

    # Reads may also cover the signed-in user's own memberships (for the tenant picker);
    # writes are always confined to the current tenant.
    op.execute(
        """
        CREATE POLICY tenant_write ON app.tenant
          USING (id = app.current_tenant()) WITH CHECK (id = app.current_tenant())
        """
    )
    op.execute(
        """
        CREATE POLICY tenant_read_own ON app.tenant FOR SELECT
          USING (id IN (SELECT m.tenant_id FROM app.membership m
                        WHERE m.user_id = app.current_user_id()))
        """
    )
    op.execute(
        """
        CREATE POLICY tenant_isolation ON app.membership
          USING (tenant_id = app.current_tenant())
          WITH CHECK (tenant_id = app.current_tenant())
        """
    )
    op.execute(
        """
        CREATE POLICY membership_read_own ON app.membership FOR SELECT
          USING (user_id = app.current_user_id())
        """
    )
    op.execute(
        """
        CREATE POLICY tenant_isolation ON app.audit_event
          USING (tenant_id = app.current_tenant())
          WITH CHECK (tenant_id = app.current_tenant())
        """
    )

    op.execute(
        """
        CREATE TABLE auth.session (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
          user_id uuid NOT NULL REFERENCES auth.user_account (id) ON DELETE CASCADE,
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          created_at timestamptz NOT NULL DEFAULT now(),
          last_seen_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL,
          revoked_at timestamptz,
          ip inet,
          user_agent text
        )
        """
    )
    op.execute("CREATE INDEX session_user_idx ON auth.session (user_id)")
    op.execute(
        """
        CREATE TABLE auth.login_attempt (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          email text NOT NULL,
          ip inet,
          succeeded boolean NOT NULL,
          at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX login_attempt_email_idx ON auth.login_attempt (email, at)")
    op.execute("CREATE INDEX login_attempt_ip_idx ON auth.login_attempt (ip, at)")
    op.execute("CREATE INDEX login_attempt_at_idx ON auth.login_attempt (at)")

    for signature, ddl in FUNCTIONS.items():
        op.execute(ddl)
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO vulnex_app")


def downgrade() -> None:
    op.execute("DROP SCHEMA auth CASCADE")  # functions, sessions, accounts (and FKs into them)
    op.execute("DROP TABLE app.audit_event, app.membership, app.tenant")
    op.execute("REVOKE SELECT ON public.alembic_version FROM vulnex_app")
    op.execute("DROP FUNCTION app.current_user_id()")
