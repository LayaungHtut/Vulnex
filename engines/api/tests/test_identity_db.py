"""ADR-0005 §6 database gates for the M2 identity schema, run as `vulnex_app` (never as owner)."""

import re
import uuid
from collections.abc import Callable

import pytest
from conftest import Org, needs_db
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

pytestmark = needs_db

CONTEXT = text("SELECT set_config('app.tenant_id', :t, true), set_config('app.user_id', :u, true)")


def as_tenant(conn: Connection, tenant: uuid.UUID, user: uuid.UUID | None = None) -> None:
    conn.execute(CONTEXT, {"t": str(tenant), "u": str(user) if user else ""})


def app_tables(conn: Connection) -> list[str]:
    return list(
        conn.execute(
            text(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'app' AND c.relkind = 'r' ORDER BY 1"
            )
        ).scalars()
    )


def test_every_app_table_has_forced_rls_and_a_policy(owner_engine: Engine) -> None:
    with owner_engine.connect() as c:
        rows = c.execute(
            text(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                "  (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'app' AND c.relkind = 'r'"
            )
        ).all()
    assert {r[0] for r in rows} >= {"tenant", "membership", "audit_event"}
    for name, enabled, forced, policies in rows:
        assert enabled and forced and policies > 0, f"app.{name} lacks forced RLS or a policy"


def test_no_context_reads_nothing(app_engine: Engine, make_org: Callable[..., Org]) -> None:
    make_org()
    with app_engine.connect() as c:
        for table in app_tables(c):
            assert c.execute(text(f"SELECT count(*) FROM app.{table}")).scalar() == 0, table


def test_tenant_sees_only_itself(app_engine: Engine, make_org: Callable[..., Org]) -> None:
    a, b = make_org("A"), make_org("B")
    with app_engine.begin() as c:
        as_tenant(c, a.id)
        assert set(c.execute(text("SELECT id FROM app.tenant")).scalars()) == {a.id}
        members = set(c.execute(text("SELECT user_id FROM app.membership")).scalars())
        assert members == {a.owner_id}
        tenants = set(c.execute(text("SELECT tenant_id FROM app.audit_event")).scalars())
        assert tenants == {a.id}
        assert b.id not in tenants


def test_cross_tenant_writes_are_rejected(app_engine: Engine, make_org: Callable[..., Org]) -> None:
    a, b = make_org("A"), make_org("B")
    for stmt, params in [
        (
            "INSERT INTO app.membership (tenant_id, user_id, role) VALUES (:b, :u, 'viewer')",
            {"b": b.id, "u": a.owner_id},
        ),
        ("INSERT INTO app.audit_event (tenant_id, action) VALUES (:b, 'x.y')", {"b": b.id}),
        ("INSERT INTO app.tenant (id, name) VALUES (gen_random_uuid(), 'evil')", {}),
    ]:
        with (
            app_engine.connect() as c,
            pytest.raises(ProgrammingError, match="row-level"),
            c.begin(),
        ):
            as_tenant(c, a.id)
            c.execute(text(stmt), params)

    # Updates and deletes aimed at B from A's context touch nothing.
    with app_engine.begin() as c:
        as_tenant(c, a.id)
        assert (
            c.execute(
                text("UPDATE app.tenant SET name = 'pwned' WHERE id = :b"), {"b": b.id}
            ).rowcount
            == 0
        )
        assert (
            c.execute(text("DELETE FROM app.membership WHERE tenant_id = :b"), {"b": b.id}).rowcount
            == 0
        )


def test_own_membership_visibility_does_not_allow_writes_elsewhere(
    app_engine: Engine, make_org: Callable[..., Org]
) -> None:
    """The user-scoped read policy (tenant picker) must not open writes in other tenants."""
    a, b = make_org("A"), make_org("B")
    with app_engine.begin() as c:
        # B's owner joins A as a viewer.
        as_tenant(c, a.id)
        c.execute(
            text("INSERT INTO app.membership (tenant_id, user_id, role) VALUES (:a, :u, 'viewer')"),
            {"a": a.id, "u": b.owner_id},
        )
    with app_engine.begin() as c:
        as_tenant(c, b.id, b.owner_id)  # acting in B, as B's owner
        seen = set(
            c.execute(
                text("SELECT tenant_id FROM app.membership WHERE user_id = :u"), {"u": b.owner_id}
            ).scalars()
        )
        assert seen == {a.id, b.id}
        assert set(c.execute(text("SELECT id FROM app.tenant")).scalars()) == {a.id, b.id}
        # ...but cannot promote itself in A, or remove itself from A, from B's context.
        assert (
            c.execute(
                text("UPDATE app.membership SET role = 'owner' WHERE tenant_id = :a"), {"a": a.id}
            ).rowcount
            == 0
        )
        assert (
            c.execute(text("DELETE FROM app.membership WHERE tenant_id = :a"), {"a": a.id}).rowcount
            == 0
        )
        assert (
            c.execute(text("UPDATE app.tenant SET name = 'x' WHERE id = :a"), {"a": a.id}).rowcount
            == 0
        )


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE app.audit_event SET action = 'x.y'",
        "DELETE FROM app.audit_event",
        "DELETE FROM app.tenant",
        "TRUNCATE app.audit_event",
        "DELETE FROM app.asset",
        "TRUNCATE app.asset",
        "TRUNCATE app.scope_group",
        "TRUNCATE app.scope_entry",
    ],
)
def test_append_only_and_undeletable_tables(app_engine: Engine, stmt: str) -> None:
    with app_engine.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
        c.execute(text(stmt))


@pytest.mark.parametrize("table", ["user_account", "session", "login_attempt"])
def test_app_role_has_no_direct_access_to_identity_tables(app_engine: Engine, table: str) -> None:
    with app_engine.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
        c.execute(text(f"SELECT * FROM auth.{table}"))


def test_definer_functions_have_fixed_search_path_and_are_not_public(owner_engine: Engine) -> None:
    with owner_engine.connect() as c:
        rows = c.execute(
            text(
                "SELECT p.proname, p.proconfig, p.proacl::text, pg_get_userbyid(p.proowner) "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname IN ('auth', 'queue') AND p.prosecdef"
            )
        ).all()
    assert len(rows) == 9 + 7 + 10  # auth (M2) + queue (M4) + workers and scans (M4)
    for name, config, acl, owner in rows:
        assert owner == "vulnex_owner", name
        assert config == ["search_path=pg_catalog, pg_temp"], name
        assert not re.search(r"[{,]=X", acl), f"{name} is executable by PUBLIC"
        assert "vulnex_app=X/" in acl, name


def test_tenant_members_is_scoped_to_the_callers_tenant(
    app_engine: Engine, make_org: Callable[..., Org]
) -> None:
    a, b = make_org("A"), make_org("B")
    with app_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM auth.tenant_members()")).scalar() == 0
        as_tenant(c, a.id)
        rows = c.execute(text("SELECT user_id, email FROM auth.tenant_members()")).all()
    assert [tuple(r) for r in rows] == [(a.owner_id, a.owner_email)]
    assert b.owner_email not in str(rows)


def test_create_session_requires_membership(
    app_engine: Engine, make_org: Callable[..., Org]
) -> None:
    a, b = make_org("A"), make_org("B")
    with (
        app_engine.connect() as c,
        pytest.raises(DBAPIError, match="no active membership"),
        c.begin(),
    ):
        c.execute(
            text("SELECT * FROM auth.create_session(:u, :t, :d, interval '1 hour', NULL, '')"),
            {"u": a.owner_id, "t": b.id, "d": b"\x00" * 32},
        )


def test_composite_keys_reject_references_into_another_tenant(
    app_engine: Engine, make_org: Callable[..., Org]
) -> None:
    """A row in A's tenant cannot point at B's scope group, even with A's tenant_id (M3)."""
    a, b = make_org("A"), make_org("B")
    with app_engine.begin() as c:
        as_tenant(c, b.id)
        b_group = c.execute(
            text("INSERT INTO app.scope_group (tenant_id, name) VALUES (:b, 'b') RETURNING id"),
            {"b": b.id},
        ).scalar_one()
    for stmt in (
        "INSERT INTO app.scope_entry (tenant_id, scope_group_id, kind, value) "
        "VALUES (:a, :g, 'cidr', '10.0.0.0/8')",
        "INSERT INTO app.asset (tenant_id, scope_group_id, kind, target) "
        "VALUES (:a, :g, 'ip', '10.0.0.1')",
    ):
        with (
            app_engine.connect() as c,
            pytest.raises(IntegrityError, match="foreign key"),
            c.begin(),
        ):
            as_tenant(c, a.id)
            c.execute(text(stmt), {"a": a.id, "g": b_group})
