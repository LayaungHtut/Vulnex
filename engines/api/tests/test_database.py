"""Empirical checks of ADR-0005 tenant-context behaviour against real PostgreSQL, as `vulnex_app`.

Needs VULNEX_TEST_OWNER_URL and VULNEX_TEST_APP_URL pointing at the `vulnex_test` database
(see DEVELOPMENT.md). Skipped, visibly, when they are unset; CI always sets them.
"""

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from vulnex.main import create_app
from vulnex.settings import Settings

OWNER_URL = os.environ.get("VULNEX_TEST_OWNER_URL")
APP_URL = os.environ.get("VULNEX_TEST_APP_URL")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not (OWNER_URL and APP_URL), reason="VULNEX_TEST_*_URL not set"),
]

SET_TENANT = text("SELECT set_config('app.tenant_id', :t, true)")
CURRENT = text("SELECT app.current_tenant()")


def alembic(url: str) -> Config:
    cfg = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    cfg.attributes["url"] = url
    return cfg


@pytest.fixture(scope="module")
def app_engine() -> Iterator[Engine]:
    assert OWNER_URL and APP_URL
    cfg = alembic(OWNER_URL)
    command.downgrade(cfg, "base")  # migrations must round-trip on a scratch database
    command.upgrade(cfg, "head")
    engine = create_engine(APP_URL, pool_size=1, max_overflow=0)
    yield engine
    engine.dispose()


def test_no_tenant_context_is_null(app_engine: Engine) -> None:
    with app_engine.connect() as c:
        assert c.execute(CURRENT).scalar() is None


def test_tenant_context_is_transaction_local_on_a_reused_connection(app_engine: Engine) -> None:
    tenant = uuid.uuid4()
    with app_engine.connect() as c:
        with c.begin():
            c.execute(SET_TENANT, {"t": str(tenant)})
            assert c.execute(CURRENT).scalar() == tenant
        # Same physical connection, new transaction: the setting now reads '' and must map to NULL.
        with c.begin():
            assert c.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar() == ""
            assert c.execute(CURRENT).scalar() is None
    # pool_size=1: the next checkout is that same connection, returned to the pool.
    with app_engine.connect() as c:
        assert c.execute(CURRENT).scalar() is None


def test_tenant_context_reset_after_rollback(app_engine: Engine) -> None:
    with app_engine.connect() as c:
        tx = c.begin()
        c.execute(SET_TENANT, {"t": str(uuid.uuid4())})
        tx.rollback()
        assert c.execute(CURRENT).scalar() is None


def test_malformed_tenant_id_errors_instead_of_matching(app_engine: Engine) -> None:
    with app_engine.connect() as c, pytest.raises(DBAPIError), c.begin():
        c.execute(SET_TENANT, {"t": "' OR 1=1 --"})
        c.execute(CURRENT)


def test_app_role_is_unprivileged(app_engine: Engine) -> None:
    with app_engine.connect() as c:
        row = c.execute(
            text(
                "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one()
        assert tuple(row) == (False, False, False, False)
        assert c.execute(text("SELECT current_user")).scalar() == "vulnex_app"


def test_app_role_cannot_create_objects(app_engine: Engine) -> None:
    for schema in ("app", "public"):
        with app_engine.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
            c.execute(text(f"CREATE TABLE {schema}.x (id int)"))


def test_app_role_cannot_become_owner(app_engine: Engine) -> None:
    with app_engine.connect() as c, pytest.raises(ProgrammingError, match="permission denied"):
        c.execute(text("SET ROLE vulnex_owner"))


def test_readiness_with_real_database(app_engine: Engine) -> None:
    assert APP_URL
    client = TestClient(create_app(Settings(database_url=SecretStr(APP_URL))))
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"
