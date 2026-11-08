"""Database access: engine, tenant-scoped transactions, schema revision (ADR-0005)."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from sqlalchemy import Connection, Engine, create_engine, text

if TYPE_CHECKING:
    from vulnex.authz import Principal

# The Alembic revision this code expects. A test keeps it equal to the migrations' head.
SCHEMA_REVISION = "0006"

_SET_CONTEXT = text(
    "SELECT set_config('app.user_id', :user_id, true), "
    "set_config('app.tenant_id', :tenant_id, true)"
)


def make_engine(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 3})


@contextmanager
def tenant_tx(engine: Engine, principal: "Principal") -> Iterator[Connection]:
    """One transaction with the principal's user and tenant as RLS context.

    The settings are transaction-local, so they end with the commit or rollback and cannot
    leak to the next request through the connection pool. The tenant comes only from the
    authenticated session, never from the request body or URL.
    """
    with engine.begin() as conn:
        conn.execute(
            _SET_CONTEXT,
            {"user_id": str(principal.user_id), "tenant_id": str(principal.tenant_id)},
        )
        yield conn


def schema_revision(conn: Connection) -> str | None:
    return conn.execute(text("SELECT version_num FROM public.alembic_version")).scalar()
