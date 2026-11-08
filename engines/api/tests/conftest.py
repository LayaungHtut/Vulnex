"""Shared fixtures. Database tests need VULNEX_TEST_OWNER_URL and VULNEX_TEST_APP_URL pointing at
the scratch `vulnex_test` database (see DEVELOPMENT.md); they are skipped, visibly, without them.
The schema is rebuilt (downgrade to base, upgrade to head) once per test session."""

import os
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, create_engine

from vulnex.cli import create_organization
from vulnex.main import create_app
from vulnex.pki import init_pki
from vulnex.settings import Settings
from vulnex.worker_api import create_worker_app

OWNER_URL = os.environ.get("VULNEX_TEST_OWNER_URL")
APP_URL = os.environ.get("VULNEX_TEST_APP_URL")

needs_db = [
    pytest.mark.db,
    pytest.mark.skipif(not (OWNER_URL and APP_URL), reason="VULNEX_TEST_*_URL not set"),
]

PASSWORD = "correct horse battery staple"


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    if url:
        cfg.attributes["url"] = url
    return cfg


@pytest.fixture(scope="session")
def migrated() -> None:
    assert OWNER_URL
    cfg = alembic_config(OWNER_URL)
    command.downgrade(cfg, "base")  # migrations must round-trip on a scratch database
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def app_engine(migrated: None) -> Iterator[Engine]:
    assert APP_URL
    engine = create_engine(APP_URL, pool_size=1, max_overflow=0)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def owner_engine(migrated: None) -> Iterator[Engine]:
    assert OWNER_URL
    engine = create_engine(OWNER_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def pki_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("pki")
    init_pki(d, ["localhost", "127.0.0.1"])
    return d


@pytest.fixture(scope="session")
def client(migrated: None, pki_dir: Path) -> TestClient:
    assert APP_URL
    settings = Settings(
        database_url=SecretStr(APP_URL),
        worker_endpoint_url="https://localhost:8443",
        worker_endpoint_ca_file=pki_dir / "server-ca.crt",
    )
    return TestClient(create_app(settings))


@pytest.fixture(scope="session")
def wclient(migrated: None, pki_dir: Path) -> TestClient:
    """The worker API. No `with` block, so its sweeper thread stays off in tests."""
    assert APP_URL
    settings = Settings(database_url=SecretStr(APP_URL), worker_pki_dir=pki_dir)
    return TestClient(create_worker_app(settings))


@dataclass
class Org:
    id: uuid.UUID
    owner_id: uuid.UUID
    owner_email: str


def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}@example.test"


@pytest.fixture
def make_org(app_engine: Engine) -> Callable[..., Org]:
    def make(name: str = "Org") -> Org:
        email = unique_email("owner")
        org_id, user_id = create_organization(app_engine, name, email, "Owner", PASSWORD)
        return Org(org_id, user_id, email)

    return make


def login(client: TestClient, email: str, password: str = PASSWORD, **extra: object) -> str:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password, **extra})
    assert r.status_code == 200, r.text
    token: str = r.json()["token"]
    return token


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def api_operations(app: FastAPI) -> set[tuple[str, str]]:
    """Every (METHOD, path) under /api/v1/.

    Collected two ways that must agree: walking the routers (FastAPI >= 0.16x nests included
    routers lazily) and the public OpenAPI schema. If either breaks in a FastAPI upgrade, the
    tests using this fail loudly instead of silently checking nothing. Routes under /api/v1/
    must therefore not use include_in_schema=False.
    """
    found: set[tuple[str, str]] = set()

    def walk(routes: Sequence[object]) -> None:
        for r in routes:
            inner = getattr(r, "original_router", None)
            if inner is not None:
                walk(inner.routes)
            elif isinstance(r, APIRoute) and r.path.startswith("/api/v1/"):
                found.update((m, r.path) for m in r.methods or ())

    walk(app.routes)
    schema = {
        (method.upper(), path)
        for path, ops in app.openapi()["paths"].items()
        if path.startswith("/api/v1/")
        for method in ops
    }
    assert found == schema, found ^ schema
    assert found, "no /api/v1 routes found"
    return found
