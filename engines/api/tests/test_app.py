"""API behaviour that needs no database. The DSN points at a closed port, so readiness must fail."""

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from vulnex.main import create_app
from vulnex.settings import Settings

UNREACHABLE = "postgresql+psycopg://nobody:x@127.0.0.1:1/none"


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Settings(database_url=SecretStr(UNREACHABLE))))


def test_liveness_needs_no_database(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readiness_fails_closed_without_leaking_details(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.headers["content-type"] == "application/problem+json"
    body = r.json()
    assert body == {
        "type": "about:blank",
        "title": "Service Unavailable",
        "status": 503,
        "detail": "Database unavailable",
    }
    assert "127.0.0.1" not in r.text and "psycopg" not in r.text


def test_unknown_route_is_problem_json(client: TestClient) -> None:
    r = client.get("/nope")
    assert r.status_code == 404
    assert r.headers["content-type"] == "application/problem+json"
    assert r.json()["title"] == "Not Found"


def test_request_id_generated_and_safe_one_echoed(client: TestClient) -> None:
    generated = client.get("/healthz").headers["x-request-id"]
    assert len(generated) == 32

    assert (
        client.get("/healthz", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"]
        == "abc-123"
    )

    for hostile in ('a"; DROP TABLE x', "y" * 65, "<script>"):
        echoed = client.get("/healthz", headers={"X-Request-ID": hostile}).headers["x-request-id"]
        assert echoed != hostile and len(echoed) == 32


def test_unhandled_error_is_generic_500(client: TestClient) -> None:
    def boom() -> None:
        raise RuntimeError("secret internal detail")

    client.app.add_api_route("/boom", boom)  # type: ignore[attr-defined]
    r = client.get("/boom")
    assert r.status_code == 500
    assert r.json() == {"type": "about:blank", "title": "Internal Server Error", "status": 500}
    assert "secret" not in r.text
    assert r.headers["x-request-id"]


def test_openapi_is_versioned(client: TestClient) -> None:
    assert client.get("/api/v1/openapi.json").status_code == 200
