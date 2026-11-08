import logging
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException

from vulnex import __version__, assets, audit, auth, logs, members, scans, scope, workers
from vulnex.db import SCHEMA_REVISION, make_engine, schema_revision
from vulnex.settings import Settings

log = logging.getLogger("vulnex.api")

# Accept a caller's request ID only if it is short and plain, so it is safe to log and echo.
_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


def problem(status: int, detail: str | None = None, **extra: Any) -> JSONResponse:
    """RFC 9457 problem details. Never put exception text or internal state in `detail`."""
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": HTTPStatus(status).phrase,
        "status": status,
    }
    if detail:
        body["detail"] = detail
    body.update(extra)
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()  # pyright: ignore[reportCallIssue]  # values come from env
    logs.configure(settings.log_level)
    engine = make_engine(settings.database_url.get_secret_value())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="VULNEX API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/v1/docs",
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.state.engine = engine
    app.state.settings = settings
    for module in (auth, members, audit, scope, assets, workers, scans):
        app.include_router(module.router)
    install_common(app, engine)
    return app


def install_common(app: FastAPI, engine: Engine) -> None:
    """Request IDs and logging, problem-details errors, health checks (shared with worker API)."""

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _REQUEST_ID.fullmatch(incoming) else uuid.uuid4().hex
        token = logs.request_id.set(rid)
        start = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:
                log.exception("unhandled error")
                response = problem(500)
            response.headers["X-Request-ID"] = rid
            log.info(
                "request",
                extra={
                    "fields": {
                        "method": request.method,
                        "path": request.url.path,
                        "status": response.status_code,
                        "ms": round((time.perf_counter() - start) * 1000, 1),
                    }
                },
            )
            return response
        finally:
            logs.request_id.reset(token)

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if exc.detail != HTTPStatus(exc.status_code).phrase else None
        response = problem(exc.status_code, detail)
        response.headers.update(exc.headers or {})
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Drop `input`/`ctx`: they echo caller data back and can be large.
        errors = [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        return problem(422, "Request validation failed", errors=errors)

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        """Liveness: the process is serving requests. No dependencies are checked."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"], response_model=None)
    def readyz() -> dict[str, str] | JSONResponse:
        """Readiness: the database accepts the application role and its schema is current."""
        try:
            with engine.connect() as conn:
                revision = schema_revision(conn)
        except SQLAlchemyError:
            log.warning("readiness check failed", exc_info=True)
            return problem(503, "Database unavailable")
        if revision != SCHEMA_REVISION:
            log.warning(
                "schema revision mismatch",
                extra={"fields": {"found": revision, "expected": SCHEMA_REVISION}},
            )
            return problem(503, "Database schema is not at the expected revision")
        return {"status": "ready", "version": __version__}
