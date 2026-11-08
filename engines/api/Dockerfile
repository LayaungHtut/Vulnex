# Build context: repository root (the uv workspace lockfile lives there).
FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.3 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR /src
COPY pyproject.toml uv.lock .python-version ./
COPY engines/api engines/api
COPY packages/worker-protocol packages/worker-protocol
COPY engines/scanner/pyproject.toml engines/scanner/pyproject.toml
RUN uv sync --locked --no-dev --no-editable --package vulnex \
    && useradd --system --no-create-home vulnex

USER vulnex
WORKDIR /src/engines/api
EXPOSE 8000
CMD ["uvicorn", "--factory", "vulnex.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
