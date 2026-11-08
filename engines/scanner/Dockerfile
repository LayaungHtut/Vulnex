# Build context: repository root (the uv workspace lockfile lives there).
FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.13.3 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    VULNEX_SCANNER_STATE=/var/lib/vulnex-scanner

WORKDIR /src
COPY pyproject.toml uv.lock .python-version ./
COPY engines/api/pyproject.toml engines/api/pyproject.toml
COPY engines/scanner engines/scanner
COPY packages/worker-protocol packages/worker-protocol
RUN uv sync --locked --no-dev --no-editable --package vulnex-scanner \
    && rm -rf /src \
    && useradd --system --no-create-home scanner \
    && install -d -o scanner -m 0700 /var/lib/vulnex-scanner

USER scanner
WORKDIR /
ENTRYPOINT ["vulnex-scanner"]
CMD ["run"]
