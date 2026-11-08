# Development

How to run and check VULNEX locally. This describes what exists today (M1 foundation). Planned layout: [ADR-0002](docs/decisions/ADR-0002.md) (PROPOSED).

## Layout

| Path                    | What                                                                   |
| ----------------------- | ---------------------------------------------------------------------- |
| `src/`, root JS configs | SvelteKit console (moves to `apps/console` per ADR-0002; not done yet) |
| `engines/api/`          | FastAPI control plane, Python package `vulnex`, Alembic migrations     |
| `deploy/compose/`       | Local stack: PostgreSQL 17, migrations, API                            |
| `pyproject.toml`        | uv workspace root; shared ruff, mypy, pytest config                    |

## Prerequisites

Node 24, Python 3.13, [uv](https://docs.astral.sh/uv/) 0.13, Docker with Compose.

## First run

```sh
npm install
uv sync
cp deploy/compose/.env.example deploy/compose/.env   # set real values: openssl rand -hex 24
docker compose -f deploy/compose/compose.yaml up -d --build
curl http://127.0.0.1:8000/readyz                    # {"status":"ready",...}
npm run dev                                           # console at http://localhost:5173
```

- The database init script creates the roles `vulnex_owner` (migrations) and `vulnex_app` (API; no superuser, no `BYPASSRLS`) and the databases `vulnex` and `vulnex_test`. It runs **only on an empty volume**. After changing it, recreate the volume with `docker compose -f deploy/compose/compose.yaml down -v`. This deletes all local data.
- If port 5432 is taken, set `VULNEX_DB_PORT` in `deploy/compose/.env`.
- The console reads `VULNEX_API_URL` (default `http://127.0.0.1:8000`), declared in `src/env.ts`.
- API docs: http://127.0.0.1:8000/api/v1/docs

## Checks (run before claiming anything works)

```sh
npm run lint && npm run check && npx vitest run --project server
uv run ruff check && uv run ruff format --check && uv run mypy engines/api
uv run pytest
```

`uv run pytest` **skips** the database tests unless these are set (CI always sets them):

```sh
set -a; . deploy/compose/.env; set +a
export VULNEX_TEST_OWNER_URL="postgresql+psycopg://vulnex_owner:$VULNEX_OWNER_PASSWORD@127.0.0.1:${VULNEX_DB_PORT:-5432}/vulnex_test"
export VULNEX_TEST_APP_URL="postgresql+psycopg://vulnex_app:$VULNEX_APP_PASSWORD@127.0.0.1:${VULNEX_DB_PORT:-5432}/vulnex_test"
uv run pytest
```

The database tests run migrations down to base and back up on `vulnex_test`. They never touch `vulnex`.

## Migrations

```sh
cd engines/api
VULNEX_MIGRATION_DATABASE_URL=postgresql+psycopg://vulnex_owner:...@127.0.0.1:5432/vulnex uv run alembic upgrade head
uv run alembic revision -m "describe change"   # write the SQL by hand; no autogenerate yet
```

Every tenant-owned table must follow [ADR-0005](docs/decisions/ADR-0005.md): `tenant_id`, composite foreign keys, `ENABLE` + `FORCE ROW LEVEL SECURITY`, and a policy, all in the same migration.
