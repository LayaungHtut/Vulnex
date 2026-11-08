# Development

How to run and check VULNEX locally. This describes what exists today (M1 foundation + M2 identity). Planned layout: [ADR-0002](docs/decisions/ADR-0002.md) (PROPOSED).

## Layout

| Path                    | What                                                                                |
| ----------------------- | ----------------------------------------------------------------------------------- |
| `src/`, root JS configs | SvelteKit console (moves to `apps/console` per ADR-0002; not done yet)              |
| `engines/api/`          | FastAPI control plane, Python package `vulnex`, Alembic migrations, operator CLI    |
| `deploy/compose/`       | Local stack: PostgreSQL 17, migrations, API                                         |
| `scripts/`              | `check-api.sh` (Python checks in a container), `hooks/pre-commit` (opt-in git hook) |
| `pyproject.toml`        | uv workspace root; shared ruff, mypy, pytest config                                 |

## Prerequisites

Node 24, Python 3.13, [uv](https://docs.astral.sh/uv/) 0.13, Docker with Compose.

**Windows with Smart App Control on:** it blocks unsigned compiled Python extensions (SQLAlchemy, mypy, argon2) in the host `.venv`, so `uv run pytest` / `uv run mypy` fail with "An Application Control policy has blocked this file". Run the Python checks with `sh scripts/check-api.sh` instead (Linux container, same as CI). `uv run ruff` still works on the host.

## First run

```sh
npm install
cp deploy/compose/.env.example deploy/compose/.env   # set real values: openssl rand -hex 24
docker compose -f deploy/compose/compose.yaml up -d --build
curl http://127.0.0.1:8000/readyz                    # {"status":"ready",...}

# Create the first organization and its owner (prompts for a 12-128 character password):
docker compose -f deploy/compose/compose.yaml run --rm -it api \
  python -m vulnex.cli create-organization --name "My Org" --owner-email you@example.com --owner-name "Your Name"

npm run dev -- --host 127.0.0.1                     # console at http://127.0.0.1:5173, sign in
git config core.hooksPath scripts/hooks              # optional: secret scan + format checks on commit
```

- There is no self-registration. Owners and administrators add members on the Members page.
- The database init script creates the roles `vulnex_owner` (migrations) and `vulnex_app` (API; no superuser, no `BYPASSRLS`) and the databases `vulnex` and `vulnex_test`. It runs **only on an empty volume**. After changing it, recreate the volume with `docker compose -f deploy/compose/compose.yaml down -v`. This deletes all local data.
- If port 5432 is taken, set `VULNEX_DB_PORT` in `deploy/compose/.env`.
- The console reads `VULNEX_API_URL` (default `http://127.0.0.1:8000`), declared in `src/env.ts`. Vite binds only IPv6 `localhost` by default on this machine, hence `--host 127.0.0.1`.
- API docs: http://127.0.0.1:8000/api/v1/docs

## Checks (run before claiming anything works)

```sh
npm run lint && npm run check && npx vitest run --project server
docker compose -f deploy/compose/compose.yaml up -d db   # database tests need it
sh scripts/check-api.sh                                  # ruff, ruff format, mypy --strict, pytest (incl. DB tests)
npx playwright test                                      # e2e; API stack must be up; first time: npx playwright install chromium
```

`scripts/check-api.sh` sets `VULNEX_TEST_OWNER_URL` / `VULNEX_TEST_APP_URL` from `deploy/compose/.env`. Without those variables, `uv run pytest` **skips** the database tests (CI always sets them). The database tests run migrations down to base and back up on `vulnex_test`; they never touch `vulnex`. Run one test: `sh scripts/check-api.sh pytest -k throttled`.

## Sessions and CSRF (how the pieces fit)

- The API accepts sessions only as `Authorization: Bearer`, never from cookies, so it is not CSRF-exposed. The console keeps the token in an HttpOnly, SameSite=Lax cookie (`vulnex_session`) and calls the API server-side.
- SvelteKit rejects cross-origin form posts **in production builds only**; `vite dev` skips that check. Test CSRF against `npm run build` output.
- `adapter-node` 6 derives the origin from the request: with plain HTTP behind no proxy, set `PROTOCOL_HEADER=x-forwarded-proto` and have the proxy send it, or all form posts fail the origin check. Over HTTPS nothing is needed.
- The console forwards the browser's address in `X-Forwarded-For`. The API believes it only from `VULNEX_TRUSTED_PROXIES` (Compose default: the Docker bridge range), so sign-in throttling and audit entries see real client addresses.

## Migrations

```sh
cd engines/api
VULNEX_MIGRATION_DATABASE_URL=postgresql+psycopg://vulnex_owner:...@127.0.0.1:5432/vulnex uv run alembic upgrade head
uv run alembic revision -m "describe change"   # write the SQL by hand; no autogenerate yet
```

After adding a migration, bump `SCHEMA_REVISION` in `engines/api/src/vulnex/db.py` (a test enforces it; `/readyz` reports 503 until the database is migrated).

Every tenant-owned table must follow [ADR-0005](docs/decisions/ADR-0005.md): `tenant_id`, composite foreign keys, `ENABLE` + `FORCE ROW LEVEL SECURITY`, and a policy, all in the same migration. `test_every_app_table_has_forced_rls_and_a_policy` fails otherwise. Every new `/api/v1` route needs a two-tenant probe in `engines/api/tests/test_tenant_isolation.py`; `test_every_route_is_in_the_matrix` fails otherwise.
