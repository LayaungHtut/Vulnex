# Changelog

All notable changes to VULNEX. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [SemVer](https://semver.org/) once releases begin; until then entries are grouped by milestone.

## [Unreleased]

### Added — M2 identity and organizations (committed 2026-11-08)

- Migration `0002`: `app.tenant`, `app.membership`, `app.audit_event` under FORCE RLS; global identity in schema `auth`, reachable only through `SECURITY DEFINER` functions; append-only audit; `app.current_user_id()`.
- Password sign-in with Argon2id; opaque bearer sessions (SHA-256 at rest, 12 h absolute, 30 min idle); logout; per-email and per-address throttling; unknown emails cost the same time as known ones.
- Roles owner, administrator, analyst, remediation contributor and viewer, with server-side permission checks. Add members, change roles, remove members; only owners change owner access; the last owner is protected.
- API: `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/session`, `GET /api/v1/organization`, `GET|POST /api/v1/members`, `PATCH|DELETE /api/v1/members/{user_id}`, `GET /api/v1/audit-events`.
- Operator CLI `python -m vulnex.cli create-organization` (controlled provisioning; no self-registration).
- Console: sign-in, sign-out, signed-in shell with role-aware navigation, Overview, Members, Audit log; HttpOnly session cookie; security headers; open-redirect guard.
- Trusted-proxy handling of `X-Forwarded-For` (`VULNEX_TRUSTED_PROXIES`).
- Tests: ADR-0005 gates (RLS coverage, no-context reads, cross-tenant writes, route matrix, pool leakage, definer functions, privileges), authentication and membership behaviour, console unit tests, first Playwright e2e run.

### Added — development hygiene

- Development hygiene: Dependabot (npm, uv, GitHub Actions, Docker), `SECURITY.md`, this changelog, an opt-in pre-commit hook (`scripts/hooks/pre-commit`: gitleaks, ruff, prettier on staged files).
- `/readyz` also reports `503` when the database schema is not at the revision the API expects.
- Console builds with `@sveltejs/adapter-node` for self-hosted deployment (founder D2).

### Removed

- SvelteKit template example code (`src/lib/vitest-examples`).

## M1 application foundation — 2026-11-08 (`66a3fdb`, not released)

### Added

- FastAPI control plane: JSON logs with request IDs, RFC 9457 problem responses, `/healthz`, `/readyz`, OpenAPI under `/api/v1`.
- Alembic baseline `0001`: `app` schema, fail-closed `app.current_tenant()`, least-privilege `vulnex_app` role.
- Docker Compose development stack (PostgreSQL 17, migrations, API) bound to loopback.
- Console status page backed by the real API.
- CI workflow (console, API with PostgreSQL, gitleaks). Not yet run on GitHub.
- `scripts/check-api.sh`: Python checks in a Linux container.

## Phase 0 documentation — 2026-11-06 (`d7df12e`)

### Added

- PRD v0.1, competitive research, initial architecture, threat model, ADR-0001, research plan, roadmap, Definition of Done.
