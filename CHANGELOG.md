# Changelog

All notable changes to VULNEX. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [SemVer](https://semver.org/) once releases begin; until then entries are grouped by milestone.

## [Unreleased]

### Added — M4 increment 1: job queue (not yet committed)

- ADR-0003 (PROPOSED): PostgreSQL pull queue with at-least-once delivery and idempotent effects.
- Migration `0004`: `app.worker` (tenant- and scope-group-bound, FORCE RLS, not deletable by the application role) and schema `queue` (jobs, results, quarantine), reachable only through `SECURITY DEFINER` functions: `enqueue_scan_task`, `claim_for_worker`, `extend`, `submit_result`, `complete`, `request_cancel`, `sweep`.
- Deleting a scope group that a worker or job still uses returns 409 instead of 500.
- Tests: 27 queue tests (concurrent claimers, tenant and scope-group isolation, leases, duplicates, stale-result quarantine, retries and backoff, cancellation, concurrent sweepers, privileges).

### Added — M3 authorized scope and asset inventory (committed `8d6912a`)

- Migration `0003`: `app.scope_group`, `app.scope_entry`, `app.asset` under FORCE RLS, with composite `(tenant_id, id)` foreign keys; assets cannot be deleted by the application role (retire instead).
- Strict target parsing (`vulnex.targets`, ADR-0006 §5 steps 1–5): canonical dotted-decimal IPv4 only (integer, hex, octal, short and zero-padded forms are rejected, never reinterpreted); CIDR host bits must be zero; IPv6 refused in v0; loopback, link-local (cloud metadata), "this network", multicast and reserved ranges are never accepted; URLs, ports and non-ASCII hostnames rejected with specific messages.
- Scope groups with included and excluded ranges, hostnames and `*.` subdomain wildcards. Owner/administrator authorization records a signed-in attestation bound to a digest of the exact entries; any later change shows as "changed since authorization" until re-authorized; authorization can be withdrawn.
- Assets (IPv4 address, range up to /20, hostname) registered inside a scope group and refused when outside it; scope eligibility recomputed on every read; edit name, criticality and notes; retire and reactivate (which re-checks scope); search, filter and pagination.
- Permissions `scope.read`, `scope.manage`, `assets.read`, `assets.manage` (owner/admin manage; analyst reads both; viewer reads assets).
- API: `GET|POST /api/v1/scope-groups`, `GET|PATCH|DELETE /api/v1/scope-groups/{group_id}`, `POST /api/v1/scope-groups/{group_id}/entries`, `DELETE /api/v1/scope-groups/{group_id}/entries/{entry_id}`, `POST|DELETE /api/v1/scope-groups/{group_id}/authorization`, `GET|POST /api/v1/assets`, `GET|PATCH /api/v1/assets/{asset_id}`, `POST /api/v1/assets/{asset_id}/retire`, `POST /api/v1/assets/{asset_id}/reactivate`; `GET /api/v1/audit-events` gains `target_type` / `target_id` filters (per-object history).
- Console: Assets (list, filters, register), asset detail (eligibility, edit, retire/reactivate, history), Authorized scope (list, create), scope group detail (entries, authorization, edit, delete).
- Tests: 69 parser and scope-membership cases, scope and asset API behaviour, role matrix, 15 new cross-tenant probes, composite-foreign-key rejection, append-only and undeletable privileges, console action helpers.

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
