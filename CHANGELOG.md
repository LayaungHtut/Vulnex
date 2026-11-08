# Changelog

All notable changes to VULNEX. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [SemVer](https://semver.org/) once releases begin; until then entries are grouped by milestone.

## [Unreleased]

### Added — M6–M8: vulnerability intelligence, findings, risk, remediation workflow, console

- Migration `0007`: schema `intel` (global reference data; the application role may only `SELECT`): `intel.source` (per-feed status, upstream version, last success, error), `intel.cve`, `intel.cve_match` (NVD CPE ranges stored verbatim), `intel.kev`, `intel.epss`. Tenant tables `app.finding` (deduplicated per service and check, FORCE RLS, not deletable by the application role) and `app.finding_event` (append-only history).
- Intelligence sync (`vulnex.intel`, `python -m vulnex.cli intel-sync [--source …] [--every-hours N]`, runs as the owner role): CISA KEV (JSON), FIRST EPSS (daily gzip CSV, COPY-loaded), NVD CVE API 2.0 per fingerprinted product (incremental by `lastModStartDate`, rate-limited, optional `VULNEX_NVD_API_KEY`, one transaction per product). A failed feed keeps its last good data and records the error. Compose service `intel-sync` (opt-in profile `intel`, every 6 h).
- Deterministic checks (`vulnex.checks`, `checks-2026.11.1`): expired, expiring, self-signed, weak-key and name-mismatched TLS certificates; TLS 1.0/1.1 accepted; SSH protocol 1; Telnet and FTP exposure; Redis and memcached without authentication (from the read-only probe); reachable database listeners; Docker API without TLS; CVE correlation from the identified version against NVD ranges. A version match is always **POTENTIAL** (PRD A1, D3), with the distribution/backport caveat in the explanation; "every version" and platform-conditional CPE matches are not reported from a banner.
- Risk model `risk-v0.1` (`vulnex.risk`, PRD §15, PROPOSED): `5×severity + 20 KEV + exposure + criticality`, bands urgent/high/medium/low, KEV floors at high, EPSS shown but not scored, every factor returned with source and provisional flag.
- Finding lifecycle (`vulnex.findings`): evaluated in the transaction that ingests a discovery scan. Only a scan in which the same check ran on the same service and found the condition absent resolves a finding; closed ports, interrupted scans and checks that could not run are recorded as "verification inconclusive" and never resolve. Resolved or manually closed findings reopen on redetection; false positives and accepted risks stay. Statuses: open, triaged, in remediation, fix claimed, resolved, risk accepted (owner/admin only, reason and expiry ≤ 1 year, expires back to open), false positive and closed unverified (reason required).
- API: `GET /api/v1/findings` (filters, sorting, paging), `GET …/summary`, `GET …/export.csv` (formula-injection safe), `GET|PATCH /api/v1/findings/{id}`, `POST …/{id}/comments`, `POST /api/v1/findings/reassess`; `GET /api/v1/intel/sources`, `GET /api/v1/intel/cves`, `GET /api/v1/intel/cves/{id}`. Permissions `findings.read`, `findings.work` (remediation contributors: assigned findings only), `findings.triage`, `findings.accept`, `intel.read`. All routes in the cross-tenant route matrix.
- Console: Overview with real metrics (active, urgent/high, KEV, overdue, severity breakdown, 30-day opened/resolved, assets needing attention, recent scans, feed freshness); Findings list (filters, CSV export) and detail (explanation, remediation, CVE intelligence, evidence, risk breakdown, workflow, assignment, comments, history); Intelligence page (feed status, CVE lookup and search); discovery scans from assets with services and findings on the asset page; discovery results and observations on the scan page.

### Added — M5: network discovery (committed `e379d3e`)

- Scanner connector that validates every destination immediately before connecting (signed lease, ceiling, own and control-plane addresses, never-scanned ranges, hostname answers), bounded TCP connect, banner, TLS and HTTP probes, read-only Redis/memcached probes; evidence and service inventory (migration `0006`); versioned fingerprint rules; Compose `lab` profile with local test targets.

### Added — M4 increments 2–3: worker trust, signed scope, scanner, scans

- `packages/worker-protocol`: the target parser (moved from the API so scanner and control plane share one set of rules), Ed25519-signed scope leases verified over the exact signed bytes, and the worker protocol models.
- Worker PKI (`vulnex.pki`, `python -m vulnex.cli init-pki`): worker CA issuing 7-day client certificates (identity set by the server, never by the request), endpoint CA and TLS certificate, scope-signing key. Never overwrites existing keys.
- Migration `0005`: single-use enrollment tokens (SHA-256 only, at most 24 h), issued-certificate registry, `app.scan` (FORCE RLS), worker version; 10 `SECURITY DEFINER` functions.
- API: `GET /api/v1/workers`, `POST /api/v1/workers/{id}/revoke` (certificates and leases end at once), enrollment tokens (`GET|POST /api/v1/workers/enrollments`, `DELETE …/{id}`), scans (`GET|POST /api/v1/scans` with `Idempotency-Key`, `GET /api/v1/scans/{id}`, `POST …/cancel`). A scan needs an authorized scope group and active assets inside it. Permissions `workers.read/manage`, `scans.read/run`.
- Worker API (`vulnex.worker_api`, separate process, `/worker/v1`): enroll, renew, heartbeat, lease (re-checks the authorization and every target, then signs the lease), extend (carries cancellation), submit; queue sweeper every 10 s.
- Scanner (`engines/scanner`, `vulnex-scanner enroll|run`): key generated locally (0600), mTLS pinned to the endpoint CA, lease verification, the `scope.check` task (no traffic to targets), optional local scope ceiling, certificate renewal, clock-skew check; on revocation it deletes its key and exits with code 3.
- Compose: `init-pki`, `worker-api` (no published port), `gateway` (Caddy 2.10.2, TLS 1.3, client certificates), `scanner` (profile `scanner`).
- Console: Scans list and detail (live while running, cancel, report), Scanners (connection state, one-time enrollment bundle download, withdraw token, revoke), "Run scope check" on assets.

### Fixed — M4

- The endpoint TLS certificate lacked an Authority Key Identifier, so Python 3.13 clients refused it.
- The gateway deleted the certificate header after setting it (Caddy applies deletes after sets).
- `.dockerignore` re-included `__pycache__` under `packages/worker-protocol`.

### Added — M4 increment 1: job queue (committed `9d56e7f`)

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
