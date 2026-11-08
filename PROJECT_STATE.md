# VULNEX Project State

Last updated: 2026-11-08 by Claude · Branch: `feature/m4-scanner` (from `8d6912a`) · **M4 increments 2–3 are committed locally in the commit that contains this file** (after `9d56e7f`, increment 1; see `git log`). Nothing is pushed (there is no remote).

## Current phase

**M4 (scanner foundation) is IMPLEMENTED and TESTED locally, and committed locally.** Increment 1 (job queue) is committed (`9d56e7f`). Increments 2 and 3 (worker identity, signed scope, scanner, console) are implemented under founder option (b) for ADR-0006 (founder, 2026-11-08: "just do whatever to make my project perfect just like Nessus", taken as approval of my recommendation (b): build the worker trust design now, Astra 6 reviews it before any scan touches a real network). ADR-0003 and ADR-0006 remain **PROPOSED**. M3 (`8d6912a`), M2 (`07a51dc`) and M1 (`66a3fdb`) are committed.

## Current milestone: M4 scanner foundation: **IMPLEMENTED, TESTED locally; committed locally; CI NOT RUN**

| Increment                       | Content                                                                                                                                                                                              | Status                                                                   |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| 1. Job queue                    | ADR-0003; migration `0004`: `app.worker`, schema `queue` and 7 definer functions                                                                                                                     | IMPLEMENTED, TESTED, committed `9d56e7f`                                 |
| 2. Worker identity              | Enrollment tokens, worker CA and 7-day client certificates, Caddy mTLS gateway, separate worker API, heartbeats, renewal, revocation (ADR-0006 §1–3)                                                 | **IMPLEMENTED, TESTED locally and over real mTLS in Compose; committed** |
| 3. Scope leases, scanner, scans | Ed25519-signed scope leases re-checked at lease time; `engines/scanner` (verifies leases, enforces scope and a local ceiling; task `scope.check` only, **no network probing**); scan API and console | **IMPLEMENTED, TESTED locally and end to end in Compose; committed**     |

### What increments 2–3 deliver (verified 2026-11-08)

| Piece                                                                                                                                                                                                                               | Where                                                    | Status                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Shared protocol package: target parser (moved from the API), signed leases (sign/verify), wire models                                                                                                                               | `packages/worker-protocol/`                              | IMPLEMENTED, TESTED (15 lease tests, 69 parser cases)                                           |
| Worker PKI: worker CA, endpoint CA and TLS certificate, Ed25519 scope-signing key; `vulnex.cli init-pki` never overwrites keys                                                                                                      | `engines/api/src/vulnex/pki.py`, `cli.py`                | IMPLEMENTED, TESTED (7 tests)                                                                   |
| Migration `0005`: `auth.worker_enrollment`, `auth.worker_certificate`, `app.scan` (FORCE RLS), `app.worker.version`, 10 definer functions                                                                                           | `engines/api/migrations/versions/0005_workers_scans.py`  | IMPLEMENTED, TESTED (round trip; applied to the dev database)                                   |
| Control-plane API: enrollment tokens (shown once, SHA-256 stored), worker list with online/stale state, revocation; scans (authorized scope and in-scope active assets required, idempotency key, list, detail with result, cancel) | `engines/api/src/vulnex/workers.py`, `scans.py`          | IMPLEMENTED, TESTED (11 + 9 route-matrix probes)                                                |
| Worker API `/worker/v1`: enroll, renew, heartbeat, lease (re-checks authorization and every target, signs the lease), extend, submit; queue sweeper thread every 10 s                                                               | `engines/api/src/vulnex/worker_api.py`                   | IMPLEMENTED, TESTED (11 tests)                                                                  |
| Scanner: enrollment with a local key, mTLS client pinned to the endpoint CA, lease verification, `scope.check`, local scope ceiling, renewal, revocation (deletes keys, exit 3), clock-skew check                                   | `engines/scanner/`                                       | IMPLEMENTED, TESTED (4 unit tests; 6 tests against the real worker API in process; Compose run) |
| Compose: `init-pki` (keys in a named volume; the user-facing API mounts only the public CA), `worker-api` (no published port), `gateway` (Caddy 2.10.2, TLS 1.3, client certificates), `scanner` (profile)                          | `deploy/compose/`                                        | IMPLEMENTED, VERIFIED on the dev machine                                                        |
| Console: Scans list and detail (auto-refresh while running, cancel, report), Scanners (status, enroll with a one-time bundle download, withdraw token, revoke), "Run scope check" on an asset                                       | `src/routes/(app)/scans/**`, `workers/**`, `assets/[id]` | IMPLEMENTED, TESTED (svelte-check, lint; browser walkthrough)                                   |

**API endpoints added:** `GET /api/v1/workers`, `POST /api/v1/workers/{worker_id}/revoke`, `GET|POST /api/v1/workers/enrollments`, `DELETE /api/v1/workers/enrollments/{enrollment_id}`, `GET|POST /api/v1/scans`, `GET /api/v1/scans/{scan_id}`, `POST /api/v1/scans/{scan_id}/cancel`. Worker API (separate app, behind the gateway): `POST /worker/v1/enroll|renew|heartbeat|lease|tasks/extend|tasks/submit`.

**Security controls verified:** cross-tenant probes for all 9 new routes; the scanner refuses a tampered lease (signature), targets outside the signed scope (including `169.254.169.254`), targets outside its local ceiling, and oversized ranges; scope changed after a scan was requested is refused at lease time (mutation-checked: removing the authorization re-check fails a test, and the per-target check still refuses on its own); revocation releases leases and the scanner deletes its keys.

**Real-network run on 2026-11-08 (Compose on the dev machine; target `192.0.2.0/28`, RFC 5737 documentation space; no packets are sent to targets in M4):** scanner enrolled over mTLS through Caddy; scan queued → completed with the report (16 addresses); header without a certificate → 401; certificate from a foreign CA → TLS handshake refused; worker API not reachable from the host; after revocation the scanner exited with code 3 and its key and certificate were gone. The same flow was then repeated from the console in a headless browser (enroll from the Scanners page with the downloaded bundle, "Run scope check" on an asset, report shown).

**Found and fixed during verification:** (1) the endpoint certificate lacked an Authority Key Identifier, which Python 3.13's strict verification requires (enrollment failed over real TLS); fixed and covered by a test. (2) The Caddyfile both deleted and set the fingerprint header; Caddy applies deletes after sets, so the header never arrived; fixed (a set replaces any client copy, verified by the spoofing test above). (3) `.dockerignore` re-included `__pycache__` for the protocol package; fixed.

### Known limitations (M4)

- No network probing: `scope.check` only. DNS resolution, per-address destination checks at connect time, redirects and the ADR-0006 destination fixtures are M5, after the Astra 6 review.
- The signed lease covers the first lease period (≤ 5 min) and is not re-signed on extension; fine for M4 tasks, required before longer M5 tasks.
- The scanner polls every 5 s when idle (no long-poll). One task at a time.
- No CRL/OCSP: revocation is enforced by the worker API's certificate lookup. Keys are files (mode 0600), not in an HSM or OS keystore.
- No rate limit on `/worker/v1/enroll` (256-bit token; 1 MB request limit at the gateway).
- The Scans list shows the newest 100 (with the total); no paging or filters yet.
- The queue load test (10,000 jobs, 4 claimers) is still NOT RUN.

## M3 authorized scope and asset inventory: **IMPLEMENTED, TESTED locally (2026-11-08); committed `8d6912a`; CI NOT RUN**

Cross-origin form protection on the new M3 pages was verified on a production build before the commit: cross-origin posts to `scope?/create` and `assets?/add` with a valid session cookie → 403; same-origin → work.

### What M3 delivers (verified 2026-11-08)

| Piece                                                                                                                                                                      | Where                                                                                                          | Status                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Migration `0003`: `app.scope_group`, `app.scope_entry`, `app.asset`; FORCE RLS; composite `(tenant_id, id)` foreign keys; app role cannot delete assets or truncate        | `engines/api/migrations/versions/0003_assets.py`                                                               | IMPLEMENTED, TESTED (round-trip down/up; applied to the dev database)                |
| Strict target parser and scope membership (ADR-0006 §5 steps 1–5): canonical IPv4 only, IPv6 refused, never-allowed ranges, CIDR rules, hostname rules, URL/port detection | `engines/api/src/vulnex/targets.py`                                                                            | IMPLEMENTED, TESTED (69 cases)                                                       |
| Scope groups: entries (include/exclude, CIDR, hostname, `*.` wildcard), owner/admin authorization bound to a digest of the exact entries, drift detection, withdrawal      | `engines/api/src/vulnex/scope.py`                                                                              | IMPLEMENTED, TESTED                                                                  |
| Assets: register inside a scope group (refused outside it), eligibility recomputed on read, edit, retire/reactivate (re-checks scope), search/filter/paginate              | `engines/api/src/vulnex/assets.py`                                                                             | IMPLEMENTED, TESTED                                                                  |
| Per-object history: `target_type` / `target_id` filters on the audit API                                                                                                   | `engines/api/src/vulnex/audit.py`                                                                              | IMPLEMENTED, TESTED                                                                  |
| Permissions `scope.read/manage`, `assets.read/manage`                                                                                                                      | `engines/api/src/vulnex/authz.py`                                                                              | IMPLEMENTED, TESTED (role matrix)                                                    |
| Console: Assets list and detail, Authorized scope list and detail, role-aware navigation, empty/error states                                                               | `src/routes/(app)/assets/**`, `src/routes/(app)/scope/**`, `src/lib/server/actions.ts`, `src/lib/components/*` | IMPLEMENTED, TESTED (unit tests; scripted browser walkthrough against the dev stack) |

**API endpoints added:** `GET|POST /api/v1/scope-groups`, `GET|PATCH|DELETE /api/v1/scope-groups/{group_id}`, `POST /api/v1/scope-groups/{group_id}/entries`, `DELETE /api/v1/scope-groups/{group_id}/entries/{entry_id}`, `POST|DELETE /api/v1/scope-groups/{group_id}/authorization`, `GET|POST /api/v1/assets`, `GET|PATCH /api/v1/assets/{asset_id}`, `POST /api/v1/assets/{asset_id}/retire`, `POST /api/v1/assets/{asset_id}/reactivate`. Changed: `GET /api/v1/audit-events` accepts `target_type`, `target_id`.

**Browser walkthrough on 2026-11-08 (headless Chromium, `vite dev` against the Compose API and database, as the dev owner):** `169.254.169.254` refused as a scope entry; range, exclusion and wildcard added; scope authorized; `10.77.1.0/24` and `web.lab.example` registered; `10.77.9.20` (excluded), `10.78.0.1` (outside) and `127.0.0.1` (never allowed) refused with the specific reason; adding an exclusion after authorization showed "Changed since authorization" and turned the affected asset "Out of scope"; retire recorded in the asset's history; an unknown asset ID shows 404.

### Known limitations (M3)

- Nothing is scanned yet. "Eligible" means "in scope and authorized"; M4 must enforce it again in the worker (ADR-0006).
- IPv4 only. IPv6 targets are refused with a clear message (PRD §7).
- Hostname assets are matched by name; the addresses they resolve to are not checked until the worker connects (M4).
- No bulk import (one asset per request). No discovered assets yet (`source = 'discovered'` exists for M5).
- The authorization is an attestation plus an audit event; there is no document upload or expiry date yet.
- Analysts can read scope and assets but not change them (PRD §10 "manage scopes" is owner/admin); remediation contributors see neither until assignment exists (M8).

## M2 identity and organizations: **IMPLEMENTED, TESTED locally (2026-11-08); committed `07a51dc`; CI NOT RUN**

**Branch:** `feature/m2-identity` (from `feature/m1-foundation` @ `66a3fdb`).

### What M2 delivers (verified 2026-11-08)

| Piece                                                                                                                                                                                                                                   | Where                                                     | Status                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Migration `0002`: `app.tenant`, `app.membership`, `app.audit_event` (FORCE RLS, append-only audit); schema `auth` (accounts, sessions, login attempts) with no table grants to the app role, reached via 9 `SECURITY DEFINER` functions | `engines/api/migrations/versions/0002_identity.py`        | IMPLEMENTED, TESTED (round-trip down/up; applied to the dev database)                                     |
| Argon2id password hashing (argon2-cffi defaults, RFC 9106), timing-equalised unknown emails, transparent rehash                                                                                                                         | `engines/api/src/vulnex/security.py`                      | IMPLEMENTED, TESTED                                                                                       |
| Opaque bearer sessions: 256-bit token, SHA-256 at rest, 12 h absolute, 30 min idle, role and membership re-read every request, logout revocation                                                                                        | `auth.py`, `deps.py`                                      | IMPLEMENTED, TESTED                                                                                       |
| Sign-in throttling: 5 failures per email or 20 per address in 15 min → 429; trusted-proxy `X-Forwarded-For` handling                                                                                                                    | `auth.py`, `deps.resolve_client_ip`                       | IMPLEMENTED, TESTED                                                                                       |
| Roles (owner, admin, analyst, remediation contributor, viewer) and permissions, deny by default; member add / role change / remove; admins cannot alter owners; last owner protected with row locks                                     | `authz.py`, `members.py`                                  | IMPLEMENTED, TESTED                                                                                       |
| Audit events in the same transaction as each change (login, logout, member added / role changed / removed, organization created); paginated audit API                                                                                   | `audit.py`                                                | IMPLEMENTED, TESTED                                                                                       |
| Operator CLI for controlled provisioning (no self-registration)                                                                                                                                                                         | `engines/api/src/vulnex/cli.py`                           | IMPLEMENTED, TESTED (unit-level via tests; run once against the dev stack)                                |
| `/readyz` also fails (503) when the schema is not at the expected revision                                                                                                                                                              | `main.py`, `db.py`                                        | IMPLEMENTED, TESTED                                                                                       |
| Console: sign-in, sign-out, signed-in shell with role-aware navigation, Overview (workspace + system status), Members, Audit log; HttpOnly SameSite=Lax cookie; security headers; open-redirect guard; loading/empty/error states       | `src/hooks.server.ts`, `src/lib/server/*`, `src/routes/*` | IMPLEMENTED, TESTED (unit tests, Playwright e2e, manual run against the dev stack and a production build) |

**API endpoints added:** `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/session`, `GET /api/v1/organization`, `GET|POST /api/v1/members`, `PATCH|DELETE /api/v1/members/{user_id}`, `GET /api/v1/audit-events`.

**Security verification done by hand on 2026-11-08 (production build `node build`):** a cross-origin form post to sign-in and to add-member (with a valid session cookie) → 403; same-origin → works; `?next=//evil.test/` → redirected to `/`; logout revokes the server-side session; demoting the last owner → 409; audit entries record the browser's address, not the Docker gateway.

### Development hygiene (same branch)

Dependabot (npm, uv, Actions, Docker), `SECURITY.md` (PROPOSED; contact address left for the founder), `CHANGELOG.md`, opt-in pre-commit hook (gitleaks via Docker, ruff, prettier; enabled in this clone), `adapter-node` instead of `adapter-auto`, template example code removed, Playwright `baseURL` fixed (the old e2e could never have run), `scripts/check-api.sh`.

### Known limitations (M2)

- Members get an initial password from an admin; there is no self-service password change, reset, invitation e-mail or MFA yet. No OIDC/SSO yet (R8 recommendation: add later).
- An organization can only be created with the CLI; there is no "create organization" UI or API for MSP-style multi-org use yet.
- Expired sessions and old login attempts are not purged by a job (login attempts older than a day are pruned on each write; sessions accumulate until a cleanup task exists in M4's runner).
- Sign-in throttling can lock a known e-mail out for 15 minutes (a deliberate trade-off; flagged for review).
- `/readyz` still returns the version without authentication.
- The console's CSRF protection is SvelteKit's origin check, which `vite dev` disables; it is active only in builds. With `adapter-node` over plain HTTP, `PROTOCOL_HEADER` must be configured (see DEVELOPMENT.md).
- Console move to `apps/console` (ADR-0002) still not done.
- Playwright e2e covers anonymous redirect and failed sign-in only; a full signed-in journey needs a test-account fixture.

### Environment notes (2026-11-08)

- C: drive now has ~20 GB free (the founder's reboot fixed it).
- **Windows Smart App Control is ON** (policy state 1). It blocks unsigned compiled Python extensions in the host `.venv` (SQLAlchemy, mypy, argon2), so `uv run pytest` and `uv run mypy` fail on the host. Workaround in place: `sh scripts/check-api.sh` runs the Python checks in a Linux container. Turning Smart App Control off is the founder's choice (Windows cannot turn it back on without a reinstall); not needed for development.

## Completed

| Item                                                                                                      | Status                                               |
| --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| M4 increments 2–3 (worker trust, signed scope leases, scanner `scope.check`, scans, console)              | IMPLEMENTED, TESTED, committed locally (this commit) |
| M4 increment 1 (PostgreSQL job queue, ADR-0003)                                                           | IMPLEMENTED, TESTED, committed `9d56e7f`             |
| M3 authorized scope and asset inventory                                                                   | IMPLEMENTED, TESTED, committed `8d6912a`             |
| M2 identity and organizations (sessions, roles, members, audit, console sign-in)                          | IMPLEMENTED, TESTED, committed `07a51dc`             |
| M1 application foundation (FastAPI, Alembic `0001`, roles, Compose, status page, CI workflow)             | IMPLEMENTED, TESTED, committed `66a3fdb`             |
| Phase 0 documents (PRD v0.1 + Amendment A, research, architecture, threat model, ADR-0001, roadmap, DoD)  | committed `d7df12e`; PROPOSED                        |
| ADR-0002, ADR-0005, ADR-0006, architecture v0.2, threat model v0.2, GitHub setup, mandate, DEVELOPMENT.md | committed `66a3fdb`; PROPOSED                        |

ADR-0003 (queue) and ADR-0007 (plugins) are **not drafted**; their designs are in architecture §7.1 and §5.4.

## Approved architecture and scope

| Item                                                                                                                    | Status                                                                                                          | Source                 |
| ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Deployment order: self-hosted → hybrid → SaaS; design for all three, implement one at a time                            | **APPROVED**                                                                                                    | Founder D2, 2026-11-06 |
| M1 = remote, non-intrusive discovery and service assessment; M2 may add authenticated read-only Linux package inventory | **APPROVED**                                                                                                    | Founder D3             |
| Rule: never `CONFIRMED` from a remotely observed version alone when backports or other uncertainty may exist            | **APPROVED**                                                                                                    | Founder D3             |
| Modular FastAPI app, PostgreSQL, separate outbound-only workers, PostgreSQL-backed job queue                            | **CONDITIONALLY APPROVED**: final approval after the conditions under D6 are addressed and Astra 6 has reviewed | Founder D5/D6          |
| ADR-0001                                                                                                                | PROPOSED: the founder will inspect it before formal approval                                                    | Founder D5             |
| Everything else                                                                                                         | PROPOSED                                                                                                        | —                      |

Standing founder constraint: **no additional infrastructure without a demonstrated requirement.**

## Decision log (D1–D9)

| ID  | Decision                                                                 | Founder ruling (2026-11-06)                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Status                     |
| --- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| D1  | Adopt PRD v0.1 + Amendment A as the planning baseline                    | Not ruled on explicitly ("approve the general direction")                                                                                                                                                                                                                                                                                                                                                                                                                          | **PENDING**                |
| D2  | Deployment order                                                         | Self-hosted, then hybrid, then SaaS; design for all three; avoid premature deployment complexity                                                                                                                                                                                                                                                                                                                                                                                   | **APPROVED**               |
| D3  | Detection scope                                                          | Remote non-intrusive M1; authenticated Linux package inventory in M2; never `CONFIRMED` from version alone                                                                                                                                                                                                                                                                                                                                                                         | **APPROVED**               |
| D4  | Beachhead: SMB/mid-market + one MSP design partner, pending interviews   | Not ruled on                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | **PENDING**                |
| D5  | ADR-0001 modular monolith + separate workers                             | Direction supported; founder will inspect ADR-0001 before formal approval                                                                                                                                                                                                                                                                                                                                                                                                          | **CONDITIONALLY APPROVED** |
| D6  | Architecture proposals to ADRs                                           | Conditional. The architecture must address: (a) transactional job claiming and locking; (b) leases, retries, idempotency, cancellation, recovery; (c) database-enforced tenant isolation; (d) RLS context handling and cross-tenant testing; (e) scanner authentication, revocation, signed scope verification; (f) DNS resolution, IPv4/IPv6, redirects, address validation; (g) secure plugin execution and resource limits. ADR-0002, 0005 and 0006 may be prepared as PROPOSED | **CONDITIONALLY APPROVED** |
| D7  | Fund research P0 items, build-vs-integrate, legal review                 | Not ruled on                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | **PENDING**                |
| D8  | Private GitHub remote + basic CI                                         | Prepare instructions and CI; never public                                                                                                                                                                                                                                                                                                                                                                                                                                          | **APPROVED**               |
| D9  | Commit Phase 0 docs; keep AI-tool folders but exclude them from Prettier | Approved; ask before committing major changes until a Git workflow is documented and approved                                                                                                                                                                                                                                                                                                                                                                                      | **APPROVED**               |
| —   | Authorship of PRD v0.1 and TASK 002 research                             | Record Claude Opus 5.5 as initial author; independent review and verification pending                                                                                                                                                                                                                                                                                                                                                                                              | **RECORDED**               |
| —   | R8: authentication provider for self-hosted v0                           | Built-in sessions now, OIDC/SSO later; not Keycloak. Founder: "add all", then "yes" to the confirmation request (2026-11-08)                                                                                                                                                                                                                                                                                                                                                       | **APPROVED**               |

## Pending (next, in order)

1. Founder: inspect ADR-0001 and rule on D1, D4, D7; set the security contact in `SECURITY.md`.
2. Founder: create the private GitHub repository (D8) so CI, gitleaks and Dependabot actually run.
3. Astra 6 reviews the architecture package plus the M1–M4 addenda ([AGENT_HANDOFF.md](AGENT_HANDOFF.md)).
4. Research P0 items R1, R3, R4, R10.

## Known bugs

None open. Found and fixed during M3 verification: (a) the add-asset form defaulted to no scope group when no filter was set (an empty string is not nullish); fixed. (b) The never-allowed message showed a single address as `/32`; fixed. Found and fixed during M2 verification: (1) route enumeration in tests silently found no routes on FastAPI 0.162 (routers are nested lazily); it now walks nested routers and cross-checks against OpenAPI. (2) The per-address sign-in throttle would have counted every user as the console's address; fixed with trusted-proxy handling. (3) Member actions recorded the Docker gateway as the audit address; the console now forwards the browser's address on every mutating call. (4) Playwright config had no `baseURL` and the preview server bound IPv6 only, so e2e could never run; fixed.

## Technical debt / issues

| Issue                                                                                                                                                | Evidence                          | Severity                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ------------------------------- |
| `npm audit`: 16 vulnerabilities (4 low, 12 moderate), all in dev tooling; 0 high/critical                                                            | `npm audit`, 2026-11-08           | Low (dev-only)                  |
| Starlette warns `httpx` with TestClient is deprecated in favour of `httpx2`                                                                          | pytest warning                    | Low                             |
| Two `eslint-disable` blocks for `svelte/no-navigation-without-resolve` in the app layout: the rule cannot see that `nav` hrefs come from `resolve()` | `src/routes/(app)/+layout.svelte` | Info (justified in the comment) |
| CI actions pinned by major tag, not SHA                                                                                                              | `.github/workflows/ci.yml`        | Low until the repo exists       |

## Security issues

None known in code. Design-level accepted risks needing founder acknowledgment: [THREAT_MODEL.md §5](docs/security/THREAT_MODEL.md), plus the M2 trade-offs listed under "Known limitations" above (e-mail lockout window, unauthenticated `/readyz` version).

## Actual test results (2026-11-08, Windows dev machine, `feature/m4-scanner`, M4 increments 2–3, before commit)

| Command                                                                                  | Result                                                                                                                                                                     |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sh scripts/check-api.sh` (Linux container, PostgreSQL 17 from Compose)                  | ruff PASS, ruff format PASS, mypy `--strict` PASS (48 files), **pytest 257 passed**, 0 skipped (increment 1: 194)                                                          |
| Mutation checks                                                                          | scans without the authorization gate; worker API without the lease-time re-check; endpoint certificate without AKI: the targeted test **failed** each time; files restored |
| `npm run lint`                                                                           | PASS                                                                                                                                                                       |
| `npm run check`                                                                          | PASS, 0 errors, 0 warnings                                                                                                                                                 |
| `npx vitest run`                                                                         | 24 passed                                                                                                                                                                  |
| `npx playwright test`                                                                    | 2 passed                                                                                                                                                                   |
| Compose: migration `0004 → 0005` on the dev volume, `/readyz`                            | PASS                                                                                                                                                                       |
| Compose real-network run (mTLS through Caddy, scanner container) and console walkthrough | PASS, details under M4 above                                                                                                                                               |
| Queue load test (10,000 jobs, 4 claimers)                                                | NOT RUN                                                                                                                                                                    |
| Host `uv run pytest` / `uv run mypy`                                                     | **BLOCKED** by Windows Smart App Control (environment, not code); same checks pass in the container                                                                        |
| GitHub Actions                                                                           | NOT RUN (no remote)                                                                                                                                                        |

## Next recommended task

1. **Astra 6:** review ADR-0006 and its M4 implementation notes (deviations listed there) **before M5**, the first milestone that sends packets to real systems. Also open: ADR-0001/2/3/5 and the M1–M4 addenda in [AGENT_HANDOFF.md](AGENT_HANDOFF.md).
2. **Founder:** create the private GitHub repository (D8) so CI, gitleaks and Dependabot run; set the `SECURITY.md` contact; rule on D1, D4, D7.
3. **Claude, next:** the queue load test; then M5 planning (DNS resolution and per-address checks at connect time, TCP port checks, service identification, TLS metadata, evidence storage) with the destination fixtures from ADR-0006 as the first tests. Nmap stays out until research R1 (licensing) is done.
