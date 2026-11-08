# VULNEX Project State

Last updated: 2026-11-08 by Claude · Branch: `feature/m4-scanner` (from `8d6912a`) · **Last commit: `8d6912a` M3 authorized scope and asset inventory** (founder: "continue", taken as approval to commit M3). M4 increment 1 is implemented and tested but **not committed**. Nothing is pushed (there is no remote).

## Current phase

**M4 (scanner foundation) is in progress.** Increment 1 (PostgreSQL job queue, ADR-0003) is IMPLEMENTED and locally TESTED, not committed. M3 (`8d6912a`), M2 (`07a51dc`) and M1 (`66a3fdb`) are committed. Phase 1 architecture documents remain PROPOSED and await founder and Astra 6 review.

## Current milestone: M4 scanner foundation: **IN PROGRESS**

M4 is split into three increments so each can be reviewed on its own:

| Increment                          | Content                                                                                                                                                                                              | Status                                                                                        |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| 1. Job queue                       | ADR-0003 (drafted, PROPOSED); migration `0004`: `app.worker`, schema `queue` (jobs, results, quarantine) and 7 `SECURITY DEFINER` functions: enqueue, claim, extend, submit, complete, cancel, sweep | **IMPLEMENTED, TESTED locally; NOT committed**                                                |
| 2. Worker identity                 | Enrollment tokens, worker CA and client certificates, mTLS termination, revocation, heartbeats (ADR-0006 §1–3, §6)                                                                                   | **NOT IMPLEMENTED: waiting for a founder decision on ADR-0006** (see "Next recommended task") |
| 3. Scope leases and worker process | Ed25519-signed scope leases from the M3 authorization; worker process that verifies leases and enforces scope with `vulnex.targets`; scan submission API and UI; no network probing (that is M5)     | NOT IMPLEMENTED                                                                               |

### What increment 1 delivers (verified 2026-11-08)

- **Queue semantics (INITIAL_ARCHITECTURE §7.1, ADR-0003):** at-least-once delivery with idempotent effects; claim with `FOR UPDATE SKIP LOCKED` and a fresh random lease per claim; claims limited to the worker's own tenant **and** scope group and to active workers; lease extension that carries the cancel flag and cannot revive an expired lease; results keyed by `(job, attempt, seq)` and bound to the lease; stale results quarantined, never applied; completion and its final result in one transaction; retries with exponential backoff and jitter, then `dead`; `refused` never retried; a sweeper for expired leases that is safe to run concurrently; per-tenant idempotent enqueue; tenant-scoped cancellation.
- **Privileges:** the application role has no table privileges on `queue.*` and cannot delete workers; every path is a definer function (verified by tests).
- **Tests:** 27 in `engines/api/tests/test_queue_db.py`. Two were mutation-checked: removing the claim's row lock makes the concurrent-claimers test fail (a job was handed out twice), and removing the scope-group filter makes the isolation test fail.
- Deleting a scope group that a worker or job uses returns 409 (it returned 500 before).
- **Not yet done:** the load test from §7.1 (10,000 jobs, 4 claimers); nothing calls the queue from the API yet (increment 3); nothing runs `queue.sweep()` periodically yet.

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

| Item                                                                                                      | Status                                   |
| --------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| M2 identity and organizations (sessions, roles, members, audit, console sign-in)                          | IMPLEMENTED, TESTED, committed `07a51dc` |
| M1 application foundation (FastAPI, Alembic `0001`, roles, Compose, status page, CI workflow)             | IMPLEMENTED, TESTED, committed `66a3fdb` |
| Phase 0 documents (PRD v0.1 + Amendment A, research, architecture, threat model, ADR-0001, roadmap, DoD)  | committed `d7df12e`; PROPOSED            |
| ADR-0002, ADR-0005, ADR-0006, architecture v0.2, threat model v0.2, GitHub setup, mandate, DEVELOPMENT.md | committed `66a3fdb`; PROPOSED            |

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
3. Astra 6 reviews the architecture package plus the M1/M2/M3 addenda ([AGENT_HANDOFF.md](AGENT_HANDOFF.md)).
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

## Actual test results (2026-11-08, Windows dev machine, `feature/m4-scanner`, uncommitted M4 increment 1)

| Command                                                                  | Result                                                                                                                 |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `sh scripts/check-api.sh` (Linux container, PostgreSQL 17 from Compose)  | ruff PASS, ruff format PASS, mypy `--strict` PASS, **pytest 194 passed**, 0 skipped (M3: 166)                          |
| Mutation checks on `0004` (row lock removed; scope-group filter removed) | the targeted test **failed** each time, as it should; file restored                                                    |
| `npm run lint`                                                           | PASS                                                                                                                   |
| Compose: migration `0003 → 0004` on the existing dev volume; `/readyz`   | PASS (`{"status":"ready","version":"0.1.0"}`)                                                                          |
| Console checks (`npm run check`, vitest, Playwright)                     | not re-run for increment 1: no console code changed since M3 (`8d6912a`, where they passed: 0 errors, 24 and 2 passed) |
| Queue load test (10,000 jobs, 4 claimers)                                | NOT RUN                                                                                                                |
| Host `uv run pytest` / `uv run mypy`                                     | **BLOCKED** by Windows Smart App Control (environment, not code); same checks pass in the container                    |
| GitHub Actions                                                           | NOT RUN (no remote)                                                                                                    |

## Next recommended task

1. **Founder: decide how to proceed with the scanner's security design (ADR-0006).** Increments 2 and 3 implement the worker trust model, which the Master Operating Prompt says not to start until its security boundaries are approved. Options: (a) approve ADR-0006 as written; (b) approve it for implementation now, with Astra 6 review before any scan touches a real network (M5); (c) wait for Astra 6 first. Increment 2 also adds Caddy as a reverse proxy for mTLS (ADR-0006 §2) and the `cryptography` Python library.
2. **Founder:** approve committing M4 increment 1 (queue); create the private GitHub repository; set the `SECURITY.md` contact.
3. Astra 6 review of the architecture package plus the M1–M4 addenda remains open.
