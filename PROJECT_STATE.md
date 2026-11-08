# VULNEX Project State

Last updated: 2026-11-08 by Claude · Branch: `feature/m2-identity` · **Last commit: M2 identity and organizations** (committed 2026-11-08 with founder approval; see `git log`). M1 is `66a3fdb`. Nothing is pushed (there is no remote).

## Current phase

**M2 (identity and organizations) is IMPLEMENTED, locally TESTED and committed (founder approval 2026-11-08).** M1 is committed (`66a3fdb`). Phase 1 architecture documents remain PROPOSED and await founder and Astra 6 review.

## Current milestone: M2 identity and organizations: **IMPLEMENTED, TESTED locally (2026-11-08); committed; CI NOT RUN**

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
3. Astra 6 reviews the architecture package plus the M1/M2 addenda ([AGENT_HANDOFF.md](AGENT_HANDOFF.md)).
4. Research P0 items R1, R3, R4, R10.

## Known bugs

None open. Found and fixed during M2 verification: (1) route enumeration in tests silently found no routes on FastAPI 0.162 (routers are nested lazily); it now walks nested routers and cross-checks against OpenAPI. (2) The per-address sign-in throttle would have counted every user as the console's address; fixed with trusted-proxy handling. (3) Member actions recorded the Docker gateway as the audit address; the console now forwards the browser's address on every mutating call. (4) Playwright config had no `baseURL` and the preview server bound IPv6 only, so e2e could never run; fixed.

## Technical debt / issues

| Issue                                                                                                                                                | Evidence                          | Severity                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ------------------------------- |
| `npm audit`: 16 vulnerabilities (4 low, 12 moderate), all in dev tooling; 0 high/critical                                                            | `npm audit`, 2026-11-08           | Low (dev-only)                  |
| Starlette warns `httpx` with TestClient is deprecated in favour of `httpx2`                                                                          | pytest warning                    | Low                             |
| Two `eslint-disable` blocks for `svelte/no-navigation-without-resolve` in the app layout: the rule cannot see that `nav` hrefs come from `resolve()` | `src/routes/(app)/+layout.svelte` | Info (justified in the comment) |
| CI actions pinned by major tag, not SHA                                                                                                              | `.github/workflows/ci.yml`        | Low until the repo exists       |

## Security issues

None known in code. Design-level accepted risks needing founder acknowledgment: [THREAT_MODEL.md §5](docs/security/THREAT_MODEL.md), plus the M2 trade-offs listed under "Known limitations" above (e-mail lockout window, unauthenticated `/readyz` version).

## Actual test results (2026-11-08, Windows dev machine, `feature/m2-identity`, tree as committed for M2)

| Command                                                                 | Result                                                                                              |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `sh scripts/check-api.sh` (Linux container, PostgreSQL 17 from Compose) | ruff PASS, ruff format PASS, mypy `--strict` PASS (22 files), **pytest 60 passed**, 0 skipped       |
| `npm run lint`                                                          | PASS                                                                                                |
| `npm run check`                                                         | 0 errors, 0 warnings                                                                                |
| `npx vitest run --project server`                                       | 2 files, **18 tests passed**                                                                        |
| `npx playwright test` (headless Chromium, API stack up)                 | **2 passed** (first ever e2e run)                                                                   |
| `npm run build` (adapter-node)                                          | PASS                                                                                                |
| `npm audit --audit-level=high`                                          | PASS (16 low/moderate in dev tooling)                                                               |
| Pre-commit hook on the staged M2 diff                                   | PASS (gitleaks: no leaks; ruff; prettier)                                                           |
| Compose: migration `0002` on the existing dev volume; `/readyz`         | PASS (`{"status":"ready","version":"0.1.0"}`)                                                       |
| Manual end-to-end against the dev stack and a production build          | PASS (see "Security verification" above)                                                            |
| Host `uv run pytest` / `uv run mypy`                                    | **BLOCKED** by Windows Smart App Control (environment, not code); same checks pass in the container |
| GitHub Actions                                                          | NOT RUN (no remote)                                                                                 |

## Next recommended task

1. **Founder:** create the private GitHub repository; set the `SECURITY.md` contact.
2. **Claude:** **M3, asset management**: authorized scope definitions (IP, hostname, CIDR) with tenant-scoped assets, composite foreign keys (the first real test of that ADR-0005 gate), asset inventory and detail views, audit history. M3 needs no new founder decision.
3. Astra 6 review of the architecture package plus the M1/M2 addenda remains open.
