# VULNEX Project State

Last updated: 2026-11-07 by Claude · Branch: `feature/m1-foundation` · **Last verified commit: `d7df12e`** (Phase 0 docs, founder D9). Nothing since then is committed. Uncommitted, awaiting founder approval to commit: the M1 foundation code (below), ADR-0002/0005/0006, architecture v0.2, threat model v0.2, GitHub setup and CI workflow, CLAUDE.md, docs/mandate/, DEVELOPMENT.md, this file and AGENT_HANDOFF.md

## Current phase

**M1 (application foundation) is IMPLEMENTED and locally TESTED. It is not committed.** Phase 0 is complete. Phase 1 architecture documents remain PROPOSED and await review. The founder's Master Build Execution Prompt (2026-11-06) directs implementation, starting with M1.

## Current milestone: M1 application foundation: **IMPLEMENTED, TESTED locally (2026-11-07); not committed; CI NOT RUN**

**Branch:** `feature/m1-foundation` (from `develop` @ `d7df12e`). **Earlier correction:** `d7df12e` was first committed to `main` by mistake. `develop` was fast-forwarded to it and `main` was moved back to `ea7c9d8`. Nothing has been pushed (there is no remote).

### What M1 delivers (all verified on 2026-11-07 against the running stack)

| Piece                                                                                                                                                                                                                                                                  | Where                                                      | Status                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| uv workspace, Python 3.13, ruff, mypy `--strict`, pytest                                                                                                                                                                                                               | `pyproject.toml`, `.python-version`, `uv.lock`             | IMPLEMENTED, TESTED                                                                           |
| FastAPI app factory: JSON logs with request IDs (a caller's ID is echoed only if it matches `[A-Za-z0-9._-]{1,64}`), RFC 9457 problem responses (no internal detail on 500/503), `/healthz` (liveness), `/readyz` (DB check as `vulnex_app`), OpenAPI under `/api/v1/` | `engines/api/src/vulnex/`                                  | IMPLEMENTED, TESTED                                                                           |
| Alembic baseline `0001`: schema `app`, fail-closed `app.current_tenant()`, grants to `vulnex_app` only                                                                                                                                                                 | `engines/api/migrations/`                                  | IMPLEMENTED, TESTED (upgrade → downgrade → upgrade)                                           |
| DB roles `vulnex_owner` and `vulnex_app` (no superuser, no BYPASSRLS, NOINHERIT); databases `vulnex` and `vulnex_test`                                                                                                                                                 | `deploy/compose/postgres/roles.psql`                       | IMPLEMENTED, TESTED                                                                           |
| Docker Compose: postgres:17-alpine, migrate, API (non-root), ports bound to 127.0.0.1                                                                                                                                                                                  | `deploy/compose/compose.yaml`, `engines/api/Dockerfile`    | IMPLEMENTED, TESTED (clean start from an empty volume)                                        |
| Console status page using the real API, server-side, with three states (Operational / Degraded / Unreachable)                                                                                                                                                          | `src/routes/+page.server.ts`, `+page.svelte`, `src/env.ts` | IMPLEMENTED, TESTED (unit tests plus manual check against the live stack in all three states) |
| CI job for the Python side with a PostgreSQL service                                                                                                                                                                                                                   | `.github/workflows/ci.yml`                                 | PROPOSED, **NOT RUN** (no remote)                                                             |
| [DEVELOPMENT.md](DEVELOPMENT.md)                                                                                                                                                                                                                                       | root                                                       | IMPLEMENTED                                                                                   |

**Database and API changes:** migration `0001` (schema `app`, function `app.current_tenant()`, default privileges). Endpoints: `GET /healthz` and `GET /readyz`. No tenant tables yet; they arrive with M2.

**Security controls in M1:** least-privilege app role, verified by tests (cannot create objects, cannot `SET ROLE` to the owner, no BYPASSRLS). The API process never holds the owner credentials. Tenant context is transaction-local and fails closed, verified empirically on PG 17 (the ADR-0005 detail that was UNVERIFIED). Malformed tenant IDs raise errors instead of matching rows. Error responses carry no stack traces or DSNs. Request-ID header injection is rejected. Secrets live only in git-ignored `deploy/compose/.env`.

### Deferred (deliberately) and remaining limitations

- **Console move to `apps/console` (ADR-0002) is not done.** Python already sits where ADR-0002 puts it, so nothing has to be redone. The move is a mechanical `git mv` plus a root npm workspace. Do it with the editor closed; on 2026-11-06 the move failed on a Windows file lock.
- No console container in Compose; the console runs on the host with `npm run dev`. `adapter-node` packaging belongs to Phase 12.
- `/readyz` returns the API version without authentication. Revisit in M2.
- `/readyz` checks connectivity, not whether migrations are at head.
- Starlette warns that `httpx` with its TestClient is deprecated in favour of `httpx2`. This is a warning only and is not yet acted on.
- Playwright e2e (updated for the status page) NOT RUN: the browser download was skipped because C: is full.

### Environment blocker (founder action)

**C: keeps filling up.** It had 9.9 GB free at the start of the session and had 0 to 0.4 GB free at the end. The cause found: `C:\pagefile.sys` grew to **17.2 GB** (system-managed) while memory commit was high. Free RAM was about 1.3 GB, the Docker VM is allowed 8 GB, and actual page-file use was only 1.6 GB. The Docker disk image is 6.2 GB. Claude has changed no system settings. Founder options, from least to most invasive: (1) reboot, which usually shrinks the page file; (2) lower Docker Desktop's memory to 4 GB (Settings → Resources), which is enough for this stack; (3) move the page file or Docker's disk image to D:. Claude Code's temp directory is also on C:.

## Completed

| Item                                                                                                                                                                                                                                                                                       | Status                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| SvelteKit 3 / Svelte 5 / TS strict / Tailwind 4 / Vitest / Playwright / ESLint / Prettier scaffold                                                                                                                                                                                         | IMPLEMENTED (template only, no VULNEX code)               |
| Git repo, `main` + `develop`, LF policy, [docs/WORKFLOW.md](docs/WORKFLOW.md)                                                                                                                                                                                                              | IMPLEMENTED                                               |
| [PRD v0.1](docs/product/PRD.md), initial author Claude Opus 5.5 (per founder); Amendment A by Claude                                                                                                                                                                                       | PROPOSED (A4, A5 APPROVED)                                |
| Competitive research TASK 002 ([docs/research/](docs/research/)), initial author Claude Opus 5.5 (per founder)                                                                                                                                                                             | PROPOSED; desk research, independent verification pending |
| [Initial architecture](docs/architecture/INITIAL_ARCHITECTURE.md), [threat model](docs/security/THREAT_MODEL.md), [ADR-0001](docs/decisions/ADR-0001.md), [research plan](docs/research/RESEARCH_PLAN.md), [roadmap](docs/product/ROADMAP.md), [Definition of Done](DEFINITION_OF_DONE.md) | PROPOSED                                                  |
| Lint cleanup: vendored AI-tool folders excluded from Prettier; 3 scaffold files reformatted                                                                                                                                                                                                | IMPLEMENTED, TESTED (`npm run lint` exit 0)               |

## In progress

| Item                                                                                                                                                         | Status                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ |
| [ADR-0002](docs/decisions/ADR-0002.md) layout, [ADR-0005](docs/decisions/ADR-0005.md) tenant isolation, [ADR-0006](docs/decisions/ADR-0006.md) scanner trust | PROPOSED, drafted, uncommitted |
| [Architecture v0.2](docs/architecture/INITIAL_ARCHITECTURE.md): queue semantics §7.1, plugin probe/evaluate split §5.4, condition map §18                    | PROPOSED, uncommitted          |
| [Threat model v0.2](docs/security/THREAT_MODEL.md)                                                                                                           | PROPOSED, uncommitted          |
| [GitHub setup](docs/operations/GITHUB_SETUP.md) and [CI workflow](.github/workflows/ci.yml)                                                                  | PROPOSED; never run on GitHub  |
| Astra 6 review package ([AGENT_HANDOFF.md](AGENT_HANDOFF.md))                                                                                                | Ready to send                  |

ADR-0003 (queue) and ADR-0007 (plugins) are **not drafted**. Their designs are in architecture §7.1 and §5.4, and drafting them needs founder permission.

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

## Pending (next, in order)

1. Founder inspects ADR-0001 and rules on D1, D4, D7.
2. Astra 6 reviews the architecture against the D6 conditions ([AGENT_HANDOFF.md](AGENT_HANDOFF.md)).
3. Research P0 items R1, R3, R4, R8, R10.
4. Founder creates the private GitHub repository.

## Known bugs

None open. Fixed during M1 verification: (1) the Compose healthcheck passed on PostgreSQL's init-time socket-only server, so migrations raced it; it now checks over TCP. (2) The console's 3 s API timeout was shorter than the API's own DB timeout (about 4 s measured), so a database outage showed as "API unreachable"; it is now 8 s.

## Technical debt / issues found (verified 2026-11-06)

| Issue                                                                                                                                          | Evidence           | Severity                         |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | -------------------------------- |
| `npm audit`: 16 vulnerabilities (4 low, 12 moderate), all in dev tooling (eslint, typescript-eslint, @sveltejs/kit chain, tailwind typography) | `npm audit`        | Low (dev-only); no high/critical |
| `adapter-auto` must become `adapter-node` for self-hosted packaging                                                                            | `vite.config.ts`   | Phase 2                          |
| Template example code (`src/lib/vitest-examples`) still present; welcome page replaced by the status page                                      | repo               | Remove                           |
| Nmap not installed on the dev machine; Python 3.13.15, Node 24.19.0, Docker 29.7.2 installed                                                   | `--version` checks | Info                             |

## Security issues

None in code. The design-level accepted risks needing founder acknowledgment are in [THREAT_MODEL.md §5](docs/security/THREAT_MODEL.md).

## Actual test results (2026-11-07, Windows dev machine, `feature/m1-foundation`, uncommitted tree)

| Command                                                                 | Result                                                                                                      |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `uv run pytest` with `VULNEX_TEST_*_URL` set (PostgreSQL 17 in Compose) | **14 passed**, 0 skipped. 6 API tests and 8 database/role/tenant-context tests                              |
| `uv run pytest` without DB URLs                                         | 6 passed, 8 skipped (as designed)                                                                           |
| `uv run ruff check`, `uv run ruff format --check`                       | PASS                                                                                                        |
| `uv run mypy engines/api` (strict)                                      | PASS, 0 issues in 8 files                                                                                   |
| `npm run check`                                                         | 0 errors, 0 warnings                                                                                        |
| `npx vitest run --project server`                                       | 2 files, 4 tests passed (3 new status-page load tests plus the template test)                               |
| `npm run lint`                                                          | PASS (exit 0)                                                                                               |
| Compose from empty volume (`down -v`, `up --build`)                     | PASS: roles created, migration `0001` applied, `/readyz` → 200 `{"status":"ready","version":"0.1.0"}`       |
| Console against live stack                                              | PASS for all three states: ready (v0.1.0) / db stopped → "Database unavailable" / api stopped → unreachable |
| Playwright e2e, browser component tests                                 | NOT RUN                                                                                                     |
| GitHub Actions (console, api, gitleaks jobs)                            | NOT RUN (no remote)                                                                                         |
| `npm audit --audit-level=high`                                          | NOT RE-RUN this session (last: PASS on 2026-11-06)                                                          |

## Next recommended task

1. **Founder:** free space on C: (see the environment blocker above), then approve or decline committing the M1 foundation plus the Phase 1 documents on `feature/m1-foundation`.
2. Claude: move the console to `apps/console` (ADR-0002), then start **M2, identity and organizations**: tenant, user, membership tables with RLS, Argon2id password hashing, server-side sessions, CSRF, and the route-matrix cross-tenant tests from ADR-0005 §6. M2 needs a founder answer on R8 (authentication provider: built-in vs Keycloak). Claude's recommendation for self-hosted v0: built-in sessions, with OIDC added later.
3. Astra 6 review of the architecture package remains open.
