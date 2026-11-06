# VULNEX Project State

Last updated: 2026-11-06 by Claude · Branch: `develop` · **Last verified commit: `ea7c9d8`** (scaffold + workflow docs)

## Current phase

**Phase 0 (Product & Technical Discovery) is complete. The founder has ruled on D2, D3, D5/D6 (conditionally), D8 and D9.** Phase 1 (architecture and security foundation) has started as documentation only: proposed ADRs and the Astra 6 review package. Founder directive: **no major implementation yet.**

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

Proposed ADR-0002 / 0005 / 0006 and the Astra 6 review package (D5/D6 conditions).

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

None in product code (there is none).

## Technical debt / issues found (verified 2026-11-06)

| Issue                                                                                                                                          | Evidence           | Severity                         |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | -------------------------------- |
| `npm audit`: 16 vulnerabilities (4 low, 12 moderate), all in dev tooling (eslint, typescript-eslint, @sveltejs/kit chain, tailwind typography) | `npm audit`        | Low (dev-only); no high/critical |
| `adapter-auto` must become `adapter-node` for self-hosted packaging                                                                            | `vite.config.ts`   | Phase 2                          |
| Template example code (`src/lib/vitest-examples`, welcome page) still present                                                                  | repo               | Remove in Phase 2                |
| Nmap not installed on the dev machine; Python 3.13.15, Node 24.19.0, Docker 29.7.2 installed                                                   | `--version` checks | Info                             |

## Security issues

None in code. The design-level accepted risks needing founder acknowledgment are in [THREAT_MODEL.md §5](docs/security/THREAT_MODEL.md).

## Actual test results (2026-11-06)

| Command                            | Result                                        |
| ---------------------------------- | --------------------------------------------- |
| `npm run lint`                     | PASS (exit 0)                                 |
| `npm run check`                    | 0 errors, 0 warnings                          |
| `npx vitest run --project server`  | 1 test file, 1 test passed (template example) |
| Browser unit tests, Playwright e2e | NOT RUN                                       |

## Next recommended task

Astra 6 review of the architecture package. Meanwhile the founder inspects ADR-0001 and creates the private GitHub repository (instructions to follow in `docs/operations/GITHUB_SETUP.md`).
