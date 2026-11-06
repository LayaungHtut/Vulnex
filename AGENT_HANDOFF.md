# Agent Handoff

**Current task:** Master Instructions §28, first assignment: repository inspection, product discovery, architecture proposal, research plan, roadmap, documentation foundation.
**From:** Claude · **To:** Astra 6 (independent review); GPT-6 when available · **Date:** 2026-11-06 · **Branch:** `develop`, uncommitted

## Relevant documents (read in this order)

1. [docs/product/PRD.md](docs/product/PRD.md): v0.1 (pre-existing) + **Amendment A** (new, end of file)
2. [docs/architecture/INITIAL_ARCHITECTURE.md](docs/architecture/INITIAL_ARCHITECTURE.md)
3. [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md)
4. [docs/decisions/ADR-0001.md](docs/decisions/ADR-0001.md)
5. [docs/research/RESEARCH_PLAN.md](docs/research/RESEARCH_PLAN.md), [docs/product/ROADMAP.md](docs/product/ROADMAP.md), [DEFINITION_OF_DONE.md](DEFINITION_OF_DONE.md), [PROJECT_STATE.md](PROJECT_STATE.md)

## Files changed

| File                                                                                                                                                                    | Change                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `PRODUCT_REQUIREMENTS.md` → `docs/product/PRD.md`                                                                                                                       | Moved. Added a status note after the header and Amendment A at the end. v0.1 body unchanged apart from Prettier whitespace                      |
| `COMPETITIVE_ANALYSIS.md`, `COMPETITOR_FEATURE_MATRIX.md`, `MARKET_OPPORTUNITIES.md`, `RESEARCH_SOURCES.md` → `docs/research/`                                          | Moved together so relative links still resolve. Added an authorship line (founder decision); otherwise unchanged apart from Prettier whitespace |
| `docs/architecture/INITIAL_ARCHITECTURE.md`, `docs/security/THREAT_MODEL.md`, `docs/decisions/ADR-0001.md`, `docs/research/RESEARCH_PLAN.md`, `docs/product/ROADMAP.md` | New                                                                                                                                             |
| `PROJECT_STATE.md`, `AGENT_HANDOFF.md`, `DEFINITION_OF_DONE.md`                                                                                                         | New                                                                                                                                             |
| `README.md`, `docs/WORKFLOW.md`                                                                                                                                         | Updated: roles per Master Instructions §3 ("Argon" is now Astra 6), document index                                                              |

No code, dependency, configuration, database or API changes.

## Decisions made

None. All items are PROPOSED. Founder decisions D1–D9 are listed in PROJECT_STATE.md.

## Tests executed

`npm run check` passes; the template server unit test passes; `npm run lint` fails on pre-existing Prettier issues (details in PROJECT_STATE.md). Nothing VULNEX-specific exists to test.

## Known issues / weaknesses I want challenged

1. **P2, PostgreSQL pull queue with no broker.** Is long-poll leasing adequate at PRD §20 targets (dispatch p95 ≤30 s, cancellation ≤10 s)? Cancellation is delivered on the next poll or heartbeat, so the poll interval bounds it.
2. **P5, Nmap deferral.** My NPSL reading is from memory and is UNVERIFIED. If it is wrong, custom discovery is wasted effort. If it is right, the fingerprinting quality gap is real.
3. **TM-5-2, plugin isolation.** A subprocess plus rlimits does not stop a Python plugin from opening raw sockets. Is "first-party only plus code review plus container egress limits" acceptable for v0?
4. **TM-3-3.** A compromised worker can forge results within its own tenant's scope. Is traceability enough for v0?
5. **PRD A1, confidence classes.** Are the `PROBABLE` criteria (banner package revision mapping to an unfixed advisory state) sound, or should banner evidence never exceed `POTENTIAL`?
6. **Roadmap effort (6–9 months for M1).** The estimate is uncalibrated. Challenge it.
7. **Risk model v0 (PRD §15).** The unknown-input defaults (X=15, B=10) push items with unknown context upward. Is that the right failure direction?

## Reviewer instructions

- Review against the Master Instructions and PRD v0.1. Flag any place where I silently changed approved scope (I believe there is none; all changes are in Amendment A and marked).
- Verify or refute every claim marked **UNVERIFIED** (Nmap NPSL, MinIO distribution, NVD backlog, IdP memory use, OpenSSH banner revisions) against primary sources.
- Use the verdicts APPROVED / APPROVED WITH CONDITIONS / NEEDS REVISION / REJECTED / NOT VERIFIED, per document.
- Write the review to `docs/reviews/2026-11-06-foundation-review.md`.
