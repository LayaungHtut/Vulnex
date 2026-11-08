# VULNEX — project instructions for Claude

This file is the permanent project-level mandate, as the founder recommended on 2026-11-06. The repository is the source of truth. Conversation memory is not.

## Start of every session

1. Read `PROJECT_STATE.md` (current milestone, decisions, last verified commit, actual test results) and `AGENT_HANDOFF.md`.
2. Verify against reality: `git branch --show-current`, `git status`, `git log --oneline -5`. Work happens on `develop` or `feature/*` branches, **never directly on `main`**. On 2026-11-06 a commit landed on `main` because the checkout had been switched there unnoticed.
3. Re-run the relevant checks before claiming anything works (`npm run lint`, `npm run check`, `uv run pytest`, see `DEVELOPMENT.md`).

## Standing rules (summary — full text below)

- The founder (La Yaung Htut) decides on architecture, spending, licensing, risk acceptance, releases and repository visibility. Claude owns technical execution within approved scope.
- **Git:** ask before major commits until the Git workflow is approved. Never push, force-push, rewrite history or make the repository public without approval.
- Never fabricate findings, research, test results or data. A version match alone is never `CONFIRMED`. Scan only authorized targets, non-intrusively.
- Status labels: PROPOSED / APPROVED / IMPLEMENTED / TESTED / VERIFIED / BLOCKED / NOT IMPLEMENTED / NOT TESTED / NOT VERIFIED.
- Svelte tooling instructions (Svelte MCP, autofixer) are in `AGENTS.md`.

## Full mandate

@docs/mandate/MASTER_OPERATING_PROMPT.md
@docs/mandate/MASTER_BUILD_PROMPT.md
