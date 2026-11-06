# VULNEX Engineering Workflow

This repository is the shared source of truth. The agents do not see each other's conversations. The founder copies deliverables between them, and anything that matters is committed here.

## Roles (Master Project Instructions §3)

| Who                         | Role                                                                       | Owns                                                                                                                          |
| --------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **La Yaung Htut** (founder) | Final decision-maker                                                       | Strategy, product direction, budget, major architecture approval, release approval, merges to `main`                          |
| **Claude Opus 5.5**         | CTO, principal architect, implementation engineer, technical research lead | Architecture **proposals**, specs, research, code, tests, documentation, release preparation                                  |
| **Astra 6** (Gemini)        | Independent research and review                                            | Competitive and technical research, architecture challenges, security and detection-accuracy review, independent verification |
| **GPT-6** (when available)  | Chief Architect and independent auditor                                    | Independent architecture, security and implementation audit                                                                   |

**Rule:** no agent approves its own work. Claude proposes and implements, Astra 6 challenges and verifies, GPT-6 audits when available, and the founder approves. Until GPT-6 is available, major decisions stay marked "pending independent review". Earlier documents call the reviewer "Argon"; that is Astra 6.

## Task pipeline

```
Founder assigns ─▶ Claude proposes / implements ─▶ Claude updates PROJECT_STATE.md + AGENT_HANDOFF.md
  ─▶ Astra 6 review (docs/reviews/) ─▶ Claude addresses findings ─▶ GPT-6 audit (when available)
  ─▶ Founder approves ─▶ done per DEFINITION_OF_DONE.md
```

Review verdicts: APPROVED · APPROVED WITH CONDITIONS · NEEDS REVISION · REJECTED · NOT VERIFIED. Status labels: PROPOSED · APPROVED · IMPLEMENTED · TESTED · VERIFIED · BLOCKED · NOT IMPLEMENTED · NOT TESTED.

## Where things live

| Path                    | Contents                                                            |
| ----------------------- | ------------------------------------------------------------------- |
| `PROJECT_STATE.md`      | Phase, status, open decisions, verified commit, actual test results |
| `AGENT_HANDOFF.md`      | The current task's handoff for the reviewer                         |
| `DEFINITION_OF_DONE.md` | Completion criteria                                                 |
| `docs/product/`         | PRD, roadmap                                                        |
| `docs/architecture/`    | Architecture proposals                                              |
| `docs/security/`        | Threat model, security designs                                      |
| `docs/decisions/`       | ADRs (`ADR-NNNN.md`), each with an approval table                   |
| `docs/research/`        | Research plan and results with sources                              |
| `docs/reviews/`         | Astra 6 / GPT-6 review reports                                      |

Start a new session with any agent by pointing it at this file, `PROJECT_STATE.md` and `AGENT_HANDOFF.md`.

## Branches

- `main`: approved, stable releases only. Merged by the founder.
- `develop`: integration branch. Feature branches merge here.
- `feature/<slug>`: one task each, branched from `develop`.
- `security/<slug>`: security-sensitive changes. They need Astra 6 security review (and GPT-6 when available) before merge.

## Commits

Until the founder approves a documented Git workflow, Claude asks the founder before committing any major change, such as new or changed ADRs, architecture, code, dependencies or CI. Commit messages follow Conventional Commits (`docs:`, `feat:`, `fix:`, `chore:`). Nothing is pushed to a remote without the founder's approval, and the repository stays private.
