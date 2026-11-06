# VULNEX Engineering Workflow

This repository is the shared source of truth. The agents do not see each other's conversations; the founder copies deliverables between them, and anything that matters is committed here.

## Roles

| Agent                     | Role                                  | Owns                                                                                                                    |
| ------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Founder / CEO** (human) | Orchestrator, final approval          | Priorities, milestone sign-off, merges to `main`                                                                        |
| **GPT-6**                 | Chief Architect & Independent Auditor | Architecture, specs, acceptance criteria, security design review, code review, final audit                              |
| **Argon (Gemini Pro)**    | Research & Innovation Director        | Research, competitor and vulnerability intelligence, alternative proposals, independent verification of implementations |
| **Claude Opus 5.5**       | Principal Implementation Engineer     | Code (backend, frontend, scanners, database), tests, deployment, documentation                                          |

**Rule:** Claude implements; it does not approve its own work. Architecture comes from GPT-6, verification from Argon, final sign-off from the founder.

## Milestone pipeline

```
Founder ─▶ GPT-6 spec ─▶ Argon challenge ─▶ GPT-6 approval ─▶ Claude implements
        ─▶ Argon verification ─▶ GPT-6 final audit ─▶ Founder approves ─▶ next milestone
```

Every stage leaves a file in `docs/milestones/<NN>-<slug>/`:

| File                   | Written by | Contents                                      |
| ---------------------- | ---------- | --------------------------------------------- |
| `01-spec.md`           | GPT-6      | Scope, architecture, acceptance criteria      |
| `02-challenge.md`      | Argon      | Objections, alternatives, research            |
| `03-approved-spec.md`  | GPT-6      | Final spec after the challenge                |
| `04-implementation.md` | Claude     | What was built, how to verify, known gaps     |
| `05-verification.md`   | Argon      | Independent check against acceptance criteria |
| `06-audit.md`          | GPT-6      | Final audit verdict                           |
| `07-approval.md`       | Founder    | Sign-off or change requests                   |

Start a new session with any agent by pointing it at this file and the latest milestone folder.

## Branches

- `main` — approved, stable releases only. Merged by the founder after `07-approval.md`.
- `develop` — integration branch. Feature branches merge here.
- `feature/<slug>` — one implementation task each, branched from `develop`.
- `security/<slug>` — security-sensitive changes; require GPT-6 security review before merge.

## Target layout

The layout below is a target, not a checklist. Directories are created when real code needs them, per the approved spec.

```
apps/  engines/  agents/  packages/  intelligence/  plugins/
deploy/  tests/  scripts/  docs/  .github/
```

The current SvelteKit app lives at the repo root; moving it under `apps/` is an architecture decision for milestone 01.
