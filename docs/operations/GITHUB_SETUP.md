# Private GitHub repository and basic CI: setup instructions

Status: **PROPOSED** (founder decision D8, 2026-11-06). The repository has **not** been created and nothing has been pushed. **The repository must stay private.**

Who runs this: the founder, or Claude with the founder's explicit go-ahead for each outward-facing step (creating the repository, pushing).

Facts marked _check_ come from my knowledge of GitHub plans and may have changed. Confirm them on GitHub's pricing and docs pages before relying on them.

## 1. Before you start

- [ ] Your GitHub account has **two-factor authentication** enabled (Settings → Password and authentication).
- [ ] Decide the owner: your **personal account** (simplest) or a **VULNEX organization**. An organization costs nothing on the free plan and makes adding people later cleaner. However, the gitleaks Action then needs a (free) license key; see §4.
- [ ] Locally: `git status` on `develop` is clean, apart from changes you have approved.

## 2. Create the repository (private)

**Web UI (recommended, no extra tools):**

1. github.com → **New repository**.
2. Name: `VULNEX`. Visibility: **Private**.
3. **Do not** add a README, .gitignore or license, because the local repository already has them.
4. Create.

**Or with GitHub CLI** (not installed on this machine yet):

```sh
gh auth login
gh repo create VULNEX --private --source . --remote origin
```

## 3. Connect and push

```sh
git remote add origin https://github.com/<owner>/VULNEX.git   # skip if gh already added it
git push -u origin main
git push -u origin develop
```

Afterwards, confirm on GitHub that the repository shows the **Private** badge.

## 4. Repository settings

| Setting                                                                                                        | Where                                            | Value                                                                                                                              | Why                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Default branch                                                                                                 | Settings → General                               | `develop`                                                                                                                          | PRs target integration; `main` holds approved releases only (WORKFLOW.md)                                                                                      |
| Actions permissions                                                                                            | Settings → Actions → General                     | "Allow _owner_, and select non-_owner_, actions": allow `actions/checkout@*`, `actions/setup-node@*`, `gitleaks/gitleaks-action@*` | Limits third-party code in CI (THREAT_MODEL TM-8-4)                                                                                                            |
| Workflow permissions                                                                                           | same page                                        | **Read repository contents** (read-only); do **not** allow Actions to create or approve PRs                                        | Least privilege for `GITHUB_TOKEN`                                                                                                                             |
| Fork PR workflows                                                                                              | same page                                        | Require approval for all outside collaborators                                                                                     | No untrusted code runs with repository access                                                                                                                  |
| Dependabot alerts + security updates                                                                           | Settings → Code security                         | Enable                                                                                                                             | Free for private repos (_check_)                                                                                                                               |
| Secret scanning / push protection                                                                              | Settings → Code security                         | Enable if offered                                                                                                                  | For private repos this may need a paid GitHub security product (_check_). The gitleaks CI job covers us either way                                             |
| Branch protection for `main` and `develop`: require PR, require the `CI` checks, block force-push and deletion | Settings → Branches / Rules                      | Enable if your plan allows                                                                                                         | Protected branches / rulesets on **private** repos may require GitHub Pro or Team (_check_). On the free plan, rely on the commit-approval rule in WORKFLOW.md |
| gitleaks license                                                                                               | Settings → Secrets → Actions: `GITLEAKS_LICENSE` | Only if the repo is owned by an **organization**                                                                                   | gitleaks-action is free for personal accounts; organizations need a free key from gitleaks.io (_check_)                                                        |

Do **not** add any other secrets. CI needs none.

## 5. CI (`.github/workflows/ci.yml`, prepared and uncommitted)

It runs on pushes to `main`/`develop` and on pull requests:

| Job       | Steps                                                                                                    | Verified locally?                                                                                                                                                                                                                                                   |
| --------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `console` | `npm ci` → `npm run lint` → `npm run check` → `vitest --project server` → `npm audit --audit-level=high` | Lint, check, tests and audit pass on Windows. `npm ci` itself failed locally with `EPERM`, because the editor held a native module open. That is a Windows file lock, not a lockfile problem; it is expected to pass on GitHub's Linux runners but **NOT VERIFIED** |
| `secrets` | gitleaks over full history                                                                               | **NOT VERIFIED** (gitleaks not installed locally)                                                                                                                                                                                                                   |

Not yet in CI, added when code exists: Python (`ruff`, `mypy`, `pytest`, `pip-audit`), PostgreSQL service for RLS tests, browser tests, SBOM (syft) and container scanning (trivy).

**Minutes:** private repositories on the free plan include a monthly allowance of Actions minutes (about 2,000/month at last knowledge; _check_). This workflow should use only a few minutes per run.

## 6. After the first push

- [ ] The Actions tab shows a CI run for `develop`; both jobs green. If gitleaks flags anything, stop and tell Claude. Do not dismiss it.
- [ ] Record the run URL and result in `PROJECT_STATE.md`.
- [ ] Optional: add `.github/dependabot.yml` for the `npm` and `github-actions` ecosystems, then pin actions to commit SHAs.
