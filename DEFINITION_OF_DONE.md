# Definition of Done

Status: **PROPOSED** (founder approval pending) · Date: 2026-11-06

Work is **done** only when every applicable item below is true **and the evidence is linked in `AGENT_HANDOFF.md`**. "Implemented" is not "done". Use the status labels exactly: PROPOSED · APPROVED · IMPLEMENTED · TESTED · VERIFIED · BLOCKED · NOT IMPLEMENTED · NOT TESTED.

## All work

- [ ] The relevant approved spec or ADR exists. If the work deviates from it, an ADR amendment exists.
- [ ] `npm run lint`, `npm run check`, unit tests and (Python) `ruff`, `mypy --strict` and `pytest` pass locally and in CI. The actual output summary is recorded.
- [ ] Tests exercise behaviour, including failure paths. No test merely asserts that a function exists.
- [ ] No secrets in code, config, logs, fixtures or commit history (gitleaks clean).
- [ ] No security check was disabled, skipped or weakened to make anything pass.
- [ ] No mock, stub or synthetic data reachable from a production code path. Test doubles live only in test code and are labeled.
- [ ] `PROJECT_STATE.md` and `AGENT_HANDOFF.md` are updated. Known limitations are written down, not omitted.

## Features

- [ ] Acceptance criteria from the spec are each shown passing, with the test name or the manual evidence.
- [ ] Authorization is enforced server-side and tested for each role that should and should not have access.
- [ ] UI states for loading, empty, error and partial coverage exist. No success state hides incomplete work (PRD NFR-08).
- [ ] Keyboard access, visible focus and labeled controls on new UI (PRD NFR-04).

## APIs

- [ ] OpenAPI contract updated and the diff reviewed. Breaking changes follow PRD API-05.
- [ ] Input validation at the boundary; RFC 9457 errors; no stack traces; correlation ID present.
- [ ] Pagination bounded; idempotency on create-type operations that may be retried.
- [ ] **Cross-tenant negative test** for every tenant-bearing endpoint (404 for another tenant's IDs).

## Database changes

- [ ] Alembic migration upgrades from the previous release on a copy of realistic data. Any downgrade limitation is documented.
- [ ] Every new tenant table has `tenant_id`, composite keys, RLS enabled with a policy, and is covered by the RLS CI check.
- [ ] Runtime role grants are least-privilege. Append-only tables have no UPDATE/DELETE grant.
- [ ] Indexes justified by a query that uses them.

## Security-sensitive work (auth, tenancy, worker trust, signing, scope, credentials, exports)

- [ ] Branch `security/<slug>`; the threat model entry is updated.
- [ ] Negative and abuse tests (forged, expired, revoked, out-of-scope, replayed inputs).
- [ ] Independent review by Astra 6 (verdict recorded) before merge to `develop`; GPT-6 audit when available.

## Scanner plugins

- [ ] Manifest complete (Master Instructions §12 fields); safety class `safe` for v0.
- [ ] Positive, negative, ambiguous and timeout fixtures pass. The fixtures are labeled synthetic or lab-derived, with their source.
- [ ] Never emits `CONFIRMED` from version-only evidence (enforced by a fixture).
- [ ] Network use only through the guarded connector; resource limits declared and tested.
- [ ] Signed in the release bundle; the tampered-bundle test still fails closed.

## Releases

- [ ] All of the above for included work; no open critical/high security defects (PRD SEC-10).
- [ ] Clean install, upgrade from the previous release, and backup/restore exercised on the reference deployment, with evidence attached.
- [ ] SBOM generated; dependency and container scans reviewed; licenses checked.
- [ ] Release notes list known limitations and unsupported coverage.
- [ ] Astra 6 verification and founder approval recorded. The founder merges to `main`.
