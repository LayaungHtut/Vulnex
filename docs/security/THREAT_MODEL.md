# VULNEX Threat Model (v0)

Status: **PROPOSED**. Every mitigation is **DESIGNED, NOT IMPLEMENTED, NOT TESTED**.
Author: Claude · Date: 2026-11-06 · Reviewer: Astra 6 (security review requested) · Scope: [INITIAL_ARCHITECTURE.md](../architecture/INITIAL_ARCHITECTURE.md) v0

Method: assets → actors → trust boundaries (TB1–TB8 from the architecture) → STRIDE threats per boundary → mitigation → how each will be verified. Revisit whenever an ADR changes a boundary.

## 1. What we protect

| Asset                                                                       | Why it matters                                                                  |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| A1 Tenant evidence and findings                                             | A map of a customer's weaknesses. Leaking it hands an attacker a target list    |
| A2 Scope definitions and asset inventory                                    | Network topology of the customer                                                |
| A3 Worker credentials, scope-signing key, plugin-signing key, worker CA key | Whoever holds them can scan in the customer's name or push code to every worker |
| A4 Session cookies, service tokens, OIDC client secret                      | Account takeover                                                                |
| A5 Integrity of findings, confidence classes and risk scores                | Wrong answers cause wrong remediation decisions; trust is the product           |
| A6 Audit log                                                                | Accountability and incident reconstruction                                      |
| A7 Third parties' systems                                                   | VULNEX must not be usable as an attack tool                                     |

## 2. Threat actors (PRD SEC-01)

T-A1 malicious or curious tenant · T-A2 external attacker with no account · T-A3 compromised worker host · T-A4 hostile scan target (returns crafted responses) · T-A5 malicious or compromised feed/plugin source · T-A6 insider (operator or support) · T-A7 dependency/supply-chain compromise · T-A8 SaaS abuser scanning systems they do not own.

## 3. Threats and mitigations

ID format: `TM-<boundary>-<n>`. Ranking (H/M/L) is my qualitative assessment of likelihood × impact for v0, not a measured score.

### TB1 Browser ↔ console/API

| ID     | STRIDE | Threat                                                                                                 | Rank | Mitigation                                                                                                                                 | Verification                                                             |
| ------ | ------ | ------------------------------------------------------------------------------------------------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| TM-1-1 | S      | Session theft or fixation                                                                              | H    | Server-side sessions; opaque random ID; `HttpOnly; Secure; SameSite=Lax`; rotate on login and privilege change; idle and absolute timeouts | Session tests; cookie flags asserted in e2e                              |
| TM-1-2 | T      | CSRF on state-changing actions                                                                         | M    | SameSite plus SvelteKit origin check plus CSRF token on API cookie routes                                                                  | Cross-origin request tests                                               |
| TM-1-3 | T/I    | **Stored XSS from scan evidence** (banners, HTTP headers and titles are attacker-controlled, see T-A4) | H    | Evidence is always rendered as text, never `{@html}`; strict CSP (no inline script); exports neutralize CSV/formula injection              | Fixture targets that return XSS and formula payloads; CSP checked in e2e |
| TM-1-4 | E      | Privilege escalation by calling the API directly with a lower role                                     | H    | Server-side deny-by-default permission checks on every route; console hiding is cosmetic only                                              | Route-enumerating role × permission test matrix                          |
| TM-1-5 | S      | MFA bypass through a fallback login path                                                               | M    | No local password path in v0; privileged roles require IdP `amr`/`acr` evidence of MFA                                                     | Login tests with MFA-less tokens                                         |

### TB2 API ↔ PostgreSQL

| ID     | STRIDE | Threat                                                    | Rank | Mitigation                                                                                                           | Verification                                                                                         |
| ------ | ------ | --------------------------------------------------------- | ---- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| TM-2-1 | I      | **Cross-tenant read** through a missing `WHERE tenant_id` | H    | RLS on every tenant table; runtime role is not owner and lacks `BYPASSRLS`; composite `(tenant_id, id)` foreign keys | Two-tenant negative tests on every route and job; a CI check that every tenant table has RLS enabled |
| TM-2-2 | I      | Tenant context leaks across pooled connections            | H    | `SET LOCAL` inside the transaction only; never session-level `SET`                                                   | Concurrency test that interleaves two tenants on one pool                                            |
| TM-2-3 | T      | SQL injection                                             | M    | SQLAlchemy parameter binding only; lint rule bans string-built SQL                                                   | Static check; injection fixtures on filter parameters                                                |
| TM-2-4 | R      | Audit tampering by the application                        | M    | App role has INSERT/SELECT only on `audit_event`; no UPDATE/DELETE grant. **No tamper-proof claim** (PRD SEC-07)     | Permission test against the role                                                                     |

### TB3 Worker ↔ worker API

| ID     | STRIDE | Threat                                                  | Rank | Mitigation                                                                                                                                                                                                                                                                | Verification                                 |
| ------ | ------ | ------------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| TM-3-1 | S      | Stolen enrollment token used to register a rogue worker | M    | Single use; expires within 24 h; stored hashed; bound to tenant and scope group; enrollment is audited and visible to admins                                                                                                                                              | Token reuse and expiry tests                 |
| TM-3-2 | S      | Stolen worker certificate                               | M    | Private key generated on the host and never transmitted; 7-day certificate; instant revocation via the worker record                                                                                                                                                      | Revoked-certificate rejection test           |
| TM-3-3 | T      | **Compromised worker forges results**                   | M    | Accepted limit: a worker can lie about **its own tenant's** targets only. Results are bound to the lease, scope group and attempt; out-of-scope or late results are rejected; the worker's identity is recorded on every observation so findings can be traced and purged | Out-of-scope and late-result rejection tests |
| TM-3-4 | I/E    | Compromised worker requests other tenants' jobs         | H    | Lease selection filters by the worker's tenant and scope group on the server; a job ID from another tenant returns 404                                                                                                                                                    | Negative lease tests                         |
| TM-3-5 | D      | Worker floods result intake                             | L    | Per-worker rate and size limits; payload schema validation before storage                                                                                                                                                                                                 | Load and oversize tests                      |

### TB4 Worker ↔ targets

| ID     | STRIDE | Threat                                                                                       | Rank | Mitigation                                                                                                                                        | Verification                                                                                                         |
| ------ | ------ | -------------------------------------------------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| TM-4-1 | E      | **Scope escape**: probing outside the authorized scope through a DNS change, redirect or bug | H    | Worker re-resolves and checks every connection against the signed scope lease; exclusions apply after resolution; caps on targets after expansion | Network-observed test: a DNS rebinding fixture and a redirect fixture must not produce off-scope packets (PRD AC-07) |
| TM-4-2 | I      | **SSRF into the worker's own environment** (cloud metadata, localhost, control plane)        | H    | Connector deny-list: loopback, link-local, metadata, control-plane addresses; private ranges only when explicitly in scope                        | Fixture targets resolving to `127.0.0.1` and `169.254.169.254`                                                       |
| TM-4-3 | D      | Scan harms a fragile target                                                                  | M    | Safe-only plugins in v0; TCP connect, no payloads; rate and concurrency caps; cancellation within 10 s                                            | Cancellation timing test; rate test with packet capture                                                              |
| TM-4-4 | T/D    | Hostile target sends huge, slow or malformed responses to exhaust or crash the worker        | M    | Read caps per probe; per-probe timeouts; parsers fuzzed; plugin subprocess rlimits                                                                | Fuzz and slow-loris fixtures                                                                                         |

### TB5 Plugin ↔ worker

| ID     | STRIDE | Threat                                                      | Rank | Mitigation                                                                                                                                                                                                          | Verification                              |
| ------ | ------ | ----------------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| TM-5-1 | T/E    | Tampered or malicious plugin bundle executes on workers     | H    | Ed25519-signed manifest with SHA-256 digests; verify before load; fail closed; first-party only in v0                                                                                                               | Tampered-bundle and wrong-key tests       |
| TM-5-2 | E      | Plugin bypasses the guarded connector and opens raw sockets | M    | **Python cannot fully prevent this.** Accepted for first-party code reviewed in CI; worker container network egress limited where the host allows. Third-party plugins are blocked until a real sandbox exists (R6) | Code review rule; container egress test   |
| TM-5-3 | I      | Plugin reads worker credentials                             | M    | Subprocess gets an empty environment and no access to the credential directory (file permissions; separate user where possible)                                                                                     | Test that plugin cannot open the key file |

### TB6 Ingester ↔ public feeds

| ID     | STRIDE | Threat                                                                              | Rank | Mitigation                                                                                                                            | Verification                          |
| ------ | ------ | ----------------------------------------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| TM-6-1 | T      | Malicious or malformed feed content (injection into UI, parser crash, huge records) | M    | Schema validation; size limits; text-only rendering; raw records kept with digests; parse failures quarantine the record, not the run | Malformed-record fixtures             |
| TM-6-2 | T      | Poisoned upstream data changes findings silently                                    | M    | Per-source values with provenance; changes create new revisions; risk recomputation records which inputs changed                      | Replay test across two feed revisions |
| TM-6-3 | D      | Feed outage leaves stale data looking fresh                                         | M    | Freshness tracking; visible stale warnings; last good snapshot kept (INT-04/05)                                                       | Outage simulation                     |

### TB7 Update distribution

| ID     | STRIDE | Threat                                                              | Rank | Mitigation                                                                                                                                | Verification                                     |
| ------ | ------ | ------------------------------------------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| TM-7-1 | T/E    | **Signing-key compromise** pushes malicious plugins to every worker | H    | Offline or hardware-held key (custody in ADR-0007); key rotation and revocation list in manifest; rollback protection (version monotonic) | Rotation drill; revoked-key test; downgrade test |
| TM-7-2 | T      | Downgrade to an older vulnerable bundle                             | M    | Monotonic version check; revoked versions listed                                                                                          | Downgrade test                                   |

### TB8 Operators ↔ customer data, and platform abuse

| ID     | STRIDE | Threat                                                     | Rank     | Mitigation                                                                                                                                                                              | Verification                                 |
| ------ | ------ | ---------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| TM-8-1 | I      | Insider or support reads tenant data                       | M        | No implicit support access; time-limited, tenant-approved, audited break-glass (PRD §10)                                                                                                | Access test and audit review                 |
| TM-8-2 | E      | **SaaS used to scan systems the user does not own** (T-A8) | H (SaaS) | SaaS is deferred (PRD A5). Before SaaS: ownership attestation, scope verification (for example DNS TXT or HTTP token for public targets), quotas, abuse review, emergency stop (SEC-08) | Abuse-scenario tests before any SaaS release |
| TM-8-3 | I      | Deleted tenant data reappears after backup restore         | M        | Deletion tombstones reapplied before service resumes (SEC-09)                                                                                                                           | Restore drill                                |
| TM-8-4 | T      | Dependency or supply-chain compromise                      | M        | Lockfiles (`package-lock.json`, `uv.lock`); `npm audit`/`pip-audit`; gitleaks; SBOM; pinned base images; Dependabot or Renovate once a remote exists                                    | CI gates                                     |

## 4. Future AI (not in v0)

When AI arrives (Master Instructions §16), add: prompt injection through evidence and advisory text, tenant data leaking to external models, AI output presented as a finding. Required mitigations: AI is read-only over authorized, tenant-scoped retrieval; it has no tool that can change findings, scores or scans; it cites evidence; data goes to external providers only with tenant consent.

## 5. Accepted risks (need founder acknowledgment)

1. A compromised worker can falsify results for its own tenant's scope (TM-3-3). Detection beyond traceability is out of v0.
2. First-party plugin isolation is defense in depth, not a sandbox (TM-5-2).
3. The audit log is append-only by permissions, not cryptographically tamper-evident (TM-2-4).
4. A self-hosted root operator is outside VULNEX's control (PRD §10).

## 6. Not yet modeled

Billing and licensing enforcement, AI, authenticated scanning credentials (M2: credential storage becomes a top threat), SaaS multi-region, and air-gapped update transport.
