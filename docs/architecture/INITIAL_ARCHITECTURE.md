# VULNEX Initial Architecture (v0 proposal)

Status: **PROPOSED**. No part of this document is approved.
Author: Claude · Date: 2026-11-06 · Reviewers: Astra 6 (independent review), GPT-6 (audit, when available) · Decision authority: Founder

Inputs: [PRD v0.1 + Amendment A](../product/PRD.md), [research](../research/), Master Project Instructions §9–16, [threat model](../security/THREAT_MODEL.md).

Labels used below: **PROPOSED** = my recommendation, awaiting review. **UNVERIFIED** = a claim from my own knowledge that I have not checked against a primary source in this session; it is tracked in the [research plan](../research/RESEARCH_PLAN.md).

## 1. Summary of proposals

| #   | Proposal                                                                                                                                                                  | Why                                                                                                                                                                        | Needs                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| P1  | **Modular monolith** control plane (FastAPI) that also contains the intelligence and risk modules; **separately deployed scanner worker**                                 | Founder directive §10; one founder cannot run a service fleet                                                                                                              | [ADR-0001](../decisions/ADR-0001.md) |
| P2  | **Workers pull jobs** over outbound HTTPS with mTLS; the job queue is a **PostgreSQL table** (`FOR UPDATE SKIP LOCKED`); **no message broker** in v0                      | Hybrid mode forbids inbound ports to customer networks; leases and idempotency are easier to reason about in one transactional store                                       | ADR-0003                             |
| P3  | **PostgreSQL Row-Level Security** plus application authorization; tenant-composite foreign keys                                                                           | PRD SEC-02 requires RLS; composite keys stop cross-tenant references at the schema level                                                                                   | ADR-0005                             |
| P4  | Humans authenticate with **OIDC** (external or bundled IdP); server-side sessions; services use hashed scoped tokens; workers use mTLS certificates                       | PRD SEC-03/API-04; MFA is delegated to the IdP and verified via claims                                                                                                     | ADR-0004                             |
| P5  | **Own TCP-connect discovery** in the worker for v0; **Nmap integration deferred until its license is reviewed**                                                           | My understanding (UNVERIFIED, R1) is that the Nmap Public Source License restricts commercial products that ship Nmap or that are built specifically to drive and parse it | ADR-0008                             |
| P6  | First-party detection plugins only, as signed bundles, each running in a resource-limited subprocess with network access only through the worker's scope-enforcing client | PRD excludes customer plugins; real sandboxing for third-party code is a later research item                                                                               | ADR-0007                             |
| P7  | Evidence stored in PostgreSQL (redacted, size-capped) in v0; object storage deferred                                                                                      | Bounded, redacted evidence is small; removes a service from the laptop and self-hosted footprint                                                                           | ADR-0011                             |
| P8  | Move the SvelteKit app to `apps/console`; Python code under `engines/`                                                                                                    | Founder's layout §18, minus empty directories                                                                                                                              | ADR-0002                             |
| P9  | Release **self-hosted first**, then hybrid, then SaaS; design multi-tenant from the first migration                                                                       | PRD Amendment A5                                                                                                                                                           | Founder decision D2                  |

## 2. Constraints this design respects

- One founder plus AI agents, a 16 GB laptop, no paid infrastructure assumed. The whole development stack must run under roughly 4 GB RAM.
- Every service added is something to secure, upgrade, back up and explain. Each one must justify itself.
- All three deployment modes must remain possible, so nothing may depend on a proprietary cloud service or on inbound connections into customer networks.
- Detection and risk must work with no AI and no internet access other than intelligence feeds.

## 3. Components

```
                 ┌──────────── VULNEX control plane (one deployable, PROPOSED) ─────────────┐
 Browser ─HTTPS─▶│ Console (SvelteKit SSR)  ──internal HTTP──▶  API (FastAPI)               │
                 │                                              ├ identity & tenancy        │
                 │                                              ├ assets & scope            │
                 │                                              ├ scans & job queue         │
                 │                                              ├ findings & remediation    │
                 │                                              ├ intelligence (read side)  │
                 │                                              ├ risk engine (pure module) │
                 │                                              └ reports & audit           │
                 │  Worker API listener (mTLS) ──────────────────┘                          │
                 │  Background runner (same codebase): schedules, ingestion, exports       │
                 │  PostgreSQL (RLS)                                                        │
                 └───────────────────────────────▲─────────────────────────┬────────────────┘
                                                 │ outbound mTLS only      │ HTTPS
                          ┌──────────────────────┴───────┐        ┌────────▼──────────────┐
                          │ Scanner worker (customer net) │        │ Public intel sources  │
                          │ scope guard · discovery ·     │        │ CVE, NVD, KEV, EPSS,  │
                          │ plugin runner · evidence      │        │ vendor/distro (R3)    │
                          └──────────────┬────────────────┘        └───────────────────────┘
                                         │ scoped probes only
                                         ▼
                                 Authorized targets
```

| Component                   | Responsibility                                                                                      | Not responsible for                                                |
| --------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Console                     | Rendering, form validation for user experience, calling the API server-side with the user's session | Authorization decisions (the API decides; the console only hides)  |
| API: identity & tenancy     | OIDC login, sessions, memberships, roles, service tokens, tenant context per request                | Storing passwords (the IdP does that)                              |
| API: assets & scope         | Asset records, identifier history, scope definitions, target expansion preview                      | Network access                                                     |
| API: scans & job queue      | Profiles, schedules, runs, tasks, leases, cancellation, result intake                               | Executing probes                                                   |
| API: findings & remediation | Deduplication, confidence class, lifecycle, exceptions, verification                                | Deciding detection logic (plugins do)                              |
| Intelligence                | Ingesting sources, provenance, normalization, freshness, correlation lookups                        | Customer data (intelligence tables are global and tenant-free)     |
| Risk engine                 | Deterministic score, band and contributions from an input snapshot and a model version              | Anything non-deterministic; it has no I/O                          |
| Background runner           | Schedules, ingestion runs, exports, retention jobs, using the same PostgreSQL queue                 | Long-running scans (workers do those)                              |
| Scanner worker              | Enrollment, heartbeat, lease jobs, enforce scope on every connection, run plugins, return evidence  | Persisting anything beyond its credentials and in-flight job state |

## 4. Scan-to-dashboard data flow

1. An Owner/Admin creates a **scope** (CIDRs, hostnames, exclusions) bound to a **scope group**, and generates a worker **enrollment token** for that group.
2. The worker enrolls (§5.1), receives a client certificate and starts heartbeating.
3. An Analyst launches a scan from a versioned profile. The API expands and validates targets against scope and exclusions (FR-02), snapshots the profile, plugin manifest and scope, and inserts **tasks** into the queue.
4. The worker long-polls `POST /worker/v1/leases`. The API selects tasks for that worker's scope group with `SKIP LOCKED` and returns them with a lease ID, deadline and **signed scope lease** (§5.2).
5. The worker re-checks every resolved destination against the scope lease, probes, runs plugins and submits **observations** with an idempotency key `(task_id, attempt, plugin_id, plugin_version, target)`.
6. The API stores observations unchanged, then derives findings. It runs correlation against intelligence, assigns the confidence class using plugin rules (PRD Amendment A1), deduplicates (PRD §13) and computes risk (§10) from a stored input snapshot.
7. The console reads findings, evidence, coverage and risk explanations from the API. Every number on the dashboard is a query over these tables. There is no client-side or placeholder data.
8. A remediation owner claims a fix, which schedules a verification task for the same asset, component and check. Only a `NOT_AFFECTED` outcome from a comparable successful check resolves the finding.

## 5. Scanner architecture

### 5.1 Enrollment and identity

- The admin creates a single-use enrollment token, stored as a hash, valid for 24 hours or less and bound to a tenant and scope group.
- The worker generates an Ed25519 or P-256 key pair locally and sends a CSR with the token over server-authenticated TLS. The API issues a client certificate from a **VULNEX worker CA** that is specific to the deployment. Proposed lifetime: 7 days, renewed at 50% of its life.
- The worker API is a separate listener that requires a client certificate. The certificate fingerprint maps to a worker record. Revocation is immediate through that record, so no CRL or OCSP infrastructure is needed in v0. Short certificate lifetimes limit the damage if the worker database row is lost.
- Undecided (ADR-0006): whether the uvicorn listener terminates TLS itself or a reverse proxy (Caddy) verifies client certificates and forwards a trusted header. A proxy-forwarded header is safe only if the API listener is unreachable except through the proxy.

### 5.2 Scope enforcement on the worker (independent of the control plane)

- Each lease carries a scope lease: tenant, allowed CIDRs and hostnames, exclusions, validity window, job ID, all signed by the control plane's scope-signing key. The worker refuses unsigned or expired leases.
- All plugin network I/O goes through one guarded connector. It resolves DNS itself, checks every resolved address against the scope lease and exclusions, and refuses loopback, link-local and metadata addresses (for example `169.254.169.254`), the control-plane address, and multicast/broadcast. A scope lease can permit a private range explicitly. Redirects and re-resolution are checked again.
- Rate, concurrency, per-task time and total-target caps are enforced in the worker, not only at dispatch (FR-07).
- When the lease expires or the job is cancelled, the worker stops new probes within 10 s and abandons in-flight probes within 30 s (PRD §20).

### 5.3 Discovery and fingerprinting (v0)

- TCP connect scanning (asyncio) over the profile's port list. It needs no raw sockets and no elevated capabilities, and it is non-intrusive by design. Host liveness is inferred from TCP responses. ICMP and ARP are deferred because they need privileges.
- Service fingerprinting through protocol-specific, read-only handshakes for catalog services only (for example SSH banner, HTTP `Server` header and TLS handshake metadata). Raw responses are size-capped and stored as evidence.
- Nmap (`-sV` and its probe database) is the established alternative with much better coverage. **It is not adopted until R1 confirms the license terms.** If R1 permits customer-installed Nmap invoked as an external tool, the plugin interface below can wrap it without changes.
- UDP, SYN scanning, OS detection and IPv6 are out of v0 (PRD §7).

### 5.4 Plugin framework

Each plugin ships a manifest with the fields the Master Instructions §12 require: `id`, `version`, metadata, supported platforms and services, prerequisites, safety class, permissions (which ports and protocols it may touch), resource limits, evidence JSON Schema, vulnerability references, remediation text, fixtures, minimum worker version.

- **Types:** `discovery`, `fingerprint`, `check`. A check returns exactly one of the five confidence-class outcomes with evidence that validates against its schema. Outcomes that fail validation are recorded as `UNKNOWN` with an error.
- **Safety:** v0 permits only `safe` checks: read-only, no authentication attempts, no payloads that change state. The worker refuses to load anything else.
- **Execution:** one subprocess per plugin run with a wall-clock timeout, CPU, memory and file-descriptor limits (rlimits on Linux), no inherited secrets, and I/O only through the guarded connector over a pipe. Python cannot sandbox Python in-process, so this isolation is defense in depth for **first-party** code only. Third-party plugins require a real sandbox (gVisor, nsjail or WASM; R6) and a separate ADR.
- **Distribution:** plugins ship as a versioned bundle with a manifest of SHA-256 digests, signed with Ed25519. The worker verifies the signature and digests before loading anything and fails closed. Key custody and rotation are in ADR-0007; TUF is evaluated in R7.
- **Fixtures:** every released check has positive, negative and ambiguous fixtures plus a timeout fixture (PRD AC-04). They run as recorded protocol transcripts in CI and against lab containers before release.

## 6. API architecture

- REST/JSON under `/api/v1` (users and service tokens) and `/worker/v1` (mTLS only, separate listener). OpenAPI is generated from FastAPI/Pydantic models and committed, and contract changes are reviewed as diffs.
- Pagination uses opaque cursors with bounded page size. Errors use RFC 9457 problem details with a correlation ID. A record in another tenant returns 404, never 403, so the API does not reveal that it exists.
- `Idempotency-Key` on scan submission, export creation and result submission. Lifecycle updates use optimistic concurrency (`version` column, `If-Match`).
- The console calls the API from SvelteKit server code with the session cookie forwarded. The browser never holds API tokens. SvelteKit's built-in CSRF origin check plus SameSite cookies protect form actions, and the API also requires a CSRF token for cookie-authenticated unsafe methods.

## 7. Database architecture

- PostgreSQL 17 (version pinned in ADR), accessed through SQLAlchemy 2.x Core/ORM with psycopg 3. Schema changes go through Alembic.
- **Roles:** `vulnex_owner` owns the schema and runs migrations. `vulnex_app` is used at runtime, has no ownership, no `BYPASSRLS`, and only INSERT/SELECT on audit tables. A `vulnex_readonly` role exists for operators.
- **Tenant isolation:**
  - Every tenant table has `tenant_id NOT NULL` and a composite unique key `(tenant_id, id)`. Child tables reference `(tenant_id, parent_id)`, so a row cannot point at another tenant's row.
  - RLS policies check `tenant_id = current_setting('app.tenant_id')::uuid`.
  - The API sets the tenant with `SET LOCAL` inside each transaction, so a pooled connection cannot carry tenant context to the next request.
  - Global intelligence tables carry no tenant data and no RLS.
- **Append-only data:** observations, evidence, score snapshots, state transitions and audit events are never updated in place. Corrections are new rows.
- **Core entities (first cut):** `tenant`, `user`, `membership`, `session`, `service_token`, `audit_event`, `asset`, `asset_identifier`, `scope`, `scope_group`, `worker`, `enrollment_token`, `scan_profile`, `scan_run`, `scan_task`, `observation`, `evidence`, `finding`, `finding_transition`, `exception`, `risk_snapshot`; global: `intel_source`, `intel_raw_record`, `vulnerability`, `vulnerability_alias`, `affected_product`, `severity_metric`, `kev_entry`, `epss_score`, `intel_ingest_run`.
- **Queue:** `job` table (`queue`, `tenant_id`, `payload`, `state`, `lease_owner`, `lease_expires_at`, `attempt`, `idempotency_key`). Expired leases are reclaimed by a sweeper, and results from stale attempts are rejected. Revisit a broker only if measured contention or latency fails PRD §20 targets.

## 8. Multi-tenancy and authorization

- A request has exactly one tenant context, chosen explicitly. Users with several memberships switch context. There is no cross-tenant aggregation in v0 (PRD §3).
- Authorization is enforced in API dependencies with deny-by-default role → permission maps (PRD §10), and RLS backs it up. Background jobs carry `tenant_id` and set it the same way.
- Required tests: for every tenant-bearing endpoint and job type, a second tenant's credentials must get 404 or an empty result, and must be unable to write. A test enumerates routes so that a new endpoint without a tenant test fails CI.

## 9. Intelligence ingestion

- One adapter per source with three methods: `fetch(cursor)`, `parse(raw)`, `normalize(parsed)`. Raw records are stored with source, upstream ID, fetch time, SHA-256 digest and parser version before any normalization (PRD INT-01).
- Upserts are idempotent, keyed on `(source, upstream_id)`, and change only when the digest changes. Each source keeps a checkpoint cursor so an interrupted run resumes. A failed run keeps the last good snapshot and raises a freshness alert (INT-04).
- Values are stored **per source**. Severity, affected ranges and dates are never merged into one "true" value. A versioned **selection policy** chooses which value the risk engine uses and records why.
- v0 candidate sources (licensing and terms checked in R3): CVE List V5, NVD API 2.0 (CVSS and CPE enrichment), CISA KEV, FIRST EPSS. Vendor and distribution advisories (Debian, Ubuntu, Red Hat CSAF/OVAL, OSV) come with authenticated assessment (M2), because without package evidence they cannot be applied correctly.
- UNVERIFIED: NVD CPE enrichment has had a large backlog since 2024. Correlation must therefore not depend on NVD CPE alone. Plugins carry their own product identity and affected-version logic, and the vulnerability references are metadata.

## 10. Risk engine

- A pure function: `score(inputs: RiskInputs, model: RiskModelVersion) -> RiskResult(score, band, contributions[], missing[])`. It has no I/O, clock or randomness, so it is unit-testable and replayable (PRD AC-08).
- `risk-model v0` is the PRD §15 formula, proposed only. The model version, input snapshot and result are stored for every computation. A model change creates a new version and never rewrites history.
- A regression fixture set of input/expected-output pairs must pass for every model version. AI never reads from or writes to this module.

## 11. Deployment

- **Packaging:** OCI images for `console` (SvelteKit with `adapter-node`, replacing `adapter-auto`), `api` (with the background runner as a second entrypoint of the same image) and `worker`. Images run as non-root with read-only filesystems where possible.
- **Development and the self-hosted reference:** Docker Compose with `postgres`, `api`, `runner`, `console`, `worker`, an IdP (choice in R8) and a reverse proxy for TLS (Caddy proposed). Estimated memory without the IdP is about 1.5 GB (estimate, not measured). Some IdPs (for example Keycloak) add roughly 0.5–1 GB (UNVERIFIED).
- **Hybrid:** the same control plane, with the worker image running on a customer host that has outbound HTTPS to the worker API only.
- **SaaS:** later. It adds managed workers, abuse controls (PRD SEC-08), backups and on-call.
- **Platforms:** Linux x86_64 servers and workers for the reference. The founder's Windows laptop runs everything through Docker Desktop. Native Windows workers are not supported in v0.

## 12. Observability

- Structured JSON logs carry a correlation ID, tenant ID and actor ID. A redaction filter removes secrets, tokens and evidence payloads before anything is written.
- `/healthz` (process up) and `/readyz` (database and migrations OK) on each service. Prometheus metrics are served on an internal-only port.
- OpenTelemetry tracing is deferred until there is a multi-process latency problem to debug. Grafana is optional and not part of the reference stack.

## 13. Security boundaries

| ID  | Boundary                               | Main control                                                                                     |
| --- | -------------------------------------- | ------------------------------------------------------------------------------------------------ |
| TB1 | Browser ↔ console/API                  | OIDC, server-side sessions, CSRF, CSP, output encoding of all evidence                           |
| TB2 | API ↔ PostgreSQL                       | Non-owner runtime role, RLS, `SET LOCAL` tenant, parameterized SQL only                          |
| TB3 | Worker ↔ worker API                    | mTLS identity, scope-group binding, leases, idempotent results, revocation                       |
| TB4 | Worker ↔ targets                       | Signed scope lease, guarded connector, safe-only plugins, rate caps                              |
| TB5 | Plugin ↔ worker                        | Signed bundle, subprocess limits, no secrets, I/O only through the connector                     |
| TB6 | Ingester ↔ public feeds                | Treated as untrusted input: schema validation, size limits, no code execution, digest provenance |
| TB7 | Update distribution ↔ workers/installs | Signatures, digests, revocation, fail closed                                                     |
| TB8 | Operators ↔ customer data              | No implicit support access; time-limited, audited break-glass                                    |

Threats per boundary: [THREAT_MODEL.md](../security/THREAT_MODEL.md).

## 14. Technology choices (all PROPOSED)

| Area           | Proposal                                                                                                                    | Alternatives                      | Reason                                                                                          |
| -------------- | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------- |
| Frontend       | SvelteKit 5 + TS strict + Tailwind 4 (already scaffolded), `adapter-node`, `@lucide/svelte`, ECharts when charts are needed | React/Next                        | Founder's expertise; already present                                                            |
| Backend        | Python 3.13, FastAPI, Pydantic v2                                                                                           | Django, Litestar                  | Founder's expertise; typed contracts; OpenAPI generation                                        |
| Data access    | SQLAlchemy 2.x + Alembic + psycopg 3                                                                                        | SQLModel, raw SQL                 | Mature; RLS works through plain SQL `SET LOCAL`                                                 |
| Python tooling | uv (environments and lockfile), ruff, mypy (strict), pytest                                                                 | Poetry, pip-tools                 | Fast and reproducible on a small laptop                                                         |
| Database       | PostgreSQL 17                                                                                                               | —                                 | RLS, JSONB, `SKIP LOCKED`                                                                       |
| Queue          | PostgreSQL table                                                                                                            | NATS, RabbitMQ, Redis             | One fewer service; transactional with results (P2)                                              |
| Object storage | none in v0                                                                                                                  | MinIO, Garage, SeaweedFS, S3      | UNVERIFIED: MinIO's community distribution changed in 2025; avoid committing until needed (R12) |
| IdP            | choose in R8                                                                                                                | Keycloak, Zitadel, Authentik, Dex | License, RAM and MFA support all matter                                                         |
| Proxy/TLS      | Caddy                                                                                                                       | nginx, Traefik                    | Simple config, automatic TLS                                                                    |
| CI             | GitHub Actions: lint, types, tests, `npm audit`/`pip-audit`, gitleaks, SBOM (syft), container scan (trivy)                  | —                                 | Founder §9; needs a remote repository first                                                     |

## 15. Proposed repository layout (ADR-0002)

```
apps/console/            SvelteKit app (moved from repo root)
engines/api/             Python control plane: src/vulnex/{identity,assets,scans,findings,intel,risk,audit,api}, migrations/, tests/
engines/scanner/         Python worker: src/vulnex_scanner/, plugins/ (first-party), fixtures/, tests/
packages/worker-protocol/ Shared Pydantic models + JSON Schema for /worker/v1 (only shared code)
deploy/compose/          Docker Compose reference stack
docs/                    product, architecture, security, decisions, research
```

This differs from the founder's §18 sketch in one way: `intelligence` and `risk` are **modules inside `engines/api`**, not separate engines, because P1 keeps them in one deployable. They can be split out later behind the same interfaces if measurements justify it. Directories are created only when code lands in them.

## 16. ADRs required before dependent implementation

| ADR                              | Decision                                                        | Blocks phase |
| -------------------------------- | --------------------------------------------------------------- | ------------ |
| [0001](../decisions/ADR-0001.md) | Modular monolith + separate workers                             | 2            |
| 0002                             | Repository layout and toolchain                                 | 2            |
| 0003                             | Job transport (PostgreSQL pull queue)                           | 4            |
| 0004                             | Identity: OIDC flow, sessions, IdP, MFA verification            | 3            |
| 0005                             | Tenancy enforcement (RLS + composite keys)                      | 3            |
| 0006                             | Worker trust: enrollment, mTLS termination, scope lease signing | 4            |
| 0007                             | Plugin contract, isolation and signing                          | 6            |
| 0008                             | Discovery engine (custom vs Nmap vs other), after R1            | 5            |
| 0009                             | Intelligence sources and redistribution, after R3               | 7            |
| 0010                             | Risk model v0                                                   | 9            |
| 0011                             | Evidence storage and retention                                  | 5            |

## 17. What this proposal deliberately leaves out

Microservices, a message broker, Redis, Kubernetes/Helm, object storage, OpenTelemetry tracing, Grafana, a Rust scanner, a plugin SDK for third parties, AI and billing. Each needs a measured reason first. None of them is excluded permanently.
