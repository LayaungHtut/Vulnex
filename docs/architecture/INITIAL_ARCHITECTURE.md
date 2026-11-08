# VULNEX Initial Architecture (v0 proposal)

Status: **PROPOSED**, revision v0.2. Founder rulings of 2026-11-06:

- **APPROVED:** D2 (self-hosted → hybrid → SaaS) and D3 (remote non-intrusive M1).
- **CONDITIONALLY APPROVED:** D5/D6, covering the modular FastAPI app, PostgreSQL, outbound-only workers and the PostgreSQL queue. Final approval waits on the conditions (a)–(g), which are mapped in [§18](#18-founder-d6-conditions-where-each-is-addressed), and on Astra 6's review.

Author: Claude · Date: 2026-11-06 · Reviewers: Astra 6 (independent review), GPT-6 (audit, when available) · Decision authority: Founder

Inputs: [PRD v0.1 + Amendment A](../product/PRD.md), [research](../research/), Master Project Instructions §9–16, [threat model](../security/THREAT_MODEL.md).

Labels used below: **PROPOSED** = my recommendation, awaiting review. **UNVERIFIED** = a claim from my own knowledge that I have not checked against a primary source in this session; it is tracked in the [research plan](../research/RESEARCH_PLAN.md).

## 1. Summary of proposals

| #   | Proposal                                                                                                                                                                                                                  | Why                                                                                                                                                                        | Needs                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| P1  | **Modular monolith** control plane (FastAPI) that also contains the intelligence and risk modules; **separately deployed scanner worker**                                                                                 | Founder directive §10; one founder cannot run a service fleet                                                                                                              | [ADR-0001](../decisions/ADR-0001.md) |
| P2  | **Workers pull jobs** over outbound HTTPS with mTLS; the job queue is a **PostgreSQL table** (`FOR UPDATE SKIP LOCKED`); **no message broker** in v0                                                                      | Hybrid mode forbids inbound ports to customer networks; leases and idempotency are easier to reason about in one transactional store                                       | §7.1; ADR-0003                       |
| P3  | **PostgreSQL Row-Level Security** plus application authorization; tenant-composite foreign keys                                                                                                                           | PRD SEC-02 requires RLS; composite keys stop cross-tenant references at the schema level                                                                                   | ADR-0005                             |
| P4  | Humans authenticate with **OIDC** (external or bundled IdP); server-side sessions; services use hashed scoped tokens; workers use mTLS certificates                                                                       | PRD SEC-03/API-04; MFA is delegated to the IdP and verified via claims                                                                                                     | ADR-0004                             |
| P5  | **Own TCP-connect discovery** in the worker for v0; **Nmap integration deferred until its license is reviewed**                                                                                                           | My understanding (UNVERIFIED, R1) is that the Nmap Public Source License restricts commercial products that ship Nmap or that are built specifically to drive and parse it | ADR-0008                             |
| P6  | First-party detection plugins only, as signed bundles. **Probe/evaluate split:** the worker runs declared probes, and plugin code only evaluates the recorded responses, in a resource-limited subprocess with no network | PRD excludes customer plugins; plugin code never touches the network; fixtures become replayable transcripts                                                               | §5.4; ADR-0007                       |
| P7  | Evidence stored in PostgreSQL (redacted, size-capped) in v0; object storage deferred                                                                                                                                      | Bounded, redacted evidence is small; removes a service from the laptop and self-hosted footprint                                                                           | ADR-0011                             |
| P8  | Move the SvelteKit app to `apps/console`; Python code under `engines/`                                                                                                                                                    | Founder's layout §18, minus empty directories                                                                                                                              | ADR-0002                             |
| P9  | Release **self-hosted first**, then hybrid, then SaaS; design multi-tenant from the first migration                                                                                                                       | PRD Amendment A5                                                                                                                                                           | **APPROVED** (D2)                    |

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

### 5.1 Enrollment, identity and revocation

Full design: [ADR-0006 §1–3](../decisions/ADR-0006.md). In short:

- A single-use, hashed enrollment token valid for 24 hours or less, bound to a tenant and scope group, plus a pinned control-plane CA.
- The worker generates its own P-256 key, which never leaves the host, and receives a 7-day client certificate renewed at 50% of its life.
- Caddy verifies the client certificate on a worker-only listener on the internal network.
- Revocation is immediate through the worker record and cancels all of the worker's leases.

### 5.2 Scope enforcement on the worker (independent of the control plane)

Full design: [ADR-0006 §4–6](../decisions/ADR-0006.md). In short:

- Every task carries an Ed25519-signed scope lease. The worker verifies the signature over the exact bytes it received, before parsing them.
- An optional **customer-controlled local scope ceiling** on the worker narrows any lease. It is recommended as mandatory for hybrid.
- One connector module handles all network I/O:
  - strict IPv4/CIDR/hostname parsing;
  - normalization of IPv4-embedding IPv6 forms;
  - a never-allowed list (loopback, link-local and metadata, multicast, the control plane, the worker itself);
  - private ranges only when explicitly in scope;
  - DNS answers validated and **pinned**;
  - no automatic redirects;
  - caps from the lease.
- v0 does not assess IPv6. AAAA answers are reported as coverage gaps.
- Cancellation reaches the worker within about 5 s through the lease-extend response, and a disconnected worker's lease expires within 30 s (§7.1).

### 5.3 Discovery and fingerprinting (v0)

- TCP connect scanning (asyncio) over the profile's port list. It needs no raw sockets and no elevated capabilities, and it is non-intrusive by design. Host liveness is inferred from TCP responses. ICMP and ARP are deferred because they need privileges.
- Service fingerprinting through protocol-specific, read-only handshakes for catalog services only (for example SSH banner, HTTP `Server` header and TLS handshake metadata). Raw responses are size-capped and stored as evidence.
- Nmap (`-sV` and its probe database) is the established alternative with much better coverage. **It is not adopted until R1 confirms the license terms.** If R1 permits customer-installed Nmap invoked as an external tool, the plugin interface below can wrap it without changes.
- UDP, SYN scanning, OS detection and IPv6 are out of v0 (PRD §7).

### 5.4 Plugin framework

Each plugin ships a manifest with the fields the Master Instructions §12 require: `id`, `version`, metadata, supported platforms and services, prerequisites, safety class, permissions (which ports and protocols it may touch), resource limits, evidence JSON Schema, vulnerability references, remediation text, fixtures, minimum worker version.

- **Types:** `discovery`, `fingerprint`, `check`. A check returns exactly one of the five confidence-class outcomes with evidence that validates against its schema. Outcomes that fail validation are recorded as `UNKNOWN` with an error.
- **Safety:** v0 permits only `safe` checks: read-only, no authentication attempts, no payloads that change state. The worker refuses to load anything else.
- **Execution (v0.2, addresses founder condition g): probe/evaluate split.**
  - A check declares a **probe plan as data**: a list of steps using worker primitives. The v0 primitives are `tcp_connect`, `tcp_exchange` (bounded send and read), `tls_handshake` (certificate, protocol version, cipher), `http_get`/`http_head` (no body upload, no redirects unless declared, see ADR-0006 §5.7) and `ssh_banner`.
  - The **worker** executes the plan through the connector. **Plugin code never opens a socket.**
  - The recorded responses (the **transcript**) then go to the plugin's `evaluate(transcript) -> Outcome` function.
  - `evaluate` runs in a fresh subprocess per check run, started in Python isolated mode, with:
    - an empty environment and a temporary empty working directory;
    - the transcript passed on stdin, and output capped at 1 MiB on stdout;
    - rlimits: `RLIMIT_CPU` 5 s, `RLIMIT_AS` 256 MiB, `RLIMIT_NOFILE` 16, `RLIMIT_FSIZE` 0 (no file writes);
    - a wall-clock timeout of 10 s, enforced by killing the whole process group.
  - The output must validate against the plugin's evidence schema, and the outcome must be one of the five classes. Otherwise the result is recorded as `UNKNOWN`, with the error.
  - On Linux hosts that allow unprivileged user and network namespaces, the evaluator also runs with **no network interface**. The worker reports this capability in its heartbeat. Whether Docker's default seccomp profile permits this is UNVERIFIED (R6).
- **What it buys:** safety class is enforced by the primitives rather than by trusting plugin code. Fixtures become recorded transcripts that replay deterministically in CI. Evidence is the transcript itself, redacted.
- **What it costs:** a check that needs a protocol the primitives do not cover needs a new, reviewed primitive in worker code. That is intentional.
- **Limits of the isolation:** it is still defense in depth for **first-party** code, because rlimits and the namespace are not a hardened sandbox. Third-party plugins require a real sandbox (gVisor, nsjail or WASM; R6) and a separate ADR. Windows hosts lack rlimits, so the v0 worker runs on Linux only, including inside Docker Desktop.
- Discovery (TCP connect) and fingerprinting are worker built-ins, not plugins, in v0.
- **Distribution:** plugins ship as a versioned bundle with a manifest of SHA-256 digests, signed with Ed25519. The worker verifies the signature and digests before loading anything and fails closed. Key custody and rotation are in ADR-0007; TUF is evaluated in R7.
- **Fixtures:** every released check has positive, negative and ambiguous fixtures plus a timeout fixture (PRD AC-04). They run as recorded protocol transcripts in CI and against lab containers before release.

## 6. API architecture

- REST/JSON under `/api/v1` (users and service tokens) and `/worker/v1` (mTLS only, separate listener). OpenAPI is generated from FastAPI/Pydantic models and committed, and contract changes are reviewed as diffs.
- Pagination uses opaque cursors with bounded page size. Errors use RFC 9457 problem details with a correlation ID. A record in another tenant returns 404, never 403, so the API does not reveal that it exists.
- `Idempotency-Key` on scan submission, export creation and result submission. Lifecycle updates use optimistic concurrency (`version` column, `If-Match`).
- The console calls the API from SvelteKit server code with the session cookie forwarded. The browser never holds API tokens. SvelteKit's built-in CSRF origin check plus SameSite cookies protect form actions, and the API also requires a CSRF token for cookie-authenticated unsafe methods.

## 7. Database architecture

- PostgreSQL 17 (version pinned in ADR), accessed through SQLAlchemy 2.x Core/ORM with psycopg 3. Schema changes go through Alembic.
- **Roles and tenant isolation:** full design in [ADR-0005](../decisions/ADR-0005.md). The roles are `vulnex_owner` (migrations), `vulnex_app` (runtime, no `BYPASSRLS`), `vulnex_ingest` (intelligence only) and `vulnex_queue` (queue functions). The isolation mechanisms are:
  - composite `(tenant_id, id)` foreign keys;
  - `ENABLE` + `FORCE ROW LEVEL SECURITY` with fail-closed `app.current_tenant()`;
  - tenant context set per transaction with `set_config('app.tenant_id', :id, true)`;
  - CI gates for RLS coverage, cross-tenant access and pool leakage.

  Global intelligence lives in schema `intel` with no tenant data and no RLS.

- **Append-only data:** observations, evidence, score snapshots, state transitions and audit events are never updated in place. Corrections are new rows.
- **Core entities (first cut):** `tenant`, `user`, `membership`, `session`, `service_token`, `audit_event`, `asset`, `asset_identifier`, `scope`, `scope_group`, `worker`, `enrollment_token`, `scan_profile`, `scan_run`, `scan_task`, `observation`, `evidence`, `finding`, `finding_transition`, `exception`, `risk_snapshot`; global: `intel_source`, `intel_raw_record`, `vulnerability`, `vulnerability_alias`, `affected_product`, `severity_metric`, `kev_entry`, `epss_score`, `intel_ingest_run`.
- **Queue:** see §7.1.

### 7.1 Job queue semantics (addresses founder conditions a and b)

**Guarantee:** at-least-once delivery, with idempotent result handling. Duplicates may be _delivered_, but their _effects_ are applied once. "Exactly once" is not claimed.

**Table** `queue.job`. Owned by `vulnex_queue`, so it is reachable only through `SECURITY DEFINER` functions (ADR-0005 §4).

| Column                                                                                            | Purpose                                                                          |
| ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `id`, `tenant_id` (NULL only for global jobs such as ingestion), `queue`, `kind`, `payload jsonb` | What to do, for whom                                                             |
| `scope_group_id`                                                                                  | Which workers may claim it (worker queues only)                                  |
| `state`                                                                                           | `queued` → `leased` → `succeeded` / `failed` / `cancelled` / `dead`              |
| `priority`, `run_after`                                                                           | Ordering and backoff                                                             |
| `attempt`, `max_attempts`                                                                         | Retry accounting                                                                 |
| `lease_id`, `lease_owner`, `lease_expires_at`                                                     | Current lease. A new random `lease_id` is issued on every claim                  |
| `cancel_requested_at`                                                                             | Cooperative cancellation                                                         |
| `idempotency_key`                                                                                 | `UNIQUE (queue, idempotency_key)`, so a re-submitted scan does not enqueue twice |
| `last_error`, `created_at`, `updated_at`                                                          | Diagnostics                                                                      |

Partial index on `(queue, priority DESC, run_after) WHERE state = 'queued'`.

**Claim.** There are two separate functions, so that a caller cannot widen a worker's claim by passing a missing or NULL filter.

- `queue.claim_for_worker(worker_id, n, ttl)` looks up the worker's `tenant_id`, `scope_group_id` and `status` **inside the function**. It returns nothing unless the status is `active`/`stale`, and it only ever touches worker queues.
- `queue.claim_for_runner(queue, owner, n, ttl)` serves runner queues only (schedules, ingestion, exports, retention), may return jobs of any tenant, and can never return worker-queue jobs.

Core of `claim_for_worker`, a single transaction:

```sql
WITH w AS (
  SELECT tenant_id, scope_group_id FROM app.worker
  WHERE id = $worker_id AND status IN ('active', 'stale')),
next AS (
  SELECT j.id FROM queue.job j, w
  WHERE j.queue = 'scan' AND j.state = 'queued' AND j.run_after <= now()
    AND j.tenant_id = w.tenant_id AND j.scope_group_id = w.scope_group_id
  ORDER BY j.priority DESC, j.run_after, j.id
  LIMIT $n
  FOR UPDATE OF j SKIP LOCKED)
UPDATE queue.job j
   SET state = 'leased', attempt = j.attempt + 1, lease_id = gen_random_uuid(),
       lease_owner = $worker_id::text, lease_expires_at = now() + $ttl, updated_at = now()
  FROM next WHERE j.id = next.id
RETURNING j.id, j.tenant_id, j.kind, j.payload, j.attempt, j.lease_id, j.lease_expires_at;
```

- `SKIP LOCKED` lets concurrent claimers each take distinct rows without blocking. The row lock and the state change commit together, so two claimers can never both hold a lease on the same job.
- All times come from the database clock (`now()`), never from worker clocks.
- The `worker_id` comes only from the authenticated certificate (ADR-0006 §2), never from the request body.
- **Long-poll:** if nothing is available, the API holds the worker's request up to 25 s, re-trying the claim every 1 s, then returns empty. This is proposed. Contention and latency must be measured against PRD §20 (dispatch p95 ≤30 s).

**Lease extension and cancellation:**

- `queue.extend(job_id, lease_id, ttl)` succeeds only if the `lease_id` is still current and the state is `leased`. The worker calls it every 5 s with TTL 30 s.
- The response includes `cancel_requested`. If a cancel was requested, the worker stops new probes at once, submits any partial results, and calls `complete(..., outcome = cancelled)`.
- `queue.request_cancel` moves a `queued` job directly to `cancelled`. A `leased` job gets `cancel_requested_at` set and stays leased until the worker acknowledges or the lease expires. An expired lease with a cancel request becomes `cancelled`, not re-queued.

**Results and completion:**

- Every result submission carries `(job_id, lease_id, attempt, seq)`. It is accepted only if the `lease_id` is current. The pair `(job_id, attempt, seq)` is unique, so a duplicate submission returns the original response and has no new effect. A submission with a stale `lease_id` gets 409, and its payload is quarantined for audit, never applied.
- `queue.complete(job_id, lease_id, outcome)` runs in the **same transaction** as the final results insert. A job can therefore never be marked `succeeded` without its results, or the reverse.

**Retries:**

- On failure, or lease expiry without a cancel request: if `attempt < max_attempts`, the job returns to `queued` with `run_after = now() + backoff`. Backoff is exponential with jitter: base 30 s, doubling, capped at 15 min.
- When attempts run out, the job becomes `dead`. It stays visible in the UI and API and raises an alert.
- Scan tasks default to `max_attempts = 3`. Observations are keyed by attempt. Partial observations from failed attempts are kept as evidence, but only a successful attempt counts toward coverage and verification (PRD §13).

**Recovery:**

- `queue.sweep()` runs in the background runner every 10 s. It moves `leased` jobs whose `lease_expires_at < now()` to their retry, cancelled or dead state, using `SKIP LOCKED`, so it is safe to run from multiple runners at once.
- No queue state lives in process memory. A control-plane restart loses nothing.
- A worker restart loses in-flight work. Its leases expire and the jobs retry.
- A scan run's state is derived from its tasks: `completed` when all are `succeeded`, `partially_completed` if any are `failed`/`dead`, `cancelled` when cancel was requested (PRD §12).

**Fairness:** `queue.claim` can cap concurrently leased jobs per tenant. v0 self-hosted is effectively single-tenant, so the cap is designed now but tuned with SaaS (D2).

**Tests:**

- Two concurrent claimers never receive the same job.
- A killed worker's job is retried after lease expiry.
- A duplicate result submission has no effect.
- A late result after re-lease gets 409 and is quarantined.
- Cancellation of a queued job, and of a leased job with the worker acknowledging and with the worker gone.
- Retry count and backoff, and the transition to `dead`.
- Complete-without-results is impossible.
- Sweeper concurrency.
- A load test: claim latency with 10,000 queued jobs and 4 claimers, on the founder's laptop.

## 8. Multi-tenancy and authorization

- A request has exactly one tenant context, chosen explicitly. Users with several memberships switch context. There is no cross-tenant aggregation in v0 (PRD §3).
- Authorization is enforced in API dependencies with deny-by-default role → permission maps (PRD §10), and RLS backs it up. Background jobs carry `tenant_id` and set it the same way.
- Required tests: for every tenant-bearing endpoint and job type, a second tenant's credentials must get 404 or an empty result, and must be unable to write. A test enumerates routes so that a new endpoint without a tenant test fails CI. The full test list is in [ADR-0005 §6](../decisions/ADR-0005.md).

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

| ADR                                                  | Decision                                             | Blocks phase |
| ---------------------------------------------------- | ---------------------------------------------------- | ------------ |
| [0001](../decisions/ADR-0001.md)                     | Modular monolith + separate workers                  | 2            |
| [0002](../decisions/ADR-0002.md) (drafted, PROPOSED) | Repository layout and toolchain                      | 2            |
| 0003                                                 | Job transport (PostgreSQL pull queue)                | 4            |
| 0004                                                 | Identity: OIDC flow, sessions, IdP, MFA verification | 3            |
| [0005](../decisions/ADR-0005.md) (drafted, PROPOSED) | Tenancy enforcement (RLS + composite keys)           | 3            |
| [0006](../decisions/ADR-0006.md) (drafted, PROPOSED) | Worker trust, signed scope, destination validation   | 4            |
| 0007                                                 | Plugin contract, isolation and signing               | 6            |
| 0008                                                 | Discovery engine (custom vs Nmap vs other), after R1 | 5            |
| 0009                                                 | Intelligence sources and redistribution, after R3    | 7            |
| 0010                                                 | Risk model v0                                        | 9            |
| 0011                                                 | Evidence storage and retention                       | 5            |

## 17. What this proposal deliberately leaves out

Microservices, a message broker, Redis, Kubernetes/Helm, object storage, OpenTelemetry tracing, Grafana, a Rust scanner, a plugin SDK for third parties, AI and billing. Each needs a measured reason first. None of them is excluded permanently.

## 18. Founder D6 conditions: where each is addressed

| #   | Condition (founder, 2026-11-06)                                  | Addressed in                                                                                                                                                            | Status                             |
| --- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| a   | Transactional job claiming and locking                           | §7.1 (claim functions, `FOR UPDATE SKIP LOCKED`, worker scope derived inside the function); ADR-0005 §4                                                                 | PROPOSED                           |
| b   | Job leases, retries, idempotency, cancellation and recovery      | §7.1 (lease IDs, 5 s extend / 30 s TTL, `(job_id, attempt, seq)` idempotency, exponential backoff and `dead`, cooperative cancel, sweeper); ADR-0006 §6 timing          | PROPOSED                           |
| c   | Database-enforced tenant isolation                               | ADR-0005 §1–2 (composite foreign keys, `FORCE` RLS, non-owner runtime role, separate schemas)                                                                           | PROPOSED                           |
| d   | RLS context handling and cross-tenant testing                    | ADR-0005 §3 (`set_config(..., true)`, fail-closed `current_tenant()`, definer functions for pre-tenant lookups) and §6 (eight CI test gates)                            | PROPOSED                           |
| e   | Scanner authentication, revocation and signed scope verification | ADR-0006 §1–4 (pinned enrollment, host-generated key, 7-day certificate, immediate revocation, Ed25519 scope lease over exact bytes, customer-controlled local ceiling) | PROPOSED                           |
| f   | DNS resolution, IPv4/IPv6, redirects and address validation      | ADR-0006 §5 (strict parsing, IPv4-embedding IPv6 normalization, never-allowed list, DNS pinning, no automatic redirects, capped hops)                                   | PROPOSED                           |
| g   | Secure plugin execution and resource limits                      | §5.4 (probe/evaluate split; evaluator subprocess with rlimits, timeout, no network where supported); formal ADR-0007 still to be written                                | PROPOSED; ADR-0007 not yet drafted |

Still not drafted, and needing founder permission: ADR-0003 (queue, which would formalize §7.1) and ADR-0007 (plugin contract and signing, which would formalize §5.4). No new infrastructure was introduced to meet these conditions. Caddy and PostgreSQL were already in the v0.1 proposal.
