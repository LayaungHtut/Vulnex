# VULNEX Product Requirements Document

Version: 0.1 — first formal draft  
Date: 2026-11-06  
Owner: Chief Architect  
Decision authority: Founder  
Review verdict: **APPROVED WITH CONDITIONS** for planning and independent challenge; not implementation or launch approval.

> **Authorship:** Claude Opus 5.5 is the initial author of v0.1, as recorded by the founder on 2026-11-06. Independent review and verification are pending.
>
> **Status note (2026-11-06, Claude):** The verdict above is the authoring agent's own. The founder has not approved the PRD as a whole, so the repository treats it as **PROPOSED**. The founder approved decisions D2 and D3 (Amendment A4, A5) on 2026-11-06. Amendment A at the end of this file proposes changes that align it with the founder's Master Project Instructions. The original v0.1 text is unchanged. "Argon" in this document refers to the independent reviewer now named **Astra 6**.

## Executive summary

VULNEX Exposure Intelligence Platform will help customers identify assets, detect supported vulnerabilities, understand the evidence and business relevance, and verify remediation. Initial products are VULNEX SCAN and VULNEX INTELLIGENCE. Long-term competition with Tenable is an ambition, not a present capability or a validated competitive claim.

The founder has committed to individuals, SMBs, mid-market, MSPs, MSSPs, enterprises and regulated organizations, and to SaaS, self-hosted and hybrid deployment. These commitments do not imply simultaneous enterprise feature completeness. This PRD proposes a bounded initial detection catalog and a small SMB/mid-market pilot, including one service-provider design partner. All three deployment modes must pass the MVP release gates on a declared reference topology. Segment-specific advanced capabilities follow later.

No customer interviews, market sizing, willingness-to-pay studies, competitive benchmarking or implementation audits were performed for this document. Market entry, numeric budgets and scoring choices below are proposals requiring validation. Reviewed repository sources: `AGENTS.md`, `docs/WORKFLOW.md`, `README.md` and `GEMINI.md`. The previously supplied shared conversation was inaccessible and is not evidence.

## 1. Product vision and positioning

Make exposure management understandable, verifiable and operable across customer-controlled and hosted environments. Customers should be able to answer: what do we own, what was actually checked, what evidence supports a finding, what should we fix first, and did the fix work?

Proposed positioning: evidence-backed vulnerability management with deployment choice and explainable prioritization. Differentiation is a hypothesis until design partners validate it. Do not market exhaustive coverage, zero false positives, breach prediction, compliance certification or equivalence to established vendors.

VULNEX SCAN owns authorized discovery, scan execution, evidence collection and remediation verification. VULNEX INTELLIGENCE owns normalized advisory context, provenance, affected-product information and prioritization inputs. Together they support a common asset and finding workflow.

## 2. Target customer personas

All needs in this table are hypotheses, not research findings.

| Segment / persona                               | Proposed job to be done                                  | Initial treatment                                               |
| ----------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------- |
| Individual practitioner                         | Assess an owned lab or small environment affordably      | Basic single-tenant workflow; validate packaging later          |
| SMB IT administrator                            | Find actionable issues without dedicated security staff  | Primary proposed pilot persona; guided scope and remediation    |
| Mid-market security analyst                     | Coordinate recurring scans and remediation owners        | Primary proposed pilot persona; repeatability and evidence      |
| MSP operator                                    | Manage separate customer environments safely             | One design partner; separate tenant contexts, no pooled data    |
| MSSP analyst                                    | Deliver consistent customer assessment services          | Validate workflow; advanced delegation and SLA automation later |
| Enterprise security lead                        | Integrate inventory, identity, operations and governance | Discovery partner; enterprise integrations and scale later      |
| Regulated organization security/compliance lead | Control data location and demonstrate decisions          | Deployment and audit foundations now; formal assurance later    |
| Infrastructure/application owner                | Understand and verify assigned remediation               | MVP contributor role and filtered finding views                 |
| Executive/risk owner                            | Understand coverage, unresolved exposure and exceptions  | MVP summary reports with limitations                            |

Buyer, operator, remediation owner and risk approver may be different people. Validate these distinctions before pricing or workflow automation.

## 3. Customer problems and workflows

Proposed problems: incomplete inventories, noisy detections, unclear evidence, unprioritized queues, stale results, disconnected remediation tracking and constraints on where scanning or evidence may run.

Primary workflow:

1. Create an organization/tenant, establish identity and declare authorized scope.
2. Register a worker and verify its network reach and health.
3. Import targets, label business criticality and review scope exclusions.
4. Preview a safe scan profile, limits and supported coverage; launch or schedule it.
5. Observe progress and coverage gaps; distinguish findings from failed checks.
6. Triage evidence, assign owners and approve time-limited exceptions when appropriate.
7. Export a report or integrate through the API.
8. Remediate externally, run a comparable verification scan, and close or reopen findings.

Additional workflows: update intelligence without rewriting historical evidence; investigate a stale/disconnected worker; recover interrupted scans; rotate credentials; export and delete tenant data; restore a deployment from backup. MSP users explicitly switch customer context before operating; cross-customer aggregation is deferred.

## 4. Initial market entry strategy and validation

Proposed entry: 3–5 design partners with bounded networks, recurring assessment needs and an accountable remediation owner. Prefer SMB/mid-market environments; include one MSP/MSSP and representation of all three deployment modes. This is a recruitment target, not an existing customer pipeline.

Pilot progression: problem interviews → supported-coverage agreement → supervised authorized scan → independent result review → remediation verification → repeat usage and commercial feedback. Do not launch a broad free public scanning service before abuse controls and support capacity are proven.

| Assumption                                               | Validation method                                         | Decision affected            |
| -------------------------------------------------------- | --------------------------------------------------------- | ---------------------------- |
| A1: Evidence quality matters more initially than breadth | Interviews plus blinded review of pilot findings          | Detection investment         |
| A2: SMB/mid-market buyers will adopt a bounded catalog   | Written pilot coverage agreement and repeat usage         | Beachhead and MVP scope      |
| A3: Deployment choice influences purchasing              | Interview buyers and observe installation completion      | Packaging and support costs  |
| A4: Customers can operate worker infrastructure          | Supervised setup followed by independent repeat operation | Managed worker offering      |
| A5: Explainable prioritization improves decisions        | Compare triage time and decisions with/without scoring    | Risk model                   |
| A6: Revenue can cover infrastructure and support         | Measure pilot costs and willingness to pay                | Pricing and launch economics |

Founder approval is required for beachhead, commercial launch, pricing, support commitments and any reduction of deployment commitments.

## 5. Product boundaries and technical analysis

The initial platform is an assessment and decision-support product. It does not guarantee discovery of every asset or vulnerability and does not perform autonomous remediation. Findings must describe the method, evidence, confidence and coverage limitations.

Proposed architecture: modular monolith for the control plane; independently deployable scan workers; a distinct intelligence ingestion and publication boundary. Logical separation does not require three microservice fleets. Customer evidence remains tenant-scoped; shared public intelligence must not contain customer data.

The control plane owns identities, authorization, inventory, policies, lifecycle and reporting. Workers execute bounded jobs and return evidence. Intelligence ingestion normalizes and versions source records. Public intelligence must never become executable detection code without a reviewed plugin release.

Candidates remain unevaluated: SvelteKit/Svelte with TypeScript, Python/FastAPI/Pydantic, PostgreSQL, SQLAlchemy or SQLModel, Alembic, NATS or RabbitMQ, Redis when justified, S3-compatible storage, Docker and OpenTelemetry/Prometheus/Grafana. This PRD selects no framework version, ORM, broker or hosting provider. ADRs must resolve these choices, service boundaries, tenancy enforcement, job delivery, secrets and update trust before dependent implementation. Kubernetes/Helm require operational justification.

## 6. Initial MVP scope

MVP means a gated pilot release, not enterprise general availability. MUST requirements below are release blockers unless formally amended by the founder with an impact assessment; security gates cannot be represented as passed through waiver.

Included:

- Tenant organizations, verified invitations, fixed roles, OIDC and MFA enforcement.
- Explicit IPv4/CIDR and DNS target import, exclusion lists, tags, ownership and business criticality.
- Bounded TCP discovery and remote checks against a published, small supported catalog.
- Manual and recurring scans, worker registration, cancellation, limits and progress.
- Evidence-backed findings, advisory enrichment, deterministic prioritization and triage.
- Verification scans, exception expiry, audit history and reporting.
- Versioned API, scoped service credentials and tenant-safe asynchronous exports.
- SaaS, self-hosted and hybrid on documented reference configurations.
- Signed, versioned detection and intelligence updates; recovery, retention and deletion procedures.

Catalog release gate: founder approves an exact manifest of target products, versions, check IDs, safe execution methods and known blind spots. Every released check requires positive, negative and ambiguous fixtures. A check-count target alone is not sufficient. Until the manifest exists, detection scope is unresolved and implementation estimates are provisional.

## 7. Features explicitly excluded from MVP and long-term ambitions

Excluded: exploit execution, brute force, denial-of-service testing, destructive probes, autonomous remediation, AI-required detection or scoring, endpoint agents, authenticated host/package scanning, full web DAST, source/dependency scanning, container image scanning, cloud account posture connectors, continuous internet-wide discovery, OT/ICS support, IPv6 scanning, custom customer-executable plugins, arbitrary custom roles, consolidated cross-tenant MSP dashboards, ticketing integrations, billing automation, active-active multi-region deployment, formal compliance certification and fully disconnected air-gap operation.

Customers must see exclusions before using the product. A banner/version observation alone cannot be presented as verified exploitability; uncertain matches remain candidates.

Long-term: SURFACE for external exposure discovery, CLOUD for cloud exposure, RESPONSE for controlled remediation workflows and COMMAND for portfolio governance. Authenticated assessment, enterprise policy, provider hierarchies, regional hosting, air-gap operation and broader coverage require separate PRDs and ADRs. Names do not constitute approved functional scope or delivery dates.

## 8. Functional requirements

| ID    | MVP requirement                                                                                             | Verification                                     |
| ----- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| FR-01 | All customer records, jobs, evidence and exports have an enforced tenant boundary                           | Cross-tenant negative tests at every access path |
| FR-02 | Preview target expansion and reject invalid, excluded or excessive scope before scheduling                  | Boundary, DNS-change and quota fixtures          |
| FR-03 | Support import validation, tags, owners, criticality and explicit asset merge review                        | Import and identity-conflict tests               |
| FR-04 | Version scan profiles; record ports, timeouts, concurrency, exclusions and plugin manifest per run          | Historical run reproducibility                   |
| FR-05 | Schedule in a declared timezone with explicit daylight-saving behavior; prevent accidental overlapping runs | Schedule and duplicate-delivery tests            |
| FR-06 | Show worker heartbeat, version, capacity, scope binding and failure reason                                  | Disconnect and stale-worker scenarios            |
| FR-07 | Enforce rate, concurrency, duration and target caps at dispatch and worker execution                        | Worker safety integration tests                  |
| FR-08 | Findings expose evidence, observation time, method, confidence, plugin version and remediation references   | Released check contract validation               |
| FR-09 | Support assignment, comments, triage, exceptions and verification without erasing history                   | Lifecycle transition tests                       |
| FR-10 | Enrich findings from versioned intelligence with provenance and freshness                                   | Replay and source-outage tests                   |
| FR-11 | Filter inventory/findings by scope, owner, status, severity, priority and freshness                         | API/UI consistency tests                         |
| FR-12 | Export tenant-scoped reports and audit records under retention and permission controls                      | Export authorization and redaction tests         |
| FR-13 | Retire assets and delete tenant data through auditable workflows                                            | Retention/deletion integration tests             |
| FR-14 | Publish supported detection coverage and failed/skipped checks per scan                                     | Partial-scan report tests                        |

## 9. Non-functional requirements

NFR-01: Core operation must work without AI services. NFR-02: UI, API, workers and storage must apply consistent authorization. NFR-03: All records use UTC timestamps, with localized display and explicit timezone scheduling. NFR-04: Core workflows must support keyboard navigation, visible focus, labeled forms and accessible status/error text; evaluate against WCAG 2.2 AA as a proposed accessibility target, not a certification claim. NFR-05: Structured logs, metrics and traces must explain failures without exposing secrets. NFR-06: Version compatibility and upgrade support must be documented. NFR-07: Configuration and secrets must be separable from images and portable between supported environments. NFR-08: No success status may hide incomplete assessment coverage.

## 10. User roles and permissions

Users may belong to multiple tenants, but every operation has one explicit tenant context. Permissions are enforced server-side, deny by default. Service credentials receive a subset of named permissions and tenant scope; they are not human administrator substitutes.

| Capability                                        | Owner                 | Administrator           | Analyst      | Remediation contributor             | Viewer    |
| ------------------------------------------------- | --------------------- | ----------------------- | ------------ | ----------------------------------- | --------- |
| Transfer ownership / request tenant deletion      | Yes, reauthentication | No                      | No           | No                                  | No        |
| Manage identity, membership and roles             | Yes                   | Yes, cannot alter owner | No           | No                                  | No        |
| Manage workers, scopes, schedules and credentials | Yes                   | Yes                     | No           | No                                  | No        |
| Run approved scan profiles                        | Yes                   | Yes                     | Yes          | No                                  | No        |
| View findings and redacted evidence               | Yes                   | Yes                     | Yes          | Assigned scope only                 | Yes       |
| Assign and triage findings                        | Yes                   | Yes                     | Yes          | Comment / request verification only | No        |
| Approve suppression or risk acceptance            | Yes                   | Yes                     | Request only | No                                  | No        |
| View/export standard reports                      | Yes                   | Yes                     | Yes          | Assigned scope only                 | View only |
| Read/export audit history                         | Yes                   | Yes                     | No           | No                                  | No        |

No role can retrieve stored plaintext scan secrets. Provider/platform operators do not receive implicit customer-content access. Exceptional support access must be time-limited, explicitly authorized, audited and revoked automatically. Self-hosted machine/database administrators remain within the customer's infrastructure trust boundary; application RBAC cannot constrain a root operator.

## 11. Asset lifecycle

States: imported/discovered → active → stale → retired. Reactivation is explicit or triggered by a new valid observation with an audit event. Deletion is a separate retention-governed operation.

- Use an immutable tenant-scoped asset ID; IP and hostname are observations, not universal identities.
- Store source, first/last seen, network/worker scope and identifier history. Overlapping private IP ranges in different scopes must remain distinct.
- Default proposed stale threshold: 30 days without successful observation; configurable. Stale means unobserved, not safe or nonexistent.
- Ambiguous identity changes require review. Merge/split records retain lineage and cannot silently transfer verified findings between machines.
- Retirement stops future targeting and preserves historical findings until retention expires. Asset retirement never means vulnerability remediation.
- Imported inventory, discovered inventory and successfully assessed inventory are separate counts.

## 12. Scan lifecycle

States: draft → validated → queued → running → completed / partially completed / failed / cancelled. Cancellation uses an intermediate cancelling state; worker loss uses retry/reconciliation before a terminal result. Terminal runs are immutable; retry creates an attempt under the same run or a linked new run according to a documented contract.

Completed requires every planned eligible check to have a recorded outcome. Unsupported/skipped checks remain visible; partial means intended checks could not finish. A worker heartbeat is not proof of scan progress. Each task has a lease, attempt ID and idempotent result key; duplicate delivery must not duplicate findings. Late results from expired or cancelled leases are quarantined or rejected.

Workers revalidate authorized resolved destinations immediately before connections and enforce exclusions after DNS resolution and redirects. Private addresses are allowed only within explicitly approved worker scope. Block metadata/control-plane infrastructure and other sensitive destinations unless the deployment policy explicitly permits a legitimate assessment target. Target caps apply after expansion and resolution.

Cancellation stops new probes promptly; bounded in-flight probes expire. Preserve partial evidence and record exactly what ran. Scope changes do not silently alter an in-progress scan snapshot. Offline workers cannot continue indefinitely on expired authorization.

## 13. Finding lifecycle

States: open → triaged → in remediation → pending verification → resolved. Open findings may become risk accepted, suppressed or false positive with reason, approver and review/expiry date. Expiry returns unresolved findings to triage. A resolved finding becomes reopened when detected again.

Detection confidence (confirmed by supported method / probable / candidate) is separate from workflow status, severity and priority. Confirmed means the check's stated condition was evidenced, not necessarily that exploitation was attempted or proven.

Deduplicate by tenant, stable asset ID, detection identity and affected service/component instance. Preserve every observation, intelligence revision and state transition. Multiple CVEs may map to one condition without inflating finding counts.

Only a successful comparable assessment of the same asset/component with sufficient check coverage can automatically resolve a finding. Timeouts, disappearance, failed authentication, excluded targets, removed plugins or stale intelligence cannot resolve it. Manual closure must be labeled unverified and reported separately from verified remediation. Plugin changes require compatibility rules before observations are compared.

## 14. Vulnerability intelligence requirements

INT-01: Store source identity, upstream identifier, canonical references, publication/modification/ingestion times, raw-record digest, parser version and provenance. Preserve corrections, withdrawals and aliases.

INT-02: Candidate sources include vendor advisories, CVE records, NVD enrichment, CISA KEV and EPSS. Availability, licensing, redistribution, rate limits and offline rights require research before selection. No source entitlement or accuracy is assumed here.

INT-03: Normalize affected versions, identifiers, severity vectors with their scheme versions, remediation references and exploitation context. Distinguish unknown, absent, conflicting and explicitly withdrawn data. Never invent version boundaries or silently choose the highest conflicting value.

INT-04: Signed ingestion snapshots must be reproducible and schema validated. Untrusted source text cannot run code, inject UI content or alter detection plugins. Failed ingestion preserves the last valid snapshot and raises freshness alerts.

INT-05: Proposed connected deployment targets: poll selected feeds at least every 6 hours within provider limits; publish validated records within 24 hours of successful upstream availability. Display last successful ingestion and source timestamps. Alert after 24 hours without expected successful refresh. Offline/manual updates show their actual age and do not inherit connected freshness claims.

INT-06: Advisory/product matches without sufficient observed version or check evidence are candidates. Backports and vendor-specific versioning require explicit handling. Risk recalculation after enrichment records the scoring version and inputs; it never rewrites original scan evidence.

## 15. Risk prioritization requirements

Keep source severity, detection confidence and VULNEX priority distinct. Explain every score with input values, sources, observation times, contributions and missing-data warnings. Scores are triage aids, not probabilities of compromise.

Proposed MVP model for validation: priority = clamp(0, 100, 5S + E + X + B), where S is selected published severity on a 0–10 scale, E is 20 for supported evidence of known exploitation and otherwise 0, X is 15 for verified internet reachability and otherwise 0, and B is 15/10/5/0 for critical/high/standard/low business criticality. Record the source-selection policy and its version. EPSS may be displayed independently until a calibrated mapping is approved.

Missing S uses a visibly provisional value of 5; unknown X and B use provisional contributions of 15 and 10 to avoid silently rewarding missing context. Absent exploitation evidence means unknown, not proof of no exploitation. Defaults, confidence and missing inputs must be conspicuous and filterable. These conservative defaults are hypotheses requiring pilot evaluation.

Proposed priority bands: urgent ≥80, high ≥60, medium ≥35, low <35. A known-exploited match with adequate evidence receives at least high priority. Candidate matches appear in a separate review queue regardless of numeric score. Overrides require reason, actor and expiry and retain the computed score. Risk acceptance does not lower the intrinsic score. Do not sum finding scores into a misleading organization breach probability. Model changes require versioning, regression fixtures and approval through an ADR.

## 16. Reporting requirements

MVP reports: executive summary, asset inventory/coverage, technical findings, remediation progress and audit export. Support human-readable downloadable HTML and machine-readable CSV/JSON; PDF and branded provider reports are deferred.

Every report includes tenant, filters, reporting period, generation time, scan IDs, assessment coverage, failures/skips, intelligence age, scoring version and caveats. Separate confirmed/probable/candidate findings; separate verified resolution, manual closure, suppression and risk acceptance. Show stale assets and overdue exceptions. Snapshot reports must remain reproducible even after later intelligence changes.

Exports inherit current authorization, redact secrets, escape active content and neutralize spreadsheet formula injection. Download links expire within a proposed 15 minutes, remain tenant-authorized, and cannot be shared as unrestricted public URLs. Export generation and downloads are audited. Technical reports provide sufficient redacted evidence and remediation references to reproduce triage decisions.

## 17. Deployment requirements

| Mode        | MVP topology                                                                              | Customer responsibility                                | Release proof                                                                |
| ----------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| SaaS        | VULNEX-hosted control/intelligence services and isolated managed scan workers             | Scope authorization, identity and target policy        | Two adversarial tenants plus operational recovery exercise                   |
| Self-hosted | Customer-hosted control plane, storage and workers; optional outbound signed updates      | Infrastructure, backups, identity and network security | Clean install, upgrade, backup/restore and external-service outage test      |
| Hybrid      | SaaS control plane with customer-network workers using outbound authenticated connections | Worker host and authorized network scope               | No required inbound customer port; disconnect/reconnect and revocation tests |

Core workflows and data semantics must match across modes; document every operational difference. Self-hosted runtime must not require a proprietary cloud service, online license check or AI. Connected updates are supported; certified air-gap packaging is later. Hybrid still transmits approved evidence/metadata to SaaS and must not be marketed as entirely local data storage.

Reference MVP packaging: OCI containers with one documented Linux architecture and installation configuration, subject to ADR. Provide resource sizing, ports, egress destinations, secret injection, health checks, backup instructions and compatibility matrix. Support current and previous minor worker protocol versions only after compatibility tests. Reject unsafe or unsupported versions with actionable errors.

Schema migrations require preflight checks and backups. Rehearse restoration to the previous release; do not assume database downgrades are safe. Regional residency, sovereign hosting and large HA clusters require separate approval and verified operational capability.

## 18. API requirements

API-01: Versioned documented API and machine-readable OpenAPI contract for assets, scan profiles, runs, findings, intelligence views, reports and audit access. UI operations use equivalent authorization semantics.

API-02: Stable opaque identifiers, bounded pagination, explicit timestamps, filter validation, consistent error codes and correlation IDs. No sensitive stack traces. Cross-tenant identifiers must not leak record existence.

API-03: Idempotency keys for scan submission and asynchronous export creation; conditional updates/version checks for conflicting lifecycle changes. Publish retry behavior, quota headers and status polling semantics. Webhooks are deferred.

API-04: Scoped, expiring, revocable service credentials; hash bearer credentials at rest and show secrets only at creation. Separate worker identity from user/API identity. Rate limits apply per principal and tenant with global safeguards.

API-05: Contract tests and documented deprecation policy before integrations depend on a release. Proposed compatibility window: current API major version throughout the pilot; breaking changes require migration notice and founder approval.

## 19. Security implications and requirements

SEC-01: Threat model must cover malicious tenants, compromised workers, hostile targets, malicious feed/plugin content, insider access, supply-chain compromise and public-scan abuse. Independent review precedes pilot access.

SEC-02: Tenant isolation at authorization, database, jobs, caches, object storage, exports and observability. PostgreSQL RLS is required unless an approved ADR replaces it with demonstrated equivalent defense in depth. Runtime roles must not own tenant tables or bypass RLS; migration roles are separate. Test pooled connections and background tasks for tenant-context leakage.

SEC-03: OIDC integration with verified issuer/audience and secure session handling. Require MFA for privileged users, through verified identity-provider policy or a supported local mechanism. Protect recovery and break-glass access; MFA cannot be silently bypassed through fallback login. Define revocation latency and session lifetime in the identity ADR.

SEC-04: Encrypt network transport and persistent sensitive data; use mTLS for worker/control communication with enrollment, rotation and revocation. Secrets stay out of logs, reports and images. Customer infrastructure requirements must state who controls storage encryption and keys.

SEC-05: Execute signed versioned plugins in a constrained worker environment with bounded CPU, memory, time and network scope. Workers cannot read other tenants' jobs or arbitrary control-plane secrets. One active tenant security context per worker process/sandbox; shared managed hosts require verified isolation.

SEC-06: Update manifests include signatures, digests, compatibility and revocation metadata. Fail closed on invalid signatures. Controlled rollback must not bypass revocation. Document signing-key rotation and compromise recovery.

SEC-07: Audit membership, policy, scope, scan, exception, export, update, administrative access and deletion events. Append-only application semantics and restricted audit storage are required; do not claim cryptographic tamper-proofing without its implementation and verification.

SEC-08: Hosted scanning requires ownership/authorization attestation plus scope verification appropriate to the target, quotas, suspension controls and abuse review. Unauthorized destination changes are blocked at execution. Offer emergency scan stop and credential revocation.

SEC-09: Collect minimal redacted evidence. Proposed defaults: raw redacted evidence 30 days, finding/scan history 365 days, audit history 365 days, downloadable export artifacts 7 days. These require founder/legal review and tenant-visible policy. Deletion completes in active storage within 7 days; backups age out within a proposed 35 days. Restores must reapply deletion tombstones before service resumes. Legal holds and jurisdiction-specific requirements need a separate approved policy.

SEC-10: Security review must cover authorization bypass, injection, SSRF, session/CSRF handling, stored-content rendering, archive/import abuse and resource exhaustion. Release requires no unresolved critical/high product-security defects under the approved severity rubric; lower defects require documented owner and due date.

## 20. Performance, reliability and scalability implications

All numbers below are proposed acceptance budgets, not measured capabilities or contractual SLAs. Benchmark fixtures, hardware, network conditions and results must accompany approval.

Reference test envelope: 10 tenants, 1,000 active assets per tenant, 100,000 current findings total, 1 million historical observations and 50 concurrent interactive users. Initial measurement topology: control/API 4 vCPU/8 GiB; database 4 vCPU/16 GiB with SSD; two workers each 4 vCPU/8 GiB; S3-compatible storage. Tune or revise through documented evidence, not silent target changes.

| Measure                             | Proposed MVP gate                                                                                                                                   |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Interactive list/detail API latency | p95 ≤500 ms, p99 ≤1.5 s over 30 minutes at 20 requests/s within envelope; exports and scans excluded                                                |
| Successful API requests             | ≥99.5% during benchmark, excluding deliberate invalid/unauthorized requests; report all error classes                                               |
| Job dispatch                        | p95 ≤30 s when a healthy worker has available capacity                                                                                              |
| Cancellation                        | No new probes within 10 s of worker receiving cancellation; in-flight probes bounded to 30 s; disconnected lease expires within 60 s                |
| Scanner regression workload         | 256 controlled reachable hosts ×20 TCP ports, concurrency ≤32, one-second probe timeout: discovery ≤10 minutes; plugin workload measured separately |
| Report generation                   | 10,000 finding rows within 60 s, asynchronously, without violating interactive latency budget                                                       |
| Tenant fairness                     | Saturating one tenant increases another tenant's p95 by <25% under declared shared capacity                                                         |
| SaaS availability objective         | ≥99.5% monthly for authenticated core API operations, measured by external probes; publish maintenance and incidents separately                     |
| SaaS recovery                       | RPO ≤24 h and RTO ≤8 h, demonstrated in a restore exercise                                                                                          |
| Worker failure                      | No lost acknowledged result or duplicate canonical finding in retry/crash tests                                                                     |

Remote target latency and throttling dominate scan time; never extrapolate the lab throughput into an unconditional customer promise. Display estimates with profile and network assumptions.

Use bounded queues, tenant quotas, backpressure and per-tenant worker scheduling. Scale workers separately from the control plane. Profile database indexes, history growth, retention processing and report loads before introducing services. Track compute, storage, egress, feed costs and support effort per tenant/asset/scan; pricing and gross-margin gates await measured pilot economics. Self-hosted reliability depends on customer topology and is not covered by a SaaS uptime claim.

## 21. Acceptance criteria and release evidence

| Gate                    | Pass condition                                                                                                                                                      | Evidence / accountable role                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| AC-01 Scope             | Founder approves pilot segment, catalog, all-mode release definition and remaining product policies                                                                 | Written decision record / Founder                                                      |
| AC-02 Architecture      | Threat model and required ADRs reviewed; Argon challenges resolved or explicitly tracked                                                                            | Approved spec / Chief Architect                                                        |
| AC-03 Isolation         | Every tenant-bearing API/job/storage/export path has negative tests; adversarial two-tenant exercise shows no leakage                                               | Test report and independent review / implementation + verification                     |
| AC-04 Detection         | Every released plugin passes positive, negative, ambiguous and timeout fixtures; no unsupported confirmed matches in fixtures                                       | Versioned corpus and manifest / implementation + verification                          |
| AC-05 Accuracy          | Pilot findings receive independent labeled review; report sample size, uncertainty and false-positive rate by check; proposed ≥95% precision for confirmed findings | Review dataset / independent verifier; insufficient sample means unvalidated, not pass |
| AC-06 Lifecycle         | Failed/partial scans cannot resolve findings; repeated delivery deduplicates; recurrence reopens; exceptions expire; identity conflicts preserve history            | Integration scenarios / implementation + verification                                  |
| AC-07 Safety            | Scope escape, DNS changes, cancellation, expired leases and quota tests pass                                                                                        | Network-observed worker test / independent verifier                                    |
| AC-08 Intelligence/risk | Outage preserves last valid data with stale warning; score replay exactly reproduces inputs and version; conflicts remain visible                                   | Replay fixtures / implementation + verification                                        |
| AC-09 Deployment        | Clean install, representative scan, export, upgrade and restore pass on SaaS, self-hosted and hybrid references                                                     | Mode-specific runbooks and evidence / implementation + verification                    |
| AC-10 Security          | SEC-01 through SEC-10 reviewed, no unresolved critical/high defects; key revocation and signed-update failure tested                                                | Security audit / Chief Architect after independent verification                        |
| AC-11 Operations        | Performance table met; backup restored; deletion replay tested; alerts and incident ownership exercised                                                             | Benchmark and recovery reports / operations owner                                      |
| AC-12 Usability         | At least 3 pilot operators complete onboarding → triage → verification using documentation; observed failures recorded and blockers corrected                       | Consented usability notes / product owner                                              |
| AC-13 Governance        | Challenge, implementation, verification and final audit artifacts exist; founder signs release                                                                      | `docs/WORKFLOW.md` milestone pipeline                                                  |

Fixture accuracy is not field recall. Report known coverage gaps and do not claim recall across unsupported products. An independent reviewer must reproduce at least one end-to-end scan and remediation cycle in each mode. This PRD itself has not passed these gates.

## 22. Product KPIs

Telemetry must be tenant-safe; self-hosted usage reporting is opt-in. Baselines do not yet exist. Proposed pilot goals below are hypotheses, not forecasts.

| KPI                         | Definition / window                                                                                                          | Proposed target or use                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Activation                  | Eligible onboarded tenants completing one authorized scan and evidence review within 7 days / all eligible onboarded tenants | ≥80%; always disclose denominator                                         |
| Time to first useful result | Median elapsed time from ready worker + approved scope to first reviewed actionable finding or valid clean-coverage report   | ≤60 minutes for reference pilot profile                                   |
| Assessment coverage         | Successfully assessed eligible assets / intended eligible assets per run                                                     | ≥95%; show exclusions separately                                          |
| Confirmed finding precision | Independently verified true positives / reviewed confirmed findings, per plugin and release                                  | Proposed ≥95%; publish sample uncertainty                                 |
| Verification completion     | Remediation claims receiving comparable successful verification within 7 days / all remediation claims                       | Establish baseline, then set goal                                         |
| Remediation time            | Median/p90 time from first observed finding to verified resolution by priority                                               | Baseline first; exclude unverified closure and report open censored cases |
| Repeat use                  | Activated tenants completing a second useful assessment within 30 days / activated tenants with 30-day eligibility           | Proposed ≥60%                                                             |
| Intelligence freshness      | Selected-source hours since last successful usable ingestion                                                                 | Match INT-05; report outages separately                                   |
| Reliability                 | Core API availability, scan completion and recovery outcomes                                                                 | Match section 20                                                          |
| Economics                   | Infrastructure + intelligence + attributable support cost per active tenant and assessed asset-month                         | Baseline before pricing; no invented margin target                        |
| Commercial validation       | Paid conversion and documented willingness to pay among eligible pilots                                                      | Track; target requires founder decision                                   |

Do not reward raw finding count, inflated severity, suppressed failures or total registered assets as substitutes for useful outcomes.

## 23. Implementation dependencies

1. Founder decisions on pilot, catalog, commercial boundaries, retention and release budgets.
2. Argon research on customer assumptions, intelligence rights, detection feasibility and alternatives; claims need sources and independent review.
3. ADRs for plane boundaries, tenancy, schema/identity, API contracts, ORM, queue semantics, worker trust, updates and deployment packaging.
4. Authorized lab targets, representative vulnerable/fixed/ambiguous fixtures and a maintained test corpus.
5. Identity provider test setup, signing-key custody, secret storage, artifact distribution and object storage.
6. CI checks, migrations, contract/security tests, deployment environments and observability.
7. Named operations/support and incident-response owners; legal review of scanning authorization, privacy and feed redistribution before external pilots.
8. Design-partner access and consent; no actual partner is assumed secured.

Follow the repository milestone pipeline. Claude implements; Argon independently verifies; Chief Architect audits; founder approves major decisions and release. This task does not delegate work or approve another agent's output.

## 24. Risks and alternatives considered

| Risk                                                | Implication                                     | Mitigation / owner                                                                                          |
| --------------------------------------------------- | ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| All-segment, all-mode ambition overwhelms resources | Delayed or unreliable release                   | Bounded pilot catalog and staged segment features / Founder                                                 |
| Remote-only checks have limited visibility          | False confidence and weak value                 | Explicit coverage, candidate classification, validate demand for authenticated checks / Product + Architect |
| Tenant or worker boundary failure                   | Customer data exposure or unauthorized scanning | Defense in depth, hostile-tenant tests, revocation / Architect                                              |
| Feed licensing or availability changes              | Distribution restrictions or stale intelligence | Rights review, provenance and source adapter isolation / Research + Founder                                 |
| Version matching/backports cause false positives    | Lost trust                                      | Evidence standards and vendor-specific fixtures / Detection owner                                           |
| Self-hosted support matrix expands                  | Unsustainable support costs                     | One reference configuration and measured support time / Operations                                          |
| Uncalibrated risk model misleads users              | Poor remediation decisions                      | Explain inputs and missingness, pilot comparison and versioning / Architect                                 |
| Sparse pilot sample overstates success              | Premature commercialization                     | Publish denominators and uncertainty; founder gate / Product                                                |
| Evidence contains sensitive content                 | Privacy/security exposure                       | Minimize, redact, enforce retention and access / Security                                                   |
| Infrastructure costs exceed price                   | Unsustainable business                          | Measure workload economics before packages / Founder                                                        |

Alternatives considered:

- Launch all segments with full feature depth: rejected for MVP due to unbounded acceptance scope; commitment remains long-term.
- SaaS-only MVP: lower operational burden, but conflicts with the proposed interpretation of the three-mode commitment; only founder may change release sequencing.
- Authenticated scanning first: potentially stronger evidence and inventory, but introduces credential/platform complexity; revisit if remote catalog cannot deliver pilot value.
- Broad plugin count first: rejected as a release criterion; verified useful coverage is the proposed measure.
- Microservices control plane: deferred until scaling/team boundaries justify its cost; modular monolith preferred.
- AI-generated vulnerability conclusions: excluded as authoritative detection; optional future assistance must preserve deterministic core operation.
- Use upstream severity alone: simpler but ignores exposure and business context; keep severity visible while validating an explainable priority model.
- Build versus integrate a scanning engine: unresolved. Evaluate licensing, redistribution, evidence quality, plugin trust, isolation and operational costs before choosing; do not assume proprietary engine development is required.

## 25. Prioritized development backlog

P0 = prerequisite or release-blocking; P1 = MVP workflow needed before pilot release; P2 = post-MVP candidate. Ordering expresses dependencies, not delivery dates or estimates.

| Order / priority | Deliverable                                                         | Dependency                                        | Completion gate                   |
| ---------------- | ------------------------------------------------------------------- | ------------------------------------------------- | --------------------------------- |
| 01 / P0          | Validate pilot problems and approve exact detection catalog         | Founder + design partners                         | AC-01                             |
| 02 / P0          | Threat model, architecture ADRs and data/API contracts              | 01                                                | AC-02                             |
| 03 / P0          | Identity, roles, tenant isolation and audit foundation              | 02                                                | AC-03, AC-10                      |
| 04 / P0          | Portable deployment skeleton, CI, secrets, metrics and backup path  | 02                                                | Initial three-mode smoke tests    |
| 05 / P0          | Asset identity, scope validation and authorization policy           | 03                                                | FR-02/03, asset lifecycle tests   |
| 06 / P0          | Worker enrollment, mTLS, job leases, safety limits and cancellation | 04–05                                             | AC-07                             |
| 07 / P0          | Plugin contract, signed updates and fixture harness                 | 02, 06                                            | AC-04, update security tests      |
| 08 / P0          | Approved discovery/detection catalog and evidence ingestion         | 07                                                | AC-04/05                          |
| 09 / P0          | Licensed intelligence ingestion, provenance and freshness           | 02, source rights review                          | AC-08                             |
| 10 / P1          | Finding deduplication, triage, exception expiry and verification    | 05, 08                                            | AC-06                             |
| 11 / P1          | Versioned risk model and explainability                             | 09–10, scoring decision                           | AC-08                             |
| 12 / P1          | Scheduling, progress, inventory and finding workflows               | 06, 10                                            | FR-05/11/14, AC-12                |
| 13 / P1          | Reports, scoped API credentials and safe exports                    | 03, 10–11                                         | API contract and AC-03 regression |
| 14 / P0          | Retention, deletion, upgrade and restore exercises in every mode    | 04, 08–13                                         | AC-09/11                          |
| 15 / P0          | Independent security, performance and pilot validation              | All MVP work                                      | AC-01 through AC-12               |
| 16 / P0          | Resolve audit blockers and founder release decision                 | 15                                                | AC-13                             |
| 17 / P2          | Authenticated scanning and expanded platform catalog                | Validated demand and credential ADR               | Separate approved scope           |
| 18 / P2          | Provider hierarchy, integrations and enterprise scale               | Pilot evidence and economics                      | Separate approved scope           |
| 19 / P2          | SURFACE, CLOUD, RESPONSE and COMMAND                                | Product discovery and founder investment decision | Separate PRDs/ADRs                |

## Outstanding founder decisions

1. Approve SMB/mid-market as the first pilot focus, with a provider design partner, while retaining all long-term segments?
2. Approve all three reference deployment modes as MVP release gates, or explicitly sequence their availability?
3. Which exact asset types, products, versions and checks must the first catalog cover? Is remote-only coverage commercially useful?
4. Approve an engine build-versus-integrate evaluation before committing development effort?
5. Which initial jurisdictions, hosting location and customer data categories are permitted?
6. Approve or revise retention/deletion defaults, identity/MFA policy and risk-exception authority?
7. Approve proposed risk defaults, priority bands and performance/recovery budgets for validation?
8. What team capacity, pilot budget, delivery constraints, support hours and incident ownership are available?
9. What pilot pricing approach, commercial success criteria and intelligence licensing budget should be tested?

## Final recommendation

**APPROVED WITH CONDITIONS** as a first planning baseline. Proceed to founder decisions, design-partner validation and Argon's independent challenge, then issue an approved implementation specification. Do not represent this PRD as approved architecture, tested product behavior or a launch authorization. Preserve all-market and all-deployment ambition while making initial coverage narrow, evidence-backed and measurable.

---

## Amendment A — alignment with Master Project Instructions (PROPOSED)

Author: Claude (CTO / Principal Engineer role) · Date: 2026-11-06 · Status: **PROPOSED**, awaiting Astra 6 review and founder approval. This amendment proposes changes and does not rewrite v0.1. Where the two conflict, v0.1 stands until the founder approves this amendment.

### A1. Detection confidence classes (replaces §13 "confirmed / probable / candidate")

The Master Instructions §12 require at least five classes. Each class is a property of one check outcome on one asset/component and is assigned only by deterministic rules recorded with the plugin version.

| Class          | Meaning                                                                                                          | Minimum evidence                                                                                                                                                                                     | Shown as a finding?                                             |
| -------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `CONFIRMED`    | The check's stated vulnerable condition was directly observed                                                    | Condition-specific evidence (e.g. protocol behaviour, configuration value, authoritative package revision compared against the vendor's fixed revision). **A version string alone never qualifies.** | Yes                                                             |
| `PROBABLE`     | Strong indirect evidence; the known backport and vendor-versioning risks have been accounted for                 | Version evidence plus corroboration that rules out backports for this platform (e.g. a distribution package revision in a banner that maps to an unfixed advisory state)                             | Yes                                                             |
| `POTENTIAL`    | Product/version correlation without enough evidence to rule out backports, configuration or platform differences | Upstream version match only                                                                                                                                                                          | Yes, in a separate review queue (replaces "candidate")          |
| `NOT_AFFECTED` | Evidence shows the condition is absent                                                                           | Fixed revision observed, condition tested and absent, or vendor states not affected for the observed platform                                                                                        | No, recorded as a check outcome for coverage and verification   |
| `UNKNOWN`      | The check ran but could not decide                                                                               | Timeout, auth failure, ambiguous response, missing prerequisite                                                                                                                                      | No, recorded as a coverage gap. It can never resolve a finding. |

Rules: the class can move up only with new evidence and down only with new evidence or a plugin revision. Every class change keeps the prior observation. AI never assigns or changes a class.

### A2. Scanner (worker) lifecycle (v0.1 has no explicit section)

States: `pending_enrollment` → `active` → `stale` (missed heartbeats beyond threshold) → `active` (on reconnect) · `active`/`stale` → `disabled` (admin, reversible) · any → `revoked` (terminal).

- An enrollment token is single-use, expires within 24 hours (proposed), is bound to one tenant and one scope group, and is stored only as a hash.
- The worker generates its own key pair. The private key never leaves the worker host. The control plane issues a short-lived client certificate and rotates it before expiry.
- A revoked worker receives no jobs. Results it submits after revocation, or after its lease expires, are rejected and audited.
- Heartbeats report version, capacity and health only. A heartbeat is not scan progress (see §12).

### A3. Remediation lifecycle (made explicit; v0.1 embeds it in §13)

`assigned` → `in_remediation` → `fix_claimed` → `verification_scheduled` → one of:

- `verified_resolved`: a comparable successful check returned `NOT_AFFECTED`.
- `verification_failed`: the condition was still detected, so the finding returns to `in_remediation`.
- `verification_inconclusive`: the result was `UNKNOWN` or coverage was partial. The finding stays open and the result is reported as a coverage failure.

Manual closure stays possible but is labeled `closed_unverified` (v0.1 §13).

### A4. Consequence of remote-only MVP scope (founder decision D3, **APPROVED 2026-11-06**)

Founder ruling: M1 is remote, non-intrusive network discovery and service assessment. M2 may add authenticated, read-only Linux package inventory. **Never classify a finding `CONFIRMED` based solely on a remotely observed version when vendor backports or other uncertainty may exist.**

Without authenticated package evidence, most Linux service-version matches cannot honestly exceed `POTENTIAL`, because distributions backport fixes without changing upstream version numbers. The coverage disclosure (FR-14) must state this. This strengthens the research challenge in `docs/research/MARKET_OPPORTUNITIES.md`: authenticated, read-only Linux package inventory is the most direct route to `CONFIRMED` and `NOT_AFFECTED` outcomes. See `docs/product/ROADMAP.md`, milestone M2.

### A5. Deployment sequencing (founder decision D2, **APPROVED 2026-11-06**)

Founder ruling: self-hosted first, hybrid second, SaaS third. Design for all three, implement one at a time, and avoid premature deployment complexity.

Proposed: design every mode from day one (tenant-aware schema, outbound-only workers), but release in this order: **self-hosted reference → hybrid → SaaS**. Reason: self-hosted needs no hosting budget and carries no public-scan abuse exposure, which fits current resources. SaaS adds multi-tenant operations, abuse controls and an on-call burden. This changes v0.1 §6/§17, where all three modes were MVP gates.

### A6. AI (Master Instructions §16)

Unchanged from v0.1: AI is excluded from the MVP. Any later AI feature is subject to Master Instructions §16. It must be optional, consent-governed, permission-aware and prompt-injection-resistant, and it never establishes findings or risk scores.
