# VULNEX Market Opportunities

Date: 2026-11-06 | TASK 002 | Hypotheses for validation, not proven advantages

Author: Claude Opus 5.5 (initial author, as recorded by the founder on 2026-11-06). Independent review and verification by Astra 6: **pending**.

## Executive summary

**APPROVED WITH CONDITIONS:** focus on trustworthy assessment outcomes and operational simplicity for a bounded pilot. The evidence does not support claiming a vacant market for findings with evidence, remediation verification, private scanning, explainable prioritization or provider management. [Tenable verification][T2] [Rapid7 proof][R6] [Greenbone reports][G2] [Microsoft multitenancy][M5]

Five recommended candidate advantages are defined at the end, with measurement plans. VULNEX has not demonstrated any of them. No market size, willingness to pay, win rate, customer demand or cost advantage was established by this desk research.

## Requirements

Preserve the founder's all-market and SaaS/self-hosted/hybrid commitments while validating a narrow entry workflow. Keep SCAN/INTELLIGENCE initial focus and deterministic detection. Do not silently alter PRODUCT_REQUIREMENTS.md, expand into every competing module, or claim competitor shortcomings from missing public documentation. Use founder approval and ADRs for material scope/architecture changes.

## Technical analysis: eight opportunity areas

| Area                          | Competitive baseline and evidence                                                                                                               | Credible hypothesis                                                                                                                    | Priority / verdict                                                 |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Evidence-backed findings      | Proof, plugin information and QoD already exist [R6][R6] [T6][T6] [G2][G2]                                                                      | A consistent evidence contract with provenance, confidence, coverage and replayable decisions reduces triage effort                    | MVP foundation; **APPROVED WITH CONDITIONS**                       |
| Remediation verification      | Targeted checks and verification states already exist [T2][T2] [R2][R2]; closure policy can be configuration dependent [Q1][Q1]                 | Strict comparable-check closure plus visible failure states prevents misleading remediation reports                                    | MVP foundation; **APPROVED WITH CONDITIONS**                       |
| Explainable risk              | VPR drivers and Active Risk inputs are documented [T5][T5] [R3][R3]                                                                             | Exportable input snapshots and complete score replay make decisions easier to defend                                                   | MVP foundation; formula validation required                        |
| Multi-tenant MSSP experience  | Provider programs/views already exist [Q5][Q5] [G7][G7] [M5][M5]; Wiz announcement includes preview qualifications [W4][W4]                     | A small-provider workflow can reduce onboarding/reporting effort without weakening isolation                                           | Design-partner experiment; aggregate provider product post-MVP     |
| Private scanning architecture | Local/hybrid deployment is established [T3][T3] [Q4][Q4] [R1][R1] [W2][W2]                                                                      | A small, clearly documented portable deployment with explicit data egress and update behavior reduces operating burden                 | MVP baseline; superiority must be measured                         |
| Detection transparency        | Greenbone offers source/community ecosystem; Tenable supports scoped custom NASL [G10][G10] [T4][T4]                                            | Per-check prerequisites, limitations, change history and fixture-backed behavior are understandable without source reverse engineering | MVP documentation; public source model remains a business decision |
| Plugin extensibility          | Custom check paths exist; feed/software rights and support restrictions differ [T4][T4] [G8][G8]                                                | A safe SDK with signed artifacts and compatibility tests could serve specialized environments                                          | Post-MVP evaluation; arbitrary customer execution remains excluded |
| AI-assisted analysis          | Wiz publicly describes AI analysis/validation [W8][W8]; selected sources do not establish an exhaustive AI feature inventory for the other five | Optional source-grounded summaries may save analyst time while preserving deterministic findings                                       | Later controlled experiment; not an initial moat                   |

“Evidence-backed” does not require exploit execution. Package evidence, a validated condition or a protocol observation may be sufficient for a precisely stated claim; exploitability and environmental reachability remain separate.

## Proposed solution and market-entry test

Recruit 3–5 design partners for a bounded network-assessment workflow, including at least one provider and representation of deployment modes. This is proposed recruitment, not an existing pipeline. Interview the buyer, analyst and remediation owner separately. Record their current workflow, budget authority, procurement constraints and cost of onboarding before presenting VULNEX's solution.

Run paired exercises on an authorized catalog of vulnerable, fixed, backported, ambiguous, unreachable and changed-identity targets. Compare against the customer's incumbent on the common supported subset; report incumbent-only coverage and VULNEX-only coverage separately. Never remove difficult cases merely to improve precision. Use randomized task order and independent labels to reduce familiarity bias.

Continue only if operators show repeated useful use and evidence of commercial willingness. A polished demo or favorable comments do not demonstrate switching demand. A companion assessment workflow may be a more credible first purchase than replacing an incumbent entirely.

## Critical challenge to the existing PRD

The current PRD excludes authenticated host scanning from MVP. Competitors document this assessment method, and it materially expands access to installed-software information. [Tenable credentials][T1] [Qualys authentication][Q1] [Greenbone authenticated scanning][G1]

**NEEDS REVISION** if the proposed remote-only catalog cannot answer pilot customers' chosen workflow. This is a conditional challenge, not an instruction to add authenticated scanning immediately. The founder should choose one of: retain a narrower external/service-assessment promise; integrate a reviewed engine for a declared authenticated scope; or approve an expanded credential-management milestone. Preserve the file until that decision is made.

The PRD also defers aggregated provider dashboards. Therefore “MSSP experience” can only be a pilot usability hypothesis initially, not a delivered fleet-management advantage. The proposed risk formula is uncalibrated; reproducible arithmetic does not establish effective prioritization.

## Alternatives considered

| Option                                                  | Assessment                                                                                                       |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Compete on full catalog breadth now                     | **REJECTED**: content maintenance and coverage validation would dominate a small initial effort                  |
| Wrap an existing engine and sell a new UI               | **NEEDS REVISION**: potentially viable only with rights, demonstrated workflow value and support economics       |
| Build all detection content internally                  | **NEEDS REVISION** until build/integrate comparison includes fixture, update and incident costs                  |
| Enter through enterprise/regulatory certifications      | Defer; buyer interest and deployment capability do not constitute certification                                  |
| Lead with AI findings/autonomous remediation            | **REJECTED** for initial scope; error and authorization consequences conflict with deterministic core principles |
| Lead with evidence and verification on a narrow catalog | **APPROVED WITH CONDITIONS**: must demonstrate useful coverage and measurable workflow gains                     |

## Security implications

- Evidence must be minimal, redacted and tenant-scoped; retain immutable decision metadata without indefinite sensitive payload retention.
- Verification must bind asset identity, service/component identity, check compatibility and successful assessment; unreachable is a coverage failure.
- Provider delegation needs per-customer roles, token boundaries, audit and noisy-neighbor protection.
- A private worker needs explicit enrollment, scope leases, revocation and disclosed data flows. A local scanner does not make cloud metadata private.
- An SDK adds execution and supply-chain risk; require sandboxing, signatures, revocation and compatibility fixtures before third-party plugins.
- AI outputs must cite authorized evidence, abstain when evidence is missing and withstand prompt injection in target banners/advisories. AI cannot change detection status or authorize actions. No tenant data leaves approved processing boundaries.

## Performance implications

Measure time spent by people separately from scan runtime. Evidence export and history replay impose storage/query costs; establish quotas and retention. Verification queues need bounded latency and fairness without claiming instant completion on unreachable targets. Optional AI adds cost, latency and availability dependencies; core workflows must remain usable without it.

## Scalability implications

Optimize many small customer contexts as well as large asset totals. Tenant onboarding, worker upgrades, exception expiry and report fan-out can become provider bottlenecks. The proposed modular monolith plus independent workers remains appropriate pending measurements; no new architecture is approved here.

## Implementation dependencies and staged backlog

1. **P0 — validate scope:** founder approves beachhead and exact catalog; interview/recruit partners; resolve engine/feed rights.
2. **P0 — trust foundation:** evidence schema, tenant isolation, scope safety, coverage outcomes and compatible verification contracts.
3. **P1 — decision workflow:** score input snapshots, exceptions, human/API reports and audited exports; measure analyst tasks.
4. **P1 — deployment proof:** one supported reference per mode, data-flow tests, recovery and upgrade exercises.
5. **P1 — pilot economics:** instrument cost per assessed asset and tenant, support time, repeat use and pricing feedback.
6. **P2 — provider workflow expansion:** only after demand, delegated role and economics validation; no immediate fleet-wide feature promise.
7. **P2 — extensibility/AI:** separately gated SDK and optional assistant trials; neither is necessary to prove the initial proposition.

No schedule or headcount estimate is defensible until catalog and deployment acceptance criteria are approved.

## Acceptance criteria

Research acceptance: six-vendor documentary matrix and source registry complete; claims classified; limitations explicit. Product-advantage acceptance requires independent trials, raw evidence, comparable workloads and disclosed uncertainty.

Before any public superiority claim, require a named comparator/SKU/version, identical supported task scope, predeclared metrics, repeated trials and independent review. Document cases where the comparator is better. A zero-error fixture run only proves the tested cases. If samples are too small, label results inconclusive. Proposed thresholds below are pilot gates, not forecasts or customer SLAs.

Commercial validation should include at least three operators from distinct organizations completing repeated assessment/remediation cycles and at least two buyers accepting a concrete paid-pilot proposal, subject to founder-approved pricing. These small samples support further learning, not market-wide demand.

## Outstanding questions

- Is the buyer purchasing a primary VM system, a verification companion, or an assessment service?
- Which systems require credentials or agents before the workflow becomes useful?
- Which customers need full private control-plane operation rather than local collection?
- What provider delegation and billing requirements actually block adoption?
- Which evidence can be retained/exported under customer policy?
- What fully loaded support and content costs can pricing sustain?
- Does transparent scoring improve decisions, or just perceived confidence?
- Can selected engine/feed rights support all three deployment modes and commercial distribution?

## Final recommendation: five measurable candidate competitive advantages

### 1. Faster, independently reviewable finding evidence

**Promise to test:** operators can determine what was detected and why with less investigation. Existing proof/QoD makes “we include evidence” insufficient. [Rapid7 API][R6] [Greenbone reports][G2]

**Measure:** 100% of confirmed findings contain check/version, observation time, asset/component binding, redacted evidence, confidence and limitation fields. Independently replay at least 100 labeled observations spanning every released check. Compare median analyst time on matched tasks; proposed target ≥25% reduction against the participating customer's current workflow, without worse precision or common-scope recall. Publish denominators and confidence intervals. Treat unsupported assets separately.

**Stage:** MVP. **Potential defensibility:** maintained fixtures and decision provenance, not an attractive evidence panel.

### 2. Verification that distinguishes a fix from missing visibility

**Promise to test:** fewer misleading closure decisions and quicker verified follow-up. Competitors already verify remediation, so the test must examine edge cases rather than checkbox presence. [Tenable][T2] [Rapid7][R2]

**Measure:** zero false closures across a predeclared corpus of at least 50 failure/identity/partial-coverage scenarios; 100% of automatic closures point to a successful comparable check. Measure p95 request-to-verification-start and completion-to-visible-state independently; proposed healthy-capacity start ≤30 seconds and completed-result display ≤60 seconds on the reference topology. For a real advantage, compare false closure and operator rework rates against a correctly configured incumbent, not an intentionally unsafe default.

**Stage:** MVP. **Potential defensibility:** explicit lifecycle contracts, regression corpus and long-term correction history.

### 3. Reproducible and understandable prioritization

**Promise to test:** customers can reconstruct why work was prioritized and distinguish changed intelligence from changed exposure. Incumbents already publish drivers; complete replay is the candidate distinction. [Tenable drivers][T5] [Rapid7 transition][R4]

**Measure:** reproduce 100% of at least 1,000 saved score decisions from versioned inputs; label every unknown input and override. At least 80% of pilot operators should correctly explain the top contributing factors in a blinded comprehension test. Compare top-k prioritization with independent analyst labels and report disagreement; do not optimize agreement at the expense of hiding uncertain critical cases. No claim of predictive breach accuracy without a separate longitudinal study.

**Stage:** MVP with conservative defaults validated. **Potential defensibility:** auditable decision history and demonstrated decision quality.

### 4. Predictable private and hybrid operations

**Promise to test:** a small team can install, update and recover a supported deployment while knowing exactly what data leaves it. Private components are already offered by competitors; simplicity and verified boundaries are the hypothesis. [Security Center][T3] [Qualys private platform][Q4] [Wiz Outpost][W2]

**Measure:** three independent operators complete each relevant reference installation using only documentation; proposed median time to healthy worker ≤60 minutes after prerequisites are ready. Packet capture and egress-deny tests show zero undeclared destinations and no prohibited payloads. Verify core self-hosted workflows during a 24-hour external-service outage using the last valid feed, with clear freshness warnings. Demonstrate the PRD's backup/restore budgets. Compare full operator hours and infrastructure/support costs on equivalent tasks before claiming cheaper operation.

**Stage:** MVP reference topologies; broad platforms and certified air-gap later. **Potential defensibility:** reproducible runbooks, constrained support matrix and transparent data contracts.

### 5. Lower operational effort for small MSSPs without weakened isolation

**Promise to test:** manage many small customers with fewer manual steps and no ambiguous customer context. Competitors already offer provider functions; target a specific underserved workflow, not “first multi-tenant VM.” [Qualys program][Q5] [Microsoft dashboard][M5] [Wiz preview][W4]

**Measure:** in a 20-tenant synthetic exercise with overlapping private address ranges, perform onboarding, scoped scan, analyst handoff and customer report tasks. Proposed target ≥30% less median operator time than the partner's current workflow; record errors and setup costs. Require zero unauthorized reads/writes across API, queue, evidence and report tests, plus complete actor/customer audit attribution. Validate with at least two provider organizations before a broad claim, and report measured cost per active customer rather than assuming margin.

**Stage:** MVP design-partner learning; full aggregate provider workflow post-MVP under a separate approved scope. **Potential defensibility:** repeatable operations and sound provider economics.

**Recommendation: APPROVED WITH CONDITIONS.** Build foundations for the first four, validate the fifth without expanding MVP by default, and defer an open plugin ecosystem and AI-led automation until evidence justifies investment.

[T1]: https://developer.tenable.com/docs/manage-scans 'Tenable: scan API'
[T2]: https://developer.tenable.com/docs/manage-remediation-scans 'Tenable: remediation scans'
[T3]: https://docs.tenable.com/quick-reference/licensing-guide/Content/tenable-security-center-licensing.htm 'Tenable: Security Center licensing'
[T4]: https://docs.tenable.com/security-center/Content/CustomPlugins.htm 'Tenable: custom NASL packages'
[T5]: https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/RiskMetrics.htm 'Tenable: current risk metrics'
[T6]: https://docs.tenable.com/vulnerability-management/Content/Explore/findings-details-vulnerabilities.htm 'Tenable: finding details'
[T7]: https://docs.tenable.com/quick-reference/licensing-guide/Content/t1-foundation-advanced-licensing.htm 'Tenable: One licensing'
[Q1]: https://docs.qualys.com/en/vmdr/latest/option_profiles/op_scan_tab.htm 'Qualys: scan options'
[Q2]: https://docs.qualys.com/en/vmdr/latest/mergedProjects/search_in_vmdr/get_started/get_started.htm 'Qualys: VMDR getting started'
[Q3]: https://docs.qualys.com/en/vmdr/getting-started-guide/features_of_vmdr/qualys_trurisk.htm 'Qualys: TruRisk packages'
[Q4]: https://www.qualys.com/private-cloud 'Qualys: Private Cloud'
[Q5]: https://www.qualys.com/partners/mssp 'Qualys: MSP/MSSP program'
[Q6]: https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm 'Qualys: Host Detection API'
[Q7]: https://docs.qualys.com/en/etm/latest/responses/remediation_validation.htm 'Qualys: ETM remediation validation'
[Q8]: https://investor.qualys.com/news-releases/news-release-details/qualys-brings-its-market-leading-vulnerability-management 'Qualys: VMDR commercial announcement'
[R1]: https://docs.rapid7.com/insightvm/planning-a-deployment/ 'Rapid7: deployment planning'
[R2]: https://docs.rapid7.com/insightvm/remediation-workflow/ 'Rapid7: remediation projects'
[R3]: https://docs.rapid7.com/insightvm/working-with-risk-strategies-to-analyze-threats/ 'Rapid7: Active Risk'
[R4]: https://docs.rapid7.com/insightvm/legacy-risk-strategies-end-of-life-announcement/ 'Rapid7: risk strategy deprecation'
[R5]: https://docs.rapid7.com/insightvm/scan-assistant-combined/ 'Rapid7: Scan Assistant'
[R6]: https://help.rapid7.com/insightvm/en-us/api/integrations.html 'Rapid7: v4 integration API'
[R7]: https://www.rapid7.com/pricing/ 'Rapid7: pricing'
[R8]: https://www.rapid7.com/globalassets/docs/managedservices/mvm-scope-of-service.pdf 'Rapid7: Managed VM scope'
[R9]: https://documentation.rapid7.com/insightgovcloud/secure-config-guide.htm 'Rapid7: InsightGovCloud secure configuration'
[G1]: https://docs.greenbone.net/GSM-Manual/gos-25.0/en/introduction.html 'Greenbone: OPENVAS SCAN introduction'
[G2]: https://docs.greenbone.net/GSM-Manual/gos-25.0/en/reports.html 'Greenbone: reports'
[G3]: https://docs.greenbone.net/GSM-Manual/gos-25.0/en/faq.html 'Greenbone: FAQ'
[G4]: https://docs.greenbone.net/GSM-Manual/gos-25.0/en/agents.html 'Greenbone: agent scans'
[G5]: https://docs.greenbone.net/GSM-Manual/gos-25.0/en/gmp.html 'Greenbone: GMP'
[G6]: https://docs.greenbone.net/GCS-Manual/gcs/en/introduction.html 'Greenbone: Cloud Service introduction'
[G7]: https://docs.greenbone.net/GCS-Manual/gcs-msp/en/billing-overview.html 'Greenbone: service-provider billing'
[G8]: https://www.greenbone.net/en/license-information/ 'Greenbone: license information'
[G9]: https://forum.greenbone.net/t/greenbone-os-25-0-0-released/22164 'Greenbone: GOS 25 release announcement'
[G10]: https://greenbone.github.io/docs/latest/faq.html 'Greenbone: Community FAQ'
[M1]: https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/defender-vulnerability-management 'Microsoft: VM overview'
[M2]: https://learn.microsoft.com/en-us/defender-vulnerability-management/defender-vulnerability-management-faq 'Microsoft: VM FAQ'
[M3]: https://learn.microsoft.com/en-us/defender-endpoint/network-devices 'Microsoft: network scanning setup'
[M4]: https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-remediation 'Microsoft: remediation'
[M5]: https://learn.microsoft.com/en-us/defender-xdr/mto-dashboard 'Microsoft: multi-tenant VM dashboard'
[M6]: https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-prerequisites 'Microsoft: prerequisites and licenses'
[W1]: https://www.wiz.io/solutions/vulnerability-management 'Wiz: unified vulnerability management'
[W2]: https://aws.amazon.com/marketplace/pp/prodview-f5su6hitnszcu 'Wiz for Gov: Outpost listing'
[W3]: https://www.wiz.io/blog/wiz-tenant-manager-multi-tenant-security 'Wiz: Tenant Manager'
[W4]: https://www.wiz.io/blog/introducing-wiz-partner-alliance-managed-service-provider-program 'Wiz: managed-service program'
[W5]: https://www.wiz.io/pricing 'Wiz: pricing'
[W6]: https://www.wiz.io/integrations 'Wiz: integrations'
[W7]: https://www.wiz.io/blog/introducing-cva 'Wiz: continuous vulnerability assessment'
[W8]: https://www.wiz.io/academy/vulnerability-management/ai-vulnerability-management 'Wiz: AI vulnerability management'
[I1]: https://www.trustradius.com/products/tenable-vulnerability-management/reviews 'TrustRadius: Tenable VM reviews'
[I2]: https://www.trustradius.com/products/qualys-vmdr/reviews 'TrustRadius: Qualys VMDR reviews'
[I3]: https://www.trustradius.com/products/rapid7-insightvm/reviews 'TrustRadius: Rapid7 InsightVM reviews'
[I4]: https://www.trustradius.com/products/wiz/reviews 'TrustRadius: Wiz reviews'
[I5]: https://discuss.rapid7.com/t/remediation-project-update-sync-interval-with-security-console/44460 'Rapid7 community: remediation synchronization'
