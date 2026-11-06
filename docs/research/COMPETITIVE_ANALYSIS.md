# VULNEX Competitive Analysis

Date: 2026-11-06 | TASK 002 | Public-source independent desk research

Author: Claude Opus 5.5 (initial author, as recorded by the founder on 2026-11-06). Independent review and verification by Astra 6: **pending**.

**Verdict: APPROVED WITH CONDITIONS** for research-led product planning. No competitive-superiority claim, product implementation or architecture change is approved.

## Executive summary

The category already offers scanning, inventory, prioritization, evidence and remediation workflows. Tenable documents targeted remediation scans; Rapid7 exposes proof and verification states; Greenbone documents detection quality and report history. These capabilities are competitive baselines, not unoccupied markets. [Tenable verification][T2] [Rapid7 workflow][R2] [Rapid7 API][R6] [Greenbone reports][G2]

VULNEX should test a narrower promise: an operator can understand a finding, see what was not checked, prioritize it using reproducible inputs, and verify a fix without confusing failed assessment with remediation. This is a **hypothesis**, not demonstrated superiority. The current PRD's remote-only MVP has a material coverage disadvantage against documented authenticated assessment approaches. [Tenable scans][T1] [Qualys options][Q1] [Greenbone scanning][G1]

## Requirements and scope

Assess six vendors across the requested fifteen dimensions. Distinguish products, modules and deployment boundaries; do not compare a standalone scanner with an entire exposure suite as though their licenses are equivalent. Companion files: [feature matrix](COMPETITOR_FEATURE_MATRIX.md), [opportunities](MARKET_OPPORTUNITIES.md), [source register](RESEARCH_SOURCES.md).

Evidence labels: **D** documented capability, **M** vendor claim, **P** preview, **I** individual user report, **U** unresolved, **H** inference. D is documentation verification only. Nothing was lab-tested. All sources were accessed or retrieved through indexed text on the research date. No customer interviews or paid analyst studies were conducted. Negative claims use U unless an explicit source documents a restriction.

## Technical analysis: vendor assessments

### Tenable

- **Positioning (M/D):** Assess the hosted Vulnerability Management product separately from Security Center's local console and the broader Tenable One packaging. Security Center Director is an additional multi-instance management component. [Security Center licensing][T3] [One licensing][T7]
- **Scanning, detection and authentication (D):** API documentation distinguishes discovery, assessment, credentialed Windows/SSH and agent scans. This is broader than VULNEX's proposed unauthenticated catalog. A product/version match and direct condition evidence must not be treated as identical detection methods merely because both are returned as findings. [Scan API][T1]
- **Inventory and intelligence (D):** Asset-based licensing and matching/reclamation rules matter to inventory operations; findings carry plugin and risk context. Current VPR documentation describes threat drivers. It is incorrect to portray the score as offering no explanation, although the public material reviewed does not establish complete offline score reproducibility. [Licensing][T7] [Finding details][T6] [Risk metrics][T5]
- **Reporting and remediation (D):** Security Center documentation includes reporting assets/templates; targeted remediation scans reassess selected plugins/targets. The remediation API explicitly excludes agent scans from that particular workflow. This restriction is not proof that agent findings cannot ever clear. [Security Center templates](https://docs.tenable.com/security-center/Content/ConfigurationSettings.htm) [Remediation scans][T2]
- **API/integrations (D):** Programmatic scan lifecycle, credentials and targeted verification are documented. Integration availability and export quotas still require edition-specific evaluation. [Scan API][T1]
- **Deployment (D):** Hosted VM with on-premises Nessus scanning is a hybrid pattern; Security Center provides a distinct customer-hosted management option. Same-brand products are not automatically feature-identical. [Remediation sensors][T2] [Security Center][T3]
- **MSSP/licensing (D):** The licensing guide explicitly addresses MSSP commercial arrangements; Director manages multiple Security Center instances. Assessed asset counts, module counts and reclamation conditions need contract modeling. A partner program alone does not prove a particular isolation design. [Security Center][T3] [One licensing][T7]
- **Extensibility (D):** Custom NASL packages exist for Security Center managed scanners, with linked-scanner and troubleshooting limitations. “Tenable cannot be extended” would be false. [Custom packages][T4]
- **Pain signals (I):** Individual TrustRadius reviewers request more client-facing reporting and simpler renewal/package navigation; the same page includes positive accounts of vulnerability explanation and filtering. These are dated experiences, not current licensing rules or a representative satisfaction study. [Reviews][I1]

**Implication (H):** Competing on raw detection breadth first is implausible without major investment. Test whether a bounded, independently reproducible workflow is simpler for a narrow buyer; do not claim Tenable lacks evidence or verification.

### Qualys

- **Positioning/inventory (D/M):** VMDR combines inventory, assessment and prioritization, with entitlement-dependent remediation capabilities. Discovery sensors and asset attributes support a broader inventory than network scan output alone. [Getting started][Q2]
- **Scanning/detection/authentication (D):** Scan profiles configure ports, QIDs and credentials. Authenticated access increases available assessment information. QIDs are detection identities; they do not imply that the user receives source code. [Options][Q1]
- **Intelligence/risk (D):** TruRisk packages expose prioritization; the detection API includes QDS. Do not flatten asset risk and detection risk into one metric or assume every package contains every remediation module. [Packages][Q3] [Detection API][Q6]
- **Reporting/remediation (D):** Dashboards, prioritization and ServiceNow-related workflows are documented. ETM documentation describes validation from subsequent source detections; ETM is a separate product context, not evidence of default VMDR entitlement. [Getting started][Q2] [ETM validation][Q7]
- **Important closure qualification (D):** A configurable option closes findings on repeatedly unreachable IP-tracked hosts. Light-scan authoritative settings also affect closure interpretation. This is documented policy behavior, not proof of universal false closure or a security defect in all configurations. [Scan options][Q1]
- **API (D):** Host Detection API provides programmatic retrieval; trial API quotas, pagination and evidence fidelity before relying on bulk extraction. [API][Q6]
- **Deployment (D/M):** Cloud-managed scanner/agent deployment is established. Qualys also advertises a Private Cloud Platform; it is inaccurate to claim Qualys has no private platform option. Hardware/operations prerequisites, VMDR feature parity and commercial eligibility remain procurement questions. [Getting started][Q2] [Private Cloud][Q4]
- **MSSP/licensing (M):** A dedicated MSP/MSSP program exists. Historical VMDR commercial material describes asset-oriented packaging; current bundle prices and precise counting rules require a quote. The historical announcement is not a current price list. [Partner offering][Q5] [Commercial announcement][Q8]
- **Pain signals (I):** Reviews include requests for simpler interfaces and connectors and conflicting views on value for money. No uniform conclusion that Qualys is expensive or unusable follows. [Reviews][I2]

**Implication (H):** Transparent closure semantics and predictable scoped packaging are testable opportunities. Private scanning and remediation alone are not differentiators.

### Rapid7

- **Positioning/deployment (D):** InsightVM uses a Security Console and scan engines, with cloud capabilities layered into the operating model. Customer-hosted components do not mean every cloud feature works offline. Rapid7 Managed VM separately documents a vendor-hosted console with service-specific limits. [Deployment][R1] [Managed VM][R8]
- **Scanning/authentication/detection (D):** Scan Assistant enables authenticated collection; it must not be conflated with the periodically assessing Insight Agent. Review mode-specific verification behavior in a trial. [Scan Assistant][R5]
- **Inventory/evidence/API (D):** Integration APIs expose assets and vulnerability observations, including proof and remediation information. Evidence-backed findings are therefore not new to this market. [Integration API][R6]
- **Intelligence/risk (D):** Active Risk uses vulnerability severity and exploitation/threat context. Legacy strategies were deprecated January 21, 2026. The documentation states historical data cannot be recalculated using Active Risk; reported risk changes must therefore be interpreted with model transitions in mind. [Risk strategy][R3] [Deprecation][R4]
- **Reporting/remediation (D):** Remediation projects assign and track work, including an awaiting-verification state that moves according to subsequent assessment. Console reports and cloud workflow features occupy different deployment components. [Projects][R2] [Deployment][R1]
- **SaaS/self-hosted/hybrid (D):** Local console/engine deployment and cloud-assisted operation are documented; hosted managed service exists. Do not describe the ordinary InsightVM topology as necessarily a pure SaaS product or the managed service as feature-identical to every installation. [Deployment][R1] [Managed service][R8]
- **MSSP (D/U):** Multi-tenant API keys are documented in InsightGovCloud. Commercial-market delegated workflows, provider economics and tenant provisioning need confirmation; that regional documentation is not sufficient evidence of universal entitlement. [Configuration][R9]
- **Licensing (M):** Public pricing is expressed per asset with volume conditions. This establishes the advertised unit, not actual customer TCO or a comparable quote for six vendors. [Pricing][R7]
- **Pain signals (I):** Reviews praise useful proof and remediation reporting while requesting simpler onboarding and reporting flexibility. A vendor-hosted community thread reports console/cloud synchronization delays; it is unverified, historical and not a supported latency specification. [Reviews][I3] [Forum report][I5]

**Implication (H):** Model-version auditability and observable scan-to-workflow latency deserve tests. Do not sell “verification states” or “proof” as features Rapid7 lacks.

### Greenbone / OPENVAS

- **Positioning and product boundaries (D):** Commercial OPENVAS SCAN appliances, Community Edition and Greenbone Cloud Service must be distinguished. Community software availability does not confer commercial feed rights or enterprise support. [Introduction][G1] [Community FAQ][G10] [Licenses][G8]
- **Scanning/authentication (D/P):** Network assessment supports credentialed internal checks. GOS 25 documentation also describes SBOM-based agent assessment as a technology preview; do not label it mature universal coverage or omit it entirely. [Scanning][G1] [Agent preview][G4]
- **Evidence/intelligence (D):** Reports include detection results and quality-of-detection information; lower-confidence checks may be filtered. Feed coverage and successful identification/authentication constrain results. Quality-of-detection is a method-confidence indicator, not this research's measured probability of correctness. [Reports][G2] [FAQ][G3]
- **Inventory/reporting/remediation (D):** The manual provides asset management, historical reports, report exports and model-dependent workflow capabilities. Validate the chosen appliance's features instead of extending one manual's menu coverage to every model. [Reports and manual navigation][G2]
- **API/extensibility (D):** GMP provides an authenticated XML management API. Open source availability is a credible transparency reference point; open management APIs, editable checks and rights to redistribute feeds are separate questions. [GMP][G5] [Community][G10] [Licenses][G8]
- **Deployment (D):** Local appliance/master-sensor patterns and cloud scanning of public/internal networks are documented. This counters any claim that VULNEX would introduce the first SaaS/private/hybrid family. [Introduction][G1] [Cloud][G6]
- **MSSP/licensing (D):** Cloud provider billing workflows exist. Commercial licenses vary by offering; a March 2026 announcement describes an asset-license transition prospectively. Confirm actual order terms. [Provider billing][G7] [Transition][G9]
- **Known limitations (D):** The cloud manual explicitly distinguishes host scanning from structural web-application testing. The FAQ describes failed login, failed product identification, missing tests and scan load as causes of gaps or problems. [Cloud boundary][G6] [FAQ][G3]
- **Customer pain evidence (U):** No sufficiently current direct independent sample was established here. Self-operated update/tuning effort is an architectural inference, not a proven customer complaint rate.

**Implication (H):** Compete on maintained workflows, support economics and independently verified catalog quality. “Open/extensible” alone is not unique, and integrating the engine needs license/security review.

### Microsoft Defender Vulnerability Management

- **Positioning/inventory/intelligence (D):** Endpoint-oriented vulnerability and configuration assessment is integrated into the Defender environment, with inventories, recommendations and exposure information. Supported operating systems and capability depth are not interchangeable. [Overview][M1]
- **Detection/authentication (D):** Endpoint collection and network-infrastructure authenticated scans must be distinguished from traditional general-purpose remote scanning. Windows authenticated scanning was removed from availability/support on December 18, 2025; network-device authenticated scanning remains separately documented. Older overview bullets are superseded by the explicit FAQ. [FAQ][M2] [Network scanning][M3]
- **Reporting/remediation (D):** Requests can create Intune tasks when integration is enabled; activities have tracking and CSV export. Marking a workflow complete is not itself evidence that every target is fixed. Completed remediation activity retention is documented as 180 days. [Remediation][M4]
- **API (D):** Machine, recommendation, score, software and vulnerability API families are listed. Exact export completeness, quota and licensing should be validated. [Overview][M1]
- **Deployment (D/U):** Cloud-tenant administration with local endpoint/network collection is documented. No customer-hosted full Defender VM control plane was established in these sources. An on-premises protected device is not a self-hosted management platform. [Overview][M1] [Network setup][M3]
- **MSSP (D):** Defender multitenant management includes aggregate vulnerability exposure and tenant drill-down. It is wrong to mark Microsoft as lacking cross-tenant VM views. [Multitenant dashboard][M5]
- **Licensing (D):** Standalone/add-on subscriptions and core capabilities in Defender for Endpoint P2 need separation; current prerequisites state per-user licensing. Server entitlements must be evaluated separately with the applicable Defender plans. [Licenses][M6] [FAQ][M2]
- **Known limitation (D):** The FAQ says certain “won't fix” CVEs are excluded from recommendations/scoring and not viewable in the product experience. This is a disclosed filtering decision, not proof the tool is unsafe. [FAQ][M2]
- **Customer pain evidence (U/H):** No current direct independent complaint sample was established here. Ecosystem procurement and capability filtering may create unmet needs, but customer interviews must validate that hypothesis.

**Implication (H):** A complementary private assessment and transparent exception-history workflow may be more credible than displacing bundled endpoint capabilities. Do not infer missing exposure data means missing endpoint support generally.

### Wiz

- **Positioning (M):** Current UVM material covers cloud, code and on-premises environments, including third-party aggregation and Sensor Workload scanning. “Wiz only works in public cloud” is not a defensible current claim. These are vendor-described capabilities; precise supported platforms and GA status need technical documentation/trial confirmation. [UVM][W1]
- **Scanning/detection/authentication (M/U):** Agentless cloud assessment relies on cloud-authorized collection, not absence of permissions. Sensor and aggregation approaches broaden the model. General Windows/SSH credential-scanner parity with network VM products was not established. [UVM][W1]
- **Inventory/intelligence/risk (M):** Security Graph context is central to positioning. The September 2026 CVA announcement describes reassessment when vulnerability intelligence changes. That should not be mistaken for independently demonstrated instantaneous fresh workload collection. [UVM][W1] [CVA][W7]
- **Reporting/remediation/API (M/I):** The integration catalog establishes offered ecosystem connections. Reviews describe reports, graph/API usage and remediation workflows; exact API contracts and comparable remediation-closure semantics remain unresolved because authenticated product documentation was not assessed. [Integrations][W6] [Reviews][I4]
- **Deployment (M/U):** Standard SaaS plus Outpost customer-environment workload scanning is documented in a vendor-authored AWS listing, specifically for Wiz for Gov. It does not prove a self-hosted full control plane or zero metadata egress. General commercial availability and data flows require confirmation. [Outpost][W2]
- **MSSP (M/P):** Tenant Manager was announced in March 2026; a subsequent MSP program announcement explicitly says public preview. Avoid both “no multitenancy” and “all MSSP functionality is GA.” [Tenant Manager][W3] [MSP preview][W4]
- **Licensing (M/U):** Public pricing offers Wiz One, Wiz Go and a la carte quote requests. No universal billing unit or price was verified from that page; obtain a workload/service mapping and contract. [Pricing][W5]
- **AI (M):** Public material describes AI-assisted investigation and validation. This is evidence of a vendor proposition, not measured correctness, safe autonomy or entitlement for every customer. [AI material][W8]
- **Pain signals (I):** 2025 reviews request improvements to exception workflows, tagging and reporting. They also praise contextualization and usability. Newer UVM/CVA releases make historical “real time” complaints especially unsafe to repeat as current defects. [Reviews][I4] [CVA announcement][W7]

**Implication (H):** VULNEX should not attempt immediate graph/CNAPP parity. Private operating simplicity for a bounded network workflow is a more testable entry hypothesis.

## Cross-industry findings and proposed solution

1. **Evidence and verification are established.** Differentiate with completeness, reproducibility and time saved, not their mere presence. [Tenable][T2] [Rapid7][R6] [Greenbone][G2]
2. **Risk transparency is a spectrum.** Published drivers already exist; full replayability, explicit missing inputs and preserved historical decisions are stronger candidate requirements. Do not call every proprietary score opaque. [Tenable drivers][T5] [Rapid7 model][R3]
3. **Deployment terminology can mislead.** Separate location of collector, raw evidence, normalized findings, management, identity and update services. Verify each path through packet capture and outage tests in future trials. [Qualys private offer][Q4] [Rapid7 topology][R1] [Wiz Outpost][W2]
4. **MSSP functionality is not a vacant market.** Compare end-to-end delegated operation, commercial counting and safe customer separation rather than checking a multitenancy box. [Qualys partners][Q5] [Greenbone provider][G7] [Microsoft dashboard][M5] [Wiz preview][W4]
5. **Remote-only MVP requires commercial validation.** It cannot be presumed equivalent to credentialed host or endpoint inventory. Preserve the approved PRD and bring an explicit coverage decision to the founder. [Authenticated scan examples][T1] [Qualys][Q1] [Greenbone][G1]

Proposed solution: retain a bounded SCAN/INTELLIGENCE pilot, build evidence and lifecycle correctness into its contracts, and evaluate five measurable candidate advantages in MARKET_OPPORTUNITIES.md. Do not expand the backlog merely because competitors expose more modules.

## Alternatives considered

- Full incumbent feature parity: **REJECTED** for MVP; scope and quality cannot be defended with current evidence/resources.
- Cheapest generic scanner: **NEEDS REVISION**; no comparable cost study or purchasing research supports a price advantage.
- Provider-first product: **APPROVED WITH CONDITIONS** for discovery only; validate delegated workflows and economics before moving provider aggregation into MVP.
- Build on Greenbone or another licensed engine: **APPROVED WITH CONDITIONS** for evaluation; software, feed, redistribution and service rights require review. [License boundary][G8]
- Optional AI assistant: **APPROVED WITH CONDITIONS** after deterministic workflows and a labeled evaluation set; not a core detection authority.

## Security implications

Evidence, privileged credentials and cloud snapshots are sensitive assets. VULNEX must minimize collection, redact exports, isolate tenants at every layer and constrain workers. Plugins and intelligence feeds are untrusted supply-chain inputs. Detection transparency must not expose tenant secrets. Future AI must resist hostile target text and must not approve exceptions, alter findings or execute remediation without explicit authorized workflows. These are design recommendations, not claims that competitors lack protections.

## Performance implications

No comparative performance winner is established. Measure scan duration against target count, port/check coverage, timeout policy, authentication and network conditions. Measure ingestion-to-display and verification-to-closure separately. Report p50/p95, failures and resource/egress costs. Fast scans with skipped checks are not equivalent assessments.

## Scalability implications

MSP scale introduces customer boundaries and operational workloads beyond asset count. Benchmark many small tenants, overlapping IP ranges, simultaneous exports and noisy-neighbor pressure. Scale scan workers independently while retaining the PRD's modular control plane. No evidence here justifies an architectural migration to microservices.

## Implementation dependencies

Founder-approved catalog and beachhead; legal/contract review for engine/feed rights; authorized test corpus; trials of selected relevant competitors; independent labeling; an operations cost model; interviews with buyers/operators. Architecture changes require ADRs. This report does not alter PRODUCT_REQUIREMENTS.md.

## Acceptance criteria for this research and next validation

This deliverable covers all six vendors and fifteen dimensions, includes sources and uncertainty, distinguishes preview/marketing from documentation, and supplies prioritized measurable hypotheses. Documentary coverage is not feature validation.

Before publishing comparative claims: use exact SKUs and dates; resolve source conflicts; conduct authorized trials on equivalent workloads; preserve raw results and model versions; publish sample sizes and uncertainty; independently review conclusions. A vendor's undocumented feature remains U, not “No.”

## Outstanding questions

Which customer workflow justifies switching or adding a tool? Is the bounded remote catalog valuable enough? What are actual provider contracts and APIs? Which private deployment buyers need an entirely local management plane? Can VULNEX maintain detection content economically? Do trial results show a meaningful advantage after onboarding costs? These require founder decisions and primary customer/procurement work.

## Final recommendation

**APPROVED WITH CONDITIONS:** pursue measurable operational trust and constrained deployment usability. **REJECTED:** claims that incumbents lack evidence, remediation verification, private scanners or provider support as a class. Five candidate advantages and test gates are specified in MARKET_OPPORTUNITIES.md; none is yet proven.

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
