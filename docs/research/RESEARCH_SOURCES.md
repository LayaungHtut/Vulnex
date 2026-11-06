# VULNEX Research Sources

Research date: 2026-11-06. Scope: public-source desk research for TASK 002. No vendor trials, authorized scans, customer interviews, private documentation or negotiated quotes were obtained.

Author: Claude Opus 5.5 (initial author, as recorded by the founder on 2026-11-06). Independent review and verification by Astra 6: **pending**.

## Evidence method

- **D — documented:** primary operational documentation or explicit release/license documentation. Verified here means verified in a public source, not tested in software.
- **M — vendor claim:** product page, commercial announcement or vendor-authored marketplace listing. Verifies what is offered or claimed, not effectiveness.
- **P — preview:** explicitly announced preview; not assumed generally available.
- **I — independent user report:** third-party review platform, or separately labeled practitioner post. Evidence of that person's experience only.
- **U — unresolved:** insufficient public evidence. Never interpret U as absence.
- **H — hypothesis/inference:** VULNEX analysis requiring validation.

All sources below were retrieved or surfaced with substantive text by web search/open on the research date. Some were available as indexed extracts rather than complete page reads; this is not a downloaded archive. Dates are stated only where retrieved text provides them. Undated live documentation is mutable. Research used primary sources for technical claims; independent reviews only inform customer-experience hypotheses. No review scores or anecdotes establish accuracy, market share or superiority.

## Source register

| ID  | Class | Source                                                                                                                                                           | Supports / caveat                                                                                    |
| --- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| T1  | D     | [Tenable: scan API](https://developer.tenable.com/docs/manage-scans)                                                                                             | Scan types, credentials, agents and automation.                                                      |
| T2  | D     | [Tenable: remediation scans](https://developer.tenable.com/docs/manage-remediation-scans)                                                                        | Targeted verification; agent-scan restriction.                                                       |
| T3  | D     | [Tenable: Security Center licensing](https://docs.tenable.com/quick-reference/licensing-guide/Content/tenable-security-center-licensing.htm)                     | Asset licensing, local console and Director; SKU qualifications.                                     |
| T4  | D     | [Tenable: custom NASL packages](https://docs.tenable.com/security-center/Content/CustomPlugins.htm)                                                              | Custom checks; managed versus linked scanner and support restrictions.                               |
| T5  | D     | [Tenable: current risk metrics](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/RiskMetrics.htm)                                      | VPR drivers; global rather than organization-specific context.                                       |
| T6  | D     | [Tenable: finding details](https://docs.tenable.com/vulnerability-management/Content/Explore/findings-details-vulnerabilities.htm)                               | Finding metadata and risk context.                                                                   |
| T7  | D     | [Tenable: One licensing](https://docs.tenable.com/quick-reference/licensing-guide/Content/t1-foundation-advanced-licensing.htm)                                  | Cross-product counting and reclamation; not a negotiated quote.                                      |
| T8  | D     | [Tenable: feed configuration](https://docs.tenable.com/security-center/Content/ConfigurationSettings.htm)                                                        | Report, dashboard, policy and asset template distribution.                                           |
| Q1  | D     | [Qualys: scan options](https://docs.qualys.com/en/vmdr/latest/option_profiles/op_scan_tab.htm)                                                                   | Authentication and conditional closure behavior.                                                     |
| Q2  | D     | [Qualys: VMDR getting started](https://docs.qualys.com/en/vmdr/latest/mergedProjects/search_in_vmdr/get_started/get_started.htm)                                 | Inventory, sensors, dashboards and subscription-dependent workflows.                                 |
| Q3  | D     | [Qualys: TruRisk packages](https://docs.qualys.com/en/vmdr/getting-started-guide/features_of_vmdr/qualys_trurisk.htm)                                            | Packaged prioritization/remediation; confirm entitlement.                                            |
| Q4  | M     | [Qualys: Private Cloud](https://www.qualys.com/private-cloud)                                                                                                    | Vendor-offered private platform; no independent installation test.                                   |
| Q5  | M     | [Qualys: MSP/MSSP program](https://www.qualys.com/partners/mssp)                                                                                                 | Partner offering and commercial program, not isolation audit.                                        |
| Q6  | D     | [Qualys: Host Detection API](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm)                                | Detection retrieval and QDS; API evidence.                                                           |
| Q7  | D     | [Qualys: ETM remediation validation](https://docs.qualys.com/en/etm/latest/responses/remediation_validation.htm)                                                 | Source rescan updates; ETM is not automatically included in VMDR.                                    |
| Q8  | M     | [Qualys: VMDR commercial announcement](https://investor.qualys.com/news-releases/news-release-details/qualys-brings-its-market-leading-vulnerability-management) | Historical asset-pricing model; current quote must supersede it.                                     |
| R1  | D     | [Rapid7: deployment planning](https://docs.rapid7.com/insightvm/planning-a-deployment/)                                                                          | Console/engine local deployment and reporting.                                                       |
| R2  | D     | [Rapid7: remediation projects](https://docs.rapid7.com/insightvm/remediation-workflow/)                                                                          | Assignment, verification and closure lifecycle.                                                      |
| R3  | D     | [Rapid7: Active Risk](https://docs.rapid7.com/insightvm/working-with-risk-strategies-to-analyze-threats/)                                                        | Current risk model and historical recalculation limit.                                               |
| R4  | D     | [Rapid7: risk strategy deprecation](https://docs.rapid7.com/insightvm/legacy-risk-strategies-end-of-life-announcement/)                                          | January 21, 2026 transition; avoid outdated RealRisk comparisons.                                    |
| R5  | D     | [Rapid7: Scan Assistant](https://docs.rapid7.com/insightvm/scan-assistant-combined/)                                                                             | Authenticated collection and agent/assistant distinction.                                            |
| R6  | D     | [Rapid7: v4 integration API](https://help.rapid7.com/insightvm/en-us/api/integrations.html)                                                                      | Asset/finding exports, proof and remediation fields.                                                 |
| R7  | M     | [Rapid7: pricing](https://www.rapid7.com/pricing/)                                                                                                               | Asset-based advertised pricing; contract and volume qualifications.                                  |
| R8  | D     | [Rapid7: Managed VM scope](https://www.rapid7.com/globalassets/docs/managedservices/mvm-scope-of-service.pdf)                                                    | Vendor-hosted managed console and integration limits.                                                |
| R9  | D     | [Rapid7: InsightGovCloud secure configuration](https://documentation.rapid7.com/insightgovcloud/secure-config-guide.htm)                                         | Multi-tenant API credentials in this documented environment; do not generalize SKU availability.     |
| G1  | D     | [Greenbone: OPENVAS SCAN introduction](https://docs.greenbone.net/GSM-Manual/gos-25.0/en/introduction.html)                                                      | Network/authenticated scanning; master-sensor and air-gap concepts.                                  |
| G2  | D     | [Greenbone: reports](https://docs.greenbone.net/GSM-Manual/gos-25.0/en/reports.html)                                                                             | Evidence/QoD, report formats and model-dependent functionality.                                      |
| G3  | D     | [Greenbone: FAQ](https://docs.greenbone.net/GSM-Manual/gos-25.0/en/faq.html)                                                                                     | Documented missed-detection and performance causes.                                                  |
| G4  | D     | [Greenbone: agent scans](https://docs.greenbone.net/GSM-Manual/gos-25.0/en/agents.html)                                                                          | Technology preview, SBOM collection and assessment flow.                                             |
| G5  | D     | [Greenbone: GMP](https://docs.greenbone.net/GSM-Manual/gos-25.0/en/gmp.html)                                                                                     | XML API, authentication and role restrictions.                                                       |
| G6  | D     | [Greenbone: Cloud Service introduction](https://docs.greenbone.net/GCS-Manual/gcs/en/introduction.html)                                                          | Hosted external/internal scanning, subscription and web-scanning boundary.                           |
| G7  | D     | [Greenbone: service-provider billing](https://docs.greenbone.net/GCS-Manual/gcs-msp/en/billing-overview.html)                                                    | Provider/end-customer commercial administration.                                                     |
| G8  | D     | [Greenbone: license information](https://www.greenbone.net/en/license-information/)                                                                              | Component/feed license distinctions; enterprise feed key restrictions.                               |
| G9  | D     | [Greenbone: GOS 25 release announcement](https://forum.greenbone.net/t/greenbone-os-25-0-0-released/22164)                                                       | March 18, 2026 model transition announcement; asset-based licensing future wording.                  |
| G10 | D     | [Greenbone: Community FAQ](https://greenbone.github.io/docs/latest/faq.html)                                                                                     | Community source distribution and support route.                                                     |
| M1  | D     | [Microsoft: VM overview](https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/defender-vulnerability-management)           | Inventory, recommendations, APIs and privacy linkage; deprecation FAQ overrides stale feature lists. |
| M2  | D     | [Microsoft: VM FAQ](https://learn.microsoft.com/en-us/defender-vulnerability-management/defender-vulnerability-management-faq)                                   | Windows scan removal on December 18, 2025; filtering and plan caveats.                               |
| M3  | D     | [Microsoft: network scanning setup](https://learn.microsoft.com/en-us/defender-endpoint/network-devices)                                                         | Supported network-infrastructure authenticated scanning remains distinct.                            |
| M4  | D     | [Microsoft: remediation](https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-remediation)                                                    | Requests, Intune connection, CSV and retention.                                                      |
| M5  | D     | [Microsoft: multi-tenant VM dashboard](https://learn.microsoft.com/en-us/defender-xdr/mto-dashboard)                                                             | Aggregated tenant exposure and navigation.                                                           |
| M6  | D     | [Microsoft: prerequisites and licenses](https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-prerequisites)                                   | Per-user licensing, add-on/standalone and permissions.                                               |
| W1  | M     | [Wiz: unified vulnerability management](https://www.wiz.io/solutions/vulnerability-management)                                                                   | Current cloud/code/on-prem positioning and sensor/aggregation claims.                                |
| W2  | M     | [Wiz for Gov: Outpost listing](https://aws.amazon.com/marketplace/pp/prodview-f5su6hitnszcu)                                                                     | Vendor-authored listing for customer-infrastructure scanning, not proof of local control plane.      |
| W3  | M     | [Wiz: Tenant Manager](https://www.wiz.io/blog/wiz-tenant-manager-multi-tenant-security)                                                                          | March 6, 2026 announcement; aggregation and delegated administration claims.                         |
| W4  | P     | [Wiz: managed-service program](https://www.wiz.io/blog/introducing-wiz-partner-alliance-managed-service-provider-program)                                        | 2026 announcement explicitly describes public preview.                                               |
| W5  | M     | [Wiz: pricing](https://www.wiz.io/pricing)                                                                                                                       | Wiz One, Wiz Go and a la carte custom-quote offering; unit price not disclosed.                      |
| W6  | M     | [Wiz: integrations](https://www.wiz.io/integrations)                                                                                                             | Published integration catalog, not validated connector reliability.                                  |
| W7  | M     | [Wiz: continuous vulnerability assessment](https://www.wiz.io/blog/introducing-cva)                                                                              | September 1, 2026 reassessment announcement; latency claim not benchmarked.                          |
| W8  | M     | [Wiz: AI vulnerability management](https://www.wiz.io/academy/vulnerability-management/ai-vulnerability-management)                                              | Vendor claims about AI investigation and validation; not independent efficacy evidence.              |
| I1  | I     | [TrustRadius: Tenable VM reviews](https://www.trustradius.com/products/tenable-vulnerability-management/reviews)                                                 | Individual UX/reporting/licensing experiences; some incentivized/reseller reviews.                   |
| I2  | I     | [TrustRadius: Qualys VMDR reviews](https://www.trustradius.com/products/qualys-vmdr/reviews)                                                                     | Conflicting value opinions and UI/integration requests; dated, nonrepresentative samples.            |
| I3  | I     | [TrustRadius: Rapid7 InsightVM reviews](https://www.trustradius.com/products/rapid7-insightvm/reviews)                                                           | 2024 reviewers praise proof/remediation and request UX/reporting improvements.                       |
| I4  | I     | [TrustRadius: Wiz reviews](https://www.trustradius.com/products/wiz/reviews)                                                                                     | 2025 experiences; newer releases may supersede reported limitations.                                 |
| I5  | I     | [Rapid7 community: remediation synchronization](https://discuss.rapid7.com/t/remediation-project-update-sync-interval-with-security-console/44460)               | User-reported delay, vendor-hosted forum; unverified and not a current SLA.                          |

## Conflict resolution and freshness

1. Microsoft's dated deprecation FAQ overrides overview/datasheet references to Windows authenticated scanning. Network-device authenticated scanning is a different capability. [Microsoft FAQ][M2] [Network setup][M3]
2. Rapid7's current model is Active Risk; older RealRisk descriptions are historical. [Risk transition][R4]
3. Greenbone agent scanning is a technology preview in the retrieved GOS 25 manual; do not label all editions agent-capable or say Greenbone has no agent approach. Appliance feature matrices are model dependent. [Agent manual][G4]
4. Wiz's current positioning includes on-premises aggregation and Sensor Workload scanning; older cloud-only comparisons are inadequate. An Outpost scanner is not evidence of a customer-operated full platform. [UVM][W1] [Outpost][W2]
5. Wiz's MSP program announcement says public preview. Tenant Manager functionality claims do not establish commercial availability for every customer. [MSP announcement][W4]
6. Greenbone's March 2026 announcement uses prospective language for asset licensing. Obtain the exact model/order terms; do not assign a universal historic appliance license or assume conversion is complete. [Release][G9]

## Excluded or insufficient evidence

Generic SEO comparisons, unrelated Outpost products, affiliate price estimates and unrelated Defender XDR reviews were not used as technical evidence. A search for direct Greenbone and Microsoft VM customer-review evidence did not produce a sufficiently specific, current sample for defensible complaint prevalence; those vendors' limitations rely on documentation and clearly labeled inferences. TrustRadius is commercially operated, some reviews are incentivized, and product pages may blend editions. The Rapid7 forum is vendor-hosted, not independent validation. Vendor customer quotations are marketing, not independent research.

No controlled six-vendor accuracy/performance benchmark was found and assessed in this work. No claim is made about comparative false-positive rates, recall, throughput, TCO or breach reduction. Procurement must confirm API quotas, supported systems, current SKUs, reseller rights, data residency, feature maturity and redistribution terms.

## Revalidation plan

Recheck dated changes and pricing at procurement; recheck all source-dependent competitive claims before publishing sales collateral. Preserve dated page/PDF snapshots in the next procurement phase, where permitted. Require an exact edition, version, configuration, source and evidence class for every future matrix change. Conduct trials against a shared authorized corpus before promoting H or M into a measured advantage.

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
