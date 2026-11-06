# VULNEX Competitor Feature Matrix

Research date: 2026-11-06 | Documentary comparison, not a tested scorecard

Author: Claude Opus 5.5 (initial author, as recorded by the founder on 2026-11-06). Independent review and verification by Astra 6: **pending**.

**Verdict: APPROVED WITH CONDITIONS.** Read product scope and evidence labels before comparing cells. Each linked source supports the bounded statement beside it, not a universal capability across that vendor's portfolio.

**D** = operationally documented; **M** = vendor product/marketing claim; **P** = preview; **I** = individual user report; **U** = not established. D does not mean independently executed. U is not “No.” License and platform qualifications apply. Full source methodology: [RESEARCH_SOURCES.md](RESEARCH_SOURCES.md).

## 1–9: Product and operational capabilities

| Dimension                 | Tenable                                                                 | Qualys                                                                      | Rapid7                                                            | Greenbone                                                                   | Microsoft Defender VM                                                                         | Wiz                                                                                                  |
| ------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| 1. Positioning            | D: VM, local Security Center and wider One suite are distinct [T3][T3]  | D: inventory-to-remediation VMDR; package dependent [Q2][Q2]                | D: console/engine VM with cloud workflows [R1][R1]                | D: commercial appliances, community and cloud offerings [G1][G1] [G10][G10] | D: Defender-integrated endpoint VM [M1][M1]                                                   | M: unified cloud/code/on-prem exposure offering [W1][W1]                                             |
| 2. Scanning               | D: network discovery, assessment and agents [T1][T1]                    | D: QID-driven network scans and sensors [Q1][Q1] [Q2][Q2]                   | D: engines plus endpoint collection [R1][R1] [R5][R5]             | D: network scanning; P: agents in GOS 25 [G1][G1] [G4][G4]                  | D: endpoint assessment plus supported network-device scanning [M1][M1] [M3][M3]               | M: agentless workload scans, sensor and third-party aggregation [W1][W1]                             |
| 3. Inventory              | D: assessed-asset identity/counting [T7][T7]                            | D: multi-sensor inventory and attributes [Q2][Q2]                           | D: asset records and API export [R6][R6]                          | D: asset-management workflow in appliance manual [G2][G2]                   | D: device/software inventories [M1][M1]                                                       | M: graph-oriented inventory/context [W1][W1]                                                         |
| 4. Intelligence           | D: plugin/risk metadata and threat drivers [T5][T5] [T6][T6]            | D: detection/QDS and TruRisk context [Q6][Q6] [Q3][Q3]                      | D: CVSS plus exploitation/threat sources [R3][R3]                 | D: feed-driven vulnerability tests; feed rights differ [G3][G3] [G8][G8]    | D: CVE/recommendation context; filtering exceptions [M1][M1] [M2][M2]                         | M: vulnerability catalog and continuous reassessment announcement [W7][W7]                           |
| 5. Detection approach     | D: plugin-based remote/credentialed/agent modes [T1][T1] [T4][T4]       | D: configured QIDs and credentialed probes [Q1][Q1]                         | D: scan/endpoint observations with proof fields [R5][R5] [R6][R6] | D: VTs and QoD; P: SBOM agent flow [G2][G2] [G4][G4]                        | D: collected device/software data and network assessment [M1][M1] [M3][M3]                    | M: workload collection plus contextual correlation; not proof every issue is exploit-tested [W1][W1] |
| 6. Authenticated scanning | D: Windows/SSH credentials [T1][T1]                                     | D: scanner authentication supported [Q1][Q1]                                | D: authenticated assessment/Scan Assistant [R5][R5]               | D: credentialed internal checks [G1][G1]                                    | D: network devices; Windows remote authenticated feature removed 2025-12-18 [M2][M2] [M3][M3] | M: cloud-authorized access; U: equivalent general Windows/SSH scanner [W1][W1]                       |
| 7. Reporting              | D: Security Center report/template ecosystem; exact SKU verify [T8][T8] | D: dashboards/prioritization reports [Q2][Q2]                               | D: console reports and remediation views [R1][R1] [R2][R2]        | D: historical reports and export formats [G2][G2]                           | D: dashboard and remediation CSV [M4][M4] [M5][M5]                                            | M/I: reporting offered and described by users; exact export scope U [W1][W1] [I4][I4]                |
| 8. Remediation            | D: targeted verification; this scan path excludes agents [T2][T2]       | D: VMDR workflow; ETM source-rescan validation separately [Q2][Q2] [Q7][Q7] | D: projects, assignment and verification states [R2][R2]          | D: model-dependent tickets/report workflows; test chosen model [G2][G2]     | D: requests/tracking/Intune integration [M4][M4]                                              | M: contextual remediation and integrations; precise closure contract U [W1][W1] [W6][W6]             |
| 9. API/integrations       | D: scan management API [T1][T1]                                         | D: Host Detection API, ServiceNow workflow [Q6][Q6] [Q2][Q2]                | D: v4 asset/finding integration API [R6][R6]                      | D: authenticated XML GMP [G5][G5]                                           | D: machine/software/vulnerability APIs [M1][M1]                                               | M: integration catalog; authenticated API contract not reviewed [W6][W6]                             |

## 10–15: Deployment, commercial and limitation matrix

“Self-hosted” below means a customer-operated management/control plane, not just a locally installed sensor. “Hybrid” identifies a split collection/management pattern, not certified data sovereignty.

| Dimension                 | Tenable                                                                                                      | Qualys                                                                                 | Rapid7                                                                                     | Greenbone                                                                                     | Microsoft Defender VM                                                           | Wiz                                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 10. SaaS                  | D: hosted VM and cloud scan path [T2][T2]                                                                    | D: cloud VMDR [Q2][Q2]                                                                 | D: cloud components; vendor-hosted Managed VM separately [R8][R8]                          | D: Greenbone Cloud Service [G6][G6]                                                           | D: Defender cloud tenant [M1][M1]                                               | M: standard SaaS described in Outpost listing [W2][W2]                                              |
| 11. Self-hosted           | D: Security Center console [T3][T3]                                                                          | M: Private Cloud offered; configuration/eligibility confirm [Q4][Q4]                   | D: local console/engines; cloud features not assumed offline [R1][R1]                      | D: appliances/community stack [G1][G1] [G10][G10]                                             | U: no full local control plane established [M1][M1]                             | U: Outpost establishes local scanning only [W2][W2]                                                 |
| 12. Hybrid                | D: hosted VM plus on-prem Nessus [T2][T2]                                                                    | D: cloud with local sensors [Q2][Q2]                                                   | D: local console/engines plus cloud workflow [R1][R1] [R2][R2]                             | D: cloud service supports internal scanning [G6][G6]                                          | D: local collection/network scanner plus cloud management [M3][M3]              | M: Outpost customer-infrastructure workload scanning; confirm exact data flows [W2][W2]             |
| 13. MSSP                  | D: MSSP terms and Director multi-instance management [T3][T3]                                                | M: dedicated partner offering [Q5][Q5]                                                 | D: multi-tenant API documented in GovCloud; broader entitlement U [R9][R9]                 | D: service-provider customer billing [G7][G7]                                                 | D: cross-tenant exposure dashboard [M5][M5]                                     | M: Tenant Manager; P: announced MSP program [W3][W3] [W4][W4]                                       |
| 14. Licensing model       | D: assessed assets and product-specific counting [T7][T7]                                                    | M: asset-oriented historical packaging; current bundle/quote confirm [Q8][Q8] [Q3][Q3] | M: per-asset advertised volume pricing [R7][R7]                                            | D: component/feed licenses plus commercial products; transition needs quote [G8][G8] [G9][G9] | D: user-based standalone/add-on; core and server plans differ [M6][M6] [M2][M2] | M: quoted One/Go/a la carte; universal unit U [W5][W5]                                              |
| 15. Limits / pain signals | D: custom-plugin and remediation-mode restrictions; I: reports/packaging friction [T4][T4] [T2][T2] [I1][I1] | D: optional unreachable-host closure; I: UX/connector requests [Q1][Q1] [I2][I2]       | D: historical Active Risk recalculation limitation; I: workflow friction [R3][R3] [I3][I3] | D: identification/login/feed gaps; host scanning not full DAST [G3][G3] [G6][G6]              | D: Windows scan removal and specified CVE filtering [M2][M2]                    | U: control-plane hosting/closure specifics; I: older exception/reporting requests [W2][W2] [I4][I4] |

## Interpretation controls

- Do not score blank or U cells as competitor failures.
- Reporting/API existence does not establish completeness, performance or usability.
- A managed service is not automatically an ordinary SaaS SKU, and provider API support does not certify tenant isolation.
- External/network, credentialed host, agent and snapshot checks have different visibility. Compare common supported workloads and disclose excluded ones.
- Marketing references to AI, continuous detection or risk reduction are not independent measurements.
- All six vendors require edition-aware procurement. No uniform price/per-asset comparison is supported by these sources.
- Evidence for pain-point prevalence is insufficient. Individual reviews establish interview questions, not universal product defects.
- No inference of VULNEX capability follows from its PRD. VULNEX remains a proposed product baseline, not a benchmarked seventh vendor.

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
[T8]: https://docs.tenable.com/security-center/Content/ConfigurationSettings.htm 'Tenable feed configuration'
