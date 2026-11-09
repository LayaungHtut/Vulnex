# VULNEX

Evidence-backed vulnerability assessment and management platform. The first products are **VULNEX SCAN** (authorized discovery, detection, evidence, remediation verification) and **VULNEX INTELLIGENCE** (vulnerability data with provenance, correlation and prioritization inputs).

**Status: Phase 0 (product and technical discovery) is complete and awaiting review. No product code exists yet.** The repository holds a SvelteKit scaffold and the foundation documents. See [PROJECT_STATE.md](PROJECT_STATE.md).

## Documents

| Document                                                                                                          | Status                   |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------ |
| [Product Requirements](docs/product/PRD.md)                                                                       | PROPOSED                 |
| [Roadmap](docs/product/ROADMAP.md)                                                                                | PROPOSED                 |
| [Initial Architecture](docs/architecture/INITIAL_ARCHITECTURE.md)                                                 | PROPOSED                 |
| [Threat Model](docs/security/THREAT_MODEL.md)                                                                     | PROPOSED                 |
| [ADR-0001: modular monolith + separate workers](docs/decisions/ADR-0001.md)                                       | PROPOSED                 |
| [Research plan](docs/research/RESEARCH_PLAN.md) and [competitive research](docs/research/COMPETITIVE_ANALYSIS.md) | PROPOSED / desk research |
| [Definition of Done](DEFINITION_OF_DONE.md)                                                                       | PROPOSED                 |
| [Workflow and roles](docs/WORKFLOW.md)                                                                            | In use                   |

## Develop (current scaffold)

Requires Node 24 and npm.

```sh
npm install
npm run dev        # dev server
npm run check      # type check
npm run lint       # prettier + eslint (currently fails on pre-existing formatting, see PROJECT_STATE.md)
npm run test:unit  # vitest
npm run test       # unit + e2e
```

## Scanning safety

VULNEX scans only targets inside an explicitly authorized scope. Default behaviour is non-intrusive. Only test against systems you own or are authorized in writing to assess.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
