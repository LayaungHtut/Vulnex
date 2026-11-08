# Security Policy

VULNEX is pre-release software in private development. There is no public release and no supported production version yet.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue.

- Email: _security contact address to be set by the founder before any external distribution_, subject line starting with `[VULNEX SECURITY]`
- Include: affected component and version or commit, steps to reproduce, impact, and any proof-of-concept. Do not include data belonging to anyone but you.

What to expect (best effort while VULNEX is a small team):

- acknowledgement within 5 business days;
- an initial assessment within 15 business days;
- coordinated disclosure: we agree a disclosure date with you once a fix is available. We will credit you unless you prefer otherwise.

## Scope

In scope: code in this repository (control-plane API, console, scanner worker once it exists, deployment files).

Out of scope: findings that need physical access to the operator's machine, social engineering, denial of service by volume, and reports produced only by automated scanners without a demonstrated impact.

## Safe harbour

Good-faith research that respects this policy, avoids privacy violations and service disruption, and only tests systems you own or are authorised to test will not be pursued legally by VULNEX.

## Our own security practices

- Threat model: [docs/security/THREAT_MODEL.md](docs/security/THREAT_MODEL.md)
- Tenant isolation: [ADR-0005](docs/decisions/ADR-0005.md); scanner trust: [ADR-0006](docs/decisions/ADR-0006.md)
- CI runs secret scanning (gitleaks) and dependency audits; Dependabot opens update PRs.
- VULNEX scanners only assess targets inside an explicitly authorised scope, non-intrusively by default.

_Status: PROPOSED. The founder must approve the contact address and response times before any public release._
