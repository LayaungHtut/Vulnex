"""VULNEX priority score, model `risk-v0.1` (PRD §15, PROPOSED; needs an ADR before approval).

    priority = clamp(0, 100, 5*S + E + X + B)

- S: published severity on 0-10 (CVSS base score for CVEs, the check's documented score for
  configuration findings). Missing S uses a visibly provisional 5.
- E: 20 when CISA KEV lists a CVE of the finding (supported evidence of known exploitation),
  otherwise 0. Absence is "unknown", never "not exploited".
- X: exposure. 0 for a private, shared or documentation address (RFC 1918, 100.64/10, ...);
  for a public address internet reachability is not verified, so the provisional 15 applies.
- B: business criticality from the asset: critical 15, high 10, medium 5, low 0.

Bands: urgent >= 80, high >= 60, medium >= 35, low < 35. A KEV-listed finding gets at least
"high". EPSS is shown beside the score, not mixed into it, until a calibrated mapping exists.
Confidence does not change the number; `potential` findings are kept in a separate review queue
instead (PRD §15). Every factor is returned with its value and reason, so the score explains
itself and can be replayed.
"""

from ipaddress import IPv4Address, ip_address
from typing import Any

MODEL = "risk-v0.1"
CRITICALITY = {"critical": 15, "high": 10, "medium": 5, "low": 0}
BANDS = ((80, "urgent"), (60, "high"), (35, "medium"), (0, "low"))


def _exposure(address: str | None) -> tuple[int, str, bool]:
    if address is None:
        return 15, "address unknown; provisional exposure", True
    try:
        addr = ip_address(address)
    except ValueError:
        return 15, "address unreadable; provisional exposure", True
    if isinstance(addr, IPv4Address) and addr.is_global:
        return 15, "public address; internet reachability not verified (provisional)", True
    return 0, "private or non-routable address", False


def score(
    *,
    severity: float | None,
    severity_source: str,
    kev: bool,
    epss: float | None,
    address: str | None,
    criticality: str,
) -> dict[str, Any]:
    s_value = 5.0 if severity is None else max(0.0, min(10.0, float(severity)))
    e_value = 20 if kev else 0
    x_value, x_reason, x_provisional = _exposure(address)
    b_value = CRITICALITY.get(criticality, 10)
    total = max(0, min(100, round(5 * s_value + e_value + x_value + b_value)))
    band = next(name for floor, name in BANDS if total >= floor)
    if kev and band in ("medium", "low"):
        band = "high"
    factors = [
        {
            "factor": "severity",
            "value": s_value,
            "contribution": round(5 * s_value, 1),
            "source": severity_source if severity is not None else "missing",
            "provisional": severity is None,
        },
        {
            "factor": "known_exploited",
            "value": kev,
            "contribution": e_value,
            "source": "CISA KEV" if kev else "not listed in CISA KEV (unknown, not proof)",
            "provisional": False,
        },
        {
            "factor": "exposure",
            "value": address,
            "contribution": x_value,
            "source": x_reason,
            "provisional": x_provisional,
        },
        {
            "factor": "business_criticality",
            "value": criticality,
            "contribution": b_value,
            "source": "asset criticality",
            "provisional": criticality not in CRITICALITY,
        },
    ]
    return {
        "model": MODEL,
        "score": total,
        "band": band,
        "factors": factors,
        "epss": epss,
        "note": "EPSS is shown for context and is not part of the score (PRD §15).",
    }
