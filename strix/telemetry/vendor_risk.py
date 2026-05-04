"""Vendor / supply-chain risk-score derivation (roadmap §16 / PR #133).

B2B customers run Strix against their suppliers — "is this
vendor safe to onboard?". They don't want a generic pentest
report; they want a vendor-risk score suitable for their vendor-
management process.

This module computes a deterministic 0-100 vendor-risk score
from the existing findings + run metadata. No new probes; the
score derives from what the engine already emits.

When `--vendor-mode` is passed, the score lands in
`run_meta.json` under `vendor_risk` and the completion message
calls it out. The agent receives an instruction block telling
it to emphasise vendor-hygiene categories.

Score model (deterministic, version 1)
--------------------------------------

Start at 100. Deduct points by:

  * Per-finding severity:
      critical = 18, high = 10, medium = 4, low = 1, info = 0
  * Vendor-hygiene categories get a category multiplier:
      hardcoded_secret           ×3.0  (top-tier signal)
      jwt_scoping / cookie_scoping ×1.8
      missing_sri                  ×1.5
      vulnerable_dependency       ×1.5
      dns_security                ×1.2
      legal_documents             ×1.0
      monitoring_posture          ×0.8
      mfa_attestation             ×1.5
      cleartext_transmission      ×1.5
      tls_audit / weak_crypto      ×2.0
      everything else              ×1.0

Floor at 0. The score reflects "would I onboard this vendor?"
rather than "is this app vuln-free?". Categories that affect
the customer's data-protection posture weigh higher than
broad-spectrum vulns.

Bands
-----

  * 80-100 — Low risk. Onboard.
  * 60-79  — Medium risk. Conditional onboarding; require
    remediation of high-impact findings.
  * 0-59   — High risk. Don't onboard / re-evaluate.

Why these bands
---------------

The B2B vendor-management workflow is binary at the procurement
gate ("approved / not approved"). Most procurement processes
treat <60 as a hard block. 60-79 is the conditional-approval
range where the security team negotiates remediation before
contract sign. 80+ is a clean approval.

References
----------

* Shared-Assessments SIG questionnaire — vendor-risk scoring
* SOC 2 CC9.0 — supplier-risk management
* ISO 27001 A.15 — supplier relationships
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


# Per-severity raw deductions.
_SEVERITY_DEDUCTIONS = {
    "critical": 18,
    "high": 10,
    "medium": 4,
    "low": 1,
    "info": 0,
}


# Per-category multipliers — categories that affect vendor-trust
# weigh more heavily than broad-spectrum vulns.
_CATEGORY_MULTIPLIERS = {
    "hardcoded_secret": 3.0,
    "jwt_scoping": 1.8,
    "cookie_scoping": 1.8,
    "missing_sri": 1.5,
    "vulnerable_dependency": 1.5,
    "dns_security": 1.2,
    "legal_documents": 1.0,
    "monitoring_posture": 0.8,
    "mfa_attestation": 1.5,
    "cleartext_transmission": 1.5,
    "tls_audit": 2.0,
    "weak_crypto": 2.0,
    "tls_misconfiguration": 2.0,
    "email_security": 1.2,
    "host_header_injection": 1.2,
    # everything else: 1.0 (default)
}


def _deduct_for_finding(finding: dict[str, Any]) -> float:
    severity = (finding.get("severity") or "").strip().lower()
    base = _SEVERITY_DEDUCTIONS.get(severity, 0)
    if base == 0:
        return 0.0

    category = (finding.get("category") or "").strip().lower()
    multiplier = _CATEGORY_MULTIPLIERS.get(category, 1.0)
    return float(base) * multiplier


def _band_for_score(score: int) -> str:
    if score >= 80:
        return "low_risk"
    if score >= 60:
        return "medium_risk"
    return "high_risk"


def _band_label(band: str) -> str:
    return {
        "low_risk": "Low risk — onboard",
        "medium_risk": "Medium risk — conditional onboarding",
        "high_risk": "High risk — do not onboard / re-evaluate",
    }.get(band, "Unknown")


def compute_vendor_risk_score(
    findings: list[dict[str, Any]],
    run_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute the vendor-risk score from a finalized scan.

    Args:
        findings: list of finding records (vulnerabilities.json shape).
        run_metadata: optional run_metadata dict — used for context
            in the breakdown.

    Returns:
        ```
        {
          schema_version: 1,
          score: int,                # 0-100
          band: str,                 # "low_risk" / "medium_risk" / "high_risk"
          band_label: str,           # human-readable
          total_deduction: float,
          deductions_by_category: {<category>: float, ...},
          deductions_by_severity: {<severity>: float, ...},
          counts_by_severity: {<severity>: int, ...},
          counts_by_category: {<category>: int, ...},
          findings_total: int,
          highest_severity_observed: str | None,
          recommendation: str,
        }
        ```
    """
    deductions_by_cat: dict[str, float] = {}
    deductions_by_sev: dict[str, float] = {}
    counts_by_sev: dict[str, int] = {}
    counts_by_cat: dict[str, int] = {}
    total_deduction = 0.0
    highest_sev_rank = -1
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for f in findings or []:
        sev = (f.get("severity") or "").strip().lower()
        cat = (f.get("category") or "uncategorised").strip().lower()
        deduct = _deduct_for_finding(f)

        deductions_by_cat[cat] = deductions_by_cat.get(cat, 0.0) + deduct
        deductions_by_sev[sev] = deductions_by_sev.get(sev, 0.0) + deduct
        counts_by_sev[sev] = counts_by_sev.get(sev, 0) + 1
        counts_by_cat[cat] = counts_by_cat.get(cat, 0) + 1
        total_deduction += deduct

        rank = sev_rank.get(sev, -1)
        if rank > highest_sev_rank:
            highest_sev_rank = rank

    raw_score = 100.0 - total_deduction
    score = max(0, min(100, int(round(raw_score))))
    band = _band_for_score(score)

    highest_sev = (
        next(
            (k for k, v in sev_rank.items() if v == highest_sev_rank),
            None,
        )
        if highest_sev_rank >= 0
        else None
    )

    # Human-readable recommendation.
    if band == "low_risk":
        recommendation = (
            f"Score {score}/100 — onboard. No critical vendor-hygiene "
            f"red flags surfaced."
        )
    elif band == "medium_risk":
        recommendation = (
            f"Score {score}/100 — conditional. Require the vendor to "
            f"remediate the high / critical findings before contract sign."
        )
    else:
        top_cat = max(
            deductions_by_cat.items(), key=lambda kv: kv[1], default=("none", 0)
        )[0]
        recommendation = (
            f"Score {score}/100 — do not onboard pending re-evaluation. "
            f"Top deduction category: {top_cat}."
        )

    return {
        "schema_version": 1,
        "score": score,
        "band": band,
        "band_label": _band_label(band),
        "total_deduction": round(total_deduction, 2),
        "deductions_by_category": {
            k: round(v, 2) for k, v in deductions_by_cat.items()
        },
        "deductions_by_severity": {
            k: round(v, 2) for k, v in deductions_by_sev.items()
        },
        "counts_by_severity": counts_by_sev,
        "counts_by_category": counts_by_cat,
        "findings_total": len(findings or []),
        "highest_severity_observed": highest_sev,
        "recommendation": recommendation,
    }
