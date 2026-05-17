"""Per-finding compliance + GRC decoration (roadmap §16).

Auto-decorates findings with the controls they implicate across
the frameworks Strix knows about (SOC 2 / ISO 27001:2022 / PCI
DSS 4.0 / OWASP ASVS 4.0 / HIPAA Security Rule / OWASP Top 10 /
GDPR / NIST 800-53 / CIS) and tags each finding with a
`data_classification` (`pii`, `phi`, `pci`, `credentials`,
`internal`, `confidential`, `restricted`, `public`) so auditors
+ GRC platforms can consume findings by control instead of by
CWE.

The CWE → control mapping data lives in
`strix.compliance.mappings` — this module is a thin per-finding
decorator that calls `controls_for_by_framework()` and grafts
the result onto the finding dict. Run-level aggregate evidence
(`compliance_evidence.json`) reads from the same map via
`strix.compliance.evidence`. ONE source of truth for both
output paths.

Hook into `Tracer.add_vulnerability_report` runs alongside the
existing threat-intel decoration.

Wrapper-facing rendering: when set, `compliance_controls` lets
the wrapper render a "this finding implicates SOC 2 CC6.1 + PCI
6.5.1" panel under each finding. `data_classification` drives
the GDPR / HIPAA breach-reporting flag.

Run-level `compliance_posture` block on `run_summary.json`:
- `days_since_last_scan` (read from prior run-meta when present)
- `cadence_required` (configurable via `STRIX_SCAN_CADENCE_DAYS`,
  default 90 — quarterly)
- `cadence_status` (`in_compliance` / `overdue`)
- `audit_log_retention_days` — Strix's own audit-log retention
  contract (default 90 unless `STRIX_AUDIT_LOG_RETENTION_DAYS`
  env)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from strix.compliance.mappings import (
    CATEGORY_TO_CONTROLS,
    CWE_TO_CONTROLS,
    RULE_ID_TO_CONTROLS,
    controls_for_by_framework,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classification inference
# ---------------------------------------------------------------------------


# Each entry: (regex, classification). The first match wins.
_DATA_CLASSIFICATION_RULES: list[tuple[re.Pattern[str], str]] = [
    # Credentials — exposed secrets, weak session IDs, JWT misconfig.
    # Note: Python regex `\b` treats `_` as a word character, so we
    # match against snake_case category strings directly without
    # word-boundary anchors on the keyword side.
    (re.compile(
        r"(?:secret|credential|token|api_?key|password|jwt|oauth|"
        r"exposed_secret|weak_session_id|session_entropy|session_id|"
        r"auth_attack|auth_bypass|auth_flaw|authn|authentication_)",
        re.IGNORECASE,
    ), "credentials"),
    # PCI — card data, payment
    (re.compile(
        r"(?:pci|card_?number|card_?data|cardholder|payment|cvv|"
        r"\bpan\b)",
        re.IGNORECASE,
    ), "pci"),
    # PHI — medical, health
    (re.compile(
        r"(?:phi|hipaa|health|medical|patient|hl7|fhir)",
        re.IGNORECASE,
    ), "phi"),
    # PII — generic personal info
    (re.compile(
        r"(?:\bpii\b|personal_data|gdpr|email|phone|ssn|address)",
        re.IGNORECASE,
    ), "pii"),
    # Information disclosure → internal data
    (re.compile(
        r"(?:information_disclosure|info_disclosure|\bleak)",
        re.IGNORECASE,
    ), "internal"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich_finding_with_compliance(report: dict[str, Any]) -> dict[str, Any]:
    """Add `compliance_controls` + `data_classification` fields based
    on the report's CWE / category / target.

    Returns a SHALLOW dict of fields to merge onto the report. Pure
    function — never raises.
    """
    out: dict[str, Any] = {}

    # ---- compliance_controls ----
    # Read from the canonical CWE / category / rule_id mappings in
    # `strix.compliance.mappings`. We attach a value when ANY of
    # the three is recognised — emitting `{}` would mislead
    # wrappers into thinking the finding has been classified.
    #
    # `rule_id` is what surfaces CIS Benchmark depth: an IaC
    # finding with `rule_id=K8S_PRIVILEGED_CONTAINER` evidences
    # CIS Kubernetes 5.2.1 + CIS Docker 5.4 even though its CWE
    # (CWE-732) wouldn't pinpoint either. The wrapper reads rule_id
    # from the report top-level OR from `metadata.rule_id` (IaC
    # findings stash it there) so the compliance overlay works
    # regardless of which emit path produced the finding.
    cwe = (report.get("cwe") or "").strip().upper()
    category = (report.get("category") or "").strip().lower()
    rule_id = report.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        meta = report.get("metadata")
        if isinstance(meta, dict):
            rid_meta = meta.get("rule_id")
            if isinstance(rid_meta, str) and rid_meta.strip():
                rule_id = rid_meta.strip()
    if isinstance(rule_id, str):
        rule_id = rule_id.strip() or None

    if (
        (cwe and cwe in CWE_TO_CONTROLS)
        or (category and category in CATEGORY_TO_CONTROLS)
        or (rule_id and rule_id in RULE_ID_TO_CONTROLS)
    ):
        out["compliance_controls"] = controls_for_by_framework(
            cwe=cwe or None,
            category=category or None,
            rule_id=rule_id,
        )

    # ---- data_classification ----
    # Build a search string from category, title, description.
    search_haystack_parts = []
    for k in ("category", "title", "description", "description_plain"):
        v = report.get(k)
        if isinstance(v, str):
            search_haystack_parts.append(v)
    haystack = " ".join(search_haystack_parts)
    classification: str | None = None
    if haystack:
        for pattern, label in _DATA_CLASSIFICATION_RULES:
            if pattern.search(haystack):
                classification = label
                break
    if classification is None:
        # Default: confidential if it has any sensitive-shaped content
        # (CVE / exposed-secret / etc.) else internal.
        if report.get("cve"):
            classification = "confidential"
        else:
            classification = "internal"
    out["data_classification"] = classification

    return out


def build_compliance_posture(
    *,
    audit_log_retention_days: int | None = None,
    cadence_required_days: int | None = None,
    days_since_last_scan: int | None = None,
) -> dict[str, Any]:
    """Build the run-level `compliance_posture` block.

    Args:
        audit_log_retention_days: defaults to `STRIX_AUDIT_LOG_RETENTION_DAYS`
            env (or 90 when unset).
        cadence_required_days: defaults to `STRIX_SCAN_CADENCE_DAYS` env
            (or 90 — quarterly when unset).
        days_since_last_scan: caller-supplied. When None, the wrapper
            should compute from prior `run_meta.json` files. We default
            to None here.

    Returns:
        {
          audit_log_retention_days, cadence_required_days,
          days_since_last_scan?, cadence_status?
        }

        `cadence_status` is `in_compliance` when
        `days_since_last_scan <= cadence_required_days`, else `overdue`.
    """
    if audit_log_retention_days is None:
        try:
            audit_log_retention_days = int(
                os.environ.get("STRIX_AUDIT_LOG_RETENTION_DAYS", "90")
            )
        except ValueError:
            audit_log_retention_days = 90
    if cadence_required_days is None:
        try:
            cadence_required_days = int(
                os.environ.get("STRIX_SCAN_CADENCE_DAYS", "90")
            )
        except ValueError:
            cadence_required_days = 90

    posture: dict[str, Any] = {
        "audit_log_retention_days": max(1, int(audit_log_retention_days)),
        "cadence_required_days": max(1, int(cadence_required_days)),
    }
    if days_since_last_scan is not None:
        try:
            d = int(days_since_last_scan)
            posture["days_since_last_scan"] = max(0, d)
            posture["cadence_status"] = (
                "in_compliance" if d <= posture["cadence_required_days"]
                else "overdue"
            )
        except (TypeError, ValueError):
            pass
    return posture


def list_known_cwes() -> list[str]:
    """Return sorted list of CWEs the canonical map covers — used for
    introspection / docs."""
    return sorted(CWE_TO_CONTROLS.keys())
