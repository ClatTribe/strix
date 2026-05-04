"""Compliance / GRC enrichment (roadmap §16).

Auto-decorates findings with the controls they implicate across
major frameworks — SOC 2 Trust Service Criteria, PCI-DSS v4,
HIPAA Security Rule, GDPR Art. 32, ISO 27001 Annex A,
NIST 800-53, OWASP Top 10, CIS Controls v8 — and tags each
finding with a `data_classification` (`pii`, `phi`, `pci`,
`credentials`, `internal`, `confidential`, `restricted`,
`public`) so auditors / GRC platforms can consume findings by
control instead of by CWE.

Mirrors the existing `threat_intel.enrich(...)` shape — pure
static map (CWE → controls), no I/O, fail-open. Hook into
`Tracer.add_vulnerability_report` runs alongside the existing
threat-intel decoration.

Wrapper-facing rendering: when set, `compliance_controls` lets
the wrapper render a "this finding implicates SOC 2 CC6.6 + PCI
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


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Static CWE → control mappings
# ---------------------------------------------------------------------------


# Each entry: per-CWE map of framework → list of control IDs.
# When a finding's CWE matches, all listed controls are attached
# under `compliance_controls`. Frameworks: soc2 (TSC), pci_dss
# (v4), hipaa (Security Rule), gdpr (Art. 32 etc.), iso_27001
# (Annex A), nist_800_53 (control families), owasp (Top 10), cis
# (Controls v8).
_CWE_CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    # ----- Injection (SQLi / cmd / SSTI / etc.) -----
    "CWE-89": {  # SQL Injection
        "soc2": ["CC6.6"],
        "pci_dss": ["6.5.1"],
        "hipaa": ["164.312(c)(1)"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A03:2021"],
        "cis": ["16.10"],
    },
    "CWE-77": {  # Command Injection
        "soc2": ["CC6.6"],
        "pci_dss": ["6.5.1"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A03:2021"],
        "cis": ["16.10"],
    },
    "CWE-78": {  # OS Command Injection
        "soc2": ["CC6.6"],
        "pci_dss": ["6.5.1"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A03:2021"],
    },
    "CWE-94": {  # Code Injection
        "soc2": ["CC6.6"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A03:2021"],
    },
    "CWE-79": {  # XSS
        "soc2": ["CC6.6"],
        "pci_dss": ["6.5.7"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A03:2021"],
    },
    "CWE-22": {  # Path Traversal
        "soc2": ["CC6.6"],
        "pci_dss": ["6.5.8"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A01:2021"],
    },
    "CWE-918": {  # SSRF
        "soc2": ["CC6.6", "CC6.1"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10", "SC-7"],
        "owasp": ["A10:2021"],
    },
    "CWE-611": {  # XXE
        "soc2": ["CC6.6"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A05:2021"],
    },
    "CWE-1236": {  # CSV / formula injection
        "soc2": ["CC6.6"],
        "nist_800_53": ["SI-10"],
        "iso_27001": ["A.14.2.5"],
    },
    # ----- Authentication / Session / Authorization -----
    "CWE-287": {  # Improper Authentication
        "soc2": ["CC6.1"],
        "pci_dss": ["8.1", "8.2"],
        "hipaa": ["164.312(d)"],
        "iso_27001": ["A.9.4.2"],
        "nist_800_53": ["IA-2"],
        "owasp": ["A07:2021"],
    },
    "CWE-285": {  # Improper Authorization
        "soc2": ["CC6.1", "CC6.3"],
        "pci_dss": ["7.1", "7.2"],
        "hipaa": ["164.312(a)(1)"],
        "iso_27001": ["A.9.4.1"],
        "nist_800_53": ["AC-3", "AC-6"],
        "owasp": ["A01:2021"],
    },
    "CWE-269": {  # Improper Privilege Management
        "soc2": ["CC6.1", "CC6.3"],
        "pci_dss": ["7.1.2"],
        "iso_27001": ["A.9.2.3"],
        "nist_800_53": ["AC-6"],
        "owasp": ["A01:2021"],
    },
    "CWE-352": {  # CSRF
        "soc2": ["CC6.1"],
        "pci_dss": ["6.5.9"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A01:2021"],
    },
    "CWE-613": {  # Insufficient Session Expiration
        "soc2": ["CC6.1"],
        "pci_dss": ["8.1.8"],
        "nist_800_53": ["IA-11"],
        "owasp": ["A07:2021"],
    },
    "CWE-330": {  # Weak Randomness
        "soc2": ["CC6.1"],
        "pci_dss": ["8.2"],
        "nist_800_53": ["SC-13"],
        "owasp": ["A02:2021"],
    },
    "CWE-347": {  # Improper Verification of Cryptographic Signature
        "soc2": ["CC6.1"],
        "iso_27001": ["A.10.1.1"],
        "nist_800_53": ["SC-13"],
        "owasp": ["A02:2021"],
    },
    "CWE-942": {  # CORS misconfiguration
        "soc2": ["CC6.1"],
        "nist_800_53": ["AC-4"],
        "owasp": ["A05:2021"],
    },
    # ----- Crypto -----
    "CWE-326": {  # Inadequate Encryption Strength
        "soc2": ["CC6.1"],
        "pci_dss": ["4.1"],
        "hipaa": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        "gdpr": ["Art.32"],
        "iso_27001": ["A.10.1.1"],
        "nist_800_53": ["SC-13"],
        "owasp": ["A02:2021"],
    },
    "CWE-327": {  # Use of a Broken or Risky Cryptographic Algorithm
        "soc2": ["CC6.1"],
        "pci_dss": ["4.1"],
        "iso_27001": ["A.10.1.1"],
        "nist_800_53": ["SC-13"],
    },
    "CWE-353": {  # Missing Support for Integrity Check (SRI)
        "soc2": ["CC9.0"],
        "iso_27001": ["A.14.2.7"],
        "nist_800_53": ["SI-7"],
    },
    # ----- Information disclosure -----
    "CWE-200": {  # Information Exposure
        "soc2": ["CC6.7"],
        "pci_dss": ["3.4"],
        "hipaa": ["164.312(a)(1)", "164.312(e)(2)(ii)"],
        "gdpr": ["Art.32"],
        "iso_27001": ["A.13.2.1"],
        "nist_800_53": ["SC-28"],
        "owasp": ["A04:2021"],
    },
    "CWE-209": {  # Information Exposure Through an Error Message
        "soc2": ["CC6.7"],
        "pci_dss": ["6.5.5"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-11"],
    },
    # ----- Race / concurrency -----
    "CWE-362": {  # Race Condition
        "soc2": ["CC6.6"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-444": {  # HTTP Request Smuggling
        "soc2": ["CC6.6"],
        "iso_27001": ["A.13.1.3"],
        "nist_800_53": ["SC-7"],
    },
    # ----- File upload / deserialisation -----
    "CWE-434": {  # Unrestricted File Upload
        "soc2": ["CC6.6"],
        "pci_dss": ["6.5"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
        "owasp": ["A05:2021"],
    },
    "CWE-915": {  # Mass Assignment / improperly controlled modification
        "soc2": ["CC6.1"],
        "iso_27001": ["A.14.2.5"],
        "owasp": ["API6:2023"],
    },
    "CWE-345": {  # Insufficient Verification of Data Authenticity
        "soc2": ["CC6.6"],
        "iso_27001": ["A.14.2.5"],
    },
    # ----- Vulnerability management / KEV -----
    "CWE-1395": {  # Vulnerable Software (KEV-flagged)
        "soc2": ["CC6.6", "CC9.0"],
        "pci_dss": ["6.2", "6.3"],
        "iso_27001": ["A.12.6.1"],
        "nist_800_53": ["SI-2"],
    },
    "CWE-1104": {  # Use of Unmaintained Third Party Components
        "soc2": ["CC9.0"],
        "iso_27001": ["A.15.1.3"],
        "nist_800_53": ["SI-2"],
    },
    "CWE-693": {  # Protection Mechanism Failure (general)
        "soc2": ["CC6.1"],
        "iso_27001": ["A.14.1.2"],
    },
    # ----- Validation -----
    "CWE-20": {  # Improper Input Validation (catch-all)
        "soc2": ["CC6.6"],
        "iso_27001": ["A.14.2.5"],
        "nist_800_53": ["SI-10"],
    },
    "CWE-453": {  # Insecure Default Variable Initialization
        "soc2": ["CC6.6"],
        "nist_800_53": ["CM-6"],
    },
    "CWE-525": {  # Cache deception / use of web-cache containing sensitive info
        "soc2": ["CC6.6"],
        "nist_800_53": ["SI-10"],
    },
}


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
    cwe = (report.get("cwe") or "").strip().upper()
    if cwe:
        controls = _CWE_CONTROL_MAP.get(cwe)
        if controls is not None:
            # Deep-copy the lists so callers can't mutate the static map.
            out["compliance_controls"] = {
                framework: list(ids) for framework, ids in controls.items()
            }

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
    """Return sorted list of CWEs the static map covers — used for
    introspection / docs."""
    return sorted(_CWE_CONTROL_MAP.keys())
