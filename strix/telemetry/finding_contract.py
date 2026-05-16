"""Canonical-finding contract validator.

Roadmap §8.0 (sub-agent canonical-finding contract). Every sub-agent
team writes findings through `tracer.add_vulnerability_report`; this
module validates that the resulting finding satisfies the canonical
shape so cross-team dedup / cross-team confidence scoring / wrapper
rendering can rely on a stable contract.

Contract guarantees (verified at write-time, AFTER the tracer's
existing coercions):

- **Required fields**: `title`, `severity`, `category`, `verification_status`,
  AND at least ONE of {`endpoint`, `target`, `code_locations`} so the
  finding is locatable.
- **Severity ∈ {info, low, medium, high, critical}**.
- **Verification status ∈ {verified, pattern_match, inconclusive,
  needs_review, could_not_verify}**.
- **CWE format**: `CWE-<digits>` (case-insensitive; canonicalised
  upstream).
- **CVE format**: `CVE-<4-digit-year>-<1+digits>`.
- **§11 UX presence**: when severity ≥ low, both `description_plain`
  AND `recommended_action` should be populated. (warn, not reject —
  legacy callers may still ship without).
- **Severity-category coherence**: certain (severity, category)
  combinations are nonsensical and warned (e.g. `severity=critical`
  on `category=informational`).

Design notes:

- **Never drops a finding.** Data loss is worse than ugly data. The
  validator returns a list of violations the writer attaches to the
  finding (`shape_violations` field), then emits a
  `finding.shape_violation` event so the wrapper can flag the run.
- **Soft enforcement**. Each violation has a severity (`error` /
  `warn`) — `error` for missing-required / wrong-shape, `warn` for
  presence-of-§11-UX / coherence checks. Both are recorded; only
  `error` is the "this finding is non-canonical" signal.
- **Composes with existing coercions**. The tracer already lowercases
  severity, strips whitespace, infers category from CWE. The
  validator runs AFTER those coercions so it sees the final shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Allow-lists
# ---------------------------------------------------------------------------


VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})

VALID_VERIFICATION_STATUSES = frozenset({
    # The gradient — least → most evidence:
    #   * pattern_match  — heuristic / signature fired; no execution
    #   * needs_review   — signal too ambiguous to auto-classify
    #   * could_not_verify — scanner tried to confirm and failed
    #   * inconclusive   — partial signal; auditor judgment needed
    #   * verified       — exploit-shape confirmed via response diff
    #                      / oracle / second-stage probe (no impact
    #                      captured)
    #   * exploited      — full attack executed end-to-end with
    #                      proof-of-impact captured (stolen cookie,
    #                      dumped column, fetched IMDS, captured flag).
    #                      Requires `proof_artifact_path` on the
    #                      finding pointing at the captured artifact.
    "verified", "pattern_match", "inconclusive",
    "needs_review", "could_not_verify", "exploited",
})


# Verification statuses that REQUIRE a `proof_artifact_path` —
# enforcing the "show me the captured impact" contract for the
# top tier. The artifact path is relative to the run dir; the
# scanner is responsible for writing the file before emitting
# the finding.
PROOF_REQUIRED_VERIFICATION_STATUSES = frozenset({"exploited"})

# Severity bands that REQUIRE §11 UX fields (description_plain +
# recommended_action). Info-severity findings are exempt because
# they're often informational / posture rows that don't need
# remediation prose.
UX_REQUIRED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

# Categories that are inherently informational. Severity ≥ medium
# on these is a coherence violation (warn).
INFORMATIONAL_CATEGORIES = frozenset({
    "informational", "posture", "telemetry", "compliance_attestation",
})


_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{1,}$", re.IGNORECASE)


@dataclass(frozen=True)
class Violation:
    """One canonical-contract violation on a finding."""
    code: str        # short stable identifier — wrapper / GRC consumers key on this
    field: str       # which field is in violation
    message: str     # human-readable description
    severity: str    # 'error' (canonical-contract violation) or 'warn' (advisory)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_canonical_finding(report: dict[str, Any]) -> list[Violation]:
    """Validate `report` against the canonical-finding contract.

    Returns a list of `Violation` records. Empty list = canonical.

    Pure function: never mutates `report`; never raises.
    """
    if not isinstance(report, dict):
        return [Violation(
            code="finding.not_dict",
            field="(report)",
            message=f"finding is not a dict: {type(report).__name__}",
            severity="error",
        )]

    violations: list[Violation] = []

    # ---- Required scalar fields ----
    for field in ("title", "severity"):
        value = report.get(field)
        if not isinstance(value, str) or not value.strip():
            violations.append(Violation(
                code=f"finding.missing.{field}",
                field=field,
                message=f"required field `{field}` is missing or empty",
                severity="error",
            ))

    # ---- Severity allow-list ----
    sev = (report.get("severity") or "").strip().lower()
    if sev and sev not in VALID_SEVERITIES:
        violations.append(Violation(
            code="finding.severity.invalid",
            field="severity",
            message=(
                f"severity {sev!r} is not in the canonical allow-list "
                f"{sorted(VALID_SEVERITIES)}"
            ),
            severity="error",
        ))

    # ---- Verification-status allow-list ----
    vs = (report.get("verification_status") or "").strip().lower()
    if not vs:
        violations.append(Violation(
            code="finding.missing.verification_status",
            field="verification_status",
            message="required field `verification_status` is missing",
            severity="error",
        ))
    elif vs not in VALID_VERIFICATION_STATUSES:
        violations.append(Violation(
            code="finding.verification_status.invalid",
            field="verification_status",
            message=(
                f"verification_status {vs!r} is not in the canonical "
                f"allow-list {sorted(VALID_VERIFICATION_STATUSES)}"
            ),
            severity="error",
        ))

    # ---- Proof-of-impact required for the `exploited` tier ----
    if vs in PROOF_REQUIRED_VERIFICATION_STATUSES:
        proof = report.get("proof_artifact_path")
        if not isinstance(proof, str) or not proof.strip():
            violations.append(Violation(
                code="finding.exploited.missing_proof",
                field="proof_artifact_path",
                message=(
                    "verification_status='exploited' requires "
                    "`proof_artifact_path` pointing at the captured "
                    "proof-of-impact (cookie / dumped row / IMDS blob / "
                    "captured flag). The path is relative to the run "
                    "dir; the scanner must write the file before "
                    "emitting the finding."
                ),
                severity="error",
            ))

    # ---- Category presence ----
    cat = (report.get("category") or "").strip()
    if not cat:
        violations.append(Violation(
            code="finding.missing.category",
            field="category",
            message=(
                "required field `category` is missing — Orient-stage "
                "routing depends on every finding having a category"
            ),
            severity="error",
        ))

    # ---- Locatability: at least one of endpoint / target / code_locations ----
    has_endpoint = bool((report.get("endpoint") or "").strip()) if isinstance(report.get("endpoint"), str) else False
    has_target = bool((report.get("target") or "").strip()) if isinstance(report.get("target"), str) else False
    has_code = bool(report.get("code_locations")) and isinstance(report.get("code_locations"), list)
    if not (has_endpoint or has_target or has_code):
        violations.append(Violation(
            code="finding.missing.location",
            field="endpoint|target|code_locations",
            message=(
                "finding has no locatable surface — at least one of "
                "`endpoint`, `target`, or `code_locations` must be set"
            ),
            severity="error",
        ))

    # ---- CWE format ----
    cwe = report.get("cwe")
    if cwe is not None:
        if not isinstance(cwe, str) or not _CWE_RE.match(cwe.strip()):
            violations.append(Violation(
                code="finding.cwe.invalid_format",
                field="cwe",
                message=f"CWE {cwe!r} doesn't match `CWE-<digits>` shape",
                severity="error",
            ))

    # ---- CVE format ----
    cve = report.get("cve")
    if cve is not None:
        if not isinstance(cve, str) or not _CVE_RE.match(cve.strip()):
            violations.append(Violation(
                code="finding.cve.invalid_format",
                field="cve",
                message=f"CVE {cve!r} doesn't match `CVE-YYYY-N+` shape",
                severity="error",
            ))

    # ---- §11 UX presence (warn for severity ≥ low) ----
    if sev in UX_REQUIRED_SEVERITIES:
        for ux_field in ("description_plain", "recommended_action"):
            v = report.get(ux_field)
            if not isinstance(v, str) or not v.strip():
                violations.append(Violation(
                    code=f"finding.ux.missing.{ux_field}",
                    field=ux_field,
                    message=(
                        f"§11 UX field `{ux_field}` should be populated "
                        f"on findings with severity={sev!r} so the wrapper "
                        f"can render plain-English prose to non-tech users"
                    ),
                    severity="warn",
                ))

    # ---- Severity-category coherence (warn) ----
    if cat.lower() in INFORMATIONAL_CATEGORIES and sev in {"medium", "high", "critical"}:
        violations.append(Violation(
            code="finding.severity_category.incoherent",
            field="severity",
            message=(
                f"severity={sev!r} on informational category "
                f"{cat!r} is unusual; review whether the severity is correct"
            ),
            severity="warn",
        ))

    return violations


def violations_to_dict_list(violations: list[Violation]) -> list[dict[str, str]]:
    """Convert violations into JSON-serialisable dicts for embedding
    in the finding artifact + emitting in events."""
    return [
        {
            "code": v.code,
            "field": v.field,
            "message": v.message,
            "severity": v.severity,
        }
        for v in violations
    ]


def has_canonical_errors(violations: list[Violation]) -> bool:
    """True if any violation has severity='error' (i.e. the finding
    is non-canonical, not just imperfect)."""
    return any(v.severity == "error" for v in violations)
