"""Finding-features extractor (RLHF Phase 1 / A2 from docs/rlhf-design.md).

For each finding, extract a structured features dict that the FP
classifier consumes as input. Stable schema — additive on changes,
versioned via `FEATURES_SCHEMA_VERSION`.

The features block lands on the finding record alongside other
auto-derived fields (compliance_controls, fingerprint, etc.).
The FP classifier (#A5, future PR) loads a checkpoint from
`~/.strix/fp_classifier/<version>.pkl` and scores every finding's
`fp_probability` from this features block.

Why a stable schema
-------------------

A versioned classifier shouldn't get its input shape pulled out
from under it. New features ship additively and bump
`FEATURES_SCHEMA_VERSION`; old features are NEVER removed without
a major version bump.

Categorical fields (category, cwe, tool_name, agent_category,
target_type, verification_status) are emitted as raw strings —
the classifier owns one-hot encoding so it can re-fit on new
values without forcing a strix-side schema change.
"""

from __future__ import annotations

from typing import Any


FEATURES_SCHEMA_VERSION: int = 1


_SEVERITY_ORDINAL = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


_TEST_PATH_FRAGMENTS = (
    "/tests/", "/test/", "/_tests/", "/_test/",
    "/spec/", "/specs/", "/__tests__/", "/__test__/",
    "/fixtures/", "/__fixtures__/",
)


def _is_test_path(path: str | None) -> bool:
    if not isinstance(path, str) or not path:
        return False
    # Prepend "/" so leading-relative paths like "tests/test_x.py" match
    # the slash-anchored fragments. Without this we'd false-negative
    # on relative repo paths.
    s = "/" + path.replace("\\", "/").lstrip("/").lower()
    return any(frag in s for frag in _TEST_PATH_FRAGMENTS)


def _evidence_length(report: dict[str, Any]) -> int:
    """Total character length of evidence-bearing fields."""
    total = 0
    for f in ("description", "technical_analysis", "poc_description", "poc_script_code"):
        v = report.get(f)
        if isinstance(v, str):
            total += len(v)
    return total


def _detection_count(report: dict[str, Any]) -> int:
    """Count of distinct detectors that fired on this finding.
    Uses the `detected_by` field populated by #98 cross-tool dedup.

    Floor at 1: a finding has been emitted, so at least one detector
    fired. Empty/missing `detected_by` happens when cross-tool dedup
    didn't merge — it doesn't mean zero detectors."""
    detected_by = report.get("detected_by")
    if isinstance(detected_by, list) and detected_by:
        return len(detected_by)
    return 1


def extract_features(report: dict[str, Any]) -> dict[str, Any]:
    """Extract the canonical features dict for a finding.

    Args:
        report: the finding record (post-finalisation; after threat-
            intel / compliance / fingerprint enrichment but before
            persistence).

    Returns: a dict suitable for direct attachment to the finding
    as the `features` field. Always returns a complete dict — every
    documented field is present so the classifier never has to
    handle absence.
    """
    # Defensive normalisation — non-string inputs fall through to "".
    def _str(v: Any) -> str:
        return v if isinstance(v, str) else ""

    severity = _str(report.get("severity")).lower()
    category = _str(report.get("category")).lower()
    cwe = _str(report.get("cwe")).upper()
    verification_status = _str(report.get("verification_status")).lower()
    target = _str(report.get("target"))
    endpoint = _str(report.get("endpoint"))

    # Test-path check — uses the first code_locations entry's file
    # if available, otherwise falls back to the endpoint string.
    is_test_path = False
    code_locs = report.get("code_locations") or []
    if isinstance(code_locs, list) and code_locs:
        first = code_locs[0]
        if isinstance(first, dict):
            is_test_path = _is_test_path(first.get("file"))
    if not is_test_path and isinstance(endpoint, str):
        is_test_path = _is_test_path(endpoint)

    return {
        "schema_version": FEATURES_SCHEMA_VERSION,
        "category": category,
        "severity": severity,
        "severity_ordinal": _SEVERITY_ORDINAL.get(severity, 0),
        "verification_status": verification_status,
        "cwe": cwe,
        "detection_count": _detection_count(report),
        "reachability_score": report.get("reachability_score"),
        "is_test_path": is_test_path,
        "evidence_length_chars": _evidence_length(report),
        "has_poc_script": bool(report.get("poc_script_code")),
        "tool_name": (report.get("detected_by") or ["unknown"])[0]
        if isinstance(report.get("detected_by"), list) and report.get("detected_by")
        else "unknown",
        "agent_category": report.get("agent_category"),
        "target_type": report.get("target_type"),
        # New §12 quality signals (from #137).
        "confidence": report.get("confidence"),
        "has_reasoning_trace": bool(report.get("reasoning_trace")),
        "has_counter_proof": bool(report.get("counter_proof")),
        # Derived sentinel for the FP classifier — fingerprint chain
        # presence (used by #98 cross-tool dedup confidence).
        "has_fingerprint": bool(report.get("fingerprint")),
    }
