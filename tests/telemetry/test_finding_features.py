"""Tests for RLHF Phase 1 / A2 — finding_features extractor.

Pins the structured-features schema the FP classifier consumes.
The schema is versioned; additive-only changes don't bump
`FEATURES_SCHEMA_VERSION`. Field removals do.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry.finding_features import (
    FEATURES_SCHEMA_VERSION,
    extract_features,
)


# ---------------------------------------------------------------------------
# Schema-stability invariants
# ---------------------------------------------------------------------------


_REQUIRED_FIELDS = {
    "schema_version",
    "category",
    "severity",
    "severity_ordinal",
    "verification_status",
    "cwe",
    "detection_count",
    "reachability_score",
    "is_test_path",
    "evidence_length_chars",
    "has_poc_script",
    "tool_name",
    "agent_category",
    "target_type",
    "confidence",
    "has_reasoning_trace",
    "has_counter_proof",
    "has_fingerprint",
}


def test_schema_version_pinned() -> None:
    """`FEATURES_SCHEMA_VERSION` is part of the public contract.
    Bumping it signals breaking change to the FP classifier."""
    assert FEATURES_SCHEMA_VERSION == 1


def test_extract_features_returns_complete_schema() -> None:
    feats = extract_features({})
    assert set(feats.keys()) == _REQUIRED_FIELDS
    assert feats["schema_version"] == FEATURES_SCHEMA_VERSION


def test_extract_features_handles_empty_report() -> None:
    """Every documented field present even with empty input — the
    classifier never has to handle absence."""
    feats = extract_features({})
    for field in _REQUIRED_FIELDS:
        assert field in feats, f"missing field {field!r}"


# ---------------------------------------------------------------------------
# Categorical normalisation
# ---------------------------------------------------------------------------


def test_category_normalised_to_lower() -> None:
    feats = extract_features({"category": "SQL_Injection"})
    assert feats["category"] == "sql_injection"


def test_severity_normalised_to_lower() -> None:
    feats = extract_features({"severity": "HIGH"})
    assert feats["severity"] == "high"


def test_cwe_normalised_to_upper() -> None:
    feats = extract_features({"cwe": "cwe-79"})
    assert feats["cwe"] == "CWE-79"


@pytest.mark.parametrize(
    "severity,ordinal",
    [
        ("info", 1),
        ("low", 2),
        ("medium", 3),
        ("high", 4),
        ("critical", 5),
        ("unknown", 0),
        ("", 0),
    ],
)
def test_severity_ordinal_mapping(severity: str, ordinal: int) -> None:
    feats = extract_features({"severity": severity})
    assert feats["severity_ordinal"] == ordinal


# ---------------------------------------------------------------------------
# Detection-count derivation (interacts with #98 cross-tool dedup)
# ---------------------------------------------------------------------------


def test_detection_count_from_detected_by_list() -> None:
    feats = extract_features({"detected_by": ["zap", "burp", "strix-internal"]})
    assert feats["detection_count"] == 3


def test_detection_count_falls_back_to_one() -> None:
    """Missing `detected_by` means single-detector — never zero,
    or the classifier may misread it as 'no detector at all'."""
    assert extract_features({})["detection_count"] == 1
    assert extract_features({"detected_by": None})["detection_count"] == 1


def test_detection_count_handles_empty_list() -> None:
    """Empty `detected_by` floors to 1 — a finding was emitted, so
    at least one detector fired even if cross-tool dedup didn't
    populate the list."""
    feats = extract_features({"detected_by": []})
    assert feats["detection_count"] == 1


# ---------------------------------------------------------------------------
# Test-path heuristic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("src/auth/login.py", False),
        ("tests/test_login.py", True),
        ("/repo/tests/auth/test_x.py", True),
        ("/repo/Tests/auth/test_x.py", True),  # case-insensitive
        ("specs/login_spec.rb", True),
        ("__tests__/auth.test.ts", True),
        ("fixtures/sample.json", True),
        ("backend\\tests\\foo.py", True),  # windows path
    ],
)
def test_is_test_path_from_code_locations(path: str, expected: bool) -> None:
    feats = extract_features({
        "code_locations": [{"file": path}],
    })
    assert feats["is_test_path"] is expected


def test_is_test_path_falls_back_to_endpoint() -> None:
    feats = extract_features({
        "code_locations": [],
        "endpoint": "/__tests__/api/x",
    })
    assert feats["is_test_path"] is True


def test_is_test_path_default_false() -> None:
    feats = extract_features({"endpoint": "/api/v1/users"})
    assert feats["is_test_path"] is False


# ---------------------------------------------------------------------------
# Evidence-length aggregation
# ---------------------------------------------------------------------------


def test_evidence_length_sums_text_fields() -> None:
    feats = extract_features({
        "description": "a" * 100,
        "technical_analysis": "b" * 200,
        "poc_description": "c" * 50,
        "poc_script_code": "d" * 75,
    })
    assert feats["evidence_length_chars"] == 100 + 200 + 50 + 75


def test_evidence_length_zero_when_absent() -> None:
    assert extract_features({})["evidence_length_chars"] == 0


def test_evidence_length_skips_non_strings() -> None:
    feats = extract_features({
        "description": "abc",
        "technical_analysis": None,
        "poc_description": 123,  # not a string — skipped
    })
    assert feats["evidence_length_chars"] == 3


# ---------------------------------------------------------------------------
# Pass-through fields (the classifier owns one-hot encoding)
# ---------------------------------------------------------------------------


def test_tool_name_from_first_detector() -> None:
    feats = extract_features({"detected_by": ["nuclei", "strix-internal"]})
    assert feats["tool_name"] == "nuclei"


def test_tool_name_default_unknown() -> None:
    assert extract_features({})["tool_name"] == "unknown"


def test_has_poc_script_truthy_check() -> None:
    assert extract_features({"poc_script_code": "import x"})["has_poc_script"] is True
    assert extract_features({"poc_script_code": ""})["has_poc_script"] is False
    assert extract_features({})["has_poc_script"] is False


def test_quality_signal_features_pass_through() -> None:
    """The features extractor surfaces #137 quality signals so the
    FP classifier can weight them."""
    feats = extract_features({
        "confidence": 0.42,
        "reasoning_trace": ["bullet"],
        "counter_proof": {"description": "...", "evidence": "..."},
        "fingerprint": "abc123",
    })
    assert feats["confidence"] == 0.42
    assert feats["has_reasoning_trace"] is True
    assert feats["has_counter_proof"] is True
    assert feats["has_fingerprint"] is True


def test_quality_signal_features_default_false() -> None:
    feats = extract_features({})
    assert feats["confidence"] is None
    assert feats["has_reasoning_trace"] is False
    assert feats["has_counter_proof"] is False
    assert feats["has_fingerprint"] is False


def test_agent_and_target_pass_through() -> None:
    feats = extract_features({
        "agent_category": "auth-attacker",
        "target_type": "web",
        "verification_status": "Verified",  # case-normalised
        "reachability_score": 0.85,
    })
    assert feats["agent_category"] == "auth-attacker"
    assert feats["target_type"] == "web"
    assert feats["verification_status"] == "verified"
    assert feats["reachability_score"] == 0.85


# ---------------------------------------------------------------------------
# Defensive-input behavior
# ---------------------------------------------------------------------------


def test_extract_features_does_not_raise_on_garbage() -> None:
    """Extractor must be defensive — never raise on malformed input."""
    bad: dict[str, Any] = {
        "category": 123,                  # wrong type — falsy `(... or "")`
        "code_locations": "not-a-list",   # wrong type — defensive branch
        "detected_by": {"not": "a list"}, # wrong type — falls back
    }
    # Should not raise.
    feats = extract_features(bad)
    assert feats["schema_version"] == FEATURES_SCHEMA_VERSION
