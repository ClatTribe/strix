"""Tests for §8.5 Phase 1 — `SpecialistResult` schema.

Pins the typed result shape every specialist-tool returns. Schema
versioning is additive; removing a field would bump
`SPECIALIST_RESULT_SCHEMA_VERSION`.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from strix.tools.specialist.result import (
    SPECIALIST_RESULT_SCHEMA_VERSION,
    DismissedHypothesis,
    FindingDraft,
    SpecialistResult,
    coerce_to_result,
)


# ---------------------------------------------------------------------------
# Schema-stability invariants
# ---------------------------------------------------------------------------


def test_schema_version_pinned() -> None:
    """Bumping signals breaking change."""
    assert SPECIALIST_RESULT_SCHEMA_VERSION == 1


def test_default_result_is_status_ok_with_empty_lists() -> None:
    out = SpecialistResult()
    assert out.status == "ok"
    assert out.findings == []
    assert out.dismissed == []
    assert out.evidence == []
    assert out.next_probes_suggested == []
    assert out.tool_metadata == {}
    assert out.error is None
    assert out.schema_version == 1


# ---------------------------------------------------------------------------
# FindingDraft — closed-enum invariants (mirrors engine-usage.md §6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity",
    ["info", "low", "medium", "high", "critical"],
)
def test_finding_draft_accepts_canonical_severities(severity: str) -> None:
    f = FindingDraft(title="t", severity=severity)
    assert f.severity == severity


def test_finding_draft_rejects_unknown_severity() -> None:
    with pytest.raises(ValidationError):
        FindingDraft(title="t", severity="apocalyptic")


@pytest.mark.parametrize(
    "vs",
    ["verified", "pattern_match", "inconclusive", "needs_review", "could_not_verify"],
)
def test_finding_draft_accepts_canonical_verification_statuses(vs: str) -> None:
    f = FindingDraft(title="t", severity="medium", verification_status=vs)
    assert f.verification_status == vs


def test_finding_draft_rejects_unknown_verification_status() -> None:
    with pytest.raises(ValidationError):
        FindingDraft(title="t", severity="medium", verification_status="haha")


def test_finding_draft_rejects_empty_title() -> None:
    with pytest.raises(ValidationError):
        FindingDraft(title="", severity="medium")


def test_finding_draft_clamps_confidence() -> None:
    """0.0–1.0 inclusive."""
    FindingDraft(title="t", severity="medium", confidence=0.0)
    FindingDraft(title="t", severity="medium", confidence=1.0)
    FindingDraft(title="t", severity="medium", confidence=0.5)
    with pytest.raises(ValidationError):
        FindingDraft(title="t", severity="medium", confidence=1.1)
    with pytest.raises(ValidationError):
        FindingDraft(title="t", severity="medium", confidence=-0.1)


def test_finding_draft_default_verification_status_is_pattern_match() -> None:
    """Per single-agent.md B.10 eager-emit at first credible evidence."""
    f = FindingDraft(title="t", severity="medium")
    assert f.verification_status == "pattern_match"


def test_finding_draft_rejects_extra_fields() -> None:
    """`extra='forbid'` so typos surface as validation errors."""
    with pytest.raises(ValidationError):
        FindingDraft(title="t", severity="medium", typo_field="x")


# ---------------------------------------------------------------------------
# DismissedHypothesis — 13-value FP_REASON enum
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        "input_properly_encoded", "framework_default_blocked",
        "csrf_token_validated", "auth_enforced", "not_reflected",
        "different_origin", "out_of_scope", "false_positive_signature",
        "compensating_control", "intended_behavior", "test_fixture",
        "deprecated_path", "other",
    ],
)
def test_dismissed_hypothesis_accepts_all_13_canonical_reasons(reason: str) -> None:
    """The 13-value FP_REASON closed-enum mirrors #118 dismiss_finding
    + #142 RLHF feedback_loader. Drift here breaks the wrapper's
    triage pipeline."""
    d = DismissedHypothesis(hypothesis="...", dismissal_reason=reason)
    assert d.dismissal_reason == reason


def test_dismissed_hypothesis_rejects_unknown_reason() -> None:
    with pytest.raises(ValidationError):
        DismissedHypothesis(hypothesis="...", dismissal_reason="i_dunno")


def test_dismissed_hypothesis_rejects_empty_hypothesis() -> None:
    with pytest.raises(ValidationError):
        DismissedHypothesis(hypothesis="", dismissal_reason="other")


# ---------------------------------------------------------------------------
# SpecialistResult — status enum
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["ok", "error", "partial"])
def test_specialist_result_accepts_canonical_statuses(status: str) -> None:
    out = SpecialistResult(status=status)
    assert out.status == status


def test_specialist_result_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        SpecialistResult(status="meh")


def test_specialist_result_caps_evidence_count() -> None:
    """Evidence list capped at 50 to bound conversation growth."""
    SpecialistResult(evidence=["e"] * 50)  # OK
    with pytest.raises(ValidationError):
        SpecialistResult(evidence=["e"] * 51)


def test_specialist_result_caps_next_probes_count() -> None:
    """Next-probes list capped at 20."""
    SpecialistResult(next_probes_suggested=["p"] * 20)  # OK
    with pytest.raises(ValidationError):
        SpecialistResult(next_probes_suggested=["p"] * 21)


# ---------------------------------------------------------------------------
# coerce_to_result — registry decorator's enforcement helper
# ---------------------------------------------------------------------------


def test_coerce_passes_through_specialist_result() -> None:
    r = SpecialistResult(status="ok")
    assert coerce_to_result(r) is r


def test_coerce_constructs_from_dict() -> None:
    out = coerce_to_result({"status": "ok", "findings": []})
    assert isinstance(out, SpecialistResult)


def test_coerce_wraps_unexpected_type_as_error() -> None:
    """Specialist returning a string / int / list → wrapped as
    `status='error'` rather than raising. Lead loop never crashes."""
    out = coerce_to_result("oops")
    assert out.status == "error"
    assert "str" in (out.error or "")


def test_coerce_propagates_pydantic_validation_error_on_dict() -> None:
    """Invalid dict payload (e.g. unknown severity) — propagates so
    the registry decorator's wrapper can swallow + emit a
    `status='error'` result."""
    with pytest.raises(ValidationError):
        coerce_to_result({"findings": [{"title": "t", "severity": "wrong"}]})
