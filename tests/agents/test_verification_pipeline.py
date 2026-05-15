"""Tests for the §4 five-stage verification pipeline.

Covers:
  * Stage transitions — canonical forward, rejected backward, FAILED terminal
  * Multi-method floor: HIGH/CRITICAL need ≥2 distinct PASSED methods
  * MEDIUM/LOW need just 1 PASSED method
  * Independence rule — two `payload_response` entries count as 1 method
  * Method type enforcement (unknown methods rejected)
  * Outcome enforcement (unknown outcomes rejected)
  * Idempotent registration
  * Persistence to <run_dir>/verification.jsonl
  * Kill switch (STRIX_VERIFICATION_DISABLED)
  * Per-severity floor env override
  * Telemetry snapshot
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.agents import verification_pipeline as vp


@pytest.fixture(autouse=True)
def _reset_pipeline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    vp.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_VERIFICATION_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_PERSIST", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_MIN_METHODS_HIGH", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_MIN_METHODS_DEFAULT", raising=False)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_creates_record() -> None:
    p = vp.get_pipeline()
    rec = p.register(finding_id="F-001", severity="high")
    assert rec.finding_id == "F-001"
    assert rec.severity == "high"
    assert rec.stage == "SCANNED"
    assert rec.evidence == []


def test_register_lowercases_severity() -> None:
    p = vp.get_pipeline()
    rec = p.register(finding_id="F-001", severity="HIGH")
    assert rec.severity == "high"


def test_register_is_idempotent() -> None:
    p = vp.get_pipeline()
    rec_a = p.register(finding_id="F-001", severity="high")
    rec_b = p.register(finding_id="F-001", severity="medium")
    # Same record returned — severity NOT overwritten
    assert rec_a is rec_b
    assert rec_b.severity == "high"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_record_evidence_appends() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.record_evidence(
        "F-001",
        method="payload_response",
        outcome="PASSED",
        tool="sqlmap",
    )
    rec = p.get("F-001")
    assert rec is not None
    assert len(rec.evidence) == 1
    assert rec.evidence[0].method == "payload_response"
    assert rec.evidence[0].outcome == "PASSED"


def test_record_evidence_unknown_method_rejected() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    with pytest.raises(ValueError) as exc:
        p.record_evidence(
            "F-001", method="psychic_reading", outcome="PASSED", tool="x",  # type: ignore[arg-type]
        )
    assert "invalid method" in str(exc.value)


def test_record_evidence_unknown_outcome_rejected() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    with pytest.raises(ValueError) as exc:
        p.record_evidence(
            "F-001", method="timing", outcome="MAYBE", tool="x",  # type: ignore[arg-type]
        )
    assert "invalid outcome" in str(exc.value)


def test_record_evidence_unknown_finding_returns_none() -> None:
    p = vp.get_pipeline()
    rec = p.record_evidence(
        "F-DOES-NOT-EXIST",
        method="timing", outcome="PASSED", tool="x",
    )
    assert rec is None


def test_distinct_passed_methods_dedups() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="a")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="b")
    rec = p.get("F-001")
    assert rec is not None
    # Two PASSED evidence entries, but both same method → set size 1
    assert rec.distinct_passed_methods() == {"payload_response"}


def test_failed_evidence_does_not_count() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.record_evidence("F-001", method="timing", outcome="FAILED", tool="a")
    rec = p.get("F-001")
    assert rec is not None
    assert rec.distinct_passed_methods() == set()


# ---------------------------------------------------------------------------
# Stage transitions — basic
# ---------------------------------------------------------------------------


def test_canonical_forward_path() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")  # medium = 1-method floor
    ok, _, _ = p.advance("F-001", target_stage="DETECTED")
    assert ok
    ok, _, _ = p.advance("F-001", target_stage="VERIFYING")
    assert ok
    p.record_evidence(
        "F-001", method="payload_response", outcome="PASSED", tool="x",
    )
    ok, _, _ = p.advance("F-001", target_stage="VERIFIED")
    assert ok
    ok, _, _ = p.advance("F-001", target_stage="EXPLOITED")
    assert ok
    ok, _, _ = p.advance("F-001", target_stage="PATCHED")
    assert ok


def test_skip_stage_rejected() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")
    # SCANNED → VERIFYING (skipping DETECTED)
    ok, reason, _ = p.advance("F-001", target_stage="VERIFYING")
    assert not ok
    assert "not allowed" in reason


def test_failed_is_terminal() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")
    p.advance("F-001", target_stage="FAILED")
    ok, reason, _ = p.advance("F-001", target_stage="DETECTED")
    assert not ok
    assert "not allowed" in reason


def test_patched_is_terminal() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="dom", outcome="PASSED", tool="x")
    p.advance("F-001", target_stage="VERIFIED")
    p.advance("F-001", target_stage="EXPLOITED")
    p.advance("F-001", target_stage="PATCHED")
    ok, reason, _ = p.advance("F-001", target_stage="EXPLOITED")
    assert not ok


def test_advance_unknown_finding() -> None:
    p = vp.get_pipeline()
    ok, reason, _ = p.advance("F-NOPE", target_stage="DETECTED")
    assert not ok
    assert "not registered" in reason


def test_advance_to_current_stage_is_noop() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")
    ok, reason, _ = p.advance("F-001", target_stage="SCANNED")
    assert ok
    assert "already" in reason


def test_advance_invalid_stage() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")
    ok, reason, _ = p.advance("F-001", target_stage="MAGIC")  # type: ignore[arg-type]
    assert not ok
    assert "invalid stage" in reason


# ---------------------------------------------------------------------------
# Multi-method floor — the §4 invariant
# ---------------------------------------------------------------------------


def test_high_severity_needs_two_methods() -> None:
    """HIGH severity finding with 1 method → VERIFIED rejected."""
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="x")

    ok, reason, _ = p.advance("F-001", target_stage="VERIFIED")
    assert not ok
    assert "insufficient independent verification methods" in reason
    assert "have 1" in reason
    assert "need 2" in reason


def test_critical_severity_needs_two_methods() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="critical")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="oob", outcome="PASSED", tool="x")
    ok, _, _ = p.advance("F-001", target_stage="VERIFIED")
    assert not ok


def test_high_severity_passes_with_two_distinct_methods() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="x")
    p.record_evidence("F-001", method="timing", outcome="PASSED", tool="y")
    ok, reason, _ = p.advance("F-001", target_stage="VERIFIED")
    assert ok
    assert "VERIFIED" in reason


def test_high_severity_blocked_by_same_method_twice() -> None:
    """Two `payload_response` entries don't count as two methods."""
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="a")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="b")
    ok, reason, _ = p.advance("F-001", target_stage="VERIFIED")
    assert not ok


def test_medium_severity_passes_with_one_method() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="medium")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="x")
    ok, _, _ = p.advance("F-001", target_stage="VERIFIED")
    assert ok


def test_low_severity_passes_with_one_method() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="low")
    p.advance("F-001", target_stage="DETECTED")
    p.advance("F-001", target_stage="VERIFYING")
    p.record_evidence("F-001", method="static_match", outcome="PASSED", tool="semgrep")
    ok, _, _ = p.advance("F-001", target_stage="VERIFIED")
    assert ok


def test_floor_env_override_raises_for_default() -> None:
    """Bumping STRIX_VERIFICATION_MIN_METHODS_DEFAULT to 2 blocks
    medium/low with 1 method."""
    import os
    os.environ["STRIX_VERIFICATION_MIN_METHODS_DEFAULT"] = "2"
    try:
        p = vp.get_pipeline()
        p.register(finding_id="F-001", severity="medium")
        p.advance("F-001", target_stage="DETECTED")
        p.advance("F-001", target_stage="VERIFYING")
        p.record_evidence("F-001", method="timing", outcome="PASSED", tool="x")
        ok, reason, _ = p.advance("F-001", target_stage="VERIFIED")
        assert not ok
        assert "need 2" in reason
    finally:
        os.environ.pop("STRIX_VERIFICATION_MIN_METHODS_DEFAULT", None)


def test_floor_env_override_relaxes_high() -> None:
    """Lowering the HIGH floor to 1 makes high severities single-method-ok."""
    import os
    os.environ["STRIX_VERIFICATION_MIN_METHODS_HIGH"] = "1"
    try:
        p = vp.get_pipeline()
        p.register(finding_id="F-001", severity="high")
        p.advance("F-001", target_stage="DETECTED")
        p.advance("F-001", target_stage="VERIFYING")
        p.record_evidence("F-001", method="payload_response", outcome="PASSED", tool="x")
        ok, _, _ = p.advance("F-001", target_stage="VERIFIED")
        assert ok
    finally:
        os.environ.pop("STRIX_VERIFICATION_MIN_METHODS_HIGH", None)


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def test_list_records_filters() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.register(finding_id="F-002", severity="low")
    p.register(finding_id="F-003", severity="high")
    p.advance("F-003", target_stage="DETECTED")

    high_only = p.list_records(severity="high")
    assert len(high_only) == 2

    detected = p.list_records(stage="DETECTED")
    assert len(detected) == 1
    assert detected[0].finding_id == "F-003"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_appends_jsonl(tmp_path: Path) -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.record_evidence("F-001", method="timing", outcome="PASSED", tool="x")
    p.advance("F-001", target_stage="DETECTED")

    log = tmp_path / "verification.jsonl"
    assert log.exists()
    records = [json.loads(line) for line in log.read_text().splitlines() if line]
    assert len(records) >= 3
    for r in records:
        assert "event" in r
        assert "ts" in r
        assert "record" in r


def test_persistence_disabled_skips_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_VERIFICATION_PERSIST", "0")
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    log = tmp_path / "verification.jsonl"
    assert not log.exists()


def test_persistence_without_run_dir_is_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")  # must not raise


# ---------------------------------------------------------------------------
# Kill switch + telemetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch_telemetry_shape(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_VERIFICATION_DISABLED", val)
    assert vp.get_pipeline_stats() == {"enabled": False, "records": 0}


def test_telemetry_breakdown_by_stage() -> None:
    p = vp.get_pipeline()
    p.register(finding_id="F-001", severity="high")
    p.register(finding_id="F-002", severity="low")
    p.advance("F-002", target_stage="DETECTED")
    stats = vp.get_pipeline_stats()
    assert stats["enabled"] is True
    assert stats["records"] == 2
    assert stats["stage_counts"]["SCANNED"] == 1
    assert stats["stage_counts"]["DETECTED"] == 1
