"""Tests for V3-2 — auto-verify deterministic findings.

The helper `auto_verify_deterministic` is the core unit: registers
a finding + records evidence + advances toward VERIFIED in one
atomic call. Gating is via `should_auto_verify_deterministic()`
(scan_mode + kill switch).

Recall-safety contract pinned by tests:
  * Auto-verify ONLY fires in quick / initial modes. Standard /
    deep keep the full LLM-verifier round-trips.
  * Kill switch (`STRIX_QUICK_SKIP_VERIFIER_DISABLED=1`) disables
    regardless of mode.
  * HIGH/CRITICAL severity findings DO NOT skip to VERIFIED with
    one method — the existing ≥2-method floor is preserved.
    They land at VERIFYING; a second method or the agent advances
    them further. Recall canary pinned.
  * MEDIUM/LOW/INFO findings land at VERIFIED with the one
    deterministic method (the existing 1-method floor).
  * Pipeline-disabled (`STRIX_VERIFICATION_DISABLED=1`) is a no-op.
"""

from __future__ import annotations

import pytest

from strix.agents import verification_pipeline as vp


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_QUICK_SKIP_VERIFIER_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_PERSIST", raising=False)
    # Disable persistence so tests don't try to write a run dir
    monkeypatch.setenv("STRIX_VERIFICATION_PERSIST", "0")
    vp.reset_for_testing()
    yield
    vp.reset_for_testing()


# ---------------------------------------------------------------------------
# Gating — should_auto_verify_deterministic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode,expected", [
    ("quick", True),
    ("initial", True),
    ("standard", False),
    ("deep", False),
    ("", False),
    ("garbage", False),
])
def test_gating_by_mode(
    monkeypatch: pytest.MonkeyPatch, mode: str, expected: bool,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", mode)
    assert vp.should_auto_verify_deterministic() is expected


def test_gating_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even in quick mode, the kill switch disables auto-verify."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_QUICK_SKIP_VERIFIER_DISABLED", "1")
    assert vp.should_auto_verify_deterministic() is False


def test_gating_pipeline_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_VERIFICATION_DISABLED", "1")
    assert vp.should_auto_verify_deterministic() is False


# ---------------------------------------------------------------------------
# auto_verify_deterministic — happy path on MEDIUM (1-method floor)
# ---------------------------------------------------------------------------


def test_auto_verify_medium_reaches_VERIFIED() -> None:
    """A medium severity finding hits the ≥1-method floor with
    a single deterministic method → lands at VERIFIED."""
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0001",
        severity="medium",
        source_tool="scan_sqli",
    )
    assert rec is not None
    assert rec.stage == "VERIFIED"
    # Evidence was recorded
    methods = rec.distinct_passed_methods()
    assert "static_match" in methods


def test_auto_verify_low_reaches_VERIFIED() -> None:
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0002",
        severity="low",
        source_tool="scan_xss",
    )
    assert rec is not None
    assert rec.stage == "VERIFIED"


# ---------------------------------------------------------------------------
# Recall safety — HIGH/CRITICAL keeps the 2-method floor
# ---------------------------------------------------------------------------


def test_auto_verify_high_stops_at_VERIFYING() -> None:
    """Recall canary — HIGH severity findings have the ≥2-method
    floor (STRIX_VERIFICATION_MIN_METHODS_HIGH=2 default). Auto-
    verify records 1 method; the finding must NOT auto-advance
    to VERIFIED with one method. It lands at VERIFYING, where a
    second method (or explicit agent action) advances further."""
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0003",
        severity="high",
        source_tool="scan_sqli",
    )
    assert rec is not None
    assert rec.stage == "VERIFYING", (
        f"recall canary: HIGH finding auto-advanced to {rec.stage} "
        "with one method — that breaks the ≥2-method floor. "
        "Auto-verify must NOT bypass the floor for HIGH/CRITICAL."
    )


def test_auto_verify_critical_stops_at_VERIFYING() -> None:
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0004",
        severity="critical",
        source_tool="scan_sqli",
    )
    assert rec is not None
    assert rec.stage == "VERIFYING"


def test_auto_verify_high_can_advance_after_second_method() -> None:
    """When a second method is recorded after auto-verify (e.g.
    the agent's verifier runs anyway, or a timing oracle fires),
    the finding can advance to VERIFIED — the floor is satisfied."""
    pipeline = vp.get_pipeline()
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0005",
        severity="high",
        source_tool="scan_sqli",
    )
    assert rec is not None
    assert rec.stage == "VERIFYING"

    # Record a second independent method
    pipeline.record_evidence(
        "vuln-0005",
        method="timing",
        outcome="PASSED",
        tool="scan_sqli_timing",
    )
    ok, _, rec2 = pipeline.advance(
        "vuln-0005", target_stage="VERIFIED",
        reason="second method recorded",
    )
    assert ok is True
    assert rec2 is not None
    assert rec2.stage == "VERIFIED"


# ---------------------------------------------------------------------------
# Disabled pipeline returns None
# ---------------------------------------------------------------------------


def test_auto_verify_no_op_when_pipeline_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_VERIFICATION_DISABLED", "1")
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0006",
        severity="medium",
        source_tool="scan_sqli",
    )
    assert rec is None


# ---------------------------------------------------------------------------
# Evidence tool / detail attribution
# ---------------------------------------------------------------------------


def test_auto_verify_records_tool_in_evidence() -> None:
    """The deterministic specialist's tool name lands in the
    evidence's `tool` field for audit."""
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0007",
        severity="medium",
        source_tool="scan_nuclei_templates",
    )
    assert rec is not None
    assert len(rec.evidence) >= 1
    assert rec.evidence[0].tool == "scan_nuclei_templates"
    assert rec.evidence[0].method == "static_match"
    assert rec.evidence[0].outcome == "PASSED"


def test_auto_verify_records_detail_when_provided() -> None:
    rec = vp.auto_verify_deterministic(
        finding_id="vuln-0008",
        severity="medium",
        source_tool="scan_sqli",
        detail="union-based SQLi confirmed via DB error fingerprint",
    )
    assert rec is not None
    assert "DB error" in rec.evidence[0].detail


# ---------------------------------------------------------------------------
# Idempotency — calling twice on the same finding doesn't crash
# ---------------------------------------------------------------------------


def test_auto_verify_idempotent_on_repeat_call() -> None:
    """If a specialist re-emits the same finding (or the tracer
    replays), auto_verify should be safe to call twice. The
    second call may add a second evidence row but the stage
    stays at VERIFIED (or advances if the first was at
    VERIFYING)."""
    rec1 = vp.auto_verify_deterministic(
        finding_id="vuln-0009",
        severity="medium",
        source_tool="scan_sqli",
    )
    rec2 = vp.auto_verify_deterministic(
        finding_id="vuln-0009",
        severity="medium",
        source_tool="scan_sqli",
    )
    assert rec1 is not None and rec2 is not None
    assert rec2.stage == "VERIFIED"
