"""Integration tests for V3-2 — the tracer's `add_vulnerability_report`
auto-verifies deterministic findings in quick / initial scan modes.

Pins:
  * `discovery_method="deterministic_specialist"` + quick mode →
    finding lands in pipeline at VERIFIED (medium) or VERIFYING
    (high/critical with 1-method floor).
  * `discovery_method=None` (LLM-discovered default) → finding
    does NOT auto-verify.
  * Standard / deep modes → no auto-verify regardless of
    discovery_method.
  * Kill switch bypasses auto-verify in quick mode.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import verification_pipeline as vp
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_QUICK_SKIP_VERIFIER_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_VERIFICATION_PERSIST", "0")
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.chdir(tmp_path)
    vp.reset_for_testing()
    yield
    vp.reset_for_testing()


def _new_tracer(name: str = "test-run") -> Tracer:
    tracer = Tracer(name)
    set_global_tracer(tracer)
    return tracer


def _emit_medium_finding(tracer: Tracer, **overrides) -> str:
    """Emit a minimal valid medium-severity SQLi finding."""
    defaults: dict = {
        "title": "SQLi on /api/users",
        "severity": "medium",
        "cwe": "CWE-89",
        "endpoint": "/api/users",
        "target": "https://x.com/api/users",
        "category": "sqli",
        "description": "SQLi via username field.",
        "impact": "DB read.",
        "technical_analysis": "Boolean-based SQLi confirmed.",
        "poc_description": "POST with crafted username.",
        "poc_script_code": "curl ...",
        "remediation_steps": "Use parameterized queries.",
    }
    defaults.update(overrides)
    return tracer.add_vulnerability_report(**defaults)


# ---------------------------------------------------------------------------
# Auto-verify fires when scan_mode == quick + discovery_method = deterministic
# ---------------------------------------------------------------------------


def test_deterministic_finding_auto_verified_in_quick_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    tracer = _new_tracer("v3-2-quick-deterministic")
    finding_id = _emit_medium_finding(
        tracer,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    pipeline = vp.get_pipeline()
    rec = pipeline.get(finding_id)
    assert rec is not None
    assert rec.stage == "VERIFIED", (
        f"expected VERIFIED, got {rec.stage}. auto-verify should "
        "have fired for medium severity + 1-method floor."
    )


def test_high_severity_lands_at_VERIFYING_in_quick_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recall canary — HIGH/CRITICAL severity findings keep the
    ≥2-method floor. Auto-verify records 1 method; the finding
    stops at VERIFYING."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    tracer = _new_tracer("v3-2-quick-high")
    finding_id = _emit_medium_finding(
        tracer,
        severity="high",
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    rec = vp.get_pipeline().get(finding_id)
    assert rec is not None
    assert rec.stage == "VERIFYING"


# ---------------------------------------------------------------------------
# No auto-verify when discovery_method is None / "ai_specialist"
# ---------------------------------------------------------------------------


def test_llm_discovered_finding_not_auto_verified_in_quick_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When discovery_method is absent or "ai_specialist", the
    finding flows through the normal verifier path — the
    pipeline shouldn't register it automatically."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    tracer = _new_tracer("v3-2-quick-llm")
    finding_id = _emit_medium_finding(tracer)  # no discovery_method
    rec = vp.get_pipeline().get(finding_id)
    assert rec is None, (
        f"LLM-discovered finding shouldn't be in the pipeline "
        f"automatically; the agent should register it explicitly. "
        f"Got rec={rec}"
    )


# ---------------------------------------------------------------------------
# Standard / deep modes don't auto-verify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_standard_and_deep_dont_auto_verify(
    monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Standard / deep modes keep full LLM verifier behavior —
    deterministic findings are NOT auto-verified."""
    monkeypatch.setenv("STRIX_SCAN_MODE", mode)
    tracer = _new_tracer(f"v3-2-{mode}")
    finding_id = _emit_medium_finding(
        tracer,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    rec = vp.get_pipeline().get(finding_id)
    assert rec is None, (
        f"{mode} mode auto-verified a deterministic finding — "
        "must only fire in quick / initial."
    )


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_disables_auto_verify_in_quick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_QUICK_SKIP_VERIFIER_DISABLED", "1")
    tracer = _new_tracer("v3-2-quick-kill")
    finding_id = _emit_medium_finding(
        tracer,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    rec = vp.get_pipeline().get(finding_id)
    assert rec is None


# ---------------------------------------------------------------------------
# Initial mode behaves like quick
# ---------------------------------------------------------------------------


def test_initial_mode_auto_verifies_like_quick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "initial")
    tracer = _new_tracer("v3-2-initial")
    finding_id = _emit_medium_finding(
        tracer,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    rec = vp.get_pipeline().get(finding_id)
    assert rec is not None
    assert rec.stage == "VERIFIED"


# ---------------------------------------------------------------------------
# Recall safety — finding still lands in tracer regardless
# ---------------------------------------------------------------------------


def test_finding_lands_in_tracer_independent_of_auto_verify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity: the auto-verify hook is best-effort. The finding
    itself MUST land in the tracer regardless of pipeline state."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_VERIFICATION_DISABLED", "1")  # pipeline off
    tracer = _new_tracer("v3-2-finding-survives")
    finding_id = _emit_medium_finding(
        tracer,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    assert finding_id, "finding must land even when pipeline is disabled"
    # Tracer's vulnerability_reports has the entry
    assert any(r.get("id") == finding_id for r in tracer.vulnerability_reports)
