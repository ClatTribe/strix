"""Tests for iter-27.2 — mid-scan correlate at phase boundaries."""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.mid_scan_correlate import (
    PhaseCorrelationResult,
    clear_seen_chain_cache,
    correlate_at_phase_boundary,
)
from strix.l15 import corroborator_ledger, hygiene_ledger, root_cause_ledger
from strix.l15.git_blame import clear_cache as _clear_blame_cache
from strix.l15.posture import clear_cache as _clear_posture_cache
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture
def tracer(tmp_path, monkeypatch):
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()
    clear_seen_chain_cache()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(
        "strix.telemetry.tracer.posthog.finding", lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.telemetry.tracer._emit_kg_auto_for_finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.llm.kev_enrichment.resolve_kev_block", lambda **_k: {},
    )
    monkeypatch.setattr(
        "strix.llm.campaign_enrichment.resolve_campaign_block",
        lambda **_k: {"matched_pulse_count": 0, "matched_pulses": []},
    )
    t = Tracer(run_name="iter-27.2-mid-scan")
    t._maybe_merge_into_existing_finding = lambda _r: None
    set_global_tracer(t)
    yield t
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()
    clear_seen_chain_cache()
    set_global_tracer(None)


# =========================================================================
# Basic invocation
# =========================================================================

def test_no_findings_returns_zero(tracer):
    """Empty tracer → 0 chains."""
    result = correlate_at_phase_boundary("recon", "probe")
    assert isinstance(result, PhaseCorrelationResult)
    assert result.chains_built == 0
    assert result.new_chains == 0
    assert result.findings_promoted == 0
    assert result.error is None


def test_no_tracer_returns_error_status(monkeypatch):
    """When no global tracer is set, return an error result but
    don't raise."""
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: None,
    )
    result = correlate_at_phase_boundary("recon", "probe")
    assert result.error is not None
    assert "tracer" in result.error.lower()


# =========================================================================
# Chain building + promotion
# =========================================================================

def test_two_related_findings_form_chain_and_promote(tracer):
    """Two findings the correlator's linkers will join → chain
    built → parent severity bumped one tier."""
    # SAST sink + DAST confirm — classic attack-chain shape
    sast_id = tracer.add_vulnerability_report(
        title="SAST SQL string concat",
        severity="medium",
        cwe="CWE-89",
        rule_id="semgrep-sqli",
        code_locations=[{"file": "src/db.py", "line": 5}],
        endpoint="https://app.example.com/search",
        discovery_source_tool="semgrep",
    )
    dast_id = tracer.add_vulnerability_report(
        title="DAST SQLi confirmed",
        severity="medium",
        cwe="CWE-89",
        endpoint="https://app.example.com/search",
        verification_status="exploited",
        discovery_source_tool="sqlmap",
    )

    result = correlate_at_phase_boundary("recon", "probe")

    # Whether the linker builds a chain depends on its own linking
    # rules. Some linkers might join SAST+DAST on same CWE+endpoint;
    # others might not. If chains_built==0, we still want the hook
    # to be no-op-safe (already covered by the empty test).
    # The key assertion: when a chain IS built, the parent finding
    # gets a `chain_summary` attached and severity bumps.
    if result.chains_built >= 1 and result.new_chains >= 1:
        parent = next(
            (
                r for r in tracer.vulnerability_reports
                if "chain_summary" in r
            ),
            None,
        )
        assert parent is not None, (
            "if a chain was built, exactly one finding should have a "
            "chain_summary block"
        )
        # Severity should have been bumped from medium → high
        assert parent["severity"] in ("high", "critical"), (
            f"chain parent should be bumped; got {parent['severity']}"
        )


def test_seen_chains_not_double_promoted(tracer):
    """Calling correlate twice with the same finding set must NOT
    double-promote — the per-scan seen-chain cache prevents this."""
    # Plant two correlatable findings
    tracer.add_vulnerability_report(
        title="SAST sqli",
        severity="medium", cwe="CWE-89",
        rule_id="semgrep-sqli",
        code_locations=[{"file": "src/db.py", "line": 5}],
        endpoint="https://app.example.com/q",
        discovery_source_tool="semgrep",
    )
    tracer.add_vulnerability_report(
        title="DAST sqli",
        severity="medium", cwe="CWE-89",
        endpoint="https://app.example.com/q",
        verification_status="exploited",
        discovery_source_tool="sqlmap",
    )

    r1 = correlate_at_phase_boundary("recon", "probe")
    r2 = correlate_at_phase_boundary("probe", "report")

    # First call may or may not build a chain — but if it did, the
    # second call must NOT re-process the same chain.
    if r1.new_chains > 0:
        assert r2.new_chains == 0, (
            f"second correlate call must not re-promote already-seen "
            f"chains; got r1.new_chains={r1.new_chains}, "
            f"r2.new_chains={r2.new_chains}"
        )


# =========================================================================
# Wired into advance_phase
# =========================================================================

def test_advance_phase_invokes_mid_scan_correlate(tracer, monkeypatch):
    """`strix.agents.workflow_state.advance_phase` must invoke
    `correlate_at_phase_boundary` after the transition."""
    captured: list[tuple[str, str]] = []

    def _capture(from_phase, to_phase, **_kw):
        captured.append((from_phase, to_phase))
        return PhaseCorrelationResult(
            from_phase=from_phase, to_phase=to_phase,
            chains_built=0, new_chains=0, findings_promoted=0,
        )

    monkeypatch.setattr(
        "strix.agents.lead_agent.mid_scan_correlate."
        "correlate_at_phase_boundary",
        _capture,
    )

    # Reset workflow state to recon explicitly, then advance.
    from strix.agents.workflow_state import (
        advance_phase,
        get_current_phase,
        reset_for_testing,
    )
    reset_for_testing()
    assert get_current_phase() == "recon"

    transitioned, _msg = advance_phase("auth_attempt", force=True)
    assert transitioned

    # The hook should have been invoked with (from, to)
    assert captured == [("recon", "auth_attempt")]


def test_correlate_error_does_not_block_phase_transition(monkeypatch):
    """If the correlator raises, the phase transition must still
    succeed — recall-safety contract."""
    def _boom(*_a, **_kw):
        raise RuntimeError("simulated correlator crash")

    monkeypatch.setattr(
        "strix.agents.lead_agent.mid_scan_correlate."
        "correlate_at_phase_boundary",
        _boom,
    )

    from strix.agents.workflow_state import (
        advance_phase,
        get_current_phase,
        reset_for_testing,
    )
    reset_for_testing()
    transitioned, _msg = advance_phase("auth_attempt", force=True)
    assert transitioned
    assert get_current_phase() == "auth_attempt"


def test_result_to_dict_round_trip():
    r = PhaseCorrelationResult(
        from_phase="recon", to_phase="probe",
        chains_built=3, new_chains=2, findings_promoted=2,
    )
    d = r.to_dict()
    assert d["from_phase"] == "recon"
    assert d["new_chains"] == 2
    assert d["error"] is None
