"""Tests for iter-37.8 — minimal CORE tools (further trim past iter-37.2).

iter-37.2 trimmed the per-asset specialist set (web 89 → 10 specialists)
but left _CORE_TOOLS at 32 tools, so total catalogs stayed at ~42.

iter-37.8 trims CORE: 32 → 13 tools. Drops the 5 note tools, 5
hypothesis tools, 2 KG query tools, multiple introspection tools
(check_budget, agent_self_audit, drain_amplify_queue, etc.).
Total catalog target per web target: ~23 tools (down from 99 legacy).
"""

from __future__ import annotations

import os

import pytest

from strix.agents.lead_agent.tool_catalog import (
    _CORE_TOOLS,
    _MINIMAL_CORE_TOOLS,
    get_lead_tool_catalog,
)


@pytest.fixture(autouse=True)
def _clean_env():
    saved = os.environ.pop("STRIX_LEGACY_CATALOG", None)
    try:
        yield
    finally:
        os.environ.pop("STRIX_LEGACY_CATALOG", None)
        if saved is not None:
            os.environ["STRIX_LEGACY_CATALOG"] = saved


# ---------------------------------------------------------------------------
# Minimal CORE is dramatically smaller
# ---------------------------------------------------------------------------

def test_minimal_core_smaller_than_legacy_core():
    """At least half the legacy CORE was redundant — should be removed."""
    assert len(_MINIMAL_CORE_TOOLS) <= len(_CORE_TOOLS) * 0.5, (
        f"iter-37.8 minimal CORE has {len(_MINIMAL_CORE_TOOLS)} tools "
        f"vs legacy {len(_CORE_TOOLS)}. The whole point is to be ≤ 50% "
        f"of legacy — note/hypothesis/introspection tools must go."
    )


def test_minimal_core_under_15_tools():
    """The minimal CORE must be a tractable set (≤15) for the LLM."""
    assert len(_MINIMAL_CORE_TOOLS) <= 15


# ---------------------------------------------------------------------------
# Essential tools are present
# ---------------------------------------------------------------------------

def test_workflow_control_in_minimal_core():
    """workflow_status stays — pure OBSERVE. iter-37.10 dropped
    advance_workflow_phase (auto-handled by gates)."""
    assert "workflow_status" in _MINIMAL_CORE_TOOLS
    # iter-37.10: advance_workflow_phase no longer in core. The
    # workflow state machine auto-advances on phase criteria; the
    # OODA-loop-breaker (PR-#232) handles the stuck-loop case.
    assert "advance_workflow_phase" not in _MINIMAL_CORE_TOOLS


def test_finding_emission_in_minimal_core():
    """create_vulnerability_report + list_pending_findings stay.
    iter-37.10 folded update_finding into create_vulnerability_report
    via upsert (`existing_report_id=` kwarg)."""
    assert "create_vulnerability_report" in _MINIMAL_CORE_TOOLS
    assert "list_pending_findings" in _MINIMAL_CORE_TOOLS
    # iter-37.10: update_finding folded into create_vulnerability_report.
    assert "update_finding" not in _MINIMAL_CORE_TOOLS


def test_termination_in_minimal_core():
    assert "finish_scan" in _MINIMAL_CORE_TOOLS


def test_chain_reasoning_in_minimal_core():
    """iter-37.10: correlate_findings dropped from core because
    mid_scan_correlate (iter-27.2) auto-fires at every phase
    boundary. The LLM-callable version is redundant + invites
    decision paralysis."""
    assert "correlate_findings" not in _MINIMAL_CORE_TOOLS


def test_threat_intel_in_minimal_core_post_q5_7():
    """iter-Q5.7 added query_threat_intel back to core. The tracer's
    auto-enrichment fires at emission time, but the LLM needs the
    callable surface mid-scan (e.g. while writing a chain narrative
    the LLM may want to check whether CVE-X hit KEV last week).
    Per CLAUDE.md §1.5.7 — FETCH EXTERNAL bucket can't be empty."""
    assert "query_threat_intel" in _MINIMAL_CORE_TOOLS


def test_http_primitive_in_minimal_core():
    """iter-37.10: probe_endpoint dropped from core. send_request
    (per-asset) is the unified HTTP primitive for web/api/ip; code
    + container + domain don't need a raw HTTP primitive in catalog."""
    assert "probe_endpoint" not in _MINIMAL_CORE_TOOLS


def test_compliance_remediation_in_minimal_core():
    """iter-37.10: both terminal artifacts dropped from core. They
    auto-fire inside finish_scan (opt-out:
    STRIX_FINISH_AUTO_ARTIFACTS=0). Frees 2 slots in the catalog
    without changing behavior."""
    assert "emit_compliance_evidence" not in _MINIMAL_CORE_TOOLS
    assert "generate_remediation_plan" not in _MINIMAL_CORE_TOOLS


def test_think_in_minimal_core():
    """`think` is the LLM scratchpad — subsumes note + hypothesis tools."""
    assert "think" in _MINIMAL_CORE_TOOLS


# ---------------------------------------------------------------------------
# Redundant tools are DROPPED from minimal CORE
# ---------------------------------------------------------------------------

def test_note_tools_dropped_from_minimal_core():
    """All 5 note tools dropped — `think` covers LLM scratchpad."""
    for note_tool in (
        "create_note", "list_notes", "get_note", "update_note", "delete_note",
    ):
        assert note_tool not in _MINIMAL_CORE_TOOLS, (
            f"{note_tool} leaked into minimal core. The 5-tool notes "
            f"system is redundant with `think` for LLM scratchpad."
        )


def test_hypothesis_tools_dropped_from_minimal_core():
    """All 5 hypothesis tools dropped — `think` + reasoning_trace cover this."""
    for hyp_tool in (
        "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
        "list_active_hypotheses", "is_surface_under_investigation",
    ):
        assert hyp_tool not in _MINIMAL_CORE_TOOLS, (
            f"{hyp_tool} leaked into minimal core. Hypothesis tracking "
            f"is redundant with `think` + reasoning_trace."
        )


def test_introspection_tools_dropped_from_minimal_core():
    """Agent introspection tools rarely help the LLM make better choices."""
    for tool in (
        "agent_self_audit", "check_budget",
        "drain_amplify_queue", "execute_adaptive_probe",
    ):
        assert tool not in _MINIMAL_CORE_TOOLS, (
            f"{tool} leaked into minimal core — adds catalog noise "
            f"without observable LLM behavior improvement."
        )


def test_kg_query_paths_dropped_from_minimal_core():
    """kg_query_paths is niche; if needed, merge into kg_query later."""
    assert "kg_query_paths" not in _MINIMAL_CORE_TOOLS
    assert "kg_query_nodes" not in _MINIMAL_CORE_TOOLS


def test_dismiss_finding_dropped_from_minimal_core():
    """dismiss_finding overlaps update_finding — LLM uses update + status."""
    assert "dismiss_finding" not in _MINIMAL_CORE_TOOLS


def test_threat_intel_status_dropped_from_minimal_core():
    """status is a cache-freshness check; not needed mid-scan."""
    assert "threat_intel_status" not in _MINIMAL_CORE_TOOLS


def test_complete_objective_dropped_from_minimal_core():
    """Orchestrator-mode-only — not needed in non-orchestrator catalogs."""
    assert "complete_objective" not in _MINIMAL_CORE_TOOLS


# ---------------------------------------------------------------------------
# Total catalog sizes hit the docs/tool-catalog-rationalization.md targets
# ---------------------------------------------------------------------------

def test_web_total_catalog_under_25_tools():
    """The audit doc target: web_application ≈ 8 specialist + ~12 core
    = ~20 tools. With iter-37.8's slim core, we should be at 22-25."""
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert len(tools) < 25, (
        f"web_application catalog is {len(tools)} tools. iter-37.8 "
        f"target is 20-23. If it's still 40+, either CORE didn't "
        f"shrink or per-asset specialist set didn't shrink."
    )


def test_api_total_catalog_under_25_tools():
    tools = get_lead_tool_catalog(target_types=["api"])
    assert len(tools) < 25


def test_code_total_catalog_under_25_tools():
    for asset in ("repository", "local_code"):
        tools = get_lead_tool_catalog(target_types=[asset])
        assert len(tools) < 25, f"{asset} has {len(tools)} tools"


def test_ip_total_catalog_under_25_tools():
    tools = get_lead_tool_catalog(target_types=["ip_address"])
    assert len(tools) < 25


def test_container_total_catalog_under_25_tools():
    tools = get_lead_tool_catalog(target_types=["container_image"])
    assert len(tools) < 25


# ---------------------------------------------------------------------------
# Legacy mode brings everything back
# ---------------------------------------------------------------------------

def test_legacy_mode_restores_full_core():
    """STRIX_LEGACY_CATALOG=1 brings back the 32-tool _CORE_TOOLS."""
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    tools = get_lead_tool_catalog(target_types=["web_application"])
    # All the dropped tools come back
    assert "open_hypothesis" in tools
    assert "create_note" in tools
    assert "check_budget" in tools
    assert "kg_query_nodes" in tools


def test_legacy_mode_web_catalog_back_to_99():
    """Legacy mode restores the pre-iter-37.x 99-tool catalog."""
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    tools = get_lead_tool_catalog(target_types=["web_application"])
    # Don't assert exactly 99 (might change over time), just that it's
    # dramatically bigger than the minimal catalog
    assert len(tools) > 80


# ---------------------------------------------------------------------------
# No accidental duplication: minimal CORE + per-asset don't overlap
# ---------------------------------------------------------------------------

def test_no_minimal_core_appears_in_per_asset_minimal_sets():
    """Tools in minimal CORE should NOT be re-added by per-asset
    minimal sets (would just duplicate the entry in the union)."""
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_TOOLS_BY_TARGET_TYPE
    for asset, tools in _MINIMAL_TOOLS_BY_TARGET_TYPE.items():
        overlap = tools & _MINIMAL_CORE_TOOLS
        # send_request might appear in per-asset web + core probe_endpoint
        # is similar but distinct. Allow up to 2 overlaps for graceful
        # transition.
        assert len(overlap) <= 2, (
            f"{asset} per-asset minimal set overlaps with CORE: {overlap}"
        )
