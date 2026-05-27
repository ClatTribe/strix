"""Tests for iter-37.10 — minimal CORE trimmed from 13 → 5.

Frame: OODA. The OSS prepass (anchor_prepass) handles OBSERVE+ORIENT
deterministically. L1.5 hooks auto-handle threat-intel enrichment +
mid-scan correlation. So the LLM's core only needs:

  OBSERVE     workflow_status + list_pending_findings
  ORIENT      think
  ACT (emit)  create_vulnerability_report
  TERMINATE   finish_scan

Total: 5 tools. Everything else (advance_workflow_phase,
update_finding, correlate_findings, query_threat_intel,
emit_compliance_evidence, generate_remediation_plan, probe_endpoint,
dispatch_specialist) is either auto-fired by a hook, folded into
another tool, or orchestrator-mode-only.
"""

from __future__ import annotations

import os

import pytest

from strix.agents.lead_agent.tool_catalog import (
    _MINIMAL_CORE_TOOLS,
    get_lead_tool_catalog,
)


@pytest.fixture(autouse=True)
def _clean_env():
    saved_legacy = os.environ.pop("STRIX_LEGACY_CATALOG", None)
    saved_artifacts = os.environ.pop("STRIX_FINISH_AUTO_ARTIFACTS", None)
    try:
        yield
    finally:
        os.environ.pop("STRIX_LEGACY_CATALOG", None)
        os.environ.pop("STRIX_FINISH_AUTO_ARTIFACTS", None)
        if saved_legacy is not None:
            os.environ["STRIX_LEGACY_CATALOG"] = saved_legacy
        if saved_artifacts is not None:
            os.environ["STRIX_FINISH_AUTO_ARTIFACTS"] = saved_artifacts


# ---------------------------------------------------------------------------
# Core size — the headline trim
# ---------------------------------------------------------------------------


def test_minimal_core_has_exactly_6_tools():
    """iter-37.10 trimmed CORE from 13 → 5. iter-Q5.6 added
    get_finding (single-finding deep read companion to
    list_pending_findings) → 6. All 6 belong in READ STATE / ORIENT /
    ACT / TERMINATE buckets per CLAUDE.md §1.5.7."""
    assert len(_MINIMAL_CORE_TOOLS) == 6, (
        f"Minimal core should be exactly 6 tools post iter-Q5.6 "
        f"(workflow_status + list_pending_findings + get_finding + "
        f"think + create_vulnerability_report + finish_scan); "
        f"got {len(_MINIMAL_CORE_TOOLS)}: {sorted(_MINIMAL_CORE_TOOLS)}"
    )


def test_minimal_core_under_6():
    """Belt-and-suspenders bound — the headline target is ≤6 tools,
    so even minor regressions stay caught."""
    assert len(_MINIMAL_CORE_TOOLS) <= 6


# ---------------------------------------------------------------------------
# The 5 essential tools are present
# ---------------------------------------------------------------------------


def test_workflow_status_in_minimal_core():
    """OBSERVE: where am I?"""
    assert "workflow_status" in _MINIMAL_CORE_TOOLS


def test_list_pending_findings_in_minimal_core():
    """OBSERVE: what did L1 surface?"""
    assert "list_pending_findings" in _MINIMAL_CORE_TOOLS


def test_think_in_minimal_core():
    """ORIENT: LLM scratchpad."""
    assert "think" in _MINIMAL_CORE_TOOLS


def test_create_vulnerability_report_in_minimal_core():
    """ACT: emit findings."""
    assert "create_vulnerability_report" in _MINIMAL_CORE_TOOLS


def test_finish_scan_in_minimal_core():
    """TERMINATE: scan-end + auto-fires compliance/remediation."""
    assert "finish_scan" in _MINIMAL_CORE_TOOLS


# ---------------------------------------------------------------------------
# Dropped tools — covered by hooks/folding/mode-gating
# ---------------------------------------------------------------------------


def test_advance_workflow_phase_dropped():
    """Phase advancement is advisory + auto-handled by gates."""
    assert "advance_workflow_phase" not in _MINIMAL_CORE_TOOLS


def test_probe_endpoint_dropped_from_core():
    """HTTP primitive folds into per-asset `send_request`."""
    assert "probe_endpoint" not in _MINIMAL_CORE_TOOLS


def test_update_finding_dropped_from_core():
    """Folded into create_vulnerability_report via upsert semantics
    (pass `existing_report_id` to mutate)."""
    assert "update_finding" not in _MINIMAL_CORE_TOOLS


def test_correlate_findings_dropped_from_core():
    """mid_scan_correlate auto-fires at every phase boundary
    (iter-27.2). LLM-callable correlate is redundant + invites
    decision paralysis (LLM calls it instead of doing real work)."""
    assert "correlate_findings" not in _MINIMAL_CORE_TOOLS


def test_query_threat_intel_dropped_from_core():
    """tracer.add_vulnerability_report auto-enriches every finding
    with CWE/CVE/KEV/EPSS at emission. The LLM-callable lookup is
    redundant for the in-scan path."""
    assert "query_threat_intel" not in _MINIMAL_CORE_TOOLS


def test_emit_compliance_evidence_dropped_from_core():
    """Terminal artifact — auto-fires inside finish_scan."""
    assert "emit_compliance_evidence" not in _MINIMAL_CORE_TOOLS


def test_generate_remediation_plan_dropped_from_core():
    """Terminal artifact — auto-fires inside finish_scan."""
    assert "generate_remediation_plan" not in _MINIMAL_CORE_TOOLS


def test_dispatch_specialist_dropped_from_core():
    """Orchestrator-mode-only — surfaced via _ORCHESTRATOR_ALLOWED_TOOLS
    when STRIX_ORCHESTRATOR_MODE=1, not in normal-mode core."""
    assert "dispatch_specialist" not in _MINIMAL_CORE_TOOLS


# ---------------------------------------------------------------------------
# All dropped tools still execute — they just aren't surfaced
# ---------------------------------------------------------------------------


def test_dropped_tools_still_registered():
    """The dropped tools STAY callable from the registry — only their
    catalog visibility changes. Sandbox tool-server, tests, and legacy
    mode all still see them."""
    from strix.tools.registry import get_tool_names

    registered = set(get_tool_names())
    for tool in (
        "advance_workflow_phase",
        "update_finding",
        "correlate_findings",
        "query_threat_intel",
        "emit_compliance_evidence",
        "generate_remediation_plan",
        "dispatch_specialist",
    ):
        assert tool in registered, (
            f"{tool} should still be REGISTERED — only its catalog "
            f"visibility is changed by iter-37.10."
        )


# ---------------------------------------------------------------------------
# Legacy mode brings everything back
# ---------------------------------------------------------------------------


def test_legacy_mode_restores_dropped_tools():
    """STRIX_LEGACY_CATALOG=1 must restore the pre-iter-37.10 catalog
    so operators relying on these tools can opt out of the trim."""
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    tools = get_lead_tool_catalog(target_types=["web_application"])
    # All the dropped tools come back via _CORE_TOOLS
    assert "advance_workflow_phase" in tools
    assert "update_finding" in tools
    assert "correlate_findings" in tools
    assert "query_threat_intel" in tools


# ---------------------------------------------------------------------------
# Total catalog sizes — iter-37.10 is a step toward the audit doc target
# ---------------------------------------------------------------------------


def test_web_total_catalog_under_16_tools():
    """5 core + 10 per-asset specialist (iter-37.2 minimal) = 15.
    Allow 16 as a safety margin against off-by-one regressions."""
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert len(tools) <= 16, (
        f"web_application catalog is {len(tools)} tools — iter-37.10 "
        f"target is ≤15 (5 core + 10 specialist). If it's still 22+, "
        f"the minimal CORE trim didn't take effect."
    )


def test_container_total_catalog_under_10_tools():
    """5 core + 4 per-asset specialist = 9."""
    tools = get_lead_tool_catalog(target_types=["container_image"])
    assert len(tools) <= 10


def test_code_total_catalog_under_14_tools():
    """5 core + 8 per-asset specialist = 13."""
    for asset in ("repository", "local_code"):
        tools = get_lead_tool_catalog(target_types=[asset])
        assert len(tools) <= 14, f"{asset} has {len(tools)} tools"


# ---------------------------------------------------------------------------
# Anti-overfit: minimal CORE has no overlap with deprecated tools list
# ---------------------------------------------------------------------------


def test_minimal_core_disjoint_from_deprecation_registry():
    """Defensive: a tool in MINIMAL CORE must NOT be in the iter-37.3
    deprecation registry — that would surface deprecation warnings on
    every L2 scan, which is nonsense."""
    try:
        from strix.tools.deprecations import _DEPRECATIONS
    except ImportError:
        pytest.skip("iter-37.3 deprecation registry not present")

    overlap = _MINIMAL_CORE_TOOLS & set(_DEPRECATIONS)
    assert not overlap, (
        f"Tools in MINIMAL CORE that are also deprecated: {overlap}. "
        f"A core tool can't be deprecated — fix one or the other."
    )
