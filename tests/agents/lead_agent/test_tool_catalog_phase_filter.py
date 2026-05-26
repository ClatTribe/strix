"""Tests for the Phase 3d / PR-α phase-filter layer on top of
`get_lead_tool_catalog`.

The catalog is built as:
    (core ∪ per_target_type) − blocked    # before PR-α
    ((core ∪ per_target_type) ∩ phase_allowed) | core   − blocked    # after

The intersection with the phase's allowed set hides off-phase
tools from the lead's prompt — reducing the per-turn cognitive
load to "pick the right tool for THIS phase" instead of "navigate
the full ~85-tool catalog."
"""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.tool_catalog import (
    get_lead_tool_catalog,
    is_tool_allowed_for_lead,
)


# iter-37.10: phase-filter tests assume the LEGACY ~85-tool catalog
# (see module docstring). Under the iter-37.2/37.8/37.10 minimal
# catalogs, the per-asset surface is intentionally too small for the
# phase-filter intersection to remove much. Opt into legacy mode so
# the phase-filter contract is tested against the catalog it was
# designed for.
@pytest.fixture(autouse=True)
def _enable_legacy_catalog(monkeypatch):
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")


# ---------------------------------------------------------------------------
# Backwards-compatibility — phase=None falls back to pre-PR-α behaviour
# ---------------------------------------------------------------------------


def test_phase_none_returns_full_target_type_catalog() -> None:
    """When phase is None (the default — backwards-compatible
    callers), the catalog is the pre-PR-α union of core +
    target-type tools."""
    unfiltered = get_lead_tool_catalog(target_types=["web_application"])
    # Web-app catalog should be substantial.
    assert len(unfiltered) > 50
    # All probe-phase tools are present.
    assert "scan_sqli" in unfiltered
    assert "scan_xss" in unfiltered
    # All recon-phase tools are present (iter-25.11 follow-up:
    # bfs_crawl + fingerprint_tech_stack DROPPED from per-target
    # catalog; replaced by crawl_with_katana + probe_hosts_httpx).
    assert "crawl_with_katana" in unfiltered
    assert "probe_hosts_httpx" in unfiltered


# ---------------------------------------------------------------------------
# Phase filter hides off-phase tools
# ---------------------------------------------------------------------------


def test_recon_phase_hides_probe_specialists() -> None:
    """During recon, the catalog does NOT include the probe
    specialists. The lead can't invoke scan_sqli before recon
    is complete because it doesn't see the tool."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application"], phase="recon",
    )
    assert "scan_sqli" not in catalog
    assert "scan_xss" not in catalog
    assert "scan_idor" not in catalog
    assert "scan_path_traversal" not in catalog
    # Recon tools ARE present. iter-25.11: bfs_crawl +
    # fingerprint_tech_stack dropped; succeeded by crawl_with_katana
    # + probe_hosts_httpx.
    assert "crawl_with_katana" in catalog
    assert "probe_hosts_httpx" in catalog
    assert "well_known_harvest" in catalog


def test_probe_phase_hides_pure_recon_tools() -> None:
    """During probe, the broad-crawl tools are hidden. The lead
    fans out specialists per discovered endpoint instead of
    crawling more."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application"], phase="probe",
    )
    # iter-25.11 follow-up: bfs_crawl + crawl_with_katana are both
    # recon-phase tools and must be absent during probe.
    assert "crawl_with_katana" not in catalog
    assert "webapp_recon_pipeline" not in catalog
    # Specialists ARE present:
    assert "scan_sqli" in catalog
    assert "scan_xss" in catalog
    assert "csrf_check" in catalog


def test_report_phase_is_narrow() -> None:
    """Report phase intentionally surfaces only finish_scan +
    the phase-agnostic surface (workflow control, finding
    emission, threat-intel lookups, reasoning)."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application"], phase="report",
    )
    assert "finish_scan" in catalog
    assert "scan_sqli" not in catalog
    assert "bfs_crawl" not in catalog
    # workflow control + finding emission still present:
    assert "workflow_status" in catalog
    assert "advance_workflow_phase" in catalog
    assert "create_vulnerability_report" in catalog


# ---------------------------------------------------------------------------
# Core tools (workflow_status / hypothesis / findings) survive in every phase
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("phase", [
    "recon", "auth_attempt", "post_auth_recon",
    "probe", "chain_correlation", "report",
])
def test_core_tools_present_in_every_phase(phase) -> None:
    """The lead must be able to:
      * inspect / advance the workflow at any time
      * emit findings the moment evidence is in hand
      * track hypotheses across phases
    These tools are in `_CORE_TOOLS` AND in the phase-agnostic
    set — both belt-and-braces."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application"], phase=phase,
    )
    must_have = {
        "workflow_status",
        "advance_workflow_phase",
        "create_vulnerability_report",
        "update_finding",
        "dismiss_finding",
        "open_hypothesis",
        "confirm_hypothesis",
        "dismiss_hypothesis",
        "list_active_hypotheses",
        "think",
        "correlate_findings",
        "emit_compliance_evidence",
    }
    missing = must_have - catalog
    assert not missing, f"phase {phase} missing core tools: {missing}"


# ---------------------------------------------------------------------------
# Catalog size reduction — quantitative
# ---------------------------------------------------------------------------


def test_phase_filtering_meaningfully_reduces_catalog_size() -> None:
    """The point of phase filtering is to reduce the rendered
    tool surface — fewer tools in the prompt → less token spend +
    smaller cognitive load for the model. Each filtered catalog
    should be measurably smaller than the unfiltered one."""
    unfiltered = get_lead_tool_catalog(target_types=["web_application"])
    by_phase = {
        phase: get_lead_tool_catalog(
            target_types=["web_application"], phase=phase,
        )
        for phase in ("recon", "auth_attempt", "post_auth_recon",
                       "probe", "chain_correlation", "report")
    }
    # Every phase strictly smaller than unfiltered.
    for phase, catalog in by_phase.items():
        assert len(catalog) < len(unfiltered), (
            f"phase {phase} catalog ({len(catalog)}) should be < "
            f"unfiltered ({len(unfiltered)})"
        )
    # Report phase is the tightest (only finish_scan + agnostic).
    assert len(by_phase["report"]) < len(by_phase["probe"])
    assert len(by_phase["report"]) < len(by_phase["recon"])


# ---------------------------------------------------------------------------
# Multi-target-type behaviour
# ---------------------------------------------------------------------------


def test_phase_filter_intersects_with_multi_target_union() -> None:
    """When the run targets multiple asset classes, the per-type
    union is computed first, then the phase filter applies."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application", "repository"],
        phase="recon",
    )
    # Recon-phase tools from BOTH target types should be present.
    # iter-25.11: crawl_with_katana succeeds bfs_crawl for web recon.
    assert "crawl_with_katana" in catalog    # web-app recon
    assert "build_code_map" in catalog       # repo recon
    # Probe-phase specialists hidden.
    assert "scan_sqli" not in catalog


# ---------------------------------------------------------------------------
# is_tool_allowed_for_lead predicate variant
# ---------------------------------------------------------------------------


def test_predicate_respects_phase() -> None:
    """`is_tool_allowed_for_lead` is the predicate-shaped API.
    Should respect the phase argument identically."""
    assert is_tool_allowed_for_lead(
        "scan_sqli",
        target_types=["web_application"],
        phase="probe",
    ) is True
    assert is_tool_allowed_for_lead(
        "scan_sqli",
        target_types=["web_application"],
        phase="recon",
    ) is False
    assert is_tool_allowed_for_lead(
        "workflow_status",
        target_types=["web_application"],
        phase="report",
    ) is True


# ---------------------------------------------------------------------------
# Unknown phase → fail open (no filtering applied)
# ---------------------------------------------------------------------------


def test_unknown_phase_yields_unfiltered_catalog() -> None:
    """An unknown phase string shouldn't crash — the filter
    short-circuits to the unfiltered union (degradation, not
    failure)."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application"], phase="bogus_phase",
    )
    # Same as phase=None.
    unfiltered = get_lead_tool_catalog(target_types=["web_application"])
    assert catalog == unfiltered
