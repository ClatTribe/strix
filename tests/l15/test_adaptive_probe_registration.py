"""Tests for iter-26.11 — `execute_adaptive_probe` registered in catalog."""

from __future__ import annotations


def test_adaptive_probe_registered():
    """The escape-hatch tool must be discoverable via the registry."""
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("execute_adaptive_probe"))


def test_adaptive_probe_in_lead_core_tools():
    """The tool must be in the Lead's _CORE_TOOLS set so every
    target_type catalog includes it."""
    from strix.agents.lead_agent.tool_catalog import _CORE_TOOLS
    assert "execute_adaptive_probe" in _CORE_TOOLS


def test_list_pending_findings_in_lead_core_tools():
    """Wave 1 sanity: list_pending_findings still in catalog."""
    from strix.agents.lead_agent.tool_catalog import _CORE_TOOLS
    assert "list_pending_findings" in _CORE_TOOLS
