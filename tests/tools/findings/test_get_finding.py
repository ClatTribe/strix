"""Tests for iter-Q5.6 — `get_finding(id)`.

Single-finding deep-read companion to `list_pending_findings`. Pure
READ STATE per CLAUDE.md §1.5.6 — the tracer's vulnerability_reports
list lives outside the LLM's conversation context.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.findings.list_findings import get_finding


@pytest.fixture
def fake_tracer(monkeypatch):
    """Inject a fake tracer with controllable vulnerability_reports."""
    tracer = MagicMock()
    tracer.vulnerability_reports = []
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: tracer,
    )
    return tracer


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_returns_full_report_when_id_matches(fake_tracer):
    full = {
        "id": "vuln-1",
        "title": "SQL injection at /api/users",
        "severity": "critical",
        "cwe": "CWE-89",
        "endpoint": "/api/users",
        "description": "Detailed description of the SQLi vector",
        "technical_analysis": "Long-form technical analysis text",
        "poc_description": "Step-by-step PoC walkthrough",
        "remediation_steps": "Patch suggestion 1, 2, 3",
        "kill_chain": "<chain>...</chain>",
        "chain_summary": "CSRF + open redirect = ATO",
        "corroborated_by": ["scan_sqli", "scan_nuclei_templates"],
        "exploitability": {"composite": 0.92, "level": "high"},
        "surface_priority": {"label": "critical"},
    }
    fake_tracer.vulnerability_reports = [full]

    out = get_finding("vuln-1")

    assert out["success"] is True
    assert out["status"] == "ok"
    assert out["report_id"] == "vuln-1"
    assert out["finding"] == full
    # Every load-bearing field surfaces.
    assert "description" in out["finding"]
    assert "technical_analysis" in out["finding"]
    assert "chain_summary" in out["finding"]
    assert "corroborated_by" in out["finding"]


def test_returned_finding_is_a_shallow_copy(fake_tracer):
    """Mutating the returned dict must not corrupt tracer state."""
    original = {"id": "vuln-1", "title": "x", "severity": "high"}
    fake_tracer.vulnerability_reports = [original]
    out = get_finding("vuln-1")
    out["finding"]["title"] = "MUTATED"
    # Original in tracer is untouched.
    assert fake_tracer.vulnerability_reports[0]["title"] == "x"


# ---------------------------------------------------------------------------
# Not found
# ---------------------------------------------------------------------------


def test_returns_not_found_for_unknown_id(fake_tracer):
    fake_tracer.vulnerability_reports = [
        {"id": "vuln-1", "title": "x"},
        {"id": "vuln-2", "title": "y"},
    ]
    out = get_finding("vuln-99")
    assert out["success"] is True
    assert out["status"] == "not_found"
    assert out["report_id"] == "vuln-99"
    assert "list_pending_findings" in out["reason"]
    assert "finding" not in out


def test_returns_not_found_when_tracer_is_empty(fake_tracer):
    fake_tracer.vulnerability_reports = []
    out = get_finding("vuln-1")
    assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_id", ["", "   ", None, 42, [], {}])
def test_rejects_empty_or_non_string_id(bad_id):
    out = get_finding(bad_id)
    assert out["success"] is False
    assert out["status"] == "error"
    assert "report_id is required" in out["reason"]


def test_strips_whitespace_from_id(fake_tracer):
    fake_tracer.vulnerability_reports = [{"id": "vuln-1", "title": "x"}]
    out = get_finding("  vuln-1  ")
    assert out["status"] == "ok"
    assert out["report_id"] == "vuln-1"


# ---------------------------------------------------------------------------
# Tracer-uninitialised path
# ---------------------------------------------------------------------------


def test_returns_partial_when_tracer_is_none(monkeypatch):
    """Before scan starts, tracer may be None; tool must not crash."""
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: None,
    )
    out = get_finding("vuln-1")
    assert out["success"] is True
    assert out["status"] == "partial"
    assert "tracer not initialised" in out["reason"]


def test_handles_tracer_lookup_exception(monkeypatch):
    """Defensive — any exception during tracer access returns
    success=False, never raises."""
    def _raises():
        raise RuntimeError("tracer module broken")
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        _raises,
    )
    out = get_finding("vuln-1")
    assert out["success"] is False
    assert out["status"] == "error"
    assert "tracer lookup failed" in out["reason"]


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_get_finding_is_registered():
    """get_finding must be available via @register_tool so the
    L2 lead can call it."""
    from strix.tools.registry import get_tool_by_name, get_tool_names
    assert "get_finding" in get_tool_names()
    fn = get_tool_by_name("get_finding")
    assert fn is not None
    assert callable(fn)


def test_get_finding_in_minimal_core_catalog():
    """iter-Q5.6: get_finding is added to _MINIMAL_CORE_TOOLS so
    every asset type's lead sees it (universal READ STATE primitive)."""
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_CORE_TOOLS
    assert "get_finding" in _MINIMAL_CORE_TOOLS


# ---------------------------------------------------------------------------
# Companion to list_pending_findings — ID round-trip
# ---------------------------------------------------------------------------


def test_get_finding_round_trips_with_list_pending_findings(fake_tracer):
    """End-to-end: pick an ID from list_pending_findings, pass to
    get_finding, get full record back."""
    fake_tracer.vulnerability_reports = [
        {"id": "vuln-a", "title": "A", "severity": "high"},
        {"id": "vuln-b", "title": "B", "severity": "critical",
         "surface_priority": {"label": "critical"}},
    ]
    from strix.tools.findings.list_findings import list_pending_findings
    listed = list_pending_findings()
    # Pick the top-ranked row (should be vuln-b — critical surface).
    top_id = listed["findings"][0]["id"]
    out = get_finding(top_id)
    assert out["status"] == "ok"
    assert out["finding"]["id"] == top_id
