"""Tests for iter-26.2 + 26.7 — `list_pending_findings`."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.findings.list_findings import list_pending_findings


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


def _f(**kw):
    """Default-fill a finding dict."""
    d = {
        "id": kw.pop("id", "vuln-0001"),
        "title": kw.pop("title", "Title"),
        "severity": kw.pop("severity", "medium"),
        "cwe": kw.pop("cwe", ""),
    }
    d.update(kw)
    return d


# --------------------------------------------------------------------
# Sorting
# --------------------------------------------------------------------

def test_critical_surface_beats_high_severity(fake_tracer):
    """A critical-surface medium finding ranks above a high-severity
    normal-surface finding."""
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", severity="high",
           surface_priority={"label": "normal"}),
        _f(id="vuln-B", severity="medium",
           surface_priority={"label": "critical"}),
    ]
    out = list_pending_findings()
    ids = [row["id"] for row in out["findings"]]
    assert ids[0] == "vuln-B"
    assert ids[1] == "vuln-A"


def test_exploitability_breaks_ties_within_label(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", severity="medium",
           surface_priority={"label": "high"},
           exploitability={"composite": 0.3}),
        _f(id="vuln-B", severity="medium",
           surface_priority={"label": "high"},
           exploitability={"composite": 0.85}),
    ]
    out = list_pending_findings()
    ids = [row["id"] for row in out["findings"]]
    assert ids[0] == "vuln-B"


def test_severity_breaks_final_tie(fake_tracer):
    """Same surface label + same composite → severity decides."""
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", severity="medium",
           surface_priority={"label": "normal"},
           exploitability={"composite": 0.5}),
        _f(id="vuln-B", severity="critical",
           surface_priority={"label": "normal"},
           exploitability={"composite": 0.5}),
    ]
    out = list_pending_findings()
    ids = [row["id"] for row in out["findings"]]
    assert ids[0] == "vuln-B"


# --------------------------------------------------------------------
# Demotion filter
# --------------------------------------------------------------------

def test_noise_hidden_by_default(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A"),
        _f(id="vuln-B", noise=True),
    ]
    out = list_pending_findings()
    ids = [row["id"] for row in out["findings"]]
    assert "vuln-B" not in ids
    assert out["demoted_hidden"] == 1


def test_corroborator_hidden_by_default(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A"),
        _f(id="vuln-B", role="corroborator", corroborates="vuln-A"),
    ]
    out = list_pending_findings()
    ids = [row["id"] for row in out["findings"]]
    assert "vuln-B" not in ids


def test_include_demoted_surfaces_noise(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A"),
        _f(id="vuln-B", noise=True),
    ]
    out = list_pending_findings(include_demoted=True)
    ids = [row["id"] for row in out["findings"]]
    assert "vuln-B" in ids
    assert out["demoted_hidden"] == 0


# --------------------------------------------------------------------
# Severity floor
# --------------------------------------------------------------------

def test_severity_floor_filters_low(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", severity="low"),
        _f(id="vuln-B", severity="high"),
        _f(id="vuln-C", severity="info"),
    ]
    out = list_pending_findings(severity_floor="medium")
    ids = [row["id"] for row in out["findings"]]
    assert "vuln-B" in ids
    assert "vuln-A" not in ids
    assert "vuln-C" not in ids


# --------------------------------------------------------------------
# Limit + truncation
# --------------------------------------------------------------------

def test_limit_truncates(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id=f"vuln-{i:04d}") for i in range(50)
    ]
    out = list_pending_findings(limit=10)
    assert out["shown"] == 10
    assert out["truncated_tail"] == 40


# --------------------------------------------------------------------
# Row annotations
# --------------------------------------------------------------------

def test_row_includes_kev_annotation(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", kev={"is_kev": True}),
    ]
    out = list_pending_findings()
    assert "KEV" in out["findings"][0]["annotations"]


def test_row_includes_corroborated_annotation(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", corroborated_by=["vuln-X", "vuln-Y"]),
    ]
    out = list_pending_findings()
    annotations = out["findings"][0]["annotations"]
    assert any("corroborated×2" in a for a in annotations)


def test_row_includes_pending_dast_annotation(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", pending_confirmations=[{"tool": "scan_sqli_sqlmap"}]),
    ]
    out = list_pending_findings()
    annotations = out["findings"][0]["annotations"]
    assert any("pending-dast" in a for a in annotations)


def test_row_includes_exploited_annotation(fake_tracer):
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", verification_status="exploited"),
    ]
    out = list_pending_findings()
    assert "EXPLOITED" in out["findings"][0]["annotations"]


# --------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------

def test_empty_tracer_returns_zero(fake_tracer):
    fake_tracer.vulnerability_reports = []
    out = list_pending_findings()
    assert out["total"] == 0
    assert out["shown"] == 0


def test_findings_without_l15_fields_default_neutral(fake_tracer):
    """Findings emitted before L1.5 was wired in still need to rank."""
    fake_tracer.vulnerability_reports = [
        _f(id="vuln-A", severity="medium"),  # no surface_priority / exploitability
        _f(id="vuln-B", severity="critical",
           surface_priority={"label": "low"}),
    ]
    out = list_pending_findings()
    # vuln-A has label rank 1 (normal default); vuln-B has label rank 0 (low)
    # So vuln-A should rank above vuln-B despite the severity difference.
    ids = [row["id"] for row in out["findings"]]
    assert ids[0] == "vuln-A"


def test_no_tracer_returns_partial(monkeypatch):
    """When tracer not initialised, return partial without crashing."""
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: None,
    )
    out = list_pending_findings()
    assert out["status"] == "partial"
    assert out["total"] == 0


def test_registered():
    """Tool registered via @register_tool."""
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("list_pending_findings"))
