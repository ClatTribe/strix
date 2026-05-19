"""Tests for V3-3 — templated quick-mode report renderer.

Pins:
  * Renderer is deterministic + byte-stable for a given input.
  * Empty findings produces a non-empty templated report
    (passes finish_scan's validation).
  * Per-severity grouping uses canonical ordering.
  * CWE-template fields (recommended_action, fix_time_estimate)
    are used when present; falls back to the finding's own
    remediation_steps otherwise.
  * Kill switch (`STRIX_QUICK_TEMPLATED_REPORT_DISABLED=1`) makes
    `should_apply_template()` return False.
  * Mode gating — only quick / initial trigger the template.
"""

from __future__ import annotations

import pytest

from strix.tools.finish.quick_report_renderer import (
    is_disabled,
    is_quick_mode,
    render_executive_summary,
    render_methodology,
    render_quick_report,
    render_recommendations,
    render_technical_analysis,
    should_apply_template,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_QUICK_TEMPLATED_REPORT_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Mode gating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode,expected", [
    ("quick", True),
    ("initial", True),
    ("standard", False),
    ("deep", False),
    ("", False),
])
def test_is_quick_mode_gating(
    monkeypatch: pytest.MonkeyPatch, mode: str, expected: bool,
) -> None:
    if mode:
        monkeypatch.setenv("STRIX_SCAN_MODE", mode)
    assert is_quick_mode() is expected


def test_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_QUICK_TEMPLATED_REPORT_DISABLED", "1")
    assert is_disabled() is True


def test_should_apply_template_in_quick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    assert should_apply_template() is True


def test_should_apply_template_kill_switch_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_QUICK_TEMPLATED_REPORT_DISABLED", "1")
    assert should_apply_template() is False


def test_should_apply_template_skips_standard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")
    assert should_apply_template() is False


# ---------------------------------------------------------------------------
# render_executive_summary
# ---------------------------------------------------------------------------


def test_summary_empty_findings_explicit() -> None:
    """Empty findings → an explicit "no findings" message, not
    generic prose that hides the result."""
    out = render_executive_summary([], None)
    assert "no findings" in out.lower()
    assert "deterministic stack" in out.lower()


def test_summary_with_findings_lists_counts_and_severity() -> None:
    findings = [
        {"severity": "critical", "title": "RCE", "cwe": "CWE-78"},
        {"severity": "high", "title": "SQLi", "cwe": "CWE-89"},
        {"severity": "high", "title": "XSS", "cwe": "CWE-79"},
        {"severity": "low", "title": "Banner", "cwe": "CWE-200"},
    ]
    out = render_executive_summary(findings, None)
    assert "4 finding" in out  # total count
    assert "1 critical" in out
    assert "2 high" in out
    assert "1 low" in out
    assert "critical" in out  # highest severity


def test_summary_uses_target_url() -> None:
    findings = [{"severity": "low", "title": "x"}]
    scan_config = {"targets": [{"original": "https://vampi.local"}]}
    out = render_executive_summary(findings, scan_config)
    assert "vampi.local" in out


def test_summary_multiple_targets_summarized() -> None:
    findings = []
    scan_config = {
        "targets": [
            {"original": "https://a.com"},
            {"original": "https://b.com"},
            {"original": "https://c.com"},
        ],
    }
    out = render_executive_summary(findings, scan_config)
    assert "3 targets" in out


# ---------------------------------------------------------------------------
# render_methodology — stable across quick-mode runs
# ---------------------------------------------------------------------------


def test_methodology_is_deterministic() -> None:
    """Methodology block is byte-stable regardless of inputs."""
    out1 = render_methodology(None)
    out2 = render_methodology({"targets": []})
    assert out1 == out2


def test_methodology_names_phase_sequence() -> None:
    out = render_methodology(None)
    assert "Recon" in out
    assert "Probing" in out
    assert "Verification" in out
    assert "Report" in out
    # Mentions quick-mode's not-in-scope work
    assert "business-logic" in out.lower() or "business logic" in out.lower()


# ---------------------------------------------------------------------------
# render_technical_analysis — per-severity grouping
# ---------------------------------------------------------------------------


def test_technical_analysis_empty() -> None:
    out = render_technical_analysis([])
    assert "no findings were emitted" in out.lower()
    assert "deterministic" in out.lower()


def test_technical_analysis_groups_by_severity() -> None:
    findings = [
        {"severity": "high", "title": "A", "description": "...", "endpoint": "/a"},
        {"severity": "critical", "title": "B", "description": "...", "endpoint": "/b"},
        {"severity": "high", "title": "C", "description": "...", "endpoint": "/c"},
    ]
    out = render_technical_analysis(findings)
    # Critical section appears before HIGH (canonical severity order)
    crit_idx = out.find("CRITICAL")
    high_idx = out.find("HIGH")
    assert crit_idx >= 0 and high_idx >= 0
    assert crit_idx < high_idx


def test_technical_analysis_truncates_long_descriptions() -> None:
    """Very long descriptions get trimmed to keep the report
    scannable; full text stays in findings.json."""
    findings = [{
        "severity": "low",
        "title": "x",
        "endpoint": "/x",
        "description": "A " * 500,  # 1000 chars
    }]
    out = render_technical_analysis(findings)
    # The full 1000 chars wouldn't fit; we cap at ~280
    assert out.count("A ") < 200  # truncated


# ---------------------------------------------------------------------------
# render_recommendations — uses CWE-template fields
# ---------------------------------------------------------------------------


def test_recommendations_empty() -> None:
    out = render_recommendations([])
    assert "no remediation actions" in out.lower()


def test_recommendations_prefers_recommended_action() -> None:
    """When the v2-step-7 CWE template filled in recommended_action,
    that wins over remediation_steps for the per-finding remediation
    line."""
    findings = [{
        "severity": "high",
        "title": "SQLi",
        "recommended_action": "Use parameterized queries.",
        "remediation_steps": "Long-form remediation goes here. " * 30,
        "fix_time_estimate": "1-4 hours",
    }]
    out = render_recommendations(findings)
    assert "parameterized queries" in out.lower()
    assert "1-4 hours" in out  # fix_time_estimate surfaced


def test_recommendations_falls_back_to_remediation_steps() -> None:
    """When recommended_action is absent, the finding's own
    remediation_steps is used."""
    findings = [{
        "severity": "medium",
        "title": "x",
        "remediation_steps": "Add a CSP header.",
    }]
    out = render_recommendations(findings)
    assert "CSP" in out


def test_recommendations_groups_by_severity() -> None:
    findings = [
        {"severity": "low", "title": "L"},
        {"severity": "critical", "title": "C"},
        {"severity": "medium", "title": "M"},
    ]
    out = render_recommendations(findings)
    # Critical first, then medium, then low (canonical order)
    c_idx = out.find("CRITICAL")
    m_idx = out.find("MEDIUM")
    l_idx = out.find("LOW")
    assert 0 <= c_idx < m_idx < l_idx


# ---------------------------------------------------------------------------
# render_quick_report — top-level (returns dict with all 4 fields)
# ---------------------------------------------------------------------------


def test_render_quick_report_returns_all_fields() -> None:
    out = render_quick_report([], None)
    assert set(out.keys()) == {
        "executive_summary",
        "methodology",
        "technical_analysis",
        "recommendations",
    }
    # All non-empty (passes finish_scan validation)
    for v in out.values():
        assert isinstance(v, str)
        assert v.strip()


def test_render_quick_report_is_deterministic() -> None:
    """Recall canary — same findings + scan_config produce
    byte-identical output. Required so re-scans of the same
    target produce stable report diffs."""
    findings = [{"severity": "low", "title": "x"}]
    config = {"targets": [{"original": "https://x.com"}]}
    out1 = render_quick_report(findings, config)
    out2 = render_quick_report(findings, config)
    assert out1 == out2


# ---------------------------------------------------------------------------
# Recall canary — finding shape from benchmarks lands in the report
# ---------------------------------------------------------------------------


def test_recall_canary_finding_lands_in_templated_report() -> None:
    """If a deterministic specialist (scan_sqli) emits a must_find
    finding, the templated report MUST include it. A renderer bug
    that drops findings on the floor would be a recall regression."""
    findings = [{
        "severity": "high",
        "title": "SQL injection on /api/users",
        "cwe": "CWE-89",
        "endpoint": "/api/users",
        "description": "Union-based SQLi via username field.",
        "recommended_action": "Use parameterized queries.",
        "fix_time_estimate": "1-4 hours",
    }]
    out = render_quick_report(findings, None)
    assert "SQL injection" in out["technical_analysis"]
    assert "/api/users" in out["technical_analysis"]
    assert "parameterized queries" in out["recommendations"].lower()
    assert "1 high" in out["executive_summary"]
