"""Integration tests for `strix.sast.tools.scan_sast` — Phase 7
LLM-facing specialist.

Tests use a fake Semgrep runner so they don't require Semgrep
installed. The `@register_specialist_tool` decorator coerces the
return value to `SpecialistResult.model_dump()`, so result is
treated as a dict.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from strix.sast.semgrep_runner import SemgrepResult, SastFinding
from strix.sast.tools import scan_sast


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_finding(
    rule_id: str = "strix-test",
    file: str = "src/handler.js",
    line: int = 1,
    cwe: str | None = "CWE-89",
    category: str | None = "sqli",
    severity: str = "high",
) -> SastFinding:
    return SastFinding(
        rule_id=rule_id,
        file=file,
        line_start=line,
        line_end=line,
        message=f"matched {rule_id}",
        severity=severity,
        cwe=cwe,
        category=category,
        language="javascript",
    )


def _make_repo(tmp_path: Path) -> Path:
    """Build a minimal repo dir with a file the rule "matched"."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.js").write_text("// stub\n")
    return repo


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_returns_partial_when_semgrep_missing(tmp_path: Path) -> None:
    """No Semgrep on PATH → status=partial with install hint, NOT
    an error. The lead-agent loop reads this as a recoverable
    condition and continues with other specialists."""
    repo = _make_repo(tmp_path)
    with patch("strix.sast.tools.is_semgrep_available", return_value=False):
        result = scan_sast(repo_path=str(repo))
    assert result["status"] == "partial"
    assert "semgrep" in (result.get("error") or "").lower()
    assert result["tool_metadata"]["engine_available"] is False


def test_returns_error_for_missing_repo_path() -> None:
    result = scan_sast(repo_path="")
    assert result["status"] == "error"


def test_returns_error_for_nonexistent_dir(tmp_path: Path) -> None:
    result = scan_sast(repo_path=str(tmp_path / "nope"))
    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# Happy path — findings emitted with calibrated severity
# ---------------------------------------------------------------------------


def test_emits_findings_from_fake_runner(tmp_path: Path) -> None:
    """Inject a fake Semgrep result; confirm findings show up
    in the SpecialistResult with category + cwe propagated."""
    repo = _make_repo(tmp_path)
    fake = SemgrepResult(
        status="ok",
        findings=[_fake_finding(rule_id="strix-sql")],
        files_scanned=1, rules_run=10,
    )
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo))
    assert result["status"] == "ok"
    findings = result["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "sqli"
    assert f["cwe"] == "CWE-89"
    assert "strix-sql" in f["title"]


def test_route_reachable_finding_bumped_to_critical(tmp_path: Path) -> None:
    """When code_map.json declares the finding's file as a route
    handler, severity bumps from high → critical."""
    repo = _make_repo(tmp_path)
    code_map = {
        "schema_version": 1,
        "routes": [{"file": "src/handler.js"}],
    }
    (repo / "code_map.json").write_text(json.dumps(code_map))

    fake = SemgrepResult(
        status="ok",
        findings=[_fake_finding(file="src/handler.js", severity="high")],
        files_scanned=1,
    )
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo))
    assert result["status"] == "ok"
    f = result["findings"][0]
    assert f["severity"] == "critical"
    # Title carries the calibration breadcrumb.
    assert "calibrated:high→critical" in f["title"]
    assert result["tool_metadata"]["calibration"]["bumped"] == 1


def test_test_file_demoted_to_low(tmp_path: Path) -> None:
    """Findings in test files demote from high → medium."""
    repo = _make_repo(tmp_path)
    fake = SemgrepResult(
        status="ok",
        findings=[_fake_finding(
            file="tests/test_handler.py", severity="high",
        )],
        files_scanned=1,
    )
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo))
    f = result["findings"][0]
    assert f["severity"] == "medium"
    assert result["tool_metadata"]["calibration"]["demoted"] == 1


def test_max_findings_caps_output(tmp_path: Path) -> None:
    """When Semgrep returns 100 findings and max_findings=5, we
    keep the 5 highest-severity ones."""
    repo = _make_repo(tmp_path)
    findings_in = [
        _fake_finding(rule_id=f"r-{i}", severity="medium")
        for i in range(100)
    ]
    # Add three high-severity ones we expect to keep.
    findings_in[:3] = [
        _fake_finding(rule_id=f"high-{i}", severity="high")
        for i in range(3)
    ]
    fake = SemgrepResult(status="ok", findings=findings_in, files_scanned=1)

    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo), max_findings=5)
    assert len(result["findings"]) == 5
    # The 3 highs should all be kept, plus 2 mediums to fill the cap.
    high_count = sum(1 for f in result["findings"] if f["severity"] == "high")
    assert high_count == 3


def test_runner_error_propagates_as_error(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    fake = SemgrepResult(status="error", error="semgrep crashed", findings=[])
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo))
    assert result["status"] == "error"
    assert "crashed" in (result.get("error") or "")


def test_partial_status_propagates(tmp_path: Path) -> None:
    """When Semgrep returns partial (rule-parse errors), the tool
    surface should also be partial — but findings still emit."""
    repo = _make_repo(tmp_path)
    fake = SemgrepResult(
        status="partial",
        findings=[_fake_finding()],
        files_scanned=1,
    )
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo))
    assert result["status"] == "partial"
    assert len(result["findings"]) == 1


def test_tool_metadata_shape(tmp_path: Path) -> None:
    """Pin the keys wrappers depend on for dashboard rendering."""
    repo = _make_repo(tmp_path)
    fake = SemgrepResult(
        status="ok", findings=[_fake_finding()],
        files_scanned=10, rules_run=42,
        config_paths=["/path/to/rules"],
    )
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo))
    md = result["tool_metadata"]
    for k in (
        "engine", "engine_available", "diff_scope",
        "files_scanned", "rules_run", "config_paths",
        "findings_total", "findings_emitted_to_tracer",
        "calibration",
    ):
        assert k in md, (k, md)
    assert md["engine"] == "semgrep"
    assert md["files_scanned"] == 10
    assert md["rules_run"] == 42


# ---------------------------------------------------------------------------
# Diff-aware mode
# ---------------------------------------------------------------------------


def test_diff_aware_no_changes_returns_empty_ok(tmp_path: Path) -> None:
    """An empty diff means the PR has no source changes — should
    return ok with zero findings, NOT fall back to full repo
    scan."""
    repo = _make_repo(tmp_path)
    from strix.sast.diff import DiffScope

    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.git_changed_files",
               return_value=DiffScope(usable=True, files=[])):
        result = scan_sast(repo_path=str(repo), since_commit="HEAD~1")
    assert result["status"] == "ok"
    assert result["findings"] == []
    assert result["tool_metadata"]["diff_scope"]["applied"] is True


def test_diff_aware_resolution_failure_falls_back_to_full_scan(
    tmp_path: Path,
) -> None:
    """When diff resolution fails (not a git repo, bad ref),
    scan_sast falls back to a full repo scan rather than scanning
    nothing. The metadata records the fallback."""
    repo = _make_repo(tmp_path)
    from strix.sast.diff import DiffScope

    fake = SemgrepResult(status="ok", findings=[_fake_finding()], files_scanned=1)
    with patch("strix.sast.tools.is_semgrep_available", return_value=True), \
         patch("strix.sast.tools.git_changed_files",
               return_value=DiffScope(usable=False, error="not a git repo")), \
         patch("strix.sast.tools.run_semgrep", return_value=fake):
        result = scan_sast(repo_path=str(repo), since_commit="origin/main")
    # Findings still flowed through.
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    assert result["tool_metadata"]["diff_scope"]["applied"] is False
    assert "not a git repo" in (
        result["tool_metadata"]["diff_scope"]["error"] or ""
    )


# ---------------------------------------------------------------------------
# Lead-agent catalog placement
# ---------------------------------------------------------------------------


def test_scan_sast_in_repository_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    cat = get_lead_tool_catalog(target_types=["repository"])
    assert "scan_sast" in cat


def test_scan_sast_in_local_code_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    cat = get_lead_tool_catalog(target_types=["local_code"])
    assert "scan_sast" in cat


def test_scan_sast_in_web_application_catalog() -> None:
    """SAST belongs in the web catalog too — co-located vibe-coded
    SaaS workflows scan URL + repo together."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    cat = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_sast" in cat


def test_scan_sast_not_in_pure_network_catalogs() -> None:
    """Domain / IP targets don't have source — SAST has nothing
    to scan. Keep it out of those catalogs."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    for tt in ("domain", "ip_address"):
        cat = get_lead_tool_catalog(target_types=[tt])
        assert "scan_sast" not in cat, tt
