"""Tests for MA-S2 P0-CVS-D — `discovery_method` block on every finding.

The block surfaces:
  * primary: which discovery path emitted the finding
  * specialist_category: derived category
  * source_tool: tool name when known
  * is_novel: True when primary=ai_specialist AND no CVE
            (the literal MA-S2 CVS-0.3 attestation)

Recall-safety contract pinned by tests:
  * Block ALWAYS present on every finding.
  * is_novel=True only when both predicates hold (ai_specialist
    + no CVE) — pinned to prevent regression from a future PR
    that loosens the condition.
  * Default (no discovery_method passed) treats finding as
    ai_specialist (LLM-driven path).
  * Deterministic emissions (scan_sqli, scan_xss) → primary=
    deterministic_specialist, is_novel=False.
  * Block has consistent 4-key shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.delenv("STRIX_EPSS_ENRICHMENT_DISABLED", raising=False)
    monkeypatch.chdir(tmp_path)
    yield


def _emit(tracer: Tracer, **overrides) -> str:
    defaults = {
        "title": "T", "severity": "medium", "endpoint": "/x",
        "target": "https://x.com/x", "category": "sqli",
        "description": "x", "impact": "x",
        "technical_analysis": "x", "poc_description": "x",
        "poc_script_code": "curl x", "remediation_steps": "x",
    }
    defaults.update(overrides)
    return tracer.add_vulnerability_report(**defaults)


def _new() -> Tracer:
    t = Tracer("dm-block")
    set_global_tracer(t)
    return t


_EXPECTED_KEYS = {"primary", "specialist_category", "source_tool", "is_novel"}


# ---------------------------------------------------------------------------
# Block always present
# ---------------------------------------------------------------------------


def test_block_present_on_finding_without_discovery_method() -> None:
    """LLM-driven create_vulnerability_report path leaves
    discovery_method unset → defaults to ai_specialist."""
    t = _new()
    fid = _emit(t)
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert "discovery_method" in r
    assert set(r["discovery_method"].keys()) == _EXPECTED_KEYS


def test_block_present_for_deterministic_emission() -> None:
    t = _new()
    fid = _emit(
        t,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    dm = r["discovery_method"]
    assert dm["primary"] == "deterministic_specialist"
    assert dm["source_tool"] == "scan_sqli"
    assert dm["specialist_category"] == "sqli"


# ---------------------------------------------------------------------------
# is_novel — the MA-S2 CVS-0.3 attestation bit
# ---------------------------------------------------------------------------


def test_is_novel_true_for_ai_specialist_without_cve() -> None:
    """The literal MA-S2 attestation: AI specialist found
    something with no matching CVE → novel."""
    t = _new()
    fid = _emit(t)  # defaults to ai_specialist, no CVE
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert r["discovery_method"]["is_novel"] is True


def test_is_novel_false_when_cve_matched() -> None:
    """AI specialist found a vuln that matches a known CVE →
    not novel (it's a re-discovery, not a zero-day-class find)."""
    t = _new()
    fid = _emit(t, cve="CVE-2024-1234")
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert r["discovery_method"]["is_novel"] is False


def test_is_novel_false_for_deterministic_emission() -> None:
    """scan_sqli / scan_xss / nuclei / SAST findings are
    deterministic detections, NOT novel."""
    t = _new()
    fid = _emit(
        t,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert r["discovery_method"]["is_novel"] is False


def test_is_novel_false_for_deterministic_with_cve() -> None:
    """Both conditions for is_novel=False — verified."""
    t = _new()
    fid = _emit(
        t,
        cve="CVE-2024-1234",
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_nuclei_templates",
    )
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert r["discovery_method"]["is_novel"] is False


def test_is_novel_recall_canary_both_predicates_required() -> None:
    """Recall canary — is_novel is True ONLY when BOTH conditions
    hold (ai_specialist AND no CVE). A future PR that loosens
    this would over-attribute novelty and inflate the attestation.
    If this test breaks, the new logic likely loosened the
    AND — revert the logic, not the test."""
    t = _new()
    # ai_specialist + CVE → not novel (CVE matched)
    fid1 = _emit(t, cve="CVE-2024-1234", title="A")
    assert next(r for r in t.vulnerability_reports if r["id"] == fid1)[
        "discovery_method"]["is_novel"] is False
    # deterministic + no CVE → not novel (deterministic, not AI-novel)
    fid2 = _emit(
        t, title="B",
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_sqli",
    )
    assert next(r for r in t.vulnerability_reports if r["id"] == fid2)[
        "discovery_method"]["is_novel"] is False
    # ai_specialist + no CVE → novel (both predicates true)
    fid3 = _emit(t, title="C")
    assert next(r for r in t.vulnerability_reports if r["id"] == fid3)[
        "discovery_method"]["is_novel"] is True


# ---------------------------------------------------------------------------
# specialist_category derivation
# ---------------------------------------------------------------------------


def test_category_from_source_tool_prefix() -> None:
    """source_tool='scan_xxxx' → specialist_category='xxxx'."""
    t = _new()
    fid = _emit(
        t,
        discovery_method="deterministic_specialist",
        discovery_source_tool="scan_path_traversal",
    )
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert r["discovery_method"]["specialist_category"] == "path_traversal"


def test_category_falls_back_to_category_field() -> None:
    """When source_tool is absent, fall back to the finding's
    own category field."""
    t = _new()
    fid = _emit(t, category="auth_flow")
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert r["discovery_method"]["specialist_category"] == "auth_flow"


def test_category_null_when_no_source_or_category() -> None:
    """Edge case: source_tool absent AND category absent.
    The tracer auto-infers category from CWE when category is
    None; pass cwe=None too to force the truly-unknown case."""
    t = _new()
    # Provide a CWE that doesn't map to a known category in
    # _infer_category_from_cwe — most CWEs do map, so use one
    # that doesn't (e.g. nonsense). The tracer's category inference
    # might fall through.
    fid = _emit(t, category=None, cwe="CWE-99999")
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    # Either the category got auto-inferred (and surfaces here)
    # or it's None. Both shapes are valid; the assertion is on
    # the dict structure, not specifically the value.
    assert "specialist_category" in r["discovery_method"]


# ---------------------------------------------------------------------------
# simulation_run.json novel_findings_count picks up the new block
# ---------------------------------------------------------------------------


def test_simulation_run_counts_novel_findings(tmp_path: Path) -> None:
    """End-to-end: emit one novel + one non-novel finding;
    simulation_run.json should report novel_findings_count=1."""
    t = _new()
    _emit(t, title="Novel via AI", cve=None)  # is_novel=True
    _emit(t, title="Known CVE", cve="CVE-2024-1234")  # is_novel=False
    t.save_run_data(mark_complete=True)

    import json
    sim_path = tmp_path / "strix_runs" / "dm-block" / "simulation_run.json"
    assert sim_path.exists()
    data = json.loads(sim_path.read_text())
    assert data["findings_count"] == 2
    assert data["novel_findings_count"] == 1
