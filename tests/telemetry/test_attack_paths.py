"""Tests for MA-S2 P0-APM-A — attack_paths.jsonl attestation.

Recall-safety contract pinned by tests:
  * File ALWAYS written at scan completion (even when zero
    qualifying chains — MA-S2 attestation discipline).
  * Only chains with ≥2 stages AND at least one HIGH/CRITICAL
    finding emit (conservative threshold; lower-tier chains
    stay in the KG but don't clutter attestation).
  * Stable per-path ID across re-emit within the same run.
  * Builder NEVER raises; build_chain_graph failures → empty
    list, file still written.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from strix.telemetry import attack_paths as ap


# ---------------------------------------------------------------------------
# Stub Chain class for the tests
# ---------------------------------------------------------------------------


class _StubChain:
    def __init__(self, findings: list[dict[str, Any]]) -> None:
        self.findings = findings
        self.edges = []
        self.chain_severity = "high"


class _StubTracer:
    def __init__(self, tool_executions: dict | None = None) -> None:
        self.tool_executions = tool_executions or {}


# ---------------------------------------------------------------------------
# Stage classification heuristic
# ---------------------------------------------------------------------------


def test_stage_type_first_is_entry() -> None:
    assert ap._stage_type(1, 3) == "entry"


def test_stage_type_middle_is_pivot() -> None:
    assert ap._stage_type(2, 3) == "pivot"


def test_stage_type_last_is_impact() -> None:
    assert ap._stage_type(3, 3) == "impact"


def test_classify_impact_for_rce() -> None:
    assert ap._classify_impact_stage(
        {"category": "rce"},
    ) == "code_execution"


def test_classify_impact_for_idor() -> None:
    assert ap._classify_impact_stage(
        {"category": "idor"},
    ) == "data_access"


def test_classify_impact_default() -> None:
    assert ap._classify_impact_stage(
        {"category": "xss"},
    ) == "impact"


# ---------------------------------------------------------------------------
# MITRE lookup
# ---------------------------------------------------------------------------


def test_mitre_lookup_returns_first_technique_for_matching_tool() -> None:
    tracer = _StubTracer(tool_executions={
        1: {"tool_name": "scan_sqli", "mitre_techniques": ["T1190", "T1078"]},
    })
    assert ap._lookup_mitre_technique(
        {"category": "sqli"}, tracer,
    ) == "T1190"


def test_mitre_lookup_none_when_no_matching_tool() -> None:
    tracer = _StubTracer(tool_executions={
        1: {"tool_name": "scan_xss", "mitre_techniques": ["T1059"]},
    })
    assert ap._lookup_mitre_technique(
        {"category": "sqli"}, tracer,
    ) is None


def test_mitre_lookup_none_when_tracer_none() -> None:
    assert ap._lookup_mitre_technique({"category": "sqli"}, None) is None


# ---------------------------------------------------------------------------
# Confidence + name + impact summary
# ---------------------------------------------------------------------------


def test_confidence_one_when_all_verified() -> None:
    findings = [
        {"verification_status": "verified"},
        {"verification_status": "exploited"},
    ]
    assert ap._confidence(findings) == 1.0


def test_confidence_half_credit_for_pattern_match() -> None:
    findings = [{"verification_status": "pattern_match"}]
    assert ap._confidence(findings) == 0.5


def test_confidence_zero_for_empty() -> None:
    assert ap._confidence([]) == 0.0


def test_chain_name_uses_category_arrow() -> None:
    findings = [
        {"category": "saml-xsw", "title": "x"},
        {"category": "idor", "title": "y"},
    ]
    name = ap._chain_name(findings)
    assert "saml-xsw" in name
    assert "idor" in name
    assert "→" in name


def test_impact_summary_truncates_long_text() -> None:
    findings = [{"impact": "A " * 200}]  # 400 chars
    out = ap._impact_summary(findings)
    assert len(out) <= 205  # 200 + ellipsis + period


# ---------------------------------------------------------------------------
# build_attack_paths filtering
# ---------------------------------------------------------------------------


def _h_finding(**kw) -> dict[str, Any]:
    return {
        "id": kw.get("id", "vuln-x"),
        "title": kw.get("title", "T"),
        "category": kw.get("category", "sqli"),
        "severity": kw.get("severity", "high"),
        "endpoint": kw.get("endpoint", "/x"),
        "verification_status": kw.get("verification_status", "verified"),
        "impact": kw.get("impact", "Generic impact."),
    }


def test_build_drops_chains_below_two_stages() -> None:
    """A 1-stage chain isn't a multi-stage attack path."""
    chain = _StubChain([_h_finding(severity="critical")])
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        return_value=[chain],
    ):
        out = ap.build_attack_paths(tracer=_StubTracer(), run_id="r1")
    assert out == []


def test_build_drops_chains_without_high_tier_findings() -> None:
    """Chain of medium findings only → not emitted (conservative
    threshold; lower-tier chains stay in the KG but don't
    clutter attestation)."""
    chain = _StubChain([
        _h_finding(severity="medium"),
        _h_finding(severity="low"),
    ])
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        return_value=[chain],
    ):
        out = ap.build_attack_paths(tracer=_StubTracer(), run_id="r1")
    assert out == []


def test_build_emits_qualifying_chain() -> None:
    chain = _StubChain([
        _h_finding(id="vuln-1", category="saml-xsw", severity="high"),
        _h_finding(id="vuln-2", category="idor", severity="critical"),
    ])
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        return_value=[chain],
    ):
        out = ap.build_attack_paths(tracer=_StubTracer(), run_id="run-1")
    assert len(out) == 1
    p = out[0]
    assert p["id"] == "ap-run-1-001"
    assert p["max_severity"] == "critical"
    assert len(p["stages"]) == 2
    assert p["stages"][0]["step"] == 1
    assert p["stages"][0]["type"] == "entry"
    assert p["stages"][1]["type"] == "data_access"  # idor → data_access
    assert p["stages"][0]["finding_id"] == "vuln-1"


def test_build_stable_path_ids_across_calls() -> None:
    """Re-emit produces the same path IDs for the same chain
    order."""
    chain = _StubChain([
        _h_finding(id="a", severity="high"),
        _h_finding(id="b", severity="critical"),
    ])
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        return_value=[chain],
    ):
        first = ap.build_attack_paths(tracer=_StubTracer(), run_id="r1")
        second = ap.build_attack_paths(tracer=_StubTracer(), run_id="r1")
    assert first[0]["id"] == second[0]["id"]


# ---------------------------------------------------------------------------
# Recall safety — builder never raises
# ---------------------------------------------------------------------------


def test_build_returns_empty_when_chain_graph_unavailable() -> None:
    """If chaining_graph itself can't import, build_attack_paths
    returns an empty list — never raises."""
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        side_effect=RuntimeError("simulated failure"),
    ):
        out = ap.build_attack_paths(tracer=_StubTracer(), run_id="r1")
    assert out == []


# ---------------------------------------------------------------------------
# File writing
# ---------------------------------------------------------------------------


def test_write_jsonl_creates_file_even_when_zero_paths(
    tmp_path: Path,
) -> None:
    """MA-S2 attestation discipline: the file is ALWAYS written,
    even with zero qualifying paths. Auditors read the empty
    file as 'we tried and found no qualifying multi-stage
    paths'."""
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        return_value=[],
    ):
        n = ap.write_attack_paths_jsonl(
            tracer=_StubTracer(), run_dir=tmp_path, run_id="r1",
        )
    assert n == 0
    assert (tmp_path / "attack_paths.jsonl").exists()


def test_write_jsonl_one_line_per_path(tmp_path: Path) -> None:
    chain1 = _StubChain([
        _h_finding(id="a1", severity="critical"),
        _h_finding(id="a2", severity="high"),
    ])
    chain2 = _StubChain([
        _h_finding(id="b1", severity="high"),
        _h_finding(id="b2", severity="critical"),
        _h_finding(id="b3", severity="high"),
    ])
    with patch(
        "strix.agents.chaining_graph.build_chain_graph",
        return_value=[chain1, chain2],
    ):
        n = ap.write_attack_paths_jsonl(
            tracer=_StubTracer(), run_dir=tmp_path, run_id="r1",
        )
    assert n == 2
    text = (tmp_path / "attack_paths.jsonl").read_text(encoding="utf-8")
    lines = [ln for ln in text.split("\n") if ln.strip()]
    assert len(lines) == 2
    # Each line is valid JSON
    for ln in lines:
        d = json.loads(ln)
        assert "id" in d and "stages" in d


# ---------------------------------------------------------------------------
# End-to-end via tracer.save_run_data
# ---------------------------------------------------------------------------


def test_attack_paths_jsonl_written_on_mark_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.chdir(tmp_path)
    from strix.telemetry.tracer import Tracer, set_global_tracer
    t = Tracer("apm-a-integration")
    set_global_tracer(t)
    t.save_run_data(mark_complete=True)
    p = tmp_path / "strix_runs" / "apm-a-integration" / "attack_paths.jsonl"
    assert p.exists()
