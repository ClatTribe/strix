"""Integration tests for `correlate_findings`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.finding_chains.tools import correlate_findings


def _vuln_doc(findings: list[dict]) -> str:
    """vulnerabilities.json is a JSON list of finding dicts."""
    return json.dumps(findings)


def test_returns_partial_when_no_input_file(tmp_path: Path) -> None:
    result = correlate_findings(
        findings_path=str(tmp_path / "missing.json"),
    )
    assert result["status"] == "partial"
    assert "no findings" in (result.get("error") or "")


def test_returns_partial_when_input_empty(tmp_path: Path) -> None:
    p = tmp_path / "vulnerabilities.json"
    p.write_text("[]")
    result = correlate_findings(findings_path=str(p))
    assert result["status"] == "partial"


def test_builds_chain_for_sca_dast_pair(tmp_path: Path) -> None:
    """The canonical case: SCA finding for lodash + DAST
    finding for prototype pollution on the same target → one
    chain."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {
            "id": "sca-1",
            "title": "Vulnerable dependency `npm:lodash@4.17.20` (1 CVE)",
            "category": "vulnerable_dependency",
            "cwe": "CWE-1321",
            "severity": "high",
            "target": "https://app.com",
        },
        {
            "id": "dast-1",
            "title": "Prototype pollution at /api/merge",
            "category": "deserialization",
            "cwe": "CWE-502",
            "severity": "critical",
            "target": "https://app.com",
            "endpoint": "/api/merge",
        },
    ]))
    out = tmp_path / "finding_chains.json"
    result = correlate_findings(
        findings_path=str(p), output_path=str(out),
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["chains_built"] == 1
    assert out.exists()
    doc = json.loads(out.read_text())
    assert len(doc["chains"]) == 1
    assert doc["chains"][0]["size"] == 2
    assert doc["chains"][0]["severity"] == "critical"


def test_no_chains_when_findings_unrelated(tmp_path: Path) -> None:
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "a", "title": "X", "category": "sqli", "cwe": "CWE-89",
         "target": "https://a.com"},
        {"id": "b", "title": "Y", "category": "xss", "cwe": "CWE-79",
         "target": "https://b.com"},
    ]))
    result = correlate_findings(findings_path=str(p))
    assert result["status"] == "ok"
    assert result["tool_metadata"]["chains_built"] == 0
    assert result["findings"] == []


def test_chains_emitted_as_finding_drafts(tmp_path: Path) -> None:
    """Each chain should appear as a FindingDraft so the lead
    sees it in its result loop. category=`finding_chain` so
    the wrapper routes through chain-specific UI."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "sca-1",
         "title": "Vulnerable dependency `npm:lodash@4.17.20`",
         "category": "vulnerable_dependency",
         "cwe": "CWE-1321", "severity": "high",
         "target": "https://x.com"},
        {"id": "dast-1", "title": "Prototype pollution",
         "category": "deserialization", "cwe": "CWE-502",
         "severity": "critical", "target": "https://x.com"},
    ]))
    result = correlate_findings(findings_path=str(p))
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["category"] == "finding_chain"
    assert f["severity"] == "critical"
    assert "[chain:" in f["title"]


def test_handles_wrapped_input_format(tmp_path: Path) -> None:
    """Input shape: `{"findings": [...]}` instead of bare list."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(json.dumps({
        "findings": [
            {"id": "a", "title": "X", "category": "vulnerable_dependency",
             "cwe": "CWE-89", "target": "https://x.com"},
            {"id": "b", "title": "Y", "category": "sqli",
             "cwe": "CWE-89", "target": "https://x.com"},
        ],
    }))
    result = correlate_findings(findings_path=str(p))
    assert result["status"] == "ok"
    assert result["tool_metadata"]["chains_built"] == 1


def test_tool_metadata_records_counts(tmp_path: Path) -> None:
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "a", "title": "X", "category": "vulnerable_dependency",
         "cwe": "CWE-89", "target": "https://x.com"},
        {"id": "b", "title": "Y", "category": "sqli",
         "cwe": "CWE-89", "target": "https://x.com"},
        {"id": "c", "title": "Z (alone)", "category": "xss",
         "cwe": "CWE-79", "target": "https://other.com"},
    ]))
    result = correlate_findings(findings_path=str(p))
    md = result["tool_metadata"]
    assert md["findings_loaded"] == 3
    assert md["findings_normalised"] == 3
    assert md["chains_built"] == 1   # only 2 of 3 form a chain
    assert "by_chain_type" in md
    assert "by_severity" in md


def test_min_chain_size_argument_enforced(tmp_path: Path) -> None:
    """A 2-finding chain at min_chain_size=3 → 0 chains."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "a", "title": "X", "category": "vulnerable_dependency",
         "cwe": "CWE-89", "target": "https://x.com"},
        {"id": "b", "title": "Y", "category": "sqli",
         "cwe": "CWE-89", "target": "https://x.com"},
    ]))
    result = correlate_findings(findings_path=str(p), min_chain_size=3)
    assert result["tool_metadata"]["chains_built"] == 0


# ---------------------------------------------------------------------------
# Lead-agent catalog placement
# ---------------------------------------------------------------------------


def test_correlate_findings_in_core_catalog() -> None:
    """correlate_findings runs at scan-end regardless of asset
    type — so it lives in the core catalog (always-on)."""
    from strix.agents.lead_agent.tool_catalog import list_core_tools

    assert "correlate_findings" in list_core_tools()


def test_correlate_findings_visible_in_every_target_type() -> None:
    """As an always-on core tool, every target_type sees it."""
    from strix.agents.lead_agent.tool_catalog import (
        get_lead_tool_catalog,
        list_target_types,
    )

    for tt in list_target_types():
        cat = get_lead_tool_catalog(target_types=[tt])
        assert "correlate_findings" in cat, tt
