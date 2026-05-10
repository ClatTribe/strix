"""Integration tests for `emit_compliance_evidence`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.compliance.tools import emit_compliance_evidence


def _vuln_doc(findings: list[dict]) -> str:
    return json.dumps(findings)


def test_returns_ok_with_no_findings_file(tmp_path: Path) -> None:
    """No input findings → still emits an artifact (every
    control is pass / untested). Useful for "are we covered?"
    runs that don't actually probe anything."""
    out = tmp_path / "compliance_evidence.json"
    result = emit_compliance_evidence(
        findings_path=str(tmp_path / "missing.json"),
        output_path=str(out),
    )
    assert result["status"] == "ok"
    assert out.exists()
    doc = json.loads(out.read_text())
    assert doc["frameworks"]
    assert doc["controls"]


def test_emits_artifact_for_real_findings(tmp_path: Path) -> None:
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {
            "id": "f1",
            "title": "SQL Injection at /api/users",
            "category": "sqli",
            "cwe": "CWE-89",
            "severity": "high",
            "target": "https://app.com",
            "endpoint": "/api/users",
        },
    ]))
    out = tmp_path / "compliance_evidence.json"
    result = emit_compliance_evidence(
        findings_path=str(p), output_path=str(out),
    )
    assert result["status"] == "ok"
    assert out.exists()
    doc = json.loads(out.read_text())
    failed = [c for c in doc["controls"] if c["verdict"] == "fail"]
    assert len(failed) >= 4   # CC6.1 + A.8.26 + 6.5.1 + V5.3.4 minimum


def test_failed_controls_emitted_as_finding_drafts(tmp_path: Path) -> None:
    """Each failed/warned control should appear as a FindingDraft
    with category=compliance_violation so the lead sees them in
    its result loop."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "f1", "title": "X", "category": "sqli",
         "cwe": "CWE-89", "severity": "high",
         "target": "https://app.com"},
    ]))
    result = emit_compliance_evidence(
        findings_path=str(p),
        output_path=str(tmp_path / "out.json"),
    )
    assert len(result["findings"]) >= 1
    cats = {f["category"] for f in result["findings"]}
    assert cats == {"compliance_violation"}
    # Title format: [compliance:framework:control_id] ...
    assert all(
        "[compliance:" in f["title"] for f in result["findings"]
    )


def test_pass_and_untested_controls_dont_appear_in_findings(
    tmp_path: Path,
) -> None:
    """Only fail/warn controls bubble up as drafts. Pass/info/
    untested are wrapper-side rendering data."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "f1", "title": "X", "category": "sqli",
         "cwe": "CWE-89", "severity": "info",
         "target": "https://app.com"},
    ]))
    result = emit_compliance_evidence(
        findings_path=str(p),
        output_path=str(tmp_path / "out.json"),
    )
    # Only info-severity findings → no fail/warn → no drafts.
    assert result["findings"] == []


def test_handles_wrapped_input_format(tmp_path: Path) -> None:
    """`{"findings": [...]}` shape — same tolerance as
    correlate_findings."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(json.dumps({
        "findings": [
            {"id": "f1", "title": "X", "category": "sqli",
             "cwe": "CWE-89", "severity": "high",
             "target": "https://x.com"},
        ],
    }))
    result = emit_compliance_evidence(
        findings_path=str(p),
        output_path=str(tmp_path / "out.json"),
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["findings_normalised"] == 1


def test_unknown_framework_returns_error(tmp_path: Path) -> None:
    result = emit_compliance_evidence(
        findings_path=str(tmp_path / "x.json"),
        output_path=str(tmp_path / "out.json"),
        frameworks=["NOT_REAL"],
    )
    assert result["status"] == "error"
    assert "NOT_REAL" in (result.get("error") or "")


def test_framework_subset_filter(tmp_path: Path) -> None:
    """`frameworks=['soc2']` should produce only SOC 2 entries
    in the artifact + summary."""
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "f1", "title": "X", "category": "sqli",
         "cwe": "CWE-89", "severity": "high",
         "target": "https://x.com"},
    ]))
    out = tmp_path / "out.json"
    result = emit_compliance_evidence(
        findings_path=str(p),
        output_path=str(out),
        frameworks=["soc2"],
    )
    assert result["tool_metadata"]["frameworks"] == ["soc2"]
    doc = json.loads(out.read_text())
    assert doc["frameworks"] == ["soc2"]
    assert all(c["framework"] == "soc2" for c in doc["controls"])


def test_tool_metadata_records_summary(tmp_path: Path) -> None:
    p = tmp_path / "vulnerabilities.json"
    p.write_text(_vuln_doc([
        {"id": "f1", "title": "X", "category": "sqli",
         "cwe": "CWE-89", "severity": "high",
         "target": "https://x.com"},
    ]))
    out = tmp_path / "out.json"
    result = emit_compliance_evidence(
        findings_path=str(p), output_path=str(out),
    )
    md = result["tool_metadata"]
    assert "summary" in md
    assert "evidence_path" in md
    assert md["evidence_path"] == str(out.resolve())
    assert md["total_controls"] > 0


# ---------------------------------------------------------------------------
# Lead-agent catalog placement
# ---------------------------------------------------------------------------


def test_emit_compliance_evidence_in_core_catalog() -> None:
    """Compliance is asset-type-agnostic — must be in core."""
    from strix.agents.lead_agent.tool_catalog import list_core_tools
    assert "emit_compliance_evidence" in list_core_tools()


def test_emit_compliance_evidence_visible_in_every_target_type() -> None:
    """Every target_type sees it as an always-on core tool."""
    from strix.agents.lead_agent.tool_catalog import (
        get_lead_tool_catalog,
        list_target_types,
    )
    for tt in list_target_types():
        cat = get_lead_tool_catalog(target_types=[tt])
        assert "emit_compliance_evidence" in cat, tt
