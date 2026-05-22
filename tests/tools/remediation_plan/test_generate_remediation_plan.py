"""Tests for iter-25.12 — generate_remediation_plan."""

from __future__ import annotations

import json

import pytest

from strix.tools.remediation_plan.generate_remediation_plan import (
    generate_remediation_plan,
)


def _findings(tmp_path):
    p = tmp_path / "vulnerabilities.json"
    return p


# --------------------------------------------------------------------
# I/O errors
# --------------------------------------------------------------------

def test_missing_findings_file_returns_error(tmp_path):
    out = generate_remediation_plan(
        findings_path=str(tmp_path / "nope.json"),
        output_path=str(tmp_path / "out.md"),
    )
    assert out["status"] == "error"


def test_invalid_json_returns_error(tmp_path):
    p = _findings(tmp_path)
    p.write_text("not json")
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(tmp_path / "out.md"),
    )
    assert out["status"] == "error"


def test_invalid_audience_returns_error(tmp_path):
    p = _findings(tmp_path)
    p.write_text("[]")
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(tmp_path / "out.md"),
        audience="ceo",
    )
    assert out["status"] == "error"


def test_empty_findings_returns_partial(tmp_path):
    p = _findings(tmp_path)
    p.write_text("[]")
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(tmp_path / "out.md"),
    )
    assert out["status"] == "partial"
    assert out["total_findings"] == 0


# --------------------------------------------------------------------
# Bucketing
# --------------------------------------------------------------------

def test_critical_finding_in_critical_section(tmp_path):
    p = _findings(tmp_path)
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "SQLi confirmed via sqlmap",
        "severity": "critical",
        "cwe": "CWE-89",
        "endpoint": "https://app.example.com/api/search",
        "verification_status": "exploited",
        "exploitability": {"composite": 0.9, "action": "promote"},
    }]))
    out_md = tmp_path / "out.md"
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
    )
    assert out["status"] == "ok"
    assert out["critical"] == 1
    text = out_md.read_text()
    assert "## 1. Critical / Confirmed" in text
    assert "SQLi confirmed via sqlmap" in text


def test_noise_finding_in_watch_section(tmp_path):
    p = _findings(tmp_path)
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "SAST hit in dead code",
        "severity": "info",
        "cwe": "CWE-89",
        "noise": True,
        "exploitability": {
            "composite": 0.0, "action": "demote",
            "reason": "code=0.0 — dead code",
        },
    }]))
    out_md = tmp_path / "out.md"
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
    )
    assert out["watch"] == 1
    text = out_md.read_text()
    assert "## 4. Watch" in text


def test_systemic_finding_in_systemic_section(tmp_path):
    p = _findings(tmp_path)
    occs = [{"file": f"src/f{i}.py", "line": i} for i in range(6)]
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "Hardcoded credential literal",
        "severity": "medium",
        "rule_id": "strix-hardcoded-cred",
        "occurrences": occs,
        "reasoning_trace": ["l1.5: promoted to systemic-issue"],
    }]))
    out_md = tmp_path / "out.md"
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
    )
    assert out["systemic"] == 1
    text = out_md.read_text()
    assert "## 2. Systemic Issues" in text
    assert "Hardcoded credential literal" in text


def test_hygiene_in_checklist(tmp_path):
    p = _findings(tmp_path)
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "Missing Content-Security-Policy header",
        "severity": "info",
    }]))
    out_md = tmp_path / "out.md"
    out = generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
    )
    assert out["hygiene"] == 1
    text = out_md.read_text()
    assert "## 3. Hygiene Checklist" in text
    assert "Missing Content-Security-Policy" in text


# --------------------------------------------------------------------
# Audience variants
# --------------------------------------------------------------------

def test_developer_audience_renders_blame_and_poc(tmp_path):
    p = _findings(tmp_path)
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "SQLi",
        "severity": "critical",
        "cwe": "CWE-89",
        "endpoint": "https://e.com/x",
        "verification_status": "exploited",
        "code_locations": [{"file": "src/auth.py", "line": 17}],
        "git_blame": {
            "author": "Alice", "commit_date": "2024-01-01",
            "days_since_change": 200, "commit_subject": "quick fix",
        },
        "poc_script_code": "curl https://e.com/x?id=1' OR 1=1--",
    }]))
    out_md = tmp_path / "out.md"
    generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
        audience="developer",
    )
    text = out_md.read_text()
    assert "src/auth.py:17" in text
    assert "Alice" in text
    assert "PoC" in text


def test_ciso_audience_emphasises_business_impact(tmp_path):
    p = _findings(tmp_path)
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "Log4j RCE",
        "severity": "critical",
        "cwe": "CWE-502",
        "endpoint": "https://e.com/",
        "verification_status": "exploited",
        "impact": "RCE on production app server; complete compromise.",
        "kev": {"is_kev": True},
        "campaigns": {
            "matched_pulse_count": 5,
            "sources_seen": ["AlienVault OTX", "MISP"],
        },
    }]))
    out_md = tmp_path / "out.md"
    generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
        audience="ciso",
    )
    text = out_md.read_text()
    assert "Business impact" in text
    assert "CISA KEV" in text
    assert "Active campaign" in text


def test_auditor_audience_maps_to_controls(tmp_path):
    p = _findings(tmp_path)
    p.write_text(json.dumps([{
        "id": "vuln-0001",
        "title": "Hardcoded AWS key",
        "severity": "critical",
        "cwe": "CWE-798",
        "verification_status": "exploited",
    }]))
    out_md = tmp_path / "out.md"
    generate_remediation_plan(
        findings_path=str(p),
        output_path=str(out_md),
        audience="auditor",
    )
    text = out_md.read_text()
    assert "SOC 2 CC6.1" in text or "Access Control" in text
    assert "ISO 27001" in text


# --------------------------------------------------------------------
# Tool registration
# --------------------------------------------------------------------

def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("generate_remediation_plan"))
