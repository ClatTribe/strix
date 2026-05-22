"""Tests for iter-25.9 — SAST→DAST auto-promotion planner."""

from __future__ import annotations

from strix.l15.sast_to_dast import (
    plan_dast_confirmation,
)


def _sast_sqli_finding(**overrides):
    base = {
        "id": "vuln-0001",
        "severity": "medium",
        "cwe": "CWE-89",
        "rule_id": "semgrep-sqli-string-concat",
        "code_locations": [{
            "file": "src/controllers/report.py",
            "line": 87,
            "snippet": "query = f'SELECT * FROM r WHERE id = {request.args.get(\"id\")}'",
        }],
        "endpoint": "https://app.example.com/api/v1/reports/download",
    }
    base.update(overrides)
    return base


def test_sast_sqli_plans_sqlmap_confirmation():
    f = _sast_sqli_finding()
    cr = plan_dast_confirmation(f)
    assert cr is not None
    assert cr.tool == "scan_sqli_sqlmap"
    assert cr.target_url == "https://app.example.com/api/v1/reports/download"
    assert cr.param == "id"
    assert cr.src_finding_id == "vuln-0001"
    assert cr.cwe == "CWE-89"


def test_sast_xss_plans_dalfox_confirmation():
    f = {
        "id": "vuln-0002",
        "severity": "medium",
        "cwe": "CWE-79",
        "rule_id": "semgrep-xss-reflected",
        "code_locations": [{
            "file": "src/views.py",
            "snippet": "return f'<h1>{request.args.get(\"q\")}</h1>'",
        }],
        "endpoint": "https://app.example.com/search",
    }
    cr = plan_dast_confirmation(f)
    assert cr is not None
    assert cr.tool == "scan_xss_dalfox"
    assert cr.param == "q"


def test_path_traversal_plans_specialist():
    f = {
        "id": "vuln-0003",
        "severity": "high",
        "cwe": "CWE-22",
        "rule_id": "semgrep-path-traversal",
        "code_locations": [{
            "file": "src/files.py",
            "snippet": "open(request.args.get('file_name'))",
        }],
    }
    cr = plan_dast_confirmation(f)
    assert cr is not None
    assert cr.tool == "scan_path_traversal"
    assert cr.param == "file_name"


def test_already_exploited_skipped():
    """No need to confirm a finding that's already been actively
    verified end-to-end."""
    f = _sast_sqli_finding(verification_status="exploited")
    cr = plan_dast_confirmation(f)
    assert cr is None


def test_no_cwe_skipped():
    f = {
        "id": "vuln-0004",
        "rule_id": "some-rule",
        "code_locations": [{"file": "x.py"}],
    }
    cr = plan_dast_confirmation(f)
    assert cr is None


def test_unsupported_cwe_skipped():
    """We only auto-confirm CWEs we have a deterministic checker for."""
    f = {
        "id": "vuln-0005",
        "cwe": "CWE-200",  # info disclosure — no deterministic confirmer
        "rule_id": "semgrep-info-disclosure",
        "code_locations": [{"file": "x.py"}],
    }
    cr = plan_dast_confirmation(f)
    assert cr is None


def test_no_rule_id_skipped():
    """SAST tools always set rule_id; without one we can't trust this
    is a SAST finding suitable for DAST confirmation."""
    f = {
        "id": "vuln-0006",
        "cwe": "CWE-89",
        "code_locations": [{"file": "x.py"}],
    }
    cr = plan_dast_confirmation(f)
    assert cr is None


def test_param_extraction_express_style():
    f = {
        "id": "vuln-0007",
        "cwe": "CWE-89",
        "rule_id": "semgrep-sqli-js",
        "code_locations": [{
            "file": "routes/api.js",
            "snippet": "db.query(`SELECT * FROM u WHERE id = ${req.query.userId}`)",
        }],
        "endpoint": "https://e.com/users",
    }
    cr = plan_dast_confirmation(f)
    assert cr is not None
    assert cr.param == "userId"


def test_request_form_extraction():
    f = {
        "id": "vuln-0008",
        "cwe": "CWE-79",
        "rule_id": "semgrep-xss",
        "code_locations": [{
            "file": "app.py",
            "snippet": "return template % request.form['comment']",
        }],
        "endpoint": "https://e.com/post",
    }
    cr = plan_dast_confirmation(f)
    assert cr is not None
    assert cr.param == "comment"


def test_no_param_still_plans():
    """If we can't extract a param name, we still plan the
    confirmation — Wave 4 amplify can fuzz."""
    f = {
        "id": "vuln-0009",
        "cwe": "CWE-89",
        "rule_id": "semgrep-sqli",
        "code_locations": [{
            "file": "src/x.py",
            "snippet": "execute_some_query()",  # no recognised pattern
        }],
        "endpoint": "https://e.com/x",
    }
    cr = plan_dast_confirmation(f)
    assert cr is not None
    assert cr.param is None


def test_to_dict_round_trip():
    f = _sast_sqli_finding()
    cr = plan_dast_confirmation(f)
    d = cr.to_dict()
    assert d["tool"] == "scan_sqli_sqlmap"
    assert d["param"] == "id"
    assert d["src_finding_id"] == "vuln-0001"
