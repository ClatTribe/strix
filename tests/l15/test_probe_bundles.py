"""Tests for iter-25.10 — finding-triggered probe bundles + adaptive probe."""

from __future__ import annotations

import pytest

from strix.l15.posture import SecurityPosture, clear_cache, set_posture
from strix.l15.probe_bundles import (
    ProbeStep,
    adaptive_call_log,
    clear_adaptive_log,
    execute_adaptive_probe,
    plan_probe_bundle,
    record_planned_bundle,
)


@pytest.fixture(autouse=True)
def _clean():
    clear_cache()
    clear_adaptive_log()
    yield
    clear_cache()
    clear_adaptive_log()


# --------------------------------------------------------------------
# Admin-panel bundle
# --------------------------------------------------------------------

def test_admin_panel_triggers_burst():
    f = {
        "title": "Exposed admin panel",
        "rule_id": "debug_endpoint_probe",
        "endpoint": "https://app.example.com/admin",
    }
    steps = plan_probe_bundle(f)
    tools = {s.tool for s in steps}
    assert "scan_auth_flow" in tools
    assert "discover_paths_feroxbuster" in tools
    assert "scan_multi_role_auth" in tools


def test_admin_panel_without_endpoint_returns_empty():
    f = {"title": "Exposed admin panel"}
    assert plan_probe_bundle(f) == []


# --------------------------------------------------------------------
# SQLi-potential bundle
# --------------------------------------------------------------------

def test_sast_sqli_triggers_sqlmap():
    f = {
        "title": "SQL string concat",
        "cwe": "CWE-89",
        "rule_id": "semgrep-sqli",
        "endpoint": "https://app.example.com/api/search?q=foo",
    }
    steps = plan_probe_bundle(f)
    assert len(steps) == 1
    assert steps[0].tool == "scan_sqli_sqlmap"
    assert steps[0].args["target_url"].startswith("https://")


def test_xss_sast_triggers_dalfox():
    f = {
        "title": "Reflected XSS",
        "cwe": "CWE-79",
        "rule_id": "semgrep-xss",
        "endpoint": "https://app.example.com/search",
    }
    steps = plan_probe_bundle(f)
    assert len(steps) == 1
    assert steps[0].tool == "scan_xss_dalfox"


# --------------------------------------------------------------------
# Verified-secret bundle
# --------------------------------------------------------------------

def test_aws_verified_secret_triggers_sts_and_s3():
    f = {
        "title": "AWS access key verified",
        "cwe": "CWE-798",
        "detector": "AWS",
        "verified": True,
    }
    steps = plan_probe_bundle(f)
    tools = [s.tool for s in steps]
    assert "terminal_execute" in tools
    rationales = " ".join(s.rationale for s in steps)
    assert "sts" in rationales.lower()
    assert "s3" in rationales.lower()


def test_stripe_verified_secret_triggers_balance_check():
    f = {
        "title": "Stripe key verified",
        "cwe": "CWE-798",
        "detector": "Stripe",
        "verified": True,
    }
    steps = plan_probe_bundle(f)
    assert any("stripe" in s.rationale.lower() for s in steps)


# --------------------------------------------------------------------
# Subdomain takeover
# --------------------------------------------------------------------

def test_subdomain_takeover_probes_with_httpx():
    f = {
        "title": "Subdomain takeover candidate",
        "subdomain": "dev.example.com",
    }
    steps = plan_probe_bundle(f)
    assert any(s.tool == "probe_hosts_httpx" for s in steps)


# --------------------------------------------------------------------
# Tech-burst bundles
# --------------------------------------------------------------------

def test_jenkins_fingerprint_triggers_jenkins_burst():
    f = {
        "title": "Jenkins detected",
        "tech": ["Jenkins", "Java"],
        "endpoint": "https://jenkins.example.com/",
    }
    steps = plan_probe_bundle(f)
    tools = {s.tool for s in steps}
    assert "scan_nuclei_templates" in tools
    assert "discover_paths_feroxbuster" in tools
    # Args should be Jenkins-specific
    nuclei_step = next(s for s in steps if s.tool == "scan_nuclei_templates")
    assert nuclei_step.args.get("tags") == "jenkins"


def test_drupal_fingerprint_triggers_drupal_burst():
    f = {
        "title": "Drupal detected",
        "tech": ["Drupal 9.2", "PHP"],
        "endpoint": "https://drupal.example.com/",
    }
    steps = plan_probe_bundle(f)
    tools = {s.tool for s in steps}
    assert "discover_paths_feroxbuster" in tools
    ferox_step = next(
        s for s in steps if s.tool == "discover_paths_feroxbuster"
    )
    assert "drupal" in str(ferox_step.args.get("wordlist", "")).lower()


# --------------------------------------------------------------------
# Stealth gate
# --------------------------------------------------------------------

def test_waf_target_marks_steps_stealth():
    """If posture says WAF detected → all steps get stealth=True."""
    set_posture(SecurityPosture(
        target="https://wafd.example.com/admin",
        waf_detected=True,
        stealth_mode_required=True,
    ))
    f = {
        "title": "Exposed admin panel",
        "rule_id": "debug_endpoint_probe",
        "endpoint": "https://wafd.example.com/admin",
    }
    steps = plan_probe_bundle(f)
    assert steps
    assert all(s.stealth for s in steps)


def test_no_waf_marks_steps_non_stealth():
    f = {
        "title": "Exposed admin panel",
        "rule_id": "debug_endpoint_probe",
        "endpoint": "https://plain.example.com/admin",
    }
    steps = plan_probe_bundle(f)
    assert steps
    assert all(not s.stealth for s in steps)


# --------------------------------------------------------------------
# Unmatched findings
# --------------------------------------------------------------------

def test_unrecognised_finding_returns_empty():
    f = {"title": "Some weird thing", "cwe": "CWE-0000"}
    assert plan_probe_bundle(f) == []


def test_malformed_finding_returns_empty():
    """Non-dict-ish input shouldn't crash."""
    f = {"title": None, "cwe": None, "tech": "not a list"}
    assert plan_probe_bundle(f) == []


# --------------------------------------------------------------------
# record_planned_bundle
# --------------------------------------------------------------------

def test_record_planned_bundle_attaches_to_finding():
    f: dict = {"id": "vuln-0001"}
    steps = [
        ProbeStep(tool="x", rationale="r1"),
        ProbeStep(tool="y", rationale="r2"),
    ]
    record_planned_bundle(f, steps)
    assert len(f["triggered_probes"]) == 2
    assert f["triggered_probes"][0]["tool"] == "x"


def test_record_planned_bundle_appends_to_existing():
    f: dict = {"triggered_probes": [{"tool": "existing", "rationale": ""}]}
    record_planned_bundle(
        f, [ProbeStep(tool="new", rationale="r")],
    )
    assert len(f["triggered_probes"]) == 2


def test_record_empty_steps_is_noop():
    f: dict = {}
    record_planned_bundle(f, [])
    assert "triggered_probes" not in f


# --------------------------------------------------------------------
# execute_adaptive_probe — L2 escape hatch
# --------------------------------------------------------------------

def test_adaptive_probe_queues_and_logs():
    r = execute_adaptive_probe(
        tool_name="scan_xss_dalfox",
        target="https://e.com/q",
        extra_args={"format": "json"},
    )
    assert r["queued"] is True
    log = adaptive_call_log()
    assert len(log) == 1
    assert log[0]["tool"] == "scan_xss_dalfox"


def test_adaptive_probe_call_cap():
    """Per-scan cap stops the LLM from looping."""
    for _ in range(15):
        execute_adaptive_probe(
            tool_name="x", target="https://e.com",
        )
    log = adaptive_call_log()
    # Cap is 10
    assert len(log) == 10
    # 11th call should report not-queued
    r = execute_adaptive_probe(tool_name="x", target="https://e.com")
    assert r["queued"] is False
    assert "cap" in r["reason"]


def test_adaptive_probe_inherits_stealth_from_posture():
    set_posture(SecurityPosture(
        target="https://wafd.example.com",
        waf_detected=True,
        stealth_mode_required=True,
    ))
    r = execute_adaptive_probe(
        tool_name="scan_xss_dalfox",
        target="https://wafd.example.com",
    )
    assert r["stealth"] is True
