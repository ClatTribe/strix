"""Tests for iter-25.3 — mid-scan corroborator."""

from __future__ import annotations

import pytest

from strix.l15.corroborator import (
    CorroboratorLedger,
    corroborator_ledger,
)


@pytest.fixture(autouse=True)
def _clean_ledger():
    corroborator_ledger.clear()
    yield
    corroborator_ledger.clear()


def _f(cwe, url=None, file=None, tool=None, sev="medium"):
    finding = {"severity": sev, "cwe": cwe}
    if url:
        finding["endpoint"] = url
    if file:
        finding["code_locations"] = [{"file": file}]
    if tool:
        finding["discovery_source_tool"] = tool
    return finding


def test_first_finding_registers_parent():
    d = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login", tool="semgrep"),
        proposed_finding_id="vuln-0001",
    )
    assert d.action == "register_parent"


def test_second_finding_same_source_does_nothing():
    """Same tool firing twice on the same surface is duplication,
    not corroboration."""
    corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login", tool="semgrep"),
        proposed_finding_id="vuln-0001",
    )
    d = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login", tool="semgrep"),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "nothing"


def test_different_source_boosts_parent():
    """SAST + DAST on same CWE + same surface → boost parent."""
    corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login", tool="semgrep", sev="medium"),
        proposed_finding_id="vuln-0001",
    )
    d = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login", tool="sqlmap", sev="medium"),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "boost_parent"
    assert d.parent_id == "vuln-0001"
    assert d.new_parent_severity == "high"  # medium → high
    assert "sqlmap" in (d.trace_line or "")


def test_query_string_normalised():
    """Same path with different ?q= is still the same surface."""
    corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login?x=1", tool="semgrep"),
        proposed_finding_id="vuln-0001",
    )
    d = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/login?x=2", tool="sqlmap"),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "boost_parent"


def test_no_cwe_no_corroboration():
    """Findings without a CWE can't be reliably corroborated."""
    d = corroborator_ledger.check(
        {"severity": "high", "endpoint": "https://e.com/x",
         "discovery_source_tool": "semgrep"},
        proposed_finding_id="vuln-0001",
    )
    assert d.action == "nothing"


def test_no_surface_no_corroboration():
    """Without an endpoint or file we can't tell if two findings are
    on the same surface."""
    d = corroborator_ledger.check(
        {"severity": "high", "cwe": "CWE-89",
         "discovery_source_tool": "semgrep"},
        proposed_finding_id="vuln-0001",
    )
    assert d.action == "nothing"


def test_cwe_normalisation():
    """CWE-89 / CWE:89 / 89 should all bucket together."""
    corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/x", tool="semgrep"),
        proposed_finding_id="vuln-0001",
    )
    d = corroborator_ledger.check(
        {"severity": "medium", "cwe": "89",
         "endpoint": "https://e.com/x",
         "discovery_source_tool": "sqlmap"},
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "boost_parent"


def test_third_source_extends_corroborated_by():
    """A third source on the same tuple should NOT bump severity
    again (already critical from second corroboration), but should
    still record itself as a corroborator."""
    corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/x", tool="semgrep"),
        proposed_finding_id="vuln-0001",
    )
    d2 = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/x", tool="sqlmap"),
        proposed_finding_id="vuln-0002",
    )
    d3 = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/x", tool="dalfox"),
        proposed_finding_id="vuln-0003",
    )
    assert d2.action == "boost_parent"
    assert d3.action == "boost_parent"
    # Second corroboration didn't bump (already boosted) — but it must
    # still be marked as a corroborator so caller can attach the id.
    assert d3.new_parent_severity is None  # already-boosted parent
    assert d3.parent_id == "vuln-0001"


def test_high_severity_boosts_to_critical():
    corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/x", tool="semgrep", sev="high"),
        proposed_finding_id="vuln-0001",
    )
    d = corroborator_ledger.check(
        _f("CWE-89", url="https://e.com/x", tool="sqlmap", sev="high"),
        proposed_finding_id="vuln-0002",
    )
    assert d.new_parent_severity == "critical"


def test_isolated_ledger_instance():
    led = CorroboratorLedger()
    d1 = led.check(
        _f("CWE-89", url="https://a/x", tool="semgrep"),
        proposed_finding_id="x-1",
    )
    d2 = led.check(
        _f("CWE-89", url="https://a/x", tool="sqlmap"),
        proposed_finding_id="x-2",
    )
    assert d1.action == "register_parent"
    assert d2.action == "boost_parent"
    assert d2.parent_id == "x-1"


def test_source_extracted_from_rule_id_prefix():
    """If discovery_source_tool / tool aren't set, fall back to
    parsing the rule_id prefix."""
    corroborator_ledger.check(
        {"severity": "medium", "cwe": "CWE-89",
         "endpoint": "https://e.com/x",
         "rule_id": "semgrep:sql.user-input"},
        proposed_finding_id="vuln-0001",
    )
    d = corroborator_ledger.check(
        {"severity": "medium", "cwe": "CWE-89",
         "endpoint": "https://e.com/x",
         "rule_id": "nuclei-sqli-template"},
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "boost_parent"
