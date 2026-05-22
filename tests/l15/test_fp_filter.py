"""Tests for iter-25.1 — pre-emission FP filter."""

from __future__ import annotations

from strix.l15.fp_filter import (
    demoted_severity,
    pre_emission_fp_filter,
)


# --------------------------------------------------------------------
# Allow path (most findings should fall through unchanged)
# --------------------------------------------------------------------

def test_allows_production_code_finding():
    f = {
        "severity": "high",
        "code_locations": [{"file": "src/auth/login.py", "line": 42}],
        "description": "SQL injection via user input",
    }
    d = pre_emission_fp_filter(f)
    assert d.is_allow


def test_allows_when_no_path_no_evidence():
    """Bare finding with no path info → can't fire any heuristic → allow."""
    f = {"severity": "high", "description": "some weird finding"}
    d = pre_emission_fp_filter(f)
    assert d.is_allow


# --------------------------------------------------------------------
# Demote — test directory
# --------------------------------------------------------------------

def test_demotes_finding_in_tests_dir():
    f = {
        "severity": "high",
        "code_locations": [{"file": "src/tests/test_login.py", "line": 17}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_demote
    assert "test path" in d.reason


def test_demotes_finding_with_test_suffix():
    f = {
        "severity": "high",
        "code_locations": [{"file": "src/parser_test.py", "line": 5}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_demote


def test_demotes_finding_in_jest_test():
    f = {
        "severity": "medium",
        "code_locations": [{"file": "web/src/auth.test.ts", "line": 22}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_demote


# --------------------------------------------------------------------
# Drop — docs/examples
# --------------------------------------------------------------------

def test_drops_finding_in_examples():
    f = {
        "severity": "high",
        "code_locations": [{"file": "examples/quickstart.py", "line": 8}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_drop
    assert "docs/example tree" in d.reason


def test_drops_low_in_markdown_file():
    f = {
        "severity": "low",
        "code_locations": [{"file": "README.md", "line": 30}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_drop
    assert "documentation file" in d.reason


def test_drops_finding_with_getenv_default_placeholder():
    f = {
        "severity": "high",
        "code_locations": [{"file": "config.py", "line": 5}],
        "description": "Hardcoded secret",
        "technical_analysis": (
            "API_KEY = os.getenv('STRIPE_KEY', 'changeme')"
        ),
    }
    d = pre_emission_fp_filter(f)
    assert d.is_drop
    assert "os.getenv" in d.reason


def test_drops_finding_with_placeholder_value():
    f = {
        "severity": "medium",
        "code_locations": [{"file": "config.py", "line": 5}],
        "masked": "placeholder",
    }
    d = pre_emission_fp_filter(f)
    assert d.is_drop


# --------------------------------------------------------------------
# Safety: critical-severity findings must not be DROPped
# --------------------------------------------------------------------

def test_critical_in_test_dir_is_preserved():
    """A real production key accidentally committed under tests/
    must NOT be silently masked. Critical wins."""
    f = {
        "severity": "critical",
        "code_locations": [{"file": "tests/fixtures/leak.py", "line": 1}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_allow
    assert "critical" in d.reason


def test_critical_in_examples_is_preserved():
    f = {
        "severity": "critical",
        "code_locations": [{"file": "examples/aws_demo.py", "line": 1}],
    }
    d = pre_emission_fp_filter(f)
    assert d.is_allow


def test_critical_with_getenv_default_is_preserved():
    f = {
        "severity": "critical",
        "code_locations": [{"file": "config.py", "line": 5}],
        "technical_analysis": "os.getenv('K', 'placeholder')",
    }
    d = pre_emission_fp_filter(f)
    assert d.is_allow


# --------------------------------------------------------------------
# Robustness — internal errors must passthrough
# --------------------------------------------------------------------

def test_malformed_finding_passes_through():
    """A finding with a list where a string is expected must not crash."""
    f = {
        "severity": "high",
        # `code_locations` should be a list of dicts; here it's garbage
        "code_locations": "this is not a list",
    }
    d = pre_emission_fp_filter(f)
    # Should NOT raise; falls back to ALLOW
    assert d.is_allow


# --------------------------------------------------------------------
# demoted_severity helper
# --------------------------------------------------------------------

def test_demoted_severity_table():
    assert demoted_severity("critical") == "high"
    assert demoted_severity("high") == "medium"
    assert demoted_severity("medium") == "low"
    assert demoted_severity("low") == "info"
    assert demoted_severity("info") == "info"
    assert demoted_severity(None) == "info"
    assert demoted_severity("unknown-tier") == "info"
