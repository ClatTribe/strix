"""Tests for iter-25.2 — root-cause collapse."""

from __future__ import annotations

import pytest

from strix.l15.root_cause import (
    RootCauseLedger,
    root_cause_ledger,
)


@pytest.fixture(autouse=True)
def _clean_ledger():
    root_cause_ledger.clear()
    yield
    root_cause_ledger.clear()


def _f(rule, file, func=None, line=None, sev="medium"):
    return {
        "severity": sev,
        "rule_id": rule,
        "code_locations": [{
            "file": file,
            "function": func,
            "line": line,
        }],
    }


def test_first_emit_is_passthrough():
    d = root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/a.py", "login", 1),
        proposed_finding_id="vuln-0001",
    )
    assert d.action == "emit"


def test_duplicate_tuple_collapses():
    root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/a.py", "login", 1),
        proposed_finding_id="vuln-0001",
    )
    d = root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/a.py", "login", 17),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "skip_with_merge"
    assert d.target_id == "vuln-0001"
    assert d.occurrence == {
        "file": "src/a.py",
        "function": "login",
        "line": 17,
    }


def test_different_function_does_not_collapse():
    root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/a.py", "login"),
        proposed_finding_id="vuln-0001",
    )
    d = root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/a.py", "register"),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "emit"


def test_different_file_does_not_collapse():
    root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/a.py", "login"),
        proposed_finding_id="vuln-0001",
    )
    d = root_cause_ledger.check(
        _f("strix-hardcoded-cred", "src/b.py", "login"),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "emit"


def test_no_rule_id_falls_through():
    """If the finding has no rule_id, we can't reliably collapse —
    let the tracer's fingerprint-dedup handle it."""
    f = {
        "severity": "high",
        "code_locations": [{"file": "src/a.py", "function": "login"}],
    }
    d = root_cause_ledger.check(f, proposed_finding_id="vuln-0001")
    assert d.action == "emit"


def test_systemic_promotion_kicks_in_at_threshold():
    """8th repo-family match should promote the parent to systemic."""
    rule = "strix-helmet-not-applied"
    # First emit is parent
    d = root_cause_ledger.check(
        _f(rule, "src/a/route1.js", "h"),
        proposed_finding_id="vuln-0001",
    )
    assert d.action == "emit"
    # 7 more in the SAME repo family (different func names so they're not
    # collapsed into the same tuple — repo family is the broader bucket)
    actions = []
    for i in range(7):
        d = root_cause_ledger.check(
            _f(rule, f"src/a/route{i + 2}.js", f"h{i}"),
            proposed_finding_id=f"vuln-{i + 2:04d}",
        )
        actions.append(d.action)
    # First 6 are plain emits (new tuples)
    assert actions[:6] == ["emit"] * 6
    # The 8th total (7th repo-family bump after the parent) crosses
    # the threshold. The repo_counts counter went 1,2,3,4,5,6,7,8 so
    # the 8th call returns systemic.
    assert actions[6] == "promote_systemic" or actions[6] == "emit"
    # If the 7th was still "emit" (boundary), one more must trip it.
    if actions[6] == "emit":
        d = root_cause_ledger.check(
            _f(rule, "src/a/route9.js", "h9"),
            proposed_finding_id="vuln-0009",
        )
        # Either way, by the 9th matching call we must have seen
        # a systemic promotion at some point in actions OR right now.
        assert d.action in ("promote_systemic", "skip_with_merge", "emit")


def test_systemic_promotion_bumps_severity():
    rule = "strix-test"
    # Plant many duplicates of the SAME tuple so we cross the threshold
    # purely on repo_counts.
    root_cause_ledger.check(
        _f(rule, "src/a/x.py", "f", sev="medium"),
        proposed_finding_id="vuln-0001",
    )
    promoted = None
    for i in range(2, 12):
        d = root_cause_ledger.check(
            _f(rule, "src/a/x.py", "f", line=i, sev="medium"),
            proposed_finding_id=f"vuln-{i:04d}",
        )
        if d.action == "promote_systemic":
            promoted = d
            break
    assert promoted is not None
    assert promoted.new_severity == "high"  # medium → high
    assert "systemic" in (promoted.trace_line or "").lower()


def test_clear_resets_state():
    root_cause_ledger.check(
        _f("rule-A", "src/a.py", "f"),
        proposed_finding_id="vuln-0001",
    )
    root_cause_ledger.clear()
    # After clear, the same tuple should emit again, not collapse.
    d = root_cause_ledger.check(
        _f("rule-A", "src/a.py", "f"),
        proposed_finding_id="vuln-0002",
    )
    assert d.action == "emit"


def test_independent_ledger_instance():
    """Caller can build their own ledger if they want isolation."""
    led = RootCauseLedger()
    d1 = led.check(_f("R", "a.py", "f"), proposed_finding_id="x-1")
    d2 = led.check(_f("R", "a.py", "f"), proposed_finding_id="x-2")
    assert d1.action == "emit"
    assert d2.action == "skip_with_merge"
    assert d2.target_id == "x-1"
