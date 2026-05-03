"""Tests for §11 non-tech-output finding fields.

Roadmap §11. The wrapper's primary dashboard surface is non-engineer-readable.
This pack adds 4 agent-supplied plain-English fields + 2 auto-derived fields
on every finding, so the wrapper renders meaningful UX without LLM-rewriting
each finding payload itself.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import (
    Tracer,
    _derive_exploitation_in_wild_plain,
    _derive_priority_label,
    _normalize_fix_time_estimate,
    set_global_tracer,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


# ---------------------------------------------------------------------------
# Agent-supplied plain-English fields
# ---------------------------------------------------------------------------


def test_agent_supplied_plain_fields_persisted() -> None:
    t = Tracer("plain-fields")
    set_global_tracer(t)
    t.add_vulnerability_report(
        title="SQL Injection in /login",
        severity="high",
        category="sql_injection",
        cwe="CWE-89",
        description_plain="An attacker can read all data in your customer database by typing special characters into the login form.",
        business_impact_plain="If exploited, an attacker could read all customer email addresses and password hashes.",
        recommended_action="Update the login form to use parameterized queries.",
        fix_time_estimate="1hr",
    )
    r = t.vulnerability_reports[0]
    assert r["description_plain"].startswith("An attacker can read all data")
    assert "email addresses and password hashes" in r["business_impact_plain"]
    assert r["recommended_action"] == "Update the login form to use parameterized queries."
    assert r["fix_time_estimate"] == "1hr"


def test_empty_plain_fields_not_persisted() -> None:
    """Agent passes None / empty string → field is absent on the report dict
    (consumers branch on key-present; don't ship empty placeholders)."""
    t = Tracer("empty-fields")
    set_global_tracer(t)
    t.add_vulnerability_report(
        title="X",
        severity="info",
        description_plain="",
        business_impact_plain="   ",
        recommended_action=None,
        fix_time_estimate="",
    )
    r = t.vulnerability_reports[0]
    assert "description_plain" not in r
    assert "business_impact_plain" not in r
    assert "recommended_action" not in r
    assert "fix_time_estimate" not in r


def test_plain_fields_stripped() -> None:
    t = Tracer("stripped")
    set_global_tracer(t)
    t.add_vulnerability_report(
        title="X",
        severity="medium",
        description_plain="  whitespace-padded  ",
        recommended_action="\nDo this thing.\n",
    )
    r = t.vulnerability_reports[0]
    assert r["description_plain"] == "whitespace-padded"
    assert r["recommended_action"] == "Do this thing."


# ---------------------------------------------------------------------------
# fix_time_estimate normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("5min", "5min"),
    ("5 min", "5min"),
    ("5 minutes", "5min"),
    ("5m", "5min"),
    ("1hr", "1hr"),
    ("1 hour", "1hr"),
    ("hour", "1hr"),
    ("few hours", "1hr"),
    ("1day", "1day"),
    ("1 day", "1day"),
    ("1d", "1day"),
    ("few days", "1day"),
    ("1week", "1week+"),
    ("1 week", "1week+"),
    ("week", "1week+"),
    ("1week+", "1week+"),
    ("many days", "1week+"),
])
def test_fix_time_estimate_normalization(raw, expected) -> None:
    assert _normalize_fix_time_estimate(raw) == expected


def test_fix_time_estimate_invalid_returns_none() -> None:
    assert _normalize_fix_time_estimate("garbage") is None
    assert _normalize_fix_time_estimate("") is None
    assert _normalize_fix_time_estimate(None) is None
    assert _normalize_fix_time_estimate(42) is None


def test_fix_time_estimate_invalid_not_persisted() -> None:
    t = Tracer("bad-estimate")
    set_global_tracer(t)
    t.add_vulnerability_report(
        title="X", severity="medium", fix_time_estimate="garbage"
    )
    assert "fix_time_estimate" not in t.vulnerability_reports[0]


# ---------------------------------------------------------------------------
# priority_label auto-derivation
# ---------------------------------------------------------------------------


def test_priority_label_critical_always_fix_now() -> None:
    assert _derive_priority_label("critical", is_kev=False, fix_time_estimate=None) == "fix-now"


def test_priority_label_kev_overrides_severity() -> None:
    """KEV-tagged finding is fix-now regardless of base severity."""
    assert _derive_priority_label("low", is_kev=True, fix_time_estimate=None) == "fix-now"
    assert _derive_priority_label("medium", is_kev=True, fix_time_estimate=None) == "fix-now"


def test_priority_label_severity_mapping() -> None:
    assert _derive_priority_label("high", is_kev=False, fix_time_estimate=None) == "fix-this-week"
    assert _derive_priority_label("medium", is_kev=False, fix_time_estimate=None) == "plan-a-fix"
    assert _derive_priority_label("low", is_kev=False, fix_time_estimate=None) == "informational"
    assert _derive_priority_label("info", is_kev=False, fix_time_estimate=None) == "informational"


def test_priority_label_cheap_fix_bumps_priority() -> None:
    """A high-severity finding with a 5min fix should become fix-now (cheap → just do it)."""
    assert _derive_priority_label("high", is_kev=False, fix_time_estimate="5min") == "fix-now"
    assert _derive_priority_label("high", is_kev=False, fix_time_estimate="1hr") == "fix-now"
    assert _derive_priority_label("medium", is_kev=False, fix_time_estimate="5min") == "fix-this-week"
    assert _derive_priority_label("low", is_kev=False, fix_time_estimate="5min") == "plan-a-fix"


def test_priority_label_expensive_fix_no_bump() -> None:
    """1day / 1week+ shouldn't bump — too expensive for the just-do-it heuristic."""
    assert _derive_priority_label("high", is_kev=False, fix_time_estimate="1day") == "fix-this-week"
    assert _derive_priority_label("medium", is_kev=False, fix_time_estimate="1week+") == "plan-a-fix"


def test_priority_label_emitted_on_every_finding() -> None:
    """Every finding gets a priority_label, even when the agent didn't populate
    fix_time_estimate."""
    t = Tracer("priority-default")
    set_global_tracer(t)
    t.add_vulnerability_report(title="X", severity="medium")
    assert t.vulnerability_reports[0]["priority_label"] == "plan-a-fix"


def test_priority_label_unknown_severity_is_informational() -> None:
    t = Tracer("unknown-sev")
    set_global_tracer(t)
    t.add_vulnerability_report(title="X", severity="totally-bogus-severity")
    assert t.vulnerability_reports[0]["priority_label"] == "informational"


# ---------------------------------------------------------------------------
# exploitation_in_wild_plain auto-derivation
# ---------------------------------------------------------------------------


def test_exploitation_in_wild_plain_when_kev() -> None:
    """Simulate the threat-intel enrichment having tagged the report as KEV."""
    report = {"kev": True, "cve": "CVE-2024-12345"}
    out = _derive_exploitation_in_wild_plain(report)
    assert out is not None
    assert "actively attacked" in out.lower()
    assert "CVE-2024-12345" in out


def test_exploitation_in_wild_plain_no_kev_returns_none() -> None:
    assert _derive_exploitation_in_wild_plain({"kev": False}) is None
    assert _derive_exploitation_in_wild_plain({}) is None


def test_exploitation_in_wild_plain_kev_no_cve() -> None:
    """KEV-tagged but no CVE on the finding — still get a plain-English alert."""
    out = _derive_exploitation_in_wild_plain({"kev": True})
    assert out is not None
    assert "actively attacked" in out.lower()


def test_kev_finding_auto_populates_plain_field(monkeypatch) -> None:
    """End-to-end: a KEV-tagged finding (via threat_intel.enrich) gets the plain
    English alert populated automatically without agent supplying it."""
    from strix.telemetry import threat_intel

    def fake_enrich(cwe, cve):
        return {"kev": True, "kev_known_ransomware": False}

    monkeypatch.setattr(threat_intel, "enrich", fake_enrich)
    monkeypatch.delenv("STRIX_KEV_DISABLED", raising=False)

    t = Tracer("kev-end-to-end")
    set_global_tracer(t)
    t.add_vulnerability_report(
        title="Apache Struts RCE",
        severity="high",
        cve="CVE-2017-5638",
        cwe="CWE-78",
    )
    r = t.vulnerability_reports[0]
    assert r["kev"] is True
    assert "exploitation_in_wild_plain" in r
    assert "actively attacked" in r["exploitation_in_wild_plain"].lower()
    # KEV bumps priority to fix-now regardless of severity.
    assert r["priority_label"] == "fix-now"


# ---------------------------------------------------------------------------
# run_summary.json top_findings surface
# ---------------------------------------------------------------------------


def test_top_findings_includes_non_tech_fields() -> None:
    t = Tracer("top-findings")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.add_vulnerability_report(
        title="X",
        severity="medium",
        description_plain="Plain summary here.",
        recommended_action="Fix this.",
        fix_time_estimate="1hr",
    )
    summary = t.build_run_summary()
    top = summary["top_findings"][0]
    assert top["description_plain"] == "Plain summary here."
    assert top["recommended_action"] == "Fix this."
    assert top["fix_time_estimate"] == "1hr"
    assert top["priority_label"] == "fix-this-week"  # medium + 1hr → bumped


def test_top_findings_missing_fields_are_none() -> None:
    """When the agent didn't populate the plain fields, top_findings still
    has the keys (consumers can branch on null without KeyError)."""
    t = Tracer("missing-fields")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.add_vulnerability_report(title="X", severity="info")
    summary = t.build_run_summary()
    top = summary["top_findings"][0]
    assert top["description_plain"] is None
    assert top["business_impact_plain"] is None
    assert top["recommended_action"] is None
    assert top["fix_time_estimate"] is None
    assert top["priority_label"] == "informational"
    assert top["exploitation_in_wild_plain"] is None


# ---------------------------------------------------------------------------
# Backward compat
# ---------------------------------------------------------------------------


def test_existing_call_sites_still_work() -> None:
    """Old call site without any of the new params produces a valid finding
    with priority_label auto-derived but no agent-supplied plain fields."""
    t = Tracer("legacy-call")
    set_global_tracer(t)
    rid = t.add_vulnerability_report(
        title="Legacy call",
        severity="medium",
        description="technical description",
        impact="technical impact",
        target="x",
        endpoint="/api",
    )
    assert rid
    r = t.vulnerability_reports[0]
    # Legacy fields preserved.
    assert r["description"] == "technical description"
    assert r["impact"] == "technical impact"
    # New auto-derived field added.
    assert r["priority_label"] == "plan-a-fix"
    # Agent-supplied plain fields absent.
    assert "description_plain" not in r
    assert "business_impact_plain" not in r
