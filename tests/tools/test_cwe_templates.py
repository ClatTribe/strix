"""Tests for `strix/tools/reporting/cwe_templates.py` — step 7
of the v2 cost-optimization plan (workflow phase 7 — report).

Recall-safety contract pinned by tests:
  * Agent-supplied values ALWAYS win — templates only fill
    fields the agent left blank / None.
  * Unknown CWEs get no template (no behavior change).
  * Kill switch bypasses every template.
  * Bad input (missing CWE, malformed CWE string) doesn't crash
    — `template_for` returns None.
"""

from __future__ import annotations

import pytest

from strix.tools.reporting import cwe_templates as ct


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_CWE_TEMPLATES_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# CWE normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("inp,expected", [
    ("CWE-89", "CWE-89"),
    ("cwe-89", "CWE-89"),
    ("CWE89", "CWE-89"),
    ("cwe89", "CWE-89"),
    ("CWE 89", "CWE-89"),
    ("cwe_89", "CWE-89"),
    ("CWE-89 SQL Injection", "CWE-89"),
    ("89", "CWE-89"),
    ("", ""),
    (None, ""),
    ("not a cwe", ""),
])
def test_normalize_cwe(inp, expected) -> None:
    assert ct._normalize_cwe(inp) == expected


# ---------------------------------------------------------------------------
# Template lookup
# ---------------------------------------------------------------------------


def test_template_for_known_cwe() -> None:
    tpl = ct.template_for("CWE-89")
    assert tpl is not None
    assert "parameterized queries" in tpl["recommended_action"].lower()
    assert tpl["fix_time_estimate"]
    assert tpl["business_impact_plain"]


def test_template_for_normalizes_input() -> None:
    tpl_canonical = ct.template_for("CWE-89")
    tpl_messy = ct.template_for("cwe89 SQL Injection")
    assert tpl_messy == tpl_canonical


def test_template_for_unknown_cwe_returns_none() -> None:
    assert ct.template_for("CWE-99999") is None


def test_template_for_missing_cwe_returns_none() -> None:
    assert ct.template_for(None) is None
    assert ct.template_for("") is None


def test_template_for_disabled_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_CWE_TEMPLATES_DISABLED", "1")
    assert ct.template_for("CWE-89") is None


# ---------------------------------------------------------------------------
# auto_fill_missing_fields — recall-safety: agent values win
# ---------------------------------------------------------------------------


def test_auto_fill_populates_missing_fields() -> None:
    out = ct.auto_fill_missing_fields(
        cwe="CWE-89",
        recommended_action=None,
        fix_time_estimate=None,
        business_impact_plain=None,
    )
    assert out["template_applied"] is True
    assert out["template_cwe"] == "CWE-89"
    assert "parameterized" in out["recommended_action"].lower()
    assert out["fix_time_estimate"]
    assert out["business_impact_plain"]


def test_auto_fill_preserves_agent_supplied_recommendation() -> None:
    """Agent's explicit value MUST win — never overwritten."""
    out = ct.auto_fill_missing_fields(
        cwe="CWE-89",
        recommended_action="Use Drizzle ORM with prepared statements.",
        fix_time_estimate=None,
        business_impact_plain=None,
    )
    assert out["recommended_action"] == "Use Drizzle ORM with prepared statements."
    # Other missing fields still filled
    assert out["fix_time_estimate"]
    assert out["template_applied"] is True


def test_auto_fill_preserves_all_agent_supplied_fields() -> None:
    """When the agent supplied every field, template never fires
    even though CWE is registered."""
    out = ct.auto_fill_missing_fields(
        cwe="CWE-89",
        recommended_action="A",
        fix_time_estimate="B",
        business_impact_plain="C",
    )
    assert out["recommended_action"] == "A"
    assert out["fix_time_estimate"] == "B"
    assert out["business_impact_plain"] == "C"
    assert out["template_applied"] is False


def test_auto_fill_empty_string_treated_as_missing() -> None:
    """Empty strings ARE treated as missing — agent intent is
    not preserved by `""`."""
    out = ct.auto_fill_missing_fields(
        cwe="CWE-89",
        recommended_action="",
        fix_time_estimate="",
        business_impact_plain="",
    )
    assert out["recommended_action"]  # filled
    assert out["template_applied"] is True


def test_auto_fill_unknown_cwe_returns_unchanged() -> None:
    out = ct.auto_fill_missing_fields(
        cwe="CWE-99999",
        recommended_action=None,
        fix_time_estimate=None,
        business_impact_plain=None,
    )
    assert out["template_applied"] is False
    assert out["recommended_action"] is None
    assert out["template_cwe"] is None


def test_auto_fill_disabled_returns_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_CWE_TEMPLATES_DISABLED", "1")
    out = ct.auto_fill_missing_fields(
        cwe="CWE-89",
        recommended_action=None,
        fix_time_estimate=None,
        business_impact_plain=None,
    )
    assert out["template_applied"] is False
    assert out["recommended_action"] is None


# ---------------------------------------------------------------------------
# Coverage canary — every templated CWE has all 3 fields
# ---------------------------------------------------------------------------


def test_every_template_has_all_three_fields() -> None:
    """Schema invariant: each template must provide all three
    boilerplate fields. A template with only some fields would
    leave gaps the agent has to fill anyway."""
    for cwe in ct.list_templated_cwes():
        tpl = ct.template_for(cwe)
        assert tpl is not None
        for required in (
            "recommended_action",
            "fix_time_estimate",
            "business_impact_plain",
        ):
            assert required in tpl, (
                f"template for {cwe} missing required field {required}"
            )
            assert tpl[required], (
                f"template for {cwe} has empty {required}"
            )


def test_coverage_includes_owasp_top_10_classes() -> None:
    """Smoke check — the most common OWASP Top 10 / reasoning-bound
    classes have templates. Adding a class here without a
    corresponding template breaks this test on purpose, forcing
    the contributor to add the template."""
    required_cwes = {
        "CWE-89",   # SQLi
        "CWE-79",   # XSS
        "CWE-78",   # Command injection
        "CWE-22",   # Path traversal
        "CWE-918",  # SSRF
        "CWE-502",  # Deserialization
        "CWE-639",  # IDOR
        "CWE-915",  # Mass assignment
        "CWE-862",  # Missing authz
        "CWE-200",  # Info disclosure
        "CWE-347",  # Signature verification
        "CWE-601",  # Open redirect
        "CWE-611",  # XXE
    }
    have = set(ct.list_templated_cwes())
    missing = required_cwes - have
    assert not missing, f"missing canonical CWE templates: {sorted(missing)}"
