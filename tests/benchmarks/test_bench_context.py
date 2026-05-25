"""Tests for iter-31.8 — context_completeness + actionable_rate bench."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_context import (
    AggregateContextReport,
    FindingContextScore,
    FixtureContextResult,
    _CONTEXT_DIMENSIONS,
    _actionable_field,
    _dimension_satisfied,
    _field_populated,
    score_finding_context,
    score_fixture_context,
)


# ---------------------------------------------------------------------------
# _field_populated
# ---------------------------------------------------------------------------

def test_field_populated_string_nonempty():
    assert _field_populated({"x": "hi"}, "x") is True


def test_field_populated_empty_string_is_false():
    assert _field_populated({"x": ""}, "x") is False
    assert _field_populated({"x": "   "}, "x") is False


def test_field_populated_missing_key():
    assert _field_populated({}, "x") is False


def test_field_populated_list_nonempty():
    assert _field_populated({"x": [1, 2]}, "x") is True


def test_field_populated_list_empty():
    assert _field_populated({"x": []}, "x") is False


def test_field_populated_dict_nonempty():
    assert _field_populated({"x": {"k": "v"}}, "x") is True


def test_field_populated_dict_empty():
    assert _field_populated({"x": {}}, "x") is False


def test_field_populated_zero_int_is_false():
    assert _field_populated({"x": 0}, "x") is False


def test_field_populated_nonzero_int_is_true():
    assert _field_populated({"x": 42}, "x") is True


def test_field_populated_bool_true_false():
    assert _field_populated({"x": True}, "x") is True
    assert _field_populated({"x": False}, "x") is False


# ---------------------------------------------------------------------------
# _dimension_satisfied — location
# ---------------------------------------------------------------------------

def test_location_satisfied_by_file_and_line():
    f = {"file": "app.py", "line": 22}
    assert _dimension_satisfied(f, "location")


def test_location_satisfied_by_endpoint_alone():
    f = {"endpoint": "/api/users"}
    assert _dimension_satisfied(f, "location")


def test_location_satisfied_by_code_locations_list():
    f = {"code_locations": [{"file": "app.py", "line_number": 51}]}
    assert _dimension_satisfied(f, "location")


def test_location_satisfied_by_code_locations_with_line_key():
    """Either `line` OR `line_number` works."""
    f = {"code_locations": [{"file": "app.py", "line": 51}]}
    assert _dimension_satisfied(f, "location")


def test_location_not_satisfied_when_file_alone_without_line():
    f = {"file": "app.py"}
    assert _dimension_satisfied(f, "location") is False


def test_location_not_satisfied_by_empty_dict():
    assert _dimension_satisfied({}, "location") is False


# ---------------------------------------------------------------------------
# _dimension_satisfied — other dimensions
# ---------------------------------------------------------------------------

def test_author_dimension_via_blame_author():
    assert _dimension_satisfied({"blame_author": "alice@x"}, "author")


def test_author_dimension_via_git_blame_block():
    assert _dimension_satisfied({"git_blame": {"author": "bob"}}, "author")


def test_fix_hint_via_recommended_action():
    f = {"recommended_action": "Use prepared statements"}
    assert _dimension_satisfied(f, "fix_hint")


def test_fix_hint_via_remediation_steps():
    f = {"remediation_steps": "Patch CVE-2024-1234"}
    assert _dimension_satisfied(f, "fix_hint")


def test_exploit_vector_via_poc_script_code():
    f = {"poc_script_code": "curl ..."}
    assert _dimension_satisfied(f, "exploit_vector")


def test_exploit_vector_via_technical_analysis():
    f = {"technical_analysis": "send `' OR 1=1--`"}
    assert _dimension_satisfied(f, "exploit_vector")


def test_business_impact_via_plain():
    f = {"business_impact_plain": "Attacker dumps user table"}
    assert _dimension_satisfied(f, "business_impact")


def test_business_impact_via_contextual_priority():
    f = {"contextual_priority": {"asset_context": {"criticality": "high"}}}
    assert _dimension_satisfied(f, "business_impact")


# ---------------------------------------------------------------------------
# _actionable_field
# ---------------------------------------------------------------------------

def test_actionable_via_remediation_steps():
    assert _actionable_field({"remediation_steps": "fix x"}) == "remediation_steps"


def test_actionable_via_next_probes():
    assert _actionable_field({"next_probes_suggested": ["probe1"]}) == "next_probes_suggested"


def test_actionable_returns_first_populated_path():
    """When multiple actionable fields are populated, return the
    canonical-order first one."""
    f = {"recommended_action": "x", "remediation_steps": "y"}
    # next_probes_suggested is first in the tuple, recommended_action is second
    assert _actionable_field(f) == "recommended_action"


def test_actionable_returns_none_when_no_fields():
    assert _actionable_field({"title": "x"}) is None


# ---------------------------------------------------------------------------
# score_finding_context
# ---------------------------------------------------------------------------

def test_score_finding_full_context():
    f = {
        "id": "v1", "title": "SQLi", "severity": "critical",
        "file": "app.py", "line": 22,
        "blame_author": "alice@example.com",
        "recommended_action": "use prepared statements",
        "poc_script_code": "curl ...",
        "business_impact_plain": "attacker dumps users",
    }
    s = score_finding_context(f)
    assert set(s.dimensions_present) == set(_CONTEXT_DIMENSIONS.keys())
    assert s.dimensions_missing == []
    assert s.actionable is True


def test_score_finding_missing_author_and_fix():
    f = {
        "id": "v1", "title": "X",
        "endpoint": "/api/users",
        "poc_script_code": "curl ...",
        "business_impact_plain": "blah",
    }
    s = score_finding_context(f)
    assert "author" in s.dimensions_missing
    assert "fix_hint" in s.dimensions_missing
    assert "location" in s.dimensions_present
    # poc_script_code is also an actionable field
    assert s.actionable is True


def test_score_finding_completely_bare():
    s = score_finding_context({"id": "v0", "title": "bare"})
    assert s.dimensions_present == []
    assert len(s.dimensions_missing) == 5
    assert s.actionable is False


# ---------------------------------------------------------------------------
# score_fixture_context
# ---------------------------------------------------------------------------

def test_score_fixture_perfect_context():
    findings = [
        {
            "id": "v1", "file": "app.py", "line": 22,
            "blame_author": "alice", "recommended_action": "fix",
            "poc_script_code": "curl", "business_impact_plain": "bad",
        },
        {
            "id": "v2", "endpoint": "/api", "git_blame": {"author": "bob"},
            "remediation_steps": "patch", "technical_analysis": "send X",
            "impact": "moderate",
        },
    ]
    r = score_fixture_context("test", findings)
    assert r.findings_total == 2
    assert r.findings_with_full_context == 2
    assert r.context_completeness == 1.0
    assert r.actionable_rate == 1.0


def test_score_fixture_partial_context():
    findings = [
        {"id": "v1", "file": "app.py", "line": 22, "recommended_action": "fix"},
        {"id": "v2", "title": "bare"},
    ]
    r = score_fixture_context("test", findings)
    assert r.findings_total == 2
    # v1 has 2/5, v2 has 0/5 — neither hits full
    assert r.findings_with_full_context == 0
    assert r.context_completeness == 0.0
    # v1 has recommended_action → actionable; v2 → not
    assert r.findings_actionable == 1
    assert r.actionable_rate == 0.5


def test_score_fixture_excludes_corroborator_siblings():
    findings = [
        {"id": "v1", "file": "app.py", "line": 22,
         "blame_author": "alice", "recommended_action": "fix",
         "poc_script_code": "curl", "business_impact_plain": "bad"},
        {"id": "v2", "role": "corroborator"},
    ]
    r = score_fixture_context("test", findings)
    # v2 excluded → only v1 counted
    assert r.findings_total == 1
    assert r.context_completeness == 1.0


def test_score_fixture_no_findings_noted():
    r = score_fixture_context("test", [])
    assert r.findings_total == 0
    assert any("no findings" in n for n in r.notes)


def test_score_fixture_only_corroborator_siblings_noted():
    findings = [{"id": "v1", "role": "corroborator"}]
    r = score_fixture_context("test", findings)
    assert any("corroborator" in n for n in r.notes)


def test_score_fixture_per_dimension_presence_tracked():
    findings = [
        {"id": "v1", "file": "a.py", "line": 1, "recommended_action": "fix"},
        {"id": "v2", "endpoint": "/x", "blame_author": "bob"},
    ]
    r = score_fixture_context("test", findings)
    # v1+v2 both have location → 2; only v2 has author → 1; only v1 has fix_hint
    assert r.per_dimension_presence["location"] == 2
    assert r.per_dimension_presence["author"] == 1
    assert r.per_dimension_presence["fix_hint"] == 1


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregateContextReport(
        fixtures=[FixtureContextResult(fixture="x", findings_total=1)],
        total_findings=1,
        total_with_full_context=1,
        total_actionable=1,
        overall_context_completeness=1.0,
        overall_actionable_rate=1.0,
    )
    json.dumps(rep.to_dict())


def test_finding_context_score_serializable():
    s = FindingContextScore(
        finding_id="v1",
        dimensions_present=["location", "fix_hint"],
        dimensions_missing=["author", "exploit_vector", "business_impact"],
        actionable=True,
        actionable_field="recommended_action",
    )
    json.dumps(s.to_dict())


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_context.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"
