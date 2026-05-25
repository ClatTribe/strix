"""Tests for iter-31.12 — explanation-clarity bench (heuristic mode)."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_explanation import (
    AggregateExplanationReport,
    ExplanationVerdict,
    FixtureExplanationResult,
    _band,
    _location_mentioned_in_description,
    score_finding_heuristic,
    score_fixture_explanation,
)


# ---------------------------------------------------------------------------
# Heuristic scoring
# ---------------------------------------------------------------------------

def test_heuristic_perfect_finding_scores_5():
    f = {
        "id": "v1", "title": "SQL injection in /search",
        "severity": "critical",
        "description": (
            "The /search endpoint passes user input directly into a "
            "SQL query in app.py at line 51. An attacker can dump the "
            "users table by sending ?q=' OR 1=1--. To fix: switch to "
            "parameterized queries via SQLAlchemy or psycopg2 placeholders."
        ),
        "business_impact_plain": "Full database read access for any user.",
        "recommended_action": "Use parameterized queries.",
        "poc_script_code": "curl 'http://x/search?q=%27%20OR%201=1--'",
        "file": "app.py", "line": 51,
    }
    v = score_finding_heuristic(f)
    assert v.score >= 4.5
    assert v.judge == "heuristic"


def test_heuristic_bare_finding_scores_1():
    f = {"id": "v1", "title": "X", "description": ""}
    v = score_finding_heuristic(f)
    assert v.score <= 1.5


def test_heuristic_only_short_description_scores_low():
    f = {"id": "v1", "description": "SQLi found"}
    v = score_finding_heuristic(f)
    # short description, no impact, no fix, no PoC
    assert v.score <= 2.5


def test_heuristic_medium_finding_lands_middle():
    f = {
        "id": "v1",
        "description": (
            "Reflected XSS in the search endpoint. The q parameter is "
            "echoed without encoding. Affects /#/search."
        ),
        "recommended_action": "Encode user input.",
    }
    v = score_finding_heuristic(f)
    # has desc + minlen + maxlen ok + remediation → ~3-4 raw → ~2.5-3
    assert 2.0 < v.score < 4.5


def test_heuristic_acronym_jungle_penalized():
    f = {
        "id": "v1",
        "description": "SQLI XSS CSRF SSRF XXE LFI RCE LFI SSRF",
    }
    v = score_finding_heuristic(f)
    # All bare acronyms, no useful content → should be low
    assert v.score <= 2.5


def test_heuristic_wall_of_text_penalized():
    """A 5000-char description doesn't get the maxlen-ok bonus."""
    f = {
        "id": "v1",
        "description": "x" * 5000 + " good content here",
    }
    v = score_finding_heuristic(f)
    # description present + minlen OK but maxlen_ok=0
    # → still partial credit, but less than the bonus
    assert v.score < 3.0


def test_heuristic_rubric_breakdown_returned():
    f = {
        "id": "v1",
        "description": "ok description with enough chars to pass minlen",
        "recommended_action": "fix x",
    }
    v = score_finding_heuristic(f)
    assert "has_description" in v.rubric_breakdown
    assert "has_remediation" in v.rubric_breakdown
    assert v.rubric_breakdown["has_remediation"] > 0
    assert v.rubric_breakdown["has_impact"] == 0


# ---------------------------------------------------------------------------
# _location_mentioned_in_description
# ---------------------------------------------------------------------------

def test_location_via_file_reference():
    f = {"file": "app.py", "description": "bug is in app.py around line 22"}
    assert _location_mentioned_in_description(f["description"], f) is True


def test_location_via_endpoint_reference():
    f = {
        "endpoint": "/api/users/v1",
        "description": "/api/users/v1 returns all users",
    }
    assert _location_mentioned_in_description(f["description"], f) is True


def test_location_via_line_number_pattern():
    f = {"description": "see line 42 in the controller"}
    assert _location_mentioned_in_description(f["description"], f) is True


def test_location_via_code_locations_line_number():
    f = {
        "code_locations": [{"file": "x.py", "line_number": 99}],
        "description": "issue at line 99",
    }
    assert _location_mentioned_in_description(f["description"], f) is True


def test_location_not_mentioned_returns_false():
    f = {"file": "app.py", "description": "generic bug, no location given"}
    assert _location_mentioned_in_description(f["description"], f) is False


# ---------------------------------------------------------------------------
# _band
# ---------------------------------------------------------------------------

def test_band_bucketing():
    assert _band(5.0) == "5"
    assert _band(4.5) == "5"
    assert _band(4.4) == "4"
    assert _band(3.5) == "4"
    assert _band(3.4) == "3"
    assert _band(2.5) == "3"
    assert _band(2.4) == "2"
    assert _band(1.5) == "2"
    assert _band(1.4) == "1"
    assert _band(1.0) == "1"


# ---------------------------------------------------------------------------
# score_fixture_explanation
# ---------------------------------------------------------------------------

def test_score_fixture_aggregates():
    findings = [
        {
            "id": "v1", "title": "X",
            "description": "long enough description with impact + fix details",
            "business_impact_plain": "bad", "recommended_action": "fix",
            "poc_script_code": "curl ...", "file": "app.py",
        },
        {"id": "v2", "title": "Y", "description": "X"},
    ]
    r = score_fixture_explanation("test", findings)
    assert r.findings_total == 2
    assert 1.0 <= r.p10_score <= r.p50_score <= 5.0
    # average reflects mixed quality
    assert 1.5 < r.average_score < 5.0


def test_score_fixture_excludes_corroborator_siblings():
    findings = [
        {"id": "v1", "description": "ok ok"},
        {"id": "v2", "description": "x", "role": "corroborator"},
    ]
    r = score_fixture_explanation("test", findings)
    assert r.findings_total == 1


def test_score_fixture_empty_findings():
    r = score_fixture_explanation("test", [])
    assert r.findings_total == 0
    assert any("no findings" in n for n in r.notes)


def test_score_fixture_p10_catches_worst():
    """When 9/10 findings are great and 1 is terrible, p10 should
    flag the terrible one — not the average."""
    findings = (
        [{"id": f"good-{i}",
          "description": "good explanation of the bug with impact "
                         "and a fix suggested via parameterized queries",
          "business_impact_plain": "bad", "recommended_action": "fix",
          "poc_script_code": "curl", "file": "app.py"}
         for i in range(9)]
        + [{"id": "bad", "description": ""}]
    )
    r = score_fixture_explanation("test", findings)
    assert r.average_score >= 4.0
    assert r.p10_score <= 2.0  # the worst one


# ---------------------------------------------------------------------------
# Dataclass serialization
# ---------------------------------------------------------------------------

def test_verdict_serializable():
    v = ExplanationVerdict(
        finding_id="v1", title="X", severity="high",
        score=4.2, rubric_breakdown={"has_impact": 1.0},
        judge="heuristic", rationale="ok",
    )
    json.dumps(v.to_dict())


def test_fixture_result_serializable():
    r = FixtureExplanationResult(fixture="x", findings_total=3)
    r.per_finding.append(ExplanationVerdict(finding_id="v1", score=4.0))
    json.dumps(r.to_dict())


def test_aggregate_report_serializable():
    rep = AggregateExplanationReport(
        fixtures=[FixtureExplanationResult(fixture="x", findings_total=2)],
        total_findings=2, overall_average_score=3.5,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_explanation.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"


def test_no_hardcoded_grading_keyed_to_specific_examples():
    """Heuristic must not have branches comparing to specific example
    descriptions (which would constitute a fixture-specific score
    boost)."""
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_explanation.py"
    )
    text = src.read_text()
    # No `if description ==` literal-comparison branches
    import re
    assert not re.search(
        r"if\s+description\s*==", text
    ), "heuristic has literal-comparison branch (overfit risk)"
