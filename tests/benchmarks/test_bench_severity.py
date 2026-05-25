"""Tests for iter-31.3 — severity calibration bench."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_severity import (
    AggregateSeverityReport,
    FixtureSeverityResult,
    SeverityMatch,
    _finding_matches_expected,
    _load_expected_findings,
    _normalize_tier,
    _tier_distance,
    score_fixture_severity,
)


# ---------------------------------------------------------------------------
# Tier helpers
# ---------------------------------------------------------------------------

def test_normalize_tier_lowercase_known():
    assert _normalize_tier("HIGH") == "high"


def test_normalize_tier_unknown_falls_back_to_info():
    assert _normalize_tier("severe") == "info"
    assert _normalize_tier(None) == "info"
    assert _normalize_tier(42) == "info"


def test_tier_distance_zero_for_same():
    assert _tier_distance("high", "high") == 0


def test_tier_distance_one_off_adjacent():
    assert _tier_distance("medium", "high") == 1
    assert _tier_distance("low", "medium") == 1


def test_tier_distance_critical_vs_low():
    assert _tier_distance("low", "critical") == 3


def test_tier_distance_unknown_inputs_map_to_info():
    # "garbage" → info=0; "info" → 0 → distance 0
    assert _tier_distance("garbage", "info") == 0
    assert _tier_distance("garbage", "critical") == 4


# ---------------------------------------------------------------------------
# Finding match logic
# ---------------------------------------------------------------------------

def test_match_when_category_and_file_align():
    expected = {"id": "x", "category": "sqli", "file": "app.py"}
    actual = {"category": "sqli", "file": "/repo/src/app.py"}
    assert _finding_matches_expected(expected, actual)


def test_match_when_category_and_endpoint_align():
    expected = {"id": "x", "category": "sqli", "endpoint": "/api/users/v1"}
    actual = {"category": "sqli", "endpoint": "http://app/api/users/v1/login"}
    assert _finding_matches_expected(expected, actual)


def test_match_rejects_category_mismatch():
    expected = {"id": "x", "category": "sqli", "file": "app.py"}
    actual = {"category": "xss", "file": "app.py"}
    assert not _finding_matches_expected(expected, actual)


def test_match_rejects_location_mismatch():
    expected = {"id": "x", "category": "sqli", "file": "app.py"}
    actual = {"category": "sqli", "file": "other/file.py"}
    assert not _finding_matches_expected(expected, actual)


def test_match_tolerates_missing_actual_category_when_locations_match():
    expected = {"id": "x", "category": "sqli", "file": "app.py"}
    actual = {"file": "/repo/app.py"}
    # Missing actual category — still match on location alone
    # (defensive: agent may emit findings without category)
    assert _finding_matches_expected(expected, actual)


def test_match_category_substring_either_direction():
    expected = {"id": "x", "category": "sqli", "file": "app.py"}
    actual = {"category": "sqli-blind", "file": "app.py"}
    assert _finding_matches_expected(expected, actual)


# ---------------------------------------------------------------------------
# score_fixture_severity
# ---------------------------------------------------------------------------

def test_score_perfect_severity_calibration():
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
        {"id": "e2", "category": "xss", "file": "app.py", "severity": "medium"},
    ]
    actual = [
        {"category": "sqli", "file": "/repo/app.py", "severity": "critical"},
        {"category": "xss", "file": "/repo/app.py", "severity": "medium"},
    ]
    result = score_fixture_severity("test", expected, actual)
    assert result.severity_tier_accuracy == 1.0
    assert result.severity_tier_accuracy_within_1 == 1.0
    assert result.exact_count == 2
    assert result.matched_count == 2


def test_score_off_by_one_caught_by_within_1():
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
    ]
    # Agent says "high" instead of "critical" — one tier off
    actual = [{"category": "sqli", "file": "/repo/app.py", "severity": "high"}]
    result = score_fixture_severity("test", expected, actual)
    assert result.severity_tier_accuracy == 0.0  # strict failed
    assert result.severity_tier_accuracy_within_1 == 1.0  # ±1 passed


def test_score_severity_off_by_three_misses_both():
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
    ]
    actual = [{"category": "sqli", "file": "/repo/app.py", "severity": "low"}]
    result = score_fixture_severity("test", expected, actual)
    assert result.severity_tier_accuracy == 0.0
    assert result.severity_tier_accuracy_within_1 == 0.0


def test_score_expected_finding_not_in_actual_does_not_grade():
    """When agent missed a finding, the bench skips severity grading
    for it — that's `must_find_recall`'s job."""
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
        {"id": "e2", "category": "xss", "file": "app.py", "severity": "medium"},
    ]
    actual = [{"category": "sqli", "file": "/repo/app.py", "severity": "critical"}]
    result = score_fixture_severity("test", expected, actual)
    assert result.matched_count == 1
    assert result.exact_count == 1
    # Denominator is matched_count, not expected_count
    assert result.severity_tier_accuracy == 1.0


def test_score_explicit_override_used_when_present():
    """When `expected_severity_tier` is set, it overrides `severity`."""
    expected = [
        {
            "id": "e1", "category": "sqli", "file": "app.py",
            "severity": "critical",
            "expected_severity_tier": "high",  # tier ground truth
        },
    ]
    # Agent says high — matches the OVERRIDE, not the technical severity
    actual = [{"category": "sqli", "file": "/repo/app.py", "severity": "high"}]
    result = score_fixture_severity("test", expected, actual)
    assert result.severity_tier_accuracy == 1.0


def test_score_no_expected_findings_skipped():
    result = score_fixture_severity("test", [], [])
    assert result.severity_tier_accuracy == 0.0
    assert any("no expected_findings" in n for n in result.notes)


def test_score_all_missed_no_match_skipped_with_note():
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
    ]
    actual = []
    result = score_fixture_severity("test", expected, actual)
    assert result.matched_count == 0
    assert any("no expected findings matched" in n for n in result.notes)


def test_score_one_actual_matched_only_once():
    """A single actual finding can't satisfy multiple expecteds —
    prevents the bench from over-crediting."""
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
        {"id": "e2", "category": "sqli", "file": "app.py", "severity": "high"},
    ]
    actual = [{"category": "sqli", "file": "/repo/app.py", "severity": "critical"}]
    result = score_fixture_severity("test", expected, actual)
    # Only one credited
    assert result.matched_count == 1


def test_severity_match_distance_recorded():
    expected = [
        {"id": "e1", "category": "sqli", "file": "app.py", "severity": "critical"},
    ]
    actual = [{"category": "sqli", "file": "/repo/app.py", "severity": "low"}]
    result = score_fixture_severity("test", expected, actual)
    assert result.matches[0].distance == 3


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def test_load_expected_findings_preserves_keys(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_findings:\n"
        "  - id: x\n    category: sqli\n    file: app.py\n    severity: critical\n"
        "  - id: y\n    category: xss\n    severity: medium\n"
    )
    out = _load_expected_findings(fixture)
    assert len(out) == 2
    assert out[0]["severity"] == "critical"
    assert out[1]["category"] == "xss"


def test_load_missing_returns_empty(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    assert _load_expected_findings(fixture) == []


def test_load_skips_entries_without_id(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_findings:\n"
        "  - id: valid\n    category: sqli\n    severity: critical\n"
        "  - category: orphan\n    severity: low\n"
    )
    out = _load_expected_findings(fixture)
    assert len(out) == 1
    assert out[0]["id"] == "valid"


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregateSeverityReport(
        fixtures=[FixtureSeverityResult(fixture="x", severity_tier_accuracy=0.9)],
        total_expected=10,
        total_matched=8,
        total_exact=7,
        overall_severity_tier_accuracy=0.875,
    )
    json.dumps(rep.to_dict())


def test_severity_match_serializable():
    m = SeverityMatch(
        expected_id="e1",
        expected_category="sqli",
        expected_severity="critical",
        actual_severity="high",
        matched=True,
        severity_within_1_match=True,
        distance=1,
    )
    json.dumps(m.to_dict())


# ---------------------------------------------------------------------------
# Anti-overfit guard
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_matching_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_severity.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich",            # Juice Shop author handle
        "juice-sh.op",           # Juice Shop public domain
        "/rest/user/login",      # Juice Shop specific path
        "vampi-admin",
        "erev0s",
        "/users/v1/_debug",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"


# ---------------------------------------------------------------------------
# Fixture-overlay acceptance — every default fixture must declare severity
# on every expected_findings[] entry (existing convention, but enforce it).
# ---------------------------------------------------------------------------

def test_default_fixtures_have_severity_on_every_finding():
    fixtures_root = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "fixtures"
    )
    for t in ("code/flask-vuln", "api/vampi", "web/juiceshop"):
        out = _load_expected_findings(fixtures_root / t)
        assert len(out) >= 1, f"{t} has no expected_findings"
        missing = [e["id"] for e in out if not e.get("severity")]
        assert not missing, (
            f"fixture {t} has expected_findings missing severity: {missing}"
        )
