"""Tests for iter-31.1 — FP suppression bench scorer + tracer dismissal list."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.per_target.bench_fp_suppression import (
    AggregateReport,
    FixtureFpResult,
    _dismissal_matches_expected,
    _load_expected_dismissed,
    score_fixture,
)


# ---------------------------------------------------------------------------
# _dismissal_matches_expected — shape-based match
# ---------------------------------------------------------------------------

def test_match_when_category_and_file_align():
    expected = {"id": "x", "category": "sqli", "file": "tests/auth.py", "line": 8}
    actual = {"category": "sqli", "file": "/repo/tests/auth.py", "line": 9}
    assert _dismissal_matches_expected(expected, actual)


def test_match_with_only_category_in_expected():
    """When only category is present in expected, file/line are not required."""
    expected = {"id": "x", "category": "csrf"}
    actual = {"category": "csrf", "file": "/some/path.py", "line": 42}
    assert _dismissal_matches_expected(expected, actual)


def test_match_with_only_file_in_expected():
    expected = {"id": "x", "file": "tests/auth.py"}
    actual = {"category": "sqli", "file": "/repo/tests/auth.py", "line": 8}
    assert _dismissal_matches_expected(expected, actual)


def test_match_rejects_mismatched_category():
    expected = {"id": "x", "category": "sqli", "file": "auth.py"}
    actual = {"category": "csrf", "file": "/repo/auth.py"}
    assert not _dismissal_matches_expected(expected, actual)


def test_match_rejects_far_off_line():
    """±2 line tolerance — more than that → no match."""
    expected = {"id": "x", "category": "sqli", "file": "auth.py", "line": 10}
    actual = {"category": "sqli", "file": "/repo/auth.py", "line": 50}
    assert not _dismissal_matches_expected(expected, actual)


def test_match_tolerates_2_line_drift():
    expected = {"id": "x", "category": "sqli", "file": "auth.py", "line": 10}
    actual = {"category": "sqli", "file": "/repo/auth.py", "line": 12}
    assert _dismissal_matches_expected(expected, actual)


def test_match_accepts_substring_file():
    expected = {"id": "x", "file": "auth.py"}
    actual = {"file": "/very/long/path/to/tests/auth.py"}
    assert _dismissal_matches_expected(expected, actual)


# ---------------------------------------------------------------------------
# score_fixture — the per-fixture scorer
# ---------------------------------------------------------------------------

def test_score_perfect_dismissal_accuracy():
    expected = [
        {"id": "d1", "category": "sqli", "file": "tests/auth.py"},
        {"id": "d2", "category": "csrf", "file": "tests/api.py"},
    ]
    actual = [
        {"category": "sqli", "file": "/repo/tests/auth.py", "line": 1},
        {"category": "csrf", "file": "/repo/tests/api.py", "line": 1},
    ]
    result = score_fixture("test-fixture", expected, actual)
    assert result.dismissal_accuracy == 1.0
    assert result.correctly_dismissed_count == 2
    assert result.missed_dismissals == []


def test_score_partial_dismissal_accuracy():
    expected = [
        {"id": "d1", "category": "sqli", "file": "tests/auth.py"},
        {"id": "d2", "category": "csrf", "file": "tests/api.py"},
    ]
    # Only d1 dismissed
    actual = [
        {"category": "sqli", "file": "/repo/tests/auth.py"},
    ]
    result = score_fixture("test-fixture", expected, actual)
    assert result.dismissal_accuracy == 0.5
    assert result.correctly_dismissed_count == 1
    assert result.missed_dismissals == ["d2"]


def test_score_unexpected_dismissals_logged():
    """If L1.5 dismisses something not in expected_dismissed[], that's
    'extra credit' — not penalized, but logged for visibility."""
    expected = [{"id": "d1", "category": "sqli", "file": "tests/auth.py"}]
    actual = [
        {"category": "sqli", "file": "/repo/tests/auth.py"},
        {"category": "xss", "file": "/repo/lib/foo.py", "title": "extra"},
    ]
    result = score_fixture("test-fixture", expected, actual)
    assert result.correctly_dismissed_count == 1
    assert result.dismissal_accuracy == 1.0
    assert len(result.unexpected_dismissals) == 1


def test_score_no_expected_skipped():
    """Fixture without expected_dismissed[] → no error, but flagged."""
    result = score_fixture("test", expected_dismissed=[], actual_dismissals=[])
    assert result.dismissal_accuracy == 0.0
    assert any("no expected_dismissed" in n for n in result.notes)


def test_score_each_expected_matches_one_actual_only():
    """A single actual dismissal can't satisfy multiple expecteds —
    prevents the bench from double-counting."""
    expected = [
        {"id": "d1", "category": "sqli", "file": "tests/auth.py"},
        {"id": "d2", "category": "sqli", "file": "tests/auth.py"},
    ]
    # Only ONE actual dismissal that matches the shape both expecteds want
    actual = [{"category": "sqli", "file": "/repo/tests/auth.py", "line": 1}]
    result = score_fixture("test", expected, actual)
    # Only one credited
    assert result.correctly_dismissed_count == 1
    assert len(result.missed_dismissals) == 1


# ---------------------------------------------------------------------------
# _load_expected_dismissed — YAML loader
# ---------------------------------------------------------------------------

def test_load_expected_dismissed_from_fixture(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_dismissed:\n"
        "  - id: x\n    category: sqli\n    file: tests/auth.py\n"
        "  - id: y\n    category: csrf\n"
    )
    out = _load_expected_dismissed(fixture)
    assert len(out) == 2
    assert out[0]["category"] == "sqli"


def test_load_missing_yaml_returns_empty(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    out = _load_expected_dismissed(fixture)
    assert out == []


def test_load_yaml_without_expected_dismissed_returns_empty(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "target: http://app\n"
        "expected_findings:\n"
        "  - id: x\n"
    )
    out = _load_expected_dismissed(fixture)
    assert out == []


def test_load_skips_entries_without_id(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_dismissed:\n"
        "  - id: valid\n    category: sqli\n"
        "  - category: orphan_no_id\n"
    )
    out = _load_expected_dismissed(fixture)
    assert len(out) == 1
    assert out[0]["id"] == "valid"


# ---------------------------------------------------------------------------
# Aggregate report dataclasses
# ---------------------------------------------------------------------------

def test_aggregate_report_serializable():
    import json
    rep = AggregateReport(
        fixtures=[FixtureFpResult(fixture="x", dismissal_accuracy=0.5)],
        total_expected_dismissals=10,
        total_correctly_dismissed=5,
        overall_dismissal_accuracy=0.5,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Anti-overfit: the bench source itself
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_matching_strings():
    """The bench scorer must use shape-based matching, not SUT-specific
    string literals. Path references in the default fixture list
    (`api/vampi`, `web/juiceshop`) are allowed since they're file-path
    constants; what we forbid are SUT-specific MATCHING values that
    couple the scorer to one fixture's content."""
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_fp_suppression.py"
    )
    text = src.read_text().lower()
    # SUT-specific identifier values that should never appear (these
    # would imply hardcoded match logic, not generic shape detection):
    forbidden = (
        "bkimminich",            # Juice Shop's author handle
        "juice-sh.op",           # Juice Shop's domain
        "/rest/user/login",      # Juice Shop's specific path
        "/api/challenges",       # Juice Shop's challenge endpoint
        "vampi-admin",           # vampi's hardcoded admin user
        "vapi_admin",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"


# ---------------------------------------------------------------------------
# Tracer dismissed_findings list — iter-31.1 signal
# ---------------------------------------------------------------------------

def test_tracer_records_dismissed_findings():
    """When pre_emission_fp_filter drops a finding,
    tracer.dismissed_findings[] gets populated."""
    from unittest.mock import patch
    from strix.telemetry.tracer import Tracer
    from strix.l15.fp_filter import FpFilterDecision

    tr = Tracer(run_name="test_iter_31_1")
    with patch("strix.l15.pre_emission_fp_filter") as mock_filter:
        mock_filter.return_value = FpFilterDecision(
            decision="drop", reason="test_file_path",
        )
        tr.add_vulnerability_report(
            target="http://app",
            category="sqli",
            title="planted decoy",
            severity="high",
            description="should be dropped",
            code_locations=[{"file": "tests/fixtures/auth.py", "line_number": 8}],
        )

    assert len(tr.dismissed_findings) == 1
    d = tr.dismissed_findings[0]
    assert d["category"] == "sqli"
    assert d["dismissed_by"] == "fp_filter"
    assert d["reason"] == "test_file_path"


def test_tracer_run_summary_includes_l15_dismissals():
    """build_run_summary() surfaces l15_dismissals + l15_dismissals_count
    for the bench scorer + per-org telemetry."""
    from unittest.mock import patch
    from strix.telemetry.tracer import Tracer
    from strix.l15.fp_filter import FpFilterDecision

    tr = Tracer(run_name="test_summary")
    with patch("strix.l15.pre_emission_fp_filter") as mock_filter:
        mock_filter.return_value = FpFilterDecision(
            decision="drop", reason="getenv_default",
        )
        tr.add_vulnerability_report(
            target="http://app", category="hardcoded_secret",
            title="getenv default decoy", severity="medium",
        )
        tr.add_vulnerability_report(
            target="http://app", category="hardcoded_secret",
            title="another decoy", severity="medium",
        )

    summary = tr.build_run_summary()
    assert summary["l15_dismissals_count"] == 2
    assert len(summary["l15_dismissals"]) == 2
    assert all(d["dismissed_by"] == "fp_filter" for d in summary["l15_dismissals"])


def test_tracer_no_dismissals_when_filter_allows():
    """When FP filter allows the finding, no dismissal recorded."""
    from unittest.mock import patch
    from strix.telemetry.tracer import Tracer
    from strix.l15.fp_filter import FpFilterDecision

    tr = Tracer(run_name="test")
    with patch("strix.l15.pre_emission_fp_filter") as mock_filter:
        mock_filter.return_value = FpFilterDecision(decision="allow", reason="")
        tr.add_vulnerability_report(
            target="http://app", category="sqli",
            title="real finding", severity="high",
        )
    assert tr.dismissed_findings == []


# ---------------------------------------------------------------------------
# Fixture YAML overlays present (iter-31.1 acceptance criterion)
# ---------------------------------------------------------------------------

def test_default_fixtures_have_expected_dismissed_overlays():
    """Acceptance criterion for iter-31.1: the 3 default fixtures
    (flask-vuln, vampi, juiceshop) each have ≥2 expected_dismissed[]
    entries. Catches accidental fixture overlay removal."""
    fixtures_root = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "fixtures"
    )
    targets = ["code/flask-vuln", "api/vampi", "web/juiceshop"]
    for t in targets:
        out = _load_expected_dismissed(fixtures_root / t)
        assert len(out) >= 2, (
            f"fixture {t} must have ≥2 expected_dismissed entries "
            f"(iter-31.1 acceptance criterion). Got {len(out)}."
        )
