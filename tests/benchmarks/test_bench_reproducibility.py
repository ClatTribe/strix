"""Tests for iter-31.7 — reproducibility_rate bench + tracer rollup."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_reproducibility import (
    AggregateReproducibilityReport,
    FixtureReproducibilityResult,
    score_reproducibility,
)


# ---------------------------------------------------------------------------
# score_reproducibility
# ---------------------------------------------------------------------------

def test_score_all_verified_perfect_rate():
    summary = {"reproducibility_by_tier": {"verified": 5}}
    r = score_reproducibility("test", summary)
    assert r.findings_total == 5
    assert r.strong_count == 5
    assert r.reproducibility_rate == 1.0


def test_score_exploited_counted_as_strong():
    summary = {"reproducibility_by_tier": {"exploited": 3, "verified": 2}}
    r = score_reproducibility("test", summary)
    assert r.strong_count == 5
    assert r.reproducibility_rate == 1.0


def test_score_likely_only_within_likely_rate():
    summary = {"reproducibility_by_tier": {"likely": 3, "verified": 1}}
    r = score_reproducibility("test", summary)
    assert r.findings_total == 4
    assert r.strong_count == 1
    assert r.weak_count == 3
    assert r.reproducibility_rate == 0.25
    assert r.reproducibility_rate_within_likely == 1.0


def test_score_suspected_dismissed_excluded_from_rates():
    summary = {
        "reproducibility_by_tier": {
            "verified": 1,
            "suspected": 5,
            "dismissed": 2,
            "pattern_match": 3,
        },
    }
    r = score_reproducibility("test", summary)
    # Total = 11, strong = 1
    assert r.findings_total == 11
    assert r.strong_count == 1
    assert r.reproducibility_rate == 0.091  # rounded


def test_score_no_tier_field_pre_iter31_7():
    summary = {"findings_summary": {"total": 5}}
    r = score_reproducibility("test", summary)
    assert r.findings_total == 0
    assert any("pre-iter-31.7" in n for n in r.notes)


def test_score_empty_tier_dict():
    summary = {"reproducibility_by_tier": {}}
    r = score_reproducibility("test", summary)
    assert r.findings_total == 0
    assert r.reproducibility_rate == 0.0


def test_score_non_dict_summary():
    r = score_reproducibility("test", None)  # type: ignore[arg-type]
    assert any("not a dict" in n for n in r.notes)


def test_score_garbage_count_value_skipped():
    summary = {"reproducibility_by_tier": {"verified": "not-an-int", "likely": 2}}
    r = score_reproducibility("test", summary)
    # Garbage "not-an-int" skipped → only likely=2 counted
    assert r.findings_total == 2
    assert r.weak_count == 2


def test_score_zero_or_negative_counts_skipped():
    summary = {"reproducibility_by_tier": {"verified": 0, "likely": -1, "exploited": 2}}
    r = score_reproducibility("test", summary)
    assert r.findings_total == 2
    assert r.strong_count == 2


def test_score_unknown_tier_in_denominator_only():
    """A tier label the bench doesn't recognize (e.g. agent invents
    `'partially_verified'`) lands in the denominator but neither bucket."""
    summary = {
        "reproducibility_by_tier": {
            "verified": 1, "partially_verified": 3,
        },
    }
    r = score_reproducibility("test", summary)
    assert r.findings_total == 4
    assert r.strong_count == 1
    assert r.weak_count == 0
    # 1/4
    assert r.reproducibility_rate == 0.25


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregateReproducibilityReport(
        fixtures=[
            FixtureReproducibilityResult(
                fixture="x",
                findings_total=10,
                strong_count=7,
                reproducibility_rate=0.7,
            ),
        ],
        total_findings=10,
        total_strong=7,
        overall_reproducibility_rate=0.7,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------

def test_tracer_builds_reproducibility_summary():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="repro_test")
    tr.vulnerability_reports.extend([
        {"id": "v1", "verification_status": "verified"},
        {"id": "v2", "verification_status": "exploited"},
        {"id": "v3", "verification_status": "likely"},
        {"id": "v4", "verification_status": "suspected"},
    ])
    summary = tr.build_run_summary()
    # strong = 2, weak = 1, total = 4
    assert summary["reproducibility_findings_total"] == 4
    assert summary["reproducibility_rate"] == 0.5
    assert summary["reproducibility_rate_within_likely"] == 0.75
    assert summary["reproducibility_by_tier"] == {
        "verified": 1, "exploited": 1, "likely": 1, "suspected": 1,
    }


def test_tracer_excludes_corroborator_siblings_from_repro():
    """Corroborator-role siblings don't count — they don't have their
    own PoC verification."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="repro_corrob")
    tr.vulnerability_reports.extend([
        {"id": "v1", "verification_status": "verified"},
        {"id": "v2", "verification_status": "verified", "role": "corroborator"},
    ])
    summary = tr.build_run_summary()
    # v2 excluded → total = 1
    assert summary["reproducibility_findings_total"] == 1
    assert summary["reproducibility_rate"] == 1.0


def test_tracer_skips_findings_without_verification_status():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="repro_no_vs")
    tr.vulnerability_reports.extend([
        {"id": "v1", "verification_status": "verified"},
        {"id": "v2"},  # no verification_status at all
        {"id": "v3", "verification_status": ""},
    ])
    summary = tr.build_run_summary()
    assert summary["reproducibility_findings_total"] == 1


def test_tracer_no_findings_zero_rate():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="repro_empty")
    summary = tr.build_run_summary()
    assert summary["reproducibility_findings_total"] == 0
    assert summary["reproducibility_rate"] == 0.0
    assert summary["reproducibility_by_tier"] == {}


def test_tracer_case_insensitive_tier_normalization():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="repro_case")
    tr.vulnerability_reports.extend([
        {"id": "v1", "verification_status": "VERIFIED"},
        {"id": "v2", "verification_status": "  Exploited  "},
    ])
    summary = tr.build_run_summary()
    assert summary["reproducibility_rate"] == 1.0
    # Tier histogram lowercased
    assert "verified" in summary["reproducibility_by_tier"]
    assert "exploited" in summary["reproducibility_by_tier"]


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_reproducibility.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"
