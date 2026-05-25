"""Tests for iter-31.6 — phase_correlate emissions bench."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_phase_correlate import (
    AggregatePhaseCorrelateReport,
    FixturePhaseCorrelateResult,
    score_phase_correlations,
)


# ---------------------------------------------------------------------------
# score_phase_correlations
# ---------------------------------------------------------------------------

def test_score_normal_run_3_invocations():
    summary = {
        "phase_correlations": [
            {"from_phase": "recon", "to_phase": "discovery",
             "chains_built": 0, "new_chains": 0, "findings_promoted": 0},
            {"from_phase": "discovery", "to_phase": "exploitation",
             "chains_built": 1, "new_chains": 1, "findings_promoted": 1},
            {"from_phase": "exploitation", "to_phase": "impact",
             "chains_built": 2, "new_chains": 2, "findings_promoted": 4},
        ],
    }
    r = score_phase_correlations("test", summary)
    assert r.invocations == 3
    assert r.invocations_with_new_chains == 2
    assert r.total_new_chains == 3
    assert r.total_findings_promoted == 5
    assert r.new_chains_per_invocation_max == 2


def test_score_p50_computed():
    summary = {
        "phase_correlations": [
            {"new_chains": 0}, {"new_chains": 1}, {"new_chains": 3},
        ],
    }
    r = score_phase_correlations("test", summary)
    assert r.new_chains_per_invocation_p50 == 1.0


def test_score_per_phase_invocations_tracked():
    summary = {
        "phase_correlations": [
            {"to_phase": "exploitation", "new_chains": 1},
            {"to_phase": "exploitation", "new_chains": 0},
            {"to_phase": "report", "new_chains": 0},
        ],
    }
    r = score_phase_correlations("test", summary)
    assert r.per_phase_invocations == {"exploitation": 2, "report": 1}


def test_score_error_count_tracked():
    summary = {
        "phase_correlations": [
            {"new_chains": 1, "error": None},
            {"new_chains": 0, "error": "synthetic"},
        ],
    }
    r = score_phase_correlations("test", summary)
    assert r.errors == 1


def test_score_no_phase_correlations_key():
    """Pre-iter-31.6 runs that don't surface the field."""
    summary = {"findings_summary": {"total": 0}}
    r = score_phase_correlations("test", summary)
    assert r.invocations == 0
    assert any("pre-iter-31.6" in n for n in r.notes)


def test_score_empty_list_handled():
    summary = {"phase_correlations": []}
    r = score_phase_correlations("test", summary)
    assert r.invocations == 0
    assert r.notes == []


def test_score_non_dict_summary():
    r = score_phase_correlations("test", None)  # type: ignore[arg-type]
    assert any("not a dict" in n for n in r.notes)


def test_score_malformed_entries_skipped():
    summary = {
        "phase_correlations": [
            "not-a-dict",
            {"new_chains": 2},
            None,
        ],
    }
    r = score_phase_correlations("test", summary)
    # Only the dict entry counts
    assert r.invocations == 1
    assert r.total_new_chains == 2


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregatePhaseCorrelateReport(
        fixtures=[FixturePhaseCorrelateResult(fixture="x", invocations=3)],
        total_invocations=3, total_new_chains=2,
        overall_new_chains_per_invocation_p50=1.0,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------

def test_tracer_record_phase_correlation_appends_entry():
    """Calling `record_phase_correlation` appends a structured entry."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="phase_corr_test")

    class _Stub:
        def to_dict(self):
            return {
                "from_phase": "recon",
                "to_phase": "discovery",
                "chains_built": 1,
                "new_chains": 1,
                "findings_promoted": 2,
                "error": None,
            }

    tr.record_phase_correlation(_Stub())
    assert len(tr.phase_correlations) == 1
    entry = tr.phase_correlations[0]
    assert entry["to_phase"] == "discovery"
    assert entry["new_chains"] == 1
    assert "recorded_at" in entry  # timestamp added by the recorder


def test_tracer_record_accepts_raw_dict():
    """The recorder works with raw dicts too (not just dataclass results)."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="raw_dict_test")
    tr.record_phase_correlation({
        "from_phase": "exploitation",
        "to_phase": "impact",
        "new_chains": 2,
    })
    assert len(tr.phase_correlations) == 1
    assert tr.phase_correlations[0]["new_chains"] == 2


def test_tracer_record_ignores_non_dict_non_to_dict():
    """Garbage input doesn't crash and doesn't add an entry."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="bad_input")
    tr.record_phase_correlation(42)
    tr.record_phase_correlation("string")
    tr.record_phase_correlation(None)
    assert tr.phase_correlations == []


def test_tracer_build_run_summary_includes_phase_correlations():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="summary_phase_corr")
    tr.record_phase_correlation({
        "from_phase": "recon", "to_phase": "discovery", "new_chains": 1,
    })
    tr.record_phase_correlation({
        "from_phase": "discovery", "to_phase": "exploitation", "new_chains": 3,
    })
    summary = tr.build_run_summary()
    assert summary["phase_correlations_count"] == 2
    assert len(summary["phase_correlations"]) == 2
    assert summary["phase_correlations_new_chains_total"] == 4


def test_tracer_empty_phase_correlations_zero_count():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="empty_phase_corr")
    summary = tr.build_run_summary()
    assert summary["phase_correlations"] == []
    assert summary["phase_correlations_count"] == 0
    assert summary["phase_correlations_new_chains_total"] == 0


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_phase_correlate.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"
