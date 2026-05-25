"""Tests for iter-31.5 — corroboration bench + tracer corroboration rollup."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_corroboration import (
    AggregateCorroborationReport,
    FixtureCorroborationResult,
    score_corroboration_summary,
)


# ---------------------------------------------------------------------------
# score_corroboration_summary
# ---------------------------------------------------------------------------

def test_score_perfect_corroboration():
    summary = {
        "findings_summary": {"total": 2},
        "corroborations": [
            {"parent_id": "v1", "source_count": 2, "corroborator_ids": ["v3"]},
            {"parent_id": "v2", "source_count": 3, "corroborator_ids": ["v4", "v5"]},
        ],
    }
    r = score_corroboration_summary("test", summary)
    assert r.corroborated_count == 2
    assert r.corroboration_rate == 1.0
    assert r.source_count_max == 3
    assert r.distribution == {2: 1, 3: 1}


def test_score_partial_corroboration():
    summary = {
        "findings_summary": {"total": 10},
        "corroborations": [
            {"parent_id": "v1", "source_count": 2, "corroborator_ids": ["v3"]},
            {"parent_id": "v2", "source_count": 2, "corroborator_ids": ["v4"]},
            {"parent_id": "v5", "source_count": 2, "corroborator_ids": ["v6"]},
        ],
    }
    r = score_corroboration_summary("test", summary)
    assert r.corroborated_count == 3
    assert r.corroboration_rate == 0.3


def test_score_no_corroborations_listed():
    summary = {
        "findings_summary": {"total": 5},
        "corroborations": [],
    }
    r = score_corroboration_summary("test", summary)
    assert r.corroborated_count == 0
    assert r.corroboration_rate == 0.0


def test_score_no_findings_at_all():
    summary = {
        "findings_summary": {"total": 0},
        "corroborations": [],
    }
    r = score_corroboration_summary("test", summary)
    assert r.total_findings == 0
    assert r.corroboration_rate == 0.0


def test_score_missing_corroborations_key_noted():
    """Pre-iter-31.5 runs that don't have `corroborations[]` at all."""
    summary = {
        "findings_summary": {"total": 3},
        # no corroborations key
    }
    r = score_corroboration_summary("test", summary)
    assert r.corroborated_count == 0
    assert r.corroboration_rate == 0.0
    assert any("pre-iter-31.5" in n for n in r.notes)


def test_score_non_dict_summary_noted():
    r = score_corroboration_summary("test", None)  # type: ignore[arg-type]
    assert any("not a dict" in n for n in r.notes)


def test_score_distribution_excludes_single_source_entries():
    """source_count == 1 shouldn't show up in distribution — that's
    not corroboration."""
    summary = {
        "findings_summary": {"total": 5},
        "corroborations": [
            {"parent_id": "v1", "source_count": 1},  # malformed; skip
            {"parent_id": "v2", "source_count": 2, "corroborator_ids": ["x"]},
        ],
    }
    r = score_corroboration_summary("test", summary)
    assert r.distribution == {2: 1}


def test_score_p50_source_count_computed():
    summary = {
        "findings_summary": {"total": 10},
        "corroborations": [
            {"parent_id": "a", "source_count": 2, "corroborator_ids": ["x"]},
            {"parent_id": "b", "source_count": 3, "corroborator_ids": ["x", "y"]},
            {"parent_id": "c", "source_count": 5, "corroborator_ids": ["x", "y", "z", "w"]},
        ],
    }
    r = score_corroboration_summary("test", summary)
    assert r.source_count_p50 == 3.0
    assert r.source_count_max == 5


# ---------------------------------------------------------------------------
# Aggregate report dataclass
# ---------------------------------------------------------------------------

def test_aggregate_report_serializable():
    rep = AggregateCorroborationReport(
        fixtures=[
            FixtureCorroborationResult(
                fixture="x",
                total_findings=10,
                corroborated_count=3,
                corroboration_rate=0.3,
            ),
        ],
        total_findings=10,
        total_corroborated=3,
        overall_corroboration_rate=0.3,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------

def test_tracer_collects_corroboration_summary():
    """`build_run_summary()` should include `corroborations[]` +
    `corroborations_count` + `corroboration_rate`."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="corroboration_test")
    # Synthesize what the corroborator_ledger would attach.
    tr.vulnerability_reports.extend([
        {
            "id": "v1",
            "severity": "critical",
            "category": "sqli",
            "endpoint": "http://app/login",
            "corroborated_by": ["v2"],
        },
        {
            "id": "v2",
            "severity": "info",
            "role": "corroborator",
            "corroborates": "v1",
        },
        {
            "id": "v3",
            "severity": "medium",
            "category": "xss",
        },
    ])
    summary = tr.build_run_summary()
    # v1 is corroborated by v2 → 1 corroboration
    assert summary["corroborations_count"] == 1
    assert len(summary["corroborations"]) == 1
    c = summary["corroborations"][0]
    assert c["parent_id"] == "v1"
    assert c["corroborator_ids"] == ["v2"]
    assert c["source_count"] == 2
    # Parent_eligible_total = 2 (v1 + v3 — v2 is corroborator sibling, excluded)
    # → rate = 1/2 = 0.5
    assert summary["corroboration_rate"] == 0.5


def test_tracer_corroboration_rate_excludes_corroborator_siblings():
    """A corroborator sibling (role=corroborator) shouldn't inflate the
    denominator of corroboration_rate."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="corroboration_denom_test")
    tr.vulnerability_reports.extend([
        {"id": "v1", "severity": "high", "corroborated_by": ["v2", "v3"]},
        {"id": "v2", "severity": "info", "role": "corroborator"},
        {"id": "v3", "severity": "info", "role": "corroborator"},
    ])
    summary = tr.build_run_summary()
    # Only v1 counts in the denominator (v2 + v3 are corroborator
    # siblings). 1/1 → 1.0
    assert summary["corroboration_rate"] == 1.0
    # source_count = parent (v1) + 2 corroborators = 3
    assert summary["corroborations"][0]["source_count"] == 3


def test_tracer_empty_no_corroborations():
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="empty_corrob")
    summary = tr.build_run_summary()
    assert summary["corroborations"] == []
    assert summary["corroborations_count"] == 0
    assert summary["corroboration_rate"] == 0.0


def test_tracer_findings_with_no_corroboration_yield_zero_rate():
    """Findings exist but none corroborated → rate is 0.0, not crash."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="no_corrob_findings")
    tr.vulnerability_reports.extend([
        {"id": "v1", "severity": "high", "category": "sqli"},
        {"id": "v2", "severity": "medium", "category": "xss"},
    ])
    summary = tr.build_run_summary()
    assert summary["corroborations_count"] == 0
    assert summary["corroboration_rate"] == 0.0


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_corroboration.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich",
        "juice-sh.op",
        "/rest/user/login",
        "/users/v1/_debug",
        "vampi-admin",
        "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"
