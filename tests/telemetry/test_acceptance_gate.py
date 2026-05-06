"""Tests for §8.5 Phase 8 — acceptance-gate validator.

Pins the §3.10 acceptance criteria computation. The validator runs
against a finished run_dir; tests use synthetic fixtures rather than
real scans.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry.acceptance_gate import (
    ACCEPTANCE_GATE_SCHEMA_VERSION,
    AcceptanceReport,
    GateResult,
    evaluate_acceptance_gates,
)


def _write_run_dir(  # noqa: PLR0913
    tmp_path: Path,
    *,
    cost_usd: float | None = 0.65,
    wall_minutes: float | None = 18.0,
    findings_count: int = 12,
    coverage_percent: float | None = 75.0,
    cache_hit_ratio: float | None = 0.65,
    peak_context_util: float | None = 0.50,
    compactions: int = 1,
    total_turns: int = 60,
    reflections: int = 4,
    phases_completed: int = 4,
) -> Path:
    """Synthesise a run_dir with the artifacts the validator reads.
    Each kwarg controls one acceptance metric — None means omit
    that signal so the validator should report it as missing."""
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()

    # vulnerabilities.json
    findings = [
        {"id": f"vuln-{i:04d}", "title": f"f{i}", "severity": "medium",
         "fingerprint": f"fp-{i}"}
        for i in range(findings_count)
    ]
    (run_dir / "vulnerabilities.json").write_text(json.dumps({
        "findings": findings,
        "schema_version": 1,
    }))

    # run_meta.json
    run_meta: dict[str, Any] = {
        "run_id": "test-run-001",
        "agent_architecture": "single-lead",
        "targets": [{"original": "http://demo.testfire.net", "type": "web_application"}],
    }
    if wall_minutes is not None:
        run_meta["start_time"] = "2026-05-06T00:00:00+00:00"
        # wall_minutes is float; produce end_time accordingly.
        from datetime import datetime, timedelta, UTC
        end = datetime(2026, 5, 6, 0, 0, 0, tzinfo=UTC) + timedelta(minutes=wall_minutes)
        run_meta["end_time"] = end.isoformat()
    (run_dir / "run_meta.json").write_text(json.dumps(run_meta))

    # coverage.json
    if coverage_percent is not None:
        (run_dir / "coverage.json").write_text(json.dumps({
            "coverage_percent": coverage_percent,
        }))

    # events.jsonl
    events: list[dict[str, Any]] = []
    if cost_usd is not None:
        events.append({
            "event_type": "run.terminated",
            "payload": {"consumed": {"cost_usd": cost_usd}},
        })
    # llm.token_breakdown events for cache_hit_ratio + context util.
    # Only emit when caller wants any of these signals; otherwise the
    # validator treats them as "no measurement".
    if (
        cache_hit_ratio is not None
        or peak_context_util is not None
        or cost_usd is not None
    ):
        payload: dict[str, Any] = {}
        if cache_hit_ratio is not None:
            payload["measured_input_tokens"] = 1000
            payload["measured_cached_tokens"] = int(1000 * cache_hit_ratio)
        if peak_context_util is not None:
            payload["context_window_utilisation"] = peak_context_util
        # Only carry per-call cost if the caller wanted it surfaced.
        # Tests that pass cost_usd=None must NOT emit a token_breakdown
        # event with cost=0.0 fallback — otherwise the validator finds
        # the 0.0 measurement instead of registering "no measurement".
        if cost_usd is not None:
            payload["measured_cost_usd"] = 0.0
        events.append({"event_type": "llm.token_breakdown", "payload": payload})
    # tool.execution.started for total_turns.
    for _ in range(total_turns):
        events.append({"event_type": "tool.execution.started", "payload": {}})
    # context.compacted for compactions.
    for _ in range(compactions):
        events.append({"event_type": "context.compacted", "payload": {}})
    # reflection.recorded for reflections.
    for _ in range(reflections):
        events.append({"event_type": "reflection.recorded", "payload": {}})
    # phase.completed for phases.
    for _ in range(phases_completed):
        events.append({"event_type": "phase.completed", "payload": {}})

    (run_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n"
    )
    return run_dir


# ---------------------------------------------------------------------------
# Schema invariants
# ---------------------------------------------------------------------------


def test_schema_version_pinned() -> None:
    assert ACCEPTANCE_GATE_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# Happy path: all gates green
# ---------------------------------------------------------------------------


def test_canonical_passing_run_passes_all_hard_gates(tmp_path: Path) -> None:
    """A run that hits every metric in the acceptable range should
    return passes=True with hard_fails=0."""
    run_dir = _write_run_dir(tmp_path)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    assert report.passes is True
    assert report.hard_fails == 0
    assert report.hard_passes == 6  # cost / wall / findings / coverage / cache / context


def test_canonical_passing_run_records_run_metadata(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    assert report.run_id == "test-run-001"
    assert report.target == "http://demo.testfire.net"
    assert report.architecture == "single-lead"


# ---------------------------------------------------------------------------
# Hard-fail per metric
# ---------------------------------------------------------------------------


def test_cost_too_high_hard_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, cost_usd=1.50)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    assert report.passes is False
    cost_row = next(r for r in report.results if r.name == "cost_usd")
    assert cost_row.passes is False
    assert cost_row.measured == 1.50


def test_cost_too_low_hard_fails(tmp_path: Path) -> None:
    """The acceptance band is $0.50-$0.80. $0.20 fails (suggests
    budget-exhaustion before completion)."""
    run_dir = _write_run_dir(tmp_path, cost_usd=0.20)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    cost_row = next(r for r in report.results if r.name == "cost_usd")
    assert cost_row.passes is False


def test_findings_below_threshold_hard_fails(tmp_path: Path) -> None:
    """Default expected_baseline_findings=20 → threshold = 10
    (50%). 5 emitted → hard fail."""
    run_dir = _write_run_dir(tmp_path, findings_count=5)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    findings_row = next(r for r in report.results if r.name == "findings_emitted")
    assert findings_row.passes is False


def test_coverage_below_70_percent_hard_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, coverage_percent=50.0)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    cov_row = next(r for r in report.results if r.name == "coverage_percent")
    assert cov_row.passes is False


def test_cache_hit_ratio_below_60_percent_hard_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, cache_hit_ratio=0.40)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    cache_row = next(r for r in report.results if r.name == "cache_hit_ratio")
    assert cache_row.passes is False


def test_context_utilisation_above_60_percent_hard_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, peak_context_util=0.85)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    ctx_row = next(
        r for r in report.results if r.name == "peak_context_window_utilisation"
    )
    assert ctx_row.passes is False


def test_wall_time_outside_band_hard_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, wall_minutes=45.0)  # too slow
    report = evaluate_acceptance_gates(run_dir=run_dir)
    wall_row = next(r for r in report.results if r.name == "wall_time_minutes")
    assert wall_row.passes is False


# ---------------------------------------------------------------------------
# Soft fails — warn but don't block
# ---------------------------------------------------------------------------


def test_too_many_compactions_soft_fails(tmp_path: Path) -> None:
    """5 compactions in 60 turns = 5/min — exceeds the soft cap."""
    run_dir = _write_run_dir(tmp_path, compactions=5, total_turns=60)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    # Soft fail does NOT flip overall passes.
    assert report.passes is True  # all hard gates still pass
    soft_row = next(r for r in report.results if r.name == "compactions_per_60_turns")
    assert soft_row.passes is False
    assert soft_row.severity == "soft"


def test_too_few_reflections_soft_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, reflections=0, phases_completed=4)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    refl_row = next(r for r in report.results if r.name == "reflections_per_phase")
    assert refl_row.passes is False
    assert refl_row.severity == "soft"
    # Hard gates still pass → overall passes.
    assert report.passes is True


# ---------------------------------------------------------------------------
# Missing measurements
# ---------------------------------------------------------------------------


def test_missing_cost_returns_hard_fail_no_measurement(tmp_path: Path) -> None:
    """When events don't carry cost data → measured=None → hard fail
    with detail='no measurement'."""
    run_dir = _write_run_dir(tmp_path, cost_usd=None)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    cost_row = next(r for r in report.results if r.name == "cost_usd")
    assert cost_row.passes is False
    assert cost_row.measured is None


def test_missing_coverage_json_hard_fails(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path, coverage_percent=None)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    cov_row = next(r for r in report.results if r.name == "coverage_percent")
    assert cov_row.passes is False
    assert cov_row.measured is None


def test_missing_run_dir_returns_error_report(tmp_path: Path) -> None:
    nonexistent = tmp_path / "no-such-dir"
    report = evaluate_acceptance_gates(run_dir=nonexistent)
    assert report.passes is False
    assert report.error is not None


# ---------------------------------------------------------------------------
# Configurable baseline
# ---------------------------------------------------------------------------


def test_expected_baseline_findings_configurable(tmp_path: Path) -> None:
    """DVWA might have different baseline; allow override."""
    run_dir = _write_run_dir(tmp_path, findings_count=8)
    # Default baseline=20 → threshold=10 → fails (8 < 10).
    report1 = evaluate_acceptance_gates(run_dir=run_dir)
    f1 = next(r for r in report1.results if r.name == "findings_emitted")
    assert f1.passes is False

    # Lower baseline=12 → threshold=6 → passes (8 ≥ 6).
    report2 = evaluate_acceptance_gates(
        run_dir=run_dir, expected_baseline_findings=12,
    )
    f2 = next(r for r in report2.results if r.name == "findings_emitted")
    assert f2.passes is True


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


def test_report_to_dict_serializes(tmp_path: Path) -> None:
    run_dir = _write_run_dir(tmp_path)
    report = evaluate_acceptance_gates(run_dir=run_dir)
    d = report.to_dict()
    # Must round-trip through json.
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert parsed["schema_version"] == 1
    assert parsed["passes"] is True
    assert isinstance(parsed["results"], list)
    assert len(parsed["results"]) == 8  # 6 hard + 2 soft


def test_gate_result_to_dict() -> None:
    g = GateResult(
        name="cost_usd", severity="hard", measured=0.65,
        threshold_min=0.50, threshold_max=0.80, passes=True,
    )
    d = g.to_dict()
    assert d["name"] == "cost_usd"
    assert d["passes"] is True
    json.dumps(d)  # serializable


# ---------------------------------------------------------------------------
# AcceptanceReport defaults
# ---------------------------------------------------------------------------


def test_acceptance_report_default_failed_state() -> None:
    """Empty report defaults to passes=False so accidental
    instantiation can't be misread as a green run."""
    r = AcceptanceReport()
    assert r.passes is False
    assert r.hard_passes == 0
    assert r.hard_fails == 0
