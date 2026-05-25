"""Tests for iter-31.11 — patcher-correctness bench + tracer rollup."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_patcher_correctness import (
    AggregatePatcherReport,
    FixturePatcherResult,
    score_fixture_patcher,
)


# ---------------------------------------------------------------------------
# score_fixture_patcher
# ---------------------------------------------------------------------------

def test_score_perfect_correctness():
    summary = {
        "patches_total": 4,
        "patches_by_status": {"verified": 4},
        "patches_verified_count": 4,
        "patches_regressed_count": 0,
        "patches_applied_count": 4,
    }
    r = score_fixture_patcher("test", summary)
    assert r.patches_total == 4
    assert r.patches_verified == 4
    assert r.patch_correctness == 1.0


def test_score_partial_correctness():
    summary = {
        "patches_total": 4,
        "patches_by_status": {"verified": 3, "regressed": 1},
        "patches_verified_count": 3,
        "patches_regressed_count": 1,
        "patches_applied_count": 3,
    }
    r = score_fixture_patcher("test", summary)
    assert r.patch_correctness == 0.75


def test_score_all_regressed_zero_correctness():
    summary = {
        "patches_total": 2,
        "patches_by_status": {"regressed": 2},
        "patches_verified_count": 0,
        "patches_regressed_count": 2,
    }
    r = score_fixture_patcher("test", summary)
    assert r.patch_correctness == 0.0


def test_score_no_verify_cycles_noted():
    """All patches proposed but never verified — rate=0 + note."""
    summary = {
        "patches_total": 5,
        "patches_by_status": {"proposed": 5},
        "patches_verified_count": 0,
        "patches_regressed_count": 0,
    }
    r = score_fixture_patcher("test", summary)
    assert r.patch_correctness == 0.0
    assert any("no verify_patch cycles" in n for n in r.notes)


def test_score_no_patches_at_all():
    summary = {
        "patches_total": 0,
        "patches_by_status": {},
        "patches_verified_count": 0,
        "patches_regressed_count": 0,
    }
    r = score_fixture_patcher("test", summary)
    assert r.patches_total == 0
    assert r.patch_correctness == 0.0


def test_score_pre_iter31_11_run_noted():
    """Old run summary without patcher keys."""
    summary = {"findings_summary": {"total": 3}}
    r = score_fixture_patcher("test", summary)
    assert any("pre-iter-31.11" in n for n in r.notes)


def test_score_non_dict_summary():
    r = score_fixture_patcher("test", None)  # type: ignore[arg-type]
    assert any("not a dict" in n for n in r.notes)


def test_score_by_status_preserved():
    summary = {
        "patches_total": 3,
        "patches_by_status": {"verified": 2, "applied": 1},
        "patches_verified_count": 2,
        "patches_regressed_count": 0,
    }
    r = score_fixture_patcher("test", summary)
    assert r.by_status == {"verified": 2, "applied": 1}


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregatePatcherReport(
        fixtures=[FixturePatcherResult(
            fixture="x", patches_total=4, patches_verified=3,
            patch_correctness=0.75,
        )],
        total_patches=4,
        total_verified=3,
        total_regressed=1,
        overall_patch_correctness=0.75,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------

def test_tracer_build_run_summary_includes_patcher_keys():
    """build_run_summary() surfaces patcher keys even when no patches
    exist (returns zero counts)."""
    from strix.telemetry.tracer import Tracer
    try:
        from strix.agents import patcher
        patcher.get_registry().reset()
    except (ImportError, AttributeError):
        pass

    tr = Tracer(run_name="patcher_summary_test")
    summary = tr.build_run_summary()
    assert "patches_total" in summary
    assert "patches_by_status" in summary
    assert "patch_correctness" in summary
    assert "patches_verified_count" in summary
    assert "patches_regressed_count" in summary
    assert summary["patches_total"] == 0


def test_tracer_patcher_summary_reflects_registry():
    """When the patcher registry has patches, tracer reflects them."""
    try:
        from strix.agents.patcher import get_registry
    except ImportError:
        return  # patcher module not present — skip

    reg = get_registry()
    reg.reset()
    p = reg.propose(
        finding_id="vuln-0001",
        diff="--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-bad()\n+good()",
        commit_message="fix",
    )
    # Manually flip to verified for the test
    p.status = "verified"

    from strix.telemetry.tracer import Tracer
    tr = Tracer(run_name="patcher_registry_test")
    summary = tr.build_run_summary()
    assert summary["patches_total"] == 1
    assert summary["patches_by_status"].get("verified") == 1

    # Cleanup
    reg.reset()


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_patcher_correctness.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"
