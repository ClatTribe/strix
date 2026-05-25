"""Tests for iter-31.9 — surface_discovery_breadth bench."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_surface import (
    AggregateSurfaceReport,
    FixtureSurfaceResult,
    _load_expected_endpoint_count,
    score_fixture_surface,
)


# ---------------------------------------------------------------------------
# score_fixture_surface
# ---------------------------------------------------------------------------

def test_score_perfect_breadth():
    summary = {
        "endpoints_discovered_total": 50,
        "endpoints_discovered_pre_auth": 30,
        "endpoints_discovered_post_auth": 20,
    }
    r = score_fixture_surface("test", 50, summary)
    assert r.actual_endpoint_count == 50
    assert r.surface_discovery_breadth == 1.0
    assert r.over_discovery is False


def test_score_partial_breadth():
    summary = {"endpoints_discovered_total": 30}
    r = score_fixture_surface("test", 60, summary)
    assert r.surface_discovery_breadth == 0.5


def test_score_over_discovery_capped_at_one():
    """Discovering more endpoints than expected is a win but
    doesn't inflate the rate above 100% — over_discovery flag
    surfaces it instead."""
    summary = {"endpoints_discovered_total": 100}
    r = score_fixture_surface("test", 60, summary)
    assert r.surface_discovery_breadth == 1.0
    assert r.over_discovery is True


def test_score_no_endpoints_zero_rate():
    summary = {"endpoints_discovered_total": 0}
    r = score_fixture_surface("test", 50, summary)
    assert r.surface_discovery_breadth == 0.0


def test_score_no_expected_count_only_absolute():
    summary = {"endpoints_discovered_total": 42}
    r = score_fixture_surface("test", None, summary)
    assert r.actual_endpoint_count == 42
    assert r.surface_discovery_breadth == 0.0  # rate not computable
    assert any("no `expected_endpoint_count`" in n for n in r.notes)


def test_score_non_dict_summary():
    r = score_fixture_surface("test", 50, None)  # type: ignore[arg-type]
    assert any("not a dict" in n for n in r.notes)


def test_score_missing_keys_treated_as_zero():
    """Summary without iter-31.9 keys at all → 0 endpoints discovered."""
    r = score_fixture_surface("test", 50, {})
    assert r.actual_endpoint_count == 0
    assert r.surface_discovery_breadth == 0.0


def test_score_pre_post_split_tracked():
    summary = {
        "endpoints_discovered_total": 30,
        "endpoints_discovered_pre_auth": 20,
        "endpoints_discovered_post_auth": 10,
    }
    r = score_fixture_surface("test", 30, summary)
    assert r.actual_endpoints_pre_auth == 20
    assert r.actual_endpoints_post_auth == 10


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def test_load_expected_endpoint_count_from_yaml(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "target: http://app\nexpected_endpoint_count: 60\n"
    )
    assert _load_expected_endpoint_count(fixture) == 60


def test_load_missing_yaml_returns_none(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    assert _load_expected_endpoint_count(fixture) is None


def test_load_yaml_without_field_returns_none(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text("target: http://app\n")
    assert _load_expected_endpoint_count(fixture) is None


def test_load_garbage_value_returns_none(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_endpoint_count: not-a-number\n"
    )
    assert _load_expected_endpoint_count(fixture) is None


def test_load_zero_or_negative_returns_none(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text("expected_endpoint_count: 0\n")
    assert _load_expected_endpoint_count(fixture) is None


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregateSurfaceReport(
        fixtures=[FixtureSurfaceResult(
            fixture="x",
            expected_endpoint_count=50,
            actual_endpoint_count=40,
            surface_discovery_breadth=0.8,
        )],
        total_expected=50,
        total_actual=40,
        overall_surface_discovery_breadth=0.8,
    )
    json.dumps(rep.to_dict())


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------

def test_tracer_build_run_summary_includes_surface_breadth():
    """Tracer.build_run_summary() exposes the surface-breadth keys
    even when workflow_state has no recorded endpoints (returns 0)."""
    from strix.telemetry.tracer import Tracer
    from strix.agents import workflow_state

    workflow_state.reset_for_testing()
    tr = Tracer(run_name="surface_smoke")
    summary = tr.build_run_summary()
    assert "endpoints_discovered_total" in summary
    assert "endpoints_discovered_pre_auth" in summary
    assert "endpoints_discovered_post_auth" in summary
    assert "endpoints_discovered_sample" in summary
    # Empty state → zero counts
    assert summary["endpoints_discovered_total"] == 0


def test_tracer_surface_breadth_reflects_workflow_state():
    """When workflow_state has endpoints, the tracer reflects them."""
    from strix.telemetry.tracer import Tracer
    from strix.agents import workflow_state

    workflow_state.reset_for_testing()
    workflow_state.record_endpoint_discovered("http://app/api/users")
    workflow_state.record_endpoint_discovered("http://app/api/products")
    workflow_state.record_endpoint_discovered("http://app/api/products")  # dup
    tr = Tracer(run_name="surface_with_endpoints")
    summary = tr.build_run_summary()
    assert summary["endpoints_discovered_total"] == 2
    assert summary["endpoints_discovered_pre_auth"] == 2
    # Cleanup for other tests
    workflow_state.reset_for_testing()


# ---------------------------------------------------------------------------
# Fixture overlay acceptance
# ---------------------------------------------------------------------------

def test_default_fixtures_have_expected_endpoint_count():
    """Acceptance: api/vampi + web/juiceshop both have
    `expected_endpoint_count` declared. flask-vuln (code target) is
    exempt — code targets don't enumerate URL endpoints."""
    fixtures_root = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "fixtures"
    )
    for t in ("api/vampi", "web/juiceshop"):
        n = _load_expected_endpoint_count(fixtures_root / t)
        assert n is not None, (
            f"fixture {t} must declare expected_endpoint_count "
            f"(iter-31.9 acceptance criterion)"
        )
        assert n > 0


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_surface.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"
