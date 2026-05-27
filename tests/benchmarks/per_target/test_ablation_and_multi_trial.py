"""Tests for iter-Q1.4 — ablation flags + multi-trial reporter.

Pins:
  * Env-flag accessors (`is_l15_disabled`, `is_l2_disabled`) return
    True/False correctly for all canonical truthy/falsy values.
  * Multi-trial reporter's median + p10/p90 math.
  * Metric extraction via dotted-path JSON walk.
  * Single-trial / all-failed / mixed-trial robustness.

Without these tests, ablation env-flag regressions would silently
disable the layer-attribution capability the Q1 proposal depends on.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from benchmarks.per_target.bench_ablation_flags import (
    ablation_metadata,
    active_layers_label,
    is_l15_disabled,
    is_l2_disabled,
)
from benchmarks.per_target.bench_multi_trial import (
    _BENCH_REGISTRY,
    _extract_metric,
    _percentile,
    _summarise,
)


# ---------------------------------------------------------------------------
# Env-flag accessors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("true", True),
        ("TRUE", True),
        ("yes", True),
        ("on", True),
        ("On", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("", False),
        ("garbage", False),
    ],
)
def test_is_l15_disabled_recognises_canonical_values(
    monkeypatch, value: str, expected: bool,
):
    """All canonical truthy/falsy env values map correctly."""
    monkeypatch.setenv("STRIX_L15_DISABLED", value)
    assert is_l15_disabled() is expected


def test_is_l15_disabled_default_false(monkeypatch):
    """Unset → False (default L1.5 hooks fire)."""
    monkeypatch.delenv("STRIX_L15_DISABLED", raising=False)
    assert is_l15_disabled() is False


@pytest.mark.parametrize(
    "value,expected",
    [("1", True), ("0", False), ("", False), ("yes", True)],
)
def test_is_l2_disabled(monkeypatch, value: str, expected: bool):
    monkeypatch.setenv("STRIX_L2_DISABLED", value)
    assert is_l2_disabled() is expected


def test_active_layers_label_full_stack(monkeypatch):
    monkeypatch.delenv("STRIX_L15_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_L2_DISABLED", raising=False)
    assert active_layers_label() == "L1+L1.5+L2"


def test_active_layers_label_l15_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_L15_DISABLED", "1")
    monkeypatch.delenv("STRIX_L2_DISABLED", raising=False)
    assert active_layers_label() == "L1+L2"


def test_active_layers_label_l2_disabled(monkeypatch):
    monkeypatch.delenv("STRIX_L15_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_L2_DISABLED", "1")
    assert active_layers_label() == "L1+L1.5"


def test_active_layers_label_l1_only(monkeypatch):
    monkeypatch.setenv("STRIX_L15_DISABLED", "1")
    monkeypatch.setenv("STRIX_L2_DISABLED", "1")
    assert active_layers_label() == "L1"


def test_ablation_metadata_structure(monkeypatch):
    """The metadata dict carries the boolean flags + the label."""
    monkeypatch.setenv("STRIX_L15_DISABLED", "1")
    monkeypatch.delenv("STRIX_L2_DISABLED", raising=False)
    md = ablation_metadata()
    assert md["l15_disabled"] is True
    assert md["l2_disabled"] is False
    assert md["active_layers"] == "L1+L2"


# ---------------------------------------------------------------------------
# Multi-trial: percentile + summary math
# ---------------------------------------------------------------------------


def test_percentile_p10_p90_linear_interpolation():
    """Linear-interpolation percentile matches numpy's default."""
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    # p10 of [10..50] with 5 points: index (5-1)*0.1 = 0.4
    # → 10 + 0.4*(20-10) = 14.0
    assert _percentile(values, 10) == pytest.approx(14.0)
    # p90 → index 3.6 → 40 + 0.6*(50-40) = 46.0
    assert _percentile(values, 90) == pytest.approx(46.0)
    # p50 (median) → index 2.0 → 30.0
    assert _percentile(values, 50) == pytest.approx(30.0)


def test_percentile_single_value():
    """One value → that value at every percentile."""
    assert _percentile([42.0], 10) == 42.0
    assert _percentile([42.0], 90) == 42.0
    assert _percentile([42.0], 50) == 42.0


def test_percentile_empty():
    """No values → 0.0, no crashes."""
    assert _percentile([], 50) == 0.0


def test_summarise_all_valid():
    """All 5 trials produced values → full stats."""
    s = _summarise(
        "scorecard.overall.youden",
        [0.20, 0.25, 0.30, 0.35, 0.40],
    )
    assert s["metric"] == "scorecard.overall.youden"
    assert s["n_valid"] == 5
    assert s["median"] == 0.30
    assert s["mean"] == 0.30
    assert s["min"] == 0.20
    assert s["max"] == 0.40
    # stdev present + > 0 for varied data
    assert s["stdev"] > 0


def test_summarise_some_failed_trials():
    """3 of 5 trials failed (None values) → summary uses only the
    valid 2."""
    s = _summarise(
        "scorecard.overall.youden",
        [0.30, None, None, 0.40, None],
    )
    assert s["n_valid"] == 2
    assert s["median"] == pytest.approx(0.35)


def test_summarise_all_failed():
    """All trials failed → zero summary, no exceptions."""
    s = _summarise("metric.x", [None, None, None])
    assert s["n_valid"] == 0
    assert s["median"] == 0.0
    assert s["mean"] == 0.0


def test_summarise_single_trial_stdev_zero():
    """Single-trial run has stdev=0 (not undefined)."""
    s = _summarise("metric.x", [0.42])
    assert s["n_valid"] == 1
    assert s["stdev"] == 0.0
    assert s["median"] == 0.42


# ---------------------------------------------------------------------------
# Metric extraction (dotted-path JSON walk)
# ---------------------------------------------------------------------------


def test_extract_metric_simple_path():
    data = {"recall_pct": 23.5}
    assert _extract_metric(data, "recall_pct") == 23.5


def test_extract_metric_nested_path():
    data = {
        "scorecard": {
            "overall": {"youden": 0.42, "tpr": 0.60},
        },
    }
    assert _extract_metric(data, "scorecard.overall.youden") == 0.42


def test_extract_metric_missing_path_returns_none():
    """Path not present → None (not exception)."""
    data = {"scorecard": {"overall": {}}}
    assert _extract_metric(data, "scorecard.overall.youden") is None


def test_extract_metric_non_numeric_value_returns_none():
    """Path resolves but value isn't a number → None (multi-trial
    summary skips non-numeric values gracefully)."""
    data = {"status": "ok"}
    assert _extract_metric(data, "status") is None


def test_extract_metric_intermediate_path_not_dict():
    """Path tries to traverse a non-dict → None, no crash."""
    data = {"scorecard": "not-a-dict"}
    assert _extract_metric(data, "scorecard.overall.youden") is None


# ---------------------------------------------------------------------------
# Bench registry — schema invariants
# ---------------------------------------------------------------------------


def test_bench_registry_has_all_q1_benches():
    """The registry must list every bench the Q1 proposal calls for."""
    assert "owasp_benchmark" in _BENCH_REGISTRY
    assert "webgoat_dual" in _BENCH_REGISTRY
    assert "vulhub_cve_corpus" in _BENCH_REGISTRY
    assert "l2_juiceshop_full" in _BENCH_REGISTRY


@pytest.mark.parametrize("bench_name", list(_BENCH_REGISTRY))
def test_bench_registry_entries_have_required_fields(bench_name: str):
    """Every registry entry has module + non-empty metrics."""
    cfg = _BENCH_REGISTRY[bench_name]
    assert "module" in cfg
    assert cfg["module"].startswith("benchmarks.per_target.")
    assert isinstance(cfg.get("metrics"), list)
    assert len(cfg["metrics"]) > 0


def test_bench_registry_owasp_headline_metric():
    """Sanity: OWASP Benchmark's headline metric is the Youden index
    (per the proposal)."""
    metrics = _BENCH_REGISTRY["owasp_benchmark"]["metrics"]
    assert any("youden" in m for m in metrics)


def test_bench_registry_webgoat_includes_chain_gap():
    """WebGoat's headline metric is the chain_gap (per iter-Q1.2)."""
    metrics = _BENCH_REGISTRY["webgoat_dual"]["metrics"]
    assert any("chain_gap" in m for m in metrics)


def test_bench_registry_vulhub_includes_kev():
    """Vulhub's pager-critical metric is the KEV hit rate
    (per iter-Q1.3)."""
    metrics = _BENCH_REGISTRY["vulhub_cve_corpus"]["metrics"]
    assert any("kev" in m for m in metrics)
