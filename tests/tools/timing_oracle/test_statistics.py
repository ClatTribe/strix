"""Unit tests for `strix.tools.timing_oracle.statistics`."""

from __future__ import annotations

import random

import pytest

from strix.tools.timing_oracle.statistics import (
    _iqr,
    _rank_sum_effect_size,
    collect_timing_samples,
    compare_distributions,
)


# ---------------------------------------------------------------------------
# Math helpers
# ---------------------------------------------------------------------------


def test_iqr_basic() -> None:
    """IQR of [1..100] is approximately 50."""
    assert 40 <= _iqr(list(range(1, 101))) <= 60


def test_iqr_empty_returns_zero() -> None:
    assert _iqr([]) == 0.0


def test_iqr_too_small_returns_zero() -> None:
    """IQR needs >= 4 samples to be meaningful."""
    assert _iqr([1.0, 2.0]) == 0.0


def test_rank_sum_effect_size_identical_distributions() -> None:
    """Same distribution → ~0.5."""
    a = [10.0] * 50
    b = [10.0] * 50
    es = _rank_sum_effect_size(a, b)
    assert 0.45 <= es <= 0.55


def test_rank_sum_effect_size_b_dominates() -> None:
    """B always exceeds A → effect size near 1.0."""
    a = list(range(0, 50))
    b = list(range(100, 150))
    es = _rank_sum_effect_size(a, b)
    assert es > 0.95


def test_rank_sum_effect_size_a_dominates() -> None:
    a = list(range(100, 150))
    b = list(range(0, 50))
    es = _rank_sum_effect_size(a, b)
    assert es < 0.05


# ---------------------------------------------------------------------------
# compare_distributions
# ---------------------------------------------------------------------------


def test_distinct_distributions_with_clear_separation() -> None:
    """A: ~100ms, B: ~300ms with low variance → distinct."""
    rng = random.Random(42)
    a = [100 + rng.gauss(0, 5) for _ in range(50)]
    b = [300 + rng.gauss(0, 5) for _ in range(50)]
    cmp = compare_distributions(a, b)
    assert cmp.distinct is True
    assert cmp.median_b_ms > cmp.median_a_ms


def test_indistinguishable_distributions_not_distinct() -> None:
    """Same distribution → not distinct."""
    rng = random.Random(42)
    a = [100 + rng.gauss(0, 10) for _ in range(50)]
    b = [100 + rng.gauss(0, 10) for _ in range(50)]
    cmp = compare_distributions(a, b)
    assert cmp.distinct is False


def test_overlapping_distributions_not_distinct() -> None:
    """Overlapping: A=[80..120], B=[100..140] — significant
    overlap → not distinct (both gates would fire false-
    positives at small N)."""
    rng = random.Random(123)
    a = [100 + rng.gauss(0, 20) for _ in range(50)]
    b = [120 + rng.gauss(0, 20) for _ in range(50)]
    cmp = compare_distributions(a, b)
    # Effect size will be ~0.6-0.7 — borderline. Median sep
    # should be < 1.5× pooled IQR. Verdict: not distinct.
    assert cmp.distinct is False


def test_empty_samples_returns_not_distinct() -> None:
    cmp = compare_distributions([], [10.0])
    assert cmp.distinct is False
    assert "skipped" in cmp.rationale.lower()


def test_distinct_with_blind_sqli_pattern() -> None:
    """Realistic blind-SQLi pattern: control 50ms, sleep
    injection 2050ms (2s sleep + base latency)."""
    rng = random.Random(0)
    control = [50 + rng.gauss(0, 10) for _ in range(50)]
    suspect = [2050 + rng.gauss(0, 10) for _ in range(50)]
    cmp = compare_distributions(control, suspect)
    assert cmp.distinct is True


# ---------------------------------------------------------------------------
# collect_timing_samples
# ---------------------------------------------------------------------------


def test_collect_uses_response_latency_when_present() -> None:
    """When the probe response supplies `latency_ms`, capture
    uses that — not wall-clock — so tests are deterministic."""
    counter = {"i": 0}

    def fake_send():
        counter["i"] += 1
        return {"latency_ms": 100.0 + counter["i"]}

    samples = collect_timing_samples(send_fn=fake_send, n_samples=5)
    assert len(samples) == 5
    assert samples[0] == 101.0
    assert samples[4] == 105.0


def test_collect_skips_failed_probes() -> None:
    counter = {"i": 0}

    def fake_send():
        counter["i"] += 1
        if counter["i"] == 3:
            raise RuntimeError("network blip")
        return {"latency_ms": 100.0}

    samples = collect_timing_samples(send_fn=fake_send, n_samples=5)
    assert len(samples) == 4
