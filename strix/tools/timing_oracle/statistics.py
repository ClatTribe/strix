"""Statistical comparison of timing samples.

Pure-Python (no scipy / numpy dep). The test we use is a
simplified Mann-Whitney U: rank-sum-based, non-parametric, robust
to outliers. We don't compute exact p-values — instead we use:

  * Median separation: `|median(A) - median(B)| / pooled_iqr`
    > 1.5 = distinct
  * Rank-sum effect size: `(U / (n_a * n_b))` > 0.7 = distinct
    (the probability that a random sample from B exceeds a
    random sample from A)

Both must trigger for a "distinct distributions" verdict —
either alone is too noisy at N=50.

Why not scipy: keeping zero-dep here matters because tests
already pull in enough heavy machinery, and the binary tests
(distinct or not) we need don't require continuous p-values.
"""

from __future__ import annotations

import logging
import statistics
import time
from dataclasses import dataclass
from typing import Callable


logger = logging.getLogger(__name__)


# Doc spec — 50 samples per payload. Tunable.
DEFAULT_SAMPLES_PER_PAYLOAD = 50

# Thresholds — tuned on small synthetic test corpus. False-
# positive risk goes up below these; false-negative risk goes
# up above them. Prefer false-negative (no finding) over false-
# positive (annoying alert) at this layer.
_MEDIAN_SEPARATION_THRESHOLD = 1.5
_RANK_SUM_EFFECT_SIZE_THRESHOLD = 0.70


@dataclass
class TimingComparison:
    """Result of comparing two timing distributions."""
    distinct: bool
    median_a_ms: float
    median_b_ms: float
    median_separation: float    # |Δmedian| / pooled IQR
    rank_sum_effect_size: float  # P(B > A) for random samples
    n_a: int
    n_b: int
    rationale: str = ""


def collect_timing_samples(
    *,
    send_fn: Callable[[], dict],
    n_samples: int = DEFAULT_SAMPLES_PER_PAYLOAD,
    inter_sample_delay_seconds: float = 0.0,
) -> list[float]:
    """Run `n_samples` calls to `send_fn`, return list of latency
    values in milliseconds.

    `send_fn()` is parameterless from this module's perspective —
    the caller closes over the URL/payload/auth context. Each
    call must return a dict (we read `latency_ms` if present,
    else wall-clock the call).
    """
    if n_samples < 1:
        n_samples = 1
    out: list[float] = []
    for _ in range(n_samples):
        try:
            t0 = time.monotonic()
            resp = send_fn()
            t1 = time.monotonic()
        except Exception as e:  # noqa: BLE001
            logger.debug("timing_oracle: send_fn raised: %s", e)
            continue
        if isinstance(resp, dict) and isinstance(
                resp.get("latency_ms"), (int, float)):
            out.append(float(resp["latency_ms"]))
        else:
            out.append((t1 - t0) * 1000.0)
        if inter_sample_delay_seconds > 0:
            time.sleep(inter_sample_delay_seconds)
    return out


def _iqr(values: list[float]) -> float:
    if len(values) < 4:
        return 0.0
    s = sorted(values)
    q1_idx = len(s) // 4
    q3_idx = (3 * len(s)) // 4
    return s[q3_idx] - s[q1_idx]


def _rank_sum_effect_size(a: list[float], b: list[float]) -> float:
    """Return `P(b > a)` for random samples from each — i.e.
    the U statistic normalised by n_a * n_b. Effect size 0.5
    means the distributions are indistinguishable; 1.0 means
    every sample in B exceeds every sample in A."""
    if not a or not b:
        return 0.5
    # Naive O(n*m) implementation — fine for N=50 each.
    wins = 0
    ties = 0
    for ai in a:
        for bj in b:
            if bj > ai:
                wins += 1
            elif bj == ai:
                ties += 1
    return (wins + 0.5 * ties) / (len(a) * len(b))


def compare_distributions(
    a: list[float],
    b: list[float],
) -> TimingComparison:
    """Compare two timing samples for "are they from distinct
    distributions?".

    Returns `TimingComparison.distinct=True` only when BOTH:
      * median separation > threshold (1.5 × pooled IQR)
      * rank-sum effect size is asymmetric (> 0.7 OR < 0.3)

    Both gates must trigger — single-signal verdicts fire too
    often on noisy networks at small N.
    """
    if not a or not b:
        return TimingComparison(
            distinct=False,
            median_a_ms=0.0, median_b_ms=0.0,
            median_separation=0.0, rank_sum_effect_size=0.5,
            n_a=len(a), n_b=len(b),
            rationale="empty sample set; comparison skipped",
        )
    median_a = statistics.median(a)
    median_b = statistics.median(b)
    pooled_iqr = max((_iqr(a) + _iqr(b)) / 2.0, 1.0)  # min 1ms denom
    median_sep = abs(median_a - median_b) / pooled_iqr
    effect_size = _rank_sum_effect_size(a, b)
    # "Asymmetric" = far from 0.5 in either direction.
    asymmetric = (
        effect_size > _RANK_SUM_EFFECT_SIZE_THRESHOLD
        or effect_size < (1.0 - _RANK_SUM_EFFECT_SIZE_THRESHOLD)
    )
    distinct = (
        median_sep > _MEDIAN_SEPARATION_THRESHOLD
        and asymmetric
    )

    if distinct:
        rationale = (
            f"medians {median_a:.1f}ms vs {median_b:.1f}ms "
            f"(separation {median_sep:.2f}× pooled IQR, "
            f"effect size {effect_size:.2f}). Both gates "
            f"trigger → distributions are distinct, suggesting "
            f"a statistical timing oracle."
        )
    else:
        why_not = []
        if median_sep <= _MEDIAN_SEPARATION_THRESHOLD:
            why_not.append(
                f"median separation {median_sep:.2f}× pooled IQR "
                f"<= threshold {_MEDIAN_SEPARATION_THRESHOLD}"
            )
        if not asymmetric:
            why_not.append(
                f"effect size {effect_size:.2f} is symmetric "
                f"(threshold {_RANK_SUM_EFFECT_SIZE_THRESHOLD})"
            )
        rationale = (
            f"medians {median_a:.1f}ms vs {median_b:.1f}ms; "
            f"NOT distinct — {'; '.join(why_not)}"
        )

    return TimingComparison(
        distinct=distinct,
        median_a_ms=median_a,
        median_b_ms=median_b,
        median_separation=median_sep,
        rank_sum_effect_size=effect_size,
        n_a=len(a), n_b=len(b),
        rationale=rationale,
    )
