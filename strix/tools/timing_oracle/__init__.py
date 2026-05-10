"""Timing-oracle specialist (roadmap §8 / Phase 9.5).

50-sample timing-sensitive probes per parameter, statistical
fit (boxplot + p50 separation), surfaces blind injection /
padding oracles / TOCTOU candidates.

The "oracle" here is in the cryptography sense: a measurable
side-channel that distinguishes two states. Padding oracle and
blind-SQLi share the same statistical pattern — payload A's
distribution is significantly different from payload B's — and
we use the same machinery to detect both.

What we ship:
  * `collect_timing_samples()` — N samples of a probe's wall-
    clock latency (test-injectable via `send_fn=`)
  * `_distinct_distributions()` — Mann-Whitney U-style
    non-parametric test (no scipy dep) for "are these two
    samples from the same distribution?"
  * `scan_timing_oracle` LLM tool — for each (control, suspect)
    payload pair, collect 50 samples each, run the test,
    surface a finding when the suspect distribution is
    statistically distinct.

Out of scope:
  * KDE-based plotting (plot output is a wrapper concern).
  * Adaptive sample-count (always 50; future iteration could
    auto-extend on borderline p-values).
  * Network-jitter compensation (we recommend running probes
    against same-AZ targets to keep noise floor low).
"""

from strix.tools.timing_oracle.statistics import (  # noqa: F401
    TimingComparison,
    collect_timing_samples,
    compare_distributions,
)
from strix.tools.timing_oracle.tools import scan_timing_oracle  # noqa: F401
