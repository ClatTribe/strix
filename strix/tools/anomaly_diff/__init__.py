"""Anomaly-diff specialist (roadmap §8 / Phase 9.3 + 9.6).

Diffs a probe response against a captured `EndpointBaseline`
and surfaces behavioural anomalies as findings. Used by every
other DAST specialist as a complementary signal — a probe's
response that diverges from baseline is a "something is
different here" signal even when no static-payload pattern
matches.

Anomaly classes detected:
  * `status_flip`            — probe returned a status not in
    the baseline distribution
  * `length_outlier`         — body length > 3× baseline p99 OR
    < 0.3× baseline p50
  * `latency_outlier_3sigma` — probe latency exceeds baseline
    p99 + 3× IQR
  * `new_keys_in_json`       — probe response has top-level
    JSON keys absent from baseline
  * `error_string_presence`  — probe body contains stack-
    traces / DB error strings absent from baseline
  * `header_set_change`      — content-type or other anchor
    headers diverge from baseline mode
  * `shape_outlier`          — Phase 9.6 — response fingerprint
    (status × length-bucket × content-type × body-key-hash)
    is unique across the probe corpus

Each anomaly is graded `info` / `low` / `medium` / `high`
based on how strong the divergence signal is.
"""

from strix.tools.anomaly_diff.diff import (  # noqa: F401
    AnomalyClass,
    AnomalyVerdict,
    diff_against_baseline,
)
from strix.tools.anomaly_diff.shape_cluster import (  # noqa: F401
    fingerprint_response,
    find_shape_outliers,
)
from strix.tools.anomaly_diff.tools import scan_response_anomaly  # noqa: F401
