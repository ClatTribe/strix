"""Compute anomaly classes between a probe response + a captured
baseline.

The diff returns 0+ `AnomalyClass` strings plus an aggregate
severity. Multiple classes can fire on a single probe — a
probe that flips status code AND adds a new JSON key AND
contains a SQL error string lights up three classes.

Severity per class (graded by signal strength):
  * status_flip         → high   (5xx seen against 200 baseline = strong)
  * error_string_present → high  (stack trace = strong signal)
  * length_outlier      → medium
  * new_keys_in_json    → medium (could be schema drift, could be leak)
  * latency_outlier_3sigma → medium
  * header_set_change   → low

The aggregate AnomalyVerdict.severity = max of the per-class
severities.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from strix.baselines.capture import EndpointBaseline


logger = logging.getLogger(__name__)


# Anomaly class identifiers. Stable strings — wrappers may
# render UI off them.
AnomalyClass = str

CLASS_STATUS_FLIP = "status_flip"
CLASS_LENGTH_OUTLIER = "length_outlier"
CLASS_LATENCY_OUTLIER = "latency_outlier_3sigma"
CLASS_NEW_KEYS_IN_JSON = "new_keys_in_json"
CLASS_ERROR_STRING_PRESENT = "error_string_present"
CLASS_HEADER_SET_CHANGE = "header_set_change"


# Severity per class. Max wins for the aggregate verdict.
_CLASS_SEVERITY: dict[str, str] = {
    CLASS_STATUS_FLIP: "high",
    CLASS_ERROR_STRING_PRESENT: "high",
    CLASS_LENGTH_OUTLIER: "medium",
    CLASS_NEW_KEYS_IN_JSON: "medium",
    CLASS_LATENCY_OUTLIER: "medium",
    CLASS_HEADER_SET_CHANGE: "low",
}


# Common error-message patterns indicating an unexpected backend
# error reached the response body. Each match is a strong signal
# something diverged. Kept narrow to limit FPs — generic words
# like "error" alone aren't here.
_ERROR_STRING_RES = [
    re.compile(r"\bsyntax error at or near\b", re.IGNORECASE),
    re.compile(r"\bunexpected token\b", re.IGNORECASE),
    re.compile(r"SQLSTATE\[", re.IGNORECASE),
    re.compile(r"\bORA-\d{5}\b"),
    re.compile(r"\bMySQL.*?Error\b", re.IGNORECASE),
    re.compile(r"PG::SyntaxError", re.IGNORECASE),
    re.compile(r"\bTraceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"\bjava\.lang\.[A-Z]\w+Exception", re.IGNORECASE),
    re.compile(r"\bSegmentation fault\b", re.IGNORECASE),
    re.compile(r"<title>Internal Server Error</title>", re.IGNORECASE),
    re.compile(r"\bStack trace:\s*#0\b", re.IGNORECASE),
    re.compile(r"\bSystem\.NullReferenceException\b", re.IGNORECASE),
]


@dataclass
class AnomalyVerdict:
    """Aggregate result of diffing one probe response against a
    baseline."""
    classes: list[str] = field(default_factory=list)
    severity: str = "info"
    rationale: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.classes)


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _max_severity(classes: list[str]) -> str:
    if not classes:
        return "info"
    sevs = [_CLASS_SEVERITY.get(c, "info") for c in classes]
    return max(sevs, key=lambda s: _SEVERITY_RANK.get(s, 0))


def _extract_json_keys(body: str, content_type: str) -> set[str]:
    if "json" not in (content_type or "").lower():
        return set()
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return set()
    if isinstance(doc, dict):
        return {str(k) for k in doc.keys()}
    if isinstance(doc, list) and doc and isinstance(doc[0], dict):
        return {str(k) for k in doc[0].keys()}
    return set()


def diff_against_baseline(
    probe_response: dict[str, Any],
    baseline: EndpointBaseline,
) -> AnomalyVerdict:
    """Compare `probe_response` to `baseline`, return verdict.

    `probe_response` is the same shape `capture_baseline`'s
    `probe_fn` produces: `{status, headers, body, latency_ms?}`.

    `baseline` MUST have `samples > 0` for the diff to fire.
    A baseline with zero successful samples means we have no
    "normal" to compare against; we return an empty verdict
    rather than false-positive every probe.
    """
    classes: list[str] = []
    rationale: list[str] = []
    metadata: dict = {}

    if not isinstance(probe_response, dict):
        return AnomalyVerdict()
    if baseline.samples <= 0:
        return AnomalyVerdict(
            rationale=["baseline has zero samples; diff skipped"],
        )

    # ---------- status_flip ----------
    try:
        probe_status = int(probe_response.get("status", 0))
    except (TypeError, ValueError):
        probe_status = 0
    if probe_status and probe_status not in baseline.status_distribution:
        classes.append(CLASS_STATUS_FLIP)
        rationale.append(
            f"probe status {probe_status} not in baseline "
            f"distribution {sorted(baseline.status_distribution)}"
        )
        metadata["status_flip"] = {
            "probe": probe_status,
            "baseline_seen": sorted(baseline.status_distribution),
        }

    # ---------- length_outlier ----------
    body = probe_response.get("body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    probe_len = len(body)
    if baseline.body_length_p99 > 0:
        # > 3× p99 OR < 0.3× p50
        if (probe_len > 3 * baseline.body_length_p99
                or (baseline.body_length_p50 > 0
                    and probe_len < 0.3 * baseline.body_length_p50)):
            classes.append(CLASS_LENGTH_OUTLIER)
            rationale.append(
                f"probe body length {probe_len} is an outlier vs "
                f"baseline p50={baseline.body_length_p50} "
                f"p99={baseline.body_length_p99}"
            )
            metadata["length_outlier"] = {
                "probe_length": probe_len,
                "baseline_p50": baseline.body_length_p50,
                "baseline_p99": baseline.body_length_p99,
            }

    # ---------- latency_outlier_3sigma ----------
    probe_lat = probe_response.get("latency_ms")
    if isinstance(probe_lat, (int, float)) and baseline.latency_p99_ms > 0:
        # 3× p99 is the doc spec heuristic. Tighter than 3σ
        # would need full sample distribution; we kept p50/p99
        # in the baseline for compactness.
        threshold = 3.0 * baseline.latency_p99_ms
        if probe_lat > threshold:
            classes.append(CLASS_LATENCY_OUTLIER)
            rationale.append(
                f"probe latency {probe_lat:.1f}ms exceeds 3× baseline "
                f"p99 ({baseline.latency_p99_ms:.1f}ms)"
            )
            metadata["latency_outlier"] = {
                "probe_latency_ms": probe_lat,
                "baseline_p99_ms": baseline.latency_p99_ms,
                "threshold_ms": threshold,
            }

    # ---------- new_keys_in_json ----------
    probe_headers = probe_response.get("headers") or {}
    probe_ct = ""
    for k, v in probe_headers.items():
        if k.lower() == "content-type":
            probe_ct = str(v).split(";", 1)[0].strip().lower()
            break
    if "json" in (baseline.content_type or "").lower() or "json" in probe_ct:
        probe_keys = _extract_json_keys(body, probe_ct)
        baseline_keys = set(baseline.response_keys)
        new_keys = probe_keys - baseline_keys
        if new_keys:
            classes.append(CLASS_NEW_KEYS_IN_JSON)
            rationale.append(
                f"probe response has new top-level JSON keys "
                f"{sorted(new_keys)} absent from baseline"
            )
            metadata["new_keys"] = sorted(new_keys)

    # ---------- error_string_present ----------
    for pat in _ERROR_STRING_RES:
        m = pat.search(body)
        if m:
            classes.append(CLASS_ERROR_STRING_PRESENT)
            rationale.append(
                f"probe response contains backend-error pattern: "
                f"`{m.group(0)[:80]}`"
            )
            metadata["error_string"] = m.group(0)[:120]
            break  # one error-string class is enough

    # ---------- header_set_change ----------
    if baseline.content_type and probe_ct \
            and baseline.content_type != probe_ct:
        classes.append(CLASS_HEADER_SET_CHANGE)
        rationale.append(
            f"probe Content-Type `{probe_ct}` differs from "
            f"baseline `{baseline.content_type}`"
        )
        metadata["content_type_change"] = {
            "baseline": baseline.content_type, "probe": probe_ct,
        }

    return AnomalyVerdict(
        classes=classes,
        severity=_max_severity(classes),
        rationale=rationale,
        metadata=metadata,
    )
