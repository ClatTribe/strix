"""Capture per-endpoint behavioural baselines.

The capture pass takes an endpoint key (`<METHOD> <URL>`) plus a
caller-supplied probe function (`probe_fn(endpoint) -> response`)
and runs N samples to build the `EndpointBaseline`.

The probe function is injected so:
  * Tests can pass deterministic fakes.
  * Production code can route through `send_request` with the
    right auth headers / cookie jar / proxy.
  * Future iterations can add per-call timing / response-body
    streaming without touching this module.
"""

from __future__ import annotations

import json
import logging
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable


logger = logging.getLogger(__name__)


# Number of samples per baseline. 5 is the doc spec; bumping
# without code review would hide the cost on large recon walks.
DEFAULT_SAMPLES = 5


@dataclass
class EndpointBaseline:
    """One endpoint's "as-observed normal" profile."""
    endpoint: str            # canonical key — `<METHOD> <URL>`
    samples: int             # how many probes were captured
    status_distribution: dict[int, int] = field(default_factory=dict)
    latency_p50_ms: float = 0.0
    latency_p99_ms: float = 0.0
    body_length_p50: int = 0
    body_length_p99: int = 0
    content_type: str = ""
    response_keys: list[str] = field(default_factory=list)
    captured_at: str = ""    # ISO-8601 UTC timestamp

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "samples": self.samples,
            "status_distribution": dict(self.status_distribution),
            "latency_p50_ms": self.latency_p50_ms,
            "latency_p99_ms": self.latency_p99_ms,
            "body_length_p50": self.body_length_p50,
            "body_length_p99": self.body_length_p99,
            "content_type": self.content_type,
            "response_keys": list(self.response_keys),
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> EndpointBaseline:
        return cls(
            endpoint=d.get("endpoint", ""),
            samples=int(d.get("samples", 0)),
            status_distribution={
                int(k): int(v) for k, v in
                (d.get("status_distribution") or {}).items()
            },
            latency_p50_ms=float(d.get("latency_p50_ms", 0.0)),
            latency_p99_ms=float(d.get("latency_p99_ms", 0.0)),
            body_length_p50=int(d.get("body_length_p50", 0)),
            body_length_p99=int(d.get("body_length_p99", 0)),
            content_type=str(d.get("content_type", "")),
            response_keys=list(d.get("response_keys") or []),
            captured_at=str(d.get("captured_at", "")),
        )


def _percentile(values: list[float], pct: float) -> float:
    """Cheap p50 / p99 — sort + index. For small N, exact rank
    rounded down. For empty list returns 0."""
    if not values:
        return 0.0
    s = sorted(values)
    rank = max(0, min(len(s) - 1, int(round((pct / 100.0) * (len(s) - 1)))))
    return float(s[rank])


def _extract_json_keys(body: str, content_type: str) -> list[str]:
    """For JSON responses, return the top-level object key set.
    For arrays of objects, return the union of object keys at
    index 0 (heuristic; arrays without dict elements → empty)."""
    ct = (content_type or "").lower()
    if "json" not in ct:
        return []
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(doc, dict):
        return sorted(str(k) for k in doc.keys())
    if isinstance(doc, list) and doc and isinstance(doc[0], dict):
        return sorted(str(k) for k in doc[0].keys())
    return []


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def capture_baseline(
    endpoint: str,
    *,
    probe_fn: Callable[[str], dict[str, Any]],
    n_samples: int = DEFAULT_SAMPLES,
    inter_sample_delay_seconds: float = 0.0,
) -> EndpointBaseline:
    """Run `n_samples` probes against `endpoint`, return baseline.

    `probe_fn(endpoint)` must return a dict with at minimum:
        {"status": int, "headers": dict, "body": str}
    Optionally `"latency_ms": float` — when absent, this fn
    times the call wall-clock.

    Robustness:
      * If the probe raises, that sample is skipped. Baseline
        records the surviving N.
      * Empty samples (all probes failed) → returns a baseline
        with samples=0 so the diff layer treats it as
        "indeterminate" rather than asserting stability.
    """
    if n_samples < 1:
        n_samples = 1

    statuses: list[int] = []
    latencies: list[float] = []
    body_lengths: list[int] = []
    content_types: list[str] = []
    keys_observed: list[set[str]] = []

    for _ in range(n_samples):
        try:
            t_start = time.monotonic()
            resp = probe_fn(endpoint)
            t_end = time.monotonic()
        except Exception as e:  # noqa: BLE001
            logger.debug("baselines: probe raised: %s", e)
            continue
        if not isinstance(resp, dict):
            continue
        # Latency: prefer caller-supplied; else wall-clock measure.
        lat = resp.get("latency_ms")
        if not isinstance(lat, (int, float)):
            lat = (t_end - t_start) * 1000.0
        try:
            statuses.append(int(resp.get("status", 0)))
        except (TypeError, ValueError):
            continue
        latencies.append(float(lat))
        body = resp.get("body") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        body_lengths.append(len(body))
        headers = resp.get("headers") or {}
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = str(v).split(";", 1)[0].strip().lower()
                break
        content_types.append(ct)
        keys_observed.append(set(_extract_json_keys(body, ct)))

        if inter_sample_delay_seconds > 0:
            time.sleep(inter_sample_delay_seconds)

    # Collapse statuses into a distribution.
    status_dist: dict[int, int] = {}
    for s in statuses:
        status_dist[s] = status_dist.get(s, 0) + 1

    # Content-type: pick the most common (mode); ties → last
    # observed (stable ordering).
    if content_types:
        from collections import Counter
        ct_counter = Counter(content_types)
        most_common = ct_counter.most_common(1)
        content_type = most_common[0][0] if most_common else ""
    else:
        content_type = ""

    # JSON keys: union across samples. The diff layer flags
    # NEW keys (in probe response, absent from this set), so
    # using union is the correct over-approximation.
    if keys_observed:
        union_keys = set()
        for s in keys_observed:
            union_keys |= s
        response_keys = sorted(union_keys)
    else:
        response_keys = []

    return EndpointBaseline(
        endpoint=endpoint,
        samples=len(statuses),
        status_distribution=status_dist,
        latency_p50_ms=_percentile(latencies, 50),
        latency_p99_ms=_percentile(latencies, 99),
        body_length_p50=int(_percentile(body_lengths, 50)),
        body_length_p99=int(_percentile(body_lengths, 99)),
        content_type=content_type,
        response_keys=response_keys,
        captured_at=_now_iso(),
    )
