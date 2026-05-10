"""Integration tests for `scan_timing_oracle`."""

from __future__ import annotations

import random

from strix.tools.timing_oracle.tools import scan_timing_oracle


def test_returns_error_for_missing_target() -> None:
    result = scan_timing_oracle(target="", payload_pairs=[])
    assert result["status"] == "error"


def test_returns_partial_when_no_pairs() -> None:
    result = scan_timing_oracle(target="https://x.com", payload_pairs=[])
    assert result["status"] == "partial"


def test_emits_finding_for_distinct_distributions() -> None:
    """Control payload returns ~50ms; suspect payload returns
    ~2050ms (simulating SLEEP injection). The tool should
    detect the distinct distribution and emit a finding."""
    rng_a = random.Random(11)
    rng_b = random.Random(22)

    def control_send():
        return {"latency_ms": 50.0 + rng_a.gauss(0, 5)}

    def suspect_send():
        return {"latency_ms": 2050.0 + rng_b.gauss(0, 5)}

    result = scan_timing_oracle(
        target="https://example.com/api/users?id=1",
        payload_pairs=[{
            "name": "blind-sqli-id-param",
            "control_send_fn": control_send,
            "suspect_send_fn": suspect_send,
        }],
        n_samples=30,   # tighter for test speed
    )
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert "blind-sqli-id-param" in f["title"]
    assert f["severity"] == "medium"
    assert f["category"] == "anomaly"


def test_no_finding_for_indistinguishable_distributions() -> None:
    """Same distribution on both sides → no finding."""
    rng_a = random.Random(11)
    rng_b = random.Random(22)

    def control_send():
        return {"latency_ms": 100.0 + rng_a.gauss(0, 10)}

    def suspect_send():
        return {"latency_ms": 100.0 + rng_b.gauss(0, 10)}

    result = scan_timing_oracle(
        target="https://example.com/x",
        payload_pairs=[{
            "name": "no-oracle",
            "control_send_fn": control_send,
            "suspect_send_fn": suspect_send,
        }],
        n_samples=30,
    )
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_skips_pairs_with_missing_send_fns() -> None:
    """A pair without callable send_fns should be skipped, not
    crash."""
    result = scan_timing_oracle(
        target="https://x.com",
        payload_pairs=[
            {"name": "missing-fns"},
            {"name": "missing-suspect", "control_send_fn": lambda: {"latency_ms": 100.0}},
        ],
        n_samples=10,
    )
    assert result["status"] == "ok"
    assert len(result["findings"]) == 0


def test_tool_metadata_records_distinct_count() -> None:
    rng_a = random.Random(33)
    rng_b = random.Random(44)

    result = scan_timing_oracle(
        target="https://x.com",
        payload_pairs=[
            {
                "name": "distinct-pair",
                "control_send_fn": lambda: {"latency_ms": 50.0 + rng_a.gauss(0, 3)},
                "suspect_send_fn": lambda: {"latency_ms": 2000.0 + rng_b.gauss(0, 3)},
            },
            {
                "name": "indistinct-pair",
                "control_send_fn": lambda: {"latency_ms": 100.0},
                "suspect_send_fn": lambda: {"latency_ms": 100.0},
            },
        ],
        n_samples=30,
    )
    md = result["tool_metadata"]
    assert md["pairs_analysed"] == 2
    assert md["distinct_count"] == 1
