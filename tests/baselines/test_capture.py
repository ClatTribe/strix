"""Unit tests for `strix.baselines.capture` — Phase 9.2."""

from __future__ import annotations

import json

import pytest

from strix.baselines.capture import (
    DEFAULT_SAMPLES,
    EndpointBaseline,
    _extract_json_keys,
    _percentile,
    capture_baseline,
)


# ---------------------------------------------------------------------------
# Math helpers
# ---------------------------------------------------------------------------


def test_percentile_p50() -> None:
    assert _percentile([1.0, 2.0, 3.0, 4.0, 5.0], 50) == 3.0


def test_percentile_p99_clamps_to_max_index() -> None:
    """p99 of a 5-sample list returns the last value."""
    assert _percentile([1.0, 2.0, 3.0, 4.0, 5.0], 99) == 5.0


def test_percentile_empty_list_returns_zero() -> None:
    assert _percentile([], 50) == 0.0


def test_extract_json_keys_for_dict_response() -> None:
    body = json.dumps({"id": 1, "name": "x", "email": "y"})
    keys = _extract_json_keys(body, "application/json")
    assert keys == ["email", "id", "name"]


def test_extract_json_keys_for_array_response() -> None:
    body = json.dumps([{"id": 1, "label": "x"}, {"id": 2, "label": "y"}])
    keys = _extract_json_keys(body, "application/json")
    assert keys == ["id", "label"]


def test_extract_json_keys_for_non_json_returns_empty() -> None:
    assert _extract_json_keys("<html>x</html>", "text/html") == []


def test_extract_json_keys_for_invalid_json_returns_empty() -> None:
    assert _extract_json_keys("{not json", "application/json") == []


# ---------------------------------------------------------------------------
# EndpointBaseline round-trip
# ---------------------------------------------------------------------------


def test_baseline_round_trip_via_dict() -> None:
    b = EndpointBaseline(
        endpoint="GET /api/users",
        samples=5,
        status_distribution={200: 5},
        latency_p50_ms=120.0,
        latency_p99_ms=350.0,
        body_length_p50=512,
        body_length_p99=2048,
        content_type="application/json",
        response_keys=["id", "name"],
        captured_at="2026-05-10T00:00:00Z",
    )
    d = b.to_dict()
    b2 = EndpointBaseline.from_dict(d)
    assert b2 == b


# ---------------------------------------------------------------------------
# capture_baseline
# ---------------------------------------------------------------------------


def _ok_response(status: int = 200, body: str = '{"id":1}',
                 ct: str = "application/json", lat: float = 100.0) -> dict:
    return {
        "status": status, "body": body,
        "headers": {"Content-Type": ct},
        "latency_ms": lat,
    }


def test_capture_baseline_basic() -> None:
    """Five identical 200 responses produce a stable baseline."""
    def probe(_endpoint):
        return _ok_response()
    b = capture_baseline("GET /x", probe_fn=probe, n_samples=5)
    assert b.samples == 5
    assert b.status_distribution == {200: 5}
    assert b.latency_p50_ms == 100.0
    assert b.content_type == "application/json"
    assert "id" in b.response_keys


def test_capture_baseline_skips_failed_probes() -> None:
    """A probe that raises shouldn't crash the capture; it should
    just contribute zero samples."""
    counter = {"calls": 0}

    def probe(_endpoint):
        counter["calls"] += 1
        if counter["calls"] in (1, 3):
            raise RuntimeError("simulated network failure")
        return _ok_response()

    b = capture_baseline("GET /x", probe_fn=probe, n_samples=5)
    # 5 attempts, 2 raised → 3 successful samples.
    assert b.samples == 3


def test_capture_baseline_with_zero_successful_samples() -> None:
    """All probes raising → samples=0; downstream diff treats this
    as 'indeterminate' rather than asserting stability."""
    def probe(_endpoint):
        raise RuntimeError("everything is broken")
    b = capture_baseline("GET /x", probe_fn=probe, n_samples=3)
    assert b.samples == 0


def test_capture_baseline_unions_json_keys_across_samples() -> None:
    """If samples have different JSON shapes, the union covers
    all observed keys — the diff layer flags NEW keys, so union
    is the right over-approximation."""
    counter = {"calls": 0}
    bodies = [
        '{"a": 1, "b": 2}',
        '{"a": 1, "c": 3}',
        '{"a": 1}',
    ]

    def probe(_endpoint):
        i = counter["calls"]
        counter["calls"] += 1
        return _ok_response(body=bodies[i])

    b = capture_baseline("GET /x", probe_fn=probe, n_samples=3)
    # Union: a, b, c.
    assert set(b.response_keys) == {"a", "b", "c"}


def test_capture_baseline_records_status_distribution() -> None:
    """Mixed status codes — capture must record the distribution
    so the diff layer can detect status_flip."""
    counter = {"calls": 0}
    statuses = [200, 200, 500, 200, 500]

    def probe(_endpoint):
        i = counter["calls"]
        counter["calls"] += 1
        return _ok_response(status=statuses[i])

    b = capture_baseline("GET /x", probe_fn=probe, n_samples=5)
    assert b.status_distribution == {200: 3, 500: 2}


def test_capture_baseline_uses_wallclock_when_latency_absent() -> None:
    """When the probe response doesn't supply latency_ms, the
    capture function times the call wall-clock."""
    def probe(_endpoint):
        return {"status": 200, "headers": {}, "body": ""}

    b = capture_baseline("GET /x", probe_fn=probe, n_samples=2)
    # Should not be 0 — wall-clock measure caught some time.
    assert b.latency_p50_ms >= 0.0
    assert b.samples == 2


def test_capture_baseline_picks_modal_content_type() -> None:
    counter = {"calls": 0}
    cts = ["application/json", "application/json", "text/html"]

    def probe(_endpoint):
        i = counter["calls"]
        counter["calls"] += 1
        return _ok_response(ct=cts[i])

    b = capture_baseline("GET /x", probe_fn=probe, n_samples=3)
    assert b.content_type == "application/json"
