"""Integration tests for `scan_response_anomaly`."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.baselines.capture import EndpointBaseline
from strix.baselines.store import BaselineStore
from strix.tools.anomaly_diff.tools import scan_response_anomaly


@pytest.fixture
def populated_store(tmp_path: Path) -> Path:
    """Fixture: a JSONL store with a single baseline for `GET /x`.
    Body lengths chosen to match the test probes' body sizes so
    the "no-anomaly" path stays clean (the diff flags lengths
    > 3× p99 OR < 0.3× p50)."""
    store = BaselineStore(path=tmp_path / "baselines.jsonl")
    store.write(EndpointBaseline(
        endpoint="GET /x",
        samples=5,
        status_distribution={200: 5},
        latency_p50_ms=100.0, latency_p99_ms=200.0,
        body_length_p50=20, body_length_p99=30,
        content_type="application/json",
        response_keys=["id", "name"],
        captured_at="2026-05-10T00:00:00Z",
    ))
    return tmp_path / "baselines.jsonl"


def test_returns_error_for_missing_endpoint() -> None:
    result = scan_response_anomaly(endpoint="")
    assert result["status"] == "error"


def test_returns_partial_when_no_response_supplied(populated_store: Path) -> None:
    result = scan_response_anomaly(
        endpoint="GET /x",
        baseline_path=str(populated_store),
    )
    assert result["status"] == "partial"


def test_returns_partial_when_baseline_missing(tmp_path: Path) -> None:
    """No baseline for the endpoint → partial. The diff layer
    can't false-positive every probe when there's nothing to
    compare against."""
    result = scan_response_anomaly(
        endpoint="GET /unknown",
        probe_response={"status": 200, "headers": {}, "body": ""},
        baseline_path=str(tmp_path / "empty.jsonl"),
    )
    assert result["status"] == "partial"
    assert "no baseline" in (result.get("error") or "")


def test_emits_finding_for_status_flip(populated_store: Path) -> None:
    """Probe with an unseen status → finding."""
    result = scan_response_anomaly(
        endpoint="GET /x",
        probe_response={
            "status": 500, "headers": {"Content-Type": "application/json"},
            "body": '{"id":1,"name":"x"}',
            "latency_ms": 100.0,
        },
        baseline_path=str(populated_store),
    )
    assert result["status"] == "ok"
    titles = [d["title"] for d in result["findings"]]
    assert any("status_flip" in t for t in titles)


def test_emits_finding_for_error_string(populated_store: Path) -> None:
    """Probe response containing a SQL error → high-severity
    finding with category=info_disclosure."""
    result = scan_response_anomaly(
        endpoint="GET /x",
        probe_response={
            "status": 200, "headers": {"Content-Type": "application/json"},
            "body": '{"error": "syntax error at or near WHERE"}',
            "latency_ms": 100.0,
        },
        baseline_path=str(populated_store),
    )
    titles = [d["title"] for d in result["findings"]]
    assert any("error_string_present" in t for t in titles)
    severities = {d["severity"] for d in result["findings"]}
    assert "high" in severities


def test_no_finding_for_baseline_match(populated_store: Path) -> None:
    """A probe identical to baseline produces no findings."""
    result = scan_response_anomaly(
        endpoint="GET /x",
        probe_response={
            "status": 200, "headers": {"Content-Type": "application/json"},
            "body": '{"id":1,"name":"x"}',
            "latency_ms": 100.0,
        },
        baseline_path=str(populated_store),
    )
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_corpus_mode_reports_shape_outliers(populated_store: Path) -> None:
    """When `probe_responses` is supplied with 5+ items, shape
    clustering runs and outliers appear in metadata."""
    corpus = [
        {"status": 200, "headers": {"Content-Type": "application/json"},
         "body": '{"id":1,"name":"x"}', "latency_ms": 100.0}
        for _ in range(5)
    ]
    corpus.append({
        "status": 500, "headers": {"Content-Type": "text/html"},
        "body": "<html>broken</html>", "latency_ms": 100.0,
    })
    result = scan_response_anomaly(
        endpoint="GET /x",
        probe_responses=corpus,
        baseline_path=str(populated_store),
    )
    md = result["tool_metadata"]
    assert md["responses_analysed"] == 6
    assert md["shape_outliers"] >= 1
    assert 5 in md["outlier_indices"]


def test_tool_metadata_shape(populated_store: Path) -> None:
    result = scan_response_anomaly(
        endpoint="GET /x",
        probe_response={"status": 200, "headers": {}, "body": "",
                         "latency_ms": 100.0},
        baseline_path=str(populated_store),
    )
    md = result["tool_metadata"]
    for k in ("endpoint", "baseline_samples", "responses_analysed",
              "anomaly_findings", "shape_outliers"):
        assert k in md
