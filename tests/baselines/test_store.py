"""Unit tests for `strix.baselines.store` — JSONL persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.baselines.capture import EndpointBaseline
from strix.baselines.store import BaselineStore


def _baseline(endpoint: str = "GET /x", samples: int = 5) -> EndpointBaseline:
    return EndpointBaseline(
        endpoint=endpoint, samples=samples,
        status_distribution={200: samples},
        latency_p50_ms=100.0, latency_p99_ms=200.0,
        body_length_p50=512, body_length_p99=1024,
        content_type="application/json",
        response_keys=["id"],
        captured_at="2026-05-10T00:00:00Z",
    )


def test_write_then_read_round_trip(tmp_path: Path) -> None:
    store = BaselineStore(path=tmp_path / "x.jsonl")
    b = _baseline()
    store.write(b)
    out = store.read("GET /x")
    assert out == b


def test_read_missing_endpoint_returns_none(tmp_path: Path) -> None:
    store = BaselineStore(path=tmp_path / "x.jsonl")
    store.write(_baseline("GET /a"))
    assert store.read("GET /b") is None


def test_read_when_file_doesnt_exist_returns_none(tmp_path: Path) -> None:
    store = BaselineStore(path=tmp_path / "nope.jsonl")
    assert store.read("GET /x") is None


def test_last_line_per_endpoint_wins(tmp_path: Path) -> None:
    """JSONL is append-only; for a given endpoint the latest
    appended row should be returned."""
    store = BaselineStore(path=tmp_path / "x.jsonl")
    store.write(_baseline(endpoint="GET /x", samples=3))
    store.write(_baseline(endpoint="GET /x", samples=5))
    out = store.read("GET /x")
    assert out is not None
    assert out.samples == 5


def test_skips_corrupt_lines(tmp_path: Path) -> None:
    """A torn write or hand-edit shouldn't poison the whole
    store. Corrupt lines are skipped; surviving rows still
    return."""
    p = tmp_path / "x.jsonl"
    valid = json.dumps(_baseline().to_dict())
    p.write_text(valid + "\n{not json\n" + valid + "\n")
    store = BaselineStore(path=p)
    out = store.read("GET /x")
    assert out is not None


def test_all_returns_latest_per_endpoint(tmp_path: Path) -> None:
    store = BaselineStore(path=tmp_path / "x.jsonl")
    store.write(_baseline(endpoint="GET /a", samples=3))
    store.write(_baseline(endpoint="GET /b", samples=4))
    store.write(_baseline(endpoint="GET /a", samples=10))  # update
    out = sorted(store.all(), key=lambda b: b.endpoint)
    assert len(out) == 2
    assert out[0].samples == 10  # GET /a updated
    assert out[1].samples == 4   # GET /b


def test_creates_parent_dirs_on_write(tmp_path: Path) -> None:
    store = BaselineStore(path=tmp_path / "deep" / "nested" / "x.jsonl")
    store.write(_baseline())
    assert (tmp_path / "deep" / "nested" / "x.jsonl").exists()
