"""Unit tests for `strix.threat_intel.streaming` — Phase 9.1."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.streaming.daemon import streaming_iteration
from strix.threat_intel.streaming.event_stream import (
    EventStream,
    StreamEvent,
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# ---------------------------------------------------------------------------
# EventStream
# ---------------------------------------------------------------------------


def test_event_stream_append_and_tail(tmp_path: Path) -> None:
    s = EventStream(path=tmp_path / "events.jsonl")
    s.append(StreamEvent(
        ts="2026-05-10T01:00:00Z", kind="kev_added",
        id="CVE-2024-1", data={"vuln_name": "x"},
    ))
    s.append(StreamEvent(
        ts="2026-05-10T01:05:00Z", kind="kev_added",
        id="CVE-2024-2", data={},
    ))
    events = list(s.tail())
    assert len(events) == 2
    assert events[0].id == "CVE-2024-1"
    assert events[1].id == "CVE-2024-2"


def test_event_stream_tail_filters_by_since(tmp_path: Path) -> None:
    s = EventStream(path=tmp_path / "events.jsonl")
    s.append(StreamEvent(
        ts="2026-05-10T01:00:00Z", kind="x", id="1", data={},
    ))
    s.append(StreamEvent(
        ts="2026-05-10T02:00:00Z", kind="x", id="2", data={},
    ))
    events = list(s.tail(since="2026-05-10T01:30:00Z"))
    assert len(events) == 1
    assert events[0].id == "2"


def test_event_stream_rotation_caps_line_count(tmp_path: Path) -> None:
    """Append more than `max_events` lines → rotation drops the
    oldest. Bounded ring buffer."""
    s = EventStream(path=tmp_path / "events.jsonl", max_events=5)
    for i in range(20):
        s.append(StreamEvent(
            ts=f"2026-05-10T0{i % 10}:00:00Z",
            kind="x", id=f"id-{i}", data={},
        ))
    # After rotation, the file should hold at most max_events.
    with (tmp_path / "events.jsonl").open() as f:
        lines = f.readlines()
    assert len(lines) <= 5


def test_event_stream_skips_corrupt_lines(tmp_path: Path) -> None:
    """A torn write or hand-edit shouldn't poison the whole
    stream — corrupt lines are skipped, valid ones return."""
    p = tmp_path / "events.jsonl"
    valid = json.dumps({
        "ts": "2026-05-10T01:00:00Z", "kind": "x",
        "id": "real", "data": {},
    })
    p.write_text(valid + "\n{not json\n" + valid + "\n")
    s = EventStream(path=p)
    events = list(s.tail())
    assert len(events) == 2
    assert all(e.id == "real" for e in events)


def test_append_kev_added_convenience(tmp_path: Path) -> None:
    s = EventStream(path=tmp_path / "events.jsonl")
    s.append_kev_added("CVE-2024-1", vendor="apache", product="tomcat")
    events = list(s.tail())
    assert len(events) == 1
    assert events[0].kind == "kev_added"
    assert events[0].id == "CVE-2024-1"
    assert events[0].data["vendor"] == "apache"


def test_append_feed_polled_convenience(tmp_path: Path) -> None:
    s = EventStream(path=tmp_path / "events.jsonl")
    s.append_feed_polled("kev", records_total=100, new_records=2)
    events = list(s.tail())
    assert len(events) == 1
    assert events[0].kind == "feed_polled"
    assert events[0].data["records_total"] == 100


# ---------------------------------------------------------------------------
# streaming_iteration
# ---------------------------------------------------------------------------


def test_streaming_iteration_emits_kev_added_for_new_entries(
    tmp_cache, tmp_path: Path,
) -> None:
    """Single iteration: pre-poll cache empty, post-poll has 1
    KEV → emits 1 kev_added + 1 feed_polled."""
    stream = EventStream(path=tmp_path / "events.jsonl")

    def fake_poll_kev(**kwargs):
        # Simulate the real KEV poll's effect: upsert one entry.
        ti_cache.upsert_kev_entries([{
            "cve_id": "CVE-2024-NEW",
            "vendor": "apache", "product": "tomcat",
            "vuln_name": "Apache RCE",
        }])
        return {"status": "ok", "ingested": 1, "catalog_version": "x"}

    result = streaming_iteration(
        stream=stream, poll_kev_fn=fake_poll_kev,
    )
    assert result["status"] == "ok"
    assert result["kev_diff"]["added"] == 1
    assert result["events_emitted"] >= 2  # kev_added + feed_polled
    events = list(stream.tail())
    kinds = [e.kind for e in events]
    assert "kev_added" in kinds
    assert "feed_polled" in kinds
    kev_ev = next(e for e in events if e.kind == "kev_added")
    assert kev_ev.id == "CVE-2024-NEW"


def test_streaming_iteration_no_new_entries_emits_only_liveness(
    tmp_cache, tmp_path: Path,
) -> None:
    """Pre-existing KEV; poll returns no new entries. Emits a
    single liveness event so tail readers know the daemon is
    alive."""
    ti_cache.upsert_kev_entries([{
        "cve_id": "CVE-2024-OLD",
        "vendor": "x", "product": "y", "vuln_name": "old",
    }])
    stream = EventStream(path=tmp_path / "events.jsonl")

    def fake_poll_kev(**kwargs):
        # No new entries — just touch the cache.
        return {"status": "ok", "ingested": 0}

    result = streaming_iteration(
        stream=stream, poll_kev_fn=fake_poll_kev,
    )
    assert result["status"] == "ok"
    assert result["kev_diff"]["added"] == 0
    events = list(stream.tail())
    assert len(events) == 1  # just feed_polled liveness
    assert events[0].kind == "feed_polled"


def test_streaming_iteration_records_error_on_poll_failure(
    tmp_cache, tmp_path: Path,
) -> None:
    """Failed poll → status=error, but a feed_polled event still
    fires so the tail reader sees the failure."""
    stream = EventStream(path=tmp_path / "events.jsonl")

    def fake_poll_kev(**kwargs):
        return {"status": "error", "error": "kev source 503"}

    result = streaming_iteration(
        stream=stream, poll_kev_fn=fake_poll_kev,
    )
    assert result["status"] == "error"
    events = list(stream.tail())
    assert any(e.kind == "feed_polled" for e in events)
    failed_event = next(e for e in events if e.kind == "feed_polled")
    assert failed_event.data["status"] == "error"


def test_streaming_iteration_handles_poll_raising(
    tmp_cache, tmp_path: Path,
) -> None:
    """Poll function raises an exception — captured, no crash."""
    stream = EventStream(path=tmp_path / "events.jsonl")

    def fake_poll_kev(**kwargs):
        raise RuntimeError("network down")

    result = streaming_iteration(
        stream=stream, poll_kev_fn=fake_poll_kev,
    )
    assert result["status"] == "error"
    assert "network down" in (result.get("error") or "")
