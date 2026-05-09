"""Tests for §workitem.md Phase 5.4 — specialist call telemetry.

Pins:
  * record_specialist_call → in-memory event with the right shape
  * `event_kind` derived from findings_count (hit vs miss)
  * Persistence to <run_dir>/specialist_telemetry.jsonl when
    STRIX_RUN_DIR set
  * Bounded summary on huge args / huge evidence lists
  * list_telemetry_events filters
  * last_call_for_target lookup
  * hit_miss_counts aggregation
  * reset_telemetry test helper
  * Best-effort: malformed input doesn't raise
  * Registry hook fires on every wrapped specialist call
"""

from __future__ import annotations

import json
import os

import pytest

from strix.agents.specialist_telemetry import (
    TelemetryEvent,
    hit_miss_counts,
    last_call_for_target,
    list_telemetry_events,
    record_specialist_call,
    reset_telemetry,
)


@pytest.fixture(autouse=True)
def _reset_telemetry_buffer() -> None:
    reset_telemetry()
    yield
    reset_telemetry()


# ---------------------------------------------------------------------------
# Basic record + retrieval
# ---------------------------------------------------------------------------


def test_record_specialist_hit() -> None:
    """findings_count > 0 → event_kind = specialist.hit."""
    event_id = record_specialist_call(
        tool_name="scan_sqli",
        category="sqli-specialist",
        target="http://example.com/api/items?id=1",
        params=["id"],
        args={"url": "http://example.com/api/items?id=1", "param": "id"},
        result={
            "status": "ok",
            "findings": [{"title": "SQL injection in `id`", "severity": "high"}],
            "evidence": ["payload triggered DB error"],
            "tool_metadata": {"probes_sent": 12},
        },
        elapsed_seconds=4.21,
    )
    assert event_id.startswith("t_")
    events = list_telemetry_events()
    assert len(events) == 1
    e = events[0]
    assert e.event_kind == "specialist.hit"
    assert e.tool_name == "scan_sqli"
    assert e.category == "sqli-specialist"
    assert e.params == ["id"]
    assert e.elapsed_seconds == 4.21
    assert e.result_summary["findings_count"] == 1
    assert "SQL injection" in e.result_summary["finding_titles"][0]


def test_record_specialist_miss() -> None:
    """No findings → event_kind = specialist.miss."""
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/api/search?q=1",
        result={"status": "ok", "findings": [], "evidence": []},
    )
    events = list_telemetry_events()
    assert events[0].event_kind == "specialist.miss"


def test_error_status_records_as_miss() -> None:
    """status=error with no findings → miss (we still record it for
    debugging; error means specialist failed to even run)."""
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/x",
        result={"status": "error", "error": "proxy unavailable"},
    )
    events = list_telemetry_events()
    assert events[0].event_kind == "specialist.miss"
    assert events[0].result_summary["status"] == "error"


# ---------------------------------------------------------------------------
# Bounded summary
# ---------------------------------------------------------------------------


def test_bounded_summary_truncates_huge_evidence() -> None:
    """A specialist that returned 1000 evidence entries shouldn't
    blow up the telemetry row — we only keep counts + first few."""
    huge_evidence = ["evidence_" + str(i) for i in range(1000)]
    record_specialist_call(
        tool_name="scan_path_traversal",
        category="path-traversal-specialist",
        target="http://example.com/dl?file=x",
        result={
            "status": "ok",
            "findings": [],
            "evidence": huge_evidence,
            "tool_metadata": {"probes_sent": 50},
        },
    )
    e = list_telemetry_events()[0]
    # Count is preserved.
    assert e.result_summary["evidence_count"] == 1000
    # But the raw evidence list is NOT in the row.
    serialized = json.dumps(e.to_dict())
    # Definitely not 1000 evidence lines in the JSON.
    assert serialized.count("evidence_") < 50


def test_bounded_summary_truncates_long_strings() -> None:
    """Long string fields in args summary → truncated marker."""
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/x",
        args={"big_arg": "x" * 1000},
        result={"status": "ok", "findings": []},
    )
    e = list_telemetry_events()[0]
    assert isinstance(e.args_summary["big_arg"], str)
    # 240-char cap from default _bounded_summary.
    assert "...+" in e.args_summary["big_arg"]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persist_to_run_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    record_specialist_call(
        tool_name="scan_sqli",
        category="sqli-specialist",
        target="http://example.com/x",
        result={"status": "ok", "findings": [{"title": "x"}]},
    )
    log_path = tmp_path / "specialist_telemetry.jsonl"
    assert log_path.exists()
    line = log_path.read_text().splitlines()[0]
    parsed = json.loads(line)
    assert parsed["tool_name"] == "scan_sqli"
    assert parsed["event_kind"] == "specialist.hit"


def test_no_persist_without_run_dir(monkeypatch, tmp_path) -> None:
    """When STRIX_RUN_DIR isn't set, persistence is silent — no
    error, just no file."""
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    record_specialist_call(
        tool_name="scan_sqli", category="x", target="x",
        result={"status": "ok"},
    )
    # No exception. In-memory event still recorded.
    assert len(list_telemetry_events()) == 1


# ---------------------------------------------------------------------------
# Filters / lookups
# ---------------------------------------------------------------------------


def test_list_filter_by_tool() -> None:
    record_specialist_call(
        tool_name="scan_sqli", category="x", target="http://a/",
        result={"status": "ok", "findings": [{"title": "x"}]},
    )
    record_specialist_call(
        tool_name="scan_xss", category="x", target="http://b/",
        result={"status": "ok", "findings": []},
    )
    events = list_telemetry_events(tool_name="scan_sqli")
    assert len(events) == 1
    assert events[0].tool_name == "scan_sqli"


def test_list_filter_by_kind() -> None:
    record_specialist_call(
        tool_name="scan_sqli", category="x", target="http://a/",
        result={"status": "ok", "findings": [{"title": "x"}]},
    )
    record_specialist_call(
        tool_name="scan_xss", category="x", target="http://b/",
        result={"status": "ok", "findings": []},
    )
    hits = list_telemetry_events(event_kind="specialist.hit")
    assert len(hits) == 1
    misses = list_telemetry_events(event_kind="specialist.miss")
    assert len(misses) == 1


def test_list_filter_by_target_substring() -> None:
    record_specialist_call(
        tool_name="scan_sqli", category="x",
        target="http://example.com/api/items",
        result={"status": "ok"},
    )
    record_specialist_call(
        tool_name="scan_xss", category="x",
        target="http://other.test/login",
        result={"status": "ok"},
    )
    matched = list_telemetry_events(target_substring="example.com")
    assert len(matched) == 1


def test_last_call_for_target() -> None:
    record_specialist_call(
        tool_name="scan_sqli", category="x",
        target="http://example.com/api",
        result={"status": "ok"},
    )
    record_specialist_call(
        tool_name="scan_xss", category="x",
        target="http://example.com/api",
        result={"status": "ok"},
    )
    last = last_call_for_target("http://example.com/api")
    assert last is not None
    assert last.tool_name == "scan_xss"  # most recent
    last_sqli = last_call_for_target(
        "http://example.com/api", tool_name="scan_sqli",
    )
    assert last_sqli.tool_name == "scan_sqli"


def test_last_call_for_target_no_match() -> None:
    record_specialist_call(
        tool_name="scan_sqli", category="x",
        target="http://a.test/", result={"status": "ok"},
    )
    assert last_call_for_target("http://nonexistent.test/") is None


def test_hit_miss_counts_aggregation() -> None:
    for _ in range(3):
        record_specialist_call(
            tool_name="scan_sqli", category="x", target="http://a/",
            result={"status": "ok", "findings": [{"title": "x"}]},
        )
    for _ in range(7):
        record_specialist_call(
            tool_name="scan_sqli", category="x", target="http://b/",
            result={"status": "ok", "findings": []},
        )
    counts = hit_miss_counts(tool_name="scan_sqli")
    assert counts == {"hits": 3, "misses": 7, "total": 10}


# ---------------------------------------------------------------------------
# Best-effort robustness
# ---------------------------------------------------------------------------


def test_record_with_malformed_result_does_not_raise() -> None:
    """Garbage `result` shape — telemetry shouldn't crash the agent."""
    eid = record_specialist_call(
        tool_name="scan_sqli", category="x", target="http://a/",
        result="not a dict",  # type: ignore[arg-type]
    )
    # Either records (with safe defaults) or returns "" — either way,
    # no exception.
    assert isinstance(eid, str)


def test_record_with_none_target_does_not_raise() -> None:
    eid = record_specialist_call(
        tool_name="x", category="y", target=None,  # type: ignore[arg-type]
        result={"status": "ok"},
    )
    assert isinstance(eid, str)


# ---------------------------------------------------------------------------
# Registry hook integration
# ---------------------------------------------------------------------------


def test_registry_hook_fires_on_specialist_call(monkeypatch) -> None:
    """Calling any registered specialist should produce a telemetry
    event automatically — no explicit call to record_specialist_call
    needed."""
    from unittest.mock import MagicMock

    # Stub the proxy so scan_xss can run end-to-end without network.
    fake = MagicMock()
    fake.send_simple_request = MagicMock(return_value={
        "status_code": 200, "body": "no payload echoed", "headers": {},
    })
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )

    # Reset specifically for this test — autouse reset already ran
    # before, but importing a specialist module may have triggered
    # other recording during fixture setup.
    reset_telemetry()

    from strix.tools.specialist.scan_xss import scan_xss
    scan_xss(url="http://example.com/search?q=test", param="q")

    events = list_telemetry_events(tool_name="scan_xss")
    assert len(events) >= 1
    # The hook recorded the target.
    assert "example.com" in events[0].target
    # No findings → miss.
    assert events[0].event_kind == "specialist.miss"
