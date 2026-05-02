"""Tests for target.started / target.completed events.

Roadmap §1. Multi-target scans had no clean per-target progress signal —
consumers had to join across multiple events to figure out what was
running where. These tests pin the contract for the new pair.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, _normalize_target_for_events, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def _events_for(run_name: str, tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / run_name / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# _normalize_target_for_events
# ---------------------------------------------------------------------------


def test_normalize_string_target() -> None:
    assert _normalize_target_for_events("example.com") == {"value": "example.com"}


def test_normalize_dict_with_value_and_type() -> None:
    assert _normalize_target_for_events({"value": "example.com", "type": "domain"}) == {
        "value": "example.com", "type": "domain",
    }


def test_normalize_cli_shape_with_details() -> None:
    """CLI builds targets_info as {type, details, original}."""
    raw = {
        "type": "web_application",
        "details": {"target_url": "https://example.com"},
        "original": "https://example.com",
    }
    out = _normalize_target_for_events(raw)
    assert out == {"value": "https://example.com", "type": "web_application"}


def test_normalize_cli_shape_repository() -> None:
    raw = {
        "type": "repository",
        "details": {"target_repo": "https://github.com/x/y"},
    }
    out = _normalize_target_for_events(raw)
    assert out == {"value": "https://github.com/x/y", "type": "repository"}


def test_normalize_returns_none_for_unusable_input() -> None:
    assert _normalize_target_for_events(None) is None
    assert _normalize_target_for_events({"type": "domain"}) is None  # no value
    assert _normalize_target_for_events("") is None
    assert _normalize_target_for_events(42) is None


# ---------------------------------------------------------------------------
# target.started emission
# ---------------------------------------------------------------------------


def test_target_started_emitted_per_target(tmp_path) -> None:
    t = Tracer("multi-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [
        {"type": "domain", "value": "a.example.com"},
        {"type": "domain", "value": "b.example.com"},
        {"type": "ip_address", "value": "1.2.3.4"},
    ]})
    events = _events_for("multi-run", tmp_path)
    started = [e for e in events if e["event_type"] == "target.started"]
    assert len(started) == 3
    values = [e["payload"]["value"] for e in started]
    assert values == ["a.example.com", "b.example.com", "1.2.3.4"]
    # Each event carries a unique target_id.
    ids = [e["payload"]["target_id"] for e in started]
    assert len(set(ids)) == 3
    assert ids[0] == "target-0001"


def test_target_started_after_run_configured(tmp_path) -> None:
    """target.started should land after run.configured so consumers reading
    in order see the scan_config first."""
    t = Tracer("order-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    events = _events_for("order-run", tmp_path)
    types = [e["event_type"] for e in events]
    cfg_idx = types.index("run.configured")
    started_idx = types.index("target.started")
    assert cfg_idx < started_idx


def test_no_target_events_when_targets_missing(tmp_path) -> None:
    t = Tracer("no-targets")
    set_global_tracer(t)
    t.set_scan_config({"targets": []})
    events = _events_for("no-targets", tmp_path)
    assert not [e for e in events if e["event_type"] in ("target.started", "target.completed")]


def test_unusable_targets_skipped(tmp_path) -> None:
    t = Tracer("partial-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [
        {"type": "domain", "value": "example.com"},
        {"type": "domain"},  # no value — should be skipped
        "raw-string-target.com",
    ]})
    events = _events_for("partial-run", tmp_path)
    started = [e for e in events if e["event_type"] == "target.started"]
    assert len(started) == 2
    assert started[0]["payload"]["value"] == "example.com"
    assert started[1]["payload"]["value"] == "raw-string-target.com"


# ---------------------------------------------------------------------------
# target.completed emission + per-target rollup
# ---------------------------------------------------------------------------


def test_target_completed_emitted_per_target(tmp_path) -> None:
    t = Tracer("complete-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [
        {"type": "domain", "value": "a.example.com"},
        {"type": "domain", "value": "b.example.com"},
    ]})
    t.save_run_data(mark_complete=True)
    events = _events_for("complete-run", tmp_path)
    completed = [e for e in events if e["event_type"] == "target.completed"]
    assert len(completed) == 2
    # target_ids match the started events.
    started_ids = [e["payload"]["target_id"] for e in events if e["event_type"] == "target.started"]
    completed_ids = [e["payload"]["target_id"] for e in completed]
    assert started_ids == completed_ids


def test_target_completed_carries_per_target_rollup(tmp_path) -> None:
    t = Tracer("rollup-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [
        {"type": "domain", "value": "a.example.com"},
        {"type": "domain", "value": "b.example.com"},
    ]})
    # Findings split between the two targets.
    t.add_vulnerability_report(title="A1", severity="medium", category="dns_security", target="a.example.com")
    t.add_vulnerability_report(title="A2", severity="low", category="dns_security", target="a.example.com")
    t.add_vulnerability_report(title="B1", severity="high", category="auth", target="b.example.com")

    # Checks split between the two targets via `surface`.
    cid1 = t.start_check(category="dns_security", surface="a.example.com", tool="x")
    t.complete_check(cid1, result="not_vulnerable")
    cid2 = t.start_check(category="auth", surface="b.example.com", tool="y")
    t.complete_check(cid2, result="vulnerable")

    t.save_run_data(mark_complete=True)
    events = _events_for("rollup-run", tmp_path)
    completed_by_value = {
        e["payload"]["value"]: e["payload"]
        for e in events
        if e["event_type"] == "target.completed"
    }
    assert completed_by_value["a.example.com"]["findings"]["total"] == 2
    assert completed_by_value["a.example.com"]["findings"]["by_severity"] == {"medium": 1, "low": 1}
    assert completed_by_value["a.example.com"]["checks"]["total"] == 1
    assert completed_by_value["b.example.com"]["findings"]["total"] == 1
    assert completed_by_value["b.example.com"]["findings"]["by_severity"] == {"high": 1}
    assert completed_by_value["b.example.com"]["checks"]["total"] == 1


def test_findings_without_target_field_dont_match(tmp_path) -> None:
    """A finding with no `target` field shouldn't be assigned to any target's rollup."""
    t = Tracer("untagged")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.add_vulnerability_report(title="orphan", severity="info")
    t.save_run_data(mark_complete=True)
    events = _events_for("untagged", tmp_path)
    completed = next(e for e in events if e["event_type"] == "target.completed")
    assert completed["payload"]["findings"]["total"] == 0


def test_target_completed_before_run_summary(tmp_path) -> None:
    """Order matters: per-target completion events should land before
    the run.summary aggregator. Consumers reading in order can render
    per-target progress, then the headline."""
    t = Tracer("order-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.save_run_data(mark_complete=True)
    events = _events_for("order-run", tmp_path)
    types = [e["event_type"] for e in events]
    completed_idx = types.index("target.completed")
    summary_idx = types.index("run.summary")
    assert completed_idx < summary_idx


def test_target_completed_idempotent(tmp_path) -> None:
    """Repeated save_run_data(mark_complete=True) calls should not re-emit
    target.completed. Same guard as run.completed."""
    t = Tracer("idem-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.save_run_data(mark_complete=True)
    t.save_run_data(mark_complete=True)
    events = _events_for("idem-run", tmp_path)
    completed = [e for e in events if e["event_type"] == "target.completed"]
    assert len(completed) == 1


def test_no_target_completed_when_mark_complete_false(tmp_path) -> None:
    t = Tracer("partial")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.save_run_data(mark_complete=False)
    events = _events_for("partial", tmp_path)
    assert not [e for e in events if e["event_type"] == "target.completed"]


def test_run_summary_targets_match_target_events(tmp_path) -> None:
    """The targets list in run.summary should be the same set the
    target.started events covered — no drift between the two views."""
    t = Tracer("consistent")
    set_global_tracer(t)
    t.set_scan_config({"targets": [
        {"type": "domain", "value": "a.example.com"},
        {"type": "ip_address", "value": "1.2.3.4"},
    ]})
    t.save_run_data(mark_complete=True)
    events = _events_for("consistent", tmp_path)
    started_values = sorted(e["payload"]["value"] for e in events if e["event_type"] == "target.started")
    summary = next(e for e in events if e["event_type"] == "run.summary")
    summary_values = sorted(t["value"] for t in summary["payload"]["targets"])
    assert started_values == summary_values
