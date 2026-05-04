"""Tests for RLHF Phase 1 / A1 — trajectory_capture.

Pins the per-finding trajectory schema, the events.jsonl walk
strategy, and the best-effort failure semantics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry.trajectory_capture import (
    TRAJECTORY_SCHEMA_VERSION,
    _build_per_finding_trajectory,
    _seconds_between,
    _walk_events,
    write_trajectory_jsonl,
)


# ---------------------------------------------------------------------------
# Schema-stability invariants
# ---------------------------------------------------------------------------


def test_schema_version_pinned() -> None:
    assert TRAJECTORY_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_events(run_dir: Path, events: list[dict[str, Any]]) -> None:
    events_path = run_dir / "events.jsonl"
    with events_path.open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _ev(
    event_id: int,
    event_type: str,
    *,
    timestamp: str = "2026-01-01T00:00:00+00:00",
    actor: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "actor": actor or {},
        "payload": payload or {},
    }


# ---------------------------------------------------------------------------
# _seconds_between
# ---------------------------------------------------------------------------


def test_seconds_between_basic() -> None:
    s = _seconds_between(
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:30+00:00",
    )
    assert s == 30.0


def test_seconds_between_returns_none_on_bad_input() -> None:
    assert _seconds_between(None, "2026-01-01T00:00:00+00:00") is None
    assert _seconds_between("not-a-timestamp", "2026-01-01T00:00:00+00:00") is None


def test_seconds_between_clamps_negative_to_zero() -> None:
    """If end_ts is somehow before start_ts, we don't return negative."""
    s = _seconds_between(
        "2026-01-01T00:00:30+00:00",
        "2026-01-01T00:00:00+00:00",
    )
    assert s == 0.0


# ---------------------------------------------------------------------------
# _walk_events — JSONL reader is tolerant
# ---------------------------------------------------------------------------


def test_walk_events_tolerates_malformed_lines(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    p.write_text(
        '{"event_id":1,"event_type":"a"}\n'
        '\n'
        'malformed\n'
        '{"event_id":2,"event_type":"b"}\n'
    )
    out = _walk_events(p)
    assert len(out) == 2
    assert out[0]["event_id"] == 1
    assert out[1]["event_id"] == 2


def test_walk_events_missing_file_returns_empty(tmp_path: Path) -> None:
    assert _walk_events(tmp_path / "nope.jsonl") == []


# ---------------------------------------------------------------------------
# _build_per_finding_trajectory
# ---------------------------------------------------------------------------


def test_build_trajectory_walks_back_to_agent_created() -> None:
    """The walk should collect events for the same agent_id from
    agent.created up to finding.created in chronological order."""
    events = [
        _ev(
            1, "agent.created",
            timestamp="2026-01-01T00:00:00+00:00",
            actor={"agent_id": "ag-1"},
            payload={"category": "auth-attacker"},
        ),
        _ev(
            2, "tool.execution.started",
            timestamp="2026-01-01T00:00:05+00:00",
            actor={"agent_id": "ag-1", "tool_name": "send_request"},
            payload={"args": {"url": "/login"}},
        ),
        _ev(
            3, "tool.execution.started",
            timestamp="2026-01-01T00:00:10+00:00",
            actor={"agent_id": "ag-1", "tool_name": "send_request"},
            payload={"args": {"url": "/admin"}},
        ),
        _ev(
            4, "finding.created",
            timestamp="2026-01-01T00:00:15+00:00",
            actor={"agent_id": "ag-1"},
            payload={"fingerprint": "fp-x"},
        ),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1",
               "category": "broken-auth", "severity": "high"}

    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    assert traj["schema_version"] == TRAJECTORY_SCHEMA_VERSION
    assert traj["finding_fingerprint"] == "fp-x"
    assert traj["finding_id"] == "vuln-1"
    assert traj["agent_id"] == "ag-1"
    assert traj["agent_category"] == "auth-attacker"
    assert traj["tool_name"] == "send_request"
    assert traj["category"] == "broken-auth"
    assert traj["severity"] == "high"
    assert traj["iterations_to_emit"] == 2
    assert traj["tool_calls_in_trajectory"] == 2
    assert traj["exploration_breadth"]["unique_endpoints"] == 2
    assert traj["exploration_breadth"]["unique_tools"] == 1
    # Time spans agent.created (00:00:00) to finding.created (00:00:15).
    assert traj["time_to_emit_seconds"] == 15.0


def test_build_trajectory_returns_stub_when_no_event_matches() -> None:
    """Findings with no matching event still get a stub trajectory
    so the wrapper renders 'trajectory unknown' rather than 'no file'."""
    events: list[dict[str, Any]] = []
    finding = {"fingerprint": "fp-orphan", "id": "v-1",
               "category": "xss", "severity": "low"}
    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    assert traj["finding_fingerprint"] == "fp-orphan"
    assert traj["events"] == []
    assert traj["iterations_to_emit"] == 0
    assert traj["tool_calls_in_trajectory"] == 0
    assert traj["agent_id"] is None


def test_build_trajectory_returns_none_for_missing_fingerprint() -> None:
    """Findings without a fingerprint can't be tracked — drop them."""
    finding = {"id": "v-1"}
    assert _build_per_finding_trajectory(finding, []) is None


def test_build_trajectory_dedupes_endpoints_across_tool_calls() -> None:
    events = [
        _ev(1, "agent.created", actor={"agent_id": "ag-1"}),
        _ev(
            2, "tool.execution.started",
            actor={"agent_id": "ag-1", "tool_name": "send_request"},
            payload={"args": {"url": "/api/x"}},
        ),
        _ev(
            3, "tool.execution.started",
            actor={"agent_id": "ag-1", "tool_name": "send_request"},
            payload={"args": {"url": "/api/x"}},  # same endpoint
        ),
        _ev(
            4, "finding.created",
            actor={"agent_id": "ag-1"},
            payload={"fingerprint": "fp-x"},
        ),
    ]
    finding = {"fingerprint": "fp-x", "id": "v-1"}
    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    assert traj["exploration_breadth"]["unique_endpoints"] == 1
    assert traj["tool_calls_in_trajectory"] == 2


def test_build_trajectory_captures_dismissed_alternatives() -> None:
    events = [
        _ev(1, "agent.created", actor={"agent_id": "ag-1"}),
        _ev(
            2, "finding.dismissed",
            actor={"agent_id": "ag-1"},
            payload={
                "surface": "/login",
                "hypothesis": "csrf-on-login",
                "dismissal_reason": "csrf_token_validated",
            },
        ),
        _ev(
            3, "finding.created",
            actor={"agent_id": "ag-1"},
            payload={"fingerprint": "fp-x"},
        ),
    ]
    finding = {"fingerprint": "fp-x", "id": "v-1"}
    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    assert len(traj["dismissed_alternatives"]) == 1
    assert traj["dismissed_alternatives"][0]["surface"] == "/login"
    assert traj["dismissed_alternatives"][0]["dismissal_reason"] == "csrf_token_validated"


def test_build_trajectory_matches_via_report_id_fallback() -> None:
    """When the event has no fingerprint but has report_id matching
    finding.id, the walk should still find the right event."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "ag-1"}),
        _ev(
            2, "finding.created",
            actor={"agent_id": "ag-1"},
            payload={"report_id": "vuln-007"},
        ),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-007"}
    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    assert traj["finding_fingerprint"] == "fp-x"
    assert traj["agent_id"] == "ag-1"


# ---------------------------------------------------------------------------
# write_trajectory_jsonl — end-to-end emission
# ---------------------------------------------------------------------------


def test_write_trajectory_jsonl_emits_one_line_per_finding(tmp_path: Path) -> None:
    events = [
        _ev(1, "agent.created", actor={"agent_id": "ag-1"}),
        _ev(
            2, "finding.created",
            actor={"agent_id": "ag-1"},
            payload={"fingerprint": "fp-a"},
        ),
        _ev(3, "agent.created", actor={"agent_id": "ag-2"}),
        _ev(
            4, "finding.created",
            actor={"agent_id": "ag-2"},
            payload={"fingerprint": "fp-b"},
        ),
    ]
    _write_events(tmp_path, events)

    findings = [
        {"fingerprint": "fp-a", "id": "v-1", "severity": "high"},
        {"fingerprint": "fp-b", "id": "v-2", "severity": "low"},
    ]
    result = write_trajectory_jsonl(run_dir=tmp_path, findings=findings)

    assert result["success"] is True
    assert result["written"] == 2
    assert "errors" not in result

    out_path = tmp_path / "trajectory.jsonl"
    assert out_path.exists()
    lines = out_path.read_text().strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert {p["finding_fingerprint"] for p in parsed} == {"fp-a", "fp-b"}


def test_write_trajectory_jsonl_handles_missing_events_file(tmp_path: Path) -> None:
    """No events.jsonl → still writes (empty/stub trajectories)."""
    findings = [{"fingerprint": "fp-x", "id": "v-1"}]
    result = write_trajectory_jsonl(run_dir=tmp_path, findings=findings)
    assert result["success"] is True
    out_path = tmp_path / "trajectory.jsonl"
    assert out_path.exists()


def test_write_trajectory_jsonl_skips_findings_without_fingerprint(
    tmp_path: Path,
) -> None:
    """`_build_per_finding_trajectory` returns None for missing
    fingerprints; those findings are silently skipped."""
    findings = [
        {"id": "v-1"},  # no fingerprint
        {"fingerprint": "fp-x", "id": "v-2"},
    ]
    result = write_trajectory_jsonl(run_dir=tmp_path, findings=findings)
    assert result["written"] == 1


def test_write_trajectory_jsonl_continues_on_per_finding_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-finding exceptions are recorded but don't abort the whole
    write — best-effort throughout."""
    from strix.telemetry import trajectory_capture

    call_count = {"n": 0}

    def fake_build(finding: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("boom")
        return {"finding_fingerprint": finding["fingerprint"]}

    monkeypatch.setattr(
        trajectory_capture, "_build_per_finding_trajectory", fake_build,
    )
    findings = [
        {"fingerprint": "fp-1", "id": "v-1"},
        {"fingerprint": "fp-2", "id": "v-2"},
    ]
    result = write_trajectory_jsonl(run_dir=tmp_path, findings=findings)
    assert result["success"] is True
    assert result["written"] == 1
    assert "errors" in result
    assert any("v-1" in e for e in result["errors"])
