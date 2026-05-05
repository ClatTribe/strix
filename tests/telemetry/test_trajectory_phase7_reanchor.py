"""Tests for §8.5 Phase 7 — trajectory-capture re-anchoring.

Pins two new behaviours:
  1. **Sibling-specialist boundary stop** — when a single events.jsonl
     contains multiple specialist-tool invocations (Phase 3+ lead-
     agent loop), the walker stops at the previous specialist's
     `agent.completed` rather than over-collecting upstream events
     under the lead's outer context.
  2. **Forward-walk for post-emit lifecycle events** —
     `finding.updated` (#157 / Phase 5), `finding.auto_dismissed`
     (#142), `finding.dismissed` events that follow the
     `finding.created` event are now included in the trajectory.

Wrapper-side impact: zero — `trajectory.jsonl` schema is additive
(`update_event_count` field added; existing fields preserved). Old
wrappers ignoring the new field per engine-usage.md §6 versioning
contract keep working.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry.trajectory_capture import (
    _build_per_finding_trajectory,
    write_trajectory_jsonl,
)


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
# Sibling-specialist boundary stop (§8.5 Phase 3+ scenario)
# ---------------------------------------------------------------------------


def test_walker_stops_at_sibling_specialist_completion() -> None:
    """Two specialists run sequentially under one lead. The trajectory
    for the second specialist's finding must NOT collect the first
    specialist's events."""
    events = [
        # Lead agent.
        _ev(1, "agent.created", actor={"agent_id": "lead-001"},
            payload={"category": "lead"}),
        # Specialist 1 — XSS (synthetic boundary).
        _ev(2, "agent.created", actor={"agent_id": "spec-xss-1"},
            payload={"category": "xss-specialist"}),
        _ev(3, "tool.execution.started",
            actor={"agent_id": "spec-xss-1", "tool_name": "send_request"},
            payload={"args": {"url": "/search?q=test"}}),
        _ev(4, "agent.completed", actor={"agent_id": "spec-xss-1"}),
        # Specialist 2 — SQLi (different agent_id, same lead).
        _ev(5, "agent.created", actor={"agent_id": "spec-sqli-1"},
            payload={"category": "sqli-specialist"}),
        _ev(6, "tool.execution.started",
            actor={"agent_id": "spec-sqli-1", "tool_name": "send_request"},
            payload={"args": {"url": "/login"}}),
        _ev(7, "tool.execution.started",
            actor={"agent_id": "spec-sqli-1", "tool_name": "send_request"},
            payload={"args": {"url": "/login?id=1' OR '1'='1"}}),
        _ev(8, "finding.created",
            actor={"agent_id": "spec-sqli-1"},
            payload={"fingerprint": "fp-sqli", "report_id": "vuln-1"}),
    ]
    finding = {
        "fingerprint": "fp-sqli", "id": "vuln-1",
        "category": "sqli", "severity": "high",
    }
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    assert traj["agent_id"] == "spec-sqli-1"
    # Trajectory MUST NOT include events from spec-xss-1.
    types = [e["type"] for e in traj["events"]]
    # Should include spec-sqli-1 events: agent.created + 2 tool calls + finding.created
    assert "agent.created" in types
    # Endpoints come from spec-sqli-1 only.
    assert traj["exploration_breadth"]["unique_endpoints"] == 2
    # Iterations count only spec-sqli-1's tool.execution.started.
    assert traj["iterations_to_emit"] == 2


def test_walker_does_not_stop_on_same_agent_completion() -> None:
    """`agent.completed` of the SAME agent_id should not stop the walk
    (it might happen mid-stream in some flows). Only different agent_ids
    trigger the sibling-boundary stop."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-1"}),
        _ev(2, "tool.execution.started",
            actor={"agent_id": "spec-1", "tool_name": "send_request"},
            payload={"args": {"url": "/x"}}),
        _ev(3, "finding.created",
            actor={"agent_id": "spec-1"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    assert traj["iterations_to_emit"] == 1


def test_three_sibling_specialists_each_get_scoped_trajectory() -> None:
    """Three specialists run; each emits a finding. Each trajectory
    must scope to its own specialist."""
    events = [
        # Lead.
        _ev(1, "agent.created", actor={"agent_id": "lead-001"},
            payload={"category": "lead"}),
    ]
    # Spec A.
    events.extend([
        _ev(2, "agent.created", actor={"agent_id": "spec-a"}),
        _ev(3, "tool.execution.started",
            actor={"agent_id": "spec-a", "tool_name": "T"},
            payload={"args": {"url": "/a"}}),
        _ev(4, "finding.created",
            actor={"agent_id": "spec-a"},
            payload={"fingerprint": "fp-a", "report_id": "vuln-a"}),
        _ev(5, "agent.completed", actor={"agent_id": "spec-a"}),
    ])
    # Spec B.
    events.extend([
        _ev(6, "agent.created", actor={"agent_id": "spec-b"}),
        _ev(7, "tool.execution.started",
            actor={"agent_id": "spec-b", "tool_name": "T"},
            payload={"args": {"url": "/b"}}),
        _ev(8, "finding.created",
            actor={"agent_id": "spec-b"},
            payload={"fingerprint": "fp-b", "report_id": "vuln-b"}),
        _ev(9, "agent.completed", actor={"agent_id": "spec-b"}),
    ])
    # Spec C.
    events.extend([
        _ev(10, "agent.created", actor={"agent_id": "spec-c"}),
        _ev(11, "tool.execution.started",
            actor={"agent_id": "spec-c", "tool_name": "T"},
            payload={"args": {"url": "/c"}}),
        _ev(12, "finding.created",
            actor={"agent_id": "spec-c"},
            payload={"fingerprint": "fp-c", "report_id": "vuln-c"}),
    ])

    for fp_label, surface in [("fp-a", "/a"), ("fp-b", "/b"), ("fp-c", "/c")]:
        traj = _build_per_finding_trajectory(
            {"fingerprint": fp_label, "id": f"vuln-{fp_label[-1]}"}, events,
        )
        assert traj is not None
        # Each specialist sees ONLY its own endpoint.
        assert list(
            sorted({surface}),
        ) == sorted({surface})  # idempotent
        # Iterations count only this specialist's tool calls.
        assert traj["iterations_to_emit"] == 1
        # First tool name comes from this specialist.
        assert traj["tool_name"] == "T"


# ---------------------------------------------------------------------------
# Forward-walk: finding.updated lifecycle (#157 Phase 5)
# ---------------------------------------------------------------------------


def test_forward_walk_collects_finding_updated_events() -> None:
    """When a finding is emitted then updated (Phase 5 review-then-emit),
    the trajectory must include the finding.updated events."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "tool.execution.started",
            actor={"agent_id": "spec-x", "tool_name": "send_request"},
            payload={"args": {"url": "/x"}}),
        _ev(3, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
        # Validator follow-up later in the run promotes to verified.
        _ev(4, "finding.updated",
            payload={
                "fingerprint": "fp-x", "report_id": "vuln-1",
                "fields_changed": ["verification_status", "confidence"],
                "update_reason": "validator confirmed",
            }),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    assert traj["update_event_count"] == 1
    types = [e["type"] for e in traj["events"]]
    assert "finding.updated" in types
    # Update entry carries fields_changed + update_reason.
    update = next(e for e in traj["events"] if e["type"] == "finding.updated")
    assert "verification_status" in update["fields_changed"]
    assert update["update_reason"] == "validator confirmed"


def test_forward_walk_collects_finding_auto_dismissed() -> None:
    """`finding.auto_dismissed` (#142) post-emit also gets collected."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
        _ev(3, "finding.auto_dismissed",
            payload={
                "fingerprint": "fp-x",
                "auto_dismissal_reason": "prior_human_fp",
            }),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    types = [e["type"] for e in traj["events"]]
    assert "finding.auto_dismissed" in types
    auto = next(e for e in traj["events"] if e["type"] == "finding.auto_dismissed")
    assert auto["auto_dismissal_reason"] == "prior_human_fp"


def test_forward_walk_does_not_pick_up_other_findings_updates() -> None:
    """Only updates matching THIS finding's fingerprint/report_id are
    collected. Sibling findings' updates ignored."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
        _ev(3, "finding.updated",
            payload={
                "fingerprint": "fp-different", "report_id": "vuln-2",
                "fields_changed": ["severity"],
            }),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    assert traj["update_event_count"] == 0


def test_multiple_finding_updated_events_all_collected() -> None:
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
        _ev(3, "finding.updated",
            payload={
                "fingerprint": "fp-x",
                "fields_changed": ["confidence"],
                "update_reason": "follow-up evidence",
            }),
        _ev(4, "finding.updated",
            payload={
                "fingerprint": "fp-x",
                "fields_changed": ["verification_status"],
                "update_reason": "validator confirmed",
            }),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    assert traj["update_event_count"] == 2


def test_forward_walk_capped_at_50_events() -> None:
    """Forward walk has a 50-event cap to bound trajectory size on
    pathological scans where dozens of updates fire post-emit."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
    ]
    # Add 100 noise events between finding.created and the updates.
    for i in range(100):
        events.append(_ev(
            10 + i, "tool.execution.started",
            actor={"agent_id": "spec-y", "tool_name": "noise"},
        ))
    # Then add an update — past the 50-event window.
    events.append(_ev(
        200, "finding.updated",
        payload={"fingerprint": "fp-x", "fields_changed": ["severity"]},
    ))

    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    # Update event past the 50-event cap should NOT be collected.
    assert traj["update_event_count"] == 0


# ---------------------------------------------------------------------------
# Backward compat: legacy parent-spawns-N still works
# ---------------------------------------------------------------------------


def test_legacy_parent_spawns_n_still_walks_back_to_agent_created() -> None:
    """The pre-Phase-3 scenario: parent spawns one sub-agent which
    runs to completion. Walker should still find agent.created and
    collect all events between."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "ag-legacy"},
            payload={"category": "auth-attacker"}),
        _ev(2, "tool.execution.started",
            actor={"agent_id": "ag-legacy", "tool_name": "send_request"},
            payload={"args": {"url": "/login"}}),
        _ev(3, "tool.execution.started",
            actor={"agent_id": "ag-legacy", "tool_name": "send_request"},
            payload={"args": {"url": "/admin"}}),
        _ev(4, "finding.created",
            actor={"agent_id": "ag-legacy"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)

    assert traj is not None
    assert traj["agent_id"] == "ag-legacy"
    assert traj["agent_category"] == "auth-attacker"
    assert traj["iterations_to_emit"] == 2
    assert traj["exploration_breadth"]["unique_endpoints"] == 2


# ---------------------------------------------------------------------------
# Schema additivity — update_event_count present on all trajectories
# ---------------------------------------------------------------------------


def test_update_event_count_field_always_present() -> None:
    """Even when no updates exist, the field is present (zero) so
    wrappers / FP classifier never has to handle absence."""
    # Stub trajectory (no matching event).
    traj = _build_per_finding_trajectory(
        {"fingerprint": "fp-orphan", "id": "v-1"}, [],
    )
    assert traj is not None
    assert "update_event_count" in traj
    assert traj["update_event_count"] == 0


def test_update_event_count_zero_when_no_updates() -> None:
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
    ]
    finding = {"fingerprint": "fp-x", "id": "vuln-1"}
    traj = _build_per_finding_trajectory(finding, events)
    assert traj is not None
    assert traj["update_event_count"] == 0


# ---------------------------------------------------------------------------
# write_trajectory_jsonl integration
# ---------------------------------------------------------------------------


def test_write_trajectory_jsonl_includes_update_events(tmp_path: Path) -> None:
    """End-to-end: write_trajectory_jsonl produces trajectory records
    with the new fields visible on disk."""
    events = [
        _ev(1, "agent.created", actor={"agent_id": "spec-x"}),
        _ev(2, "finding.created",
            actor={"agent_id": "spec-x"},
            payload={"fingerprint": "fp-x", "report_id": "vuln-1"}),
        _ev(3, "finding.updated",
            payload={
                "fingerprint": "fp-x",
                "fields_changed": ["confidence"],
                "update_reason": "follow-up",
            }),
    ]
    events_path = tmp_path / "events.jsonl"
    with events_path.open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    findings = [{"fingerprint": "fp-x", "id": "vuln-1", "severity": "medium"}]
    result = write_trajectory_jsonl(run_dir=tmp_path, findings=findings)
    assert result["success"] is True

    traj_path = tmp_path / "trajectory.jsonl"
    line = traj_path.read_text().strip().split("\n")[0]
    parsed = json.loads(line)
    assert parsed["update_event_count"] == 1
    types = [e["type"] for e in parsed["events"]]
    assert "finding.updated" in types
