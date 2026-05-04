"""Per-finding trajectory capture (RLHF Phase 1 / A1 from docs/rlhf-design.md).

Walks `events.jsonl` post-run and emits `trajectory.jsonl` —
per-finding records that capture the agent's investigation path.
The labeler in the wrapper uses this to grade not just the
verdict but the reasoning. The RLHF FP-classifier consumes the
trajectory features (iterations_to_emit, time_to_emit_seconds,
exploration_breadth) for training.

Design choices
--------------

* **Read-only post-walk.** Built ONCE at run-end by walking the
  existing `events.jsonl`. Per-event runtime overhead is zero.
* **Best-effort.** Walk failures fall back silently. The agent
  loop never depends on trajectory output being healthy.
* **Schema-stable.** Bump `TRAJECTORY_SCHEMA_VERSION` on
  breaking changes. Additive fields don't bump.

trajectory.jsonl schema (one line per finding):

```json
{
  "schema_version": 1,
  "finding_fingerprint": "a1b2c3d4...",
  "finding_id": "vuln-001",
  "agent_id": "agent_4f3a2c1b",
  "agent_category": "auth-attacker",
  "tool_name": "send_request",
  "category": "sql_injection",
  "severity": "high",
  "events": [
    {"event_id": <int>, "type": "tool.execution.started", "timestamp": "..."},
    ...
  ],
  "iterations_to_emit": <int>,        // number of LLM rounds
  "time_to_emit_seconds": <float>,    // span from agent start to finding
  "tool_calls_in_trajectory": <int>,
  "dismissed_alternatives": [
    {"surface": "...", "hypothesis": "...", "dismissal_reason": "..."}
  ],
  "exploration_breadth": {
    "unique_endpoints": <int>,
    "unique_tools": <int>
  }
}
```
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


TRAJECTORY_SCHEMA_VERSION: int = 1


def _parse_timestamp(s: str | None) -> datetime | None:
    """ISO-8601 timestamp with timezone (events.jsonl format)."""
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _seconds_between(start_ts: str | None, end_ts: str | None) -> float | None:
    s = _parse_timestamp(start_ts)
    e = _parse_timestamp(end_ts)
    if s is None or e is None:
        return None
    return max(0.0, (e - s).total_seconds())


def _walk_events(events_path: Path) -> list[dict[str, Any]]:
    """Read events.jsonl. Tolerant — malformed lines silently skipped."""
    out: list[dict[str, Any]] = []
    if not events_path.exists():
        return out
    try:
        for raw in events_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict):
                out.append(ev)
    except OSError:
        logger.debug("trajectory_capture: read failed", exc_info=True)
    return out


def _build_per_finding_trajectory(
    finding: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Build one trajectory record for one finding.

    Strategy: walk events backwards from the most recent
    `finding.created` event with a matching fingerprint, collecting
    upstream events that share the same `actor.agent_id`. Stop
    when we hit `agent.created` for that agent (or 200 events,
    whichever first).
    """
    fingerprint = finding.get("fingerprint")
    finding_id = finding.get("id")
    if not isinstance(fingerprint, str) or not fingerprint:
        return None

    # Find the finding.created event (or fallback) for this finding.
    finding_event_idx: int | None = None
    finding_agent_id: str | None = None
    for i, ev in enumerate(events):
        if ev.get("event_type") not in ("finding.created", "finding.reviewed"):
            continue
        payload = ev.get("payload") or {}
        if (
            payload.get("fingerprint") == fingerprint
            or payload.get("report_id") == finding_id
        ):
            finding_event_idx = i
            actor = ev.get("actor") or {}
            agent_id_val = actor.get("agent_id") or payload.get("agent_id")
            if isinstance(agent_id_val, str):
                finding_agent_id = agent_id_val
            break

    if finding_event_idx is None:
        # No matching event — emit a stub trajectory so the finding
        # is still represented (helps the wrapper render "trajectory
        # unknown" rather than "no trajectory file").
        return {
            "schema_version": TRAJECTORY_SCHEMA_VERSION,
            "finding_fingerprint": fingerprint,
            "finding_id": finding_id,
            "agent_id": None,
            "agent_category": None,
            "tool_name": None,
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "events": [],
            "iterations_to_emit": 0,
            "time_to_emit_seconds": None,
            "tool_calls_in_trajectory": 0,
            "dismissed_alternatives": [],
            "exploration_breadth": {"unique_endpoints": 0, "unique_tools": 0},
        }

    # Walk backwards to collect upstream events for this agent.
    # Stop bound is `-1` (range stop is exclusive) so we always
    # visit index 0; otherwise we'd miss agent.created when it
    # lives at the very start of the events log.
    related_events: list[dict[str, Any]] = []
    agent_started_idx: int | None = None
    max_walk = 200
    stop_at = max(-1, finding_event_idx - max_walk - 1)
    for j in range(finding_event_idx, stop_at, -1):
        ev = events[j]
        actor = ev.get("actor") or {}
        actor_agent_id = actor.get("agent_id")
        if (
            finding_agent_id is None
            or actor_agent_id == finding_agent_id
        ):
            related_events.append(ev)
            if ev.get("event_type") == "agent.created":
                agent_started_idx = j
                break

    related_events.reverse()  # restore chronological order

    # Compact event list — only the metadata the labeler / RLHF
    # pipeline actually grades.
    events_compact: list[dict[str, Any]] = []
    unique_endpoints: set[str] = set()
    unique_tools: set[str] = set()
    tool_calls_count = 0
    dismissed: list[dict[str, Any]] = []
    agent_category: str | None = None
    tool_name_first: str | None = None

    for ev in related_events:
        et = ev.get("event_type")
        actor = ev.get("actor") or {}
        ts = ev.get("timestamp")

        # Compact form: type + ts + (small subset of actor / payload).
        compact: dict[str, Any] = {"type": et, "timestamp": ts}
        if "tool_name" in actor:
            compact["tool_name"] = actor.get("tool_name")
            unique_tools.add(str(actor.get("tool_name")))
        if et == "tool.execution.started":
            tool_calls_count += 1
            if tool_name_first is None:
                tool_name_first = actor.get("tool_name")
            payload = ev.get("payload") or {}
            args = payload.get("args") or {}
            for key in ("url", "target_url", "endpoint", "target"):
                v = args.get(key) if isinstance(args, dict) else None
                if isinstance(v, str) and v.strip():
                    unique_endpoints.add(v)
                    break

        if et == "agent.created":
            payload = ev.get("payload") or {}
            agent_category = payload.get("category")

        if et == "finding.dismissed":
            payload = ev.get("payload") or {}
            dismissed.append({
                "surface": payload.get("surface"),
                "hypothesis": payload.get("hypothesis"),
                "dismissal_reason": payload.get("dismissal_reason"),
            })

        events_compact.append(compact)

    # Iterations & timing.
    iterations = sum(
        1 for ev in related_events
        if ev.get("event_type") == "tool.execution.started"
    )
    time_to_emit: float | None = None
    if related_events:
        time_to_emit = _seconds_between(
            related_events[0].get("timestamp"),
            related_events[-1].get("timestamp"),
        )

    return {
        "schema_version": TRAJECTORY_SCHEMA_VERSION,
        "finding_fingerprint": fingerprint,
        "finding_id": finding_id,
        "agent_id": finding_agent_id,
        "agent_category": agent_category,
        "tool_name": tool_name_first,
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "events": events_compact,
        "iterations_to_emit": iterations,
        "time_to_emit_seconds": time_to_emit,
        "tool_calls_in_trajectory": tool_calls_count,
        "dismissed_alternatives": dismissed,
        "exploration_breadth": {
            "unique_endpoints": len(unique_endpoints),
            "unique_tools": len(unique_tools),
        },
    }


def write_trajectory_jsonl(
    *,
    run_dir: Path,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build trajectories for every finding and write them to
    `<run_dir>/trajectory.jsonl`. Returns
    `{success, written, trajectory_path, errors?}`.

    Best-effort throughout — failures are recorded but don't raise.
    """
    out_path = run_dir / "trajectory.jsonl"
    events = _walk_events(run_dir / "events.jsonl")

    written = 0
    errors: list[str] = []
    try:
        with out_path.open("w", encoding="utf-8") as f:
            for finding in findings:
                try:
                    trajectory = _build_per_finding_trajectory(finding, events)
                    if trajectory is None:
                        continue
                    f.write(json.dumps(trajectory, ensure_ascii=False, default=str))
                    f.write("\n")
                    written += 1
                except Exception as e:  # noqa: BLE001
                    errors.append(
                        f"finding {finding.get('id') or '<unknown>'}: {e}"
                    )
    except OSError as e:
        return {
            "success": False,
            "error": f"write failed: {e}",
            "trajectory_path": str(out_path),
        }

    out: dict[str, Any] = {
        "success": True,
        "written": written,
        "trajectory_path": str(out_path),
    }
    if errors:
        out["errors"] = errors
    return out
