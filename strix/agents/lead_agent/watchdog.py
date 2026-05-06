"""Watchdog (roadmap §8.5 Phase 6 / single-agent.md §2.6).

Counts turns since the lead agent last made progress. Force-exits
the loop when too many idle turns pass — catches stuck-loop
pathologies (the agent thinks-without-acting, calls the same tool
repeatedly with the same args, etc.) without burning the entire
budget.

Progress definition:
  * `finding`        — `finding.created` event fired (eager-emit).
  * `endpoint`       — `target.completed` (or new endpoint added).
  * `phase`          — `phase.completed` event fired.
  * `update`         — `finding.updated` (#157) event fired (counts
                       as progress because the agent advanced a
                       prior finding's verification status).

Default `max_idle_turns=5`. When exceeded, the lead emits a
`run.terminated` event with `reason="watchdog_no_progress"` and
returns from the loop with whatever findings were collected.

Wrapper-side impact: `run.terminated.payload.reason` gains a new
value `watchdog_no_progress` (additive within the closed-enum per
engine-usage.md §6 — wrappers ignoring unknown reason values treat
it as informational).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Literal


ProgressKind = Literal["finding", "endpoint", "phase", "update"]


@dataclass
class WatchdogState:
    """Per-agent watchdog state. Thread-safe (`record_progress` and
    `tick` may be called from different threads under the §8.5
    Phase 3b parallel-tool-dispatch loop).

    Args:
        max_idle_turns: turns without progress before
            `should_force_exit()` returns True. Default 5 mirrors
            single-agent.md §2.6.
    """

    max_idle_turns: int = 5
    turns_since_progress: int = 0
    total_turns: int = 0
    progress_events: list[ProgressKind] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def tick(self) -> None:
        """Called once per turn at the top of the agent loop."""
        with self._lock:
            self.turns_since_progress += 1
            self.total_turns += 1

    def record_progress(self, kind: ProgressKind) -> None:
        """Reset the idle counter when the agent makes progress."""
        with self._lock:
            self.turns_since_progress = 0
            self.progress_events.append(kind)

    def should_force_exit(self) -> bool:
        """True when too many idle turns have passed. The lead loop
        polls this every turn after `tick()`."""
        with self._lock:
            return self.turns_since_progress >= self.max_idle_turns

    def reset(self) -> None:
        """Test-only — clear counters between scenarios."""
        with self._lock:
            self.turns_since_progress = 0
            self.total_turns = 0
            self.progress_events.clear()

    def snapshot(self) -> dict[str, int | list[str]]:
        """Read-only snapshot for telemetry / `check_budget`
        integration."""
        with self._lock:
            return {
                "max_idle_turns": self.max_idle_turns,
                "turns_since_progress": self.turns_since_progress,
                "total_turns": self.total_turns,
                "progress_event_count": len(self.progress_events),
                "progress_kinds": list(self.progress_events),
            }


def emit_watchdog_terminated(reason_detail: str | None = None) -> None:
    """Emit a `run.terminated` event with `reason="watchdog_no_progress"`.

    Best-effort: tracer-absent fallback is silent. The lead loop
    calls this once when `should_force_exit()` first returns True;
    re-calls are deduplicated by the existing `run.terminated`
    once-only latch in `strix/llm/run_budget.py`."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return
        tracer._emit_event(
            "run.terminated",
            payload={
                "reason": "watchdog_no_progress",
                "reason_detail": reason_detail,
            },
            status="terminated",
            source="strix.agents.lead_agent.watchdog",
        )
    except Exception:  # noqa: BLE001
        pass
