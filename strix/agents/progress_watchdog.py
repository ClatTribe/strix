"""Progress watchdog — the 5th termination criterion (PR-γ).

Closes the architectural gap diagnosed in the OODA-loop analysis:
strix has four termination mechanisms today (hard caps, iteration
cap, workflow phase gate, explicit finish_scan), but none of them
fire on "lead is making no progress."

A senior pentester knows when to stop looking — when nothing new
is appearing per unit of effort. Strix didn't have that signal.
PR-γ adds it as a process-global watchdog that:

  1. Listens for progress events (any of: finding.created,
     endpoint.probed, endpoint.discovered, hypothesis.resolved,
     phase.transitioned)
  2. Tracks time-since-last-progress (monotonic)
  3. Returns escalating warning messages when stalled
  4. After N warnings without progress, recommends hard
     termination (advance to report + finish_scan)

The watchdog SIGNALS — it doesn't unilaterally terminate. The
agent loop reads the watchdog and either:
  (a) injects a warning message into the next turn's context so
      the lead's LLM observes + reorients, OR
  (b) at the escalation tier, force-advances to report phase
      and triggers a stop request.

This matches the Phase 3d philosophy: put structure in the system
(state machine, OODA-shaped responses, progress watchdog), not in
the model's prompt. Smaller models become viable when stagnation
is detected mechanically rather than requiring the model to
self-recognize "I'm stuck."

## Tunables (CLI flags + env vars)

  --max-stall-minutes <int>     | STRIX_MAX_STALL_MINUTES
    Minutes of no-progress before the first warning fires.
    Default: 5 (matches the "no progress in last 5 min" pattern
    in the legacy run-stall metric).

  --watchdog-escalate-after <N> | STRIX_WATCHDOG_ESCALATE_AFTER
    How many consecutive warnings (each separated by another
    stall-minutes window) before escalating from "soft nudge" to
    "force-advance to report." Default: 3.

  STRIX_PROGRESS_WATCHDOG_DISABLED=1
    Kill switch — watchdog records progress events but never
    emits warnings. Use for A/B benchmarking.

## Cost shape

Negligible — the watchdog is a few timestamps + a counter. The
warning messages are added to the agent's conversation history
(at most one per turn), so the marginal cost is the LLM's
attention to a ~200-char system note. No new LLM calls.

The VALUE: a stalled scan that would otherwise burn through the
full --max-cost / --max-duration cap terminates at the first
stall-window. Empirical: the Phase 3d 36-retry finish_scan loop
(stalled at 2 findings for ~7 minutes) would have terminated
via the watchdog at the 5-min mark, capping cost ~30% earlier.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


# Progress-signal kinds. The agent loop subscribes to these via
# `record_progress(kind=..., detail=...)`. Any of them resets the
# stall clock.
PROGRESS_KINDS: frozenset[str] = frozenset({
    "finding.created",         # new vulnerability emitted
    "endpoint.probed",          # workflow recorded a probe
    "endpoint.discovered",      # recon found a new endpoint
    "hypothesis.confirmed",     # hypothesis → finding
    "hypothesis.dismissed",     # explicit "not exploitable" decision
    "phase.transitioned",       # workflow advanced
    "auth.captured",            # session captured via scan_auth_flow
})


def _monotonic_now() -> float:
    """Indirection through the time module so test fixtures can
    monkey-patch `time.monotonic` and have the patched value flow
    into `WatchdogState.__init__` defaults. Capturing
    `default_factory=time.monotonic` directly binds the original
    builtin reference and bypasses patches — that's a real bug
    that surfaced once the snapshot deadlock was fixed."""
    return time.monotonic()


@dataclass
class WatchdogState:
    """Process-singleton tracking progress across the run."""
    created_at: float = field(default_factory=_monotonic_now)
    last_progress_at: float = field(default_factory=_monotonic_now)
    last_progress_kind: str = ""
    last_progress_detail: str = ""

    # Counters
    total_progress_events: int = 0
    events_by_kind: dict[str, int] = field(default_factory=dict)

    # Warning ladder — counts how many stall windows have elapsed
    # without progress. Reset to 0 on any progress event.
    warning_count: int = 0
    last_warning_emitted_at: float | None = None


_STATE: WatchdogState | None = None
# Re-entrant — `snapshot()` acquires the lock and then calls
# `is_stalled()` / `should_escalate()`, each of which acquire the
# lock for their internal read. Using a plain Lock here would
# deadlock the snapshot path. The non-reentrant choice is preserved
# in spirit by NOT releasing-and-reacquiring (RLock just allows the
# same thread to re-enter); cross-thread contention behaviour is
# unchanged.
_LOCK = threading.RLock()


def _get_or_create() -> WatchdogState:
    global _STATE
    if _STATE is None:
        _STATE = WatchdogState()
    return _STATE


def reset_for_testing() -> None:
    """Tests call this in fixtures."""
    global _STATE
    with _LOCK:
        _STATE = None


def init_for_testing() -> None:
    """Force-materialize `_STATE` at the current (possibly mocked)
    time. Tests that drive the warning ladder without first
    calling `record_progress` use this so `last_progress_at` is
    seeded to the fixture's clock=0 rather than to the lazy init
    at first `get_warning_message`."""
    global _STATE
    with _LOCK:
        _STATE = WatchdogState()


# ---------------------------------------------------------------------------
# Tunables (env vars)
# ---------------------------------------------------------------------------


def _read_env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        v = int(float(raw))
    except (ValueError, TypeError):
        return default
    return max(1, v)


def get_stall_minutes() -> int:
    """Minutes of no-progress before the first warning."""
    return _read_env_int("STRIX_MAX_STALL_MINUTES", 5)


def get_escalation_threshold() -> int:
    """How many consecutive warnings before hard escalation."""
    return _read_env_int("STRIX_WATCHDOG_ESCALATE_AFTER", 3)


def is_disabled() -> bool:
    """Kill switch."""
    return os.environ.get(
        "STRIX_PROGRESS_WATCHDOG_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Progress recording
# ---------------------------------------------------------------------------


def record_progress(kind: str, detail: str = "") -> None:
    """Any tool that produces a progress signal calls this.

    Kinds: see PROGRESS_KINDS. Unknown kinds are accepted (they
    still reset the stall clock) but only PROGRESS_KINDS are
    counted in `events_by_kind`.

    Idempotent + cheap — just timestamps + a counter increment.
    Safe to call from any thread (acquires the module lock).
    """
    if not isinstance(kind, str) or not kind:
        return
    with _LOCK:
        s = _get_or_create()
        s.last_progress_at = time.monotonic()
        s.last_progress_kind = kind
        s.last_progress_detail = detail or ""
        s.total_progress_events += 1
        if kind in PROGRESS_KINDS:
            s.events_by_kind[kind] = s.events_by_kind.get(kind, 0) + 1
        # Reset the warning ladder — progress means the lead is
        # not stalled anymore.
        s.warning_count = 0
        s.last_warning_emitted_at = None


# ---------------------------------------------------------------------------
# Watchdog queries
# ---------------------------------------------------------------------------


def minutes_since_progress() -> float:
    """How long since the last progress signal (or watchdog
    creation, whichever is more recent). 0 when the watchdog
    hasn't been initialised yet."""
    if _STATE is None:
        return 0.0
    with _LOCK:
        return (time.monotonic() - _STATE.last_progress_at) / 60.0


def is_stalled() -> bool:
    """True when no-progress time exceeds `STRIX_MAX_STALL_MINUTES`.
    Always False when the watchdog is disabled."""
    if is_disabled():
        return False
    return minutes_since_progress() >= float(get_stall_minutes())


def should_escalate() -> bool:
    """True when the warning ladder has reached the escalation
    threshold. At this point the agent loop should HARD-terminate:
    force-advance to report phase + request stop.

    `record_progress()` resets the ladder, so a productive lead
    never sees escalation."""
    if is_disabled():
        return False
    if _STATE is None:
        return False
    with _LOCK:
        return _STATE.warning_count >= get_escalation_threshold()


# ---------------------------------------------------------------------------
# Warning-message ladder
# ---------------------------------------------------------------------------


def get_warning_message() -> str | None:
    """Returns the warning message to inject into the lead's
    next-turn context, or None if no warning is due right now.

    Call this once per agent-loop iteration. Side effect: when
    a warning is due, the watchdog's internal counter increments.
    The agent loop is responsible for surfacing the message to
    the LLM (e.g. via `state.add_message("user", warning)`).

    Three tiers:

      * tier 1 (first stall window):
          "PROGRESS_WATCHDOG_STALL: No new findings / endpoints
          probed / hypotheses resolved in N minutes. Change
          tactics..."

      * tier 2 (subsequent stall windows, count < escalation):
          "PROGRESS_WATCHDOG_REPEATED_STALL: Still no progress
          after N warnings..."

      * tier 3 (count >= escalation_threshold):
          "PROGRESS_WATCHDOG_ESCALATION: Auto-advancing to
          report phase. Call finish_scan now."
    """
    if is_disabled():
        return None
    # Lazy-init the watchdog state on first warning check. Without
    # this, a scan that NEVER hits a progress signal (e.g. agent
    # spends all its time in recon without emitting findings) would
    # never trigger the stall escalation — `_STATE is None` would
    # short-circuit the check forever.
    with _LOCK:
        _get_or_create()
    if not is_stalled():
        return None

    with _LOCK:
        s = _get_or_create()
        # Throttle: only emit a new warning if we haven't emitted
        # within the last stall-window. Without this, every loop
        # iteration after the threshold would emit a warning,
        # blowing up the context.
        now = time.monotonic()
        stall_seconds = get_stall_minutes() * 60.0
        if (s.last_warning_emitted_at is not None
                and (now - s.last_warning_emitted_at) < stall_seconds):
            return None

        s.warning_count += 1
        s.last_warning_emitted_at = now
        elapsed = (now - s.last_progress_at) / 60.0
        count = s.warning_count
        escalate_at = get_escalation_threshold()

    if count >= escalate_at:
        return (
            f"PROGRESS_WATCHDOG_ESCALATION (warning {count}/{escalate_at}): "
            f"No progress signal in {elapsed:.1f} minutes after "
            f"{count} consecutive stall warnings. Auto-advancing to "
            f"'report' phase + recommending immediate finish_scan. "
            f"You've exhausted productive exploration of this target — "
            f"emit your final findings and finish_scan with the "
            f"summary."
        )
    if count > 1:
        return (
            f"PROGRESS_WATCHDOG_REPEATED_STALL (warning {count}/{escalate_at}): "
            f"Still no progress after {elapsed:.1f} minutes. "
            f"Change tactics IMMEDIATELY — either probe a "
            f"different endpoint kind, dispatch a specialist you "
            f"haven't used, OR explicitly advance toward 'report' "
            f"with finish_scan. After {escalate_at - count} more "
            f"warnings the watchdog will force-advance you."
        )
    return (
        f"PROGRESS_WATCHDOG_STALL: No new findings / endpoints "
        f"probed / hypotheses resolved in {elapsed:.1f} minutes. "
        f"Change tactics — try a different endpoint kind via "
        f"probe_endpoint(kind=...), dispatch a specialist you "
        f"haven't used, dismiss any stuck hypotheses, OR advance "
        f"the workflow toward 'report' if you've completed the "
        f"probing you intended."
    )


# ---------------------------------------------------------------------------
# Snapshot for telemetry
# ---------------------------------------------------------------------------


def snapshot() -> dict:
    """Return a structured snapshot of watchdog state. Useful
    for run_meta.json + benchmark tooling to characterize the
    scan's progress shape."""
    if _STATE is None:
        return {
            "initialized": False,
            "stall_minutes_threshold": get_stall_minutes(),
            "escalation_threshold": get_escalation_threshold(),
            "disabled": is_disabled(),
        }
    with _LOCK:
        s = _get_or_create()
        return {
            "initialized": True,
            "elapsed_s": round(time.monotonic() - s.created_at, 2),
            "last_progress_kind": s.last_progress_kind,
            "last_progress_detail": s.last_progress_detail,
            "minutes_since_progress": round(
                (time.monotonic() - s.last_progress_at) / 60.0, 2,
            ),
            "total_progress_events": s.total_progress_events,
            "events_by_kind": dict(s.events_by_kind),
            "warning_count": s.warning_count,
            "stall_minutes_threshold": get_stall_minutes(),
            "escalation_threshold": get_escalation_threshold(),
            "is_stalled": is_stalled(),
            "should_escalate": should_escalate(),
            "disabled": is_disabled(),
        }
