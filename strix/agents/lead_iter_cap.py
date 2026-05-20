"""Scan-mode-aware lead iteration cap — V3-1 of the quick-mode
lightweight plan (docs/proposals/2026-05-19-quick-mode-lightweight.md).

## Why this exists

After the v2 cost-optimization arc (PRs #334-#344), `quick` mode
caps `dispatch_specialist` at 0 — but the *lead* is still a full
LLM agent making 22-64 calls per scan. The v2 steps captured what
the lead can dispatch; they did not cap how many lead-loop
iterations fire.

This module derives a per-scan-mode iteration cap for the lead
agent's main loop and applies it via the existing
`state.max_iterations` mechanism that BaseAgent already enforces
(graceful warnings at "approaching" + a final warning at
`max_iterations - 3`).

## Caps

| mode      | cap | reasoning |
|-----------|----:|-----------|
| `initial` |   6 | "newly-discovered asset" fast pass — boot + recon + finish |
| `quick`   |  12 | boot + 1-2 recon + 3-4 probe + 2-3 emission + 1 report |
| `standard`|  60 | matches current standard-mode usage; no behavior change |
| `deep`    | None (unbounded — current behavior) |

For unknown / unset `scan_mode`, return None so we never silently
throttle a run that didn't opt in.

## Recall safety

* The cap is a **ceiling on iterations** — when reached, the
  existing BaseAgent loop sends "approaching limit" warnings
  starting at `is_approaching_max_iterations()` and a hard
  critical at `max_iterations - 3`. The lead can still call
  `finish_scan` gracefully; it doesn't crash mid-iteration.
* When the configured `max_iterations` is **already lower**
  than the mode cap (e.g. a wrapper passed `max_iterations=5`),
  the lower value wins — we never *raise* a cap, only lower it.
* The kill switch `STRIX_LEAD_ITER_CAP_DISABLED=1` bypasses the
  cap entirely and the configured value is used as-is.

## Override

`STRIX_LEAD_ITER_OVERRIDE=<int>` replaces the mode-derived cap
for runs where an operator explicitly wants more (or fewer)
iterations than the mode default. Useful for benchmarking +
debugging.
"""

from __future__ import annotations

import logging
import os
from typing import Any


logger = logging.getLogger(__name__)


# Per-mode lead iteration cap. None = unbounded (deep-mode behavior).
#
# 2026-05-20 — caps tightened after the OSS-first anchor pre-pass
# landed (docs/proposals/2026-05-20-quick-mode-oss-first-architecture.md).
# The prepass runs the L1 deterministic anchors BEFORE the lead loop;
# the lead's role collapses to L2 ranking / dedup / FP demote / novel-
# vuln tagging. That fits in far fewer iterations than the previous
# LLM-drives-tool-selection design assumed.
#
# Iteration roles by mode (post-prepass):
#   * quick:    1 boot + 2-3 rank/dedup/FP + 1 report                = 4
#   * standard: 1 boot + 4-6 reasoning + 2-3 chain hypothesis + 1    = ~10-15
#               (down from 60 — specialist dispatch is the work, not
#                lead iterations)
#   * deep:     unbounded — depth + chain enumeration + PoC synthesis
#
# Kill switch: STRIX_LEAD_ITER_CAP_DISABLED=1
_SCAN_MODE_LEAD_ITER_CAP: dict[str, int | None] = {
    "initial": 6,
    "quick": 4,
    "standard": 15,
    "deep": None,
}


def is_disabled() -> bool:
    """Returns True when `STRIX_LEAD_ITER_CAP_DISABLED` is truthy.
    Default is enabled."""
    return os.environ.get(
        "STRIX_LEAD_ITER_CAP_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def get_scan_mode_lead_iter_cap() -> int | None:
    """Return the lead iteration cap derived from the active
    scan mode + override env. None means unbounded.

    Resolution order:
      1. `STRIX_LEAD_ITER_OVERRIDE=<int>` if set + parseable
      2. `STRIX_SCAN_MODE` mapped through `_SCAN_MODE_LEAD_ITER_CAP`
      3. None (unbounded) for unknown / unset mode
    """
    override = (os.environ.get("STRIX_LEAD_ITER_OVERRIDE") or "").strip()
    if override:
        try:
            v = int(float(override))
            return max(1, v)
        except (ValueError, TypeError):
            pass
    mode = (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower()
    if mode in _SCAN_MODE_LEAD_ITER_CAP:
        return _SCAN_MODE_LEAD_ITER_CAP[mode]
    # Unknown / unset mode — unbounded so we never silently
    # throttle a run that didn't opt in.
    return None


def get_effective_max_iterations(configured_max: int) -> int:
    """Resolve the effective `state.max_iterations` for the lead
    agent given the run's configured max + the scan-mode cap.

    Recall-safety rule: the cap is a *ceiling*, not a floor.
      * If kill switch → return `configured_max` verbatim.
      * If mode cap is None (deep / unset) → return `configured_max`.
      * If `configured_max` is already lower than the mode cap →
        return `configured_max` (we never RAISE the cap).
      * Otherwise → return the mode cap.

    Args:
      configured_max: the max_iterations the caller (cli.py /
        tui.py / wrapper) wanted. Default is 300.

    Returns:
      The smaller of `configured_max` and the mode cap.
    """
    if is_disabled():
        return configured_max
    cap = get_scan_mode_lead_iter_cap()
    if cap is None:
        return configured_max
    return min(configured_max, cap)


def emit_cap_applied_event(
    *, configured_max: int, effective_max: int, mode: str | None = None,
) -> None:
    """Best-effort telemetry — surface when the lead-iter cap
    actually clipped the configured value. Operators can see this
    in events.jsonl to verify the cap fired."""
    if effective_max >= configured_max:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return
        evt: dict[str, Any] = {
            "event": "lead_iter_cap.applied",
            "configured_max": configured_max,
            "effective_max": effective_max,
            "mode": mode or (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower() or "unset",
            "override_set": bool((os.environ.get("STRIX_LEAD_ITER_OVERRIDE") or "").strip()),
        }
        if hasattr(tracer, "emit_event"):
            tracer.emit_event(**evt)
        elif hasattr(tracer, "add_event"):
            tracer.add_event(evt)
    except Exception as e:  # noqa: BLE001
        logger.debug("lead_iter_cap telemetry suppressed: %s", e)
