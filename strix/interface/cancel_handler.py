"""Clean SIGTERM / SIGINT cancellation contract (roadmap §4 / PR #114).

Wrapper "cancel scan" buttons need a signal they can trust. Today
`kill -TERM <pid>` may leave half-written `events.jsonl`, an
emitted-but-not-processed in-flight LLM response, and an orphaned
sandbox. This module makes the cancel deterministic.

Contract
--------

On `SIGTERM`:

    1. The signal handler latches `_CANCEL_LATCH["cancelled"] = True`
       and stores `signum`. The asyncio code is NOT interrupted by
       the handler itself — we set the flag and return.
    2. The agent loop polls `is_cancellation_requested()` every
       iteration (same pattern as the run-budget cap in #113) and
       calls `state.request_stop()` when set.
    3. As each agent's loop exits, the runner's `finally` blocks
       teardown sandboxes (existing cleanup path).
    4. Tracer flushes `events.jsonl` (existing on-write behaviour
       — every event is `f.write(...)+ flush()`, so partial writes
       aren't a concern; the bigger risk is missing the
       `run.cancelled` event entirely).
    5. `emit_run_cancelled_event_once` fires `run.cancelled` with
       `{signum, signal_name, reason}`.
    6. The runner reads the latch at scan-end and exits with
       `EXIT_SIGTERM (143)` instead of 0/2/3.

A second SIGTERM during shutdown is treated as "force-exit": the
handler sys.exit(128 + signum) immediately. This is the standard
Unix convention — the user clicked cancel twice, so we don't try
to be clever.

`SIGINT` (Ctrl+C) is handled the same way for symmetry; the
runner emits `EXIT_SIGINT (130)`. Python's default SIGINT handler
(`KeyboardInterrupt`) is preserved for compatibility — the latch
just adds the structured `run.cancelled` event so wrappers can
distinguish "cancelled cleanly" from "crashed".

Why module-level singleton
--------------------------

Signal handlers run in the main thread; the asyncio agent loop
runs on the event loop in (typically) the same thread but the
state must be visible across all agent instances. A process-wide
module attribute is the cheapest correct location.
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any


logger = logging.getLogger(__name__)


_LOCK = threading.Lock()
_CANCEL_LATCH: dict[str, Any] = {
    "cancelled": False,
    "signum": None,
    "event_emitted": False,
}


def is_cancellation_requested() -> tuple[bool, int | None]:
    """Return `(cancelled, signum)`. `signum` is None when no
    cancel has been requested yet."""
    with _LOCK:
        return _CANCEL_LATCH["cancelled"], _CANCEL_LATCH["signum"]


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except (ValueError, AttributeError):
        return f"SIG{signum}"


def _handler(signum: int, _frame: Any) -> None:
    """Signal handler for SIGTERM / SIGINT. Latches the request;
    a second signal = force-exit."""
    with _LOCK:
        already = _CANCEL_LATCH["cancelled"]
        if already:
            # Second cancel signal — operator has clicked twice.
            # Honor the request immediately rather than continuing
            # to wait on the in-flight LLM call.
            import sys

            sys.exit(128 + int(signum))
        _CANCEL_LATCH["cancelled"] = True
        _CANCEL_LATCH["signum"] = int(signum)
    logger.info(
        "cancellation requested via %s — agents will wind down", _signal_name(signum)
    )


def install_handlers() -> None:
    """Install handlers for SIGTERM and SIGINT. Idempotent —
    re-registering the same handler is harmless."""
    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError) as e:
        # signal.signal() can fail in non-main threads or on
        # exotic platforms. Best-effort.
        logger.debug("failed to install SIGTERM handler: %s", e)
    try:
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError) as e:
        logger.debug("failed to install SIGINT handler: %s", e)


def emit_run_cancelled_event_once() -> None:
    """Fire `run.cancelled` exactly once on the first cancel
    request. Called by the agent loop / runner shutdown path."""
    with _LOCK:
        if _CANCEL_LATCH["event_emitted"]:
            return
        if not _CANCEL_LATCH["cancelled"]:
            return
        signum = _CANCEL_LATCH["signum"] or 0
        _CANCEL_LATCH["event_emitted"] = True

    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return

    try:
        tracer._emit_event(  # noqa: SLF001
            "run.cancelled",
            payload={
                "signum": int(signum),
                "signal_name": _signal_name(signum),
                "reason": "user_cancel",
            },
            status="cancelled",
            source="strix.run",
        )
    except Exception:  # noqa: BLE001
        logger.debug("run.cancelled emission failed", exc_info=True)


def get_exit_code_for_cancel() -> int | None:
    """Return the documented POSIX exit code for the latched
    cancel signal, or None when no cancel was requested. The
    runner calls this at scan-end to choose exit 130 vs 143."""
    cancelled, signum = is_cancellation_requested()
    if not cancelled or signum is None:
        return None
    # POSIX convention: 128 + signal number.
    return 128 + int(signum)


def reset_for_testing() -> None:
    """Clear the latch. Tests call this in fixtures."""
    with _LOCK:
        _CANCEL_LATCH.update({
            "cancelled": False,
            "signum": None,
            "event_emitted": False,
        })
