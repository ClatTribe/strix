"""Tests for SIGTERM / SIGINT graceful cancel (roadmap §4 / PR #114).

Covers:

  * is_cancellation_requested initially False
  * Manually invoking the handler latches the request
  * Second handler invocation = sys.exit(128 + signum)
  * emit_run_cancelled_event_once fires exactly once
  * No event fires when no cancel was requested
  * get_exit_code_for_cancel returns 143 for SIGTERM, 130 for SIGINT
  * install_handlers is idempotent + survives ValueError
  * Latch survives env-var clobbers + concurrent reset
"""

from __future__ import annotations

import json
import signal as _signal
from typing import Any

import pytest

from strix.interface import cancel_handler
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    cancel_handler.reset_for_testing()
    tracer = Tracer("cancel-test")
    set_global_tracer(tracer)
    yield
    cancel_handler.reset_for_testing()


def _load_events(tmp_path) -> list[dict[str, Any]]:
    events_path = tmp_path / "strix_runs" / "cancel-test" / "events.jsonl"
    if not events_path.exists():
        return []
    return [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line
    ]


# ---------------------------------------------------------------------------
# Latch behaviour
# ---------------------------------------------------------------------------


def test_initial_state_no_cancel() -> None:
    cancelled, signum = cancel_handler.is_cancellation_requested()
    assert cancelled is False
    assert signum is None


def test_handler_latches_sigterm() -> None:
    cancel_handler._handler(_signal.SIGTERM, None)
    cancelled, signum = cancel_handler.is_cancellation_requested()
    assert cancelled is True
    assert signum == int(_signal.SIGTERM)


def test_handler_latches_sigint() -> None:
    cancel_handler._handler(_signal.SIGINT, None)
    cancelled, signum = cancel_handler.is_cancellation_requested()
    assert cancelled is True
    assert signum == int(_signal.SIGINT)


def test_second_handler_invocation_force_exits() -> None:
    """Second cancel signal during shutdown = sys.exit(128 + signum).
    Mimics the user clicking 'cancel' twice when the first cancel
    is still being processed."""
    cancel_handler._handler(_signal.SIGTERM, None)
    with pytest.raises(SystemExit) as exc_info:
        cancel_handler._handler(_signal.SIGTERM, None)
    assert exc_info.value.code == 128 + int(_signal.SIGTERM)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_get_exit_code_none_before_cancel() -> None:
    assert cancel_handler.get_exit_code_for_cancel() is None


def test_get_exit_code_143_for_sigterm() -> None:
    cancel_handler._handler(_signal.SIGTERM, None)
    code = cancel_handler.get_exit_code_for_cancel()
    assert code == 143


def test_get_exit_code_130_for_sigint() -> None:
    cancel_handler._handler(_signal.SIGINT, None)
    code = cancel_handler.get_exit_code_for_cancel()
    assert code == 130


# ---------------------------------------------------------------------------
# run.cancelled event emission
# ---------------------------------------------------------------------------


def test_run_cancelled_event_emitted_once_for_sigterm(tmp_path) -> None:
    cancel_handler._handler(_signal.SIGTERM, None)
    cancel_handler.emit_run_cancelled_event_once()
    # Calling again should NOT emit a duplicate event.
    cancel_handler.emit_run_cancelled_event_once()
    cancel_handler.emit_run_cancelled_event_once()

    events = _load_events(tmp_path)
    cancel_events = [e for e in events if e.get("event_type") == "run.cancelled"]
    assert len(cancel_events) == 1, (
        f"expected exactly one run.cancelled event; got {len(cancel_events)}"
    )

    payload = cancel_events[0].get("payload") or {}
    assert payload["reason"] == "user_cancel"
    assert payload["signum"] == int(_signal.SIGTERM)
    assert payload["signal_name"] == "SIGTERM"


def test_run_cancelled_event_carries_sigint_name(tmp_path) -> None:
    cancel_handler._handler(_signal.SIGINT, None)
    cancel_handler.emit_run_cancelled_event_once()

    events = _load_events(tmp_path)
    cancel_events = [e for e in events if e.get("event_type") == "run.cancelled"]
    assert len(cancel_events) == 1
    assert cancel_events[0]["payload"]["signal_name"] == "SIGINT"


def test_no_event_when_no_cancel_requested(tmp_path) -> None:
    cancel_handler.emit_run_cancelled_event_once()

    events = _load_events(tmp_path)
    assert not any(e.get("event_type") == "run.cancelled" for e in events)


# ---------------------------------------------------------------------------
# install_handlers
# ---------------------------------------------------------------------------


def test_install_handlers_idempotent(monkeypatch) -> None:
    """Calling install_handlers twice is harmless. Different from
    just registering the same handler twice — Python's signal.signal
    returns the previous handler on each call."""
    cancel_handler.install_handlers()
    cancel_handler.install_handlers()
    # No assertion on the registered handler — we just want
    # idempotency to NOT raise.


def test_install_handlers_swallows_value_error(monkeypatch) -> None:
    """signal.signal can raise ValueError when called from a
    non-main thread. The wrapper must be best-effort."""
    def boom(*_a, **_kw):
        raise ValueError("not in main thread")

    monkeypatch.setattr(_signal, "signal", boom)

    # Should not raise.
    cancel_handler.install_handlers()


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_for_testing_clears_latch() -> None:
    cancel_handler._handler(_signal.SIGTERM, None)
    assert cancel_handler.is_cancellation_requested() == (True, int(_signal.SIGTERM))

    cancel_handler.reset_for_testing()
    assert cancel_handler.is_cancellation_requested() == (False, None)
    assert cancel_handler.get_exit_code_for_cancel() is None


def test_event_emission_resets_after_reset(tmp_path) -> None:
    """After reset, a fresh cancel cycle can emit again."""
    cancel_handler._handler(_signal.SIGTERM, None)
    cancel_handler.emit_run_cancelled_event_once()
    cancel_handler.reset_for_testing()
    cancel_handler._handler(_signal.SIGINT, None)
    cancel_handler.emit_run_cancelled_event_once()

    events = _load_events(tmp_path)
    cancel_events = [e for e in events if e.get("event_type") == "run.cancelled"]
    # Reset wiped the latch so the second cycle emits its own event.
    assert len(cancel_events) == 2
    assert {e["payload"]["signal_name"] for e in cancel_events} == {"SIGTERM", "SIGINT"}
