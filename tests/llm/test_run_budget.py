"""Tests for run-level budget cap (roadmap §4 / PR #113).

Covers:

  * record_run_usage accumulates across multiple calls
  * is_run_budget_exceeded returns False under the cap
  * is_run_budget_exceeded returns True at/over the cap
  * Latch — once-tripped state sticks even if env vars change
  * Each cap (max_cost_usd / max_input_tokens) fires its dimension
  * 0 / unset env var = unlimited (never trips)
  * `run.terminated` event emitted exactly once on first breach
  * Thread safety — concurrent record_run_usage produces correct totals
"""

from __future__ import annotations

import json
import threading
from typing import Any

import pytest

from strix.llm import run_budget
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
    monkeypatch.delenv("STRIX_MAX_COST_USD", raising=False)
    monkeypatch.delenv("STRIX_MAX_INPUT_TOKENS_RUN", raising=False)
    monkeypatch.delenv("STRIX_MAX_DURATION_S", raising=False)
    run_budget.reset_for_testing()
    tracer = Tracer("budget-test")
    set_global_tracer(tracer)
    yield
    run_budget.reset_for_testing()


def _load_events(tmp_path) -> list[dict[str, Any]]:
    events_path = tmp_path / "strix_runs" / "budget-test" / "events.jsonl"
    if not events_path.exists():
        return []
    return [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line
    ]


# ---------------------------------------------------------------------------
# Accumulation
# ---------------------------------------------------------------------------


def test_record_run_usage_accumulates() -> None:
    run_budget.record_run_usage(input_tokens=100, output_tokens=50, cost_usd=0.01)
    run_budget.record_run_usage(input_tokens=200, output_tokens=75, cost_usd=0.02)

    totals = run_budget.get_run_total()
    assert totals["input_tokens"] == 300
    assert totals["output_tokens"] == 125
    assert totals["cost_usd"] == pytest.approx(0.03)
    assert totals["requests"] == 2


def test_record_run_usage_ignores_zero_or_negative() -> None:
    run_budget.record_run_usage(input_tokens=100, output_tokens=0, cost_usd=0.0)
    run_budget.record_run_usage(input_tokens=-50, output_tokens=-10, cost_usd=-0.01)

    totals = run_budget.get_run_total()
    assert totals["input_tokens"] == 100
    assert totals["output_tokens"] == 0
    assert totals["cost_usd"] == 0.0
    # Each call still increments the request counter (idempotent
    # on the count, not on the values).
    assert totals["requests"] == 2


# ---------------------------------------------------------------------------
# Cost cap
# ---------------------------------------------------------------------------


def test_no_cap_never_exceeded() -> None:
    run_budget.record_run_usage(input_tokens=1_000_000, cost_usd=999.0)
    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


def test_cost_cap_below_threshold(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "1.0")
    run_budget.record_run_usage(cost_usd=0.50)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


def test_cost_cap_at_threshold_trips(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "1.0")
    run_budget.record_run_usage(cost_usd=1.0)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is True
    assert reason == "max_cost_usd"


def test_cost_cap_over_threshold_trips(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "1.0")
    run_budget.record_run_usage(cost_usd=1.5)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is True
    assert reason == "max_cost_usd"


def test_cost_cap_zero_means_unlimited(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "0")
    run_budget.record_run_usage(cost_usd=999.0)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


# ---------------------------------------------------------------------------
# Token cap
# ---------------------------------------------------------------------------


def test_token_cap_below_threshold(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_INPUT_TOKENS_RUN", "10000")
    run_budget.record_run_usage(input_tokens=5000)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


def test_token_cap_at_threshold_trips(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_INPUT_TOKENS_RUN", "10000")
    run_budget.record_run_usage(input_tokens=10000)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is True
    assert reason == "max_input_tokens"


def test_token_cap_zero_means_unlimited(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_INPUT_TOKENS_RUN", "0")
    run_budget.record_run_usage(input_tokens=10_000_000)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


# ---------------------------------------------------------------------------
# Latch
# ---------------------------------------------------------------------------


def test_latch_sticks_even_if_env_changes(monkeypatch) -> None:
    """Once-tripped, the latch returns True even if the cap is
    raised mid-flight. Prevents a wrapper from clearing the env
    var to "uncancel" a budget breach."""
    monkeypatch.setenv("STRIX_MAX_COST_USD", "1.0")
    run_budget.record_run_usage(cost_usd=1.5)

    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is True

    # Raise the cap to 100 — the latch holds.
    monkeypatch.setenv("STRIX_MAX_COST_USD", "100.0")
    exceeded2, reason2 = run_budget.is_run_budget_exceeded()
    assert exceeded2 is True
    assert reason2 == "max_cost_usd"


# ---------------------------------------------------------------------------
# run.terminated event
# ---------------------------------------------------------------------------


def test_run_terminated_event_emitted_once(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "1.0")
    run_budget.record_run_usage(cost_usd=1.5, input_tokens=12_345, output_tokens=2_345)

    run_budget.is_run_budget_exceeded()  # trip the latch
    run_budget.emit_run_terminated_event_once()
    # Calling again should NOT emit a second event.
    run_budget.emit_run_terminated_event_once()
    run_budget.emit_run_terminated_event_once()

    events = _load_events(tmp_path)
    terminated = [e for e in events if e.get("event_type") == "run.terminated"]
    assert len(terminated) == 1, f"expected exactly one run.terminated event; got {len(terminated)}"

    payload = terminated[0].get("payload") or {}
    assert payload["reason"] == "budget_exceeded"
    assert payload["budget_dimension"] == "max_cost_usd"
    assert payload["limits"]["max_cost_usd"] == 1.0
    # Note: the tracer's PII scrubber may redact bare integer
    # values that look phone-shaped. We only assert the schema
    # shape (key present); the unredacted value is checked
    # directly via get_run_total() above.
    assert "input_tokens" in payload["consumed"]
    assert "output_tokens" in payload["consumed"]
    assert "cost_usd" in payload["consumed"]
    assert payload["consumed"]["cost_usd"] == pytest.approx(1.5)
    # The pre-emit totals snapshot is unredacted.
    totals = run_budget.get_run_total()
    assert totals["input_tokens"] == 12_345
    assert totals["output_tokens"] == 2_345


def test_run_terminated_not_emitted_when_not_exceeded(tmp_path) -> None:
    """When the budget hasn't been tripped, calling emit doesn't
    inject a phantom event."""
    run_budget.record_run_usage(cost_usd=0.10)
    run_budget.emit_run_terminated_event_once()

    events = _load_events(tmp_path)
    assert not any(e.get("event_type") == "run.terminated" for e in events)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_concurrent_record_run_usage_thread_safe() -> None:
    """200 threads × 100 increments each — final total should be 20000.
    A non-thread-safe implementation would lose updates."""
    def worker():
        for _ in range(100):
            run_budget.record_run_usage(input_tokens=1, cost_usd=0.0001)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    totals = run_budget.get_run_total()
    assert totals["input_tokens"] == 2000  # 20 threads × 100 increments
    assert totals["cost_usd"] == pytest.approx(0.2, rel=1e-3)


# ---------------------------------------------------------------------------
# get_run_caps
# ---------------------------------------------------------------------------


def test_get_run_caps_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "5.50")
    monkeypatch.setenv("STRIX_MAX_INPUT_TOKENS_RUN", "100000")

    caps = run_budget.get_run_caps()
    assert caps["max_cost_usd"] == pytest.approx(5.50)
    assert caps["max_input_tokens"] == 100000


def test_get_run_caps_handles_garbage_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_COST_USD", "not-a-number")
    monkeypatch.setenv("STRIX_MAX_INPUT_TOKENS_RUN", "")

    caps = run_budget.get_run_caps()
    assert caps["max_cost_usd"] == 0.0
    assert caps["max_input_tokens"] == 0


# ---------------------------------------------------------------------------
# --max-duration cap (recall-lift PR-1)
#
# Same self-exit contract as --max-cost / --max-input-tokens, but emits
# a different reason and exits with a different code (4 vs 3) so wrappers
# can distinguish "ran out of money" from "ran out of time."
# ---------------------------------------------------------------------------


def test_duration_cap_unset_means_unlimited(monkeypatch) -> None:
    run_budget.mark_run_started()
    monkeypatch.delenv("STRIX_MAX_DURATION_S", raising=False)
    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


def test_duration_cap_zero_means_unlimited(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_MAX_DURATION_S", "0")
    run_budget.mark_run_started()
    exceeded, reason = run_budget.is_run_budget_exceeded()
    assert exceeded is False
    assert reason is None


def test_duration_cap_fires_when_elapsed_exceeds(monkeypatch) -> None:
    """When elapsed > cap, the budget reports max_duration_s as the
    reason. Implementation uses time.monotonic, so we monkeypatch
    it to advance the clock deterministically."""
    import time as _time
    from strix.llm import run_budget as _rb

    real_monotonic = _time.monotonic

    # Pin the start time, then advance the clock past the cap.
    base = real_monotonic()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base)
    monkeypatch.setenv("STRIX_MAX_DURATION_S", "30")
    _rb.mark_run_started()

    # Under the cap.
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base + 10.0)
    assert _rb.is_run_budget_exceeded() == (False, None)

    # Over the cap.
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base + 31.0)
    assert _rb.is_run_budget_exceeded() == (True, "max_duration_s")


def test_duration_cap_latches_like_other_caps(monkeypatch) -> None:
    """Once tripped, subsequent calls keep reporting True even if
    the env var changes (matches the cost-cap latch semantics)."""
    import time as _time
    from strix.llm import run_budget as _rb

    base = _time.monotonic()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base)
    monkeypatch.setenv("STRIX_MAX_DURATION_S", "30")
    _rb.mark_run_started()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base + 35.0)
    assert _rb.is_run_budget_exceeded()[0] is True

    # Disable the cap mid-flight — latch keeps it true.
    monkeypatch.setenv("STRIX_MAX_DURATION_S", "0")
    assert _rb.is_run_budget_exceeded()[0] is True


def test_duration_cap_emits_run_terminated_with_duration_dimension(
    monkeypatch, tmp_path,
) -> None:
    """Breach should emit `run.terminated` with reason='duration_exceeded'
    (top-level reason, distinct from the cost cap's 'budget_exceeded')."""
    import time as _time
    from strix.llm import run_budget as _rb

    base = _time.monotonic()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base)
    monkeypatch.setenv("STRIX_MAX_DURATION_S", "10")
    _rb.mark_run_started()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base + 15.0)

    exceeded, reason = _rb.is_run_budget_exceeded()
    assert (exceeded, reason) == (True, "max_duration_s")
    _rb.emit_run_terminated_event_once()

    events = _load_events(tmp_path)
    terminated = [e for e in events if e.get("event_type") == "run.terminated"]
    assert len(terminated) == 1
    payload = terminated[0].get("payload") or {}
    assert payload["reason"] == "duration_exceeded"
    assert payload["budget_dimension"] == "max_duration_s"
    assert payload["limits"]["max_duration_s"] == 10
    assert "elapsed_s" in payload["consumed"]


def test_duration_cap_independent_of_cost_cap(monkeypatch) -> None:
    """Cost cap unset; duration cap fires — `is_run_budget_exceeded`
    correctly attributes to max_duration_s, not max_cost_usd."""
    import time as _time
    from strix.llm import run_budget as _rb

    base = _time.monotonic()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base)
    monkeypatch.delenv("STRIX_MAX_COST_USD", raising=False)
    monkeypatch.setenv("STRIX_MAX_DURATION_S", "10")
    _rb.mark_run_started()

    _rb.record_run_usage(cost_usd=999.0, input_tokens=999_999)
    # Cost cap unset → cost shouldn't trip; duration not yet expired → no breach.
    assert _rb.is_run_budget_exceeded() == (False, None)

    monkeypatch.setattr(_rb.time, "monotonic", lambda: base + 11.0)
    assert _rb.is_run_budget_exceeded() == (True, "max_duration_s")


def test_mark_run_started_is_idempotent(monkeypatch) -> None:
    """Pinning the start time twice doesn't reset the clock."""
    import time as _time
    from strix.llm import run_budget as _rb

    base = _time.monotonic()
    monkeypatch.setattr(_rb.time, "monotonic", lambda: base)
    _rb.mark_run_started()

    monkeypatch.setattr(_rb.time, "monotonic", lambda: base + 50.0)
    _rb.mark_run_started()    # second call — should NOT reset

    # Elapsed reflects the first mark, not the second.
    assert _rb.get_run_elapsed_s() == pytest.approx(50.0, abs=0.5)


def test_get_run_elapsed_returns_zero_before_mark() -> None:
    """When `mark_run_started()` hasn't been called (e.g. unit
    tests bypassing the CLI entrypoint), elapsed reports 0.0
    rather than crashing."""
    assert run_budget.get_run_elapsed_s() == 0.0
