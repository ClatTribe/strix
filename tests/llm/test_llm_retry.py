"""Tests for LLM retry on transient upstream failures (roadmap §4 / PR #112).

Hermetic — `_stream` is monkeypatched to raise / succeed in a
sequence the test controls. We verify:

  * Retry happens on retryable status codes (429 / 502 / 503 / 504).
  * Retry does NOT happen on 401 / 400 / etc.
  * Backoff schedule follows the documented 5s / 15s / 45s ladder
    (with jitter — we test bounds, not exact values).
  * `llm.retry_attempted` event is emitted per retry with the
    documented schema.
  * After max_retries exhausted, `LLMRequestFailedError` is raised
    (preserving today's outer-loop contract).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM, LLMRequestFailedError, LLMResponse
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
    tracer = Tracer("llm-retry-test")
    set_global_tracer(tracer)
    yield


def _load_events(events_path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line
    ]


class _UpstreamError(Exception):
    """Mimics litellm's upstream errors with a `status_code` attr."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


def _patch_sleep(monkeypatch) -> list[float]:
    """Patch asyncio.sleep to record sleep durations and not actually sleep."""
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(float(seconds))

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return sleeps


def _make_llm() -> LLM:
    return LLM(LLMConfig(model_name="openai/gpt-5"), agent_name="Test Agent")


# ---------------------------------------------------------------------------
# Retryable codes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status_code", [429, 502, 503, 504])
def test_retries_on_transient_upstream_codes(monkeypatch, status_code) -> None:
    """5xx / 429 → retry. 1 failure + 1 success = 1 retry attempt."""
    sleeps = _patch_sleep(monkeypatch)
    llm = _make_llm()

    call_count = {"n": 0}

    async def fake_stream(self, messages):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise _UpstreamError("upstream blip", status_code=status_code)
        # Async generator must yield to be awaitable as `async for`.
        yield LLMResponse(content="ok")

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        out: list[LLMResponse] = []
        async for r in llm.generate([]):
            out.append(r)
        return out

    out = asyncio.run(consume())

    assert call_count["n"] == 2, f"expected 1 retry on {status_code}; got {call_count['n']} calls"
    assert len(sleeps) == 1, "expected exactly one sleep before the retry"
    assert out[-1].content == "ok"


def test_no_retry_on_non_retryable_400(monkeypatch) -> None:
    """4xx that's not 429 → fail-fast, no retry."""
    sleeps = _patch_sleep(monkeypatch)
    llm = _make_llm()

    async def fake_stream(self, messages):
        raise _UpstreamError("bad request", status_code=400)
        yield  # pragma: no cover — unreachable, makes this an async generator

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    with pytest.raises(LLMRequestFailedError):
        asyncio.run(consume())

    assert sleeps == [], "expected no sleeps on non-retryable error"


def test_no_retry_on_401_auth_error(monkeypatch) -> None:
    sleeps = _patch_sleep(monkeypatch)
    llm = _make_llm()

    async def fake_stream(self, messages):
        raise _UpstreamError("auth failed", status_code=401)
        yield  # pragma: no cover

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    with pytest.raises(LLMRequestFailedError):
        asyncio.run(consume())

    assert sleeps == []


# ---------------------------------------------------------------------------
# Backoff schedule (5s / 15s / 45s ± jitter)
# ---------------------------------------------------------------------------


def test_backoff_schedule_follows_5_15_45(monkeypatch) -> None:
    """Three failed attempts → sleeps approximately [5, 15, 45]
    with ±20% jitter. Test bounds, not exact values, since the
    jitter is intentional (avoids retry-thundering-herd)."""
    sleeps = _patch_sleep(monkeypatch)
    llm = _make_llm()

    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "3")

    async def fake_stream(self, messages):
        raise _UpstreamError("upstream out", status_code=503)
        yield  # pragma: no cover

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    with pytest.raises(LLMRequestFailedError):
        asyncio.run(consume())

    # max_retries=3 means: attempts 0, 1, 2 each fail and sleep,
    # attempt 3 fails and we give up (no sleep).
    assert len(sleeps) == 3, f"expected 3 sleeps; got {sleeps}"

    # Each sleep should be within ±20% of the base schedule.
    expected_base = [5.0, 15.0, 45.0]
    for actual, base in zip(sleeps, expected_base, strict=True):
        # ±20% jitter range [0.8x, 1.2x]; clamped at floor=1.
        lo = max(1.0, base * 0.8)
        hi = base * 1.2
        assert lo <= actual <= hi, (
            f"sleep {actual:.2f}s out of bounds [{lo:.2f}, {hi:.2f}] for base {base}"
        )


def test_backoff_capped_at_90_seconds(monkeypatch) -> None:
    """5 * 3**4 = 405s — must clamp to 90s (then ± jitter)."""
    sleeps = _patch_sleep(monkeypatch)
    llm = _make_llm()

    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "5")

    async def fake_stream(self, messages):
        raise _UpstreamError("upstream out", status_code=503)
        yield  # pragma: no cover

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    with pytest.raises(LLMRequestFailedError):
        asyncio.run(consume())

    # The 4th + 5th attempts (5 * 3**3 = 135 and 5 * 3**4 = 405)
    # both exceed the 90s cap, so they should be clamped.
    assert sleeps[-1] <= 90 * 1.2, (
        f"final sleep {sleeps[-1]:.2f}s exceeds the 90s cap (with jitter ceiling)"
    )
    assert sleeps[-2] <= 90 * 1.2


# ---------------------------------------------------------------------------
# llm.retry_attempted event emission
# ---------------------------------------------------------------------------


def test_retry_attempted_event_emitted_per_retry(monkeypatch, tmp_path) -> None:
    _patch_sleep(monkeypatch)
    llm = _make_llm()
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "2")

    call_count = {"n": 0}

    async def fake_stream(self, messages):
        call_count["n"] += 1
        if call_count["n"] <= 2:
            raise _UpstreamError("upstream blip", status_code=503)
        yield LLMResponse(content="ok")

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    asyncio.run(consume())

    events_path = tmp_path / "strix_runs" / "llm-retry-test" / "events.jsonl"
    events = _load_events(events_path)
    retry_events = [e for e in events if e.get("event_type") == "llm.retry_attempted"]
    # 2 failures = 2 retry events emitted (one per retry).
    assert len(retry_events) == 2, f"expected 2 retry events; got {len(retry_events)}"

    # Schema sanity on the first event.
    payload = retry_events[0].get("payload") or {}
    assert payload.get("attempt") == 1
    assert payload.get("max_retries") == 2
    assert payload.get("status_code") == 503
    assert payload.get("error_type") == "_UpstreamError"
    assert "wait_seconds" in payload
    assert payload["wait_seconds"] > 0


def test_retry_event_carries_agent_and_model(monkeypatch, tmp_path) -> None:
    _patch_sleep(monkeypatch)
    llm = _make_llm()
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "1")

    call_count = {"n": 0}

    async def fake_stream(self, messages):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise _UpstreamError("blip", status_code=503)
        yield LLMResponse(content="ok")

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    asyncio.run(consume())

    events_path = tmp_path / "strix_runs" / "llm-retry-test" / "events.jsonl"
    events = _load_events(events_path)
    retry = next(e for e in events if e.get("event_type") == "llm.retry_attempted")
    actor = retry.get("actor") or {}
    assert actor.get("agent_name") == "Test Agent"
    assert actor.get("model") == "openai/gpt-5"


def test_no_retry_event_when_call_succeeds_first_try(monkeypatch, tmp_path) -> None:
    _patch_sleep(monkeypatch)
    llm = _make_llm()

    async def fake_stream(self, messages):
        yield LLMResponse(content="ok")

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    asyncio.run(consume())

    events_path = tmp_path / "strix_runs" / "llm-retry-test" / "events.jsonl"
    if not events_path.exists():
        return  # no events file = no retry events. Vacuously OK.
    events = _load_events(events_path)
    assert not any(e.get("event_type") == "llm.retry_attempted" for e in events), (
        "should not emit llm.retry_attempted when the first call succeeds"
    )


# ---------------------------------------------------------------------------
# Tracer-absent resilience
# ---------------------------------------------------------------------------


def test_retry_event_emit_failure_does_not_break_retry_loop(monkeypatch) -> None:
    """If the tracer raises during emission, the retry loop must
    still complete the retry. We test by patching `get_global_tracer`
    to return an object whose `_emit_event` raises."""
    _patch_sleep(monkeypatch)
    llm = _make_llm()
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "1")

    class BrokenTracer:
        def _emit_event(self, *_a, **_kw):
            raise RuntimeError("tracer broken")

    monkeypatch.setattr(
        tracer_module, "get_global_tracer", lambda: BrokenTracer()
    )

    call_count = {"n": 0}

    async def fake_stream(self, messages):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise _UpstreamError("blip", status_code=503)
        yield LLMResponse(content="ok")

    monkeypatch.setattr(LLM, "_stream", fake_stream)

    async def consume():
        async for _ in llm.generate([]):
            pass

    # Should NOT raise — even though the tracer's emit fails.
    asyncio.run(consume())
    assert call_count["n"] == 2, "retry should have completed despite tracer failure"
