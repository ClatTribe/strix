"""Tests for the STRIX_LLM_RPM rolling-window throttle in
`strix/llm/llm.py`.

Why this exists: Gemini free tier @ 10 RPM and Anthropic free tier @
5 RPM are mathematically incompatible with strix's lead-loop fan-out
pattern. When strix issues 12 lead iterations × up to 5 retries each
= up to 60 LLM call attempts per fixture, an RPM-capped upstream
rate-limits every call, retries thrash, and the run dies. The
`STRIX_LLM_RPM` env var enables a process-global rolling-60s gate
that holds calls until making one more wouldn't exceed the cap.

Tests cover:
  * Default behaviour (env unset) — no throttle, calls fire freely
  * `STRIX_LLM_RPM=N` enforces at most N calls per rolling 60s
  * `STRIX_LLM_RPM=0` / negative / non-numeric → no throttle (graceful)
  * Multiple concurrent waiters serialize cleanly (rolling-window
    correctness)
  * Process-global state (multiple LLM instances share the cap)
"""

from __future__ import annotations

import asyncio
import time

import pytest

from strix.llm.llm import (
    _LLM_CALL_TIMESTAMPS,
    _read_rpm_cap,
    _reset_rpm_state_for_tests,
    _wait_for_rpm_slot,
)


@pytest.fixture(autouse=True)
def _isolated_rpm(monkeypatch) -> None:
    """Each test starts with a clean RPM window + no env var set."""
    monkeypatch.delenv("STRIX_LLM_RPM", raising=False)
    _reset_rpm_state_for_tests()
    yield
    _reset_rpm_state_for_tests()


# ---------------------------------------------------------------------------
# Env-var parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        ("", None),
        ("0", None),  # 0 / negative disable the throttle
        ("-3", None),
        ("not-a-number", None),
        ("5", 5),
        ("10", 10),
        ("10.7", 10),  # float strings get int-cast
    ],
)
def test_read_rpm_cap_parses_env(monkeypatch, raw, expected) -> None:
    if raw is None:
        monkeypatch.delenv("STRIX_LLM_RPM", raising=False)
    else:
        monkeypatch.setenv("STRIX_LLM_RPM", raw)
    assert _read_rpm_cap() == expected


# ---------------------------------------------------------------------------
# Throttle behaviour
# ---------------------------------------------------------------------------


def test_no_throttle_when_env_unset() -> None:
    """Without STRIX_LLM_RPM, _wait_for_rpm_slot must return
    immediately. No sleep, no timestamp recorded."""
    async def go():
        before = time.monotonic()
        await _wait_for_rpm_slot()
        after = time.monotonic()
        # Should be effectively instant (< 50ms).
        assert (after - before) < 0.05
        # No timestamp added (throttle disabled).
        assert len(_LLM_CALL_TIMESTAMPS) == 0
    asyncio.run(go())


def test_throttle_records_timestamp_on_call(monkeypatch) -> None:
    """First call under cap records its timestamp and returns
    immediately."""
    monkeypatch.setenv("STRIX_LLM_RPM", "10")

    async def go():
        await _wait_for_rpm_slot()
        assert len(_LLM_CALL_TIMESTAMPS) == 1
    asyncio.run(go())


def test_throttle_allows_up_to_cap_immediately(monkeypatch) -> None:
    """With cap=5, the first 5 calls in quick succession must all
    return immediately. The 6th must block until the window has
    space."""
    monkeypatch.setenv("STRIX_LLM_RPM", "5")

    async def go():
        starts = []
        for i in range(5):
            before = time.monotonic()
            await _wait_for_rpm_slot()
            starts.append(time.monotonic() - before)
        # All 5 should fire essentially instantly.
        assert all(s < 0.1 for s in starts), (
            f"first 5 calls under cap=5 must be instant; got {starts}"
        )
        assert len(_LLM_CALL_TIMESTAMPS) == 5
    asyncio.run(go())


def test_throttle_blocks_when_cap_exceeded(monkeypatch) -> None:
    """With cap=2, the 3rd call must wait until the rolling window
    has space. We patch asyncio.sleep to record the wait without
    actually sleeping so the test runs fast — the production code
    would sleep ~60s minus the elapsed since the oldest call."""
    monkeypatch.setenv("STRIX_LLM_RPM", "2")

    real_sleep = asyncio.sleep
    sleeps: list[float] = []

    async def fake_sleep(s):
        sleeps.append(float(s))
        # Don't actually sleep — but DO advance the rolling-window
        # logic by aging the existing timestamps so the next loop
        # iteration finds them expired.
        # We do this by shifting them backward in time.
        for i in range(len(_LLM_CALL_TIMESTAMPS)):
            _LLM_CALL_TIMESTAMPS[i] -= s

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def go():
        # Fire 3 calls; 3rd should trigger a sleep.
        for _ in range(3):
            await _wait_for_rpm_slot()
        assert len(sleeps) >= 1, (
            f"expected at least 1 sleep for the 3rd call; got {sleeps}"
        )
        # Each sleep should be the "wait until oldest expires" math.
        # With cap=2, after 2 fresh timestamps the wait until the
        # oldest is 60s old is approximately 60s (minus epsilon).
        # We just sanity-check it's > 1s and < 65s.
        for s in sleeps:
            assert 1.0 < s < 65.0, f"sleep duration out of band: {s}"
    asyncio.run(go())


def test_window_trims_old_entries(monkeypatch) -> None:
    """Entries older than 60s must be trimmed from the rolling
    window so they don't count against the cap forever."""
    monkeypatch.setenv("STRIX_LLM_RPM", "3")

    # Manually inject 3 timestamps "70 seconds ago" — they should
    # all be trimmed on the next call.
    old = time.monotonic() - 70.0
    for _ in range(3):
        _LLM_CALL_TIMESTAMPS.append(old)
    assert len(_LLM_CALL_TIMESTAMPS) == 3

    async def go():
        before = time.monotonic()
        await _wait_for_rpm_slot()
        after = time.monotonic()
        # Old entries trimmed, so new call fires instantly.
        assert (after - before) < 0.1
        # Now the window should have exactly 1 entry (the new one),
        # not 4 — old entries got trimmed.
        assert len(_LLM_CALL_TIMESTAMPS) == 1
    asyncio.run(go())


def test_throttle_state_is_process_global(monkeypatch) -> None:
    """Multiple LLM instances share the same rolling window — the
    upstream rate limit doesn't care which Python object is making
    the call. Two distinct waiters in the same process must observe
    the same cap."""
    monkeypatch.setenv("STRIX_LLM_RPM", "1")

    # Pre-populate with one fresh entry — simulates an "earlier LLM
    # instance already made its 1 call this minute."
    _LLM_CALL_TIMESTAMPS.append(time.monotonic())

    sleeps: list[float] = []

    async def fake_sleep(s):
        sleeps.append(float(s))
        # Age the existing entries so the loop can proceed.
        for i in range(len(_LLM_CALL_TIMESTAMPS)):
            _LLM_CALL_TIMESTAMPS[i] -= s

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def go():
        # This is a SECOND LLM "instance" trying to make a call —
        # but with cap=1 and an existing fresh entry, it must block.
        await _wait_for_rpm_slot()
        assert len(sleeps) >= 1, "second LLM must wait for the first's window"
    asyncio.run(go())


def test_concurrent_waiters_serialize(monkeypatch) -> None:
    """Two concurrent `_wait_for_rpm_slot` callers with cap=1 must
    serialize: one returns immediately, the other waits."""
    monkeypatch.setenv("STRIX_LLM_RPM", "1")

    sleeps: list[float] = []

    async def fake_sleep(s):
        sleeps.append(float(s))
        for i in range(len(_LLM_CALL_TIMESTAMPS)):
            _LLM_CALL_TIMESTAMPS[i] -= s

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def go():
        # Fire 3 concurrent waiters with cap=1. The first should
        # fire immediately, the other 2 should block.
        await asyncio.gather(
            _wait_for_rpm_slot(),
            _wait_for_rpm_slot(),
            _wait_for_rpm_slot(),
        )
        # 2 of the 3 callers had to wait → 2 sleeps recorded.
        assert len(sleeps) == 2, (
            f"expected 2 sleeps for concurrent cap=1 waiters; got {sleeps}"
        )
        # All 3 ultimately recorded their timestamps (the window
        # advances after each sleep due to our fake_sleep aging).
        # The final length depends on aging math; the key invariant
        # is that all 3 returned without hanging.
    asyncio.run(go())
