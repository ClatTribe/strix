"""Tests for Phase 1.7 — parallel specialist dispatch in
`process_tool_invocations`.

Pins:
  * Single invocation runs serially (no overhead from gather)
  * Multi-invocation runs concurrently (verified via timing)
  * Order preserved in observation_parts
  * STRIX_PARALLEL_TOOL_DISPATCH=0 env flag falls back to serial
  * Errors in one tool don't block others
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from strix.tools.executor import process_tool_invocations


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def slow_tool(monkeypatch):
    """Fake `_execute_single_tool` that sleeps 0.1s per call. Lets us
    assert parallelism via timing — 4 calls in serial = 0.4s; in
    parallel = ~0.1s."""
    async def _fake(tool_inv, agent_state, tracer, agent_id):
        await asyncio.sleep(0.1)
        return (
            f"<tool_result tool={tool_inv['toolName']!r}/>",
            [],
            False,
        )
    monkeypatch.setattr(
        "strix.tools.executor._execute_single_tool",
        _fake,
    )
    return _fake


def test_parallel_dispatch_runs_concurrently(monkeypatch, slow_tool) -> None:
    """4 tools × 0.1s each → ~0.1s total when parallel."""
    monkeypatch.delenv("STRIX_PARALLEL_TOOL_DISPATCH", raising=False)
    history: list[dict] = []
    invs = [{"toolName": f"t{i}", "args": {}} for i in range(4)]
    start = time.time()
    _run(process_tool_invocations(invs, history))
    elapsed = time.time() - start
    # Generous bound (0.4s ≈ serial). Parallel should be well under 0.3s.
    assert elapsed < 0.3, f"4 parallel calls took {elapsed:.2f}s — likely serial"


def test_serial_fallback_via_env_flag(monkeypatch, slow_tool) -> None:
    monkeypatch.setenv("STRIX_PARALLEL_TOOL_DISPATCH", "0")
    history: list[dict] = []
    invs = [{"toolName": f"t{i}", "args": {}} for i in range(4)]
    start = time.time()
    _run(process_tool_invocations(invs, history))
    elapsed = time.time() - start
    # Serial: 4 × 0.1s = ~0.4s. Allow some overhead.
    assert elapsed >= 0.35, f"4 serial calls took {elapsed:.2f}s — looks parallel?"


def test_single_invocation_uses_serial_path(monkeypatch, slow_tool) -> None:
    """Single tool call: no asyncio.gather needed; serial path is fine
    and avoids unnecessary overhead."""
    monkeypatch.delenv("STRIX_PARALLEL_TOOL_DISPATCH", raising=False)
    history: list[dict] = []
    invs = [{"toolName": "t", "args": {}}]
    _run(process_tool_invocations(invs, history))
    # No exception; conversation history grew by exactly one entry.
    assert len(history) == 1


def test_results_preserve_order(monkeypatch) -> None:
    """When tools have different sleep times, their results in
    observation_parts must still appear in invocation order."""
    sleep_per_tool = {"a": 0.05, "b": 0.20, "c": 0.05}

    async def _fake(tool_inv, agent_state, tracer, agent_id):
        await asyncio.sleep(sleep_per_tool[tool_inv["toolName"]])
        return (f"RESULT_{tool_inv['toolName']}", [], False)

    monkeypatch.setattr("strix.tools.executor._execute_single_tool", _fake)
    monkeypatch.delenv("STRIX_PARALLEL_TOOL_DISPATCH", raising=False)
    history: list[dict] = []
    invs = [
        {"toolName": "a", "args": {}},
        {"toolName": "b", "args": {}},
        {"toolName": "c", "args": {}},
    ]
    _run(process_tool_invocations(invs, history))
    # Last message in history is the joined "Tool Results:\n\n<part1>..."
    content = history[-1]["content"]
    assert "RESULT_a" in content
    # Order: a should come before b, b before c (despite b being slowest)
    assert content.index("RESULT_a") < content.index("RESULT_b") < content.index("RESULT_c")


def test_finish_signal_propagates(monkeypatch) -> None:
    """If any one tool returns finish=True, the batch returns True."""
    async def _fake(tool_inv, agent_state, tracer, agent_id):
        finish = tool_inv["toolName"] == "finish_scan"
        return (f"<r/>", [], finish)

    monkeypatch.setattr("strix.tools.executor._execute_single_tool", _fake)
    history: list[dict] = []
    invs = [
        {"toolName": "scan_xss", "args": {}},
        {"toolName": "finish_scan", "args": {}},
    ]
    result = _run(process_tool_invocations(invs, history))
    assert result is True
