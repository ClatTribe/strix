"""Tests for §8.5 Phase 6 — async / background tool dispatch.

Pins the lifecycle: `fire_async` returns immediately with task_id;
`task_status` reports current state; `task_cancel` short-circuits
pre-flight or marks running tasks. Mocks the underlying tool so
the test runs hermetically without network access.
"""

from __future__ import annotations

import threading
import time

import pytest

from strix.tools.specialist.async_dispatch import (
    _reset_for_tests,
    fire_async,
    task_cancel,
    task_status,
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    _reset_for_tests()
    yield
    _reset_for_tests()


# ---------------------------------------------------------------------------
# fire_async — input validation
# ---------------------------------------------------------------------------


def test_fire_async_requires_tool_name() -> None:
    out = fire_async(tool_name="", args={})
    assert out["status"] == "errored"


def test_fire_async_rejects_non_dict_args() -> None:
    out = fire_async(tool_name="some_tool", args="not a dict")  # type: ignore[arg-type]
    assert out["status"] == "errored"


def test_fire_async_unknown_tool_returns_errored() -> None:
    out = fire_async(tool_name="nonexistent_xyz_tool", args={})
    assert out["status"] == "errored"
    assert "not registered" in (out["error"] or "")


# ---------------------------------------------------------------------------
# Lifecycle — happy path with a mock tool
# ---------------------------------------------------------------------------


def test_fire_async_returns_task_id_immediately() -> None:
    """`fire_async` must NOT block waiting for the tool. It should
    return the task_id within tens of milliseconds even when the
    tool would take seconds."""
    from strix.tools.registry import register_tool

    @register_tool(sandbox_execution=False)
    def _slow_dummy_tool() -> dict[str, str]:
        time.sleep(2)  # slow tool
        return {"result": "done"}

    start = time.monotonic()
    out = fire_async(tool_name="_slow_dummy_tool", args={})
    elapsed = time.monotonic() - start

    assert out["status"] == "started"
    assert out["task_id"].startswith("task_")
    assert out["eta_seconds"] > 0
    assert elapsed < 0.5, f"fire_async blocked for {elapsed:.2f}s"


def test_task_status_reports_completed_after_finish() -> None:
    from strix.tools.registry import register_tool

    @register_tool(sandbox_execution=False)
    def _quick_dummy_tool() -> dict[str, str]:
        return {"result": "ok"}

    out = fire_async(tool_name="_quick_dummy_tool", args={})
    task_id = out["task_id"]
    # Wait briefly for the worker to finish.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        st = task_status(task_id=task_id)
        if st["status"] == "completed":
            break
        time.sleep(0.05)

    final = task_status(task_id=task_id)
    assert final["status"] == "completed"
    assert final["result"] == {"result": "ok"}
    assert final["error"] is None


def test_task_status_reports_errored_when_tool_raises() -> None:
    from strix.tools.registry import register_tool

    @register_tool(sandbox_execution=False)
    def _raising_dummy_tool() -> dict[str, str]:
        raise RuntimeError("boom")

    out = fire_async(tool_name="_raising_dummy_tool", args={})
    task_id = out["task_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        st = task_status(task_id=task_id)
        if st["status"] in ("errored", "completed"):
            break
        time.sleep(0.05)

    final = task_status(task_id=task_id)
    assert final["status"] == "errored"
    assert "boom" in (final["error"] or "")


def test_task_status_unknown_returns_unknown() -> None:
    out = task_status(task_id="task_does_not_exist")
    assert out["status"] == "unknown"


def test_task_status_requires_task_id() -> None:
    out = task_status(task_id="")
    assert out["status"] == "errored"


# ---------------------------------------------------------------------------
# task_cancel
# ---------------------------------------------------------------------------


def test_task_cancel_marks_pending_task_as_cancelled() -> None:
    """A task fired then immediately cancelled should not run.
    Use a tool that blocks on an event so we can guarantee timing."""
    from strix.tools.registry import register_tool

    started_event = threading.Event()
    proceed_event = threading.Event()

    @register_tool(sandbox_execution=False)
    def _blocking_dummy_tool() -> dict[str, str]:
        started_event.set()
        proceed_event.wait(timeout=5)
        return {"result": "ran"}

    out = fire_async(tool_name="_blocking_dummy_tool", args={})
    task_id = out["task_id"]

    # Cancel before letting the tool proceed.
    cancelled = task_cancel(task_id=task_id)
    assert cancelled["success"] is True

    # Let the worker thread proceed (so it doesn't hang in the pool).
    proceed_event.set()
    time.sleep(0.2)

    final = task_status(task_id=task_id)
    assert final["status"] == "cancelled"


def test_task_cancel_unknown_task_returns_no_such_task() -> None:
    out = task_cancel(task_id="task_does_not_exist")
    assert out["success"] is False
    assert "no such task" in (out["error"] or "")


def test_task_cancel_already_completed_task_idempotent() -> None:
    from strix.tools.registry import register_tool

    @register_tool(sandbox_execution=False)
    def _instant_dummy_tool() -> dict[str, str]:
        return {"result": "ok"}

    out = fire_async(tool_name="_instant_dummy_tool", args={})
    task_id = out["task_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if task_status(task_id=task_id)["status"] == "completed":
            break
        time.sleep(0.05)

    # Cancel after completion — should still return success (idempotent).
    cancelled = task_cancel(task_id=task_id)
    assert cancelled["success"] is True


def test_task_cancel_requires_task_id() -> None:
    out = task_cancel(task_id="")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_async_tools_registered_in_catalog() -> None:
    """`fire_async` / `task_status` / `task_cancel` must appear in
    the agent's tool catalog so the lead can call them."""
    import strix.tools  # ensure side-effects
    from strix.tools.registry import get_tool_by_name

    for name in ("fire_async", "task_status", "task_cancel"):
        assert get_tool_by_name(name) is not None, f"{name} not registered"
