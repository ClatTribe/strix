"""Async / background specialist-tool dispatch (roadmap §8.5 Phase 6
/ B.5 / single-agent.md §2.7).

Long-running specialist-tools (nuclei against 10K endpoints,
masscan, recon-ng pipelines, browser_specialist's session-replay)
should NOT block the lead-agent loop. This module wires the
fire-and-forget pattern: the tool returns `{status: "started",
task_id: "task_abc123", eta_seconds: 600}` immediately; the
framework runs the work in a thread-pool; the lead observes a
deferred `tool.execution.completed` event later (same events.jsonl
stream).

Wrapper-side impact: zero schema change. `tool.execution.started`
+ `tool.execution.completed` events still fire as today; the gap
between them just gets larger on async tasks. The wrapper sees the
same shape regardless.

Public API
----------

```python
# Fire async — returns task_id immediately.
result = fire_async(tool_name="bulk_subdomain_scan", args={...},
                    eta_seconds=600)
# → {"status": "started", "task_id": "task_abc...", "eta_seconds": 600}

# Lead observes async-task lifecycle:
status = task_status(task_id="task_abc...")
# → {"status": "running" | "completed" | "errored" | "cancelled",
#    "result": ... | None, "elapsed_seconds": ..., "error": ...}

# Cancel mid-flight:
cancelled = task_cancel(task_id="task_abc...")
# → {"success": bool, "was_running": bool}
```

Phase 6 ships the lifecycle primitives. Phase 3b's specialist-tool
registry decorator (already shipped in #155) supports
`async_capable=True`; an LLM-driven specialist that opts in returns
`{status: "started", task_id, eta_seconds}` and the framework
dispatches the inner LLM call asynchronously via this module.

The lead's system prompt instructs:

> Long-running specialist-tools return `{status: "started",
> task_id, eta_seconds}` instead of `{status: "ok"}`. Continue
> with other work; the result will arrive as a system
> notification within `eta_seconds`. Do NOT poll — observe via
> natural turn progression.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


TaskStatus = Literal["pending", "running", "completed", "errored", "cancelled"]


@dataclass
class AsyncTask:
    """Lifecycle record for one fire-and-forget specialist-tool call.

    Stored in the module-level registry; cleaned up on cancel or
    after `STALE_TASK_TTL_SECONDS` (1 hour) post-completion."""

    task_id: str
    tool_name: str
    args: dict[str, Any]
    eta_seconds: int
    status: TaskStatus = "pending"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: Any = None
    error: str | None = None
    future: Future[Any] | None = field(default=None, repr=False)

    def to_status_dict(self) -> dict[str, Any]:
        elapsed: float = 0.0
        if self.started_at:
            end = self.completed_at or datetime.now(UTC)
            elapsed = max(0.0, (end - self.started_at).total_seconds())
        return {
            "status": self.status,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "result": self.result if self.status == "completed" else None,
            "error": self.error if self.status == "errored" else None,
            "elapsed_seconds": round(elapsed, 2),
            "eta_seconds": self.eta_seconds,
        }


# Module-level state. Bounded to avoid memory leak on long-running scans.
_REGISTRY: dict[str, AsyncTask] = {}
_REGISTRY_LOCK = threading.Lock()
_EXECUTOR: ThreadPoolExecutor | None = None
_EXECUTOR_LOCK = threading.Lock()
_MAX_WORKERS = 8
_STALE_TASK_TTL_SECONDS = 3600


def _get_executor() -> ThreadPoolExecutor:
    """Lazy-init thread pool. Bounded at 8 workers — enough for the
    common case of 8 parallel specialists per turn (B.3) without
    blowing memory."""
    global _EXECUTOR
    if _EXECUTOR is not None:
        return _EXECUTOR
    with _EXECUTOR_LOCK:
        if _EXECUTOR is None:
            _EXECUTOR = ThreadPoolExecutor(
                max_workers=_MAX_WORKERS,
                thread_name_prefix="strix-async-tool",
            )
    return _EXECUTOR


def _gen_task_id() -> str:
    return f"task_{uuid.uuid4().hex[:12]}"


def _gc_stale_tasks() -> None:
    """Remove completed/errored/cancelled tasks older than the TTL.
    Called opportunistically on each `fire_async` to bound registry
    size."""
    cutoff = datetime.now(UTC).timestamp() - _STALE_TASK_TTL_SECONDS
    with _REGISTRY_LOCK:
        stale: list[str] = []
        for tid, task in _REGISTRY.items():
            if task.status not in ("completed", "errored", "cancelled"):
                continue
            ts = task.completed_at
            if ts is None:
                continue
            if ts.timestamp() < cutoff:
                stale.append(tid)
        for tid in stale:
            _REGISTRY.pop(tid, None)


def _emit_completion_event(task: AsyncTask) -> None:
    """Best-effort `tool.execution.completed` event for the deferred
    completion. Tracer-absent → silent."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return
        tracer._emit_event(
            "tool.execution.completed",
            actor={"tool_name": task.tool_name, "async_task_id": task.task_id},
            payload={
                "result": task.result,
                "error": task.error,
                "elapsed_seconds": (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.started_at and task.completed_at else None
                ),
                "async": True,
            },
            status=task.status,
            source="strix.tools.specialist.async_dispatch",
        )
    except Exception:  # noqa: BLE001
        logger.debug("async_dispatch: completion event failed", exc_info=True)


def _run_task(task_id: str, fn: Any, args: dict[str, Any]) -> Any:
    """Inner thread function. Executes the underlying tool, updates
    the AsyncTask record, fires the completion event."""
    with _REGISTRY_LOCK:
        task = _REGISTRY.get(task_id)
        if task is None or task.status == "cancelled":
            return None
        task.status = "running"
        task.started_at = datetime.now(UTC)

    try:
        result = fn(**args) if args else fn()
        with _REGISTRY_LOCK:
            t = _REGISTRY.get(task_id)
            if t is not None and t.status != "cancelled":
                t.status = "completed"
                t.result = result
                t.completed_at = datetime.now(UTC)
        _emit_completion_event(_REGISTRY[task_id])
        return result
    except Exception as e:  # noqa: BLE001
        with _REGISTRY_LOCK:
            t = _REGISTRY.get(task_id)
            if t is not None:
                t.status = "errored"
                t.error = f"{type(e).__name__}: {e}"
                t.completed_at = datetime.now(UTC)
        _emit_completion_event(_REGISTRY[task_id])
        return None


@register_tool(sandbox_execution=False, provenance="framework")
def fire_async(
    *,
    tool_name: str,
    args: dict[str, Any] | None = None,
    eta_seconds: int = 600,
) -> dict[str, Any]:
    """Dispatch a tool asynchronously. Returns immediately with
    `{status: "started", task_id}`. The actual work runs in the
    framework's bounded thread pool.

    Args:
        tool_name: name of the tool to invoke. Must be registered
            in the global tool registry.
        args: kwargs for the tool. Must NOT contain forbidden
            bounded-input args (B.2 — enforced by the specialist
            registry decorator on the underlying tool, not here).
        eta_seconds: caller-provided ETA. Used by the lead's system
            prompt for "wait approximately N seconds before checking
            back" pacing.

    Returns:
        `{status: "started", task_id, eta_seconds}` on dispatch;
        `{status: "errored", error}` if the tool can't be looked up.
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        return {"status": "errored", "error": "tool_name required"}
    args = args or {}
    if not isinstance(args, dict):
        return {"status": "errored", "error": "args must be a dict"}

    try:
        from strix.tools.registry import get_tool_by_name

        fn = get_tool_by_name(tool_name)
        if fn is None:
            return {
                "status": "errored",
                "error": f"tool {tool_name!r} not registered",
            }
    except Exception as e:  # noqa: BLE001
        return {"status": "errored", "error": f"{type(e).__name__}: {e}"}

    _gc_stale_tasks()

    task = AsyncTask(
        task_id=_gen_task_id(),
        tool_name=tool_name,
        args=dict(args),
        eta_seconds=max(1, int(eta_seconds)),
    )
    with _REGISTRY_LOCK:
        _REGISTRY[task.task_id] = task

    executor = _get_executor()
    future = executor.submit(_run_task, task.task_id, fn, args)
    with _REGISTRY_LOCK:
        task.future = future

    return {
        "status": "started",
        "task_id": task.task_id,
        "eta_seconds": task.eta_seconds,
    }


@register_tool(sandbox_execution=False, provenance="framework")
def task_status(*, task_id: str) -> dict[str, Any]:
    """Query an async task's lifecycle. Returns the current status
    + (when completed) the result. The lead doesn't typically poll
    this — the deferred `tool.execution.completed` event is the
    primary observation channel — but it's available for explicit
    sync-points."""
    if not isinstance(task_id, str) or not task_id.strip():
        return {"status": "errored", "error": "task_id required"}
    with _REGISTRY_LOCK:
        task = _REGISTRY.get(task_id)
    if task is None:
        return {"status": "unknown", "task_id": task_id, "error": "no such task"}
    return task.to_status_dict()


@register_tool(sandbox_execution=False, provenance="framework")
def task_cancel(*, task_id: str) -> dict[str, Any]:
    """Best-effort cancel. If the task is `pending`, marks
    `cancelled` and the worker thread's pre-flight check skips
    execution. If `running`, marks `cancelled` but the in-flight
    work continues (Python doesn't reliably interrupt threads);
    the result is discarded."""
    if not isinstance(task_id, str) or not task_id.strip():
        return {"success": False, "was_running": False, "error": "task_id required"}
    with _REGISTRY_LOCK:
        task = _REGISTRY.get(task_id)
        if task is None:
            return {"success": False, "was_running": False, "error": "no such task"}
        was_running = task.status == "running"
        if task.status in ("completed", "errored", "cancelled"):
            return {"success": True, "was_running": was_running, "error": None}
        task.status = "cancelled"
        task.completed_at = datetime.now(UTC)
    return {"success": True, "was_running": was_running, "error": None}


def _reset_for_tests() -> None:
    """Test-only: clear the registry + executor."""
    global _EXECUTOR
    with _REGISTRY_LOCK:
        _REGISTRY.clear()
    with _EXECUTOR_LOCK:
        if _EXECUTOR is not None:
            _EXECUTOR.shutdown(wait=False)
            _EXECUTOR = None
