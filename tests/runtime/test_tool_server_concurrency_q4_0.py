"""Tests for iter-Q4.0 — sandbox tool_server concurrent tasks per agent.

Pre-Q4.0 the tool_server keyed its running-task registry on agent_id
alone and CANCELLED the in-flight task whenever a new request arrived
for the same agent ("newest wins per agent"). That cancelled all but
the last of N concurrent fan-out dispatches sharing one agent_id —
the documented cause of fan-out being pinned to serial (concurrency=1)
and the 2h WAVSEP bench.

Q4.0 keys on (agent_id, request_id) and drops the implicit cancel, so
concurrent same-agent requests run in parallel.

The tool_server module raises at import unless STRIX_SANDBOX_MODE is
set, so we set it before import (matching the runtime contract).
"""

from __future__ import annotations

import asyncio
import importlib
import os
import sys

import pytest

# tool_server.py runs argparse.parse_args() + a sandbox-mode guard at
# IMPORT time (it's the sandbox entrypoint script). Set both before
# importing so the module loads in-process for testing.
os.environ.setdefault("STRIX_SANDBOX_MODE", "true")
_saved_argv = sys.argv
sys.argv = ["tool_server.py", "--token", "test-token", "--port", "0"]
try:
    ts = importlib.import_module("strix.runtime.tool_server")
finally:
    sys.argv = _saved_argv


@pytest.fixture(autouse=True)
def _clear_registry():
    ts.agent_tasks.clear()
    yield
    ts.agent_tasks.clear()


class _FakeCreds:
    credentials = "test-token"


def _req(agent_id: str, tool_name: str, request_id: str | None = None, **kwargs):
    return ts.ToolExecutionRequest(
        agent_id=agent_id, tool_name=tool_name, kwargs=kwargs, request_id=request_id,
    )


class TestRequestModel:
    def test_request_id_optional(self):
        """Backward-compat: an old host that doesn't send request_id
        still constructs a valid request (server generates one)."""
        r = ts.ToolExecutionRequest(agent_id="a", tool_name="t", kwargs={})
        assert r.request_id is None

    def test_request_id_accepted(self):
        r = _req("a", "t", request_id="req-123")
        assert r.request_id == "req-123"


class TestConcurrentSameAgentNoCancel:
    def test_two_same_agent_requests_both_complete(self, monkeypatch):
        """The core Q4.0 property: two concurrent requests with the
        SAME agent_id but distinct request_ids BOTH run to completion.
        Pre-Q4.0 the second cancelled the first."""
        monkeypatch.setattr(ts, "verify_token", lambda creds: "test-token")

        started: list[str] = []
        finished: list[str] = []

        async def _fake_run_tool(agent_id, tool_name, kwargs):
            started.append(tool_name)
            # Hold long enough that both are concurrently in-flight.
            await asyncio.sleep(0.05)
            finished.append(tool_name)
            return {"status": "ok", "tool": tool_name}

        monkeypatch.setattr(ts, "_run_tool", _fake_run_tool)

        async def _run():
            return await asyncio.gather(
                ts.execute_tool(_req("agent-1", "toolA", "r1"), _FakeCreds()),
                ts.execute_tool(_req("agent-1", "toolB", "r2"), _FakeCreds()),
            )

        results = asyncio.run(_run())
        # Both ran (neither cancelled).
        assert sorted(started) == ["toolA", "toolB"]
        assert sorted(finished) == ["toolA", "toolB"]
        # Neither response is a cancellation error.
        errors = [r.error for r in results if r.error]
        assert errors == [], f"unexpected errors: {errors}"
        # Both carried their real result.
        tools = sorted(r.result["tool"] for r in results)
        assert tools == ["toolA", "toolB"]

    def test_registry_keys_are_agent_request_tuples(self, monkeypatch):
        """While in-flight, the registry must hold (agent_id, request_id)
        tuple keys — proving per-request isolation, not per-agent."""
        monkeypatch.setattr(ts, "verify_token", lambda creds: "test-token")
        observed_keys: list = []

        async def _fake_run_tool(agent_id, tool_name, kwargs):
            # Snapshot the live registry keys mid-flight.
            observed_keys.append(list(ts.agent_tasks.keys()))
            await asyncio.sleep(0.02)
            return {"status": "ok"}

        monkeypatch.setattr(ts, "_run_tool", _fake_run_tool)

        async def _run():
            await asyncio.gather(
                ts.execute_tool(_req("agent-1", "toolA", "r1"), _FakeCreds()),
                ts.execute_tool(_req("agent-1", "toolB", "r2"), _FakeCreds()),
            )

        asyncio.run(_run())
        # At peak, the registry held both (agent-1, r1) and (agent-1, r2).
        flat = {k for snapshot in observed_keys for k in snapshot}
        assert ("agent-1", "r1") in flat
        assert ("agent-1", "r2") in flat

    def test_missing_request_id_gets_unique_server_key(self, monkeypatch):
        """Two concurrent requests with NO request_id (old host) still
        don't collide — the server generates a unique id for each."""
        monkeypatch.setattr(ts, "verify_token", lambda creds: "test-token")
        finished: list[str] = []

        async def _fake_run_tool(agent_id, tool_name, kwargs):
            await asyncio.sleep(0.03)
            finished.append(tool_name)
            return {"status": "ok"}

        monkeypatch.setattr(ts, "_run_tool", _fake_run_tool)

        async def _run():
            return await asyncio.gather(
                ts.execute_tool(_req("agent-1", "toolA"), _FakeCreds()),
                ts.execute_tool(_req("agent-1", "toolB"), _FakeCreds()),
            )

        results = asyncio.run(_run())
        assert sorted(finished) == ["toolA", "toolB"]
        assert all(r.error is None for r in results)


class TestRegistryCleanup:
    def test_registry_emptied_after_completion(self, monkeypatch):
        monkeypatch.setattr(ts, "verify_token", lambda creds: "test-token")

        async def _fake_run_tool(agent_id, tool_name, kwargs):
            return {"status": "ok"}

        monkeypatch.setattr(ts, "_run_tool", _fake_run_tool)

        async def _run():
            await ts.execute_tool(_req("agent-1", "toolA", "r1"), _FakeCreds())

        asyncio.run(_run())
        assert ts.agent_tasks == {}, "registry must be cleaned after each call"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
