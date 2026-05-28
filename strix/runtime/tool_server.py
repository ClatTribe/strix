from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import uuid
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError


SANDBOX_MODE = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
if not SANDBOX_MODE:
    raise RuntimeError("Tool server should only run in sandbox mode (STRIX_SANDBOX_MODE=true)")

parser = argparse.ArgumentParser(description="Start Strix tool server")
parser.add_argument("--token", required=True, help="Authentication token")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")  # nosec
parser.add_argument("--port", type=int, required=True, help="Port to bind to")
parser.add_argument(
    "--timeout",
    type=int,
    default=300,
    help=(
        "Hard timeout in seconds for each request execution "
        "(default: 300). iter-27.5 raised from 120s to fit "
        "trivy/sqlmap/nuclei/dalfox heavy scans; nginx-vuln "
        "container_image bench fixture had been timing out at 120s "
        "on every run."
    ),
)

args = parser.parse_args()
EXPECTED_TOKEN = args.token
REQUEST_TIMEOUT = args.timeout

# iter-Q5.31b — instantiate a sandbox-side Tracer at module load and
# set it as the global so `tracer.add_vulnerability_report` calls
# from sandbox-resident tools (scan_sast / scan_iac / scan_idor /
# scan_auth_flow / probe_open_tcp_ports / ... — ~30+ tools) have a
# place to land. Without this, `get_global_tracer()` returns None
# inside the tool_server process and every in-tool tracer call is
# silently a no-op. iter-35.4's pre/post-snapshot sidecar mechanism
# also requires the tracer to exist — when None, captured stays [].
# The bench-flow symptom was scan_sast's 200 semgrep findings
# disappearing on the sandbox side (verified iter-Q5.31 by stderr
# instrumenting `_propagate_sandbox_findings_to_host`:
# `findings_emitted_type=NoneType` for every tool call). The sandbox
# tracer is hookless by design — the host's tracer carries the L1.5
# hook chain; here we just need a clean append-only store for the
# pre/post diff to work.
try:
    from strix.telemetry.tracer import Tracer, set_global_tracer
    _sandbox_tracer = Tracer(run_name="sandbox-tool-server")
    set_global_tracer(_sandbox_tracer)
except Exception as _sandbox_tracer_init_e:  # noqa: BLE001
    # Don't block tool_server startup if Tracer init fails — the
    # tool dispatch path still works, we just lose finding capture.
    import logging as _lg_st
    _lg_st.getLogger(__name__).warning(
        "iter-Q5.31b — sandbox-side Tracer init failed: %s",
        _sandbox_tracer_init_e,
    )

app = FastAPI()
security = HTTPBearer()
security_dependency = Depends(security)

# iter-Q4.0 — keyed by (agent_id, request_id) so concurrent tools
# under one agent run in parallel instead of cancelling each other.
agent_tasks: dict[tuple[str, str], asyncio.Task[Any]] = {}


def verify_token(credentials: HTTPAuthorizationCredentials) -> str:
    if not credentials or credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != EXPECTED_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]
    # iter-Q4.0 — unique per-call id. The running-task registry keys
    # on (agent_id, request_id) so concurrent tools under one agent
    # no longer cancel each other (the pre-Q4.0 `agent_id`-only key
    # cancelled the in-flight task on every new same-agent request,
    # forcing fan-out to serial). Optional for backward-compat: an
    # older host that doesn't send it gets a server-generated id, so
    # each request still keys uniquely.
    request_id: str | None = None


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None
    # iter-Q5.31 — sandbox-emitted findings sidecar surfaced as an
    # explicit field, NOT via piggyback on `result`. The previous
    # iter-35.4 mechanism (stuff `_sandbox_emitted_findings` key into
    # the result dict) relied on the `result: Any` field preserving
    # arbitrary keys through Pydantic + FastAPI's response_model
    # serialization. In practice, Pydantic 2's serializer for
    # `Any`-typed fields containing dicts dropped keys that weren't
    # in the inner type's schema — `SpecialistResult.model_dump()`
    # produces a dict with exactly the SpecialistResult fields, the
    # subsequent `result["_sandbox_emitted_findings"] = ...` mutation
    # was lost across the HTTP boundary even though it survived
    # in-process. Diagnostic: iter-Q5.31 instrumented
    # `_propagate_sandbox_findings_to_host` and confirmed the host
    # received the SpecialistResult-shaped dict WITHOUT the sidecar
    # key (8 keys = the 8 SpecialistResult fields, no 9th).
    findings_emitted: list[dict[str, Any]] | None = None


# iter-Q4.0 — the iter-35.4 `_tracer_lock` (held across each tool run
# to serialise pre/post tracer snapshots) is gone. Per-call finding
# capture now uses a contextvar sink (tracer._finding_capture_sink),
# so concurrent tool runs no longer contend on a shared lock.


async def _run_tool(agent_id: str, tool_name: str, kwargs: dict[str, Any]) -> Any:
    """Run a tool inside the sandbox and capture any findings the
    tool emits via ``tracer.add_vulnerability_report``.

    iter-35.4 — sandbox tools historically called the tracer directly
    from inside their body, but the sandbox-side tracer is a fresh,
    hookless singleton (the L1.5 enrichment chain runs on the host's
    tracer). The findings effectively vanished — no FP filter,
    surface_priority, exploitability, corroborator, or
    post_emit_verifier ran for the ~53 tools matching this pattern.

    The fix: snapshot the sandbox tracer before the tool runs,
    capture any new ``vulnerability_reports`` entries afterward,
    truncate the sandbox tracer back to baseline (so it doesn't
    accumulate cross-call state), and ship the captured findings
    back to the host inside the result dict via the
    ``_sandbox_emitted_findings`` sidecar key. The host's
    ``_execute_tool_in_sandbox`` extracts the sidecar and re-emits
    each finding through the host's ``tracer.add_vulnerability_report``
    — that path runs the full L1.5 hook chain.

    The lock serialises pre/post snapshots across concurrent in-flight
    tool calls so each call sees only the findings IT emitted. Without
    the lock, two parallel ``scan_*`` tools could mix their findings.
    """
    from strix.tools.argument_parser import convert_arguments
    from strix.tools.context import set_current_agent_id
    from strix.tools.registry import get_tool_by_name

    set_current_agent_id(agent_id)

    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)

    # iter-Q4.0 — per-call contextvar capture sink (replaces the
    # iter-35.4 `_tracer_lock` + index-snapshot scheme). The old
    # scheme held `_tracer_lock` across the ENTIRE tool run so two
    # concurrent tools couldn't interleave their appends to the
    # shared sandbox tracer's `vulnerability_reports` list — which
    # serialised every fan-out / multi-tool dispatch and was the
    # dominant bottleneck behind the 2h WAVSEP bench.
    #
    # The sink is contextvar-scoped: each asyncio task gets its own,
    # and `asyncio.to_thread` copies the context into the worker
    # thread, so a tool calling `tracer.add_vulnerability_report`
    # from inside `to_thread` lands its findings in THIS call's sink
    # (see tracer._finding_capture_sink). No shared mutable state,
    # no lock, no cross-call contamination — concurrent tools run
    # truly in parallel.
    from strix.telemetry.tracer import (
        pop_finding_capture_sink,
        push_finding_capture_sink,
    )

    sink, token = push_finding_capture_sink()
    try:
        result = await asyncio.to_thread(tool_func, **converted_kwargs)
    finally:
        pop_finding_capture_sink(token)

    captured: list[dict[str, Any]] = list(sink)

    if captured:
        # Inject the sidecar into the result so the host can re-emit
        # with L1.5 hooks. Handles dict-shaped results (most tools)
        # AND SpecialistResult / arbitrary objects (rare).
        result = _attach_findings_sidecar(result, captured)

    return result


def _attach_findings_sidecar(
    result: Any, captured: list[dict[str, Any]],
) -> Any:
    """Inject ``_sandbox_emitted_findings`` into the tool's return
    value so the host executor can extract and re-emit on the host
    tracer. Dict results get a new key; non-dict results are wrapped
    in a dict so the sidecar survives the HTTP round-trip."""
    if isinstance(result, dict):
        # Don't overwrite if the tool already set this key — preserve
        # whichever value is more complete.
        if "_sandbox_emitted_findings" not in result:
            result["_sandbox_emitted_findings"] = captured
        return result
    # Non-dict result (str, list, SpecialistResult, etc.) — wrap so
    # the sidecar travels. The host's executor handles unwrapping.
    return {
        "_sandbox_wrapped_result": result,
        "_sandbox_emitted_findings": captured,
    }


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest, credentials: HTTPAuthorizationCredentials = security_dependency
) -> ToolExecutionResponse:
    verify_token(credentials)

    agent_id = request.agent_id

    # iter-Q4.0 — key the running-task registry on (agent_id,
    # request_id) instead of agent_id alone. Pre-Q4.0 a new request
    # for an in-flight agent_id CANCELLED the running task ("newest
    # request wins per agent"), correct for the sequential L2 lead
    # but fatal for concurrent dispatch: fan-out fired N tools under
    # ONE agent_id, so request #2 cancelled #1, #3 cancelled #2 …
    # only the last survived. That's why fan-out concurrency was
    # pinned to 1 (serial) and the WAVSEP bench took 2h+.
    #
    # request_id is unique per call (host sends a uuid; absent →
    # server-generated), so there is no collision and no implicit
    # cancellation. Concurrent tools under one agent now run in
    # parallel. Orphaned tasks (host stopped awaiting) self-clean at
    # REQUEST_TIMEOUT via the asyncio.wait_for below — bounded, so
    # dropping the eager cancel costs nothing in practice.
    request_id = request.request_id or uuid.uuid4().hex
    task_key = (agent_id, request_id)

    task = asyncio.create_task(
        asyncio.wait_for(
            _run_tool(agent_id, request.tool_name, request.kwargs), timeout=REQUEST_TIMEOUT
        )
    )
    agent_tasks[task_key] = task

    try:
        result = await task
        # iter-Q5.31 — extract the sidecar from the result dict (if
        # attached by `_attach_findings_sidecar`) and put it on the
        # explicit `findings_emitted` field. The wrapped-result
        # variant (non-dict tool returns) puts both sidecar + the
        # original result inside a wrapper dict — unwrap that too so
        # the host receives the original result shape it expects.
        findings_emitted = None
        if isinstance(result, dict):
            findings_emitted = result.pop("_sandbox_emitted_findings", None)
            if "_sandbox_wrapped_result" in result and len(result) == 1:
                result = result.get("_sandbox_wrapped_result")
        return ToolExecutionResponse(
            result=result, findings_emitted=findings_emitted,
        )

    except asyncio.CancelledError:
        return ToolExecutionResponse(error="Cancelled by newer request")

    except TimeoutError:
        return ToolExecutionResponse(error=f"Tool timed out after {REQUEST_TIMEOUT}s")

    except ValidationError as e:
        return ToolExecutionResponse(error=f"Invalid arguments: {e}")

    except (ValueError, RuntimeError, ImportError) as e:
        return ToolExecutionResponse(error=f"Tool execution error: {e}")

    except Exception as e:  # noqa: BLE001
        return ToolExecutionResponse(error=f"Unexpected error: {e}")

    finally:
        if agent_tasks.get(task_key) is task:
            del agent_tasks[task_key]


@app.post("/register_agent")
async def register_agent(
    agent_id: str, credentials: HTTPAuthorizationCredentials = security_dependency
) -> dict[str, str]:
    verify_token(credentials)
    return {"status": "registered", "agent_id": agent_id}


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "healthy",
        "sandbox_mode": str(SANDBOX_MODE),
        "environment": "sandbox" if SANDBOX_MODE else "main",
        "auth_configured": "true" if EXPECTED_TOKEN else "false",
        "active_agents": len({a for a, _ in agent_tasks}),
        "active_tasks": len(agent_tasks),
        "agents": sorted({a for a, _ in agent_tasks}),
    }


def signal_handler(_signum: int, _frame: Any) -> None:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    for task in agent_tasks.values():
        task.cancel()
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
