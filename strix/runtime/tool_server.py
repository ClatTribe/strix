from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
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

agent_tasks: dict[str, asyncio.Task[Any]] = {}


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


_tracer_lock = asyncio.Lock()


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

    # iter-35.4 — pre/post snapshot of the sandbox tracer to capture
    # findings the tool emitted in-band. The lock keeps concurrent
    # tool runs from cross-contaminating each other's captures.
    async with _tracer_lock:
        sandbox_tracer = _get_sandbox_tracer()
        pre_count = (
            len(sandbox_tracer.vulnerability_reports) if sandbox_tracer else 0
        )
        try:
            result = await asyncio.to_thread(tool_func, **converted_kwargs)
        except BaseException:
            # Restore pre-call state on failure so a crashed tool
            # doesn't leave half-emitted findings dangling.
            if sandbox_tracer is not None:
                del sandbox_tracer.vulnerability_reports[pre_count:]
            raise

        captured: list[dict[str, Any]] = []
        if sandbox_tracer is not None and len(
            sandbox_tracer.vulnerability_reports,
        ) > pre_count:
            captured = list(
                sandbox_tracer.vulnerability_reports[pre_count:],
            )
            # Truncate so the sandbox tracer doesn't accumulate state
            # across tool calls — it's not the authoritative store.
            del sandbox_tracer.vulnerability_reports[pre_count:]

    if captured:
        # Inject the sidecar into the result so the host can re-emit
        # with L1.5 hooks. Handles dict-shaped results (most tools)
        # AND SpecialistResult / arbitrary objects (rare).
        result = _attach_findings_sidecar(result, captured)

    return result


def _get_sandbox_tracer() -> Any:
    """Return the sandbox-side tracer singleton, or None if the
    tracer subsystem is unavailable (tests, partial init, etc.)."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        return get_global_tracer()
    except Exception:  # noqa: BLE001
        return None


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

    if agent_id in agent_tasks:
        old_task = agent_tasks[agent_id]
        if not old_task.done():
            old_task.cancel()

    task = asyncio.create_task(
        asyncio.wait_for(
            _run_tool(agent_id, request.tool_name, request.kwargs), timeout=REQUEST_TIMEOUT
        )
    )
    agent_tasks[agent_id] = task

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
        if agent_tasks.get(agent_id) is task:
            del agent_tasks[agent_id]


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
        "active_agents": len(agent_tasks),
        "agents": list(agent_tasks.keys()),
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
