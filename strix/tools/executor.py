import inspect
import logging
import os
from typing import Any

import httpx


logger = logging.getLogger(__name__)

from strix.config import Config
from strix.telemetry import posthog


if os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "false":
    from strix.runtime import get_runtime

from .argument_parser import convert_arguments
from .registry import (
    get_tool_by_name,
    get_tool_names,
    get_tool_param_schema,
    needs_agent_state,
    should_execute_in_sandbox,
)


_SERVER_TIMEOUT = float(Config.get("strix_sandbox_execution_timeout") or "120")
SANDBOX_EXECUTION_TIMEOUT = _SERVER_TIMEOUT + 30
SANDBOX_CONNECT_TIMEOUT = float(Config.get("strix_sandbox_connect_timeout") or "10")


# Roadmap §8.5 — tools that the lead agent must NEVER invoke.
# Mirrors `strix.agents.lead_agent.tool_catalog._BLOCKED_TOOLS` (kept
# in sync intentionally — duplicated here so the executor avoids a
# circular import on the agents package). Update both lists together.
_LEAD_BLOCKED_TOOLS: frozenset[str] = frozenset({
    "create_agent",
    "spawn_webapp_specialist_team",
    "spawn_code_specialist_team",
    "spawn_webapp_subteam",
    "wait_for_message",
    "send_message_to_agent",
    "stop_agent",
    "view_agent_graph",
})


async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs: Any) -> Any:
    # iter-37.3 — emit a deprecation warning on every invocation of a
    # tool that's been retired in favor of an OSS engine. The tool
    # still EXECUTES (so existing tests + sandbox tool-server keep
    # working); the warning surfaces in logs and lets the caller see
    # which OSS replacement to use. See docs/tool-catalog-
    # rationalization.md for the full list + replacements.
    try:
        from strix.tools.deprecations import emit_deprecation_warning
        emit_deprecation_warning(tool_name)
    except Exception:  # noqa: BLE001
        pass  # never block execution on a warning hook

    execute_in_sandbox = should_execute_in_sandbox(tool_name)
    sandbox_mode = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"

    if execute_in_sandbox and not sandbox_mode:
        return await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)

    return await _execute_tool_locally(tool_name, agent_state, **kwargs)


async def _execute_tool_in_sandbox(tool_name: str, agent_state: Any, **kwargs: Any) -> Any:
    if not hasattr(agent_state, "sandbox_id") or not agent_state.sandbox_id:
        raise ValueError("Agent state with a valid sandbox_id is required for sandbox execution.")

    if not hasattr(agent_state, "sandbox_token") or not agent_state.sandbox_token:
        raise ValueError(
            "Agent state with a valid sandbox_token is required for sandbox execution."
        )

    if (
        not hasattr(agent_state, "sandbox_info")
        or "tool_server_port" not in agent_state.sandbox_info
    ):
        raise ValueError(
            "Agent state with a valid sandbox_info containing tool_server_port is required."
        )

    runtime = get_runtime()
    tool_server_port = agent_state.sandbox_info["tool_server_port"]
    server_url = await runtime.get_sandbox_url(agent_state.sandbox_id, tool_server_port)
    request_url = f"{server_url}/execute"

    agent_id = getattr(agent_state, "agent_id", "unknown")

    request_data = {
        "agent_id": agent_id,
        "tool_name": tool_name,
        "kwargs": kwargs,
    }

    headers = {
        "Authorization": f"Bearer {agent_state.sandbox_token}",
        "Content-Type": "application/json",
    }

    timeout = httpx.Timeout(
        timeout=SANDBOX_EXECUTION_TIMEOUT,
        connect=SANDBOX_CONNECT_TIMEOUT,
    )

    async with httpx.AsyncClient(trust_env=False) as client:
        try:
            response = await client.post(
                request_url, json=request_data, headers=headers, timeout=timeout
            )
            response.raise_for_status()
            response_data = response.json()
            if response_data.get("error"):
                posthog.error("tool_execution_error", f"{tool_name}: {response_data['error']}")
                raise RuntimeError(f"Sandbox execution error: {response_data['error']}")
            result = response_data.get("result")
            # iter-35.4 + iter-Q5.31 — extract any findings the sandbox
            # tool emitted via tracer.add_vulnerability_report (sandbox
            # tracer is hookless) and re-emit them on the host tracer so
            # the L1.5 hook chain (FP filter / surface_priority /
            # exploitability / corroborator / post_emit_verifier) fires.
            #
            # iter-Q5.31: the sandbox tool_server now puts the findings
            # on an explicit `findings_emitted` Pydantic field rather
            # than piggybacking a `_sandbox_emitted_findings` key on the
            # result dict — Pydantic 2's serializer for `Any`-typed
            # fields dropped the extra key across the HTTP boundary
            # (verified by direct diagnostic in iter-Q5.31). Fall back
            # to the legacy sidecar location for forward-compat with
            # older sandbox images that don't surface the new field.
            findings_emitted = response_data.get("findings_emitted")
            if findings_emitted:
                # Attach as the legacy sidecar key so
                # `_propagate_sandbox_findings_to_host` can extract it
                # via the same code path (no need for a second
                # branching code path on the host).
                if isinstance(result, dict):
                    result["_sandbox_emitted_findings"] = findings_emitted
                else:
                    result = {
                        "_sandbox_wrapped_result": result,
                        "_sandbox_emitted_findings": findings_emitted,
                    }
            result = _propagate_sandbox_findings_to_host(tool_name, result)
            return result
        except httpx.HTTPStatusError as e:
            posthog.error("tool_http_error", f"{tool_name}: HTTP {e.response.status_code}")
            if e.response.status_code == 401:
                raise RuntimeError("Authentication failed: Invalid or missing sandbox token") from e
            raise RuntimeError(f"HTTP error calling tool server: {e.response.status_code}") from e
        except httpx.RequestError as e:
            error_type = type(e).__name__
            posthog.error("tool_request_error", f"{tool_name}: {error_type}")
            raise RuntimeError(f"Request error calling tool server: {error_type}") from e


# iter-35.4 — fields that L1.5 hooks attach during emission. Stripped
# before re-emission on the host so the host's hooks attach their own
# (potentially different) values rather than inheriting the sandbox-
# side computations (which may be partial — e.g. corroborator can't
# see the host's existing finding set from inside the sandbox).
_L15_HOOK_ATTACHED_FIELDS: frozenset[str] = frozenset({
    "id", "fingerprint", "report_id",
    "surface_priority", "exploitability",
    "corroborated_by", "corroborators",
    "post_emit_verifier", "verified_by_post_emit",
    "auto_dismissed", "dismissal_reason",
    "l15_dismissed", "l15_dismissal_reason",
    "discovery_method",
    "epss", "kev", "campaign",
    "threat_intel", "threat_intel_status",
    "merged_from", "merged_into",
    "scan_run_id", "emitted_at",
    "root_cause_collapsed_into",
    "_sandbox_emitted_findings",  # never recurse the sidecar itself
})


def _propagate_sandbox_findings_to_host(
    tool_name: str, result: Any,
) -> Any:
    """iter-35.4 — extract sandbox-emitted findings from the result
    sidecar and re-emit each on the host tracer.

    Sandbox tools historically called `tracer.add_vulnerability_report`
    from inside their body. The sandbox-side tracer is a fresh
    singleton without the L1.5 enrichment hook chain attached, so
    those findings landed in a dead store — never reaching the host
    process, never gaining surface_priority / exploitability /
    corroborated_by annotations, never appearing in vulnerabilities.json
    or run_summary.json.

    The sandbox tool_server now captures the new findings post-call
    and ships them back inside the result as a
    `_sandbox_emitted_findings` list. We extract that list here, strip
    the fields L1.5 hooks attach (they'll be recomputed by the host's
    hooks against the host's tracer state), and replay each finding
    through `tracer.add_vulnerability_report(**filtered)` — which
    triggers the canonical L1.5 chain end-to-end.

    Best-effort: any failure during propagation is logged + swallowed
    so a misbehaving tool can't crash the executor.
    """
    # Common case: no sidecar present.
    if not isinstance(result, dict):
        return result
    sidecar = result.pop("_sandbox_emitted_findings", None)
    # Unwrap if the sandbox wrapped a non-dict result.
    if "_sandbox_wrapped_result" in result and len(result) <= 2:
        # Replace the wrapper with the original return value before
        # giving it back to callers. The sidecar (already extracted)
        # propagates separately via the host tracer.
        result = result.get("_sandbox_wrapped_result")

    if not sidecar:
        return result

    import inspect
    try:
        from strix.telemetry.tracer import get_global_tracer
    except Exception:  # noqa: BLE001
        # Tracer module not importable in this context — preserve
        # the result and skip propagation. Findings will be visible
        # in the sidecar if the caller cares.
        return result
    host_tracer = get_global_tracer()
    if host_tracer is None:
        return result

    # Build the set of kwargs add_vulnerability_report accepts so we
    # can filter the captured dict — extra keys would error.
    try:
        params = set(
            inspect.signature(host_tracer.add_vulnerability_report).parameters,
        ) - {"self"}
    except (TypeError, ValueError):
        # If signature introspection fails, fall back to a permissive
        # core set so we don't drop findings.
        params = {
            "title", "severity", "description", "endpoint", "method",
            "category", "cwe", "cve", "target", "verification_status",
            "confidence", "code_locations",
            "discovery_source_tool",
        }

    for raw in sidecar:
        if not isinstance(raw, dict):
            continue
        kwargs = {
            k: v for k, v in raw.items()
            if k in params and k not in _L15_HOOK_ATTACHED_FIELDS
        }
        # Drop a few specific keys we never want to inherit verbatim.
        kwargs.pop("id", None)
        kwargs.pop("fingerprint", None)
        kwargs.pop("report_id", None)
        # Tag the propagation source so audit can trace which path
        # the finding came in via.
        try:
            host_tracer.add_vulnerability_report(**kwargs)
        except Exception as e:  # noqa: BLE001
            posthog.error(
                "sandbox_findings_propagation_error",
                f"{tool_name}: {type(e).__name__}: {e}",
            )

    # iter-35.5 — propagate captured auth states from sandbox tools
    # (e.g. scan_auth_flow) into the host's SecurityContext so the
    # L2 lead's per-turn system-prompt rendering picks them up.
    _propagate_auth_states_to_host(tool_name, result)

    return result


def _propagate_auth_states_to_host(tool_name: str, result: Any) -> None:
    """iter-35.5 — extract captured auth states from a sandbox tool's
    ``tool_metadata.auth_states_captured`` (when present) and replay
    each through the host's ``record_auth_state``.

    The lead's per-turn prompt-renderer reads HOST
    ``SecurityContext.AuthState``; without this, sandbox-side auth
    captures (scan_auth_flow logging in as user-a) would be invisible
    to the lead, blocking IDOR / BOLA follow-up flows.

    Best-effort: any propagation failure is logged + swallowed.
    """
    if not isinstance(result, dict):
        return
    # Tool may return tool_metadata as a dict OR as a sub-key inside
    # a SpecialistResult-like envelope. Try both.
    tool_metadata: dict[str, Any] | None = None
    if isinstance(result.get("tool_metadata"), dict):
        tool_metadata = result["tool_metadata"]
    captured = (
        (tool_metadata or {}).get("auth_states_captured")
        or result.get("auth_states_captured")
    )
    if not captured or not isinstance(captured, list):
        return

    try:
        from strix.agents.security_context import record_auth_state
    except Exception:  # noqa: BLE001
        return

    for entry in captured:
        if not isinstance(entry, dict):
            continue
        label = entry.get("label")
        if not isinstance(label, str) or not label.strip():
            continue
        try:
            record_auth_state(
                label=label,
                cookies=entry.get("cookies"),
                bearer=entry.get("bearer"),
                csrf_token=entry.get("csrf_token"),
                notes=entry.get("notes") or "",
            )
        except Exception as e:  # noqa: BLE001
            posthog.error(
                "sandbox_auth_state_propagation_error",
                f"{tool_name}: {type(e).__name__}: {e}",
            )


async def _execute_tool_locally(tool_name: str, agent_state: Any | None, **kwargs: Any) -> Any:
    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)

    if needs_agent_state(tool_name):
        if agent_state is None:
            raise ValueError(f"Tool '{tool_name}' requires agent_state but none was provided.")
        result = tool_func(agent_state=agent_state, **converted_kwargs)
    else:
        result = tool_func(**converted_kwargs)

    return await result if inspect.isawaitable(result) else result


def validate_tool_availability(tool_name: str | None) -> tuple[bool, str]:
    if tool_name is None:
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool name is missing. Available tools: {available}"

    if tool_name not in get_tool_names():
        available = ", ".join(sorted(get_tool_names()))
        return False, f"Tool '{tool_name}' is not available. Available tools: {available}"

    return True, ""


def _validate_tool_arguments(tool_name: str, kwargs: dict[str, Any]) -> str | None:
    param_schema = get_tool_param_schema(tool_name)
    if not param_schema or not param_schema.get("has_params"):
        return None

    allowed_params: set[str] = param_schema.get("params", set())
    required_params: set[str] = param_schema.get("required", set())
    optional_params = allowed_params - required_params

    schema_hint = _format_schema_hint(tool_name, required_params, optional_params)

    unknown_params = set(kwargs.keys()) - allowed_params
    if unknown_params:
        unknown_list = ", ".join(sorted(unknown_params))
        return f"Tool '{tool_name}' received unknown parameter(s): {unknown_list}\n{schema_hint}"

    missing_required = [
        param for param in required_params if param not in kwargs or kwargs.get(param) in (None, "")
    ]
    if missing_required:
        missing_list = ", ".join(sorted(missing_required))
        return f"Tool '{tool_name}' missing required parameter(s): {missing_list}\n{schema_hint}"

    return None


def _format_schema_hint(tool_name: str, required: set[str], optional: set[str]) -> str:
    parts = [f"Valid parameters for '{tool_name}':"]
    if required:
        parts.append(f"  Required: {', '.join(sorted(required))}")
    if optional:
        parts.append(f"  Optional: {', '.join(sorted(optional))}")
    return "\n".join(parts)


async def execute_tool_with_validation(
    tool_name: str | None, agent_state: Any | None = None, **kwargs: Any
) -> Any:
    is_valid, error_msg = validate_tool_availability(tool_name)
    if not is_valid:
        return f"Error: {error_msg}"

    assert tool_name is not None

    arg_error = _validate_tool_arguments(tool_name, kwargs)
    if arg_error:
        return f"Error: {arg_error}"

    try:
        result = await execute_tool(tool_name, agent_state, **kwargs)
    except Exception as e:  # noqa: BLE001
        error_str = str(e)
        if len(error_str) > 500:
            error_str = error_str[:500] + "... [truncated]"
        return f"Error executing {tool_name}: {error_str}"
    else:
        return result


async def execute_tool_invocation(tool_inv: dict[str, Any], agent_state: Any | None = None) -> Any:
    tool_name = tool_inv.get("toolName")
    tool_args = tool_inv.get("args", {})

    return await execute_tool_with_validation(tool_name, agent_state, **tool_args)


def _check_error_result(result: Any) -> tuple[bool, Any]:
    is_error = False
    error_payload: Any = None

    if (isinstance(result, dict) and "error" in result) or (
        isinstance(result, str) and result.strip().lower().startswith("error:")
    ):
        is_error = True
        error_payload = result

    return is_error, error_payload


def _update_tracer_with_result(
    tracer: Any, execution_id: Any, is_error: bool, result: Any, error_payload: Any
) -> None:
    if not tracer or not execution_id:
        return

    try:
        if is_error:
            tracer.update_tool_execution(execution_id, "error", error_payload)
        else:
            tracer.update_tool_execution(execution_id, "completed", result)
    except (ConnectionError, RuntimeError) as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        raise


def _format_tool_result(
    tool_name: str, result: Any,
    execution_id: str | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    images: list[dict[str, Any]] = []

    screenshot_data = extract_screenshot_from_result(result)
    if screenshot_data:
        images.append(
            {
                "type": "image_url",
                "image_url": {"url": f"data:image/png;base64,{screenshot_data}"},
            }
        )
        result_str = remove_screenshot_from_result(result)
    else:
        result_str = result

    if result_str is None:
        final_result_str = f"Tool {tool_name} executed successfully"
    else:
        final_result_str = str(result_str)

        # §6 / PR-#235 — tiered output management. Replaces the
        # legacy 10K head-tail truncation that lost the middle
        # entirely. Now: ≤15K inline, 15-100K saved to scratch
        # with summary + path, >100K aggressive save. ANSI
        # stripping + repeat-line compression applied universally.
        # Kill switch: STRIX_OUTPUT_TIERING_DISABLED=1 reverts to
        # the legacy truncation below.
        try:
            from strix.runtime.output_tiering import (
                apply_tiering, is_tiering_disabled,
            )
            if not is_tiering_disabled():
                final_result_str = apply_tiering(
                    tool_name=tool_name,
                    raw_output=final_result_str,
                    execution_id=execution_id,
                )
            elif len(final_result_str) > 10000:
                # Legacy path — preserved for kill-switch parity.
                start_part = final_result_str[:4000]
                end_part = final_result_str[-4000:]
                final_result_str = (
                    start_part
                    + "\n\n... [middle content truncated] ...\n\n"
                    + end_part
                )
        except Exception:  # noqa: BLE001
            # Tiering bug must never break a tool call — fall back
            # to legacy truncation.
            logger.debug("output_tiering failed", exc_info=True)
            if len(final_result_str) > 10000:
                start_part = final_result_str[:4000]
                end_part = final_result_str[-4000:]
                final_result_str = (
                    start_part
                    + "\n\n... [middle content truncated] ...\n\n"
                    + end_part
                )

    # Trust-boundary: scan for prompt-injection markers in the tool
    # output before the LLM sees it. Emits a tool.output.injected
    # event when patterns are found; redacts inline so the agent
    # sees the redaction marker rather than the attacker payload.
    # See strix/agents/safety/output_sanitizer.py.
    try:
        from strix.agents.safety.output_sanitizer import sanitize_tool_output

        final_result_str, _detections = sanitize_tool_output(
            final_result_str, tool_name=tool_name,
        )
    except Exception:  # noqa: BLE001
        # Sanitiser must NEVER fail the tool call. Log + continue.
        logger.debug("sanitize_tool_output failed", exc_info=True)

    observation_xml = (
        f"<tool_result>\n<tool_name>{tool_name}</tool_name>\n"
        f"<result>{final_result_str}</result>\n</tool_result>"
    )

    return observation_xml, images


async def _execute_single_tool(
    tool_inv: dict[str, Any],
    agent_state: Any | None,
    tracer: Any | None,
    agent_id: str,
) -> tuple[str, list[dict[str, Any]], bool]:
    tool_name = tool_inv.get("toolName", "unknown")
    args = tool_inv.get("args", {})
    execution_id = None
    should_agent_finish = False

    if tracer:
        execution_id = tracer.log_tool_execution_start(agent_id, tool_name, args)

    # Roadmap §8.5 — architectural-commitment guard. The single-lead
    # architecture (LeadAgent + filtered catalog) declares that the
    # lead must NEVER spawn sub-agents — that's the architectural
    # difference from parent-spawns-N. The catalog allowlist surfaces
    # this in the lead's prompt context, but `get_tools_prompt()`
    # currently renders the FULL tool registry, so the model sees
    # `create_agent`'s schema and naturally calls it. Without this
    # guard the architecture devolves to legacy mode at runtime.
    #
    # We refuse the call here (rather than at prompt-render time)
    # because:
    #   1. The model sees a structured error, not silent disappearance
    #      — it can adapt within the same conversation.
    #   2. One enforcement point covers all entry paths (XML tool
    #      call, recovery retry, hypothetical future tool-call format).
    #   3. The error message names the right alternative tools, so
    #      the next iteration moves toward direct probing.
    if (
        tool_name in _LEAD_BLOCKED_TOOLS
        and agent_state is not None
        and getattr(agent_state, "category", None) == "lead"
    ):
        block_msg = (
            f"Tool {tool_name!r} is blocked under the single-lead "
            f"architecture (roadmap §8.5). The lead must probe "
            f"directly using its tool catalog: scan_misconfig, "
            f"scan_xss, scan_sqli, send_request, browser_action, "
            f"http_security_headers_audit, csrf_check, jwt_audit, "
            f"open_redirect_check, etc. Sub-agent spawning is "
            f"architecturally disabled. Re-attempt with a direct "
            f"probe instead."
        )
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", block_msg)
        observation_xml = (
            f"<tool_result>\n<tool_name>{tool_name}</tool_name>\n"
            f"<error>{block_msg}</error>\n</tool_result>"
        )
        return observation_xml, [], False

    try:
        result = await execute_tool_invocation(tool_inv, agent_state)

        is_error, error_payload = _check_error_result(result)

        if (
            tool_name in ("finish_scan", "agent_finish")
            and not is_error
            and isinstance(result, dict)
        ):
            if tool_name == "finish_scan":
                should_agent_finish = result.get("scan_completed", False)
            elif tool_name == "agent_finish":
                should_agent_finish = result.get("agent_completed", False)

        _update_tracer_with_result(tracer, execution_id, is_error, result, error_payload)

    except (ConnectionError, RuntimeError, ValueError, TypeError, OSError) as e:
        error_msg = str(e)
        if tracer and execution_id:
            tracer.update_tool_execution(execution_id, "error", error_msg)
        raise

    observation_xml, images = _format_tool_result(
        tool_name, result, execution_id=execution_id,
    )
    return observation_xml, images, should_agent_finish


def _get_tracer_and_agent_id(agent_state: Any | None) -> tuple[Any | None, str]:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        agent_id = agent_state.agent_id if agent_state else "unknown_agent"
    except (ImportError, AttributeError):
        tracer = None
        agent_id = "unknown_agent"

    return tracer, agent_id


async def process_tool_invocations(
    tool_invocations: list[dict[str, Any]],
    conversation_history: list[dict[str, Any]],
    agent_state: Any | None = None,
) -> bool:
    """Execute a batch of tool invocations and append results to the
    conversation history.

    Phase 1.7 — execute the batch concurrently when:
      * `len(tool_invocations) > 1` (no benefit for single calls), AND
      * `STRIX_PARALLEL_TOOL_DISPATCH != "0"` (env-flag escape hatch)
    Each invocation goes through `_execute_single_tool` which is
    async-safe (the inner `execute_tool_invocation` either awaits a
    sandbox HTTP call or runs the synchronous tool body in-process).
    The SecurityContext singleton is thread-safe via its internal
    `_lock`.

    Order preservation: results are emitted into `observation_parts`
    in the same index order as `tool_invocations` so the conversation
    history reads naturally even when the underlying execution
    interleaved.
    """
    observation_parts: list[str | None] = [None] * len(tool_invocations)
    all_images: list[dict[str, Any]] = []
    should_agent_finish = False

    tracer, agent_id = _get_tracer_and_agent_id(agent_state)

    parallel_disabled = os.environ.get("STRIX_PARALLEL_TOOL_DISPATCH", "1").strip() == "0"

    if len(tool_invocations) > 1 and not parallel_disabled:
        import asyncio as _asyncio

        async def _run_one(idx: int, inv: dict[str, Any]) -> tuple[int, str, list[dict], bool]:
            obs, imgs, finish = await _execute_single_tool(
                inv, agent_state, tracer, agent_id
            )
            return idx, obs, imgs, finish

        tasks = [_run_one(i, inv) for i, inv in enumerate(tool_invocations)]
        results = await _asyncio.gather(*tasks, return_exceptions=False)
        for idx, obs, imgs, finish in results:
            observation_parts[idx] = obs
            all_images.extend(imgs)
            if finish:
                should_agent_finish = True
    else:
        for i, tool_inv in enumerate(tool_invocations):
            observation_xml, images, tool_should_finish = await _execute_single_tool(
                tool_inv, agent_state, tracer, agent_id
            )
            observation_parts[i] = observation_xml
            all_images.extend(images)
            if tool_should_finish:
                should_agent_finish = True

    obs_strs = [o for o in observation_parts if o is not None]

    if all_images:
        content = [{"type": "text", "text": "Tool Results:\n\n" + "\n\n".join(obs_strs)}]
        content.extend(all_images)
        conversation_history.append({"role": "user", "content": content})
    else:
        observation_content = "Tool Results:\n\n" + "\n\n".join(obs_strs)
        conversation_history.append({"role": "user", "content": observation_content})

    return should_agent_finish


def extract_screenshot_from_result(result: Any) -> str | None:
    if not isinstance(result, dict):
        return None

    screenshot = result.get("screenshot")
    if isinstance(screenshot, str) and screenshot:
        return screenshot

    return None


def remove_screenshot_from_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result

    result_copy = result.copy()
    if "screenshot" in result_copy:
        result_copy["screenshot"] = "[Image data extracted - see attached image]"

    return result_copy
