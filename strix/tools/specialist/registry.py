"""`@register_specialist_tool` decorator + introspection (roadmap §8.5
Phase 1 / single-agent.md B.1, B.2, B.8).

Two tool classes per single-agent.md B.1:

  * **Deterministic specialist-tools** (`llm=False`) — pure-Python
    checks with no internal LLM call. Cache manager not needed.
    First Phase 1 migration target (e.g. `scan_misconfig`).

  * **LLM-driven specialist-tools** (`llm=True`) — internally fire a
    bounded LLM loop with a cached system prompt. Phase 3 lands the
    first three (XSS / SQLi / IDOR). Phase 1 only enforces the
    decorator's `system_prompt_path` requirement; the inner-LLM
    invocation machinery is built later.

Properties enforced (single-agent.md §2.2):

  1. **Bounded input** (B.2). The decorator validates that the
     wrapped function does NOT accept a `messages` /
     `conversation_history` / `parent_context` / `history` arg —
     specialists take typed args, never inherited conversation
     state. Without this rule the cost-pricing argument collapses
     (the inner LLM is back to paying cache-miss on a 700K dump).

  2. **Cached system prompt** (LLM class only — Phase 2 ships the
     cache_manager). The decorator validates that `llm=True` carries
     a `system_prompt_path`; `llm=False` carries None.

  3. **Structured output schema** (B.8). The wrapper coerces the
     return value to `SpecialistResult` (or the configured
     `output_schema`). Failures fall back to `status="error"` rather
     than crashing the lead loop.

Wrapper-side impact: zero. Specialist-tools register through the
existing `@register_tool` mechanism so they appear in the agent's
tool catalog; their typed result shape is internal to the §8.5
single-lead architecture.
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from strix.tools.specialist.result import SpecialistResult, coerce_to_result


logger = logging.getLogger(__name__)


# Bounded-input rule (B.2). Specialist-tools must NOT accept
# conversation-history-shaped args. The list is exhaustive enough to
# catch the common mistake; new shapes can be added without a
# schema bump (it's purely an internal validation list).
_FORBIDDEN_BOUNDED_INPUT_ARGS = frozenset({
    "messages",
    "conversation_history",
    "parent_context",
    "history",
    "chat_history",
    "context",  # too broad — but reserved for documentation
})

# Special-case: `agent_state` IS allowed because the existing
# `register_tool` plumbing injects it; `category` IS allowed because
# the specialist may want to log its own category. None of those
# carry conversation history.
_ALLOWED_FRAMEWORK_ARGS = frozenset({
    "agent_state",
    "category",
})


@dataclass
class SpecialistDescriptor:
    """Registry record for a `@register_specialist_tool`-decorated
    function. Used by §8.5 introspection (which specialist-tools are
    registered, their LLM class, their cached-tool subset)."""

    name: str
    category: str
    llm: bool
    output_schema: type
    default_budget: dict[str, Any] | None = None
    cache_ttl_seconds: int = 3600
    cached_tool_subset: list[str] | None = None
    async_capable: bool = False
    system_prompt_path: str | None = None
    sandbox_execution: bool = False
    provenance: str = "framework"
    func: Callable[..., Any] | None = field(default=None, repr=False)


# Module-level registry. Indexed by function name (the tool name as
# the agent sees it).
_SPECIALIST_REGISTRY: dict[str, SpecialistDescriptor] = {}


def _validate_bounded_input(func: Callable[..., Any]) -> None:
    """Raises ValueError if the function signature violates B.2.
    Inspection runs at decorator-time so misuse is caught at import."""
    sig = inspect.signature(func)
    for param_name in sig.parameters:
        if param_name in _ALLOWED_FRAMEWORK_ARGS:
            continue
        if param_name in _FORBIDDEN_BOUNDED_INPUT_ARGS:
            raise ValueError(
                f"Specialist-tool {func.__name__!r} accepts a forbidden "
                f"bounded-input arg: {param_name!r}. Specialist-tools "
                f"must take typed args only — never inherited conversation "
                f"history (single-agent.md B.2). Pass the relevant context "
                f"as typed Pydantic args (URL, params, auth_session, "
                f"target_summary, ...)."
            )


def _validate_llm_args(
    *, llm: bool, system_prompt_path: str | None, func_name: str,
) -> None:
    """LLM-class consistency. `llm=True` requires a cached system
    prompt; `llm=False` rejects one (no inner-LLM invocation, so
    a system prompt would be dead weight)."""
    if llm and not system_prompt_path:
        raise ValueError(
            f"Specialist-tool {func_name!r} declared llm=True but "
            f"system_prompt_path is None. LLM-driven specialists "
            f"require a cached system prompt path (single-agent.md "
            f"B.2). Phase 2 ships the cache_manager that registers "
            f"these prompts."
        )
    if not llm and system_prompt_path:
        raise ValueError(
            f"Specialist-tool {func_name!r} declared llm=False but "
            f"system_prompt_path={system_prompt_path!r}. Deterministic "
            f"specialists don't invoke an inner LLM — drop the prompt "
            f"path or set llm=True."
        )


def register_specialist_tool(  # noqa: PLR0913
    *,
    category: str,
    llm: bool,
    output_schema: type = SpecialistResult,
    default_budget: dict[str, Any] | None = None,
    cache_ttl_seconds: int = 3600,
    cached_tool_subset: list[str] | None = None,
    async_capable: bool = False,
    system_prompt_path: str | None = None,
    sandbox_execution: bool = False,
    provenance: str = "framework",
    mitre_techniques: list[str] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: register a function as a §8.5 specialist-tool.

    The wrapped function is ALSO registered via the existing
    `@register_tool` so the agent can call it normally. The
    `SpecialistDescriptor` is stored in `_SPECIALIST_REGISTRY` for
    §8.5 introspection (`list_specialist_tools`,
    `get_specialist_descriptor`).

    Args:
        category: hyphenated specialist category (e.g.
            "misconfig-specialist", "xss-specialist"). Must match
            a #89 `SpecialistProfile.category` when the specialist
            corresponds to one (it's a soft convention, not enforced).
        llm: True for LLM-driven specialists, False for deterministic.
            Per single-agent.md B.1.
        output_schema: Pydantic model for the return value. Defaults
            to `SpecialistResult`. Coercion via `coerce_to_result`.
        default_budget: cost / token / wall-time caps. Same shape as
            #88 `AgentState.set_budget()`. Phase 1 records but doesn't
            enforce — Phase 3 lead-agent loop reads + enforces.
        cache_ttl_seconds: how long the cached system prompt lives
            (LLM class only). Phase 2 reads.
        cached_tool_subset: explicit list of tool names the inner
            LLM can invoke. Bounded inner-LLM tool catalog (B.9).
            Phase 3 reads.
        async_capable: True if the tool returns `task_id` immediately
            (B.5 / §2.7). Phase 6 wires lifecycle.
        system_prompt_path: required for `llm=True`; rejected for
            `llm=False`.
        sandbox_execution: pass-through to `register_tool`.
        provenance: pass-through to `register_tool` (defaults to
            "framework" — specialists are in-process orchestrators).
        mitre_techniques: pass-through to `register_tool`.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        _validate_bounded_input(func)
        _validate_llm_args(
            llm=llm,
            system_prompt_path=system_prompt_path,
            func_name=func.__name__,
        )

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            import time as _time
            started = _time.monotonic()
            try:
                if llm and _should_route_to_inner_llm():
                    # Phase 3b — `llm=True` specialists route through
                    # the inner-LLM orchestrator (one adaptive retry
                    # when the first pass returns 0 findings). The
                    # orchestrator handles its own fallback to
                    # direct call on any internal failure, so this
                    # path is safe-by-default. Kill switch:
                    # STRIX_SPECIALIST_INNER_LLM_DISABLED=1.
                    from strix.tools.specialist.llm_orchestrator import (
                        run_inner_llm_specialist,
                    )
                    raw = run_inner_llm_specialist(
                        procedural_func=func,
                        specialist_name=func.__name__,
                        category=category,
                        system_prompt_path=system_prompt_path,
                        default_budget=default_budget,
                        task_args=kwargs,
                    )
                else:
                    raw = func(*args, **kwargs)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "specialist-tool %s raised: %s",
                    func.__name__, e, exc_info=True,
                )
                err_result = output_schema(
                    status="error",
                    error=f"{type(e).__name__}: {e}",
                ).model_dump()
                _emit_telemetry(
                    func.__name__, category, args, kwargs,
                    err_result, _time.monotonic() - started,
                )
                return err_result

            # Coerce output to schema dict.
            try:
                if isinstance(raw, output_schema):
                    coerced = raw.model_dump()
                elif isinstance(raw, dict):
                    coerced = output_schema(**raw).model_dump()
                elif hasattr(raw, "model_dump") and callable(raw.model_dump):
                    coerced = raw.model_dump()
                else:
                    coerced = output_schema(
                        status="error",
                        error=(
                            f"specialist returned unexpected type: "
                            f"{type(raw).__name__}"
                        ),
                    ).model_dump()
            except Exception as e:  # noqa: BLE001
                logger.debug(
                    "specialist-tool %s output coercion failed: %s",
                    func.__name__, e,
                )
                coerced = output_schema(
                    status="error",
                    error=(
                        f"output coercion failed: "
                        f"{type(e).__name__}: {e}"
                    ),
                ).model_dump()

            _emit_telemetry(
                func.__name__, category, args, kwargs,
                coerced, _time.monotonic() - started,
            )
            return coerced

        descriptor = SpecialistDescriptor(
            name=func.__name__,
            category=category,
            llm=llm,
            output_schema=output_schema,
            default_budget=dict(default_budget) if default_budget else None,
            cache_ttl_seconds=cache_ttl_seconds,
            cached_tool_subset=list(cached_tool_subset) if cached_tool_subset else None,
            async_capable=async_capable,
            system_prompt_path=system_prompt_path,
            sandbox_execution=sandbox_execution,
            provenance=provenance,
            func=wrapper,
        )
        _SPECIALIST_REGISTRY[func.__name__] = descriptor

        # Also register via the existing tool plumbing so the
        # specialist-tool appears in the agent's tool catalog.
        from strix.tools.registry import register_tool

        registered = register_tool(
            sandbox_execution=sandbox_execution,
            provenance=provenance,
            mitre_techniques=mitre_techniques,
        )(wrapper)
        return registered

    return decorator


# ---------------------------------------------------------------------------
# Introspection helpers
# ---------------------------------------------------------------------------


def get_specialist_descriptor(name: str) -> SpecialistDescriptor | None:
    """Look up a registered specialist by tool-function name."""
    return _SPECIALIST_REGISTRY.get(name)


def list_specialist_tools(*, llm_only: bool | None = None) -> list[str]:
    """Return registered specialist-tool names. Filter by class via
    `llm_only=True` (LLM-driven only) / `llm_only=False` (deterministic
    only) / `llm_only=None` (both)."""
    if llm_only is None:
        return sorted(_SPECIALIST_REGISTRY.keys())
    return sorted(
        name for name, d in _SPECIALIST_REGISTRY.items() if d.llm == llm_only
    )


def list_specialists_by_category() -> dict[str, list[str]]:
    """Group registered specialist-tools by `category`. Useful for
    Phase 3 per-target-type catalog filtering (B.9 / §2.8)."""
    out: dict[str, list[str]] = {}
    for name, d in _SPECIALIST_REGISTRY.items():
        out.setdefault(d.category, []).append(name)
    for k in out:
        out[k].sort()
    return out


def reset_registry_for_tests() -> None:
    """Test-only helper. Clears the module-level registry between
    test cases that register conflicting categories."""
    _SPECIALIST_REGISTRY.clear()


def _should_route_to_inner_llm() -> bool:
    """Phase 3b dispatch gate. Returns False when the kill-switch
    env var is set, otherwise True.

    Lives here (not in llm_orchestrator) so the decorator can
    check it cheaply BEFORE importing the orchestrator module —
    keeps the llm=False codepath import-free of any LLM machinery."""
    import os
    return os.environ.get(
        "STRIX_SPECIALIST_INNER_LLM_DISABLED", ""
    ).lower() not in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Phase 5.4 telemetry hook
# ---------------------------------------------------------------------------


def _emit_telemetry(
    tool_name: str, category: str,
    args: tuple, kwargs: dict[str, Any],
    result_dict: dict[str, Any],
    elapsed_seconds: float,
) -> None:
    """Best-effort telemetry hook called after every specialist
    invocation. Extracts target/params from kwargs and forwards to
    `strix.agents.specialist_telemetry.record_specialist_call`.

    Failures swallowed — telemetry must never break a specialist
    call. We import inside the function so a circular import or
    missing module never propagates."""
    try:
        from strix.agents.specialist_telemetry import (
            record_specialist_call,
        )
    except Exception:  # noqa: BLE001
        return
    try:
        # Most specialists take target via `url=` or `urls=`. Both
        # shapes are common; record whichever is present.
        target = ""
        for key in ("url", "urls", "login_url", "target"):
            v = kwargs.get(key)
            if isinstance(v, str) and v:
                target = v
                break
            if isinstance(v, list) and v:
                target = str(v[0])
                break
        # Params shape varies — `params=[...]` or `param="..."`.
        params: list[str] = []
        if isinstance(kwargs.get("params"), list):
            params = [str(p) for p in kwargs["params"]]
        elif isinstance(kwargs.get("params"), str):
            params = [kwargs["params"]]
        elif isinstance(kwargs.get("param"), str):
            params = [kwargs["param"]]
        # Args summary excludes large-shape fields that bloat the row.
        args_summary = {
            k: v for k, v in kwargs.items()
            if k not in {"body_template", "extra_headers", "other_params"}
        }
        record_specialist_call(
            tool_name=tool_name,
            category=category,
            target=target,
            params=params,
            args=args_summary,
            result=result_dict,
            elapsed_seconds=elapsed_seconds,
        )
    except Exception:  # noqa: BLE001
        # Swallow; telemetry must never break the call.
        pass

    # Phase 5.3 — counter-example logging. When this call EMITTED a
    # finding, walk the telemetry stream for misses on the same
    # endpoint by other tools and log the (caught_by, missed_by) pair.
    try:
        findings = result_dict.get("findings") or []
        if isinstance(findings, list) and findings:
            from strix.agents.specialist_misses import (
                record_caught_finding,
            )
            for f in findings:
                if not isinstance(f, dict):
                    continue
                endpoint = f.get("endpoint") or target
                if not endpoint:
                    continue
                record_caught_finding(
                    endpoint=str(endpoint),
                    caught_by_tool=tool_name,
                    caught_by_category=category,
                    caught_finding=f,
                    caught_params=params,
                )
    except Exception:  # noqa: BLE001
        pass
