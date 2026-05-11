"""Inner-LLM orchestrator for `llm=True` specialist tools (Phase 3b).

When a specialist is declared with `llm=True`, calling it from the
lead's tool catalog routes through this module instead of invoking
the procedural probe function directly.

## v0 — adaptive-retry pattern

The full Phase 3b vision (per `strix/agents/lead_agent/lead_agent.py`
docstring + `single-agent.md` B.9) is a bounded inner-LLM loop with
its own tool catalog, multi-round reasoning, payload adaptation,
and findings emission. That's substantial — every round adds
LLM-orchestration complexity (parsing tool_calls, executing them
against the strix tool registry, threading agent_state, accounting
budget across rounds).

This v0 ships the **smallest useful slice**: a single
adaptive-retry call. The protocol is:

```
1. Call the procedural specialist (existing llm=False behaviour).
2. If it emitted findings: return as-is (cheap, no LLM cost).
3. If it emitted 0 findings: spend ONE LLM call on a structured
   "suggest an adapted retry" decision. Parse the LLM's JSON
   reply, call the procedural specialist again with the adapted
   args, return that result.
```

The empirical pain point this addresses is "first-pass probe
corpus misses on a clearly-reflective endpoint" — under legacy,
the SQLi specialist would have a sub-agent that observes the
empty result, reasons about it, and tries a different angle.
Under single-lead v0 (Phase 3a, `llm=False`), there's no second
attempt. This v0 adds exactly one structured retry, gated on
the procedural probe coming back empty.

Cost shape: at most ONE additional inner-LLM call (~$0.005 on
Gemini Flash, ~$0.02 on Claude Sonnet) per specialist invocation
that returned 0 findings.

## What v0 does NOT do (left for v1+)

* Multi-round reasoning — only one adaptive retry per call.
* Inner tool dispatch — the inner LLM can't call arbitrary tools;
  it can only suggest adapted args for the SAME procedural
  specialist function.
* Streaming / async — synchronous wrap.
* Memory / cache_manager — system prompts are loaded fresh per
  call. Prompt-caching at the litellm layer still applies if the
  underlying model supports it.

When v1 lands a real multi-round inner loop, the lead-side
contract stays identical (`scan_xss(url=...)` → `SpecialistResult`)
so this module is the only thing that changes.

## Kill switch

Set `STRIX_SPECIALIST_INNER_LLM_DISABLED=1` to force every
`llm=True` specialist back to direct procedural invocation.
The wrapper in `register_specialist_tool` checks this BEFORE
routing to the orchestrator. Useful for A/B benchmark runs
(Phase 3b vs Phase 3a) and for safe roll-backs.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable

from strix.tools.specialist.result import SpecialistResult


logger = logging.getLogger(__name__)


# Module-level prompt cache. Loaded on first use per specialist;
# refreshed only on process restart. The cache_manager (Phase 2)
# will eventually own this — for v0 it's a simple dict.
_PROMPT_CACHE: dict[str, str] = {}


def is_inner_llm_disabled() -> bool:
    """Honour `STRIX_SPECIALIST_INNER_LLM_DISABLED=1` as a kill
    switch. Used by the decorator before routing to this module."""
    return os.environ.get(
        "STRIX_SPECIALIST_INNER_LLM_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _resolve_prompt_path(rel_or_abs: str) -> Path:
    """The decorator can take either an absolute path or a path
    relative to the strix package root. Resolve to absolute.

    Why a path (not embedded string): keeps the prompts editable
    without code changes, and lets the wrapper team mount a
    customised prompt over the bundled one via a volume mount
    + an env-var override (v1 work)."""
    p = Path(rel_or_abs)
    if p.is_absolute() and p.exists():
        return p
    # Try resolving against the strix package root.
    pkg_root = Path(__file__).resolve().parents[2]   # …/strix/
    candidate = pkg_root / rel_or_abs
    if candidate.exists():
        return candidate
    # Try resolving against the strix-installed-as-package layout
    # (e.g. site-packages/strix/...).
    candidate2 = Path(__file__).resolve().parent.parent.parent / rel_or_abs
    if candidate2.exists():
        return candidate2
    return Path(rel_or_abs)


def _load_system_prompt(path_str: str) -> str | None:
    """Load + cache. Returns None when the file can't be read —
    the orchestrator will short-circuit to direct procedural call."""
    if path_str in _PROMPT_CACHE:
        return _PROMPT_CACHE[path_str]
    p = _resolve_prompt_path(path_str)
    try:
        contents = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.warning(
            "specialist inner-LLM: failed to load system prompt "
            "from %s (%s) — falling back to direct procedural call",
            path_str, e,
        )
        return None
    _PROMPT_CACHE[path_str] = contents
    return contents


def _format_task_message(
    specialist_name: str,
    task_args: dict[str, Any],
    procedural_result: dict[str, Any],
) -> str:
    """Build the user message for the inner LLM. Carries the
    initial task args + the empty-result evidence the LLM needs
    to reason about an adapted retry."""
    # Trim large fields so we don't blow up the inner-LLM context
    # with body templates / response payloads.
    summarised_args = {
        k: v for k, v in task_args.items()
        if k not in {"body_template", "extra_headers"}
    }
    # The procedural result's `evidence` / `next_probes_suggested`
    # are the most informative bits for a retry decision.
    return json.dumps(
        {
            "specialist": specialist_name,
            "initial_args": summarised_args,
            "first_pass_result": {
                "status": procedural_result.get("status"),
                "findings_count": len(procedural_result.get("findings") or []),
                "error": procedural_result.get("error"),
                "evidence_summary": (procedural_result.get("evidence") or [])[:5],
                "next_probes_suggested": (
                    procedural_result.get("next_probes_suggested") or []
                )[:5],
                "tool_metadata": procedural_result.get("tool_metadata") or {},
            },
        },
        indent=2,
        default=str,
    )


def _call_inner_llm(
    *,
    system_prompt: str,
    user_message: str,
    model: str,
    timeout_seconds: int = 30,
) -> dict[str, Any] | None:
    """One synchronous litellm call. Returns the LLM's parsed JSON
    suggestion or None when the call / parse failed.

    Why litellm directly (not strix.llm.LLM): the strix LLM class
    is wrapped in agent-loop semantics (state, memory_compressor,
    tracer integration). The inner-LLM specialist is intentionally
    stateless — a one-shot decision call. Going to litellm directly
    keeps cost / latency low and avoids cross-contaminating the
    parent agent's state."""
    try:
        import litellm
    except ImportError:
        logger.warning("litellm not importable; inner-LLM disabled")
        return None

    try:
        resp = litellm.completion(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,        # Deterministic-ish retries.
            max_tokens=600,         # JSON reply is small.
            timeout=timeout_seconds,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "specialist inner-LLM call failed (%s: %s) — falling "
            "back to direct result",
            type(e).__name__, e,
        )
        return None

    content = (
        getattr(resp.choices[0].message, "content", None) or ""
        if getattr(resp, "choices", None) else ""
    )
    if not content:
        return None
    return _parse_suggestion_json(content)


def _parse_suggestion_json(content: str) -> dict[str, Any] | None:
    """The system prompt asks for a strict-JSON reply. Models
    sometimes wrap it in ```json fences or add prefatory prose;
    we strip both. Returns None when the content can't be parsed
    into a dict — that's a signal to fall back to no-retry."""
    s = content.strip()
    # Strip code fences.
    if s.startswith("```"):
        lines = s.splitlines()
        # Drop the first line (```json or ```) and a closing fence
        # if present.
        s = "\n".join(
            line for line in lines[1:]
            if not line.strip().startswith("```")
        )
    # Find the first '{' and last '}' — handles prefatory prose.
    first = s.find("{")
    last = s.rfind("}")
    if first < 0 or last < first:
        return None
    s = s[first : last + 1]
    try:
        parsed = json.loads(s)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _merge_retry_args(
    original_args: dict[str, Any],
    suggestion: dict[str, Any],
) -> dict[str, Any]:
    """Apply the LLM's suggestion to the original args. Only
    accept keys the original call already used + a known retry-safe
    allowlist. This prevents the LLM from injecting unexpected args
    that the procedural function would reject."""
    # Allowlist of fields the LLM is permitted to override / add.
    # Matches the union of XSS / SQLi / IDOR procedural signatures.
    retry_safe_keys = {
        "url", "urls", "params", "param", "method", "body_template",
        "body_format", "owner_label", "other_params",
    }
    merged = dict(original_args)
    for k, v in suggestion.items():
        if k in retry_safe_keys:
            merged[k] = v
    return merged


def run_inner_llm_specialist(
    *,
    procedural_func: Callable[..., Any],
    specialist_name: str,
    category: str,
    system_prompt_path: str | None,
    default_budget: dict[str, Any] | None,
    task_args: dict[str, Any],
) -> dict[str, Any]:
    """Entry point used by `register_specialist_tool` when llm=True.

    Returns a SpecialistResult-shaped dict. On any internal failure
    (prompt-load, LLM call, parse, retry) the function returns the
    direct procedural result rather than raising — the wrapper
    treats this as a strictly-optional optimization layer.
    """
    started = time.monotonic()
    budget = default_budget or {}
    cost_cap = float(budget.get("cost_usd", 0.0) or 0.0)
    wall_cap = float(budget.get("max_wall_seconds", 90) or 90)

    # 1. Always run the procedural function first.
    procedural_result = procedural_func(**task_args)
    if not isinstance(procedural_result, dict):
        # Schema-coerced result is expected to be a dict; fall through.
        return procedural_result if procedural_result is not None else (
            SpecialistResult(
                status="error",
                error="procedural specialist returned None",
            ).model_dump()
        )

    findings = procedural_result.get("findings") or []
    if findings:
        # Already found something — no inner-LLM cost needed.
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": False, "reason": "first_pass_had_findings"}
        return procedural_result

    if time.monotonic() - started > wall_cap:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": False, "reason": "wall_time_exhausted_first_pass"}
        return procedural_result

    # 2. First pass found nothing. Consult inner LLM for an adapted
    # retry suggestion.
    if not system_prompt_path:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": False, "reason": "no_system_prompt_configured"}
        return procedural_result

    system_prompt = _load_system_prompt(system_prompt_path)
    if not system_prompt:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": False, "reason": "system_prompt_unreadable"}
        return procedural_result

    model = _resolve_inner_llm_model()
    if not model:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": False, "reason": "no_model_configured"}
        return procedural_result

    user_msg = _format_task_message(
        specialist_name, task_args, procedural_result,
    )
    suggestion = _call_inner_llm(
        system_prompt=system_prompt,
        user_message=user_msg,
        model=model,
    )
    if not suggestion:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": True, "reason": "llm_call_or_parse_failed"}
        return procedural_result

    # 3. If the LLM explicitly says "no retry productive", honour it.
    if suggestion.get("retry") is False:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {
            "engaged": True,
            "reason": "llm_decided_no_retry",
            "llm_reasoning": suggestion.get("reasoning"),
        }
        return procedural_result

    # 4. Apply the suggestion and re-run procedural.
    retry_args = _merge_retry_args(task_args, suggestion)
    if retry_args == task_args:
        # Suggestion was a no-op; treat as no-retry.
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": True, "reason": "suggestion_was_noop"}
        return procedural_result

    if time.monotonic() - started > wall_cap:
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {"engaged": True, "reason": "wall_time_exhausted_before_retry"}
        return procedural_result

    try:
        retry_result = procedural_func(**retry_args)
    except TypeError as e:
        # Suggestion contained an arg the procedural func doesn't
        # accept. Surface to telemetry; keep original result.
        logger.warning(
            "specialist inner-LLM retry rejected by procedural "
            "signature: %s", e,
        )
        procedural_result.setdefault("tool_metadata", {})[
            "inner_llm_retry"
        ] = {
            "engaged": True,
            "reason": "retry_args_invalid",
            "retry_args_attempted": _redact_for_log(retry_args),
        }
        return procedural_result

    if not isinstance(retry_result, dict):
        return procedural_result

    retry_findings = retry_result.get("findings") or []
    retry_result.setdefault("tool_metadata", {})[
        "inner_llm_retry"
    ] = {
        "engaged": True,
        "reason": "retry_executed",
        "retry_findings_count": len(retry_findings),
        "retry_args_diff": {
            k: v for k, v in retry_args.items() if k not in task_args
            or task_args.get(k) != v
        },
        "llm_reasoning": suggestion.get("reasoning"),
        "cost_cap_usd": cost_cap,
    }
    return retry_result


def _resolve_inner_llm_model() -> str | None:
    """Use the same model the parent run is using. Read directly
    from STRIX_LLM (set at process start by interface/main.py).

    Future v1 enhancement: allow per-specialist model override
    via an env var like `STRIX_INNER_LLM_MODEL` so wrappers can
    route adaptive retries to a cheaper / faster model than the
    one the lead is using."""
    override = os.environ.get("STRIX_INNER_LLM_MODEL", "").strip()
    if override:
        return override
    primary = os.environ.get("STRIX_LLM", "").strip()
    return primary or None


def _redact_for_log(args: dict[str, Any]) -> dict[str, Any]:
    """Trim large fields before logging the failed-retry args."""
    redacted = {}
    for k, v in args.items():
        if k in {"body_template", "extra_headers", "other_params"}:
            redacted[k] = f"<{type(v).__name__}>"
        elif isinstance(v, str) and len(v) > 100:
            redacted[k] = v[:100] + "…"
        else:
            redacted[k] = v
    return redacted


def reset_prompt_cache_for_tests() -> None:
    """Test-only helper."""
    _PROMPT_CACHE.clear()
