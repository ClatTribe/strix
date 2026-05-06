"""`check_budget` agent-callable tool (roadmap §8.5 Phase 3 / §2.9).

Surfaces remaining cost / token / wall-time budget plus context-window
utilisation so the lead agent can self-throttle before the quality
knee. Per [`single-agent.md §2.9`](single-agent.md), the lead's
system prompt instructs:

  > When `cost_usd_remaining` falls below `0.20` AND
  > `findings_emitted` is below baseline expectation, prioritise the
  > highest-leverage remaining specialist-tool over breadth.
  >
  > When `context_window_utilisation` exceeds `0.50`, prefer
  > specialist-tools that emit findings and clear hypotheses over
  > broad recon. When it exceeds `0.55`, call `compact_context()`
  > proactively before the next big specialist-tool call.

This is what makes incident #147's "$2.50 cap exhausted with 0
findings" self-correctable.

Wrapper-side impact: zero. The tool is internal — it reads existing
state (run_budget, cache_manager stats, agent conversation length).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Per-provider context-window thresholds (single-agent.md §2.5.2).
# "Compact at 60% of advertised window" deliberately undershoots the
# lost-in-the-middle quality knee (Liu et al. 2023).
_CONTEXT_WINDOWS_BY_MODEL_FRAGMENT: tuple[tuple[str, int], ...] = (
    # (substring, context window in tokens)
    ("claude-opus-4", 1_000_000),
    ("claude-sonnet-4", 200_000),
    ("claude-3-5-sonnet", 200_000),
    ("claude-3-5-haiku", 200_000),
    ("gpt-5", 256_000),
    ("o3", 256_000),
    ("o1", 256_000),
    ("gemini-2.5-pro", 2_000_000),
    ("gemini-3-pro", 1_000_000),
    ("gemini-1.5-pro", 2_000_000),
)
_DEFAULT_CONTEXT_WINDOW = 128_000
_COMPACTION_THRESHOLD_FRACTION = 0.60


def _detect_context_window(model: str | None) -> int:
    """Map a model name to its advertised context window. Falls back
    to a conservative default when unknown."""
    if not isinstance(model, str) or not model:
        return _DEFAULT_CONTEXT_WINDOW
    m = model.lower()
    for fragment, window in _CONTEXT_WINDOWS_BY_MODEL_FRAGMENT:
        if fragment in m:
            return window
    return _DEFAULT_CONTEXT_WINDOW


@register_tool(sandbox_execution=False, provenance="framework")
def check_budget(agent_state: Any = None) -> dict[str, Any]:  # noqa: PLR0915
    """Return the lead-agent's current budget + context utilisation.

    Returns:
        ```python
        {
            "cost_usd_consumed": float,
            "cost_usd_cap": float,                   # 0 = unlimited
            "cost_usd_remaining": float | None,
            "input_tokens_consumed": int,
            "input_tokens_cap": int,
            "wall_seconds_elapsed": int,
            "wall_seconds_cap": int,                 # 0 = unlimited
            "cache_hit_ratio": float,                # 0.0-1.0
            "context_tokens_active": int,            # hot+warm in conversation
            "context_window_cap": int,               # provider-dependent
            "context_window_utilisation": float,     # active/cap
            "context_compaction_threshold": float,   # default 0.60
            "compactions_so_far": int,
            "findings_emitted": int,                 # for self-correction
        }
        ```

    Best-effort throughout. Any subsystem failure returns the field
    with a conservative default (zero / None) rather than raising.
    """
    out: dict[str, Any] = {
        "cost_usd_consumed": 0.0,
        "cost_usd_cap": 0.0,
        "cost_usd_remaining": None,
        "input_tokens_consumed": 0,
        "input_tokens_cap": 0,
        "wall_seconds_elapsed": 0,
        "wall_seconds_cap": 0,
        "cache_hit_ratio": 0.0,
        "context_tokens_active": 0,
        "context_window_cap": _DEFAULT_CONTEXT_WINDOW,
        "context_window_utilisation": 0.0,
        "context_compaction_threshold": _COMPACTION_THRESHOLD_FRACTION,
        "compactions_so_far": 0,
        "findings_emitted": 0,
    }

    # Run-level cost / token caps (#113).
    try:
        from strix.llm.run_budget import get_run_caps, get_run_total

        caps = get_run_caps()
        total = get_run_total()
        cost_consumed = float(total.get("cost_usd", 0.0))
        cost_cap = float(caps.get("max_cost_usd", 0.0))
        out["cost_usd_consumed"] = round(cost_consumed, 6)
        out["cost_usd_cap"] = cost_cap
        if cost_cap > 0:
            out["cost_usd_remaining"] = round(max(0.0, cost_cap - cost_consumed), 6)
        out["input_tokens_consumed"] = int(total.get("input_tokens", 0))
        out["input_tokens_cap"] = int(caps.get("max_input_tokens", 0))
    except Exception:  # noqa: BLE001
        logger.debug("check_budget: run_budget read failed", exc_info=True)

    # Wall-time elapsed (per-agent).
    try:
        if agent_state is not None and hasattr(agent_state, "start_time"):
            start = getattr(agent_state, "start_time", None)
            if isinstance(start, int | float) and start > 0:
                out["wall_seconds_elapsed"] = int(time.time() - start)
        if agent_state is not None and hasattr(agent_state, "time_budget_seconds"):
            cap = getattr(agent_state, "time_budget_seconds", 0)
            if isinstance(cap, int | float) and cap > 0:
                out["wall_seconds_cap"] = int(cap)
    except Exception:  # noqa: BLE001
        logger.debug("check_budget: wall-time read failed", exc_info=True)

    # Cache-hit ratio from §8.5 Phase 2 cache manager.
    try:
        from strix.llm.cache_manager import get_global_cache_manager

        cache_stats = get_global_cache_manager().get_stats()
        out["cache_hit_ratio"] = cache_stats.hit_ratio()
    except Exception:  # noqa: BLE001
        logger.debug("check_budget: cache stats read failed", exc_info=True)

    # Context window: derive from active LLM model + conversation length.
    try:
        if agent_state is not None and hasattr(agent_state, "get_conversation_history"):
            history = agent_state.get_conversation_history() or []
            # Cheap estimate: chars/4 approximation. Cheap enough to call
            # every turn; precise enough for self-throttling decisions.
            total_chars = 0
            for msg in history:
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    total_chars += len(content)
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            t = item.get("text") or item.get("content")
                            if isinstance(t, str):
                                total_chars += len(t)
            out["context_tokens_active"] = total_chars // 4
    except Exception:  # noqa: BLE001
        logger.debug("check_budget: conversation read failed", exc_info=True)

    # Context window cap.
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None and hasattr(tracer, "run_metadata"):
            model = (tracer.run_metadata or {}).get("model_name")
            if isinstance(model, str):
                out["context_window_cap"] = _detect_context_window(model)
    except Exception:  # noqa: BLE001
        logger.debug("check_budget: model detection failed", exc_info=True)

    cap = max(1, out["context_window_cap"])
    out["context_window_utilisation"] = round(
        out["context_tokens_active"] / cap, 4,
    )

    # Findings emitted so far.
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None:
            out["findings_emitted"] = len(tracer.get_existing_vulnerabilities())
    except Exception:  # noqa: BLE001
        logger.debug("check_budget: findings count failed", exc_info=True)

    return out
