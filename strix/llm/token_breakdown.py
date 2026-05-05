"""Per-LLM-call token-breakdown classification (roadmap §8.5 Phase 0.A).

Decision-gate input for the single-lead-agent architecture migration
(see [`single-agent.md`](single-agent.md)). Without per-component
cost data the architectural decision rests on inference (the RFC's
"$1.74 of 8 × 700K context-load" number is plausible but not
bisected). This module instruments every LLM round-trip so the
operator can see where the per-call token cost actually lives.

Schema-versioned. Wrapper-side impact: `llm.token_breakdown` is a new
additive event emitted alongside the existing `llm.request.completed`
event — wrappers ignoring unknown events keep working per
[`engine-usage.md §6`](engine-usage.md) versioning contract.

Components classified per call:

  * `system_tokens`           — the agent's system message (which
                                today contains the full tool catalog
                                rendered as XML; tool_catalog isn't
                                separable post-hoc without a structural
                                change).
  * `agent_identity_tokens`   — the `<agent_identity>` block prepended
                                by `LLM._prepare_messages` (small but
                                non-zero; explicitly classified).
  * `conversation_tokens`     — everything else in the message list:
                                compressed history, tool results,
                                thinking blocks, scope-addendum-as-task,
                                etc. This is the bucket the §8.5
                                inherit_context flip targets.
  * `output_tokens`           — assistant response (already tracked
                                in `RequestStats`; surfaced here for
                                completeness).
  * `cached_tokens`           — already tracked from the
                                `prompt_tokens_details.cached_tokens`
                                field returned by litellm.

Aggregator API: `Tracer.token_breakdown_summary()` walks
`events.jsonl` and produces per-component totals + per-call
distribution + cache-hit ratio so the operator can see which
component dominates.
"""

from __future__ import annotations

import logging
from typing import Any

import litellm


logger = logging.getLogger(__name__)


TOKEN_BREAKDOWN_SCHEMA_VERSION: int = 1


# Sentinel substrings that identify the agent_identity block. The
# block is emitted by `LLM._prepare_messages` with these XML markers
# so the classifier can detect it without coupling to the exact
# template.
_AGENT_IDENTITY_MARKERS = (
    "<agent_identity>",
    "<agent_id>",
)


def _count_tokens(text: str, model: str) -> int:
    """Token count via litellm; falls back to chars/4 estimate on
    failure (mirrors `memory_compressor._count_tokens` behaviour)."""
    if not text:
        return 0
    try:
        return int(litellm.token_counter(model=model, text=text))
    except Exception:  # noqa: BLE001
        logger.debug("token_counter failed, falling back to estimate", exc_info=True)
        return len(text) // 4


def _message_text(msg: dict[str, Any]) -> str:
    """Extract the string content from a message. Handles both
    plain-string content and the cache_control list-of-dicts form
    used by anthropic prompt-caching."""
    content = msg.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                t = item.get("text") or item.get("content")
                if isinstance(t, str):
                    parts.append(t)
        return "\n".join(parts)
    return str(content)


def _is_agent_identity(msg: dict[str, Any]) -> bool:
    """True when this message is the `<agent_identity>` block prepended
    by `LLM._prepare_messages`. Detected by content marker, not by
    role+position (which can drift)."""
    if msg.get("role") != "user":
        return False
    text = _message_text(msg)
    return any(marker in text for marker in _AGENT_IDENTITY_MARKERS)


def breakdown_messages(
    messages: list[dict[str, Any]],
    *,
    model: str,
) -> dict[str, int]:
    """Classify every message in the prepared message list into one
    of three input buckets. Returns absolute token counts per bucket
    plus the total.

    Args:
        messages: the message list passed to `litellm.acompletion`.
            Order matters for cache-stability but not for classification.
        model: model name, used by `litellm.token_counter` for accurate
            tokenisation. Falls back to chars/4 on failure.

    Returns:
        Dict with keys:
          * `system_tokens`           (int)
          * `agent_identity_tokens`   (int)
          * `conversation_tokens`     (int)
          * `total_input_tokens_estimated` (int) — sum of the three
            above. Note: the model's reported `prompt_tokens` may
            differ slightly due to provider-side overhead (chat-format
            tokens, role markers); the classifier reports an estimate
            usable for relative bisection.
          * `message_count`           (int)
          * `schema_version`          (int)

    Defensive: handles malformed messages (missing `role` / `content`)
    by classifying them under `conversation_tokens` rather than
    raising. Telemetry is best-effort.
    """
    system_tokens = 0
    agent_identity_tokens = 0
    conversation_tokens = 0
    counted = 0

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        text = _message_text(msg)
        if not text:
            continue
        n = _count_tokens(text, model)

        role = msg.get("role")
        if role == "system":
            system_tokens += n
        elif _is_agent_identity(msg):
            agent_identity_tokens += n
        else:
            conversation_tokens += n
        counted += 1

    total = system_tokens + agent_identity_tokens + conversation_tokens

    return {
        "schema_version": TOKEN_BREAKDOWN_SCHEMA_VERSION,
        "system_tokens": system_tokens,
        "agent_identity_tokens": agent_identity_tokens,
        "conversation_tokens": conversation_tokens,
        "total_input_tokens_estimated": total,
        "message_count": counted,
    }
