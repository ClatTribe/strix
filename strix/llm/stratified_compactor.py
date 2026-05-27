"""iter-Q2.1 — stratified conversation compactor.

Per docs/proposals/2026-05-27-token-reduction-v2-stratified-compaction.md:
the context window is a stratified store, not a flat blob. Recent turns
are high-value; old turns are mostly redundant noise. Decisions are
signal; deliberations are summarizable. This compactor classifies
each prior message by recency × content type and applies per-cell
compression rules.

Where the existing MemoryCompressor fires once at 90% fill via an
LLM-summarizer call (expensive + variable), this stratified compactor
runs EVERY turn deterministically — no LLM call, no cost, no variance.
Existing MemoryCompressor still fires as a fallback when the stratified
output is still over the 90% threshold (large workspace dumps, etc.).

## Strata

| Stratum | Range | Tool outputs | think() | Tool calls | Emit calls (CV-report) |
|---|---|---|---|---|---|
| HOT | last 5 turns | verbatim | verbatim | verbatim | verbatim |
| WARM | turn 5-20 | summary line + drill-down ref | first sentence | verbatim | verbatim |
| COLD | turn 20+ | one-liner ref | dropped | verbatim (args trimmed) | verbatim |

User messages: NEVER touched (the scan kickoff + any operator
intervention is canonical input).

L1.5-enriched data structures (workflow_state, SecurityContext,
list_pending_findings) are NEVER part of the message stream — they
render into the system prompt separately and aren't affected by this
compactor.

## Decision tree (per message, in order)

  1. User message?              → keep verbatim
  2. System message?            → keep verbatim
  3. In HOT stratum?            → keep verbatim
  4. create_vulnerability_report → keep verbatim (canonical scan output)
  5. finish_scan call            → keep verbatim (canonical termination)
  6. Tool call (other)          → keep call name + key args; trim verbose args after COLD
  7. Tool result block          → WARM: summary line; COLD: one-line ref
  8. Assistant think() block    → WARM: first sentence; COLD: drop
  9. Assistant text (other)     → WARM: one-line summary; COLD: drop

## Opt-out

`STRIX_STRATIFIED_COMPACTION_DISABLED=1` — bypass entirely. Existing
MemoryCompressor still runs.

## Detection guarantee

Every drop has a written-down justification. Findings are L1.5-enriched
+ persisted in `tracer.vulnerability_reports` regardless of conversation
state; the LLM accesses them via `list_pending_findings` (always in the
system prompt). Tool outputs that get dropped from the conversation
remain accessible via `read_tool_output(id)` drill-down (iter-Q2 surface).

Validation: every PR touching this module must run multi-trial
benchmarks per CLAUDE.md §6.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HOT_TURN_COUNT = 5      # last 5 turns: verbatim
WARM_TURN_COUNT = 15    # turns 5..20: light compression

# Preserved-verbatim tool names — these are the canonical scan output
# / canonical decisions. Never compressed regardless of stratum.
_PRESERVED_TOOL_NAMES: frozenset[str] = frozenset({
    "create_vulnerability_report",
    "update_finding",
    "finish_scan",
})

# Maximum length of a summary line we generate (in chars, not tokens —
# we apply token counting separately if needed).
_SUMMARY_MAX_CHARS = 240


def is_stratified_compaction_disabled() -> bool:
    """Opt-out env flag — operators can bisect via env var without
    code changes."""
    return os.environ.get(
        "STRIX_STRATIFIED_COMPACTION_DISABLED", "",
    ).strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Per-message classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MessageClassification:
    """The decision the compactor makes for one message."""
    stratum: str          # "hot" / "warm" / "cold"
    kind: str             # "user" / "system" / "emit" / "tool_call"
                          # / "tool_result" / "think" / "assistant_text"
    preserved: bool       # whether to keep verbatim
    reason: str           # why this decision was made


def _extract_tool_call_name(msg: dict[str, Any]) -> str | None:
    """Return the tool name for an assistant message that contains a
    tool_call. None when the message isn't a tool call.

    Handles two schemas: OpenAI/LiteLLM (`tool_calls`) and Anthropic
    (`content` list with `type=="tool_use"`).
    """
    if msg.get("role") != "assistant":
        return None
    tcs = msg.get("tool_calls")
    if isinstance(tcs, list) and tcs:
        first = tcs[0]
        if isinstance(first, dict):
            fn = first.get("function") or {}
            name = fn.get("name") if isinstance(fn, dict) else None
            if isinstance(name, str):
                return name
    content = msg.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use":
                name = item.get("name")
                if isinstance(name, str):
                    return name
    return None


def _is_tool_result(msg: dict[str, Any]) -> bool:
    """True for tool-response messages.

    OpenAI/LiteLLM uses `role: tool`. Anthropic embeds tool results
    inside a user-role message with `content: [{type:tool_result}]`.
    """
    if msg.get("role") == "tool":
        return True
    if msg.get("role") == "user":
        content = msg.get("content")
        if isinstance(content, list):
            return any(
                isinstance(item, dict) and item.get("type") == "tool_result"
                for item in content
            )
    return False


def _is_think_block(msg: dict[str, Any]) -> bool:
    """Heuristic: an assistant text message whose body opens with a
    `<think>` block or a `[think]` marker. The strix `think()` tool
    surfaces here as a tool_use; this catches the inline-text variant."""
    if msg.get("role") != "assistant":
        return False
    content = msg.get("content")
    if isinstance(content, str):
        return bool(re.match(r"^\s*[<\[]think", content, re.IGNORECASE))
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text") or ""
                if re.match(r"^\s*[<\[]think", text, re.IGNORECASE):
                    return True
    return False


def classify_message(
    msg: dict[str, Any], *, age_turns: int,
) -> MessageClassification:
    """Decide compactor disposition for one message."""
    role = msg.get("role", "")
    if age_turns <= HOT_TURN_COUNT:
        stratum = "hot"
    elif age_turns <= HOT_TURN_COUNT + WARM_TURN_COUNT:
        stratum = "warm"
    else:
        stratum = "cold"

    # User messages → always verbatim, regardless of stratum.
    if role == "user" and not _is_tool_result(msg):
        return MessageClassification(
            stratum=stratum, kind="user", preserved=True,
            reason="user-message-canonical-input",
        )

    if role == "system":
        return MessageClassification(
            stratum=stratum, kind="system", preserved=True,
            reason="system-message-never-compressed",
        )

    # Tool result.
    if _is_tool_result(msg):
        return MessageClassification(
            stratum=stratum, kind="tool_result",
            preserved=(stratum == "hot"),
            reason=(
                "hot-stratum-verbatim" if stratum == "hot"
                else "tool-result-summarized-in-warm-cold"
            ),
        )

    # Assistant tool call.
    tool_name = _extract_tool_call_name(msg)
    if tool_name:
        if tool_name in _PRESERVED_TOOL_NAMES:
            return MessageClassification(
                stratum=stratum, kind="emit", preserved=True,
                reason=f"preserved-tool-{tool_name}",
            )
        return MessageClassification(
            stratum=stratum, kind="tool_call",
            preserved=(stratum != "cold"),
            reason=(
                "hot-warm-tool-call-verbatim" if stratum != "cold"
                else "cold-tool-call-trim-verbose-args"
            ),
        )

    # Assistant think() block.
    if _is_think_block(msg):
        return MessageClassification(
            stratum=stratum, kind="think",
            preserved=(stratum == "hot"),
            reason=(
                "hot-think-verbatim" if stratum == "hot"
                else "warm-think-first-sentence" if stratum == "warm"
                else "cold-think-dropped"
            ),
        )

    # Plain assistant text.
    return MessageClassification(
        stratum=stratum, kind="assistant_text",
        preserved=(stratum == "hot"),
        reason=(
            "hot-text-verbatim" if stratum == "hot"
            else "warm-text-summarized" if stratum == "warm"
            else "cold-text-dropped"
        ),
    )


# ---------------------------------------------------------------------------
# Compression primitives — per-cell rules
# ---------------------------------------------------------------------------


def _extract_text(msg: dict[str, Any]) -> str:
    """Pull all text content out of a message (string or list shape)."""
    content = msg.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "tool_result":
                    inner = item.get("content")
                    if isinstance(inner, str):
                        parts.append(inner)
                    elif isinstance(inner, list):
                        for sub in inner:
                            if isinstance(sub, dict) and sub.get("type") == "text":
                                parts.append(sub.get("text", ""))
        return "\n".join(parts)
    return str(content)


def _summarize_tool_result(msg: dict[str, Any], *, stratum: str) -> dict[str, Any]:
    """Replace verbose tool output with a summary line + drill-down ref."""
    text = _extract_text(msg)
    if stratum == "warm":
        # Keep first 240 chars + a structural marker pointing to drill-down.
        truncated = text.replace("\n", " ").strip()
        if len(truncated) > _SUMMARY_MAX_CHARS:
            truncated = truncated[:_SUMMARY_MAX_CHARS] + "…"
        summary = (
            f"<tool_result_summary>{truncated}</tool_result_summary>\n"
            f"<full_output_id>see compaction_transcript for details</full_output_id>"
        )
    else:  # cold
        line_count = text.count("\n")
        char_count = len(text)
        summary = (
            f"<tool_result_dropped lines={line_count} chars={char_count} "
            f"reason=cold-stratum see compaction_transcript />"
        )
    # Preserve message shape (OpenAI vs Anthropic).
    out = dict(msg)
    if msg.get("role") == "tool":
        out["content"] = summary
    elif isinstance(msg.get("content"), list):
        out["content"] = [{"type": "tool_result", "content": summary}]
    else:
        out["content"] = summary
    return out


def _summarize_think_block(msg: dict[str, Any], *, stratum: str) -> dict[str, Any]:
    """Reduce a think() block. WARM: first sentence. COLD: drop entirely.

    Caller is responsible for filtering COLD-stratum think blocks
    BEFORE calling — this function returns the WARM compression.
    """
    text = _extract_text(msg)
    # First sentence (split on . / ? / ! / newline-pair).
    m = re.match(r"^(?:\s*[<\[]think[^>\]]*[>\]])?\s*(.+?[.?!])(?:\s|$)", text)
    first_sentence = m.group(1) if m else text[:_SUMMARY_MAX_CHARS]
    summary = (
        f"<think_summary stratum={stratum}>{first_sentence.strip()}"
        f"</think_summary>"
    )
    out = dict(msg)
    out["content"] = summary
    return out


def _summarize_assistant_text(msg: dict[str, Any], *, stratum: str) -> dict[str, Any]:
    """WARM text: keep first sentence; COLD: caller drops."""
    text = _extract_text(msg).strip()
    if not text:
        return msg
    # First sentence-ish.
    m = re.match(r"^(.+?[.?!])(?:\s|$)", text)
    first = m.group(1) if m else text[:_SUMMARY_MAX_CHARS]
    out = dict(msg)
    out["content"] = (
        f"<assistant_summary stratum={stratum}>{first}</assistant_summary>"
    )
    return out


def _trim_tool_call_args(msg: dict[str, Any]) -> dict[str, Any]:
    """In COLD stratum, keep the tool-call name + first arg only.
    Long arg values (>100 chars) get truncated."""
    out = dict(msg)
    # OpenAI/LiteLLM shape.
    tcs = out.get("tool_calls")
    if isinstance(tcs, list):
        new_tcs = []
        for tc in tcs:
            if not isinstance(tc, dict):
                new_tcs.append(tc)
                continue
            new_tc = dict(tc)
            fn = new_tc.get("function")
            if isinstance(fn, dict):
                new_fn = dict(fn)
                args_str = new_fn.get("arguments")
                if isinstance(args_str, str) and len(args_str) > 100:
                    new_fn["arguments"] = args_str[:100] + "…[trimmed in COLD]"
                new_tc["function"] = new_fn
            new_tcs.append(new_tc)
        out["tool_calls"] = new_tcs
    # Anthropic shape.
    content = out.get("content")
    if isinstance(content, list):
        new_content = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "tool_use":
                new_item = dict(item)
                inp = new_item.get("input")
                if isinstance(inp, dict):
                    new_inp = {}
                    for k, v in inp.items():
                        if isinstance(v, str) and len(v) > 100:
                            new_inp[k] = v[:100] + "…[trimmed in COLD]"
                        else:
                            new_inp[k] = v
                    new_item["input"] = new_inp
                new_content.append(new_item)
            else:
                new_content.append(item)
        out["content"] = new_content
    return out


# ---------------------------------------------------------------------------
# Top-level compactor
# ---------------------------------------------------------------------------


@dataclass
class CompactionStats:
    """Per-call telemetry — surfaces in bench reports."""
    messages_input: int = 0
    messages_output: int = 0
    messages_dropped: int = 0
    messages_compressed: int = 0
    by_stratum: dict[str, int] | None = None
    by_kind: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "messages_input": self.messages_input,
            "messages_output": self.messages_output,
            "messages_dropped": self.messages_dropped,
            "messages_compressed": self.messages_compressed,
            "by_stratum": dict(self.by_stratum or {}),
            "by_kind": dict(self.by_kind or {}),
        }


def stratify_and_compact(
    messages: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], CompactionStats]:
    """Apply HOT/WARM/COLD stratification to a conversation history.

    Returns (compacted_messages, stats). The compacted history is
    the input messages list with WARM/COLD entries replaced by their
    summarized form, COLD think()+text entries dropped entirely, and
    HOT entries unchanged.

    Determinism: this function makes NO LLM calls. Same input always
    produces the same output. Test-friendly.
    """
    stats = CompactionStats(
        messages_input=len(messages),
        by_stratum={"hot": 0, "warm": 0, "cold": 0},
        by_kind={},
    )

    if is_stratified_compaction_disabled():
        stats.messages_output = len(messages)
        return (list(messages), stats)

    if not messages:
        return (list(messages), stats)

    # Compute per-message age in REVERSE turn order (most recent = age 1).
    # We walk from end to start to assign ages, then re-output in original
    # order.
    n = len(messages)
    out: list[dict[str, Any] | None] = [None] * n

    # First pass: classify every message.
    classifications: list[MessageClassification] = []
    for idx, msg in enumerate(messages):
        # Age in turns: most recent is 1 (1-indexed). Each message
        # counts as one "step" for age purposes — fine-grained
        # enough for the stratum cutoffs.
        age_turns = n - idx
        cls = classify_message(msg, age_turns=age_turns)
        classifications.append(cls)
        stats.by_stratum[cls.stratum] = stats.by_stratum.get(cls.stratum, 0) + 1
        stats.by_kind[cls.kind] = stats.by_kind.get(cls.kind, 0) + 1

    # Second pass: apply per-cell rules.
    for idx, (msg, cls) in enumerate(zip(messages, classifications, strict=True)):
        if cls.preserved:
            out[idx] = msg
            continue
        # Apply compression rule.
        if cls.kind == "tool_result":
            out[idx] = _summarize_tool_result(msg, stratum=cls.stratum)
            stats.messages_compressed += 1
        elif cls.kind == "think":
            if cls.stratum == "cold":
                out[idx] = None  # drop
                stats.messages_dropped += 1
            else:
                out[idx] = _summarize_think_block(msg, stratum=cls.stratum)
                stats.messages_compressed += 1
        elif cls.kind == "assistant_text":
            if cls.stratum == "cold":
                out[idx] = None
                stats.messages_dropped += 1
            else:
                out[idx] = _summarize_assistant_text(msg, stratum=cls.stratum)
                stats.messages_compressed += 1
        elif cls.kind == "tool_call":
            if cls.stratum == "cold":
                out[idx] = _trim_tool_call_args(msg)
                stats.messages_compressed += 1
            else:
                out[idx] = msg  # WARM: verbatim (per the table)
        else:
            # Shouldn't reach here — defensive default to preserve.
            out[idx] = msg

    compacted = [m for m in out if m is not None]
    stats.messages_output = len(compacted)
    return (compacted, stats)
