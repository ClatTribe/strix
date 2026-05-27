"""Tests for iter-Q2.1 — stratified ConversationCompactor.

Per docs/proposals/2026-05-27-token-reduction-v2-stratified-compaction.md.

Pins the per-cell (stratum × content type) decision tree against
regressions. Detection-preservation invariants are the headline
gate:

  * `create_vulnerability_report` calls preserved at every stratum.
  * `finish_scan` calls preserved at every stratum.
  * User messages preserved at every stratum.
  * Tool CALLS (the decisions) preserved at HOT + WARM; cold trims args only.
  * Tool RESULTS summarized in WARM, replaced with one-liner in COLD.
  * think() blocks: WARM first sentence; COLD dropped.
"""

from __future__ import annotations

import os

import pytest

from strix.llm.stratified_compactor import (
    HOT_TURN_COUNT,
    WARM_TURN_COUNT,
    CompactionStats,
    MessageClassification,
    _PRESERVED_TOOL_NAMES,
    _extract_tool_call_name,
    _is_think_block,
    _is_tool_result,
    _summarize_assistant_text,
    _summarize_think_block,
    _summarize_tool_result,
    _trim_tool_call_args,
    classify_message,
    is_stratified_compaction_disabled,
    stratify_and_compact,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Default to ON for tests (matches production default)."""
    monkeypatch.delenv("STRIX_STRATIFIED_COMPACTION_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Opt-out flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("v,expected", [
    ("1", True), ("true", True), ("yes", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("garbage", False),
])
def test_opt_out_flag_canonical_values(monkeypatch, v, expected):
    monkeypatch.setenv("STRIX_STRATIFIED_COMPACTION_DISABLED", v)
    assert is_stratified_compaction_disabled() is expected


def test_opt_out_default_false():
    """Default ON (compactor runs)."""
    assert is_stratified_compaction_disabled() is False


def test_opt_out_passes_messages_through(monkeypatch):
    """When disabled, output messages == input messages verbatim."""
    monkeypatch.setenv("STRIX_STRATIFIED_COMPACTION_DISABLED", "1")
    messages = [
        {"role": "user", "content": "scan x"},
        {"role": "assistant", "content": "ok"},
    ]
    out, stats = stratify_and_compact(messages)
    assert out == messages
    assert stats.messages_output == 2


# ---------------------------------------------------------------------------
# Message classification primitives
# ---------------------------------------------------------------------------


def test_extract_tool_call_name_openai_shape():
    msg = {
        "role": "assistant",
        "tool_calls": [{
            "function": {"name": "scan_sqli_sqlmap", "arguments": "{}"},
        }],
    }
    assert _extract_tool_call_name(msg) == "scan_sqli_sqlmap"


def test_extract_tool_call_name_anthropic_shape():
    msg = {
        "role": "assistant",
        "content": [
            {"type": "text", "text": "let me run sqlmap"},
            {"type": "tool_use", "name": "scan_sqli_sqlmap", "input": {}},
        ],
    }
    assert _extract_tool_call_name(msg) == "scan_sqli_sqlmap"


def test_extract_tool_call_name_none_when_not_tool_call():
    assert _extract_tool_call_name(
        {"role": "assistant", "content": "just text"},
    ) is None


def test_is_tool_result_openai_shape():
    assert _is_tool_result(
        {"role": "tool", "tool_call_id": "x", "content": "..."},
    ) is True


def test_is_tool_result_anthropic_shape():
    assert _is_tool_result({
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "x", "content": "..."}],
    }) is True


def test_is_tool_result_false_for_regular_user_message():
    assert _is_tool_result({"role": "user", "content": "scan x"}) is False


def test_is_think_block_inline():
    assert _is_think_block({
        "role": "assistant",
        "content": "<think>let me reason about this...</think>",
    }) is True


def test_is_think_block_anthropic_content_list():
    assert _is_think_block({
        "role": "assistant",
        "content": [{"type": "text", "text": "[think] sqli on /search?"}],
    }) is True


def test_is_think_block_false_for_regular_text():
    assert _is_think_block({
        "role": "assistant",
        "content": "Looking at the prepass output...",
    }) is False


# ---------------------------------------------------------------------------
# classify_message — the per-cell decision tree
# ---------------------------------------------------------------------------


def test_classify_user_message_always_preserved():
    """User messages: preserved at every stratum (canonical input)."""
    msg = {"role": "user", "content": "scan example.com"}
    for age in (1, 10, 100):
        cls = classify_message(msg, age_turns=age)
        assert cls.preserved is True
        assert cls.kind == "user"


def test_classify_create_vulnerability_report_preserved_in_cold():
    """The canonical scan output — preserved even in COLD."""
    msg = {
        "role": "assistant",
        "tool_calls": [{
            "function": {"name": "create_vulnerability_report", "arguments": "{}"},
        }],
    }
    cls = classify_message(msg, age_turns=100)
    assert cls.preserved is True
    assert cls.kind == "emit"


def test_classify_finish_scan_preserved_in_cold():
    """Terminate call — preserved at every stratum."""
    msg = {
        "role": "assistant",
        "content": [{"type": "tool_use", "name": "finish_scan", "input": {}}],
    }
    cls = classify_message(msg, age_turns=100)
    assert cls.preserved is True
    assert cls.kind == "emit"


def test_classify_tool_call_preserved_in_hot_warm_trimmed_in_cold():
    """Non-emit tool calls: verbatim HOT/WARM, args trimmed COLD."""
    msg = {
        "role": "assistant",
        "tool_calls": [{
            "function": {"name": "scan_sqli_sqlmap", "arguments": "..."},
        }],
    }
    assert classify_message(msg, age_turns=1).preserved is True   # hot
    assert classify_message(msg, age_turns=10).preserved is True  # warm
    assert classify_message(msg, age_turns=100).preserved is False  # cold


def test_classify_tool_result_summarized_in_warm():
    msg = {"role": "tool", "tool_call_id": "x", "content": "huge nuclei output ..."}
    assert classify_message(msg, age_turns=1).preserved is True   # hot
    assert classify_message(msg, age_turns=10).preserved is False  # warm summary
    assert classify_message(msg, age_turns=100).preserved is False  # cold one-liner


def test_classify_think_dropped_in_cold():
    msg = {"role": "assistant", "content": "<think>reasoning...</think>"}
    cls_hot = classify_message(msg, age_turns=1)
    cls_warm = classify_message(msg, age_turns=10)
    cls_cold = classify_message(msg, age_turns=100)
    assert cls_hot.preserved is True
    assert cls_warm.preserved is False  # first-sentence
    assert cls_cold.preserved is False  # dropped
    assert cls_cold.kind == "think"


def test_classify_stratum_boundaries():
    """Verify the HOT/WARM/COLD cutoffs are at HOT_TURN_COUNT and
    HOT_TURN_COUNT+WARM_TURN_COUNT."""
    msg = {"role": "user", "content": "x"}
    # Age 1..HOT_TURN_COUNT → hot
    for age in range(1, HOT_TURN_COUNT + 1):
        assert classify_message(msg, age_turns=age).stratum == "hot"
    # Age HOT_TURN_COUNT+1 .. HOT+WARM → warm
    for age in range(HOT_TURN_COUNT + 1, HOT_TURN_COUNT + WARM_TURN_COUNT + 1):
        assert classify_message(msg, age_turns=age).stratum == "warm"
    # Beyond → cold
    assert classify_message(
        msg, age_turns=HOT_TURN_COUNT + WARM_TURN_COUNT + 1,
    ).stratum == "cold"


# ---------------------------------------------------------------------------
# Compression primitives
# ---------------------------------------------------------------------------


def test_summarize_tool_result_warm_truncates():
    """WARM tool result keeps first ~240 chars + drill-down ref."""
    long_text = "A" * 1000
    msg = {"role": "tool", "tool_call_id": "x", "content": long_text}
    out = _summarize_tool_result(msg, stratum="warm")
    assert "tool_result_summary" in out["content"]
    assert "full_output_id" in out["content"]
    # Body must be smaller than the original.
    assert len(out["content"]) < len(long_text)


def test_summarize_tool_result_cold_one_liner():
    long_text = "A" * 1000
    msg = {"role": "tool", "tool_call_id": "x", "content": long_text}
    out = _summarize_tool_result(msg, stratum="cold")
    assert "tool_result_dropped" in out["content"]
    assert "lines=" in out["content"]


def test_summarize_think_block_keeps_first_sentence():
    msg = {
        "role": "assistant",
        "content": (
            "<think>The prepass found a SQLi at /search. "
            "I should follow up with sqlmap on the q parameter. "
            "Also considering scan_idor on the captured session.</think>"
        ),
    }
    out = _summarize_think_block(msg, stratum="warm")
    # First sentence should survive; subsequent ones don't.
    assert "SQLi" in out["content"]
    assert "scan_idor" not in out["content"]


def test_summarize_assistant_text_first_sentence():
    msg = {
        "role": "assistant",
        "content": (
            "Looking at the prepass output. "
            "I notice three SQLi candidates. "
            "Let me probe the first one."
        ),
    }
    out = _summarize_assistant_text(msg, stratum="warm")
    assert "Looking at the prepass output" in out["content"]
    assert "third one" not in out["content"]


def test_trim_tool_call_args_openai_truncates_long_args():
    """COLD-stratum tool call: keep name, truncate long arg strings."""
    long_args = '{"target_url": "' + ("a" * 500) + '"}'
    msg = {
        "role": "assistant",
        "tool_calls": [{
            "function": {"name": "scan_sqli_sqlmap", "arguments": long_args},
        }],
    }
    out = _trim_tool_call_args(msg)
    new_args = out["tool_calls"][0]["function"]["arguments"]
    assert len(new_args) < len(long_args)
    assert "trimmed in COLD" in new_args


def test_trim_tool_call_args_anthropic_truncates_long_inputs():
    msg = {
        "role": "assistant",
        "content": [{
            "type": "tool_use", "name": "scan_sqli_sqlmap",
            "input": {"target_url": "a" * 500, "short": "ok"},
        }],
    }
    out = _trim_tool_call_args(msg)
    new_input = out["content"][0]["input"]
    assert len(new_input["target_url"]) < 500
    # Short args untouched.
    assert new_input["short"] == "ok"


# ---------------------------------------------------------------------------
# Top-level stratify_and_compact integration tests
# ---------------------------------------------------------------------------


def _build_long_conversation(n_old: int = 50) -> list[dict]:
    """Build a representative conversation: 1 user kickoff + N old
    turns (alternating assistant text + tool calls + tool results)
    + 5 recent turns (must stay HOT)."""
    convo: list[dict] = [
        {"role": "user", "content": "Scan http://example.com for web vulns"},
    ]
    for i in range(n_old):
        # Tool call
        convo.append({
            "role": "assistant",
            "tool_calls": [{
                "function": {
                    "name": "scan_sqli_sqlmap",
                    "arguments": '{"target_url": "http://example.com/?id=' + str(i) + '"}',
                },
            }],
        })
        # Tool result (verbose)
        convo.append({
            "role": "tool", "tool_call_id": f"call_{i}",
            "content": "sqlmap output line\n" * 200,  # 200 lines = ~3K chars
        })
        # think() block
        convo.append({
            "role": "assistant",
            "content": f"<think>Saw param id at endpoint {i}. Worth probing.</think>",
        })
    # 5 recent turns (within HOT)
    for i in range(HOT_TURN_COUNT):
        convo.append({
            "role": "assistant",
            "content": f"Recent turn {i}: still reasoning",
        })
    return convo


def test_stratify_long_conversation_drops_cold_think_blocks():
    convo = _build_long_conversation(n_old=20)
    out, stats = stratify_and_compact(convo)
    # User kickoff still there.
    assert out[0]["role"] == "user"
    assert out[0]["content"].startswith("Scan ")
    # Some messages dropped.
    assert stats.messages_dropped > 0
    # Output length < input.
    assert stats.messages_output < stats.messages_input


def test_stratify_preserves_create_vulnerability_report_in_cold():
    """The headline detection-preservation invariant: every emit
    call survives every stratum."""
    convo = [
        {"role": "user", "content": "scan"},
    ]
    # Add an old emit call (will be in COLD by virtue of position).
    convo.append({
        "role": "assistant",
        "tool_calls": [{
            "function": {
                "name": "create_vulnerability_report",
                "arguments": '{"title":"SQLi","severity":"high"}',
            },
        }],
    })
    # Then pad with 30 more turns to push the emit deep into COLD.
    for _ in range(30):
        convo.append({"role": "assistant", "content": "more text"})
        convo.append({"role": "tool", "content": "tool output"})
    out, _stats = stratify_and_compact(convo)
    # The create_vulnerability_report message must still be in the output.
    emit_msgs = [
        m for m in out
        if isinstance(m.get("tool_calls"), list)
        and m["tool_calls"][0].get("function", {}).get("name")
        == "create_vulnerability_report"
    ]
    assert len(emit_msgs) == 1
    # And it's verbatim (full args preserved).
    args = emit_msgs[0]["tool_calls"][0]["function"]["arguments"]
    assert "SQLi" in args
    assert "high" in args


def test_stratify_preserves_user_messages_in_cold():
    """User messages: every operator instruction survives forever."""
    convo = [
        {"role": "user", "content": "First instruction"},
    ]
    # Pad to push it COLD.
    for _ in range(40):
        convo.append({"role": "assistant", "content": "reply"})
    # Add a mid-scan user intervention (will be in WARM by position).
    convo.append({"role": "user", "content": "Operator intervention mid-scan"})
    for _ in range(5):
        convo.append({"role": "assistant", "content": "recent"})
    out, _stats = stratify_and_compact(convo)
    user_msgs = [m for m in out if m.get("role") == "user" and not _is_tool_result(m)]
    user_contents = [m["content"] for m in user_msgs]
    assert "First instruction" in user_contents
    assert "Operator intervention mid-scan" in user_contents


def test_stratify_summarizes_tool_results_in_warm_and_cold():
    """Verbose tool outputs shrink dramatically in WARM and COLD."""
    big = "A" * 5000
    convo = [{"role": "user", "content": "scan"}]
    # Warm-stratum tool result (positioned beyond HOT but within WARM).
    for i in range(8):
        convo.append({"role": "tool", "content": big})
    # Recent HOT turns.
    for _ in range(HOT_TURN_COUNT):
        convo.append({"role": "assistant", "content": "recent"})
    out, _stats = stratify_and_compact(convo)
    # The WARM tool-result entries should be summarized (shorter than 5K).
    summarized = 0
    for m in out:
        if m.get("role") == "tool":
            if "tool_result_summary" in (m.get("content") or ""):
                summarized += 1
            elif "tool_result_dropped" in (m.get("content") or ""):
                summarized += 1
    assert summarized > 0


def test_stratify_hot_turns_completely_verbatim():
    """The last HOT_TURN_COUNT turns must be byte-identical to input."""
    convo = [{"role": "user", "content": "scan"}]
    # Recent 5 messages = HOT.
    hot_marker_msgs = []
    for i in range(HOT_TURN_COUNT):
        m = {"role": "assistant", "content": f"HOT_MARKER_{i}"}
        hot_marker_msgs.append(m)
        convo.append(m)
    out, _stats = stratify_and_compact(convo)
    # Every HOT marker must be present verbatim.
    out_contents = [m.get("content") for m in out]
    for hm in hot_marker_msgs:
        assert hm["content"] in out_contents


def test_stratify_empty_input():
    """Defensive — empty conversation history is a no-op."""
    out, stats = stratify_and_compact([])
    assert out == []
    assert stats.messages_input == 0


def test_stratify_telemetry_stats_accurate():
    """CompactionStats should accurately report per-stratum + per-kind
    counts for downstream bench analysis."""
    convo = _build_long_conversation(n_old=10)
    _out, stats = stratify_and_compact(convo)
    total = sum(stats.by_stratum.values())
    assert total == stats.messages_input
    # Both hot and cold strata must be represented.
    assert stats.by_stratum["hot"] > 0
    assert stats.by_stratum["warm"] > 0 or stats.by_stratum["cold"] > 0


# ---------------------------------------------------------------------------
# Preserved-tool-name guarantees
# ---------------------------------------------------------------------------


def test_preserved_tool_names_include_emit_path():
    assert "create_vulnerability_report" in _PRESERVED_TOOL_NAMES
    assert "update_finding" in _PRESERVED_TOOL_NAMES
    assert "finish_scan" in _PRESERVED_TOOL_NAMES


# ---------------------------------------------------------------------------
# Anti-overfit guard
# ---------------------------------------------------------------------------


def test_compactor_module_has_no_fixture_identifiers():
    """The compactor is generic — it must not contain bench-fixture
    names (juiceshop / vampi / etc.). Catches the case where someone
    tunes thresholds for one bench."""
    from pathlib import Path
    src = (
        Path(__file__).parent.parent.parent
        / "strix" / "llm" / "stratified_compactor.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("juice-shop", "juiceshop", "bkimminich", "vampi", "crapi", "erev0s", "webgoat"):
        assert forbidden not in src.lower(), (
            f"stratified_compactor.py contains {forbidden!r}"
        )
