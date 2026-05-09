"""Tests for §8.5 Phase 4b — native tool calling integration.

Pins the LLM client's behaviour when `STRIX_TOOL_CALL_FORMAT=native`:
  * `_build_completion_args` adds `tools=[...]` and `tool_choice="auto"`
  * `_extract_native_tool_invocations` converts the API's
    `tool_calls` shape to strix's existing `tool_invocations` shape
    so the executor consumes them unchanged
  * env-var default is `xml` (preserves prior behaviour)
  * graceful no-op when no tool_calls present (text-only response)
  * malformed tool_calls (missing function/name/arguments) dropped
    silently — not raised to the caller
  * arguments parsed from JSON string per OpenAI spec
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


@pytest.fixture(autouse=True)
def _llm_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    yield


@pytest.fixture
def llm() -> LLM:
    return LLM(LLMConfig(), agent_name="StrixAgent")


# ---------------------------------------------------------------------------
# Env-flag gate
# ---------------------------------------------------------------------------


def test_native_disabled_by_default(llm: LLM, monkeypatch) -> None:
    monkeypatch.delenv("STRIX_TOOL_CALL_FORMAT", raising=False)
    assert llm._native_tool_calls_enabled() is False


def test_native_enabled_when_env_set(llm: LLM, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TOOL_CALL_FORMAT", "native")
    assert llm._native_tool_calls_enabled() is True


def test_native_case_insensitive(llm: LLM, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TOOL_CALL_FORMAT", "  Native  ")
    assert llm._native_tool_calls_enabled() is True


def test_unknown_value_treated_as_disabled(llm: LLM, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TOOL_CALL_FORMAT", "garbage")
    assert llm._native_tool_calls_enabled() is False


# ---------------------------------------------------------------------------
# _build_completion_args wiring
# ---------------------------------------------------------------------------


def test_completion_args_no_tools_when_disabled(llm: LLM, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TOOL_CALL_FORMAT", "xml")
    args = llm._build_completion_args([{"role": "user", "content": "hi"}])
    assert "tools" not in args
    assert "tool_choice" not in args


def test_completion_args_includes_tools_when_enabled(llm: LLM, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TOOL_CALL_FORMAT", "native")
    args = llm._build_completion_args([{"role": "user", "content": "hi"}])
    # tools should be a non-empty list (the live registry has tools)
    assert "tools" in args
    assert isinstance(args["tools"], list)
    assert len(args["tools"]) > 0
    assert args["tool_choice"] == "auto"
    # Each tool entry follows OpenAI shape
    for t in args["tools"]:
        assert t["type"] == "function"
        assert "name" in t["function"]
        assert "parameters" in t["function"]


def test_completion_args_filters_by_allowlist(llm: LLM, monkeypatch) -> None:
    """When the lead's `tool_catalog_allowlist` is in
    system_prompt_context, native tool calling renders ONLY those
    tools — same allowlist semantics as the XML prompt-side filter."""
    monkeypatch.setenv("STRIX_TOOL_CALL_FORMAT", "native")
    llm._system_prompt_context["tool_catalog_allowlist"] = ["finish_scan"]
    args = llm._build_completion_args([{"role": "user", "content": "hi"}])
    assert "tools" in args
    names = {t["function"]["name"] for t in args["tools"]}
    # Only the allowed name should be present.
    assert "finish_scan" in names
    # Heuristic: way fewer tools than the unfiltered ~65.
    assert len(args["tools"]) <= 5


# ---------------------------------------------------------------------------
# _extract_native_tool_invocations — the adapter
# ---------------------------------------------------------------------------


def _mk_response(tool_calls: list[dict] | None) -> SimpleNamespace:
    """Build a minimal SimpleNamespace mimicking litellm's structured
    streaming response shape."""
    if tool_calls is None:
        choices = [SimpleNamespace(message=SimpleNamespace(content="text", tool_calls=None))]
    else:
        tc_objs = []
        for tc in tool_calls:
            fn = SimpleNamespace(name=tc["name"], arguments=tc["arguments"])
            tc_objs.append(SimpleNamespace(function=fn))
        choices = [SimpleNamespace(
            message=SimpleNamespace(content="", tool_calls=tc_objs),
        )]
    return SimpleNamespace(choices=choices)


def test_extract_returns_none_for_text_only_response(llm: LLM) -> None:
    response = _mk_response(None)
    assert llm._extract_native_tool_invocations(response) is None


def test_extract_single_tool_call(llm: LLM) -> None:
    response = _mk_response([{
        "name": "scan_xss",
        "arguments": json.dumps({"url": "http://x/", "params": ["q"]}),
    }])
    invs = llm._extract_native_tool_invocations(response)
    assert invs == [
        {"toolName": "scan_xss", "args": {"url": "http://x/", "params": ["q"]}},
    ]


def test_extract_multiple_tool_calls(llm: LLM) -> None:
    response = _mk_response([
        {"name": "scan_xss", "arguments": json.dumps({"url": "http://a/"})},
        {"name": "scan_sqli", "arguments": json.dumps({"url": "http://b/"})},
    ])
    invs = llm._extract_native_tool_invocations(response)
    assert len(invs) == 2
    assert invs[0]["toolName"] == "scan_xss"
    assert invs[1]["toolName"] == "scan_sqli"


def test_extract_handles_dict_arguments_directly(llm: LLM) -> None:
    """litellm normally emits arguments as JSON-encoded string per
    OpenAI spec, but some providers / future versions may pass dict
    directly. Handle both."""
    fn = SimpleNamespace(name="t", arguments={"x": 1, "y": "z"})
    tc = SimpleNamespace(function=fn)
    msg = SimpleNamespace(content="", tool_calls=[tc])
    response = SimpleNamespace(choices=[SimpleNamespace(message=msg)])
    invs = llm._extract_native_tool_invocations(response)
    assert invs == [{"toolName": "t", "args": {"x": 1, "y": "z"}}]


def test_extract_handles_malformed_arguments_gracefully(llm: LLM) -> None:
    """If the API returns non-JSON `arguments`, drop the args (don't
    crash the caller). The downstream tool sees `args={}` and can
    error appropriately."""
    response = _mk_response([{
        "name": "t",
        "arguments": "not valid {json",
    }])
    invs = llm._extract_native_tool_invocations(response)
    assert invs == [{"toolName": "t", "args": {}}]


def test_extract_drops_entries_without_name(llm: LLM) -> None:
    fn = SimpleNamespace(name=None, arguments="{}")
    tc = SimpleNamespace(function=fn)
    msg = SimpleNamespace(content="", tool_calls=[tc])
    response = SimpleNamespace(choices=[SimpleNamespace(message=msg)])
    invs = llm._extract_native_tool_invocations(response)
    # No usable entries → None (falsy from caller's perspective).
    assert invs is None


def test_extract_handles_dict_form_responses(llm: LLM) -> None:
    """Some litellm code paths return plain dicts instead of objects."""
    response = {
        "choices": [
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "scan_xss",
                                "arguments": '{"url":"http://x/"}',
                            }
                        }
                    ],
                }
            }
        ]
    }
    invs = llm._extract_native_tool_invocations(response)
    assert invs == [{"toolName": "scan_xss", "args": {"url": "http://x/"}}]


def test_extract_handles_empty_arguments_string(llm: LLM) -> None:
    response = _mk_response([{"name": "t", "arguments": ""}])
    invs = llm._extract_native_tool_invocations(response)
    assert invs == [{"toolName": "t", "args": {}}]


# ---------------------------------------------------------------------------
# Output shape compatibility — must match XML path's tool_invocations
# ---------------------------------------------------------------------------


def test_native_output_shape_matches_xml_path(llm: LLM) -> None:
    """The whole point of the adapter: downstream code (executor.py,
    process_tool_invocations) consumes the same shape regardless of
    transport. Pin it."""
    response = _mk_response([{
        "name": "scan_xss",
        "arguments": json.dumps({"url": "http://x/", "params": ["q"]}),
    }])
    invs = llm._extract_native_tool_invocations(response)
    # Same shape as parse_tool_invocations() returns
    for inv in invs:
        assert set(inv.keys()) == {"toolName", "args"}
        assert isinstance(inv["toolName"], str)
        assert isinstance(inv["args"], dict)
