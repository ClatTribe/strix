"""Unit tests for the Phase 3b inner-LLM orchestrator.

These tests cover the orchestrator's dispatch shape and fallback
behaviour WITHOUT actually calling a live LLM. The litellm
`completion` function is monkeypatched to return controlled JSON.

Empirical recall validation against real targets (e.g. testfire)
is a separate benchmark pass — these tests pin the contract,
not the agentic behaviour.
"""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from strix.tools.specialist import llm_orchestrator
from strix.tools.specialist.llm_orchestrator import (
    _merge_retry_args,
    _parse_suggestion_json,
    is_inner_llm_disabled,
    reset_prompt_cache_for_tests,
    run_inner_llm_specialist,
)
from strix.tools.specialist.result import SpecialistResult


@pytest.fixture(autouse=True)
def _reset_prompt_cache():
    reset_prompt_cache_for_tests()
    yield
    reset_prompt_cache_for_tests()


@pytest.fixture
def _stub_llm_env(monkeypatch):
    """Set the model env var so the orchestrator reaches the
    `_call_inner_llm` call (which the individual tests then mock)
    rather than short-circuiting at the no-model-configured guard."""
    monkeypatch.setenv("STRIX_LLM", "test-model/stub")
    monkeypatch.delenv(
        "STRIX_SPECIALIST_INNER_LLM_DISABLED", raising=False,
    )
    yield


# ---------------------------------------------------------------------------
# Suggestion-JSON parser
# ---------------------------------------------------------------------------


def test_parse_suggestion_strict_json() -> None:
    out = _parse_suggestion_json('{"retry": true, "reasoning": "x"}')
    assert out == {"retry": True, "reasoning": "x"}


def test_parse_suggestion_with_code_fence() -> None:
    content = (
        "Here's my suggestion:\n"
        "```json\n"
        '{"retry": true, "params": ["q"]}\n'
        "```"
    )
    out = _parse_suggestion_json(content)
    assert out == {"retry": True, "params": ["q"]}


def test_parse_suggestion_returns_none_on_garbage() -> None:
    assert _parse_suggestion_json("not json at all") is None
    assert _parse_suggestion_json("") is None
    assert _parse_suggestion_json("```\nno braces here\n```") is None


def test_parse_suggestion_rejects_array() -> None:
    """LLM sometimes returns a top-level array. Treat as None
    (the orchestrator expects a dict-shaped suggestion)."""
    assert _parse_suggestion_json("[1, 2, 3]") is None


# ---------------------------------------------------------------------------
# Retry-arg merge — only allowlisted keys flow through
# ---------------------------------------------------------------------------


def test_merge_retry_args_replaces_allowlisted_keys() -> None:
    original = {"url": "http://x", "params": ["q"], "method": "GET"}
    suggestion = {"method": "POST", "params": ["query"]}
    merged = _merge_retry_args(original, suggestion)
    assert merged == {"url": "http://x", "params": ["query"], "method": "POST"}


def test_merge_retry_args_drops_unknown_keys() -> None:
    """LLM can't inject random keys into the procedural function's
    signature — only the allowlist of retry-safe fields passes."""
    original = {"url": "http://x", "params": ["q"]}
    suggestion = {
        "url": "http://y",
        "agent_state": "evil",          # framework-injected, must drop
        "evil_field": "exploit",        # unknown, must drop
        "params": ["q2"],
    }
    merged = _merge_retry_args(original, suggestion)
    assert merged == {"url": "http://y", "params": ["q2"]}
    assert "agent_state" not in merged
    assert "evil_field" not in merged


def test_merge_retry_args_with_empty_suggestion() -> None:
    original = {"url": "http://x", "params": ["q"]}
    merged = _merge_retry_args(original, {})
    assert merged == original


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_default_off(monkeypatch) -> None:
    monkeypatch.delenv(
        "STRIX_SPECIALIST_INNER_LLM_DISABLED", raising=False,
    )
    assert is_inner_llm_disabled() is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_kill_switch_enabled_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_SPECIALIST_INNER_LLM_DISABLED", val)
    assert is_inner_llm_disabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", ""])
def test_kill_switch_disabled_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_SPECIALIST_INNER_LLM_DISABLED", val)
    assert is_inner_llm_disabled() is False


# ---------------------------------------------------------------------------
# Orchestrator end-to-end — proedural mocked
# ---------------------------------------------------------------------------


def _ok_result(findings: list | None = None) -> dict:
    return SpecialistResult(
        status="ok",
        findings=findings or [],
        evidence=["probed with corpus v1"],
    ).model_dump()


def test_first_pass_findings_skip_inner_llm() -> None:
    """When the procedural probe already returned findings, the
    orchestrator must NOT spend an LLM call — that's the cost
    optimization."""
    procedural = MagicMock(return_value=_ok_result(
        findings=[{"title": "xss in q", "category": "xss", "severity": "high"}]
    ))

    with patch("strix.tools.specialist.llm_orchestrator._call_inner_llm") as mock_llm:
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="tools/specialist/prompts/xss.md",
            default_budget={"cost_usd": 0.05, "max_wall_seconds": 60},
            task_args={"url": "http://x", "params": ["q"]},
        )

    assert procedural.call_count == 1
    mock_llm.assert_not_called()
    assert result["tool_metadata"]["inner_llm_retry"]["engaged"] is False
    assert "first_pass_had_findings" in result["tool_metadata"]["inner_llm_retry"]["reason"]


def test_empty_first_pass_triggers_llm_retry(_stub_llm_env) -> None:
    """When procedural returns 0 findings, the orchestrator engages
    the LLM, parses a retry suggestion, and re-runs procedural with
    adapted args."""
    # First call: empty; second call: a finding.
    procedural = MagicMock(side_effect=[
        _ok_result(findings=[]),
        _ok_result(findings=[{"title": "xss via body", "category": "xss", "severity": "high"}]),
    ])
    llm_mock = MagicMock(return_value={
        "retry": True,
        "reasoning": "switch to POST body form",
        "method": "POST",
        "body_template": {"q": "PAYLOAD"},
        "body_format": "form",
    })

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
        llm_mock,
    ):
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="tools/specialist/prompts/xss.md",
            default_budget={"cost_usd": 0.05, "max_wall_seconds": 60},
            task_args={"url": "http://x", "params": ["q"]},
        )

    assert procedural.call_count == 2
    llm_mock.assert_called_once()
    # Second call got the adapted args.
    retry_kwargs = procedural.call_args_list[1].kwargs
    assert retry_kwargs["method"] == "POST"
    assert retry_kwargs["body_format"] == "form"
    # Result reflects the retry.
    meta = result["tool_metadata"]["inner_llm_retry"]
    assert meta["engaged"] is True
    assert meta["retry_findings_count"] == 1
    assert meta["llm_reasoning"] == "switch to POST body form"


def test_llm_says_no_retry_returns_first_result(_stub_llm_env) -> None:
    """LLM returning `retry: false` is honoured — no second
    procedural call, original result returned with metadata."""
    procedural = MagicMock(return_value=_ok_result(findings=[]))
    llm_mock = MagicMock(return_value={
        "retry": False,
        "reasoning": "endpoint clearly CSP-locked",
    })

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
        llm_mock,
    ):
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="tools/specialist/prompts/xss.md",
            default_budget={"cost_usd": 0.05, "max_wall_seconds": 60},
            task_args={"url": "http://x", "params": ["q"]},
        )

    assert procedural.call_count == 1
    assert result["tool_metadata"]["inner_llm_retry"]["engaged"] is True
    assert result["tool_metadata"]["inner_llm_retry"]["reason"] == "llm_decided_no_retry"


def test_llm_call_failure_falls_back_silently(_stub_llm_env) -> None:
    """LLM call returning None (network failure, parse failure)
    must NOT crash — orchestrator returns the procedural result
    with telemetry hinting at the failure mode."""
    procedural = MagicMock(return_value=_ok_result(findings=[]))
    llm_mock = MagicMock(return_value=None)

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
        llm_mock,
    ):
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="tools/specialist/prompts/xss.md",
            default_budget={"cost_usd": 0.05, "max_wall_seconds": 60},
            task_args={"url": "http://x", "params": ["q"]},
        )

    assert procedural.call_count == 1
    meta = result["tool_metadata"]["inner_llm_retry"]
    assert meta["engaged"] is True
    assert "llm_call_or_parse_failed" in meta["reason"]


def test_missing_system_prompt_path_skips_llm(tmp_path) -> None:
    """`system_prompt_path=None` means the lead's wiring forgot
    to supply a prompt. Skip cleanly (return procedural result),
    don't call litellm."""
    procedural = MagicMock(return_value=_ok_result(findings=[]))

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
    ) as mock_llm:
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path=None,
            default_budget=None,
            task_args={"url": "http://x"},
        )

    mock_llm.assert_not_called()
    assert result["tool_metadata"]["inner_llm_retry"]["reason"] == "no_system_prompt_configured"


def test_unreadable_system_prompt_skips_llm() -> None:
    """A wrong path doesn't crash — skip cleanly + telemetry."""
    procedural = MagicMock(return_value=_ok_result(findings=[]))

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
    ) as mock_llm:
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="nonexistent/path/to/prompt.md",
            default_budget=None,
            task_args={"url": "http://x"},
        )

    mock_llm.assert_not_called()
    assert result["tool_metadata"]["inner_llm_retry"]["reason"] == "system_prompt_unreadable"


def test_retry_args_invalid_for_procedural_signature(_stub_llm_env) -> None:
    """If the LLM suggestion produces args the procedural function
    rejects (TypeError), the orchestrator catches + returns the
    original result with diagnostic metadata. Never crashes."""

    def fake_procedural(*, url, params):
        # Only accepts url + params; doesn't take `method` etc.
        return _ok_result(findings=[])

    llm_mock = MagicMock(return_value={
        "retry": True,
        "reasoning": "try POST",
        "method": "POST",       # this will TypeError fake_procedural
    })

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
        llm_mock,
    ):
        result = run_inner_llm_specialist(
            procedural_func=fake_procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="tools/specialist/prompts/xss.md",
            default_budget=None,
            task_args={"url": "http://x", "params": ["q"]},
        )

    # No crash — returns sensible result.
    assert isinstance(result, dict)
    assert result["tool_metadata"]["inner_llm_retry"]["reason"] == "retry_args_invalid"


def test_noop_suggestion_skips_retry_call(_stub_llm_env) -> None:
    """LLM suggestion that matches the original args exactly should
    NOT trigger a wasted second procedural call."""
    procedural = MagicMock(return_value=_ok_result(findings=[]))
    llm_mock = MagicMock(return_value={
        "retry": True,
        "reasoning": "no changes needed",
        # No fields different from task_args.
    })

    with patch(
        "strix.tools.specialist.llm_orchestrator._call_inner_llm",
        llm_mock,
    ):
        result = run_inner_llm_specialist(
            procedural_func=procedural,
            specialist_name="scan_xss",
            category="xss-specialist",
            system_prompt_path="tools/specialist/prompts/xss.md",
            default_budget=None,
            task_args={"url": "http://x", "params": ["q"]},
        )

    assert procedural.call_count == 1
    assert result["tool_metadata"]["inner_llm_retry"]["reason"] == "suggestion_was_noop"


# ---------------------------------------------------------------------------
# Registry dispatch wiring (the decorator routes llm=True via orchestrator)
# ---------------------------------------------------------------------------


def test_decorator_routes_llm_true_through_orchestrator() -> None:
    """Pinning the dispatch contract: when llm=True, the wrapper
    must route through `run_inner_llm_specialist`, NOT call the
    procedural function directly."""
    from strix.tools.specialist.registry import (
        get_specialist_descriptor,
    )
    d = get_specialist_descriptor("scan_xss")
    assert d is not None
    assert d.llm is True
    assert d.system_prompt_path == "tools/specialist/prompts/xss.md"

    d2 = get_specialist_descriptor("scan_sqli")
    assert d2 is not None
    assert d2.llm is True
    assert d2.system_prompt_path == "tools/specialist/prompts/sqli.md"

    d3 = get_specialist_descriptor("scan_idor")
    assert d3 is not None
    assert d3.llm is True
    assert d3.system_prompt_path == "tools/specialist/prompts/idor.md"


def test_kill_switch_routes_directly_to_procedural(monkeypatch) -> None:
    """When STRIX_SPECIALIST_INNER_LLM_DISABLED=1, the decorator
    must NOT call the orchestrator at all — bypass straight to
    the procedural function. Critical for safe roll-back."""
    monkeypatch.setenv("STRIX_SPECIALIST_INNER_LLM_DISABLED", "1")
    from strix.tools.specialist.registry import _should_route_to_inner_llm
    assert _should_route_to_inner_llm() is False


def test_kill_switch_off_routes_to_inner_llm(monkeypatch) -> None:
    monkeypatch.delenv(
        "STRIX_SPECIALIST_INNER_LLM_DISABLED", raising=False,
    )
    from strix.tools.specialist.registry import _should_route_to_inner_llm
    assert _should_route_to_inner_llm() is True
