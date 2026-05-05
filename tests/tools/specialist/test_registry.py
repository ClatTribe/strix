"""Tests for §8.5 Phase 1 — `@register_specialist_tool` decorator.

Pins B.1 (two tool classes), B.2 (bounded input), B.8 (result-shape
discipline). These are the load-bearing rules for the §8.5 architecture.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.specialist.registry import (
    SpecialistDescriptor,
    get_specialist_descriptor,
    list_specialist_tools,
    list_specialists_by_category,
    register_specialist_tool,
    reset_registry_for_tests,
)
from strix.tools.specialist.result import SpecialistResult


@pytest.fixture(autouse=True)
def _reset_registry():
    """Reset the module-level registry between tests, but preserve
    real production registrations (e.g. `scan_misconfig`) which live
    at module-import scope."""
    from strix.tools.specialist.registry import _SPECIALIST_REGISTRY

    saved = dict(_SPECIALIST_REGISTRY)
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()
    _SPECIALIST_REGISTRY.update(saved)


# ---------------------------------------------------------------------------
# B.1 — `llm=True` vs `llm=False` distinction
# ---------------------------------------------------------------------------


def test_register_deterministic_specialist() -> None:
    @register_specialist_tool(category="test-deterministic", llm=False)
    def dummy_deterministic(*, url: str) -> SpecialistResult:
        return SpecialistResult(status="ok")

    desc = get_specialist_descriptor("dummy_deterministic")
    assert desc is not None
    assert desc.llm is False
    assert desc.system_prompt_path is None


def test_register_llm_specialist_requires_system_prompt() -> None:
    """B.2 — LLM-driven specialists need a cached system prompt."""
    with pytest.raises(ValueError, match="system_prompt_path is None"):
        @register_specialist_tool(category="test-llm-bad", llm=True)
        def _bad_llm(*, url: str) -> SpecialistResult:
            return SpecialistResult()


def test_register_deterministic_rejects_system_prompt() -> None:
    """No inner-LLM call → no system prompt path."""
    with pytest.raises(ValueError, match="don't invoke an inner LLM"):
        @register_specialist_tool(
            category="test-det-bad",
            llm=False,
            system_prompt_path="strix/prompts/x.jinja",
        )
        def _bad_det(*, url: str) -> SpecialistResult:
            return SpecialistResult()


def test_register_llm_specialist_with_prompt_path() -> None:
    @register_specialist_tool(
        category="test-llm-ok",
        llm=True,
        system_prompt_path="strix/prompts/specialists/x.jinja",
        cached_tool_subset=["send_request"],
    )
    def dummy_llm(*, url: str, params: list[str]) -> SpecialistResult:
        return SpecialistResult(status="ok")

    desc = get_specialist_descriptor("dummy_llm")
    assert desc is not None
    assert desc.llm is True
    assert desc.system_prompt_path.endswith("x.jinja")
    assert desc.cached_tool_subset == ["send_request"]


# ---------------------------------------------------------------------------
# B.2 — bounded input rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forbidden_arg",
    ["messages", "conversation_history", "parent_context", "history", "chat_history"],
)
def test_decorator_rejects_forbidden_bounded_input_args(forbidden_arg: str) -> None:
    """The single load-bearing rule of the §8.5 architecture: the
    decorator catches signature violations at import-time."""
    with pytest.raises(ValueError, match="bounded-input"):
        # Construct a function with the forbidden arg dynamically.
        def _bad(**kwargs: Any) -> SpecialistResult:  # placeholder
            return SpecialistResult()
        # Re-bind to trigger the inspect.signature check.
        exec(f"def _bad(*, {forbidden_arg}): return SpecialistResult()", {"SpecialistResult": SpecialistResult})
        # We can simulate via a lambda with annotated-arg.
        # Easier: define a real function with the forbidden name.
        ns: dict[str, Any] = {"SpecialistResult": SpecialistResult}
        exec(
            f"def _real_bad(*, {forbidden_arg}=None): return SpecialistResult()",
            ns,
        )
        register_specialist_tool(category="test", llm=False)(ns["_real_bad"])


def test_decorator_allows_typed_args() -> None:
    """The corollary: typed args (URL, params, auth_session, target_summary)
    are fine."""
    @register_specialist_tool(category="test-typed", llm=False)
    def dummy_typed(
        *, url: str, params: list[str] | None = None,
        target_summary: str = "",
    ) -> SpecialistResult:
        return SpecialistResult(status="ok")

    assert get_specialist_descriptor("dummy_typed") is not None


def test_decorator_allows_framework_arg_agent_state() -> None:
    """`agent_state` is injected by the existing register_tool plumbing.
    Specialist-tools that accept it must not be rejected."""
    @register_specialist_tool(category="test-with-state", llm=False)
    def dummy_with_state(agent_state: Any, *, url: str) -> SpecialistResult:
        return SpecialistResult(status="ok")

    assert get_specialist_descriptor("dummy_with_state") is not None


# ---------------------------------------------------------------------------
# B.8 — result-shape discipline
# ---------------------------------------------------------------------------


def test_wrapper_coerces_dict_to_specialist_result() -> None:
    @register_specialist_tool(category="test-coerce-dict", llm=False)
    def dummy_dict_return(*, url: str) -> dict:
        return {"status": "ok", "findings": []}

    out = dummy_dict_return(url="https://x")
    assert out["schema_version"] == 1
    assert out["status"] == "ok"


def test_wrapper_passes_through_specialist_result() -> None:
    @register_specialist_tool(category="test-pass-through", llm=False)
    def dummy_result_return(*, url: str) -> SpecialistResult:
        return SpecialistResult(status="ok", evidence=["a", "b"])

    out = dummy_result_return(url="https://x")
    assert out["evidence"] == ["a", "b"]


def test_wrapper_swallows_exception_to_error_result() -> None:
    """Specialists that raise must not crash the lead loop."""
    @register_specialist_tool(category="test-raises", llm=False)
    def dummy_raises(*, url: str) -> SpecialistResult:
        raise RuntimeError("kaboom")

    out = dummy_raises(url="https://x")
    assert out["status"] == "error"
    assert "kaboom" in (out["error"] or "")


def test_wrapper_handles_unexpected_return_type() -> None:
    """Specialist returning a string / int / list → status='error'."""
    @register_specialist_tool(category="test-bad-return", llm=False)
    def dummy_bad_return(*, url: str) -> str:
        return "this is not a SpecialistResult"  # type: ignore[return-value]

    out = dummy_bad_return(url="https://x")
    assert out["status"] == "error"
    assert "unexpected type" in (out["error"] or "")


def test_wrapper_swallows_invalid_dict_payload() -> None:
    """Dict that fails Pydantic validation → swallowed as
    status='error' rather than raising."""
    @register_specialist_tool(category="test-bad-dict", llm=False)
    def dummy_bad_dict(*, url: str) -> dict:
        return {"findings": [{"title": "t", "severity": "wrong"}]}

    out = dummy_bad_dict(url="https://x")
    assert out["status"] == "error"
    assert "coercion" in (out["error"] or "")


# ---------------------------------------------------------------------------
# Introspection helpers (Phase 3 catalog filtering depends on these)
# ---------------------------------------------------------------------------


def test_list_specialist_tools_returns_sorted() -> None:
    @register_specialist_tool(category="cat-a", llm=False)
    def alpha(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    @register_specialist_tool(category="cat-b", llm=False)
    def beta(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    assert list_specialist_tools() == ["alpha", "beta"]


def test_list_specialist_tools_filters_by_llm_class() -> None:
    @register_specialist_tool(category="det", llm=False)
    def deterministic(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    @register_specialist_tool(
        category="llm-x",
        llm=True,
        system_prompt_path="strix/prompts/x.jinja",
    )
    def llm_driven(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    assert list_specialist_tools(llm_only=True) == ["llm_driven"]
    assert list_specialist_tools(llm_only=False) == ["deterministic"]


def test_list_specialists_by_category() -> None:
    @register_specialist_tool(category="security-headers", llm=False)
    def first(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    @register_specialist_tool(category="security-headers", llm=False)
    def second(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    @register_specialist_tool(category="auth", llm=False)
    def third(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    by_cat = list_specialists_by_category()
    assert by_cat["security-headers"] == ["first", "second"]
    assert by_cat["auth"] == ["third"]


def test_descriptor_carries_default_budget_and_cache_ttl() -> None:
    @register_specialist_tool(
        category="test-budget",
        llm=False,
        default_budget={"cost_usd": 0.5, "max_iterations": 20},
        cache_ttl_seconds=7200,
    )
    def dummy_budget(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    desc = get_specialist_descriptor("dummy_budget")
    assert desc.default_budget == {"cost_usd": 0.5, "max_iterations": 20}
    assert desc.cache_ttl_seconds == 7200


def test_descriptor_records_async_capable() -> None:
    @register_specialist_tool(
        category="test-async",
        llm=False,
        async_capable=True,
    )
    def dummy_async(*, url: str) -> SpecialistResult:
        return SpecialistResult()

    desc = get_specialist_descriptor("dummy_async")
    assert desc.async_capable is True
