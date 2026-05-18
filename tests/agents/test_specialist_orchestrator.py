"""Tests for the §1 fresh-context specialist orchestrator
(`strix/agents/specialist_orchestrator.py` + `strix/tools/workflow/
specialist_dispatch.py`).

This is the MVP of the architectural shift: lead becomes a pure
orchestrator; specialists run bounded multi-round loops in their
own conversation context.

Tests cover:
  * `dispatch_specialist` exit semantics (PASSED / BLOCKED /
    ITERATION_CAP_REACHED / BUDGET_EXCEEDED / ERROR)
  * Fresh-context contract (history doesn't inherit the lead's
    messages)
  * Profile-driven config (per-category system prompts, tool
    subsets, cost caps)
  * Inner-LLM exit signal (`complete_objective` raises the
    signal; the loop polls + exits)
  * Catalog gating: `STRIX_ORCHESTRATOR_MODE=true` swaps the
    lead's catalog to orchestration-only

The inner LLM call is mocked via the `inner_call_fn` parameter so
tests are deterministic + don't consume real LLM cost.
"""

from __future__ import annotations

import os

import pytest

from strix.agents import specialist_orchestrator as so


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_ORCHESTRATOR_MODE", raising=False)
    monkeypatch.delenv("STRIX_SPECIALIST_MAX_ITERATIONS", raising=False)
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_DISPATCH_CAP_OVERRIDE", raising=False)
    so.reset_for_testing()
    yield
    so.reset_for_testing()


# ---------------------------------------------------------------------------
# Profile lookup
# ---------------------------------------------------------------------------


def test_list_categories_returns_built_ins() -> None:
    cats = so.list_categories()
    for expected in ("sqli", "xss", "idor", "recon", "auth"):
        assert expected in cats


def test_get_profile_known_category() -> None:
    p = so.get_profile("sqli")
    assert p.category == "sqli"
    assert "SQLi specialist" in p.system_prompt_addendum
    assert "scan_sqli" in p.allowed_tool_subset
    assert p.max_cost_usd == 0.30


def test_get_profile_falls_through_to_generic() -> None:
    p = so.get_profile("never-heard-of-this")
    # Generic profile — has system prompt but no tool subset.
    assert "bounded specialist" in p.system_prompt_addendum.lower()
    assert p.allowed_tool_subset == []


def test_get_profile_normalises_case_and_whitespace() -> None:
    p1 = so.get_profile("  SQLi  ")
    p2 = so.get_profile("sqli")
    assert p1.category == p2.category


def test_patcher_profile_registered() -> None:
    """P1 — Patcher specialist profile should be available and
    expose the patch CRUD + auto_verify_patch tools."""
    p = so.get_profile("patcher")
    assert p.category == "patcher"
    assert "Patcher" in p.system_prompt_addendum
    # Patcher must have access to the patch toolchain.
    for tool in ("propose_patch", "verify_patch", "auto_verify_patch",
                 "list_patches", "mark_patch_applied"):
        assert tool in p.allowed_tool_subset, (
            f"patcher profile missing tool: {tool}"
        )
    # Plus the §4 verification surface for reading finding state.
    assert "verification_status" in p.allowed_tool_subset
    # Plus an editor for reading + writing code.
    assert "str_replace_editor" in p.allowed_tool_subset
    # Plus the §2 objective hooks (Patcher works from an objective).
    assert "complete_objective" in p.allowed_tool_subset
    # KG read access for chain reasoning.
    assert "kg_query_nodes" in p.allowed_tool_subset


def test_patcher_profile_cost_cap_set() -> None:
    """Patcher gets a slightly larger cost cap than scanners
    because diff-writing + verification eats more tokens."""
    p = so.get_profile("patcher")
    assert p.max_cost_usd == 0.50


# ---------------------------------------------------------------------------
# Dispatch — happy path + exit signal
# ---------------------------------------------------------------------------


def _fake_exit_call(*, history, iteration, profile, **_):
    """Inner-LLM stub that immediately emits a complete_objective
    tool call. Used to verify the loop's exit-signal handling."""
    return {
        "message": "I have completed the objective.",
        "tool_calls": [{
            "tool": "complete_objective",
            "args": {
                "status": "PASSED",
                "reason": "fake exit",
                "summary": "ran 1 iteration via test stub",
            },
        }],
        "cost_usd": 0.001,
    }


def test_dispatch_passes_when_specialist_signals_complete() -> None:
    """The specialist's `complete_objective` call exits the
    loop. Status flows through to the result."""
    result = so.dispatch_specialist(
        category="sqli", objective="probe /login",
        inner_call_fn=_fake_exit_call,
    )
    assert result["status"] == "PASSED"
    assert result["reason"] == "fake exit"
    assert result["summary"].startswith("ran 1 iteration")
    assert result["iterations_used"] == 1


def test_dispatch_signals_status_blocked() -> None:
    def fake_blocked(*, history, iteration, profile):
        return {
            "message": "Need more info",
            "tool_calls": [{
                "tool": "complete_objective",
                "args": {"status": "BLOCKED",
                         "reason": "need_second_session"},
            }],
        }
    result = so.dispatch_specialist(
        category="idor", objective="cross-session probe",
        inner_call_fn=fake_blocked,
    )
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "need_second_session"


# ---------------------------------------------------------------------------
# Dispatch — exit reasons (cap / budget / error)
# ---------------------------------------------------------------------------


def test_dispatch_hits_iteration_cap() -> None:
    """If the specialist never signals exit, the loop terminates
    at `max_iterations`. Returns ITERATION_CAP_REACHED."""
    def fake_no_exit(*, history, iteration, profile):
        return {
            "message": f"iter {iteration}",
            "tool_calls": [{"tool": "send_request", "args": {}}],
            "cost_usd": 0.0,
        }
    result = so.dispatch_specialist(
        category="sqli", objective="probe forever",
        max_iterations=3,
        inner_call_fn=fake_no_exit,
    )
    assert result["status"] == "ITERATION_CAP_REACHED"
    assert result["iterations_used"] == 3


def test_dispatch_exits_on_budget_breach() -> None:
    """When the specialist's accumulated cost exceeds
    `max_cost_usd`, the loop exits with BUDGET_EXCEEDED."""
    def fake_expensive(*, history, iteration, profile):
        return {
            "message": "spending money",
            "tool_calls": [{"tool": "send_request", "args": {}}],
            "cost_usd": 0.50,        # blows past the 0.30 cap immediately
        }
    result = so.dispatch_specialist(
        category="sqli", objective="break the budget",
        max_cost_usd=0.30,
        inner_call_fn=fake_expensive,
    )
    assert result["status"] == "BUDGET_EXCEEDED"
    assert "$0.30" in (result["reason"] or "")


def test_dispatch_exits_passed_on_no_tool_calls() -> None:
    """When the LLM returns no tool_calls + no exit signal,
    treat as implicit completion."""
    def fake_empty(*, history, iteration, profile):
        return {"message": "done", "tool_calls": [], "cost_usd": 0.0}
    result = so.dispatch_specialist(
        category="sqli", objective="exit silently",
        inner_call_fn=fake_empty,
    )
    assert result["status"] == "PASSED"
    assert "no tool calls" in (result["reason"] or "")


def test_dispatch_catches_inner_exception() -> None:
    """If the inner_call_fn raises, the loop catches +
    returns status=ERROR with the exception detail."""
    def fake_raise(*, history, iteration, profile):
        raise RuntimeError("inner LLM unavailable")
    result = so.dispatch_specialist(
        category="sqli", objective="trigger error",
        inner_call_fn=fake_raise,
    )
    assert result["status"] == "ERROR"
    assert "RuntimeError" in (result["reason"] or "")


# ---------------------------------------------------------------------------
# Dispatch — input validation
# ---------------------------------------------------------------------------


def test_dispatch_rejects_empty_category() -> None:
    r = so.dispatch_specialist(
        category="", objective="x", inner_call_fn=_fake_exit_call,
    )
    assert r["status"] == "ERROR"
    assert "category" in (r["reason"] or "").lower()


def test_dispatch_rejects_empty_objective() -> None:
    r = so.dispatch_specialist(
        category="sqli", objective="", inner_call_fn=_fake_exit_call,
    )
    assert r["status"] == "ERROR"
    assert "objective" in (r["reason"] or "").lower()


# ---------------------------------------------------------------------------
# Fresh-context contract
# ---------------------------------------------------------------------------


def test_fresh_context_no_inherited_history() -> None:
    """Verify that the specialist's conversation history starts
    fresh — only the system prompt + the objective, NO inherited
    chat from any caller."""
    captured_histories: list[list[dict]] = []

    def fake_capture(*, history, iteration, profile):
        captured_histories.append(list(history))
        return {
            "message": "exit",
            "tool_calls": [{
                "tool": "complete_objective",
                "args": {"status": "PASSED"},
            }],
            "cost_usd": 0.0,
        }
    so.dispatch_specialist(
        category="sqli", objective="test fresh context",
        inner_call_fn=fake_capture,
    )
    assert len(captured_histories) == 1
    h = captured_histories[0]
    # Exactly two seed messages: system + user(objective).
    assert len(h) == 2
    assert h[0]["role"] == "system"
    assert h[1]["role"] == "user"
    assert h[1]["content"] == "test fresh context"


def test_dispatch_preserves_objective_in_history() -> None:
    captured: list[list[dict]] = []
    def fake(*, history, iteration, profile):
        captured.append(list(history))
        return {"message": "x", "tool_calls": [
            {"tool": "complete_objective", "args": {"status": "PASSED"}}
        ]}
    so.dispatch_specialist(
        category="xss",
        objective="Verify reflected XSS on /search?q=",
        inner_call_fn=fake,
    )
    h = captured[0]
    assert h[1]["content"] == "Verify reflected XSS on /search?q="


# ---------------------------------------------------------------------------
# Exit signal — module level
# ---------------------------------------------------------------------------


def test_signal_specialist_complete_writes_signal() -> None:
    so.signal_specialist_complete(
        status="PASSED", reason="r", summary="s",
    )
    sig = so.get_specialist_exit_signal()
    assert sig is not None
    assert sig["status"] == "PASSED"
    assert sig["reason"] == "r"
    assert sig["summary"] == "s"


def test_signal_cleared_after_read() -> None:
    """`get_specialist_exit_signal` clears the signal. A second
    read returns None — prevents stale signals from triggering
    spurious exits in subsequent dispatches."""
    so.signal_specialist_complete(status="PASSED")
    assert so.get_specialist_exit_signal() is not None
    assert so.get_specialist_exit_signal() is None


def test_signal_normalises_status_uppercase() -> None:
    so.signal_specialist_complete(status="blocked")
    sig = so.get_specialist_exit_signal()
    assert sig["status"] == "BLOCKED"


# ---------------------------------------------------------------------------
# Orchestrator mode env var
# ---------------------------------------------------------------------------


def test_orchestrator_mode_default_off(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_ORCHESTRATOR_MODE", raising=False)
    assert so.is_orchestrator_mode_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_orchestrator_mode_enabled_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_ORCHESTRATOR_MODE", val)
    assert so.is_orchestrator_mode_enabled() is True


# ---------------------------------------------------------------------------
# Catalog filter integration
# ---------------------------------------------------------------------------


def test_catalog_hides_probing_tools_under_orchestrator_mode(
    monkeypatch,
) -> None:
    """When STRIX_ORCHESTRATOR_MODE=true, the lead's catalog is
    swapped to orchestration-only. Probing specialists are
    hidden."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    monkeypatch.setenv("STRIX_ORCHESTRATOR_MODE", "true")
    catalog = get_lead_tool_catalog(target_types=["web_application"])

    # Probing tools hidden.
    for hidden in (
        "scan_sqli", "scan_xss", "scan_idor", "scan_xxe",
        "scan_ssrf", "scan_path_traversal",
        "open_redirect_check", "csrf_check",
    ):
        assert hidden not in catalog, (
            f"orchestrator mode should hide {hidden!r}"
        )

    # Orchestration tools present.
    for present in (
        "dispatch_specialist",
        "workflow_status", "advance_workflow_phase",
        "create_vulnerability_report", "finish_scan",
        "open_hypothesis", "dismiss_hypothesis",
        "think",
    ):
        assert present in catalog, (
            f"orchestrator mode should expose {present!r}"
        )


def test_catalog_default_unchanged_when_orchestrator_off(monkeypatch) -> None:
    """Default (no env var) → catalog matches pre-PR-#233 behaviour:
    probing specialists are present."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    monkeypatch.delenv("STRIX_ORCHESTRATOR_MODE", raising=False)
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_sqli" in catalog
    assert "scan_xss" in catalog
    # dispatch_specialist is also available in default mode (core
    # tool) — the lead CAN call it; the orchestrator-only
    # commitment is only enforced when the env var is set.
    assert "dispatch_specialist" in catalog


def test_catalog_orchestrator_mode_is_compact(monkeypatch) -> None:
    """The orchestrator catalog is intentionally NARROW —
    significantly smaller than the default. This is a key part of
    the architectural commitment: the orchestrator's decision
    space is small, so its decisions are fast + cheap."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    monkeypatch.setenv("STRIX_ORCHESTRATOR_MODE", "true")
    orch_catalog = get_lead_tool_catalog(target_types=["web_application"])

    monkeypatch.delenv("STRIX_ORCHESTRATOR_MODE", raising=False)
    default_catalog = get_lead_tool_catalog(target_types=["web_application"])

    # Orchestrator catalog should be < half the default size.
    assert len(orch_catalog) < len(default_catalog) // 2


# ---------------------------------------------------------------------------
# Env-var tunable max_iterations
# ---------------------------------------------------------------------------


def test_max_iterations_env_override(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SPECIALIST_MAX_ITERATIONS", "10")
    assert so.get_max_iterations() == 10


def test_max_iterations_default(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_SPECIALIST_MAX_ITERATIONS", raising=False)
    assert so.get_max_iterations() == so.DEFAULT_MAX_ITERATIONS


def test_max_iterations_garbage_env_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SPECIALIST_MAX_ITERATIONS", "not-a-number")
    assert so.get_max_iterations() == so.DEFAULT_MAX_ITERATIONS


# ---------------------------------------------------------------------------
# Result dict shape
# ---------------------------------------------------------------------------


def test_result_dict_has_documented_keys() -> None:
    result = so.dispatch_specialist(
        category="sqli", objective="x",
        inner_call_fn=_fake_exit_call,
    )
    for key in (
        "category", "objective", "status", "reason",
        "iterations_used", "findings_count", "duration_s", "summary",
    ):
        assert key in result, f"result missing {key!r}"


def test_result_carries_category_and_objective_back() -> None:
    """Caller can correlate the result with the dispatch by
    reading category + objective off the response."""
    result = so.dispatch_specialist(
        category="xss", objective="probe /search",
        inner_call_fn=_fake_exit_call,
    )
    assert result["category"] == "xss"
    assert result["objective"] == "probe /search"


# ---------------------------------------------------------------------------
# P3 — inner tool routing v1
# ---------------------------------------------------------------------------


def test_execute_inner_tool_calls_complete_objective_always() -> None:
    """`complete_objective` is the exit signal — must be allowed
    regardless of profile.allowed_tool_subset."""
    so.reset_for_testing()
    # Construct a profile with EMPTY allowed_tool_subset.
    profile = so.SpecialistDispatchProfile(
        category="restricted",
        system_prompt_addendum="x",
        allowed_tool_subset=[],
    )
    r = so._execute_inner_tool_call(
        {"tool": "complete_objective", "args": {"status": "PASSED"}},
        profile=profile,
    )
    assert r["success"] is True
    assert r["signaled"] == "complete_objective"
    # And the exit signal was set.
    assert so.get_specialist_exit_signal() is not None


def test_execute_inner_tool_rejects_tool_outside_subset() -> None:
    """Profile gates the allowed tool surface — calling a tool
    outside the subset returns a structured rejection."""
    profile = so.SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum="x",
        allowed_tool_subset=["scan_sqli", "complete_objective"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "browser_action", "args": {}},
        profile=profile,
    )
    assert r["success"] is False
    assert "not in specialist profile" in r["error"]


def test_execute_inner_tool_calls_real_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v1 routes through `strix.tools.registry.get_tool_by_name`.
    Verify by injecting a fake tool that records its call."""
    captured: dict = {}

    def fake_tool(**kwargs) -> dict:
        captured.update(kwargs)
        return {"success": True, "echo": kwargs.get("input", "")}

    from strix.tools.registry import _tools_by_name
    monkeypatch.setitem(_tools_by_name, "fake_tool", fake_tool)

    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=["fake_tool"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "fake_tool", "args": {"input": "hello"}},
        profile=profile,
    )
    assert r["success"] is True
    assert r["echo"] == "hello"
    assert captured == {"input": "hello"}


def test_execute_inner_tool_unknown_tool_returns_error() -> None:
    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=["nonexistent_tool"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "nonexistent_tool", "args": {}},
        profile=profile,
    )
    assert r["success"] is False
    assert "not registered" in r["error"]


def test_execute_inner_tool_handles_typeerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the model passes args the tool doesn't accept, we get
    a structured TypeError-shaped error — NOT a crashed inner loop."""
    def fussy_tool(*, required_arg: str) -> dict:
        return {"ok": required_arg}

    from strix.tools.registry import _tools_by_name
    monkeypatch.setitem(_tools_by_name, "fussy_tool", fussy_tool)

    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=["fussy_tool"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "fussy_tool", "args": {"wrong_arg": "x"}},
        profile=profile,
    )
    assert r["success"] is False
    assert "arg shape" in r["error"]


def test_execute_inner_tool_handles_tool_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crashy_tool(**kwargs) -> dict:
        raise RuntimeError("boom")

    from strix.tools.registry import _tools_by_name
    monkeypatch.setitem(_tools_by_name, "crashy_tool", crashy_tool)

    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=["crashy_tool"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "crashy_tool", "args": {}},
        profile=profile,
    )
    assert r["success"] is False
    assert "RuntimeError" in r["error"]
    assert "boom" in r["error"]


def test_execute_inner_tool_handles_non_dict_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tools that return scalars / strings / lists get wrapped in
    the standard {"success": True, "result": ...} envelope."""
    def list_tool(**kwargs) -> list:
        return [1, 2, 3]

    from strix.tools.registry import _tools_by_name
    monkeypatch.setitem(_tools_by_name, "list_tool", list_tool)

    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=["list_tool"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "list_tool", "args": {}},
        profile=profile,
    )
    assert r["success"] is True
    assert r["result"] == [1, 2, 3]


def test_kill_switch_reverts_to_v0(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """STRIX_SPECIALIST_TOOLS_DISABLED=1 → only complete_objective
    allowed, every other tool returns the v0 rejection."""
    monkeypatch.setenv("STRIX_SPECIALIST_TOOLS_DISABLED", "1")

    def fake_tool(**kwargs) -> dict:
        return {"success": True}

    from strix.tools.registry import _tools_by_name
    monkeypatch.setitem(_tools_by_name, "should_not_run", fake_tool)

    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=["should_not_run"],
    )
    r = so._execute_inner_tool_call(
        {"tool": "should_not_run", "args": {}},
        profile=profile,
    )
    assert r["success"] is False
    assert "v0 mode" in r["error"]


def test_kill_switch_still_allows_complete_objective(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even in v0 mode (kill switch on), complete_objective must
    still work — otherwise the inner loop can't exit."""
    so.reset_for_testing()
    monkeypatch.setenv("STRIX_SPECIALIST_TOOLS_DISABLED", "1")
    profile = so.SpecialistDispatchProfile(
        category="custom",
        system_prompt_addendum="x",
        allowed_tool_subset=[],
    )
    r = so._execute_inner_tool_call(
        {"tool": "complete_objective", "args": {"status": "PASSED"}},
        profile=profile,
    )
    assert r["success"] is True


# ---------------------------------------------------------------------------
# Phase-1 scan-mode dispatch gate
# (docs/proposals/2026-05-19-scan-mode-cost-optimization.md)
#
# These tests pin the engine-level gate: --scan-mode quick / initial cap
# at 0 dispatches (deterministic-only); standard caps at 8; deep is
# unbounded. The override env (STRIX_DISPATCH_CAP_OVERRIDE) takes
# precedence.
# ---------------------------------------------------------------------------


def test_dispatch_cap_quick_blocks_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--scan-mode quick` → cap=0 → first dispatch is denied."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    assert so.get_scan_mode_dispatch_cap() == 0
    r = so.dispatch_specialist(
        category="sqli", objective="probe /login",
        inner_call_fn=_fake_exit_call,
    )
    assert r["status"] == "DENIED_BY_SCAN_MODE"
    assert "quick" in (r["reason"] or "")
    assert r["iterations_used"] == 0
    assert r["findings_count"] == 0
    # Counter does not increment for denied calls — the cap is the
    # gate, not a quota that the denied call consumes.
    assert so.get_dispatch_count() == 0


def test_dispatch_cap_initial_blocks_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Engine-wishlist §2 — `initial` mode shares the cap=0
    semantics with quick."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "initial")
    assert so.get_scan_mode_dispatch_cap() == 0
    r = so.dispatch_specialist(
        category="recon", objective="enumerate endpoints",
        inner_call_fn=_fake_exit_call,
    )
    assert r["status"] == "DENIED_BY_SCAN_MODE"


def test_dispatch_cap_standard_allows_8_denies_9th(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--scan-mode standard` → cap=8 → first 8 dispatches run,
    9th is denied."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")
    assert so.get_scan_mode_dispatch_cap() == 8
    statuses = []
    for i in range(9):
        r = so.dispatch_specialist(
            category="sqli", objective=f"dispatch-{i}",
            inner_call_fn=_fake_exit_call,
        )
        statuses.append(r["status"])
    assert statuses[:8] == ["PASSED"] * 8
    assert statuses[8] == "DENIED_BY_SCAN_MODE"
    assert so.get_dispatch_count() == 8


def test_dispatch_cap_deep_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--scan-mode deep` → no cap — caller is bounded only by
    `--max-cost`."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    assert so.get_scan_mode_dispatch_cap() is None
    statuses = [
        so.dispatch_specialist(
            category="sqli", objective=f"dispatch-{i}",
            inner_call_fn=_fake_exit_call,
        )["status"]
        for i in range(12)
    ]
    assert statuses == ["PASSED"] * 12
    assert so.get_dispatch_count() == 12


def test_dispatch_cap_unset_mode_falls_through_to_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset / unknown scan_mode → unbounded (we never silently
    throttle a run that didn't opt in)."""
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    assert so.get_scan_mode_dispatch_cap() is None
    monkeypatch.setenv("STRIX_SCAN_MODE", "wat")
    assert so.get_scan_mode_dispatch_cap() is None


def test_dispatch_cap_override_overrides_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`STRIX_DISPATCH_CAP_OVERRIDE=2` should win over the mode."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    monkeypatch.setenv("STRIX_DISPATCH_CAP_OVERRIDE", "2")
    assert so.get_scan_mode_dispatch_cap() == 2
    statuses = [
        so.dispatch_specialist(
            category="sqli", objective=f"d-{i}",
            inner_call_fn=_fake_exit_call,
        )["status"]
        for i in range(3)
    ]
    assert statuses == ["PASSED", "PASSED", "DENIED_BY_SCAN_MODE"]


def test_dispatch_cap_override_zero_disables_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Override = 0 should hard-disable dispatch even on deep."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    monkeypatch.setenv("STRIX_DISPATCH_CAP_OVERRIDE", "0")
    r = so.dispatch_specialist(
        category="sqli", objective="probe",
        inner_call_fn=_fake_exit_call,
    )
    assert r["status"] == "DENIED_BY_SCAN_MODE"


def test_dispatch_cap_override_garbage_falls_back_to_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-int override is ignored — we fall back to the
    mode-derived cap, so we never silently disable dispatch on a
    typo."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    monkeypatch.setenv("STRIX_DISPATCH_CAP_OVERRIDE", "high")
    assert so.get_scan_mode_dispatch_cap() is None


def test_reset_for_testing_clears_dispatch_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`reset_for_testing` (called between scans + by the
    cli/tui boot path) must zero the counter, otherwise a
    re-entrant CLI invocation would inherit the previous run's
    count and start partway into the cap."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")
    for _ in range(3):
        so.dispatch_specialist(
            category="sqli", objective="probe",
            inner_call_fn=_fake_exit_call,
        )
    assert so.get_dispatch_count() == 3
    so.reset_for_testing()
    assert so.get_dispatch_count() == 0


def test_dispatch_cap_denied_call_does_not_consume_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DENIED_BY_SCAN_MODE call must not bump the counter —
    otherwise repeated denied attempts would loop the counter
    upward without anyone noticing."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    for _ in range(5):
        r = so.dispatch_specialist(
            category="sqli", objective="probe",
            inner_call_fn=_fake_exit_call,
        )
        assert r["status"] == "DENIED_BY_SCAN_MODE"
    assert so.get_dispatch_count() == 0
