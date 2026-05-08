"""Tests for §8.5 Phase 3a — LeadAgent class skeleton.

Pins the architectural commitments at the class level:
  * `category="lead"` is forced regardless of caller-supplied state.
  * `system_prompt_context` carries the lead-architecture directives
    + tool-catalog allow-list / block-list.
  * `STRIX_AGENT_ARCHITECTURE=single-lead` env-gate selects LeadAgent.
  * Default (unset / `legacy`) keeps StrixAgent.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.agents.lead_agent import (
    LeadAgent,
    is_single_lead_architecture_enabled,
)
from strix.agents.state import AgentState


# ---------------------------------------------------------------------------
# Env-gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("single-lead", True),
        ("Single-Lead", True),
        ("SINGLE-LEAD", True),
        ("  single-lead  ", True),
        ("legacy", False),
        ("", False),
        ("garbage", False),
    ],
)
def test_env_gate_selection(monkeypatch, raw: str, expected: bool) -> None:
    monkeypatch.setenv("STRIX_AGENT_ARCHITECTURE", raw)
    assert is_single_lead_architecture_enabled() is expected


def test_env_gate_unset_defaults_legacy(monkeypatch) -> None:
    """Default is legacy (parent-spawns-N) — Phase 8 acceptance gate
    flips this default after benchmark validation."""
    monkeypatch.delenv("STRIX_AGENT_ARCHITECTURE", raising=False)
    assert is_single_lead_architecture_enabled() is False


# ---------------------------------------------------------------------------
# LeadAgent construction — category / system_prompt_context
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _llm_env(monkeypatch) -> None:
    """LLMConfig requires STRIX_LLM and an API key."""
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    yield


@pytest.fixture
def base_config() -> dict[str, Any]:
    """Minimal config that BaseAgent.__init__ accepts."""
    state = AgentState(
        task="test task",
        agent_name="test-lead",
        category="auth-attacker",  # caller set wrong category
        max_iterations=10,
    )
    return {"state": state}


def test_lead_agent_forces_category_lead(base_config) -> None:
    """LeadAgent overrides any caller-supplied category to 'lead' so
    the agent.created event carries the right tag."""
    agent = LeadAgent(base_config)
    assert agent.state.category == "lead"


def test_lead_agent_records_is_lead_flag(base_config) -> None:
    agent = LeadAgent(base_config)
    assert agent.is_lead_agent is True


def test_lead_agent_system_prompt_context_carries_directives(base_config) -> None:
    """Lead-architecture directives must reach the LLM client via
    system_prompt_context. Without these, the LLM doesn't know it's
    in single-lead mode."""
    agent = LeadAgent(base_config)
    ctx = agent.llm._system_prompt_context
    assert ctx.get("lead_architecture_active") is True
    assert "lead_architecture_directives" in ctx
    directives = ctx["lead_architecture_directives"]
    # Pinned semantic content of the addendum — short single-paragraph
    # form (the verbose 7-rule version was reverted because it caused
    # prose-hallucination of findings, see the prompt-fix PR).
    assert "single-lead mode" in directives
    assert "no sub-agents" in directives
    assert "probe the live target" in directives
    # Emission-discipline reinforcement (the no-emission failure mode
    # showed real exploits described in prose without ever calling
    # create_vulnerability_report). Pin the must-have phrases.
    assert "EMIT FINDINGS EAGERLY" in directives
    assert "create_vulnerability_report" in directives
    assert "verification_status=pattern_match" in directives
    assert "Prose without an emission means the finding is lost" in directives
    # Canonical-invocation block (gemini-2.5-pro kept inventing wrong
    # params — `url` / `severity` / `remediation` / `type` — until
    # the schema was spelled out explicitly. Pin all 9 required
    # param names here.)
    for required_param in (
        "title", "description", "impact", "target",
        "technical_analysis", "poc_description", "poc_script_code",
        "remediation_steps", "cvss_breakdown",
    ):
        assert f"<parameter={required_param}>" in directives, (
            f"required param {required_param!r} missing from "
            f"canonical-invocation block — agents will fail with "
            f"TypeError on real calls"
        )


def test_lead_agent_carries_tool_catalog_allowlist(base_config) -> None:
    agent = LeadAgent(base_config)
    ctx = agent.llm._system_prompt_context
    allowlist = ctx.get("tool_catalog_allowlist")
    assert isinstance(allowlist, list)
    assert "create_agent" not in allowlist  # architectural commitment
    assert "scan_misconfig" in allowlist  # available specialist
    assert "open_hypothesis" in allowlist  # core
    assert "check_budget" in allowlist  # §2.9 budget introspection


def test_lead_agent_carries_tool_catalog_blocklist(base_config) -> None:
    agent = LeadAgent(base_config)
    ctx = agent.llm._system_prompt_context
    blocklist = ctx.get("tool_catalog_blocklist")
    assert isinstance(blocklist, list)
    assert "create_agent" in blocklist
    for spawn in (
        "spawn_webapp_specialist_team",
        "spawn_code_specialist_team",
        "spawn_webapp_subteam",
    ):
        assert spawn in blocklist


# ---------------------------------------------------------------------------
# Target-type extraction
# ---------------------------------------------------------------------------


def test_lead_agent_extracts_target_types_from_scan_config() -> None:
    state = AgentState(task="t", agent_name="lead", max_iterations=10)
    config = {
        "state": state,
        "scan_config": {
            "targets": [
                {"type": "web_application", "details": {"target_url": "https://x"}},
                {"type": "repository", "details": {"target_repo": "git@..."}},
            ],
        },
    }
    agent = LeadAgent(config)
    assert set(agent.target_types) == {"web_application", "repository"}


def test_lead_agent_falls_back_to_all_target_types_when_scan_config_absent(
    base_config,
) -> None:
    """No scan_config → catalog defaults to union of all target types
    (safest for direct instantiation in tests / debug)."""
    agent = LeadAgent(base_config)
    # Should include tools from at least multiple target types.
    ctx = agent.llm._system_prompt_context
    allowlist = ctx["tool_catalog_allowlist"]
    # Web-app + repo + domain tools all appear.
    assert "send_request" in allowlist  # web_application
    assert "build_code_map" in allowlist  # repository
    assert "subdomain_enum_tool" in allowlist  # domain


def test_lead_agent_target_types_normalised_lowercase() -> None:
    state = AgentState(task="t", agent_name="lead", max_iterations=10)
    config = {
        "state": state,
        "scan_config": {
            "targets": [
                {"type": "WEB_APPLICATION", "details": {}},
                {"type": "  Domain  ", "details": {}},
            ],
        },
    }
    agent = LeadAgent(config)
    assert set(agent.target_types) == {"web_application", "domain"}


# ---------------------------------------------------------------------------
# Inheritance + agent.created event
# ---------------------------------------------------------------------------


def test_lead_agent_is_subclass_of_strix_agent() -> None:
    """LeadAgent inherits StrixAgent.execute_scan so the existing
    scan flow works unchanged."""
    from strix.agents.StrixAgent import StrixAgent

    state = AgentState(task="t", agent_name="lead", max_iterations=10)
    agent = LeadAgent({"state": state})
    assert isinstance(agent, StrixAgent)


def test_lead_agent_inherits_execute_scan_method() -> None:
    state = AgentState(task="t", agent_name="lead", max_iterations=10)
    agent = LeadAgent({"state": state})
    assert hasattr(agent, "execute_scan")
    assert callable(agent.execute_scan)


# ---------------------------------------------------------------------------
# Real-CLI flow: config has NO `state` key, BaseAgent builds it
# ---------------------------------------------------------------------------


def test_lead_agent_forces_category_when_state_built_by_super() -> None:
    """Regression test for the bug surfaced by the demo.testfire.net
    benchmark: cli.py builds `agent_config = {llm_config, max_iterations}`
    WITHOUT a pre-built state. BaseAgent.__init__ then constructs
    `self.state`. The pre-super category-forcing in LeadAgent only
    fires when state is in config; so under the real CLI flow the
    category leaked through as None and `agent.created` events
    showed `category=None` instead of `category="lead"`.

    Fix: post-super category-forcing on `self.state.category`
    regardless of how state was constructed."""
    from strix.llm.config import LLMConfig

    config_without_state = {
        "llm_config": LLMConfig(),
        "max_iterations": 10,
    }
    agent = LeadAgent(config_without_state)
    assert agent.state is not None
    assert agent.state.category == "lead", (
        f"category leaked through as {agent.state.category!r} — the "
        f"category-forcing path is bypassed when config has no `state`"
    )
