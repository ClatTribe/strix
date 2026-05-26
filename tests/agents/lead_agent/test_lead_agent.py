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
    # iter-37.2 — minimal catalog is OSS-anchored.
    # iter-37.8 — minimal CORE drops redundant tools (hypothesis x5,
    # notes x5, introspection).
    # iter-37.10 — core trimmed to 5 (workflow_status, list_pending_
    # findings, think, create_vulnerability_report, finish_scan).
    # iter-37.11 — per-asset trimmed to ACT-only; recon (katana) +
    # broad-orient (nuclei) dropped because the prepass fires them.
    # Assertions now reference the survivor set: the 5-tool core +
    # web's ACT-only specialists.
    assert "workflow_status" in allowlist        # core — observe
    assert "list_pending_findings" in allowlist  # core — observe L1 queue
    assert "create_vulnerability_report" in allowlist  # core — emit
    assert "think" in allowlist                  # core — scratchpad
    assert "finish_scan" in allowlist            # core — terminate
    assert "scan_sqli_sqlmap" in allowlist       # web — deep SQLi (sqlmap)
    assert "scan_idor" in allowlist              # web — session-aware authz


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
    # iter-37.2 — minimal catalog: tools from multiple asset types
    # all appear in the union when no scan_config is supplied.
    assert "send_request" in allowlist  # web_application
    assert "build_code_map" in allowlist  # repository
    assert "domain_recon_pipeline" in allowlist  # domain (replaces subdomain_enum_tool — OSS-anchored)


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


# ---------------------------------------------------------------------------
# System prompt — must be loaded (regression for empty-prompt bug)
# ---------------------------------------------------------------------------


def test_lead_agent_system_prompt_is_loaded(base_config) -> None:
    """Regression test for the empty-system-prompt bug surfaced by the
    second demo.testfire.net benchmark (run id `*_4fed`):

    `BaseAgent.__init__` builds `LLM(self.llm_config, agent_name=self.agent_name)`,
    which uses `agent_name` to locate the jinja template via
    `get_strix_resource_path("agents", agent_name)`. The metaclass
    `AgentMeta` overrides `agent_name` to the *class name* — so for
    `class LeadAgent(StrixAgent)` it became `"LeadAgent"`, but the
    template lives under `strix/agents/StrixAgent/`. The lookup
    silently failed in `_load_system_prompt`'s bare-except clause →
    `self.llm.system_prompt = ""`.

    Empirical impact: the lead's first LLM request had `prompt_tokens=145`
    instead of ~80K. Gemini-2.5-pro received only the user instruction,
    fabricated a complete pentest from training data using `<tool_code>`
    Python-syntax, hit zero real probes, and the watchdog terminated
    the run after 8 idle iterations.

    The fix: LeadAgent overrides `agent_name` resolution so the LLM
    finds StrixAgent's template. This test pins that the rendered
    prompt is large (template + tool catalog) AND contains the
    lead-architecture markers."""
    agent = LeadAgent(base_config)
    sp = agent.llm.system_prompt
    # Sanity: prompt is non-trivial (template + tool catalog combined
    # is normally >50k chars; a regression to "" or "missing template"
    # short-circuits this check).
    assert len(sp) > 5000, (
        f"system_prompt is only {len(sp)} chars — template lookup "
        f"likely failed (agent_name resolution bug). Empty/short "
        f"prompts cause LLMs to hallucinate the entire scan from "
        f"training data."
    )
    # The lead-architecture block must render — that's how the model
    # learns about <function=...> XML format reinforcement.
    assert "SINGLE-LEAD ARCHITECTURE" in sp
    assert "CRITICAL — TOOL CALL FORMAT" in sp
    assert "<function=tool_name>" in sp
    # The `EMIT FINDINGS EAGERLY` discipline (PR #167) must reach the
    # rendered prompt, not just the context dict.
    assert "EMIT FINDINGS EAGERLY" in sp
    # The canonical-invocation block (PR #168) must reach the prompt
    # so gemini stops inventing wrong param names.
    assert "<parameter=cvss_breakdown>" in sp


def test_lead_agent_system_prompt_loaded_under_real_cli_path() -> None:
    """Same regression check, but for the cli.py path that doesn't
    pre-build state. This mirrors the actual demo.testfire.net flow
    where the bug originally surfaced."""
    from strix.llm.config import LLMConfig

    config_without_state = {
        "llm_config": LLMConfig(),
        "max_iterations": 10,
    }
    agent = LeadAgent(config_without_state)
    assert len(agent.llm.system_prompt) > 5000
    assert "SINGLE-LEAD ARCHITECTURE" in agent.llm.system_prompt


def test_lead_agent_prompt_excludes_blocked_tools() -> None:
    """Companion to PR #172 (dispatch guard) and #173 (prompt filter):
    the lead's rendered system prompt MUST NOT contain `create_agent`
    or any other blocked tool's schema. If it does, the model is
    tempted to call them — wasting a turn before the dispatch guard
    refuses.

    This test confirms the prompt-side filter actually fires when
    `tool_catalog_allowlist` is in `system_prompt_context` (set by
    LeadAgent.__init__)."""
    from strix.llm.config import LLMConfig

    agent = LeadAgent({"llm_config": LLMConfig(), "max_iterations": 10})
    sp = agent.llm.system_prompt
    assert sp, "system prompt must be non-empty"
    # Hard requirement: no spawn-helper tool schemas.
    assert "<tool name=\"create_agent\"" not in sp
    assert "<tool name=\"spawn_webapp_specialist_team\"" not in sp
    assert "<tool name=\"spawn_code_specialist_team\"" not in sp
    assert "<tool name=\"wait_for_message\"" not in sp
    # And the lead's ACTUAL allowed tools must be present.
    # iter-37.2 — assertions updated for the minimal OSS-anchored
    # catalog. Verify the OSS-anchored generic detection tool
    # (scan_nuclei_templates) is exposed. Other OSS tools
    # (scan_xss_dalfox, scan_sqli_sqlmap) appear in the catalog
    # allowlist but not the base operating directive text — the
    # directive references are scheduled for cleanup in iter-37.5
    # (along with the in-house tool deletions).
    assert "scan_nuclei_templates" in sp


def test_lead_agent_prompt_includes_security_context_block() -> None:
    """§8.5 Phase 5 regression: the lead's system prompt must always
    include the SECURITY CONTEXT block — it's the cross-tool fact
    ledger the model uses for chained reasoning. Even when the
    context is empty, the section header + reasoning directives
    must be present so the model knows the ledger exists."""
    from strix.agents.security_context import (
        record_endpoint,
        reset_security_context,
        set_target_url,
        update_tech_stack,
    )
    from strix.llm.config import LLMConfig

    reset_security_context()
    set_target_url("http://example.com")
    update_tech_stack(server="nginx/1.18", database="MySQL")
    record_endpoint("/login", method="POST", probed_for="sqli")

    agent = LeadAgent({
        "llm_config": LLMConfig(),
        "max_iterations": 10,
        "scan_config": {"targets": [{"type": "web_application",
                                      "details": {"target_url": "http://example.com"}}]},
    })
    sp = agent.llm.system_prompt
    assert "SECURITY CONTEXT" in sp
    # Notebook content must render.
    assert "TARGET: http://example.com" in sp
    assert "nginx/1.18" in sp
    assert "MySQL" in sp
    assert "informs SQLi payload selection" in sp
    assert "/login" in sp
    # Reasoning directives must be present.
    assert "REASON LIKE A SECURITY ENGINEER" in sp
    assert "Chain findings" in sp
    assert "Chase partial signals" in sp
    assert "Test with auth" in sp
    reset_security_context()


def test_lead_agent_prompt_size_reduced_by_filter() -> None:
    """Token-efficiency check: with the allowlist applied, the prompt
    is meaningfully smaller than the unfiltered registry would be.
    Without baseline numbers in the test we just assert a plausible
    upper bound — ~250K chars is the unfiltered size on this branch
    (rough proxy for ~80K tokens). Filtered should be well under."""
    from strix.llm.config import LLMConfig

    agent = LeadAgent({"llm_config": LLMConfig(), "max_iterations": 10})
    sp_filtered = agent.llm.system_prompt
    # With ~30 tools instead of ~130, the prompt should be < 150K chars.
    # Even with some slack for skill content + framework boilerplate.
    assert len(sp_filtered) < 200_000, (
        f"filtered prompt is {len(sp_filtered)} chars — filter may "
        f"not have applied; check `system_prompt_context.tool_catalog_"
        f"allowlist` is being threaded through to `get_tools_prompt`"
    )


# ---------------------------------------------------------------------------
# Asset-aware routing (Phase 6 — DAST + SCA correlation)
# ---------------------------------------------------------------------------


def _make_agent(*target_types: str) -> LeadAgent:
    """Helper: build a LeadAgent with the given target_types."""
    state = AgentState(task="t", agent_name="lead", max_iterations=10)
    return LeadAgent({
        "state": state,
        "scan_config": {
            "targets": [
                {"type": tt, "details": {}}
                for tt in target_types
            ],
        },
    })


def test_asset_routing_repository_anchors_on_sca() -> None:
    """When the only asset is a repo, the routing block must name
    `scan_sca_lockfiles` as the anchor — that's what makes Phase 6
    actionable on a code-only target."""
    agent = _make_agent("repository")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "[repository]" in routing
    assert "scan_sca_lockfiles" in routing


def test_asset_routing_local_code_anchors_on_sca() -> None:
    agent = _make_agent("local_code")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "[local_code]" in routing
    assert "scan_sca_lockfiles" in routing


def test_asset_routing_web_anchors_on_dast_specialists() -> None:
    """Pure web target — DAST anchors named, SCA not the lead-with."""
    agent = _make_agent("web_application")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "[web_application]" in routing
    # DAST specialist names must be present.
    assert "scan_sqli" in routing
    assert "scan_xss" in routing
    # Single-asset path → no cross-asset block.
    assert "CROSS-ASSET CORRELATION" not in routing


def test_asset_routing_paired_web_repo_includes_cross_asset_block() -> None:
    """The vibe-coded-app workflow: deployed URL + co-located repo.
    The routing prompt MUST surface the cross-asset block so the
    lead correlates SCA findings with DAST hypotheses (and vice
    versa). This is the single-lead alternative to the deprecated
    multi-agent "specialist hands findings up" pattern."""
    agent = _make_agent("web_application", "repository")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "[web_application]" in routing
    assert "[repository]" in routing
    assert "CROSS-ASSET CORRELATION" in routing
    # Pin the canonical example so the LLM has a concrete chain to
    # follow — abstract instruction-only routing has historically
    # produced no behaviour change.
    assert "lodash" in routing
    assert "prototype-pollution" in routing or "prototype pollution" in routing.lower()


def test_asset_routing_renders_into_system_prompt() -> None:
    """The routing block must reach the *rendered* system prompt, not
    just the context dict. If the jinja template doesn't pick up
    `lead_asset_routing`, the LLM never sees it."""
    agent = _make_agent("web_application", "repository")
    sp = agent.llm.system_prompt
    assert "ASSET-AWARE ROUTING" in sp
    assert "[repository]" in sp
    assert "CROSS-ASSET CORRELATION" in sp


def test_asset_routing_empty_when_no_known_target_types() -> None:
    """Garbage target_types → routing block is empty (graceful
    degradation, not a hard error)."""
    state = AgentState(task="t", agent_name="lead", max_iterations=10)
    agent = LeadAgent({
        "state": state,
        "scan_config": {
            "targets": [{"type": "unknown_alien_target", "details": {}}],
        },
    })
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    # Either empty string or absent — both are acceptable.
    assert routing == "" or "ASSET-AWARE ROUTING" not in (
        agent.llm.system_prompt
    )


def test_asset_routing_domain_anchors_on_recon() -> None:
    agent = _make_agent("domain")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "[domain]" in routing
    assert "domain_recon_pipeline" in routing


def test_asset_routing_ip_anchors_on_port_scan() -> None:
    agent = _make_agent("ip_address")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "[ip_address]" in routing
    # IP-target routing pivots to web-app probes when HTTP found —
    # the cross-correlation hint is in the per-asset block, not the
    # multi-asset block (since only one asset class is in scope).
    assert "send_request" in routing


def test_asset_routing_web_directs_nuclei_xss_tag_run() -> None:
    """The web_application routing block must direct the lead to ALSO
    call `scan_nuclei_templates` with an xss tag filter alongside
    `scan_xss`. The two are complementary — scan_xss is a generic
    reflected-XSS fuzzer for custom code, nuclei matches product-
    specific XSS CVEs (WordPress plugins, Confluence, etc.). Without
    this explicit instruction the agent historically called only
    scan_xss and missed every product-XSS CVE in the customer's
    third-party stack."""
    agent = _make_agent("web_application")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "scan_nuclei_templates" in routing
    assert "xss" in routing.lower()
    # Pair must be explicit, not vague — `tags=` filter is the
    # critical piece nuclei needs to scope the run.
    assert "tags=" in routing


def test_asset_routing_api_directs_nuclei_cve_run() -> None:
    """The api routing block must direct the lead to ALSO run nuclei
    with a cve tag filter — many APIs ship admin / docs / swagger
    UIs with known XSS / SSRF / RCE CVEs that the deterministic
    API specialists won't catch."""
    agent = _make_agent("api")
    routing = agent.llm._system_prompt_context.get("lead_asset_routing", "")
    assert "scan_nuclei_templates" in routing
    assert "cve" in routing.lower()
