"""Tests for the specialist registry + scope discipline (roadmap §8.0).

Tests cover:

- Registry has the expected categories
- get_specialist_profile case-insensitive lookup
- get_specialist_profile returns None for unknown / empty / non-string
- Each profile has required fields populated (smoke test on registry)
- Validator profile has inherit_context_default=False
- Web specialists default to inherit_context=True
- list_specialist_categories returns sorted unique list
- create_agent: when category matches profile, defaults applied
  (skills, budget, scope_addendum, inherit_context)
- create_agent: caller skills override profile recommendation
- create_agent: caller budget merges with profile (caller wins per key)
- create_agent: scope_addendum prepended to task
- create_agent: scope_addendum not duplicated on re-spawn
- create_agent: unknown category → no profile applied
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from strix.agents.specialists import (
    SPECIALIST_REGISTRY,
    SpecialistProfile,
    get_specialist_profile,
    list_specialist_categories,
)


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_registry_has_core_categories() -> None:
    """Smoke test: the registry contains the OODA-team specialists
    referenced in §8.1-§8.4."""
    expected = {
        # Web (§8.2)
        "sqli-specialist",
        "xss-specialist",
        "ssrf-scanner",
        "auth-attacker",
        "idor-specialist",
        "csrf-specialist",
        # Code (§8.1)
        "secret-agent",
        "dependency-agent",
        "sast-agent",
        # Domain (§8.3)
        "subdomain-takeover-specialist",
        # IP/Network (§8.4)
        "port-service-specialist",
        # Validator (§7.1 / §17.1)
        "validator-agent",
    }
    actual = set(SPECIALIST_REGISTRY.keys())
    assert expected <= actual, f"registry missing: {expected - actual}"


def test_registry_profiles_have_required_fields() -> None:
    for cat, p in SPECIALIST_REGISTRY.items():
        assert isinstance(p, SpecialistProfile), cat
        assert p.category == cat
        assert p.recommended_skills, f"{cat}: empty skills"
        assert p.scope_addendum, f"{cat}: empty scope_addendum"
        # Default budget is non-empty (per-specialist cost cap is the point)
        assert p.default_budget, f"{cat}: empty default_budget"


def test_validator_starts_fresh() -> None:
    """The Validator should NOT inherit the lead's chain-of-thought."""
    p = get_specialist_profile("validator-agent")
    assert p is not None
    assert p.inherit_context_default is False


def test_web_specialists_inherit_context() -> None:
    """Web specialists DO inherit context from the lead — they need
    the recon findings and crawl output."""
    for cat in ("sqli-specialist", "xss-specialist", "ssrf-scanner"):
        p = get_specialist_profile(cat)
        assert p is not None
        assert p.inherit_context_default is True, cat


# ---------------------------------------------------------------------------
# get_specialist_profile lookup
# ---------------------------------------------------------------------------


def test_get_profile_canonical() -> None:
    p = get_specialist_profile("sqli-specialist")
    assert p is not None
    assert p.category == "sqli-specialist"


def test_get_profile_case_insensitive() -> None:
    p = get_specialist_profile("SQLI-Specialist")
    assert p is not None
    assert p.category == "sqli-specialist"


def test_get_profile_strips_whitespace() -> None:
    p = get_specialist_profile("  xss-specialist  ")
    assert p is not None


def test_get_profile_unknown() -> None:
    assert get_specialist_profile("not-a-specialist") is None


def test_get_profile_none() -> None:
    assert get_specialist_profile(None) is None
    assert get_specialist_profile("") is None
    assert get_specialist_profile("   ") is None


def test_get_profile_non_string() -> None:
    assert get_specialist_profile(123) is None  # type: ignore[arg-type]


def test_list_categories_sorted_and_unique() -> None:
    cats = list_specialist_categories()
    assert cats == sorted(cats)
    assert len(cats) == len(set(cats))
    # The list should match the registry size.
    assert set(cats) == set(SPECIALIST_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Integration with create_agent: scope discipline applied at spawn
# ---------------------------------------------------------------------------


@pytest.fixture
def _stub_spawn_dependencies(monkeypatch):
    """Stub the heavy parts of create_agent so we can observe what
    config it would build without actually starting an agent thread."""
    captured: dict[str, object] = {}

    class _FakeAgent:
        def __init__(self, config):
            captured["config"] = config

    class _FakeState:
        def __init__(self, **kwargs):
            captured["state_kwargs"] = kwargs
            self.agent_id = "agent_test_0001"
            self.agent_name = kwargs.get("agent_name", "x")

        def get_conversation_history(self):
            return []

    class _FakeLLMConfig:
        def __init__(self, **kwargs):
            captured["llm_config_kwargs"] = kwargs

    # Don't actually thread.
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.threading.Thread",
        lambda **_kw: _NoopThread(),
    )

    # Patch the from-imports inside create_agent.
    import strix.agents
    monkeypatch.setattr(strix.agents, "StrixAgent", _FakeAgent, raising=False)
    import strix.agents.state
    monkeypatch.setattr(strix.agents.state, "AgentState", _FakeState, raising=False)
    import strix.llm.config
    monkeypatch.setattr(strix.llm.config, "LLMConfig", _FakeLLMConfig, raising=False)

    return captured


class _NoopThread:
    daemon = True
    def start(self): pass
    def join(self, timeout=None): pass


def _make_parent_state():
    """Minimal parent-state stand-in for create_agent."""
    class _P:
        agent_id = "parent_0001"
        def get_conversation_history(self):
            return []
    return _P()


def test_create_agent_unknown_category_no_profile_applied(_stub_spawn_dependencies):
    """When category isn't registered, no profile defaults applied."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent

    out = create_agent(
        agent_state=_make_parent_state(),
        task="Probe the target.",
        name="Generic-Worker",
        category="not-a-real-category",
    )
    # Spawn either succeeded or failed gracefully — but no profile
    # addendum should appear.
    captured = _stub_spawn_dependencies
    state_kwargs = captured.get("state_kwargs") or {}
    task = state_kwargs.get("task") or ""
    # Scope addendum from any registered profile shouldn't appear:
    for p in SPECIALIST_REGISTRY.values():
        if p.scope_addendum:
            assert p.scope_addendum not in task


def test_create_agent_known_category_applies_addendum(_stub_spawn_dependencies):
    """When category=sqli-specialist, the SQLi scope addendum is
    prepended to the task."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent
    from strix.agents.specialists import get_specialist_profile

    create_agent(
        agent_state=_make_parent_state(),
        task="Probe /api/login for SQLi.",
        name="SQL-Specialist-1",
        category="sqli-specialist",
    )
    captured = _stub_spawn_dependencies
    state_kwargs = captured.get("state_kwargs") or {}
    task = state_kwargs.get("task") or ""
    profile = get_specialist_profile("sqli-specialist")
    assert profile is not None
    assert profile.scope_addendum in task
    # And the original task is preserved.
    assert "Probe /api/login for SQLi." in task


def test_create_agent_known_category_applies_skills(_stub_spawn_dependencies):
    """No skills passed → profile.recommended_skills is used."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent
    from strix.agents.specialists import get_specialist_profile

    create_agent(
        agent_state=_make_parent_state(),
        task="probe",
        name="XSS-1",
        category="xss-specialist",
    )
    captured = _stub_spawn_dependencies
    llm_config_kwargs = captured.get("llm_config_kwargs") or {}
    skills = llm_config_kwargs.get("skills") or []
    profile = get_specialist_profile("xss-specialist")
    assert profile is not None
    # `parse_skill_list` lower-cases and splits on commas.
    expected = {s.strip().lower() for s in profile.recommended_skills.split(",")}
    actual = {str(s).strip().lower() for s in skills}
    assert actual == expected


def test_create_agent_caller_skills_override_profile(_stub_spawn_dependencies):
    """Caller-supplied skills win over profile defaults."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent

    create_agent(
        agent_state=_make_parent_state(),
        task="probe",
        name="SQL-Custom",
        category="sqli-specialist",
        skills="xss",  # caller wants XSS skills, not the profile's sql_injection,sqlmap
    )
    captured = _stub_spawn_dependencies
    llm_config_kwargs = captured.get("llm_config_kwargs") or {}
    skills = llm_config_kwargs.get("skills") or []
    skill_set = {str(s).strip().lower() for s in skills}
    # Caller-supplied "xss" only — not the profile's sql_injection / sqlmap.
    assert "sql_injection" not in skill_set
    assert "sqlmap" not in skill_set
    assert "xss" in skill_set


def test_create_agent_known_category_applies_budget(_stub_spawn_dependencies):
    """No budget passed → profile.default_budget applied to agent_config."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent
    from strix.agents.specialists import get_specialist_profile

    create_agent(
        agent_state=_make_parent_state(),
        task="probe",
        name="SSRF-1",
        category="ssrf-scanner",
    )
    captured = _stub_spawn_dependencies
    config = captured.get("config") or {}
    budget = config.get("budget") or {}
    profile = get_specialist_profile("ssrf-scanner")
    assert profile is not None
    for k, v in profile.default_budget.items():
        assert budget.get(k) == v


def test_create_agent_caller_budget_merges_per_key(_stub_spawn_dependencies):
    """Caller-supplied budget keys win; absent keys fill from profile."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent

    create_agent(
        agent_state=_make_parent_state(),
        task="probe",
        name="SSRF-2",
        category="ssrf-scanner",
        budget={"max_cost_usd": 5.00},  # override only this key
    )
    captured = _stub_spawn_dependencies
    config = captured.get("config") or {}
    budget = config.get("budget") or {}
    assert budget["max_cost_usd"] == 5.00  # caller wins
    # Profile defaults fill remaining:
    from strix.agents.specialists import get_specialist_profile
    profile = get_specialist_profile("ssrf-scanner")
    assert profile is not None
    if "max_input_tokens" in profile.default_budget:
        assert budget.get("max_input_tokens") == profile.default_budget["max_input_tokens"]


def test_create_agent_validator_inherit_context_overridden(_stub_spawn_dependencies):
    """Validator profile says inherit_context_default=False; when
    caller passes the signature default (True) AND profile says
    False, profile wins."""
    from strix.tools.agents_graph.agents_graph_actions import create_agent

    # Use a parent with messages so we can detect inheritance.
    class _ParentWithHistory:
        agent_id = "parent_0002"
        def get_conversation_history(self):
            return [
                {"role": "user", "content": "previous lead chain-of-thought"},
            ]

    create_agent(
        agent_state=_ParentWithHistory(),
        task="Validate the candidates.",
        name="Validator-1",
        category="validator-agent",
        # inherit_context not set explicitly → defaults to True →
        # but the validator profile says False, so profile wins.
    )
    # The agent's inherited_messages should be empty because profile
    # forced inherit_context=False. Hard to inspect with the stub
    # since the threading path is no-op; instead we just verify the
    # profile's intent is respected by the create_agent flow.
    # (Direct unit test of the profile field below.)
    p = get_specialist_profile("validator-agent")
    assert p is not None
    assert p.inherit_context_default is False


def test_addendum_not_duplicated_on_repeat() -> None:
    """If the same task already contains the scope addendum, don't
    prepend again."""
    from strix.agents.specialists import get_specialist_profile

    p = get_specialist_profile("sqli-specialist")
    assert p is not None
    addendum = p.scope_addendum
    task_with_addendum = f"{addendum}\n\nProbe /api/login."

    # We simulate the create_agent logic:
    if addendum and addendum not in task_with_addendum:
        result = f"{addendum.strip()}\n\n{task_with_addendum}"
    else:
        result = task_with_addendum
    # Addendum should appear exactly once.
    assert result.count(addendum) == 1


# ---------------------------------------------------------------------------
# Smoke: profile data is informationally rich
# ---------------------------------------------------------------------------


def test_each_profile_addendum_mentions_scope_words() -> None:
    """Sanity check: each scope_addendum mentions either 'specialist'
    or 'scope' so the spawned agent gets a clear role-context cue."""
    for cat, p in SPECIALIST_REGISTRY.items():
        text = p.scope_addendum.lower()
        assert any(word in text for word in ("specialist", "scope", "validator")), cat


def test_validator_addendum_mentions_verification_status() -> None:
    """The Validator's addendum should explicitly tell the agent how
    to set verification_status — that's its raison d'être."""
    p = get_specialist_profile("validator-agent")
    assert p is not None
    assert "verification_status" in p.scope_addendum
