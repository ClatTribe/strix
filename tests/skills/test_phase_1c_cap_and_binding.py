"""Phase 1C — drop hard 5-skill cap + specialist→skill auto-binding.

Two architectural changes shipped:

  1. `strix/skills/__init__.py` — the hard 5-cap in
     `validate_requested_skills` becomes an env-tunable default
     of 20 via `STRIX_SKILLS_MAX_PER_AGENT`. The menu-based
     two-level disclosure (PR #236 / `strix/skills/menu.py`)
     made the count cap mostly a leftover; the new default
     covers multi-stack apps (Django + Postgres + Stripe + ...).

  2. `strix/agents/specialist_orchestrator.py` —
     `SpecialistDispatchProfile` gains `recommended_skills`.
     `_build_system_prompt` auto-attaches the matching skill
     bodies (loaded via `strix.skills.load_skills`) into the
     fresh-context specialist's system prompt.
     `dispatch_specialist` accepts a `skills_override` arg so
     operators / tests can override per-call.

The contract this test pins:
  * Default cap is 20, env-tunable.
  * Validation rejects oversized lists with a helpful message.
  * Every built-in profile (except `generic` + `patcher`) has at
    least one paired skill.
  * The system prompt actually contains the skill body when a
    profile with `recommended_skills` is built.
  * `skills_override=[]` suppresses skill injection entirely.
  * `skills_override=['x']` injects only `x`.
  * A missing / invalid skill name fails gracefully (no
    exception; the specialist boots without the skill body).
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Cap removal
# ---------------------------------------------------------------------------


def test_default_cap_is_20(monkeypatch) -> None:
    """Default per-agent skill cap is 20 (up from the legacy 5)."""
    monkeypatch.delenv("STRIX_SKILLS_MAX_PER_AGENT", raising=False)
    from strix.skills import get_max_skills_per_agent

    assert get_max_skills_per_agent() == 20


def test_cap_env_tunable(monkeypatch) -> None:
    """STRIX_SKILLS_MAX_PER_AGENT raises (or lowers) the cap."""
    from strix.skills import get_max_skills_per_agent

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "50")
    assert get_max_skills_per_agent() == 50

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "3")
    assert get_max_skills_per_agent() == 3


def test_cap_env_invalid_falls_back_to_default(monkeypatch) -> None:
    """Garbage env values don't break; default returns."""
    from strix.skills import get_max_skills_per_agent

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "not-a-number")
    assert get_max_skills_per_agent() == 20

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "")
    assert get_max_skills_per_agent() == 20


def test_cap_env_clamps_to_min_1(monkeypatch) -> None:
    """Cap of 0 or negative gets clamped to 1 (can't have a 0-cap)."""
    from strix.skills import get_max_skills_per_agent

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "0")
    assert get_max_skills_per_agent() == 1

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "-5")
    assert get_max_skills_per_agent() == 1


def test_validate_accepts_up_to_default(monkeypatch) -> None:
    """20 valid skills passes; 21 rejects with new helpful message."""
    monkeypatch.delenv("STRIX_SKILLS_MAX_PER_AGENT", raising=False)
    from strix.skills import (
        get_all_skill_names,
        validate_requested_skills,
    )

    available = sorted(get_all_skill_names())
    # Take the first 20 valid skill names from the registry.
    twenty = available[:20]
    assert validate_requested_skills(twenty) is None, (
        "20 valid skills should pass"
    )

    twenty_one = available[:21]
    err = validate_requested_skills(twenty_one)
    assert err is not None and "20" in err, (
        f"21 skills should reject with cap-cite; got: {err!r}"
    )


def test_validate_honours_env_cap(monkeypatch) -> None:
    """Lowering the cap via env tightens validation."""
    from strix.skills import (
        get_all_skill_names,
        validate_requested_skills,
    )

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "3")

    available = sorted(get_all_skill_names())
    assert validate_requested_skills(available[:3]) is None
    err = validate_requested_skills(available[:4])
    assert err is not None and "3" in err


def test_validate_explicit_override_wins(monkeypatch) -> None:
    """An explicit max_skills=N call overrides the env."""
    from strix.skills import (
        get_all_skill_names,
        validate_requested_skills,
    )

    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "100")
    available = sorted(get_all_skill_names())

    # Caller explicitly asks for cap=2 → 3 should reject
    err = validate_requested_skills(available[:3], max_skills=2)
    assert err is not None and "2" in err


# ---------------------------------------------------------------------------
# Specialist → skill auto-binding
# ---------------------------------------------------------------------------


def test_dispatch_profile_has_recommended_skills_field() -> None:
    """The dataclass gained the new field."""
    from strix.agents.specialist_orchestrator import (
        SpecialistDispatchProfile,
    )

    profile = SpecialistDispatchProfile(
        category="test", system_prompt_addendum="...",
    )
    assert profile.recommended_skills == []


def test_every_active_profile_declares_skills() -> None:
    """All shipping profiles except `generic` + `patcher` ship with
    at least one paired skill. New profiles must add their skills."""
    from strix.agents.specialist_orchestrator import _PROFILES

    skill_exempt = {"generic", "patcher"}
    missing = [
        cat for cat, p in _PROFILES.items()
        if cat not in skill_exempt and not p.recommended_skills
    ]
    assert not missing, (
        f"profiles without recommended_skills: {missing}. "
        f"Phase 1C requires every active profile to declare at "
        f"least one paired skill, or be in the exempt set "
        f"({sorted(skill_exempt)})."
    )


def test_recommended_skills_resolve_to_real_files() -> None:
    """Every recommended_skills entry across all profiles must
    match a real `strix/skills/.../<stem>.md` file. Catches typos
    immediately at test time."""
    from strix.agents.specialist_orchestrator import _PROFILES
    from strix.skills import get_all_skill_names

    available = get_all_skill_names()
    broken: list[tuple[str, str]] = []
    for cat, profile in _PROFILES.items():
        for skill in profile.recommended_skills:
            if skill not in available:
                broken.append((cat, skill))
    assert not broken, (
        f"profiles cite missing skills: {broken}. Fix the skill "
        f"name or add the skill file."
    )


def test_build_system_prompt_injects_skill_body() -> None:
    """When a profile has recommended_skills, _build_system_prompt
    inlines the skill body inside a `SKILL: <name>` block."""
    from strix.agents.specialist_orchestrator import (
        SpecialistDispatchProfile,
        _build_system_prompt,
    )

    profile = SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum="sqli specialist addendum",
        recommended_skills=["sql_injection"],
    )
    prompt = _build_system_prompt(
        profile=profile, scope_context=None, relevant_findings=None,
    )
    assert "SKILL: sql_injection" in prompt
    # A canonical phrase from sql_injection.md (frontmatter stripped):
    assert "SQLi" in prompt or "SQL Injection" in prompt


def test_skills_override_empty_list_suppresses_injection() -> None:
    """skills_override=[] means 'no skills' — even when the profile
    has recommended_skills."""
    from strix.agents.specialist_orchestrator import (
        SpecialistDispatchProfile,
        _build_system_prompt,
    )

    profile = SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum="addendum",
        recommended_skills=["sql_injection"],
    )
    prompt = _build_system_prompt(
        profile=profile, scope_context=None, relevant_findings=None,
        skills_override=[],
    )
    assert "SKILL:" not in prompt


def test_skills_override_replaces_profile_default() -> None:
    """skills_override=['x'] uses 'x' instead of the profile's defaults."""
    from strix.agents.specialist_orchestrator import (
        SpecialistDispatchProfile,
        _build_system_prompt,
    )

    profile = SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum="addendum",
        recommended_skills=["sql_injection"],
    )
    prompt = _build_system_prompt(
        profile=profile, scope_context=None, relevant_findings=None,
        skills_override=["xss"],
    )
    assert "SKILL: sql_injection" not in prompt
    assert "SKILL: xss" in prompt


def test_unknown_skill_is_skipped_gracefully() -> None:
    """A bogus skill name doesn't break prompt construction."""
    from strix.agents.specialist_orchestrator import (
        SpecialistDispatchProfile,
        _build_system_prompt,
    )

    profile = SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum="addendum",
        recommended_skills=["sql_injection", "this_skill_does_not_exist"],
    )
    prompt = _build_system_prompt(
        profile=profile, scope_context=None, relevant_findings=None,
    )
    # The real skill still loads
    assert "SKILL: sql_injection" in prompt
    # The bogus one is silently skipped, no exception
    assert "this_skill_does_not_exist" not in prompt


def test_dispatch_specialist_threads_override(monkeypatch) -> None:
    """dispatch_specialist passes skills_override through to the
    inner prompt build. Verified via the test-hook inner_call_fn."""
    from strix.agents import specialist_orchestrator as so

    captured_prompts: list[str] = []

    def fake_inner_call(*, history, iteration, profile):
        # Record the system prompt (history[0]) and exit immediately
        captured_prompts.append(history[0]["content"])
        so.signal_specialist_complete(status="PASSED", summary="test")
        return {"content": "", "tool_calls": []}

    result = so.dispatch_specialist(
        category="sqli",
        objective="test objective",
        skills_override=["xss"],
        inner_call_fn=fake_inner_call,
        max_iterations=1,
    )
    assert result["status"] == "PASSED"
    assert captured_prompts, "inner_call_fn should have been called"
    prompt = captured_prompts[0]
    # The override (xss) should appear; the profile default
    # (sql_injection) should NOT.
    assert "SKILL: xss" in prompt
    assert "SKILL: sql_injection" not in prompt


def test_dispatch_specialist_default_uses_profile_skills(monkeypatch) -> None:
    """Without skills_override, the profile's recommended_skills apply."""
    from strix.agents import specialist_orchestrator as so

    captured_prompts: list[str] = []

    def fake_inner_call(*, history, iteration, profile):
        captured_prompts.append(history[0]["content"])
        so.signal_specialist_complete(status="PASSED", summary="test")
        return {"content": "", "tool_calls": []}

    result = so.dispatch_specialist(
        category="sqli",
        objective="test",
        inner_call_fn=fake_inner_call,
        max_iterations=1,
    )
    assert result["status"] == "PASSED"
    prompt = captured_prompts[0]
    assert "SKILL: sql_injection" in prompt


@pytest.mark.parametrize("category,expected_skill", [
    ("sqli", "sql_injection"),
    ("xss", "xss"),
    ("idor", "idor"),
    ("recon", "asset_discovery_pipeline"),
    ("auth", "authentication_jwt"),
])
def test_each_profile_injects_its_skill(
    category: str, expected_skill: str,
) -> None:
    """Per-category sanity: each built-in profile boots with its
    paired skill body in the prompt."""
    from strix.agents.specialist_orchestrator import (
        _build_system_prompt,
        get_profile,
    )

    profile = get_profile(category)
    prompt = _build_system_prompt(
        profile=profile, scope_context=None, relevant_findings=None,
    )
    assert f"SKILL: {expected_skill}" in prompt
