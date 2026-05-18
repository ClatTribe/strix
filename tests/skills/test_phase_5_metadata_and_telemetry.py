"""Phase 5 — trigger backfill + last_updated metadata + skill.loaded
telemetry + TEMPLATE.md.

Pins:
  * 8 older skills had `triggers:` backfilled (sqlmap, semgrep, nuclei,
    kubernetes, fastapi, nextjs, graphql, supabase).
  * `get_skill_frontmatter(name)` reads frontmatter into a dict.
  * `load_skills(..., loaded_by='x')` emits a skill.loaded event with
    attribution.
  * TEMPLATE.md exists at the top level + has the canonical sections.
"""

from __future__ import annotations

from pathlib import Path

from strix.utils.resource_paths import get_strix_resource_path


def test_backfilled_triggers_present() -> None:
    """The 8 older skills that lacked triggers now have them."""
    base = get_strix_resource_path("skills")
    backfilled = [
        ("tooling", "sqlmap"),
        ("tooling", "semgrep"),
        ("tooling", "nuclei"),
        ("cloud", "kubernetes"),
        ("frameworks", "fastapi"),
        ("frameworks", "nextjs"),
        ("protocols", "graphql"),
        ("technologies", "supabase"),
    ]
    for category, skill in backfilled:
        path: Path = base / category / f"{skill}.md"
        content = path.read_text(encoding="utf-8")
        assert "\ntriggers:" in content, (
            f"{category}/{skill}: triggers backfill missing"
        )


def test_get_skill_frontmatter_returns_dict() -> None:
    """Frontmatter inspector reads required fields."""
    from strix.skills import get_skill_frontmatter

    fm = get_skill_frontmatter("sql_injection")
    assert fm is not None
    assert fm.get("name") == "sql-injection"
    assert "description" in fm


def test_get_skill_frontmatter_unknown_returns_none() -> None:
    from strix.skills import get_skill_frontmatter

    assert get_skill_frontmatter("definitely_not_a_skill_xyz") is None


def test_template_exists() -> None:
    """TEMPLATE.md sits at the top level with canonical sections."""
    base = get_strix_resource_path("skills")
    template = base / "TEMPLATE.md"
    assert template.exists(), "strix/skills/TEMPLATE.md missing"

    content = template.read_text(encoding="utf-8")
    # Canonical sections from the template
    for section in [
        "## Attack Surface",
        "## Detection Channels",
        "## Operational Runbook",
        "## Validation",
        "## False Positives",
        "## Remediation",
        "## Summary",
    ]:
        assert section in content, f"TEMPLATE.md missing section: {section}"


def test_template_not_in_menu() -> None:
    """TEMPLATE.md must NOT appear as a skill in the menu (it's a
    top-level file, not in a category)."""
    from strix.skills.menu import generate_skills_menu

    menu = generate_skills_menu()
    assert "skill-template" not in menu, (
        "TEMPLATE.md leaked into the agent-facing menu"
    )
    assert "TEMPLATE" not in menu.upper().split("\n")[0:30], (
        "TEMPLATE in menu header — should be skipped"
    )


def test_load_skills_emits_skill_loaded_event(monkeypatch) -> None:
    """load_skills() fires a skill.loaded event with loaded_by attrib."""
    from strix.skills import load_skills

    events: list[dict] = []

    class FakeTracer:
        def emit_event(self, **kwargs):
            events.append(kwargs)

    def fake_get_tracer():
        return FakeTracer()

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        fake_get_tracer,
    )

    result = load_skills(["sql_injection"], loaded_by="test")
    assert "sql_injection" in result, "skill should have loaded"
    assert any(
        e.get("kind") == "skill.loaded" and e.get("skill_name") == "sql_injection"
        and e.get("loaded_by") == "test"
        for e in events
    ), f"expected a skill.loaded event with loaded_by=test; got {events}"


def test_load_skills_telemetry_swallows_tracer_errors(monkeypatch) -> None:
    """A broken tracer must not break skill loading."""
    from strix.skills import load_skills

    def broken_tracer():
        raise RuntimeError("tracer broken")

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        broken_tracer,
    )

    # Must still load the skill despite the tracer breaking
    result = load_skills(["sql_injection"])
    assert "sql_injection" in result


def test_load_skills_default_loaded_by_is_unknown(monkeypatch) -> None:
    """Backward-compat: callers without loaded_by get 'unknown'."""
    from strix.skills import load_skills

    events: list[dict] = []

    class FakeTracer:
        def emit_event(self, **kwargs):
            events.append(kwargs)

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: FakeTracer(),
    )

    load_skills(["sql_injection"])
    assert any(
        e.get("loaded_by") == "unknown" for e in events
    ), "default loaded_by should be 'unknown'"


def test_orchestrator_loads_skills_as_orchestrator(monkeypatch) -> None:
    """When the orchestrator builds a system prompt, the loaded_by
    attribution is 'orchestrator'."""
    from strix.agents.specialist_orchestrator import (
        SpecialistDispatchProfile,
        _build_system_prompt,
    )

    events: list[dict] = []

    class FakeTracer:
        def emit_event(self, **kwargs):
            events.append(kwargs)

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: FakeTracer(),
    )

    profile = SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum="x",
        recommended_skills=["sql_injection"],
    )
    _build_system_prompt(
        profile=profile, scope_context=None, relevant_findings=None,
    )

    assert any(
        e.get("kind") == "skill.loaded"
        and e.get("loaded_by") == "orchestrator"
        for e in events
    ), f"orchestrator path should emit skill.loaded with loaded_by=orchestrator; got {events}"
