"""Tests for §8.5 — `system_prompt.jinja` renders the lead-architecture
block when the LeadAgent's `system_prompt_context` is in play.

The render block was added because gemini-2.5-pro consistently
disregarded strix's `<function=...>` tool-call format and produced
`<start_code>` Python-style calls instead. The framework couldn't
parse them, the agent hallucinated the results, and the watchdog
then fired (correctly).

The template addition reinforces the format inside the rendered
prompt — much closer to the model's effective attention than a
context dict the template doesn't read.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape


@pytest.fixture
def env() -> Environment:
    template_dir = Path("strix/agents/StrixAgent")
    e = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        keep_trailing_newline=True,
    )
    # Stub the helpers the real LLM class injects so the template
    # renders without IO. We don't need their output for these tests
    # — only the lead-architecture block matters here.
    e.globals["get_tools_prompt"] = lambda *a, **kw: ""
    e.globals["get_skill"] = lambda name: ""
    return e


def _render(env: Environment, **ctx) -> str:
    base_ctx = {
        "loaded_skill_names": [],
        "interactive": False,
    }
    base_ctx.update(ctx)
    return env.get_template("system_prompt.jinja").render(**base_ctx)


# ---------------------------------------------------------------------------
# Rendering — lead-architecture block
# ---------------------------------------------------------------------------


def test_block_absent_when_lead_architecture_inactive(env: Environment) -> None:
    """Legacy parent-spawns-N runs do NOT render the lead block."""
    out = _render(
        env,
        agent_id="a", agent_name="Root Agent", agent_role="root",
        agent_category=None, interactive=False,
        skills_text="",
        system_prompt_context={
            "scope_source": "test",
            "authorization_source": "test",
            "authorized_targets": [],
        },
    )
    assert "SINGLE-LEAD ARCHITECTURE" not in out
    assert "lead_architecture_directives" not in out


def test_block_renders_when_lead_architecture_active(env: Environment) -> None:
    out = _render(
        env,
        agent_id="a", agent_name="Root Agent", agent_role="root",
        agent_category="lead", interactive=False,
        skills_text="",
        system_prompt_context={
            "scope_source": "test",
            "authorization_source": "test",
            "authorized_targets": [],
            "lead_architecture_active": True,
            "lead_architecture_directives": "Custom directive here.",
        },
    )
    assert "SINGLE-LEAD ARCHITECTURE" in out
    assert "Custom directive here." in out


def test_block_uses_default_directive_when_unspecified(env: Environment) -> None:
    """When `lead_architecture_active=True` but `lead_architecture_directives`
    is absent, the template still renders a sensible default."""
    out = _render(
        env,
        agent_id="a", agent_name="Root Agent", agent_role="root",
        agent_category="lead", interactive=False,
        skills_text="",
        system_prompt_context={
            "scope_source": "test",
            "authorization_source": "test",
            "authorized_targets": [],
            "lead_architecture_active": True,
        },
    )
    assert "Always probe the live target" in out


# ---------------------------------------------------------------------------
# Rendering — tool-format reinforcement
# ---------------------------------------------------------------------------


def test_block_includes_xml_tool_format_reinforcement(env: Environment) -> None:
    """The block must explicitly call out the `<function=...>` format
    AND name the wrong formats gemini-2.5-pro keeps producing
    (`<start_code>`, triple-backtick, JSON, Python-style)."""
    out = _render(
        env,
        agent_id="a", agent_name="Root Agent", agent_role="root",
        agent_category="lead", interactive=False,
        skills_text="",
        system_prompt_context={
            "scope_source": "test",
            "authorization_source": "test",
            "authorized_targets": [],
            "lead_architecture_active": True,
            "lead_architecture_directives": "Probe before reporting.",
        },
    )
    assert "<function=tool_name>" in out
    assert "<parameter=name>value</parameter>" in out
    # Wrong-format mentions — model shouldn't disregard these.
    assert "<start_code>" in out
    assert "JSON" in out


def test_block_explains_consequence_of_wrong_format(env: Environment) -> None:
    """Just listing the right format isn't enough — the model needs
    to know what happens if it disregards (no execution, hallucination)."""
    out = _render(
        env,
        agent_id="a", agent_name="Root Agent", agent_role="root",
        agent_category="lead", interactive=False,
        skills_text="",
        system_prompt_context={
            "scope_source": "test",
            "authorization_source": "test",
            "authorized_targets": [],
            "lead_architecture_active": True,
            "lead_architecture_directives": "Probe before reporting.",
        },
    )
    assert "hallucination" in out
    assert "tool will NOT execute" in out


def test_block_lists_blocked_spawn_helpers(env: Environment) -> None:
    """The architectural commitment: spawn helpers are absent. The
    block names them so the model doesn't try."""
    out = _render(
        env,
        agent_id="a", agent_name="Root Agent", agent_role="root",
        agent_category="lead", interactive=False,
        skills_text="",
        system_prompt_context={
            "scope_source": "test",
            "authorization_source": "test",
            "authorized_targets": [],
            "lead_architecture_active": True,
            "lead_architecture_directives": "Probe before reporting.",
        },
    )
    assert "create_agent" in out
    assert "spawn_webapp_specialist_team" in out
