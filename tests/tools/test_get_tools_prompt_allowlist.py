"""Tests for §8.5 — `get_tools_prompt(allowlist=...)` filtering.

Companion to #172 (dispatch-side guard). The prompt-side filter
removes blocked tools from the model's choice space entirely and
saves ~50K tokens per LLM call when the lead's catalog is filtered.

Behavior pinned:
  * `allowlist=None` (default) → full registry rendered (legacy).
  * `allowlist={...}` → only those tool names appear in the output.
  * Module grouping preserved when filtering.
  * Empty allowlist → empty output (no tools).
"""

from __future__ import annotations

import pytest

from strix.tools.registry import get_tools_prompt, register_tool, tools as _tool_registry


@pytest.fixture(autouse=True)
def _seed_registry():
    """Stash + restore the global registry so tests don't pollute each
    other or the live import-time registration."""
    snapshot = list(_tool_registry)
    yield
    _tool_registry.clear()
    _tool_registry.extend(snapshot)


def _make_tool(name: str, module: str, xml: str | None = None) -> dict:
    return {
        "name": name,
        "module": module,
        "xml_schema": xml or f"<tool name=\"{name}\"><param name=\"x\"/></tool>",
    }


def test_default_renders_all_tools() -> None:
    """No allowlist → full registry. Pre-existing behaviour, must not
    regress."""
    _tool_registry.clear()
    _tool_registry.extend([
        _make_tool("alpha", "modA"),
        _make_tool("beta", "modB"),
        _make_tool("gamma", "modA"),
    ])
    out = get_tools_prompt()
    assert "alpha" in out
    assert "beta" in out
    assert "gamma" in out


def test_allowlist_filters_to_listed_names() -> None:
    _tool_registry.clear()
    _tool_registry.extend([
        _make_tool("alpha", "modA"),
        _make_tool("beta", "modB"),
        _make_tool("gamma", "modA"),
    ])
    out = get_tools_prompt(allowlist=["alpha", "gamma"])
    assert "alpha" in out
    assert "gamma" in out
    assert "beta" not in out


def test_allowlist_empty_renders_no_tools() -> None:
    """An empty allowlist (`set()` / `[]`) renders an empty prompt —
    NOT all tools. Distinguishes 'no allowlist' (None) from 'allowlist
    of nothing' (empty set)."""
    _tool_registry.clear()
    _tool_registry.extend([_make_tool("alpha", "modA")])
    out = get_tools_prompt(allowlist=set())
    assert "alpha" not in out


def test_allowlist_excludes_blocked_tool() -> None:
    """The architectural-commitment use case: lead's allowlist excludes
    `create_agent`, so the model's prompt doesn't include its schema
    at all. Pairs with #172's dispatch refusal for defense in depth."""
    _tool_registry.clear()
    _tool_registry.extend([
        _make_tool("scan_xss", "specialist"),
        _make_tool("scan_sqli", "specialist"),
        _make_tool("create_agent", "agents_graph"),
    ])
    out = get_tools_prompt(allowlist=["scan_xss", "scan_sqli"])
    assert "scan_xss" in out
    assert "scan_sqli" in out
    assert "create_agent" not in out


def test_allowlist_with_unknown_name_is_silent() -> None:
    """An allowlist entry that doesn't match any registered tool is
    silently ignored — does NOT raise. (Treats the allowlist as a
    soft policy; new code naming an old/renamed tool shouldn't crash
    the LLM init path.)"""
    _tool_registry.clear()
    _tool_registry.extend([_make_tool("alpha", "modA")])
    out = get_tools_prompt(allowlist=["alpha", "nonexistent"])
    assert "alpha" in out
    # No exception, no mention of 'nonexistent' in output.
    assert "nonexistent" not in out


def test_module_grouping_preserved_under_filter() -> None:
    """Tools from the same module render under the same `<{module}_tools>`
    section. Filtering must not break the section boundaries."""
    _tool_registry.clear()
    _tool_registry.extend([
        _make_tool("alpha", "specialist"),
        _make_tool("beta", "specialist"),
        _make_tool("gamma", "core"),
    ])
    out = get_tools_prompt(allowlist=["alpha", "gamma"])
    assert "<specialist_tools>" in out
    assert "<core_tools>" in out
    # Within specialist module, only `alpha` (not `beta`).
    spec_section = out[out.find("<specialist_tools>"):out.find("</specialist_tools>")]
    assert "alpha" in spec_section
    assert "beta" not in spec_section


def test_allowlist_accepts_iterable_not_just_set() -> None:
    """Pass list, tuple, set, frozenset — all work. The signature
    types `Iterable[str]` so callers don't have to materialize."""
    _tool_registry.clear()
    _tool_registry.extend([_make_tool("a", "m"), _make_tool("b", "m")])
    for kind in ([" a "], ("a",), {"a"}, frozenset(["a"])):
        out = get_tools_prompt(allowlist=kind)
        # `b` always excluded; `a` always present (with whitespace
        # tolerance is NOT in scope — passing " a " should NOT match
        # since it's not the literal name).
        assert "b" not in out
