import importlib
import sys
from collections.abc import Iterator
from types import ModuleType
from typing import Any

import pytest

from strix.config import Config
from strix.tools.registry import clear_registry


def _empty_config_load(_cls: type[Config]) -> dict[str, dict[str, str]]:
    return {"env": {}}


def _reload_tools_module() -> ModuleType:
    clear_registry()

    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)

    return importlib.import_module("strix.tools")


@pytest.fixture(autouse=True)
def _restore_default_registry() -> Iterator[None]:
    # These tests deliberately clear the tool registry and selectively
    # re-import tool modules under different env configurations. Without
    # cleanup the registry stays in whatever partial state the last test
    # left it in, causing pollution failures elsewhere — e.g. tool modules
    # imported lazily by sibling test files (like `tests/tools/websocket/
    # test_websocket_audit.py` doing `import strix.tools.websocket.websocket_audit`
    # at collection time) come up empty in `get_tool_mitre_techniques`
    # because they were popped from sys.modules and never re-registered.
    # Reloading `strix.tools` doesn't help — its `__init__` doesn't import
    # those lazy modules. Snapshot the registry + relevant sys.modules
    # entries before each test and restore afterwards.
    from strix.tools import registry as _registry

    saved_tools = list(_registry.tools)
    saved_by_name = dict(_registry._tools_by_name)
    saved_param_schemas = dict(_registry._tool_param_schemas)
    saved_modules = {
        name: mod
        for name, mod in sys.modules.items()
        if name == "strix.tools" or name.startswith("strix.tools.")
    }

    yield

    _registry.tools[:] = saved_tools
    _registry._tools_by_name.clear()
    _registry._tools_by_name.update(saved_by_name)
    _registry._tool_param_schemas.clear()
    _registry._tool_param_schemas.update(saved_param_schemas)
    for name in list(sys.modules):
        if (name == "strix.tools" or name.startswith("strix.tools.")) and name not in saved_modules:
            sys.modules.pop(name, None)
    for name, mod in saved_modules.items():
        sys.modules[name] = mod
        # Restoring sys.modules alone isn't enough: when the test reimported
        # `strix.tools`, Python set a fresh `tools` attribute on the parent
        # `strix` package, and likewise rebuilt nested submodule attributes
        # on the new packages. Tests elsewhere that resolve dotted paths via
        # attribute walks (e.g. `monkeypatch.setattr("strix.tools.proxy.
        # proxy_manager.get_proxy_manager", ...)`) follow those attributes
        # rather than sys.modules, so we have to point the parent's
        # attribute at the saved module too.
        parent_name, _, child_name = name.rpartition(".")
        parent = sys.modules.get(parent_name) if parent_name else None
        if parent is not None:
            setattr(parent, child_name, mod)


def test_non_sandbox_registers_agents_graph_but_not_browser_or_web_search_when_disabled(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "false")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.setattr(Config, "load", classmethod(_empty_config_load))

    tools = _reload_tools_module()
    names = set(tools.get_tool_names())

    assert "create_agent" in names
    assert "browser_action" not in names
    assert "web_search" not in names


def test_sandbox_registers_sandbox_tools_but_not_non_sandbox_tools(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.setattr(Config, "load", classmethod(_empty_config_load))

    tools = _reload_tools_module()
    names = set(tools.get_tool_names())

    assert "terminal_execute" in names
    assert "python_action" in names
    assert "list_requests" in names
    assert "create_agent" not in names
    assert "finish_scan" not in names
    assert "load_skill" not in names
    assert "browser_action" not in names
    assert "web_search" not in names


def test_load_skill_import_does_not_register_create_agent_in_sandbox(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_MODE", "true")
    monkeypatch.setenv("STRIX_DISABLE_BROWSER", "true")
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.setattr(Config, "load", classmethod(_empty_config_load))

    clear_registry()
    for name in list(sys.modules):
        if name == "strix.tools" or name.startswith("strix.tools."):
            sys.modules.pop(name, None)

    load_skill_module = importlib.import_module("strix.tools.load_skill.load_skill_actions")
    registry = importlib.import_module("strix.tools.registry")

    names_before = set(registry.get_tool_names())
    assert "load_skill" not in names_before
    assert "create_agent" not in names_before

    state_type = type(
        "DummyState",
        (),
        {
            "agent_id": "agent_test",
            "context": {},
            "update_context": lambda self, key, value: self.context.__setitem__(key, value),
        },
    )
    result = load_skill_module.load_skill(state_type(), "nmap")

    names_after = set(registry.get_tool_names())
    assert "create_agent" not in names_after
    assert result["success"] is False
