"""Tests for iter-Q7.8 — every tool the anchor prepass dispatches must
be registered, and its dispatch kwargs must match the tool signature.

Generalises the Q7.7 crawl-kwarg guard to the WHOLE prepass dispatch
surface. The Q7.7 signature audit found 7 tools (amass, crt.sh, grype,
syft, masscan, zgrab2, kiterunner) referenced in the `_ANCHORS_*` /
`_FANOUT_*` lists but never imported in `strix/tools/__init__.py`, so
`get_tool_by_name` returned None and every dispatch failed silently with
"Tool not found". This pins both invariants so neither regresses.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest


ap = importlib.import_module("strix.agents.lead_agent.anchor_prepass")
reg = importlib.import_module("strix.tools.registry")


def _anchor_builder_pairs():
    """Every (tool_name, kwarg_builder) entry across module-level
    anchor / fan-out lists in anchor_prepass."""
    pairs = []
    for _name, val in vars(ap).items():
        if not isinstance(val, (list, tuple)):
            continue
        for item in val:
            if (
                isinstance(item, (list, tuple))
                and len(item) >= 2
                and isinstance(item[0], str)
                and callable(item[1])
            ):
                pairs.append((item[0], item[1]))
    # de-dup on (tool, builder name)
    seen = set()
    out = []
    for t, b in pairs:
        k = (t, b.__name__)
        if k not in seen:
            seen.add(k)
            out.append((t, b))
    return out


def test_all_anchor_referenced_tools_are_registered():
    """Q7.8 — the regression that bit us: a tool in an anchor list that
    isn't registered → silent 'Tool not found' at dispatch."""
    registered = set(reg.get_tool_names())
    missing = sorted({t for t, _b in _anchor_builder_pairs() if t not in registered})
    assert not missing, (
        f"anchor/fan-out lists reference unregistered tools {missing} — "
        f"wire their `*_runner` package into strix/tools/__init__.py (iter-Q7.8)"
    )


def test_the_seven_q7_8_tools_are_registered():
    """Explicit canary for the 7 tools Q7.8 wired in."""
    registered = set(reg.get_tool_names())
    for t in (
        "enumerate_subdomains_amass",
        "enumerate_subdomains_crtsh",
        "scan_image_grype",
        "extract_sbom_syft",
        "fingerprint_services_masscan",
        "grab_banner_zgrab2",
        "discover_api_endpoints_kiterunner",
    ):
        assert t in registered, f"{t} not registered (iter-Q7.8 import dropped?)"


def test_builder_kwargs_match_tool_signature():
    """Every builder's output kwargs must be accepted by the tool's
    signature (generalises the Q7.7 crawl-kwarg fix)."""
    bad: list[str] = []
    for tool, builder in _anchor_builder_pairs():
        fn = reg.get_tool_by_name(tool)
        if fn is None:
            continue  # covered by the registration test above
        kwargs = None
        for args in (
            ("http://t.test/p?a=1", "/ws", tool),
            ("http://t.test/p?a=1", "/ws"),
            ("http://t.test/p?a=1",),
        ):
            try:
                kwargs = builder(*args)
                break
            except Exception:  # noqa: BLE001, S112
                continue
        if not isinstance(kwargs, dict):
            continue
        sig = inspect.signature(fn)
        params = set(sig.parameters)
        accepts_var = any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values())
        if accepts_var:
            continue
        invalid = [k for k in kwargs if k not in params]
        if invalid:
            bad.append(f"{tool} via {builder.__name__}: {invalid} (valid: {sorted(params)})")
    assert not bad, "anchor builders pass kwargs the tool rejects:\n" + "\n".join(bad)


def test_inline_run_one_tool_kwargs_match_signature():
    """AST-walk inline `_run_one_tool("name", {literal kwargs})` calls and
    assert kwargs are valid for the tool (the Q7.7 crawl `depth` bug shape)."""
    src = Path(ap.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        fname = getattr(node.func, "attr", getattr(node.func, "id", ""))
        if fname not in ("_run_one_tool", "execute_tool", "execute_tool_invocation"):
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        tool = first.value
        dlit = next((a for a in node.args[1:] if isinstance(a, ast.Dict)), None)
        if dlit is None:
            continue
        keys = [k.value for k in dlit.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        fn = reg.get_tool_by_name(tool)
        if fn is None:
            bad.append(f"L{node.lineno}: {tool} NOT REGISTERED")
            continue
        sig = inspect.signature(fn)
        params = set(sig.parameters)
        if any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values()):
            continue
        invalid = [k for k in keys if k not in params]
        if invalid:
            bad.append(f"L{node.lineno}: {tool} -> invalid {invalid} (valid: {sorted(params)})")
    assert not bad, "inline anchor dispatches pass invalid kwargs:\n" + "\n".join(bad)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
