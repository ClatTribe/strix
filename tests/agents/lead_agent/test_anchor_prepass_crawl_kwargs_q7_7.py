"""Tests for iter-Q7.7 — anchor_prepass crawl_with_katana kwargs contract.

Regression guard for the silent WAVSEP recall collapse: anchor_prepass
dispatched `crawl_with_katana(... depth=2)`, but the tool's parameter is
`max_depth`. The sandbox raised `crawl_with_katana() got an unexpected
keyword argument 'depth'`, the crawl died, the anchor fan-out was
starved of enumerated URLs, and sqli / path_traversal / redirect recall
dropped to 0 (only the landing page got scanned). The old pre-rebuild
sandbox image happened to accept `depth`, masking the mismatch until the
image was rebuilt to the current `max_depth` signature.

These tests pin both sides of the contract so a future rename/typo
can't silently re-starve the fan-out.
"""

from __future__ import annotations

import ast
import inspect
import importlib
from pathlib import Path


def _crawl_with_katana():
    m = importlib.import_module("strix.tools.katana_runner.crawl_with_katana")
    return m.crawl_with_katana


# ----------------------------------------------------------------------
# tool side
# ----------------------------------------------------------------------

def test_tool_accepts_max_depth_not_depth():
    params = set(inspect.signature(_crawl_with_katana()).parameters)
    assert "max_depth" in params, "crawl_with_katana should expose max_depth"
    assert "depth" not in params, (
        "crawl_with_katana has no `depth` param — callers must pass `max_depth`"
    )


def test_tool_accepts_prepass_kwargs():
    """The exact kwargs the prepass passes must all be valid params."""
    params = set(inspect.signature(_crawl_with_katana()).parameters)
    for kw in ("target_url", "max_pages", "max_depth"):
        assert kw in params, f"crawl_with_katana missing prepass kwarg {kw!r}"


# ----------------------------------------------------------------------
# caller side — every crawl_with_katana dispatch in anchor_prepass must
# pass only kwargs the tool actually accepts (AST, not text grep, so it
# survives reformatting).
# ----------------------------------------------------------------------

def _anchor_prepass_path() -> Path:
    m = importlib.import_module("strix.agents.lead_agent.anchor_prepass")
    return Path(m.__file__)


def test_prepass_crawl_dispatch_kwargs_are_valid():
    src = _anchor_prepass_path().read_text(encoding="utf-8")
    tree = ast.parse(src)
    valid = set(inspect.signature(_crawl_with_katana()).parameters)

    # Find every call whose first positional arg is the string literal
    # "crawl_with_katana" (the _run_one_tool / execute_tool dispatch
    # form) and whose second arg is a dict literal of kwargs.
    bad: list[str] = []
    seen_dispatch = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and first.value == "crawl_with_katana"):
            continue
        # second positional arg = kwargs dict literal
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Dict):
            seen_dispatch = True
            for key in node.args[1].keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if key.value not in valid:
                        bad.append(key.value)

    assert seen_dispatch, "expected at least one crawl_with_katana dispatch in anchor_prepass"
    assert not bad, (
        f"anchor_prepass passes kwarg(s) {sorted(set(bad))} to crawl_with_katana "
        f"that the tool does not accept (valid: {sorted(valid)}). This starves "
        f"the fan-out — see iter-Q7.7."
    )


def test_no_literal_depth_kwarg_to_crawl():
    """Belt-and-suspenders text check for the specific regression."""
    src = _anchor_prepass_path().read_text(encoding="utf-8")
    # The fixed call uses "max_depth"; the original bug passed
    # `"depth": 2`. Forbid the exact regression shape.
    assert '"depth": 2' not in src and "'depth': 2" not in src, (
        "the crawl_with_katana dispatch must use max_depth, not depth (iter-Q7.7)"
    )
