"""Regression test: workflow tools must not trigger a circular
import when `strix.tools` is loaded.

The bug (post Phase 3d merge): `strix/tools/__init__.py:37` did
`from .workflow import *`, which loaded
`strix/tools/workflow/workflow_actions.py`, which did
`from strix.agents.workflow_state import ...` at module-load
time. But `strix.agents.__init__` pulls in `BaseAgent` →
`strix.llm`, and at that point `strix.llm` was still mid-init
(strix.tools.__init__ is invoked from within strix.llm's import
chain). Result:

    ImportError: cannot import name 'LLM' from partially
    initialized module 'strix.llm' (most likely due to a
    circular import)

The fix is the same lazy-import pattern that
`strix/tools/active_hypotheses/active_hypotheses_tools.py:15`
uses for the same reason. This test pins the contract so the
regression can't sneak back.
"""

from __future__ import annotations

import importlib
import subprocess
import sys


def test_strix_tools_imports_without_circular_error() -> None:
    """`import strix.tools` from a fresh interpreter must
    succeed. We do it in a subprocess so we get the
    fresh-interpreter import path (matters because pytest's
    own conftest fixtures + earlier-test imports prime the
    module cache)."""
    code = (
        "import strix.tools\n"
        "print('OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=30,
        check=False,
    )
    assert result.returncode == 0, (
        f"`import strix.tools` failed:\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )
    assert "OK" in result.stdout


def test_workflow_tools_module_has_no_module_level_agents_imports() -> None:
    """The workflow_actions module MUST NOT import from
    `strix.agents.workflow_state` at module-load time — the
    `strix.agents.__init__` pulls in `BaseAgent` which
    transitively imports `strix.llm`, and circular re-entry
    blows up.

    Pinned by inspecting the module source for the disallowed
    pattern. Equivalent test for hypothesis tools:
    `strix/tools/active_hypotheses/active_hypotheses_tools.py:15`
    uses the same lazy-import dodge."""
    from pathlib import Path

    pkg_root = Path(__file__).resolve().parents[3]
    actions_src = (
        pkg_root / "strix" / "tools" / "workflow" / "workflow_actions.py"
    ).read_text()

    # The forbidden pattern: top-level `from strix.agents.workflow_state ...`
    # (lines NOT indented). We walk the source and check that any
    # `strix.agents.workflow_state` reference is INSIDE a function
    # body (indented).
    for lineno, line in enumerate(actions_src.splitlines(), 1):
        if "strix.agents.workflow_state" not in line:
            continue
        stripped = line.lstrip()
        is_indented = stripped != line
        is_comment = stripped.startswith("#")
        # An import IS top-level when it's not indented and not
        # in a comment. Anything inside a `def` block is indented.
        if not is_indented and not is_comment and stripped.startswith(
            ("from ", "import ")
        ):
            raise AssertionError(
                f"workflow_actions.py line {lineno}: top-level "
                f"strix.agents.workflow_state import will trigger "
                f"circular re-entry through strix.llm. Move the "
                f"import inside the function body or use the "
                f"`_ws()` lazy-getter pattern.\n"
                f"  line: {line!r}"
            )


def test_workflow_tools_callable_after_import() -> None:
    """End-to-end: import + call the public tools. The lazy
    `_ws()` helper resolves at FIRST call, not at import — so
    the first call must succeed."""
    # Fresh-import via a clean module reload to mimic real boot.
    if "strix.tools.workflow.workflow_actions" in sys.modules:
        importlib.reload(
            sys.modules["strix.tools.workflow.workflow_actions"]
        )
    from strix.agents.workflow_state import reset_for_testing
    from strix.tools.workflow.workflow_actions import (
        advance_workflow_phase,
        workflow_status,
    )

    reset_for_testing()
    snap = workflow_status()
    assert snap["success"] is True
    assert snap["current_phase"] == "recon"

    out = advance_workflow_phase("not_a_phase")
    assert out["success"] is False
    assert out["error"] == "invalid_target_phase"
