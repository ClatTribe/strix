"""Tests for iter-35.1 — replace host-side `_katana_crawl` helper with
sandbox-routed `crawl_with_katana` tool dispatch.

Closes the host-vs-sandbox boundary violation flagged in CLAUDE.md §3.
The host-side `_katana_crawl` helper used `subprocess.run(["katana",
...])` against the host PATH — bypassing the sandbox boundary AND
iter-32.1's `record_endpoint_discovered` hook. After iter-35.1 the
crawl runs via `execute_tool("crawl_with_katana", ...)` which:
  * dispatches through the sandbox HTTP API
  * runs katana in the sandbox container (consistent network policy)
  * fires iter-32.1's workflow_state recording hook
"""

from __future__ import annotations

from pathlib import Path

import pytest

import strix.agents.lead_agent.anchor_prepass as ap_mod


def test_host_side_katana_crawl_helper_removed():
    """The host-side `_katana_crawl` helper that shelled out to katana
    on the host PATH must no longer exist.

    If you're adding it back: STOP. Use the registered tool via
    execute_tool instead. See CLAUDE.md §3.6 for the rationale."""
    assert not hasattr(ap_mod, "_katana_crawl"), (
        "iter-35.1 regression: host-side _katana_crawl helper was "
        "re-introduced. Use execute_tool('crawl_with_katana', ...) "
        "instead. See CLAUDE.md §3."
    )


def test_no_subprocess_invocation_of_katana_in_anchor_prepass():
    """No remaining `subprocess.run(["katana"...])` invocations in
    anchor_prepass.py source. Sandbox dispatch only."""
    src = Path(ap_mod.__file__).read_text()
    forbidden_patterns = (
        'subprocess.run(["katana"',
        '"katana", "-u"',
        '_subprocess.run',
        'shutil.which("katana")',
        '_shutil.which("katana")',
    )
    for pat in forbidden_patterns:
        assert pat not in src, (
            f"iter-35.1 regression: anchor_prepass.py contains "
            f"host-side katana invocation pattern: {pat!r}"
        )


def test_iter_35_1_marker_present_in_anchor_prepass():
    """The iter-35.1 deletion marker must be discoverable in source so
    future maintainers see the rationale for the removed helper."""
    src = Path(ap_mod.__file__).read_text()
    assert "iter-35.1" in src, (
        "iter-35.1 marker missing — restore the explanatory comment "
        "block where `_katana_crawl` was deleted"
    )


def test_anchor_prepass_invokes_crawl_with_katana_via_execute_tool():
    """The replacement code path must call `_run_one_tool` (which routes
    through `execute_tool` → sandbox) with `crawl_with_katana`."""
    src = Path(ap_mod.__file__).read_text()
    # The new path uses _run_one_tool with "crawl_with_katana"
    assert '"crawl_with_katana"' in src, (
        "Replacement dispatcher must reference the registered "
        "`crawl_with_katana` tool name"
    )
    assert "_run_one_tool(" in src, (
        "Replacement dispatcher must use the sandbox-routed "
        "`_run_one_tool` helper"
    )


def test_crawl_with_katana_tool_remains_sandbox_registered():
    """Defensive: the registered tool we now dispatch to must keep
    its `sandbox_execution=True` flag. If someone flips it to False,
    iter-35.1 silently regresses to host execution."""
    import importlib
    ck_mod = importlib.import_module(
        "strix.tools.katana_runner.crawl_with_katana"
    )
    src = Path(ck_mod.__file__).read_text()
    # The decorator must declare sandbox_execution=True
    assert "sandbox_execution=True" in src, (
        "crawl_with_katana lost its sandbox_execution=True flag — "
        "iter-35.1's sandbox routing depends on it"
    )
