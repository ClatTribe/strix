"""Tests for iter-35.2 — anchor-prepass probes routed through sandbox.

Per CLAUDE.md §3.6, 11 `probe_*` helpers in `anchor_prepass.py` were
host-side urllib / socket / ftplib calls. iter-35.2 introduces thin
sandbox-registered wrappers in `strix.tools.anchor_probes` that
lazy-import the implementations. The prepass orchestrator dispatches
via `execute_tool`, so the I/O fires inside the sandbox container.

This file pins:
  1. Every wrapper is registered with sandbox_execution=True
  2. Every wrapper returns a dict with `findings` (or `open_ports`
     for the port-discovery probe) so `_count_findings` works
  3. The prepass orchestrator no longer calls the host-side
     functions directly (only the wrappers, via _run_one_tool)
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import strix.tools  # noqa: F401 — trigger all @register_tool decorators


_PROBE_NAMES = (
    "probe_openapi_spec_exposed",
    "probe_jwt_none_alg",
    "probe_mass_assignment_priv_fields",
    "probe_unauth_debug_paths",
    "probe_open_redirect",
    "probe_unauth_bola_path_params",
    "probe_directory_listing",
    "probe_open_tcp_ports",
    "probe_redis_no_auth",
    "probe_http_port",
    "probe_ftp_anonymous",
)


# ---------------------------------------------------------------------------
# Registry / sandbox-routing invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("probe", _PROBE_NAMES)
def test_probe_is_registered(probe: str) -> None:
    """Every probe wrapper must be discoverable via the tool
    registry. Without registration, `execute_tool` can't dispatch."""
    from strix.tools.registry import get_tool_names

    assert probe in get_tool_names(), (
        f"{probe} is not registered. Check that "
        f"`strix.tools.anchor_probes` is imported by "
        f"`strix/tools/__init__.py`."
    )


@pytest.mark.parametrize("probe", _PROBE_NAMES)
def test_probe_routes_to_sandbox(probe: str) -> None:
    """Every probe must be marked sandbox_execution=True so
    `execute_tool` POSTs to the sandbox tool_server instead of
    running the urllib / socket call on the host."""
    from strix.tools.executor import should_execute_in_sandbox

    assert should_execute_in_sandbox(probe), (
        f"{probe} must route to sandbox. The whole point of iter-35.2 "
        f"is that the network I/O fires inside the sandbox container, "
        f"not on the host."
    )


# ---------------------------------------------------------------------------
# Return-shape contract
# ---------------------------------------------------------------------------


def test_finding_emitting_probes_return_findings_key() -> None:
    """Probes that emit findings must return a dict with a `findings`
    key so the prepass's `_count_findings` helper picks them up via
    the canonical SpecialistResult shape."""
    from strix.tools import anchor_probes as ap

    # Use parameters that produce zero findings safely (empty
    # endpoints / bogus URL) — we only check the return shape, not the
    # finding content.
    out = ap.probe_jwt_none_alg(endpoints=[])
    assert isinstance(out, dict)
    assert "findings" in out
    assert isinstance(out["findings"], list)
    assert out.get("ok") is True
    assert out.get("status") == "ok"


def test_open_tcp_ports_returns_open_ports_key() -> None:
    """The port-discovery probe is special — it returns
    `open_ports: list[int]` (not a list of finding dicts). The
    wrapper must preserve that shape so the IP prepass orchestrator
    can read the discovered ports off the result dict."""
    from strix.tools import anchor_probes as ap

    out = ap.probe_open_tcp_ports("256.256.256.256")  # invalid → empty
    assert isinstance(out, dict)
    assert "open_ports" in out
    assert isinstance(out["open_ports"], list)
    # findings list is also present (always empty for this probe).
    assert out.get("findings") == []


# ---------------------------------------------------------------------------
# Orchestrator no longer calls host-side probes directly
# ---------------------------------------------------------------------------


def test_anchor_prepass_no_direct_probe_calls() -> None:
    """The whole iter-35.2 point: the orchestrator must dispatch every
    probe through `_run_one_tool` (sandbox-routed), not call the
    host-side function directly. This grep-test catches accidental
    regressions where someone re-introduces a direct call."""
    src = Path(
        "strix/agents/lead_agent/anchor_prepass.py",
    ).read_text(encoding="utf-8")

    # Strip the function definitions themselves — those are allowed.
    # We're checking for INVOCATION call sites.
    import re
    # Remove def lines + their immediate docstrings to avoid false
    # positives. Lines like `def probe_X(` are fine — only `probe_X(`
    # (mid-expression) outside the function body is bad.
    forbidden_patterns = [
        # Direct invocation: `probe_X(` not preceded by `def ` and not
        # inside a string/comment. Loose grep; the assertion is on the
        # COUNT being zero for non-def occurrences.
        rf"(?<!def )(?<!\"){probe}\("
        for probe in _PROBE_NAMES
    ]
    found_violations: list[str] = []
    for probe in _PROBE_NAMES:
        # Count non-def, non-comment, non-docstring occurrences.
        # Pattern: `probe_X(` that isn't preceded by `def ` and isn't
        # on a comment line.
        for m in re.finditer(rf"\b{probe}\(", src):
            line_start = src.rfind("\n", 0, m.start()) + 1
            line = src[line_start:m.start()]
            # Skip function definitions (`def probe_X(` — `line` here
            # is everything before the match on the same line, so a
            # `def` keyword that strips to literal "def" means this is
            # the function definition itself, not a call site).
            if line.rstrip().endswith("def"):
                continue
            # Skip comment lines
            if line.lstrip().startswith("#"):
                continue
            # Skip docstring contexts (lines inside triple-quoted
            # strings; heuristic: line contains a `"""` mark before
            # the probe, OR the probe is referenced as a tool name
            # in quotes).
            # Tool-name-as-string is fine: "probe_X", in any context.
            char_before = src[m.start() - 1] if m.start() > 0 else ""
            if char_before in ('"', "'"):
                continue
            found_violations.append(
                f"{probe}() called directly near char {m.start()} "
                f"(line context: {line.strip()!r})"
            )

    assert not found_violations, (
        f"iter-35.2 violation — host-side probe calls re-introduced "
        f"in anchor_prepass.py:\n  " + "\n  ".join(found_violations)
    )


def test_dispatch_helpers_call_run_one_tool() -> None:
    """The prepass's web/api + ip probe dispatch sections must use
    `_run_one_tool` (which routes via execute_tool → sandbox HTTP)
    rather than direct in-process calls."""
    src = Path(
        "strix/agents/lead_agent/anchor_prepass.py",
    ).read_text(encoding="utf-8")
    # The new dispatch pattern uses _run_one_tool with each probe name.
    # At least the unique probe names should appear quoted as the
    # first arg to a _run_one_tool / _dispatch_probe call.
    expected_dispatch_targets = set(_PROBE_NAMES)
    missing = {
        p for p in expected_dispatch_targets
        if f'"{p}"' not in src and f"'{p}'" not in src
    }
    assert not missing, (
        f"iter-35.2: these probe names aren't referenced as tool-name "
        f"strings in anchor_prepass.py (so they're not being dispatched "
        f"via _run_one_tool): {missing}"
    )
