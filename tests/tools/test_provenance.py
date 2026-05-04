"""Tests for tool-output provenance / trust-taint (roadmap §17.6 / §18 row 10).

Two layers covered:
1. **Registry** — `register_tool(provenance=...)` accepts the canonical
   set, normalises (lowercase + strip), drops invalid values.
   `get_tool_provenance(name)` always returns a canonical class.
2. **Tracer integration** — `tool.execution.started` and
   `tool.execution.updated` events carry `actor.provenance`.

The schema-stable contract: `actor.provenance` is ALWAYS present
on every tool.execution.* event (default-resolved when undeclared).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.registry import (
    _VALID_PROVENANCE_CLASSES,
    get_tool_provenance,
    register_tool,
)


# Force registration of the threat-intel tools we annotated. Each
# package's `__init__` registers its tool via the @register_tool
# decorator at import time.
import strix.tools.cve_lookup.cve_lookup  # noqa: F401, E402
import strix.tools.nvd_lookup.nvd_lookup  # noqa: F401, E402
import strix.tools.vt_reputation.vt_reputation  # noqa: F401, E402
import strix.tools.greynoise.greynoise_classify  # noqa: F401, E402


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("provenance-test")
    set_global_tracer(tracer)
    yield


def _events(tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / "provenance-test" / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# Canonical class set
# ---------------------------------------------------------------------------


def test_canonical_provenance_classes() -> None:
    """The 6 documented classes are the allow-list."""
    assert _VALID_PROVENANCE_CLASSES == frozenset({
        "trusted_source",
        "intel_feed",
        "target",
        "operator_input",
        "framework",
        "mixed",
    })


# ---------------------------------------------------------------------------
# get_tool_provenance — known tools (declared explicitly)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name,expected_provenance",
    [
        ("cve_lookup", "trusted_source"),
        ("nvd_lookup", "trusted_source"),
        ("vt_reputation", "intel_feed"),
        ("greynoise_classify", "intel_feed"),
    ],
)
def test_threat_intel_tools_declare_provenance(
    tool_name: str, expected_provenance: str
) -> None:
    """Threat-intel tools that this PR annotated."""
    assert get_tool_provenance(tool_name) == expected_provenance


# ---------------------------------------------------------------------------
# get_tool_provenance — default policy
# ---------------------------------------------------------------------------


def test_default_provenance_for_in_process_tool() -> None:
    """Tools with sandbox_execution=False (in-process / framework) →
    `framework` default."""
    # Create a tool that doesn't declare provenance.
    @register_tool(sandbox_execution=False)
    def _ephemeral_framework_tool() -> dict[str, Any]:
        return {"ok": True}

    assert get_tool_provenance("_ephemeral_framework_tool") == "framework"


def test_default_provenance_for_sandbox_tool() -> None:
    """Tools with sandbox_execution=True (probe the target) →
    `target` default — adversarial-by-default is the right policy."""
    @register_tool(sandbox_execution=True)
    def _ephemeral_target_tool() -> dict[str, Any]:
        return {"ok": True}

    assert get_tool_provenance("_ephemeral_target_tool") == "target"


def test_unknown_tool_defaults_to_target() -> None:
    """Unknown / unregistered tool → `target`. Adversarial-by-default
    is the right policy when in doubt."""
    assert get_tool_provenance("nonexistent-tool-xyz") == "target"


# ---------------------------------------------------------------------------
# register_tool — invalid values dropped
# ---------------------------------------------------------------------------


def test_invalid_provenance_dropped_to_default() -> None:
    """Non-canonical provenance string → dropped + falls back to default."""
    @register_tool(sandbox_execution=True, provenance="not-real-class")  # type: ignore[arg-type]
    def _ephemeral_invalid_provenance() -> dict[str, Any]:
        return {"ok": True}

    # Falls back to the default (target, since sandbox_execution=True).
    assert get_tool_provenance("_ephemeral_invalid_provenance") == "target"


def test_provenance_normalisation_lowercase() -> None:
    """Mixed-case input lowercased on registration."""
    @register_tool(sandbox_execution=True, provenance="TRUSTED_Source")
    def _ephemeral_uppercase_provenance() -> dict[str, Any]:
        return {"ok": True}

    assert get_tool_provenance("_ephemeral_uppercase_provenance") == "trusted_source"


def test_each_canonical_class_accepted() -> None:
    """Sanity: each of the 6 canonical classes registers cleanly."""
    for klass in _VALID_PROVENANCE_CLASSES:
        # Each iteration creates a unique tool name.
        @register_tool(sandbox_execution=True, provenance=klass)
        def _f() -> dict[str, Any]:  # noqa: F811
            return {"ok": True}

        # Skip the assertion on _f's name (closure-over-loop captures
        # the LAST iteration's tool entry); we just confirm the
        # registration didn't raise.
    # Spot-check that at least the last one registered.
    assert get_tool_provenance("_f") in _VALID_PROVENANCE_CLASSES


# ---------------------------------------------------------------------------
# Tracer integration: tool.execution.* events carry actor.provenance
# ---------------------------------------------------------------------------


def test_tool_execution_started_carries_provenance(tmp_path) -> None:
    """The `tool.execution.started` event for a known threat-intel tool
    carries the right provenance class on its actor block."""
    tracer = tracer_module.get_global_tracer()
    tracer.set_scan_config({"targets": ["https://example.com"]})
    tracer.log_agent_creation("agent-1", "Test", "task")

    eid = tracer.log_tool_execution_start(
        "agent-1", "cve_lookup", {"name": "express", "version": "4.16.0"}
    )
    tracer.update_tool_execution(eid, "completed", {"vulns": []})

    events = _events(tmp_path)
    started = next(
        e for e in events if e.get("event_type") == "tool.execution.started"
        and e["actor"].get("tool_name") == "cve_lookup"
    )
    assert started["actor"]["provenance"] == "trusted_source"


def test_tool_execution_updated_carries_provenance(tmp_path) -> None:
    """The matching `tool.execution.updated` event also carries provenance —
    schema-stable across started/updated."""
    tracer = tracer_module.get_global_tracer()
    tracer.log_agent_creation("agent-1", "Test", "task")
    eid = tracer.log_tool_execution_start("agent-1", "vt_reputation", {"ioc": "1.2.3.4"})
    tracer.update_tool_execution(eid, "completed", {"reputation": "clean"})

    events = _events(tmp_path)
    updated = next(
        e for e in events if e.get("event_type") == "tool.execution.updated"
        and e["actor"].get("tool_name") == "vt_reputation"
    )
    assert updated["actor"]["provenance"] == "intel_feed"


def test_unknown_tool_falls_back_to_target_in_event(tmp_path) -> None:
    """Unknown tool name → target (default for unrecognized)."""
    tracer = tracer_module.get_global_tracer()
    tracer.log_agent_creation("agent-1", "Test", "task")
    eid = tracer.log_tool_execution_start("agent-1", "_nonexistent_test_tool", {})
    tracer.update_tool_execution(eid, "completed", {})

    events = _events(tmp_path)
    started = next(
        e for e in events if e.get("event_type") == "tool.execution.started"
    )
    # Always present as a string — never missing.
    assert isinstance(started["actor"]["provenance"], str)
    assert started["actor"]["provenance"] == "target"


def test_provenance_always_present_field(tmp_path) -> None:
    """Schema stability: the field is ALWAYS present on every
    tool.execution.* event so consumers don't have to handle absence."""
    tracer = tracer_module.get_global_tracer()
    tracer.log_agent_creation("agent-1", "Test", "task")
    # Make a few different tools fire.
    for tool in ("cve_lookup", "vt_reputation", "_unknown_tool"):
        eid = tracer.log_tool_execution_start("agent-1", tool, {})
        tracer.update_tool_execution(eid, "completed", {})

    events = _events(tmp_path)
    for ev in events:
        if ev.get("event_type") in ("tool.execution.started", "tool.execution.updated"):
            assert "provenance" in ev["actor"], (
                f"event {ev.get('event_type')} actor missing provenance"
            )
            assert ev["actor"]["provenance"] in _VALID_PROVENANCE_CLASSES


# ---------------------------------------------------------------------------
# Provenance is consistent across started/updated for the same execution
# ---------------------------------------------------------------------------


def test_provenance_consistent_across_started_and_updated(tmp_path) -> None:
    """The provenance class is resolved once at started-time and
    re-emitted on the updated event. Same value on both."""
    tracer = tracer_module.get_global_tracer()
    tracer.log_agent_creation("agent-1", "Test", "task")
    eid = tracer.log_tool_execution_start("agent-1", "cve_lookup", {})
    tracer.update_tool_execution(eid, "completed", {})

    events = _events(tmp_path)
    matching = [
        e for e in events
        if e.get("event_type") in ("tool.execution.started", "tool.execution.updated")
        and e["actor"].get("execution_id") == eid
    ]
    assert len(matching) == 2
    assert matching[0]["actor"]["provenance"] == matching[1]["actor"]["provenance"]
    assert matching[0]["actor"]["provenance"] == "trusted_source"
