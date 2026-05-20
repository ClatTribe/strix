"""Integration tests for V3-1 — verifies the scan-mode-aware
lead iteration cap actually clips `state.max_iterations` when
LeadAgent constructs.

Pins:
  * Pre-supplied state with high `max_iterations` gets clipped
    to the mode cap.
  * Pre-supplied state with low `max_iterations` is NOT raised
    (ceiling-only).
  * Default state-construction path (no caller-supplied state)
    also clips.
  * Deep mode + unset mode never clip.
  * Kill switch bypasses the cap.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.agents.lead_agent import LeadAgent
from strix.agents.state import AgentState


@pytest.fixture(autouse=True)
def _llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    # Reset v3 cap env per-test
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_LEAD_ITER_OVERRIDE", raising=False)
    monkeypatch.delenv("STRIX_LEAD_ITER_CAP_DISABLED", raising=False)
    yield


def _config_with_state(max_iter: int = 300) -> dict[str, Any]:
    """Build a config with a caller-supplied state."""
    state = AgentState(
        task="test task",
        agent_name="test-lead",
        category="lead",
        max_iterations=max_iter,
    )
    return {"state": state}


# ---------------------------------------------------------------------------
# Pre-supplied state path
# ---------------------------------------------------------------------------


def test_quick_mode_caps_pre_supplied_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    agent = LeadAgent(_config_with_state(max_iter=300))
    # 2026-05-20 — quick mode cap reduced from 12 → 4 after the
    # OSS-first anchor pre-pass landed. The lead's post-prepass role
    # is L2 ranking / dedup / FP demote / report — fits in ~4 iter.
    assert agent.state.max_iterations == 4


def test_standard_mode_caps_pre_supplied_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")
    agent = LeadAgent(_config_with_state(max_iter=300))
    # 2026-05-20 — standard mode cap reduced from 60 → 15 after the
    # OSS-first anchor pre-pass landed. The lead delegates specialist
    # dispatch via dispatch_specialist (cap=8) which is its own
    # fresh-context loop — the lead's iter budget shouldn't be the
    # work multiplier.
    assert agent.state.max_iterations == 15


def test_deep_mode_does_not_cap_pre_supplied_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    agent = LeadAgent(_config_with_state(max_iter=300))
    assert agent.state.max_iterations == 300


def test_unset_mode_does_not_cap_pre_supplied_state() -> None:
    """Backwards compat: a run without scan_mode env keeps its
    configured max_iterations."""
    agent = LeadAgent(_config_with_state(max_iter=300))
    assert agent.state.max_iterations == 300


def test_cap_does_not_raise_already_tighter_max_iter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recall canary — if the caller explicitly passed
    max_iterations=3, the quick-mode cap of 4 MUST NOT raise it.
    The cap is a ceiling."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    agent = LeadAgent(_config_with_state(max_iter=3))
    assert agent.state.max_iterations == 3


def test_kill_switch_disables_cap_on_pre_supplied_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_LEAD_ITER_CAP_DISABLED", "1")
    agent = LeadAgent(_config_with_state(max_iter=300))
    assert agent.state.max_iterations == 300


def test_override_env_caps_pre_supplied_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "25")
    agent = LeadAgent(_config_with_state(max_iter=300))
    assert agent.state.max_iterations == 25


# ---------------------------------------------------------------------------
# Default state-construction path (no caller-supplied state)
# ---------------------------------------------------------------------------


def test_quick_mode_caps_default_state_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the caller doesn't pre-supply state, LeadAgent builds
    one itself — the cap must apply there too."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    agent = LeadAgent({"max_iterations": 300})
    # 2026-05-20 — quick cap is now 4 (post-OSS-anchor-prepass).
    assert agent.state.max_iterations == 4


def test_deep_mode_default_state_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    agent = LeadAgent({"max_iterations": 300})
    assert agent.state.max_iterations == 300


# ---------------------------------------------------------------------------
# Recall canary — the quick cap must leave enough headroom for
# the deterministic happy path
# ---------------------------------------------------------------------------


def test_quick_cap_leaves_minimum_iterations_for_recall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recall safeguard: quick mode caps must leave AT LEAST 3
    iterations available for the post-prepass lead.

    The OSS-first anchor pre-pass (2026-05-20) runs the L1 detection
    layer BEFORE the lead's first LLM call. The lead's remaining role
    is L2 ranking / dedup / FP demote / report — which fits in ~3-4
    iterations. Anything tighter risks the lead being unable to:
    boot + dedup + emit + report.

    If this canary breaks, the cap is too tight and reverts —
    NOT the canary."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    agent = LeadAgent(_config_with_state(max_iter=300))
    assert agent.state.max_iterations >= 3, (
        f"quick mode cap {agent.state.max_iterations} is too "
        "tight; min floor is 3 iterations for the deterministic "
        "happy path (post-prepass: boot + dedup + emit + report). "
        "Loosen the cap rather than this canary."
    )
