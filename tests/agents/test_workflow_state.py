"""Tests for the Phase 3d / PR-α workflow state machine.

The state machine is the architectural answer to the diagnosed
13%-recall gap: instead of relying on the lead's LLM to follow
multi-step protocols from 6000+ chars of system prompt directives
(which Flash empirically doesn't), workflow structure lives in
enforced state.

These tests pin:
  * The 6 canonical phases + their order
  * Forward-transition gates (e.g. probe requires endpoints discovered)
  * Backwards transitions (always allowed — re-entry pattern)
  * `force=True` bypasses gates
  * Snapshot shape (gates / next_recommended_actions / phase_history)
  * Recorders update state idempotently and thread-safely
  * Tool-catalog phase filtering returns the right intersection
  * Kill switch (`STRIX_WORKFLOW_DISABLED=1`) is honoured
"""

from __future__ import annotations

import os
import threading

import pytest

from strix.agents import workflow_state as ws


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    """Each test starts with a fresh state machine and no kill switch."""
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)
    ws.reset_for_testing()
    yield
    ws.reset_for_testing()


# ---------------------------------------------------------------------------
# Canonical phases
# ---------------------------------------------------------------------------


def test_phases_are_canonical_order() -> None:
    """The 6 phases in canonical order. This pin is intentional —
    code elsewhere (tool_catalog phase filter, finish_scan guard,
    workflow_status next-action suggester) assumes this order.
    Renaming a phase requires updates to all three."""
    assert ws.PHASES == (
        "recon",
        "auth_attempt",
        "post_auth_recon",
        "probe",
        "chain_correlation",
        "report",
    )


def test_initial_phase_is_recon() -> None:
    """Every run starts in recon. The state machine auto-initialises
    on first access — no explicit `init()` call needed."""
    assert ws.get_current_phase() == "recon"
    snap = ws.snapshot()
    assert snap["current_phase"] == "recon"
    assert len(snap["phase_history"]) == 1
    assert snap["phase_history"][0]["phase"] == "recon"


# ---------------------------------------------------------------------------
# Phase-transition gates
# ---------------------------------------------------------------------------


def test_advance_to_auth_blocked_without_login_form() -> None:
    """Cannot enter auth_attempt without recon having discovered
    a login form. The blocker message tells the lead what's missing."""
    ok, why = ws.advance_phase("auth_attempt")
    assert ok is False
    assert "login form" in why.lower()
    assert ws.get_current_phase() == "recon"  # unchanged


def test_advance_to_auth_allowed_after_login_form_found() -> None:
    ws.record_login_form_found("https://x.com/login")
    ok, why = ws.advance_phase("auth_attempt", reason="login form found")
    assert ok is True
    assert ws.get_current_phase() == "auth_attempt"


def test_advance_to_post_auth_recon_blocked_without_captured_session() -> None:
    """post_auth_recon requires `auth_state_captured=True`. A failed
    auth attempt (attempted but not captured) blocks transition."""
    ws.record_login_form_found("https://x.com/login")
    ws.advance_phase("auth_attempt")
    ws.record_auth_attempt(captured=False)
    ok, why = ws.advance_phase("post_auth_recon")
    assert ok is False
    assert "auth state" in why.lower()


def test_advance_to_post_auth_recon_allowed_after_capture() -> None:
    ws.record_login_form_found("https://x.com/login")
    ws.advance_phase("auth_attempt")
    ws.record_auth_attempt(captured=True, label="admin-user")
    ok, _ = ws.advance_phase("post_auth_recon")
    assert ok is True
    snap = ws.snapshot()
    assert "admin-user" in snap["captured_auth_labels"]


def test_advance_to_probe_blocked_without_endpoints() -> None:
    """Probe phase requires at least one endpoint discovered.
    Recon has to produce something before probing makes sense."""
    ok, why = ws.advance_phase("probe")
    assert ok is False
    assert "endpoints" in why.lower()


def test_advance_to_probe_allowed_with_endpoints() -> None:
    ws.record_endpoint_discovered("https://x.com/api/users")
    ok, _ = ws.advance_phase("probe", reason="ready to probe")
    assert ok is True


def test_advance_to_chain_correlation_blocked_without_findings() -> None:
    """chain_correlation is a no-op with zero findings; the gate
    suggests advancing directly to report instead."""
    ws.record_endpoint_discovered("https://x.com/api/users")
    ws.advance_phase("probe")
    ok, why = ws.advance_phase("chain_correlation")
    assert ok is False
    assert "no findings" in why.lower()


def test_advance_to_report_always_allowed_from_any_phase() -> None:
    """The terminal phase has no prerequisites. `finish_scan` is
    where the "are you sure?" guard fires — the workflow itself
    doesn't refuse forward transition to report."""
    ws.record_endpoint_discovered("https://x.com/a")
    for source in ("recon", "probe"):
        ws.reset_for_testing()
        ws.record_endpoint_discovered("https://x.com/a")
        if source == "probe":
            ws.advance_phase("probe")
        ok, _ = ws.advance_phase("report", reason="early-exit")
        assert ok is True, f"report-from-{source} should be allowed"


# ---------------------------------------------------------------------------
# Backwards transitions
# ---------------------------------------------------------------------------


def test_backwards_transitions_always_allowed() -> None:
    """probe → recon (e.g. discovered a new endpoint during probing
    that warrants re-crawl). Backwards moves don't trigger gates."""
    ws.record_endpoint_discovered("https://x.com/a")
    ws.advance_phase("probe")
    ok, _ = ws.advance_phase("recon", reason="found new sub-resource")
    assert ok is True
    assert ws.get_current_phase() == "recon"


# ---------------------------------------------------------------------------
# force=True
# ---------------------------------------------------------------------------


def test_force_bypasses_gates() -> None:
    """force=True allows transition even when the gate would refuse.
    Used when the lead has explicitly decided to skip a phase."""
    # Gate would refuse — no endpoints, no login form.
    ok, _ = ws.advance_phase("probe", force=True)
    assert ok is True
    assert ws.get_current_phase() == "probe"


def test_force_not_needed_for_in_phase_transition() -> None:
    """Re-entering the current phase is always allowed; force is
    irrelevant."""
    ws.record_endpoint_discovered("https://x.com/a")
    ws.advance_phase("probe")
    ok, _ = ws.advance_phase("probe")
    assert ok is True


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


def test_snapshot_carries_gates() -> None:
    """The snapshot's `gates` dict is the lead's structured view
    of "what prerequisites have I met?". Tested gates: endpoints
    discovered, login form found, auth attempted, auth captured,
    probe-coverage percentage, findings emitted."""
    ws.record_endpoint_discovered("https://x.com/a")
    ws.record_endpoint_discovered("https://x.com/b")
    ws.record_login_form_found("https://x.com/login")
    ws.record_auth_attempt(captured=True)
    ws.advance_phase("auth_attempt", force=True)
    ws.advance_phase("probe", force=True)
    ws.record_endpoint_probed("https://x.com/a")
    ws.record_finding_emitted()

    snap = ws.snapshot()
    g = snap["gates"]
    assert g["recon_has_endpoints"] is True
    assert g["recon_found_login_form"] is True
    assert g["auth_attempted"] is True
    assert g["auth_state_captured"] is True
    assert g["probe_coverage_pct"] == 50.0   # 1 of 2 endpoints probed
    assert g["findings_emitted"] == 1


def test_snapshot_phase_history_records_transitions() -> None:
    """Phase history is the audit log: every transition adds an
    entry with entered_at + duration. The first phase (recon)
    is auto-populated from time-zero."""
    ws.record_endpoint_discovered("https://x.com/a")
    ws.advance_phase("probe")
    history = ws.snapshot()["phase_history"]
    phases = [e["phase"] for e in history]
    assert phases == ["recon", "probe"]
    # First entry has a closed-out duration; current entry doesn't.
    assert history[0]["exited_at"] is not None
    assert history[1]["exited_at"] is None
    assert history[1]["duration_s"] >= 0


def test_snapshot_next_recommended_actions_reacts_to_phase() -> None:
    """next_recommended_actions should reflect the current phase
    + gate state. Recon with no endpoints → recommend recon tools."""
    # Empty recon
    actions = ws.snapshot()["next_recommended_actions"]
    assert any("recon" in a.lower() or "bfs_crawl" in a for a in actions)

    # Login form found, no auth yet → recommend advance to auth_attempt
    ws.record_endpoint_discovered("https://x.com/a")
    ws.record_login_form_found("https://x.com/login")
    actions = ws.snapshot()["next_recommended_actions"]
    assert any("auth" in a.lower() for a in actions)


def test_snapshot_unprobed_endpoints_sample_caps_at_ten() -> None:
    """Long unprobed-endpoint lists get truncated in the snapshot
    so the rendered output stays small."""
    for i in range(25):
        ws.record_endpoint_discovered(f"https://x.com/e{i}")
    ws.advance_phase("probe")
    snap = ws.snapshot()
    assert len(snap["unprobed_endpoints_sample"]) == 10
    # Total count is unaffected by sample truncation.
    assert snap["endpoints_discovered_count"] == 25


# ---------------------------------------------------------------------------
# Tool-catalog phase filtering
# ---------------------------------------------------------------------------


def test_allowed_tools_for_phase_recon_excludes_probe_specialists() -> None:
    """Recon phase should NOT include scan_sqli, scan_xss, etc.
    Probe specialists are hidden during recon → reduces the lead's
    cognitive load to recon-appropriate tools."""
    allowed = ws.allowed_tools_for_phase("recon")
    assert "scan_sqli" not in allowed
    assert "scan_xss" not in allowed
    assert "scan_idor" not in allowed
    # Recon tools should be present:
    assert "bfs_crawl" in allowed
    assert "webapp_recon_pipeline" in allowed
    assert "fingerprint_tech_stack" in allowed


def test_allowed_tools_for_phase_probe_includes_specialists() -> None:
    """The full specialist fan-out lives in the probe phase."""
    allowed = ws.allowed_tools_for_phase("probe")
    for tool in (
        "scan_sqli", "scan_xss", "scan_idor", "csrf_check",
        "scan_path_traversal", "open_redirect_check",
    ):
        assert tool in allowed, f"probe phase should allow {tool}"
    # Recon-only tools are absent.
    assert "bfs_crawl" not in allowed


def test_allowed_tools_for_phase_agnostic_tools_in_every_phase() -> None:
    """workflow_status / workflow control / findings emission live
    in every phase — the lead can always inspect state and emit a
    finding when evidence is in hand."""
    agnostic = {
        "workflow_status", "advance_workflow_phase",
        "create_vulnerability_report",
        "open_hypothesis", "dismiss_hypothesis",
        "think",
    }
    for phase in ws.PHASES:
        allowed = ws.allowed_tools_for_phase(phase)
        missing = agnostic - allowed
        assert not missing, f"phase {phase} missing agnostic tools: {missing}"


def test_allowed_tools_for_phase_report_is_terminal() -> None:
    """Report phase is intentionally narrow — only `finish_scan` +
    the phase-agnostic surface. Probe / recon tools are gone."""
    allowed = ws.allowed_tools_for_phase("report")
    assert "finish_scan" in allowed
    assert "scan_sqli" not in allowed
    assert "bfs_crawl" not in allowed


def test_allowed_tools_for_phase_unknown_phase_returns_empty() -> None:
    """A bogus phase string returns empty (the caller should
    detect this and disable filtering)."""
    assert ws.allowed_tools_for_phase("bogus") == set()
    assert ws.allowed_tools_for_phase(None) == set()


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_default_off(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)
    assert ws.is_workflow_disabled() is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_kill_switch_enabled_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_WORKFLOW_DISABLED", val)
    assert ws.is_workflow_disabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", ""])
def test_kill_switch_disabled_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_WORKFLOW_DISABLED", val)
    assert ws.is_workflow_disabled() is False


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_concurrent_record_endpoint_discovered_is_safe() -> None:
    """Recorders are called from specialist tools that may run
    concurrently. Final state should reflect all writes."""

    def writer(start: int, count: int) -> None:
        for i in range(start, start + count):
            ws.record_endpoint_discovered(f"https://x.com/e{i}")

    threads = [
        threading.Thread(target=writer, args=(i * 50, 50))
        for i in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snap = ws.snapshot()
    assert snap["endpoints_discovered_count"] == 200


# ---------------------------------------------------------------------------
# Post-auth recon endpoints recorded into the right bucket
# ---------------------------------------------------------------------------


def test_recon_endpoints_segregated_from_post_auth() -> None:
    """During post_auth_recon, newly-discovered endpoints land in
    the post-auth bucket (separately countable in the snapshot)."""
    ws.record_endpoint_discovered("https://x.com/login")
    ws.record_login_form_found("https://x.com/login")
    ws.advance_phase("auth_attempt")
    ws.record_auth_attempt(captured=True)
    ws.advance_phase("post_auth_recon")

    ws.record_endpoint_discovered("https://x.com/admin")
    ws.record_endpoint_discovered("https://x.com/bank/account")

    snap = ws.snapshot()
    assert snap["endpoints_discovered_count"] == 1                  # /login
    assert snap["post_auth_endpoints_discovered_count"] == 2         # /admin /bank
