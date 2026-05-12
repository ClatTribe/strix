"""Tests for the `finish_scan` hypothesis-block guard
(recall-lift PR-1).

The guard refuses to terminate the scan while there are
`investigating`-status hypotheses on the table. Forces the lead to
either confirm them (→ finding emission) or dismiss them (→ explicit
"not exploitable" decision) before calling finish_scan — closes the
recall-lossy pattern where the lead emits a few findings and bails
on the remaining open hypotheses.

The lead can override with `force=True` when its own reasoning has
genuinely exhausted the open hypotheses; the default is to refuse.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from strix.tools.finish.finish_actions import (
    _check_open_hypotheses,
    finish_scan,
)


# ---------------------------------------------------------------------------
# _check_open_hypotheses — unit-level (decoupled from the rest of finish_scan)
# ---------------------------------------------------------------------------


def test_guard_returns_none_when_no_open_hypotheses() -> None:
    """No in-flight hypotheses → finish_scan should be allowed."""
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=[],
    ):
        result = _check_open_hypotheses(force=False)
    assert result is None


def test_guard_blocks_when_open_hypotheses_present() -> None:
    """One or more `investigating` hypotheses → guard refuses."""
    fake_open = [
        {"id": "h-1", "category": "sqli", "surface": "/login",
         "summary": "POST /login username param looks reflectable"},
        {"id": "h-2", "category": "idor", "surface": "/api/account",
         "summary": "Account ID in URL — cross-session diff pending"},
    ]
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=fake_open,
    ):
        result = _check_open_hypotheses(force=False)

    assert result is not None
    assert result["success"] is False
    assert result["error"] == "open_hypotheses_remain"
    assert result["open_count"] == 2
    assert len(result["open_hypothesis_summaries"]) == 2
    # The surfaces / categories should appear in the summary so the
    # lead can identify what's still open.
    surfaces = [s["surface"] for s in result["open_hypothesis_summaries"]]
    assert "/login" in surfaces
    assert "/api/account" in surfaces


def test_guard_force_true_bypasses_block() -> None:
    """force=True → guard is opted-out, even with open hypotheses."""
    fake_open = [{"id": "h-1", "category": "sqli", "surface": "/x", "summary": "y"}]
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=fake_open,
    ):
        result = _check_open_hypotheses(force=True)
    assert result is None


def test_guard_fails_open_when_hypothesis_module_unavailable() -> None:
    """If the hypothesis module raises (e.g. circular import in a
    weird state), the guard MUST fall through — never block
    finish_scan due to a bug in an auxiliary subsystem."""
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        side_effect=RuntimeError("hypothesis store offline"),
    ):
        result = _check_open_hypotheses(force=False)
    # No block → finish_scan proceeds.
    assert result is None


def test_guard_truncates_to_six_summaries() -> None:
    """When 20+ hypotheses are open, the guard surfaces only the
    first 6 in summaries (caps the response size); open_count
    remains accurate."""
    many = [
        {"id": f"h-{i}", "category": "sqli", "surface": f"/p{i}", "summary": "x"}
        for i in range(20)
    ]
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=many,
    ):
        result = _check_open_hypotheses(force=False)
    assert result is not None
    assert result["open_count"] == 20
    assert len(result["open_hypothesis_summaries"]) == 6


def test_guard_truncates_long_summary_fields() -> None:
    """Surface and summary fields are truncated to keep the
    response small — important because the agent loop logs these."""
    long_summary = "x" * 500
    long_surface = "/very/long/path/" + "a" * 200
    fake_open = [
        {"id": "h-1", "category": "sqli", "surface": long_surface,
         "summary": long_summary},
    ]
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=fake_open,
    ):
        result = _check_open_hypotheses(force=False)
    s = result["open_hypothesis_summaries"][0]
    assert len(s["surface"]) <= 80
    assert len(s["summary"]) <= 120


# ---------------------------------------------------------------------------
# finish_scan integration — guard wired in correctly
# ---------------------------------------------------------------------------


def test_finish_scan_blocked_by_open_hypothesis() -> None:
    """End-to-end via finish_scan: open hypothesis → blocked."""
    fake_open = [{"id": "h-1", "category": "sqli", "surface": "/login", "summary": "x"}]
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=fake_open,
    ):
        result = finish_scan(
            executive_summary="x",
            methodology="y",
            technical_analysis="z",
            recommendations="w",
        )
    assert result["success"] is False
    assert result["error"] == "open_hypotheses_remain"


def test_finish_scan_force_true_succeeds_despite_open_hypothesis() -> None:
    """force=True bypasses the open-hypothesis block end-to-end."""
    fake_open = [{"id": "h-1", "category": "sqli", "surface": "/login", "summary": "x"}]
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=fake_open,
    ):
        # finish_scan still needs a valid tracer / agent_state path
        # to fully succeed; this test just confirms it gets PAST the
        # guard. The "tracer unavailable" failure mode is a different
        # branch from "blocked by open hypotheses."
        result = finish_scan(
            executive_summary="x",
            methodology="y",
            technical_analysis="z",
            recommendations="w",
            force=True,
        )
    # The guard didn't fire — error (if any) is not the open-hypotheses one.
    assert result.get("error") != "open_hypotheses_remain"


def test_finish_scan_no_open_hypotheses_proceeds() -> None:
    """Clean state → guard doesn't fire."""
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=[],
    ):
        result = finish_scan(
            executive_summary="x",
            methodology="y",
            technical_analysis="z",
            recommendations="w",
        )
    assert result.get("error") != "open_hypotheses_remain"
