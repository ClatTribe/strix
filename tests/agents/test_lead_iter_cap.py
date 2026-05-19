"""Tests for `strix/agents/lead_iter_cap.py` — V3-1 of the
quick-mode lightweight plan.

Recall-safety contract pinned by tests:
  * The cap is a CEILING — never raises the configured
    max_iterations.
  * `deep` and unknown / unset modes return the configured value
    verbatim (no silent throttling).
  * Kill switch (`STRIX_LEAD_ITER_CAP_DISABLED=1`) bypasses the
    cap entirely.
  * Override env wins over the mode-derived cap.
  * Garbage override values fall through to the mode cap.
  * Telemetry only fires when the cap actually clipped the value.
"""

from __future__ import annotations

import pytest

from strix.agents import lead_iter_cap as lic


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_LEAD_ITER_OVERRIDE", raising=False)
    monkeypatch.delenv("STRIX_LEAD_ITER_CAP_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# get_scan_mode_lead_iter_cap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode,expected", [
    ("initial", 6),
    ("quick", 12),
    ("standard", 60),
    ("deep", None),
    ("DEEP", None),     # case-insensitive
    ("Quick", 12),
])
def test_scan_mode_cap_table(
    monkeypatch: pytest.MonkeyPatch, mode: str, expected: int | None,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", mode)
    assert lic.get_scan_mode_lead_iter_cap() == expected


def test_unknown_mode_returns_none_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "wat")
    assert lic.get_scan_mode_lead_iter_cap() is None


def test_unset_mode_returns_none_unbounded() -> None:
    """No mode env → unbounded; we never silently throttle."""
    assert lic.get_scan_mode_lead_iter_cap() is None


# ---------------------------------------------------------------------------
# Override
# ---------------------------------------------------------------------------


def test_override_wins_over_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")  # would be 12
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "100")
    assert lic.get_scan_mode_lead_iter_cap() == 100


def test_override_minimum_is_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator can't set 0 — the agent loop needs at least one
    iteration to call finish_scan."""
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "0")
    assert lic.get_scan_mode_lead_iter_cap() == 1


def test_override_garbage_falls_back_to_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "not-an-int")
    assert lic.get_scan_mode_lead_iter_cap() == 12  # quick


# ---------------------------------------------------------------------------
# get_effective_max_iterations — the recall-safety surface
# ---------------------------------------------------------------------------


def test_effective_max_caps_to_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """The cap CLIPS — configured=300 + mode=quick → 12."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    assert lic.get_effective_max_iterations(300) == 12


def test_effective_max_never_raises_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recall safety canary — the cap is a CEILING. If the caller
    explicitly wanted max_iterations=5, we must NOT raise it to
    the quick-mode cap of 12. The configured value wins when it's
    already tighter."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    assert lic.get_effective_max_iterations(5) == 5


def test_effective_max_unbounded_for_deep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "deep")
    assert lic.get_effective_max_iterations(300) == 300


def test_effective_max_unbounded_for_unset_mode() -> None:
    """No scan_mode → no clipping. Backwards-compat with runs that
    never opted in."""
    assert lic.get_effective_max_iterations(300) == 300


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_returns_configured_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")  # would cap to 12
    monkeypatch.setenv("STRIX_LEAD_ITER_CAP_DISABLED", "1")
    assert lic.get_effective_max_iterations(300) == 300


def test_kill_switch_ignores_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the kill switch is on, neither the mode cap nor the
    override env matters — the configured value is used verbatim."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "5")
    monkeypatch.setenv("STRIX_LEAD_ITER_CAP_DISABLED", "1")
    assert lic.get_effective_max_iterations(300) == 300


# ---------------------------------------------------------------------------
# Override applies via get_effective_max_iterations too
# ---------------------------------------------------------------------------


def test_effective_max_respects_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "25")
    # configured=300, override=25 (smaller than 300) → effective=25
    assert lic.get_effective_max_iterations(300) == 25


def test_effective_max_caps_even_when_override_exceeds_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Override=500, configured=300 → effective=300 (we never raise)."""
    monkeypatch.setenv("STRIX_LEAD_ITER_OVERRIDE", "500")
    assert lic.get_effective_max_iterations(300) == 300


# ---------------------------------------------------------------------------
# Recall canary — the "deterministic stack catches everything"
# pinning. If the quick-mode cap drops below this minimum, the cap
# is too tight and the value reverts.
# ---------------------------------------------------------------------------


def test_quick_mode_cap_floor_for_recall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Quick-mode floor: at least 10 iterations to cover boot +
    minimal recon interpretation + 3-4 probe decisions + finding
    emission + report. The proposal pins this at 12; if a future
    PR drops it below 10, this canary breaks and the change must
    revert."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")
    cap = lic.get_scan_mode_lead_iter_cap()
    assert cap is not None and cap >= 10, (
        f"quick mode cap {cap} is too tight; min floor is 10 "
        "iterations to cover the deterministic-stack happy path. "
        "Loosen the cap rather than this canary."
    )


def test_standard_mode_cap_floor_for_recall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Standard-mode floor: at least 30 iterations. Standard
    allows full multi-round specialist work (8 dispatches × ~3
    lead iterations each + recon + verify + report)."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")
    cap = lic.get_scan_mode_lead_iter_cap()
    assert cap is not None and cap >= 30, (
        f"standard mode cap {cap} is too tight; min floor is 30."
    )
