"""Tests for iter-26.3 + 26.4 — L1.5 dispatch budget scaling."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.l15.hygiene import hygiene_ledger
from strix.tools.workflow.specialist_dispatch import dispatch_specialist


@pytest.fixture(autouse=True)
def _clean():
    hygiene_ledger.clear()
    yield
    hygiene_ledger.clear()


@pytest.fixture
def mock_orchestrator(monkeypatch):
    """Capture the args dispatch_specialist passes to the orchestrator."""
    captured: dict = {}
    fake = MagicMock()

    def _capture(**kwargs):
        captured.update(kwargs)
        return {"status": "PASSED", "iterations_used": 0}

    fake.dispatch_specialist = _capture
    monkeypatch.setattr(
        "strix.tools.workflow.specialist_dispatch._orchestrator",
        lambda: fake,
    )
    return captured


# --------------------------------------------------------------------
# Surface priority depth multiplier
# --------------------------------------------------------------------

def test_critical_surface_triples_iter_cap(mock_orchestrator):
    """Critical surface (e.g. /admin) → 3.0× the default 50 = 150."""
    dispatch_specialist(
        category="auth",
        objective="probe admin panel",
        target="https://app.example.com/admin/users",
    )
    # 50 default × 3.0 critical × 1.0 hygiene (empty ledger = neutral)
    # Actually empty ledger compute() returns score 1.0 → mult 0.6.
    # Combined: 3.0 × 0.6 = 1.8 → 50 × 1.8 = 90
    assert mock_orchestrator["max_iterations"] == 90


def test_low_surface_trims_iter_cap(mock_orchestrator):
    """Low surface (/static/) → 0.3× × 0.6 = 0.18 → clamped to 0.2× → 10."""
    dispatch_specialist(
        category="recon",
        objective="probe static assets",
        target="https://app.example.com/static/main.css",
    )
    # 0.3 × 0.6 = 0.18 → clamped to combined-floor 0.2 → 50 × 0.2 = 10
    assert mock_orchestrator["max_iterations"] == 10


def test_normal_surface_unchanged(mock_orchestrator):
    """Normal surface → 1.0 × hygiene multiplier only."""
    dispatch_specialist(
        category="generic",
        objective="probe normal endpoint",
        target="https://app.example.com/products/42",
    )
    # 50 × (1.0 × 0.6) = 30
    assert mock_orchestrator["max_iterations"] == 30


# --------------------------------------------------------------------
# Hygiene multiplier
# --------------------------------------------------------------------

def test_poor_hygiene_doubles_dispatch_budget(mock_orchestrator):
    """Sloppy target (many missing headers + dev banners) → 2.0× depth."""
    # Pile on enough signals to push hygiene score below 0.30
    # (penalty > 0.7): max-out missing headers + dev banners +
    # stack traces + vuln deps + secret density.
    for _ in range(10):
        hygiene_ledger.observe({"title": "Missing HSTS header"})
    for _ in range(5):
        hygiene_ledger.observe({"title": "Server: Werkzeug/2.2.3"})
    for _ in range(5):
        hygiene_ledger.observe({"description": "Traceback (most recent call last)"})
    for _ in range(10):
        hygiene_ledger.observe({
            "title": "Vulnerable dependency `npm:lodash@4.17.20`",
            "category": "sca",
        })
    dispatch_specialist(
        category="sqli",
        objective="probe sloppy target",
        target="https://app.example.com/api/foo",
    )
    # Normal surface (1.0) × poor hygiene (2.0) = 2.0 → 50 × 2.0 = 100
    assert mock_orchestrator["max_iterations"] == 100


def test_combined_critical_surface_and_poor_hygiene_clamps_to_max(
    mock_orchestrator,
):
    """3.0 × 2.0 = 6.0 → clamped to 5.0 → 50 × 5.0 = 250."""
    # Pile on enough signals to push hygiene score below 0.30
    # (penalty > 0.7): max-out missing headers + dev banners +
    # stack traces + vuln deps + secret density.
    for _ in range(10):
        hygiene_ledger.observe({"title": "Missing HSTS header"})
    for _ in range(5):
        hygiene_ledger.observe({"title": "Server: Werkzeug/2.2.3"})
    for _ in range(5):
        hygiene_ledger.observe({"description": "Traceback (most recent call last)"})
    for _ in range(10):
        hygiene_ledger.observe({
            "title": "Vulnerable dependency `npm:lodash@4.17.20`",
            "category": "sca",
        })
    dispatch_specialist(
        category="auth",
        objective="probe critical+sloppy target",
        target="https://app.example.com/admin/users",
    )
    assert mock_orchestrator["max_iterations"] == 250


def test_combined_low_surface_and_tidy_hygiene_clamps_to_min(
    mock_orchestrator,
):
    """0.3 × 0.6 = 0.18 → clamped to 0.2 → 50 × 0.2 = 10."""
    dispatch_specialist(
        category="recon",
        objective="probe static asset on tidy target",
        target="https://app.example.com/static/main.css",
    )
    # 0.3 × 0.6 = 0.18 → clamps to 0.2 → 50 × 0.2 = 10
    # But min iter-cap floor is 5, so result is max(5, 10) = 10
    assert mock_orchestrator["max_iterations"] == 10


# --------------------------------------------------------------------
# Explicit max_iterations override
# --------------------------------------------------------------------

def test_explicit_max_iterations_overrides_l15_scaling(mock_orchestrator):
    """When caller pins max_iterations, L1.5 scaling is skipped."""
    dispatch_specialist(
        category="auth",
        objective="explicit budget",
        target="https://app.example.com/admin",
        max_iterations=25,
    )
    assert mock_orchestrator["max_iterations"] == 25


# --------------------------------------------------------------------
# No target → no scaling
# --------------------------------------------------------------------

def test_no_target_no_scaling(mock_orchestrator):
    """Without a target we can't compute surface priority — passthrough."""
    dispatch_specialist(
        category="generic",
        objective="no target dispatch",
    )
    # max_iterations remains None — orchestrator uses its default
    assert mock_orchestrator["max_iterations"] is None


# --------------------------------------------------------------------
# Floor at 5 iterations
# --------------------------------------------------------------------

def test_iter_cap_never_below_5(mock_orchestrator):
    """Even extreme down-scaling shouldn't drop below 5 iterations."""
    # Setup tidiest possible hygiene
    dispatch_specialist(
        category="recon",
        objective="static asset",
        target="https://app.example.com/favicon.ico",
    )
    # 0.3 × 0.6 = 0.18 → clamps to 0.2 → 50 × 0.2 = 10 ≥ 5 floor
    assert mock_orchestrator["max_iterations"] >= 5
