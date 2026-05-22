"""Tests for iter-25.6 — hygiene prior."""

from __future__ import annotations

import pytest

from strix.l15.hygiene import (
    HygieneLedger,
    hygiene_ledger,
)


@pytest.fixture(autouse=True)
def _clean_ledger():
    hygiene_ledger.clear()
    yield
    hygiene_ledger.clear()


def test_empty_ledger_is_neutral():
    s = hygiene_ledger.compute()
    assert 0.9 <= s.score <= 1.0
    assert s.depth_multiplier == 0.6  # strong hygiene → trim depth


def test_missing_headers_lower_score():
    for _ in range(6):
        hygiene_ledger.observe({
            "title": "Missing Content-Security-Policy header",
            "category": "http_security_headers",
        })
    s = hygiene_ledger.compute()
    assert s.missing_headers == 6
    # 6 × 0.05 = 0.30 penalty → score 0.70
    assert 0.65 <= s.score <= 0.75


def test_dev_banner_dominates_score():
    hygiene_ledger.observe({
        "title": "Server header discloses version: Werkzeug/2.2.3",
        "description": "Werkzeug development server in production",
    })
    hygiene_ledger.observe({
        "title": "Server: Werkzeug/2.2.3",
    })
    s = hygiene_ledger.compute()
    assert s.dev_banners >= 2
    # 2 × 0.15 = 0.30 penalty → score around 0.70
    assert s.score < 0.80


def test_poor_hygiene_bumps_depth():
    # Pile on signals
    for _ in range(8):
        hygiene_ledger.observe({"title": "Missing HSTS header"})
    for _ in range(3):
        hygiene_ledger.observe({"title": "Server: Werkzeug/2.2.3"})
    for _ in range(5):
        hygiene_ledger.observe({"description": "Traceback (most recent call last)"})
    for _ in range(10):
        hygiene_ledger.observe({
            "title": "Vulnerable dependency `npm:lodash@4.17.20`",
            "category": "sca",
        })
    s = hygiene_ledger.compute()
    assert s.score < 0.30
    assert s.depth_multiplier == 2.0
    assert "poor" in s.rationale


def test_secret_density_uses_kloc():
    hygiene_ledger.set_kloc(0.5)  # 500 LOC repo
    for _ in range(3):
        hygiene_ledger.observe({
            "title": "AWS secret detected",
            "cwe": "CWE-798",
        })
    s = hygiene_ledger.compute()
    # 3 secrets / 0.5 kloc = 6/kloc density
    assert s.secret_density_per_kloc == 6.0


def test_isolated_ledger_instance():
    led = HygieneLedger()
    led.observe({"title": "Missing CSP header"})
    s = led.compute()
    assert s.missing_headers == 1


def test_score_capped_at_one():
    # No observations at all → score = 1.0
    s = hygiene_ledger.compute()
    assert s.score <= 1.0


def test_score_floor_at_zero():
    # Pile on extreme amounts
    for _ in range(200):
        hygiene_ledger.observe({"title": "Missing HSTS header"})
        hygiene_ledger.observe({"title": "Server: Werkzeug/2.2.3"})
        hygiene_ledger.observe({"description": "Traceback (most recent call last)"})
        hygiene_ledger.observe({
            "title": "Vulnerable dependency", "category": "sca",
        })
    s = hygiene_ledger.compute()
    assert s.score >= 0.0
    assert s.depth_multiplier == 2.0


def test_malformed_finding_doesnt_crash():
    """A finding without expected fields shouldn't crash observe()."""
    hygiene_ledger.observe({})  # empty dict
    hygiene_ledger.observe({"description": None})
    s = hygiene_ledger.compute()
    assert isinstance(s.score, float)


def test_dev_banner_regex_misses_prod():
    """Production-stage servers shouldn't trigger the dev banner check."""
    hygiene_ledger.observe({"title": "Server: nginx/1.18.0"})
    hygiene_ledger.observe({"title": "Server: gunicorn/20.1.0"})
    hygiene_ledger.observe({"title": "Server: apache/2.4.49"})
    s = hygiene_ledger.compute()
    assert s.dev_banners == 0


def test_to_dict_round_trip():
    hygiene_ledger.observe({"title": "Missing CSP header"})
    s = hygiene_ledger.compute()
    d = s.to_dict()
    assert "score" in d
    assert "depth_multiplier" in d
    assert "missing_headers" in d
