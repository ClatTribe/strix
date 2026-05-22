"""Tests for iter-26.8 — posture-aware stealth payload guidance."""

from __future__ import annotations

import pytest

from strix.l15.posture import SecurityPosture, clear_cache, set_posture
from strix.l15.stealth_guidance import stealth_addendum_for


@pytest.fixture(autouse=True)
def _clean():
    clear_cache()
    yield
    clear_cache()


def test_no_target_returns_empty():
    assert stealth_addendum_for("sqli", target=None) == ""


def test_no_posture_returns_empty():
    """Posture cache empty (target not probed) → no addendum."""
    assert stealth_addendum_for("sqli", "https://unprobed.com") == ""


def test_clean_posture_returns_empty():
    set_posture(SecurityPosture(
        target="https://plain.com",
        waf_detected=False,
        stealth_mode_required=False,
    ))
    assert stealth_addendum_for("sqli", "https://plain.com") == ""


def test_waf_posture_emits_sqli_guidance():
    set_posture(SecurityPosture(
        target="https://wafd.com",
        waf_detected=True,
        waf_vendor="cloudflare",
        stealth_mode_required=True,
    ))
    out = stealth_addendum_for("sqli", "https://wafd.com")
    assert "STEALTH MODE" in out
    assert "TIME-BASED" in out or "tamper" in out.lower()


def test_waf_posture_emits_xss_guidance():
    set_posture(SecurityPosture(
        target="https://wafd.com",
        waf_detected=True,
        stealth_mode_required=True,
    ))
    out = stealth_addendum_for("xss", "https://wafd.com")
    assert "XSS STEALTH" in out
    assert "svg" in out.lower() or "details" in out.lower()


def test_unknown_category_falls_back_to_default():
    set_posture(SecurityPosture(
        target="https://wafd.com",
        waf_detected=True,
        stealth_mode_required=True,
    ))
    out = stealth_addendum_for("nonexistent", "https://wafd.com")
    assert "GENERIC STEALTH" in out


def test_rps_info_included_when_measured():
    set_posture(SecurityPosture(
        target="https://wafd.com",
        waf_detected=True,
        stealth_mode_required=True,
        rate_limit_rps=20,
    ))
    out = stealth_addendum_for("sqli", "https://wafd.com")
    assert "Rate-limit cap" in out
    # 20 rps observed → 10 rps cap
    assert "10 rps" in out


def test_path_traversal_guidance():
    set_posture(SecurityPosture(
        target="https://wafd.com",
        waf_detected=True,
        stealth_mode_required=True,
    ))
    out = stealth_addendum_for("path_traversal", "https://wafd.com")
    assert "PATH-TRAVERSAL STEALTH" in out
    assert "%2e%2e%2f" in out or "double-encoded" in out


def test_ssrf_guidance_mentions_metadata_skip():
    set_posture(SecurityPosture(
        target="https://wafd.com",
        waf_detected=True,
        stealth_mode_required=True,
    ))
    out = stealth_addendum_for("ssrf", "https://wafd.com")
    assert "169.254" in out or "metadata" in out.lower()


def test_robustness_invalid_target():
    """Invalid target → no crash, returns empty."""
    out = stealth_addendum_for("sqli", "not a url")
    assert out == ""
