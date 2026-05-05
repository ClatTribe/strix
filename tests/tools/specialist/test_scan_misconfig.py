"""Tests for §8.5 Phase 1 — `scan_misconfig` (first deterministic
specialist-tool).

Pins the deterministic header / cookie / version-disclosure detection
rules. Hermetic — no network access; passes pre-fetched response
data so the test exercises only the pure-Python analysis.
"""

from __future__ import annotations

import pytest

from strix.tools.specialist.scan_misconfig import scan_misconfig


# ---------------------------------------------------------------------------
# Defensive input handling
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_misconfig(url="", headers={"X-Test": "1"})
    assert out["status"] == "error"
    assert "url" in (out["error"] or "")


def test_invalid_url_returns_error() -> None:
    out = scan_misconfig(url="not-a-url", headers={"X-Test": "1"})
    assert out["status"] == "error"


def test_missing_headers_returns_partial() -> None:
    """Lead may invoke before fetching headers — partial status surfaces
    the issue without crashing."""
    out = scan_misconfig(url="https://app.example.com", headers=None)
    assert out["status"] == "partial"
    assert "headers" in (out["error"] or "")


# ---------------------------------------------------------------------------
# HSTS detection
# ---------------------------------------------------------------------------


def test_hsts_missing_on_https() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={"Content-Security-Policy": "default-src 'self'"},
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("Strict-Transport-Security" in t for t in titles)


def test_hsts_skipped_on_http() -> None:
    """HSTS is irrelevant on plaintext HTTP."""
    out = scan_misconfig(
        url="http://app.example.com",
        headers={"Content-Security-Policy": "default-src 'self'"},
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("Strict-Transport-Security" in t for t in titles)


def test_hsts_low_max_age_flagged() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Strict-Transport-Security": "max-age=300",
            "Content-Security-Policy": "default-src 'self'",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("max-age too low" in t for t in titles)


def test_hsts_strong_passes() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("Strict-Transport-Security" in t for t in titles)
    assert not any("max-age" in t for t in titles)


# ---------------------------------------------------------------------------
# CSP detection
# ---------------------------------------------------------------------------


def test_csp_missing_emits_medium() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
    )
    csp_findings = [f for f in out["findings"] if "Content-Security-Policy" in f["title"]]
    assert csp_findings
    assert csp_findings[0]["severity"] == "medium"


def test_csp_unsafe_inline_flagged() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("unsafe-inline" in t for t in titles)


def test_csp_unsafe_eval_flagged() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("unsafe-eval" in t for t in titles)


def test_csp_with_frame_ancestors_satisfies_clickjacking_check() -> None:
    """No clickjacking finding when CSP frame-ancestors is set."""
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("clickjacking protection" in t for t in titles)


# ---------------------------------------------------------------------------
# Clickjacking
# ---------------------------------------------------------------------------


def test_clickjacking_neither_xfo_nor_frame_ancestors() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={"Content-Security-Policy": "default-src 'self'"},
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("clickjacking" in t.lower() for t in titles)


def test_clickjacking_xfo_only_satisfies() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("clickjacking" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# Cookie attributes
# ---------------------------------------------------------------------------


def test_cookie_missing_secure() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Set-Cookie": "session=abc; Path=/; HttpOnly; SameSite=Lax",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("missing Secure" in t for t in titles)


def test_cookie_missing_httponly() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Set-Cookie": "session=abc; Path=/; Secure; SameSite=Lax",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("HttpOnly" in t for t in titles)


def test_cookie_missing_samesite() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Set-Cookie": "session=abc; Path=/; Secure; HttpOnly",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("SameSite" in t for t in titles)


def test_cookie_value_substring_does_not_satisfy_attribute() -> None:
    """Regression: a cookie value containing the substring 'Secure' /
    'HttpOnly' / 'SameSite' must NOT be treated as having the
    attribute. Attribute detection is segment-based, not substring."""
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            # Value contains "Secure" + "HttpOnly" + "SameSite" as
            # substrings but no actual attributes.
            "Set-Cookie": "token=abc-Secure-HttpOnly-SameSite-Strict; Path=/",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    # All three flags should still be flagged as missing.
    assert any("missing Secure" in t for t in titles)
    assert any("HttpOnly" in t and "missing" in t for t in titles)
    assert any("SameSite" in t and "missing" in t for t in titles)


def test_well_configured_cookie_passes() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Set-Cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("session" in t and "missing" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# Version disclosure
# ---------------------------------------------------------------------------


def test_server_header_with_version_flagged() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Server": "nginx/1.21.4",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("Server" in t and "version" in t.lower() for t in titles)


def test_server_header_without_version_passes() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "Server": "nginx",  # no digit → no disclosure flag
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("Server" in t and "version" in t.lower() for t in titles)


def test_x_powered_by_with_version_flagged() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "X-Powered-By": "PHP/7.4.3",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("X-Powered-By" in t for t in titles)


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------


def test_result_has_evidence_and_metadata() -> None:
    out = scan_misconfig(
        url="https://app.example.com",
        headers={"X-Test": "1"},
        status=200,
    )
    assert out["evidence"]
    assert "scheme" in out["tool_metadata"]
    assert out["tool_metadata"]["scheme"] == "https"


def test_result_suggests_browser_followup_on_clickjacking() -> None:
    out = scan_misconfig(
        url="https://app.example.com/admin",
        headers={"Content-Security-Policy": "default-src 'self'"},  # no frame-ancestors / XFO
    )
    assert out["next_probes_suggested"]


def test_case_insensitive_header_lookup() -> None:
    """Real-world HTTP libraries normalise header names differently —
    the specialist must handle any casing."""
    out = scan_misconfig(
        url="https://app.example.com",
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
        },
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("Strict-Transport-Security" in t for t in titles)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_scan_misconfig_registered_in_specialist_registry() -> None:
    """Importing scan_misconfig must register it in the §8.5
    specialist registry. Phase 3 lead-agent reads from this."""
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_misconfig")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "misconfig-specialist"
    assert desc.provenance == "framework"
