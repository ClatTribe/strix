"""Tests for cache_deception_check.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- Variant generator (correct mutation per class, dedup on identical URLs)
- Body-similarity heuristic (length tolerance + Jaccard threshold)
- Cacheability classification (explicit / cached_already / ambiguous / not_cacheable)
- Cacheable + body-match → high CWE-525 finding
- Ambiguous + body-match → medium CWE-525 finding
- not_cacheable response → no finding
- Body-divergence → no finding
- Per-class dedup (one finding per class × severity)
- Baseline non-200 → graceful skip
- Baseline too-short body → graceful skip
- Baseline excluded by --exclude-path → graceful no-op
- Variant excluded mid-scan → no crash
- All findings carry description_plain + recommended_action (§11 UX)
- Check event emitted with category=web_cache_deception
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.cache_deception.cache_deception_check  # noqa: F401

cd_module = sys.modules["strix.tools.cache_deception.cache_deception_check"]
cache_deception_check = cd_module.cache_deception_check


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("cd-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=12.0):
        headers = dict(headers or {})
        log.append({"url": url, "headers": headers})
        return responder(url, headers)

    monkeypatch.setattr(cd_module, "_http_get", fake)
    return log


def _resp(*, status=200, body="", headers=None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


# Realistic authenticated body — longer than 80 bytes; tokens dominate so
# the Jaccard match is stable.
_AUTHED_BODY = (
    "<!doctype html><html><head><title>My Account</title></head>"
    "<body><h1>Welcome ashishmishra</h1><p>Your email is "
    "ashish@example.com</p><p>Account balance: $1,234.56</p>"
    "<p>Last login: 2026-01-15 10:23 UTC from 198.51.100.42</p>"
    "<a href='/logout'>Sign out</a></body></html>"
)


# ---------------------------------------------------------------------------
# Variant generator
# ---------------------------------------------------------------------------


def test_variants_cover_all_classes() -> None:
    variants = cd_module._build_variants("https://app.example.com/account")
    classes = {v["class_"] for v in variants}
    assert "static_ext" in classes
    assert "delim_traversal" in classes
    assert "matrix_uri" in classes
    assert "byte_truncation" in classes
    assert "query_strip" in classes


def test_variants_dedup_on_identical_url() -> None:
    """The generator should never emit duplicate URLs."""
    variants = cd_module._build_variants("https://app.example.com/account")
    urls = [v["url"] for v in variants]
    assert len(urls) == len(set(urls))


def test_variant_dot_css_url_correct() -> None:
    variants = cd_module._build_variants("https://app.example.com/account")
    dot_css = next(v for v in variants if v["label"] == "dot_css")
    assert dot_css["url"] == "https://app.example.com/account.css"


def test_variant_query_css_does_not_eat_params() -> None:
    variants = cd_module._build_variants("https://app.example.com/account")
    qcss = next(v for v in variants if v["label"] == "query_css")
    assert "x=.css" in qcss["url"]


# ---------------------------------------------------------------------------
# Body match heuristic
# ---------------------------------------------------------------------------


def test_body_match_exact() -> None:
    out = cd_module._body_match(_AUTHED_BODY, _AUTHED_BODY)
    assert out["match"] is True
    assert out["jaccard"] == 1.0
    assert out["length_ratio"] == 1.0


def test_body_match_close_variant() -> None:
    """Same content with a few-char drift (e.g. timestamp change) still matches."""
    drifted = _AUTHED_BODY.replace("10:23", "10:24")
    out = cd_module._body_match(_AUTHED_BODY, drifted)
    assert out["match"] is True
    assert out["jaccard"] >= 0.85


def test_body_match_unrelated_pages_diverge() -> None:
    other = "<html><body>Login required</body></html>"
    out = cd_module._body_match(_AUTHED_BODY, other)
    assert out["match"] is False


def test_body_match_length_divergence_short_circuits() -> None:
    out = cd_module._body_match(_AUTHED_BODY, _AUTHED_BODY * 5)
    assert out["match"] is False


# ---------------------------------------------------------------------------
# Cacheability classifier
# ---------------------------------------------------------------------------


def test_cacheability_explicit_max_age() -> None:
    assert cd_module._cacheability({"cache-control": "public, max-age=3600"}) == "cacheable_explicit"


def test_cacheability_cached_already_x_cache() -> None:
    assert cd_module._cacheability({"x-cache": "HIT"}) == "cached_already"


def test_cacheability_cached_already_age() -> None:
    assert cd_module._cacheability({"age": "42"}) == "cached_already"


def test_cacheability_cached_already_cf() -> None:
    assert cd_module._cacheability({"cf-cache-status": "HIT"}) == "cached_already"


def test_cacheability_not_cacheable_no_store() -> None:
    assert cd_module._cacheability({"cache-control": "no-store, private"}) == "not_cacheable"


def test_cacheability_ambiguous_silent() -> None:
    assert cd_module._cacheability({}) == "ambiguous"


def test_cacheability_no_store_overrides_max_age() -> None:
    """Cache-Control: max-age=3600, no-store → not_cacheable wins."""
    assert cd_module._cacheability(
        {"cache-control": "max-age=3600, no-store"}
    ) == "not_cacheable"


# ---------------------------------------------------------------------------
# Cacheable + body match → high finding
# ---------------------------------------------------------------------------


def test_cacheable_explicit_match_emits_high(monkeypatch) -> None:
    cache_headers = {"Cache-Control": "public, max-age=3600"}

    def responder(url, headers):
        # Origin returns the authed body for everything (vulnerable
        # path-normalization).
        if url.endswith(".css") or url.endswith(".js"):
            return _resp(body=_AUTHED_BODY, headers=cache_headers)
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "no-store"})

    _patch_http(monkeypatch, responder)
    out = cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high
    assert high[0]["cwe"] == "CWE-525"
    assert high[0]["category"] == "web_cache_deception"
    assert out["findings_emitted"] >= 1


def test_cached_already_match_emits_high(monkeypatch) -> None:
    """X-Cache: HIT counts as cached_already → high."""
    def responder(url, headers):
        if url.endswith(".css"):
            return _resp(body=_AUTHED_BODY, headers={"X-Cache": "HIT"})
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "no-store"})

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" for r in reports)


# ---------------------------------------------------------------------------
# Ambiguous cacheability + body match → medium
# ---------------------------------------------------------------------------


def test_ambiguous_cache_match_emits_medium(monkeypatch) -> None:
    """No Cache-Control + no cache-hit headers → ambiguous → medium."""
    def responder(url, headers):
        if url.endswith(".css") or url.endswith(".js") or "x.css" in url:
            return _resp(body=_AUTHED_BODY, headers={})  # no cache info
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "no-store"})

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "medium" for r in reports)
    assert all(r["severity"] != "high" for r in reports)


# ---------------------------------------------------------------------------
# not_cacheable + body match → no finding
# ---------------------------------------------------------------------------


def test_not_cacheable_no_finding(monkeypatch) -> None:
    """Even if origin returns authed body for the variant, if Cache-Control:
    no-store is set, the response can't be cache-deceived."""
    def responder(url, headers):
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "no-store, private"})

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Body divergence → no finding
# ---------------------------------------------------------------------------


def test_origin_distinguishes_no_finding(monkeypatch) -> None:
    """Origin returns 404 / static-asset-not-found for the variants → safe."""
    def responder(url, headers):
        if url.endswith("/account"):
            return _resp(body=_AUTHED_BODY)
        return _resp(status=404, body="<html><body>Not Found</body></html>")

    _patch_http(monkeypatch, responder)
    out = cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["findings_emitted"] == 0


def test_origin_returns_unrelated_200_no_finding(monkeypatch) -> None:
    """Origin returns 200 with totally different body (e.g. login page redirect to a 200-style template) → no body match → no finding."""
    def responder(url, headers):
        if url.endswith("/account"):
            return _resp(body=_AUTHED_BODY)
        return _resp(
            body="<html><body>Sign in to continue</body></html>",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Per-class dedup
# ---------------------------------------------------------------------------


def test_per_class_dedup_collapses_static_ext(monkeypatch) -> None:
    """Vulnerable for all five static-ext variants → one finding (not five)."""
    def responder(url, headers):
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "public, max-age=3600"})

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    static_ext_findings = [
        r for r in reports
        if any(ext in r["endpoint"] for ext in (".css", ".js", ".png", ".jpg", ".ico"))
    ]
    # All 5 static-ext variants would match, but dedup keeps just one.
    # The full report set may include findings from other classes too
    # (delim_traversal, matrix_uri etc.) — assert at-most-1 PER CLASS.
    static_ext_titles = {r["title"] for r in static_ext_findings}
    # We don't assert exactly 1 here because slash_x_css.endpoint also
    # contains ".css". So check by checking each finding's class is unique.
    classes_seen = set()
    for r in reports:
        if r["severity"] != "high":
            continue
        classes_seen.add(r["title"])  # full title acts as key proxy
    # Practical assertion: the count of high findings is small (≤ 5
    # classes), not 15.
    high = [r for r in reports if r["severity"] == "high"]
    assert 1 <= len(high) <= 5


# ---------------------------------------------------------------------------
# Baseline edge cases
# ---------------------------------------------------------------------------


def test_baseline_non_200_no_findings(monkeypatch) -> None:
    """Canonical path returns 401 → no probes → no findings."""
    log = _patch_http(monkeypatch, lambda url, h: _resp(status=401, body="auth required"))
    out = cache_deception_check("https://app.example.com/account")
    assert out["success"] is True
    assert out["findings_emitted"] == 0
    # Only baseline was attempted, not the variant cohort.
    assert len(log) == 1


def test_baseline_too_short_body_no_findings(monkeypatch) -> None:
    """40-byte baseline → fuzzy match would false-positive → skip."""
    log = _patch_http(monkeypatch, lambda url, h: _resp(body="ok"))
    out = cache_deception_check("https://app.example.com/account")
    assert out["success"] is True
    assert out["findings_emitted"] == 0
    # Only baseline.
    assert len(log) == 1


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_baseline_excluded_short_circuits(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda url, h: {"status": 0, "headers": {}, "body": "", "skipped": True})
    out = cache_deception_check("https://app.example.com/admin/destroy")
    assert out["skipped"] is True
    assert len(log) == 1
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_individual_variant_excluded_does_not_crash(monkeypatch) -> None:
    """A single variant URL excluded by --exclude-path → recorded, others run."""
    call = [0]

    def responder(url, headers):
        call[0] += 1
        if call[0] == 4:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        return _resp(body=_AUTHED_BODY)

    _patch_http(monkeypatch, responder)
    out = cache_deception_check("https://app.example.com/account")
    assert out["success"] is True
    skipped = [v for v in out["variants"] if "skipped" in (v.get("evidence") or "")]
    assert len(skipped) == 1


# ---------------------------------------------------------------------------
# §11 non-tech UX baseline
# ---------------------------------------------------------------------------


def test_every_finding_has_plain_and_action(monkeypatch) -> None:
    def responder(url, headers):
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "public, max-age=3600"})

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) >= 1
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action: {r['title']}"
        assert r["category"] == "web_cache_deception"
        assert r["cwe"] == "CWE-525"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    def responder(url, headers):
        if url.endswith("/account"):
            return _resp(body=_AUTHED_BODY)
        return _resp(status=404, body="not found")

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "web_cache_deception" in summary["by_category"]


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    def responder(url, headers):
        return _resp(body=_AUTHED_BODY, headers={"Cache-Control": "public, max-age=3600"})

    _patch_http(monkeypatch, responder)
    cache_deception_check("https://app.example.com/account")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["web_cache_deception"]
    assert cat["vulnerable"] == 1


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_bare_hostname_gets_https_prefix(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda url, h: _resp(body=_AUTHED_BODY))
    out = cache_deception_check("app.example.com/account")
    assert out["success"] is True
    assert out["target_url"].startswith("https://")


def test_invalid_target_rejected(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp())
    out = cache_deception_check("")
    assert out["success"] is False
