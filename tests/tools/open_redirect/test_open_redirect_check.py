"""Tests for open_redirect_check.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- URL normalization (bare host / scheme / invalid)
- Redirect-shaped param discovery (case-insensitive, lexicon match)
- Default-fallback param probing when no redirect params present
- Bypass cohort coverage (11 payloads, all classes present)
- Attacker host placement detection in:
  - 3xx Location header (high, direct https)
  - 3xx Refresh header (high)
  - 200 with `<meta http-equiv=refresh>` (medium)
  - 200 with `window.location =` JS (medium)
  - 3xx Location: `javascript:` (medium, capped)
  - 3xx Location: `data:` (medium, capped)
- False-positive guards:
  - attacker host substring in body but not in Location → no finding
  - attacker host appearing only in path or query of Location → no finding
  - relative paths in Location → no finding
- Subdomain match: `target.evil.example` matches; `target.com/evil.example` doesn't
- Per-param dedup: 11 payloads against vuln param → at most one high finding per param
- Multi-param probing
- extra_param_names plumbing
- attacker_host override
- Cluster-A skip handling
- Network error handling
- §11 UX baseline (description_plain + recommended_action on every finding)
- check.completed event emission
- preserve_others vs replace-query for default-fallback probing
"""

from __future__ import annotations

import sys
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.open_redirect.open_redirect_check  # noqa: F401

or_module = sys.modules["strix.tools.open_redirect.open_redirect_check"]
open_redirect_check = or_module.open_redirect_check


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
    tracer = Tracer("or-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_get(monkeypatch, responder):
    log: list[str] = []

    def fake(url, *, timeout=10.0):
        log.append(url)
        return responder(url)

    monkeypatch.setattr(or_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert open_redirect_check("")["success"] is False
    assert open_redirect_check("ftp://x.com/")["success"] is False


def test_bare_hostname_gets_https_prefix(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    out = open_redirect_check("app.example.com/login?next=/dash")
    assert out["target_url"].startswith("https://")
    assert out["target_host"] == "app.example.com"


# ---------------------------------------------------------------------------
# Param discovery
# ---------------------------------------------------------------------------


def test_discover_named_redirect_param() -> None:
    out = or_module._discover_redirect_params("https://x.com/login?next=/dash&csrf=abc")
    assert out == [("next", "/dash")]


def test_discover_case_insensitive() -> None:
    out = or_module._discover_redirect_params("https://x.com/login?Next=/dash&NEXT=/y")
    # Both match case-insensitively; the parser preserves original case.
    names = [n for n, _ in out]
    assert "Next" in names
    assert "NEXT" in names


def test_discover_no_redirect_params() -> None:
    out = or_module._discover_redirect_params("https://x.com/login?csrf=abc&user=ashish")
    assert out == []


def test_discover_no_query_string() -> None:
    out = or_module._discover_redirect_params("https://x.com/login")
    assert out == []


def test_discover_full_lexicon() -> None:
    """Sanity check that the lexicon catches the common names."""
    for name in ("next", "redirect", "redirect_uri", "return_url", "callback", "goto"):
        url = f"https://x.com/?{name}=/y"
        out = or_module._discover_redirect_params(url)
        assert out == [(name, "/y")], f"name `{name}` not detected"


# ---------------------------------------------------------------------------
# Default-fallback probing
# ---------------------------------------------------------------------------


def test_default_fallback_probes_six_names(monkeypatch) -> None:
    """No redirect params + no extras → probe the 6 default-fallback names."""
    _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    out = open_redirect_check("https://app.example.com/logout")
    assert set(out["probed_params"]) == {"next", "redirect", "url", "return", "goto", "dest"}


# ---------------------------------------------------------------------------
# Bypass cohort
# ---------------------------------------------------------------------------


def test_bypass_cohort_size() -> None:
    payloads = or_module._build_payloads("target.com", "evil.com")
    assert len(payloads) == 11


def test_bypass_cohort_classes() -> None:
    classes = {p["class_"] for p in or_module._build_payloads("t.com", "e.com")}
    assert "direct_scheme" in classes
    assert "protocol_relative" in classes
    assert "backslash" in classes
    assert "userinfo" in classes
    assert "suffix" in classes
    assert "query_bypass" in classes
    assert "encoded" in classes
    assert "js_scheme" in classes
    assert "data_scheme" in classes


def test_bypass_payloads_contain_attacker_host() -> None:
    payloads = or_module._build_payloads("target.com", "evil.example")
    # Every payload either contains the attacker host OR is a sentinel
    # scheme (javascript:, data:).
    for p in payloads:
        if p["class_"] in ("js_scheme", "data_scheme"):
            continue
        assert "evil.example" in p["payload"]


# ---------------------------------------------------------------------------
# Detection — Location header
# ---------------------------------------------------------------------------


def test_location_header_https_attacker_emits_high(monkeypatch) -> None:
    """Server reflects ?next=https://evil into 302 Location → high CWE-601."""
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        next_val = params.get("next", [""])[0]
        if next_val:
            return _resp(status=302, headers={"Location": next_val}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    out = open_redirect_check("https://app.example.com/login?next=/dash")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high, [r["title"] for r in reports]
    assert high[0]["cwe"] == "CWE-601"
    assert high[0]["category"] == "open_redirect"
    assert out["findings_emitted"] >= 1


def test_protocol_relative_attacker_emits_high(monkeypatch) -> None:
    """`?next=//evil.com` → Location: `//evil.com` → high."""
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v.startswith("//strix-"):
            return _resp(status=302, headers={"Location": v}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/login?next=/dash")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" for r in reports)


def test_userinfo_confusion_emits_high(monkeypatch) -> None:
    """`https://target.com@evil` → Location: same → high."""
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if "@strix-" in v:
            return _resp(status=302, headers={"Location": v}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/login?next=/dash")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" for r in reports)


# ---------------------------------------------------------------------------
# Detection — body redirects (medium)
# ---------------------------------------------------------------------------


def test_meta_refresh_emits_medium(monkeypatch) -> None:
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v and v.startswith("https://strix-"):
            return _resp(
                status=200,
                body=f'<html><head><meta http-equiv="refresh" content="0; url={v}"></head></html>',
            )
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium"]
    assert medium
    assert "meta" in medium[0]["title"].lower() or "refresh" in medium[0]["title"].lower()


def test_window_location_emits_medium(monkeypatch) -> None:
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v and v.startswith("https://strix-"):
            return _resp(
                status=200,
                body=f'<html><script>window.location = "{v}";</script></html>',
            )
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "medium" for r in reports)


def test_js_scheme_in_location_emits_medium(monkeypatch) -> None:
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v.startswith("javascript:"):
            return _resp(status=302, headers={"Location": v}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium"]
    assert medium
    assert "javascript" in medium[0]["title"].lower()


def test_data_scheme_in_location_emits_medium(monkeypatch) -> None:
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v.startswith("data:"):
            return _resp(status=302, headers={"Location": v}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any("data" in r["title"].lower() for r in reports)


# ---------------------------------------------------------------------------
# False-positive guards
# ---------------------------------------------------------------------------


def test_attacker_host_in_body_only_no_finding(monkeypatch) -> None:
    """Server echoes the param value into the page body but doesn't redirect.
    Echo alone is XSS territory, not open-redirect — no finding here."""
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        return _resp(status=200, body=f"<p>You clicked: {v}</p>")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_attacker_host_in_path_segment_no_finding(monkeypatch) -> None:
    """Location: /strix-evil.example/x — attacker host is a PATH on
    target, not the netloc. Should not fire."""
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v:
            return _resp(status=302, headers={"Location": f"/strix-{v}/x"}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_relative_path_location_no_finding(monkeypatch) -> None:
    """Location: /dashboard — same-origin redirect. No finding."""
    def responder(url):
        return _resp(status=302, headers={"Location": "/dashboard"})

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_clean_app_no_findings(monkeypatch) -> None:
    """App ignores ?next= and just returns 200 with normal page."""
    _patch_get(monkeypatch, lambda url: _resp(body="<html>welcome</html>"))
    out = open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Subdomain matching
# ---------------------------------------------------------------------------


def test_location_redirects_to_exact_match() -> None:
    assert or_module._location_redirects_to("https://evil.example/x", "evil.example") is True


def test_location_redirects_to_subdomain_match() -> None:
    assert or_module._location_redirects_to("https://strix-abc.evil.example/x", "strix-abc.evil.example") is True


def test_location_does_not_match_path_segment() -> None:
    """`/evil.example` is a path on the original origin, not the netloc."""
    assert or_module._location_redirects_to("/evil.example/x", "evil.example") is False


def test_location_relative_path_no_match() -> None:
    assert or_module._location_redirects_to("/dashboard", "evil.example") is False


def test_location_protocol_relative_match() -> None:
    assert or_module._location_redirects_to("//evil.example/x", "evil.example") is True


def test_location_userinfo_strip() -> None:
    """`https://target.com@evil.example/` netloc IS evil.example."""
    assert or_module._location_redirects_to("https://target.com@evil.example/x", "evil.example") is True


def test_location_encoded_slash_match() -> None:
    """`https:%2f%2fevil.example` decoded netloc is evil.example."""
    assert or_module._location_redirects_to("https:%2f%2fevil.example", "evil.example") is True


# ---------------------------------------------------------------------------
# Per-param dedup
# ---------------------------------------------------------------------------


def test_per_param_dedup_collapses_payloads(monkeypatch) -> None:
    """11 vulnerable payloads on one param → at most ONE high finding."""
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v and "strix-" in v:
            return _resp(status=302, headers={"Location": v if v.startswith(("http", "//")) else f"https://{v}"}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high_per_param = [r for r in reports if r["severity"] == "high"]
    # All 11 high-eligible payloads collapse to 1.
    assert len(high_per_param) <= 1


# ---------------------------------------------------------------------------
# Multi-param probing
# ---------------------------------------------------------------------------


def test_multi_param_each_probed(monkeypatch) -> None:
    log = _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    out = open_redirect_check("https://app.example.com/?next=/a&redirect=/b&csrf=abc")
    # `next` and `redirect` matched; `csrf` filtered out.
    assert set(out["probed_params"]) == {"next", "redirect"}
    # Each param × 11 payloads = 22 probes.
    assert len(log) == 22


# ---------------------------------------------------------------------------
# extra_param_names plumbing
# ---------------------------------------------------------------------------


def test_extra_param_names_get_probed(monkeypatch) -> None:
    log = _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    out = open_redirect_check(
        "https://app.example.com/?next=/x",
        extra_param_names=["myredirect", "forwardto"],
    )
    assert set(out["probed_params"]) == {"next", "myredirect", "forwardto"}
    # 3 params × 11 payloads = 33 probes.
    assert len(log) == 33


# ---------------------------------------------------------------------------
# attacker_host override
# ---------------------------------------------------------------------------


def test_attacker_host_override(monkeypatch) -> None:
    log = _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    out = open_redirect_check(
        "https://app.example.com/?next=/x",
        attacker_host="burpcollab.test",
    )
    assert out["attacker_host"].endswith(".burpcollab.test")
    # At least one probe URL contains the override host.
    assert any("burpcollab.test" in u for u in log)


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_skipped_response_does_not_crash(monkeypatch) -> None:
    """All probes return skipped → no findings, no crash."""
    _patch_get(monkeypatch, lambda url: {"status": 0, "headers": {}, "body": "", "skipped": True})
    out = open_redirect_check("https://app.example.com/?next=/x")
    assert out["success"] is True
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_network_error_does_not_crash(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 0, "headers": {}, "body": "", "error": "conn refused"})
    out = open_redirect_check("https://app.example.com/?next=/x")
    assert out["success"] is True
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v and v.startswith(("http", "//")):
            return _resp(status=302, headers={"Location": v}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "open_redirect"
        assert r["cwe"] == "CWE-601"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check event
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    open_redirect_check("https://app.example.com/?next=/x")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "open_redirect" in summary["by_category"]


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    def responder(url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        v = params.get("next", [""])[0]
        if v and v.startswith(("http", "//")):
            return _resp(status=302, headers={"Location": v}, body="")
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    open_redirect_check("https://app.example.com/?next=/x")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["open_redirect"]
    assert cat["vulnerable"] == 1


# ---------------------------------------------------------------------------
# preserve_others vs replace-query
# ---------------------------------------------------------------------------


def test_preserve_others_when_param_in_original(monkeypatch) -> None:
    """When `next` was already in the URL alongside other params, those
    others should round-trip into every probe URL."""
    log = _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    open_redirect_check("https://app.example.com/?next=/x&csrf=abc&user=u")
    # Every probe URL should contain `csrf=abc&user=u` (in some order)
    # because `next` was discovered in-place; preserve_others=True.
    for u in log:
        params = parse_qs(urlparse(u).query)
        assert params.get("csrf") == ["abc"]
        assert params.get("user") == ["u"]


def test_replace_query_for_default_fallback(monkeypatch) -> None:
    """Default-fallback probing on a URL without redirect params drops
    other query params (preserve_others=False)."""
    log = _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    open_redirect_check("https://app.example.com/?csrf=abc")
    # Every probe URL should NOT contain `csrf=abc` (replaced).
    for u in log:
        params = parse_qs(urlparse(u).query)
        assert "csrf" not in params


# ---------------------------------------------------------------------------
# Sanity / smoke
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    out = open_redirect_check("https://app.example.com/?next=/x")
    for k in ("success", "target_url", "target_host", "attacker_host",
              "probed_params", "probes", "findings_emitted"):
        assert k in out


def test_attacker_host_is_per_run_unique(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _resp(body="ok"))
    a = open_redirect_check("https://app.example.com/?next=/x")
    b = open_redirect_check("https://app.example.com/?next=/x")
    assert a["attacker_host"] != b["attacker_host"]
    assert a["attacker_host"].startswith("strix-")
    assert b["attacker_host"].startswith("strix-")
