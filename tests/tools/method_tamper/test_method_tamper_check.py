"""Tests for method_tamper_check.

Hermetic — `_http_request` is monkeypatched. Tests cover:

- URL normalization (bare host, scheme, invalid)
- Default cohort runs OPTIONS / TRACE / HEAD / PROPFIND only
- Destructive cohort skipped by default; runs when include_destructive=True
- OPTIONS Allow-header parsing
- WebDAV verb in OPTIONS Allow → medium webdav_exposure
- WebDAV PROPFIND 207 → medium webdav_exposure (deduped against OPTIONS path)
- TRACE with header reflection → medium xst
- TRACE without reflection or non-200 → no finding
- OPTIONS reveals destructive methods → low method_disclosure
- HEAD 405/501 vs GET 200 → low method_disclosure
- Direct PUT 2xx (when destructive enabled) → high improper_authorization
- X-HTTP-Method-Override 2xx → high improper_authorization (override class)
- _method form param 2xx → high (form_method class)
- Per-class destructive dedup (3 direct verbs → 1 finding)
- 405 on destructive method → no finding (correctly rejected)
- Baseline GET non-2xx → graceful inconclusive, no probes
- --exclude-path on baseline → graceful no-op
- §11 UX baseline (description_plain + recommended_action + needs_review)
- Check.completed events
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.method_tamper.method_tamper_check  # noqa: F401

mt_module = sys.modules["strix.tools.method_tamper.method_tamper_check"]
method_tamper_check = mt_module.method_tamper_check


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
    tracer = Tracer("mt-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_request(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(method, url, *, headers=None, body="", timeout=10.0):
        kwargs = {
            "method": method, "url": url,
            "headers": dict(headers or {}), "body": body,
        }
        log.append(kwargs)
        return responder(method, url, kwargs)

    monkeypatch.setattr(mt_module, "_http_request", fake)
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
    assert method_tamper_check("")["success"] is False
    assert method_tamper_check("ftp://x.com/")["success"] is False


def test_bare_hostname_gets_https(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok") if m == "GET" else _resp(status=405))
    out = method_tamper_check("app.example.com/api")
    assert out["target_url"].startswith("https://")
    assert out["target_host"] == "app.example.com"


# ---------------------------------------------------------------------------
# Default cohort — only read-only verbs
# ---------------------------------------------------------------------------


def test_default_cohort_no_destructive(monkeypatch) -> None:
    """When include_destructive=False (default), only GET/OPTIONS/TRACE/
    HEAD/PROPFIND are dispatched."""
    log = _patch_request(monkeypatch, lambda m, u, k: _resp(status=200 if m == "GET" else 405))
    out = method_tamper_check("https://app.example.com/api")
    methods = [entry["method"] for entry in log]
    assert "GET" in methods
    assert "OPTIONS" in methods
    assert "TRACE" in methods
    assert "HEAD" in methods
    assert "PROPFIND" in methods
    # No destructive verbs.
    assert "PUT" not in methods
    assert "PATCH" not in methods
    assert "DELETE" not in methods
    assert out["include_destructive"] is False


def test_destructive_cohort_runs_when_enabled(monkeypatch) -> None:
    log = _patch_request(monkeypatch, lambda m, u, k: _resp(status=200) if m == "GET" else _resp(status=405))
    method_tamper_check("https://app.example.com/api", include_destructive=True)
    methods = {entry["method"] for entry in log}
    # Destructive methods now present.
    assert "PUT" in methods
    assert "PATCH" in methods
    assert "DELETE" in methods
    # Plus 3 POST-with-override-header variants and 2 POST-with-_method-form.
    post_calls = [e for e in log if e["method"] == "POST"]
    assert len(post_calls) >= 5


# ---------------------------------------------------------------------------
# OPTIONS Allow-header parsing
# ---------------------------------------------------------------------------


def test_parse_allow_methods_basic() -> None:
    assert mt_module._parse_allow_methods("GET, POST, OPTIONS") == {"GET", "POST", "OPTIONS"}


def test_parse_allow_methods_case_normalize() -> None:
    assert mt_module._parse_allow_methods("get, post") == {"GET", "POST"}


def test_parse_allow_methods_empty() -> None:
    assert mt_module._parse_allow_methods("") == set()
    assert mt_module._parse_allow_methods(None) == set()


# ---------------------------------------------------------------------------
# WebDAV — OPTIONS Allow header
# ---------------------------------------------------------------------------


def test_webdav_in_options_emits_medium(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(
                status=200,
                headers={"Allow": "GET, OPTIONS, PROPFIND, MKCOL, MOVE"},
            )
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/files/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    webdav = [r for r in reports if r["category"] == "webdav_exposure"]
    assert webdav
    assert webdav[0]["severity"] == "medium"
    assert webdav[0]["cwe"] == "CWE-200"


def test_webdav_propfind_207_emits_medium(monkeypatch) -> None:
    """OPTIONS doesn't advertise WebDAV but PROPFIND returns 207 → medium."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        if method == "PROPFIND":
            return _resp(
                status=207,
                headers={"Content-Type": "application/xml"},
                body="<?xml version=\"1.0\"?><multistatus />",
            )
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/files/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    webdav = [r for r in reports if r["category"] == "webdav_exposure"]
    assert webdav
    assert "PROPFIND" in webdav[0]["title"]


def test_webdav_options_and_propfind_dedup_to_one(monkeypatch) -> None:
    """When BOTH the OPTIONS-advertise path and the PROPFIND-207 path
    fire, the tool emits only ONE WebDAV finding (not two)."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS, PROPFIND, MKCOL"})
        if method == "PROPFIND":
            return _resp(status=207, headers={"Content-Type": "application/xml"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/files/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    webdav = [r for r in reports if r["category"] == "webdav_exposure"]
    assert len(webdav) == 1


# ---------------------------------------------------------------------------
# TRACE / XST
# ---------------------------------------------------------------------------


def test_trace_with_reflection_emits_medium(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "TRACE":
            # Reflect the X-Strix-Trace-* header back in the body.
            marker = next(
                (h for h in k["headers"] if h.lower().startswith("x-strix-trace-")),
                None,
            )
            body = f"TRACE / HTTP/1.1\r\n{marker}: echo-this-back\r\n" if marker else "TRACE / HTTP/1.1\r\n"
            return _resp(status=200, body=body)
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS, TRACE"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    xst = [r for r in reports if r["category"] == "xst"]
    assert xst
    assert xst[0]["severity"] == "medium"
    assert "TRACE" in xst[0]["title"]


def test_trace_without_reflection_no_finding(monkeypatch) -> None:
    """TRACE returns 200 but DOESN'T reflect the marker → no finding."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "TRACE":
            return _resp(status=200, body="TRACE accepted but no reflection")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert not [r for r in reports if r["category"] == "xst"]


def test_trace_404_no_finding(monkeypatch) -> None:
    """TRACE returns 405 → no XST."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert not [r for r in reports if r["category"] == "xst"]


# ---------------------------------------------------------------------------
# OPTIONS reveals destructive methods
# ---------------------------------------------------------------------------


def test_options_reveals_modifying_methods_emits_low(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/api/users/123")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    low = [r for r in reports if r["severity"] == "low" and r["category"] == "method_disclosure"]
    assert low


def test_options_only_safe_methods_no_method_disclosure_from_options(monkeypatch) -> None:
    """OPTIONS advertises GET/HEAD/OPTIONS only → no method_disclosure
    from the OPTIONS path (HEAD returning 200 prevents the
    head_asymmetry method_disclosure path too)."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "HEAD":
            return _resp(status=200)
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, HEAD, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    md = [r for r in reports if r["category"] == "method_disclosure"]
    assert md == []


# ---------------------------------------------------------------------------
# HEAD asymmetry
# ---------------------------------------------------------------------------


def test_head_405_vs_get_200_emits_low(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "HEAD":
            return _resp(status=405)
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    head_findings = [r for r in reports if "HEAD" in r["title"]]
    assert head_findings
    assert head_findings[0]["severity"] == "low"


def test_head_200_no_finding(monkeypatch) -> None:
    """HEAD returns 200 → no asymmetry → no finding."""
    def responder(method, url, k):
        if method in ("GET", "HEAD"):
            return _resp(status=200, body="ok" if method == "GET" else "")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, HEAD, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert not [r for r in reports if "HEAD" in r["title"]]


# ---------------------------------------------------------------------------
# Destructive cohort — direct verbs
# ---------------------------------------------------------------------------


def test_direct_put_2xx_emits_high(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method in ("PUT", "PATCH", "DELETE"):
            return _resp(status=200, body="ok")  # all accepted
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    out = method_tamper_check(
        "https://app.example.com/api/users/123",
        include_destructive=True,
    )
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high
    assert high[0]["cwe"] == "CWE-285"
    assert high[0]["category"] == "improper_authorization"
    assert out["findings_emitted"] >= 1


def test_direct_destructive_cohort_dedup(monkeypatch) -> None:
    """Three direct verbs all accepted → ONE finding (per-class dedup)."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method in ("PUT", "PATCH", "DELETE"):
            return _resp(status=200, body="accepted")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/api/users/123", include_destructive=True)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    direct_findings = [r for r in reports if "Destructive verb" in r["title"]]
    assert len(direct_findings) == 1


def test_destructive_405_no_finding(monkeypatch) -> None:
    """Direct PUT/PATCH/DELETE all return 405 → no finding."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/", include_destructive=True)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high == []


# ---------------------------------------------------------------------------
# Destructive cohort — override headers
# ---------------------------------------------------------------------------


def test_override_header_2xx_emits_high(monkeypatch) -> None:
    """POST with X-HTTP-Method-Override returns 2xx → high (override class)."""
    def responder(method, url, k):
        headers_ci = {h.lower(): v for h, v in k["headers"].items()}
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "POST" and "x-http-method-override" in headers_ci:
            return _resp(status=200, body="override accepted")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/api/", include_destructive=True)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    overrides = [r for r in reports if "Method override" in r["title"] and "X-HTTP-Method-Override" in r["title"]]
    assert overrides
    assert overrides[0]["severity"] == "high"


def test_form_method_2xx_emits_high(monkeypatch) -> None:
    """POST with _method=DELETE form param returns 2xx → high (form_method class)."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "POST" and "_method=" in k["body"]:
            return _resp(status=200, body="form method accepted")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/api/", include_destructive=True)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    fm = [r for r in reports if "form `_method` param" in r["title"]]
    assert fm
    assert fm[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Baseline edge cases
# ---------------------------------------------------------------------------


def test_baseline_non_2xx_skips_probes(monkeypatch) -> None:
    log = _patch_request(monkeypatch, lambda m, u, k: _resp(status=401))
    out = method_tamper_check("https://app.example.com/")
    # Only baseline GET attempted; no probes.
    assert len(log) == 1
    assert out["findings_emitted"] == 0


def test_baseline_excluded_short_circuits(monkeypatch) -> None:
    log = _patch_request(monkeypatch, lambda m, u, k: {"status": 0, "headers": {}, "body": "", "skipped": True})
    out = method_tamper_check("https://app.example.com/")
    assert len(log) == 1
    assert out["baseline"]["skipped"] is True
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    """Hit multiple finding types and confirm all carry plain + action."""
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS, PROPFIND, MKCOL"})
        if method == "TRACE":
            marker = next((h for h in k["headers"] if h.lower().startswith("x-strix-trace-")), None)
            return _resp(status=200, body=f"{marker}: echo-this-back" if marker else "")
        if method == "HEAD":
            return _resp(status=405)
        if method in ("PUT", "PATCH", "DELETE"):
            return _resp(status=200, body="ok")
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/api/", include_destructive=True)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) >= 3
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, HEAD, OPTIONS"})
        if method == "HEAD":
            return _resp(status=200)
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["method_tamper"]
    assert cat.get("not_vulnerable", 0) == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, PROPFIND, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    method_tamper_check("https://app.example.com/files/")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["method_tamper"]
    assert cat.get("vulnerable", 0) == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=200 if m == "GET" else 405))
    out = method_tamper_check("https://app.example.com/")
    for k in ("success", "target_url", "target_host", "include_destructive",
              "baseline", "options_advertised", "probes", "findings_emitted"):
        assert k in out


def test_options_advertised_populated(monkeypatch) -> None:
    def responder(method, url, k):
        if method == "GET":
            return _resp(status=200, body="ok")
        if method == "OPTIONS":
            return _resp(status=200, headers={"Allow": "GET, POST, OPTIONS"})
        return _resp(status=405)

    _patch_request(monkeypatch, responder)
    out = method_tamper_check("https://app.example.com/")
    assert "GET" in out["options_advertised"]
    assert "POST" in out["options_advertised"]
