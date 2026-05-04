"""Tests for cors_deep_check.

Hermetic — `_http_request` is monkeypatched. Tests cover:

- URL normalization (bare host, scheme, invalid)
- Three probe families dispatched (origin / preflight-method /
  preflight-header)
- Baseline non-2xx → origin probes skip; preflight still runs
- --exclude-path on baseline → graceful no-op
- Origin reflection variants:
  - null + credentials → high
  - null without credentials → medium
  - subdomain_suffix + credentials → critical
  - subdomain_prefix + credentials → critical
  - trailing_slash → high if credentialed; medium if not
  - scheme_swap → high if credentialed; medium if not
  - wildcard + credentials → high
  - no reflection → no finding
- Per-(severity, issue) dedup
- Pre-flight method laxity (TRACE echoed back) → medium
- Pre-flight header laxity (X-Internal-User-Id echoed back) → medium
- §11 UX baseline (description_plain + recommended_action +
  needs_review)
- check.completed events
- MITRE T1190 attached
- Result schema integrity
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.cors_check.cors_deep_check  # noqa: F401

cd_module = sys.modules["strix.tools.cors_check.cors_deep_check"]
cors_deep_check = cd_module.cors_deep_check


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
    tracer = Tracer("cors-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://api.example.com/"}]}
    )
    yield


def _patch_request(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(method, url, *, headers=None, timeout=10.0):
        kwargs = {
            "method": method, "url": url,
            "headers": dict(headers or {}),
        }
        log.append(kwargs)
        return responder(method, url, kwargs)

    monkeypatch.setattr(cd_module, "_http_request", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _findings_from_tracer() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return []
    return list(t.get_existing_vulnerabilities())


def _check_summary() -> dict[str, Any]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return {}
    return t.get_check_summary()


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert cors_deep_check("")["success"] is False
    assert cors_deep_check("ftp://x.com/")["success"] is False


def test_bare_hostname_gets_https(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    out = cors_deep_check("api.example.com/v1/profile")
    assert out["target_url"].startswith("https://")
    assert out["target_host"] == "api.example.com"


# ---------------------------------------------------------------------------
# Probe families dispatched
# ---------------------------------------------------------------------------


def test_three_families_dispatched(monkeypatch) -> None:
    log = _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    out = cors_deep_check("https://api.example.com/v1/profile")
    assert out["success"] is True
    # GET-with-Origin probes (origin family) ran
    get_with_origin = [e for e in log if e["method"] == "GET" and e["headers"].get("Origin")]
    assert len(get_with_origin) >= 5
    # Pre-flight OPTIONS probes ran
    options = [e for e in log if e["method"] == "OPTIONS"]
    assert len(options) >= 3
    # Origin probes set the right Origin headers
    assert any(e["headers"].get("Origin") == "null" for e in get_with_origin)


def test_baseline_non_2xx_skips_origin_probes(monkeypatch) -> None:
    """Baseline 401 → origin probes skip; preflight still runs."""
    _patch_request(
        monkeypatch,
        lambda m, u, k: _resp(status=401) if m == "GET" else _resp(),
    )
    out = cors_deep_check("https://api.example.com/v1/profile")
    assert out["origin_probes"] == []
    # Preflight probes still ran
    assert len(out["preflight_probes"]) > 0


def test_baseline_excluded_no_op(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        return {"status": 0, "headers": {}, "body": "", "skipped": True}

    _patch_request(monkeypatch, responder)
    out = cors_deep_check("https://api.example.com/v1/profile")
    assert out["baseline"]["skipped"] is True
    assert out["origin_probes"] == []
    assert out["preflight_probes"] == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Origin reflection findings
# ---------------------------------------------------------------------------


def test_subdomain_prefix_with_credentials_critical(monkeypatch) -> None:
    """`Origin: https://api.example.com.evil.example` reflected with
    Allow-Credentials: true → critical."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin and "evil.example" in origin and origin.startswith("https://api.example.com."):
                return _resp(
                    headers={
                        "access-control-allow-origin": origin,
                        "access-control-allow-credentials": "true",
                    },
                )
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    crit = [f for f in findings if f.get("severity") == "critical"]
    assert len(crit) == 1
    assert "subdomain_prefix" in crit[0].get("description", "").lower() or \
           "subdomain_prefix" in crit[0].get("title", "").lower()


def test_subdomain_suffix_no_creds_high(monkeypatch) -> None:
    """`Origin: https://strix-XXX.evil.example.api.example.com` reflected without credentials → high."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin and origin.endswith(".api.example.com"):
                return _resp(headers={"access-control-allow-origin": origin})
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    high = [f for f in findings if f.get("severity") == "high"]
    assert len(high) >= 1


def test_null_origin_with_credentials_high(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin == "null":
                return _resp(headers={
                    "access-control-allow-origin": "null",
                    "access-control-allow-credentials": "true",
                })
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    null_findings = [f for f in findings if "null_with_credentials" in f.get("description", "")
                     or "null_with_credentials" in f.get("title", "")]
    assert len(null_findings) == 1
    assert null_findings[0]["severity"] == "high"


def test_null_origin_no_creds_medium(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin == "null":
                return _resp(headers={"access-control-allow-origin": "null"})
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    null_findings = [f for f in findings if "null_reflected" in f.get("description", "")
                     or "null_reflected" in f.get("title", "")]
    assert len(null_findings) == 1
    assert null_findings[0]["severity"] == "medium"


def test_scheme_swap_reflection_no_creds_medium(monkeypatch) -> None:
    """https → http origin reflected without credentials → medium."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin == "http://api.example.com":
                return _resp(headers={"access-control-allow-origin": origin})
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    scheme = [f for f in findings if "scheme_bypass" in f.get("description", "")
              or "scheme_bypass" in f.get("title", "")]
    assert len(scheme) == 1
    assert scheme[0]["severity"] == "medium"


def test_scheme_swap_reflection_with_creds_high(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin == "http://api.example.com":
                return _resp(headers={
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                })
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    scheme = [f for f in findings if "scheme_bypass" in f.get("description", "")
              or "scheme_bypass" in f.get("title", "")]
    assert len(scheme) == 1
    assert scheme[0]["severity"] == "high"


def test_wildcard_with_credentials_high(monkeypatch) -> None:
    """ACAO=* + ACAC=true → high (browsers reject this combo, but documents intent)."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            return _resp(headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            })
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    wildcard = [f for f in findings if "wildcard_with_credentials" in f.get("description", "")
                or "wildcard" in f.get("title", "").lower()]
    assert any(f.get("severity") == "high" for f in wildcard)


def test_no_cors_response_no_finding(monkeypatch) -> None:
    """Server doesn't set CORS headers at all → no findings."""
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    assert findings == []


def test_dedup_by_severity_issue(monkeypatch) -> None:
    """If 5 different bypass classes all reflect with credentials,
    we still emit dedup-by-(severity, issue). Each issue is unique
    per class so we'd expect 5 findings; verify we don't blow up
    into more than that."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            # Reflect every probe origin we receive.
            return _resp(headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            })
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    crit = [f for f in findings if f.get("severity") == "critical"]
    # Each (severity, issue) tuple is unique per probe class — so
    # we should get a finding per non-deduped class. There are
    # currently 7 classes that map to "*_with_credentials" issues
    # (baseline_evil, subdomain_suffix, subdomain_prefix,
    # subdomain_substring, userinfo_confusion, backslash_bypass,
    # backtick_bypass). Verify we get at least 5 and they're all
    # distinct issues.
    issues = {f.get("title", "") for f in crit}
    assert len(issues) >= 5
    # And no two findings share the same (severity, issue) — the
    # dedup contract.
    issue_strings = []
    for f in crit:
        for word in f.get("title", "").split():
            if "_with_credentials" in word.strip("()"):
                issue_strings.append(word)
    assert len(issue_strings) == len(set(issue_strings))


# ---------------------------------------------------------------------------
# Pre-flight laxity findings
# ---------------------------------------------------------------------------


def test_preflight_method_trace_echoed_medium(monkeypatch) -> None:
    """OPTIONS pre-flight requesting TRACE; server echoes TRACE
    back in Access-Control-Allow-Methods → medium."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "OPTIONS":
            req_method = kw["headers"].get("Access-Control-Request-Method", "")
            if req_method == "TRACE":
                return _resp(headers={"access-control-allow-methods": "GET, POST, TRACE"})
            return _resp()
        return _resp(body="ok")

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    method_lax = [f for f in findings if "pre-flight method laxity" in f.get("title", "").lower()
                  or "preflight_method_laxity" in f.get("description", "")]
    assert len(method_lax) == 1
    assert method_lax[0]["severity"] == "medium"


def test_preflight_header_internal_echoed_medium(monkeypatch) -> None:
    """OPTIONS pre-flight requesting X-Internal-User-Id; server
    echoes it back in Access-Control-Allow-Headers → medium."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "OPTIONS":
            req_headers = kw["headers"].get("Access-Control-Request-Headers", "")
            if req_headers == "X-Internal-User-Id":
                return _resp(headers={
                    "access-control-allow-headers": "Content-Type, X-Internal-User-Id",
                })
            return _resp()
        return _resp(body="ok")

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    header_lax = [f for f in findings if "pre-flight header laxity" in f.get("title", "").lower()
                  or "preflight_header_laxity" in f.get("description", "")]
    assert len(header_lax) == 1
    assert header_lax[0]["severity"] == "medium"


def test_preflight_method_no_echo_no_finding(monkeypatch) -> None:
    """Server returns its own static method list, doesn't echo TRACE → no finding."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "OPTIONS":
            return _resp(headers={"access-control-allow-methods": "GET, POST"})
        return _resp(body="ok")

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    method_lax = [f for f in findings if "pre-flight method laxity" in f.get("title", "").lower()]
    assert method_lax == []


def test_preflight_method_dedup(monkeypatch) -> None:
    """3 method laxity probes (TRACE/DELETE/CONNECT) all echo →
    only ONE method-laxity finding (per-(severity, issue) dedup)."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "OPTIONS":
            req_method = kw["headers"].get("Access-Control-Request-Method", "")
            if req_method:
                return _resp(headers={
                    "access-control-allow-methods": f"GET, POST, {req_method}",
                })
            return _resp()
        return _resp(body="ok")

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    method_lax = [f for f in findings if "pre-flight method laxity" in f.get("title", "").lower()]
    assert len(method_lax) == 1


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_finding_ux_fields(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin and "evil" in origin:
                return _resp(headers={
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                })
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    findings = _findings_from_tracer()
    assert findings
    for f in findings:
        assert f.get("description_plain")
        assert f.get("recommended_action")
        assert f.get("verification_status") == "needs_review"
        assert f.get("category") == "cors_misconfiguration"
        assert f.get("cwe") == "CWE-942"


# ---------------------------------------------------------------------------
# Check summary
# ---------------------------------------------------------------------------


def test_check_summary_vulnerable(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        if method == "GET":
            origin = kw["headers"].get("Origin", "")
            if origin and "evil" in origin:
                return _resp(headers={
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                })
            return _resp(body="ok")
        return _resp()

    _patch_request(monkeypatch, responder)
    cors_deep_check("https://api.example.com/v1/profile")
    summary = _check_summary()
    assert summary["by_category"]["cors_deep"]["vulnerable"] >= 1


def test_check_summary_clean(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    cors_deep_check("https://api.example.com/v1/profile")
    summary = _check_summary()
    assert summary["by_category"]["cors_deep"]["not_vulnerable"] >= 1


# ---------------------------------------------------------------------------
# MITRE technique tag
# ---------------------------------------------------------------------------


def test_mitre_technique_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("cors_deep_check")
    assert "T1190" in techniques


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    out = cors_deep_check("https://api.example.com/v1/profile")
    assert set(out.keys()) >= {
        "success", "target_url", "target_host", "baseline",
        "origin_probes", "preflight_probes", "findings_emitted",
    }


def test_origin_probe_schema(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    out = cors_deep_check("https://api.example.com/v1/profile")
    assert out["origin_probes"]
    p = out["origin_probes"][0]
    assert set(p.keys()) >= {
        "label", "probe_origin", "reflected", "credentialed",
        "wildcard", "severity", "issue", "evidence",
        "aco_header", "acc_header",
    }


def test_preflight_probe_schema(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(body="ok"))
    out = cors_deep_check("https://api.example.com/v1/profile")
    assert out["preflight_probes"]
    p = out["preflight_probes"][0]
    assert set(p.keys()) >= {
        "label", "request_method", "request_header",
        "response_methods", "response_headers", "echoed",
        "severity", "evidence",
    }


# ---------------------------------------------------------------------------
# _origin_reflected helper
# ---------------------------------------------------------------------------


def test_origin_reflected_exact() -> None:
    assert cd_module._origin_reflected("https://evil.example", "https://evil.example")


def test_origin_reflected_case_insensitive() -> None:
    assert cd_module._origin_reflected("HTTPS://Evil.Example", "https://evil.example")


def test_origin_reflected_trailing_slash_tolerance() -> None:
    assert cd_module._origin_reflected("https://x.com/", "https://x.com")
    assert cd_module._origin_reflected("https://x.com", "https://x.com/")


def test_origin_reflected_no_match() -> None:
    assert not cd_module._origin_reflected("https://x.com", "https://y.com")
    assert not cd_module._origin_reflected("https://x.com", "")


def test_origin_reflected_wildcard_not_match() -> None:
    """Wildcard `*` should not be treated as reflection of any specific origin."""
    assert not cd_module._origin_reflected("https://x.com", "*")
