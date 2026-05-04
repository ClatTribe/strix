"""Tests for debug_endpoint_check.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- URL normalization (bare host, scheme, invalid)
- Three probe families dispatched (parametric / framework / error)
- skip_framework_pages → no host-root crawl
- Baseline non-2xx → only framework family runs
- --exclude-path on baseline → graceful no-op
- Parametric debug toggle with stack trace + debug header → high
- Parametric debug toggle with stack trace only → medium
- Parametric debug toggle with debug header only → medium
- Parametric debug toggle no change → no finding
- Per-family parametric dedup (only one finding even if multiple toggles match)
- Framework page (Spring actuator JSON) → medium framework finding
- Framework page (Symfony profiler) → medium framework finding
- Framework page (Apache server-status) → medium
- Framework page 404 → no finding
- Framework page dedup by label (multiple actuator paths → 1 finding)
- Error-trigger payload bleeds new trace → low finding
- Error-trigger no new trace → no finding
- Per-family error-trigger dedup
- §11 UX baseline (description_plain + recommended_action + needs_review)
- check.completed events
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


import strix.tools.debug_endpoint.debug_endpoint_check  # noqa: F401

de_module = sys.modules["strix.tools.debug_endpoint.debug_endpoint_check"]
debug_endpoint_check = de_module.debug_endpoint_check


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
    tracer = Tracer("debug-bleed-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com/"}]}
    )
    yield


def _patch_get(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=10.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(de_module, "_http_get", fake)
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
    assert debug_endpoint_check("")["success"] is False
    assert debug_endpoint_check("ftp://x.com/")["success"] is False
    assert debug_endpoint_check("not-a-url-at-all-but-still")["success"] is True
    # bare host gets https
    # We don't probe it (no monkeypatch); but normalization happens.


def test_bare_hostname_gets_https(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    out = debug_endpoint_check("app.example.com/api")
    assert out["target_url"].startswith("https://")
    assert out["target_host"] == "app.example.com"


# ---------------------------------------------------------------------------
# Probe families dispatched
# ---------------------------------------------------------------------------


def test_three_families_dispatched(monkeypatch) -> None:
    """All three families run when baseline is 2xx."""
    log = _patch_get(monkeypatch, lambda u, h: _resp(body="ok"))
    out = debug_endpoint_check("https://app.example.com/api/users")
    assert out["success"] is True
    # parametric_probes always run
    assert len(out["parametric_probes"]) > 0
    # framework_probes always run by default
    assert len(out["framework_probes"]) > 0
    # error_probes run when baseline 2xx
    assert len(out["error_probes"]) > 0
    # Each family hits at least its respective URL prefixes
    urls = [entry["url"] for entry in log]
    assert any("debug=1" in u for u in urls)
    assert any("/_profiler/" in u for u in urls)
    assert any("strix_probe=" in u for u in urls)


def test_skip_framework_pages_disables_host_root_crawl(monkeypatch) -> None:
    log = _patch_get(monkeypatch, lambda u, h: _resp(body="ok"))
    out = debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    assert out["framework_probes"] == []
    urls = [entry["url"] for entry in log]
    assert not any("/_profiler/" in u for u in urls)


def test_baseline_non_2xx_skips_parametric_and_error(monkeypatch) -> None:
    """If baseline GET is 404, parametric + error families skip; framework still runs."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if url == "https://app.example.com/api/users":
            return _resp(status=404, body="not found")
        return _resp(status=404, body="not found")

    _patch_get(monkeypatch, responder)
    out = debug_endpoint_check("https://app.example.com/api/users")
    assert out["parametric_probes"] == []
    assert out["error_probes"] == []
    # Framework probes still ran
    assert len(out["framework_probes"]) > 0


def test_baseline_excluded_skips_parametric_and_error(monkeypatch) -> None:
    """If baseline is excluded by --exclude-path, parametric + error skip."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if url == "https://app.example.com/api/users":
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        return _resp(body="ok")

    _patch_get(monkeypatch, responder)
    out = debug_endpoint_check("https://app.example.com/api/users")
    assert out["baseline"]["skipped"] is True
    assert out["parametric_probes"] == []
    assert out["error_probes"] == []


# ---------------------------------------------------------------------------
# Parametric toggle findings
# ---------------------------------------------------------------------------


def test_parametric_full_debug_high(monkeypatch) -> None:
    """Stack trace + debug header → high CWE-200."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "debug=1" in url:
            return _resp(
                body="Traceback (most recent call last):\n  File '/app/views.py', line 42",
                headers={"x-debug-token": "abc123"},
            )
        if "/_profiler/" in url or "/actuator" in url or url.endswith("/server-status"):
            return _resp(status=404)
        return _resp(body="hello world")

    _patch_get(monkeypatch, responder)
    out = debug_endpoint_check("https://app.example.com/api/users")
    findings = _findings_from_tracer()
    high = [f for f in findings if f.get("severity") == "high"]
    assert len(high) >= 1
    # Should mention debug toggle
    assert any("Debug mode toggleable" in f["title"] for f in high)
    assert out["findings_emitted"] >= 1


def test_parametric_trace_only_medium(monkeypatch) -> None:
    """New stack trace, no debug header → medium."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "debug=1" in url:
            return _resp(body="Traceback (most recent call last):\n  File '/app.py', line 1")
        return _resp(body="hello world")

    _patch_get(monkeypatch, responder)
    out = debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    parametric = [f for f in findings if "Parametric debug toggle" in f.get("title", "")]
    assert len(parametric) == 1
    assert parametric[0]["severity"] == "medium"


def test_parametric_debug_header_only_medium(monkeypatch) -> None:
    """Debug header but no new trace → medium."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "debug=1" in url:
            return _resp(body="hello world", headers={"x-debug-token": "z"})
        return _resp(body="hello world")

    _patch_get(monkeypatch, responder)
    out = debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    parametric = [f for f in findings if "Parametric" in f.get("title", "")]
    assert len(parametric) == 1
    assert parametric[0]["severity"] == "medium"


def test_parametric_no_change_no_finding(monkeypatch) -> None:
    """Same body / no debug header on toggle → no finding."""
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    out = debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    parametric = [f for f in findings if "Parametric" in f.get("title", "")]
    assert parametric == []
    assert out["findings_emitted"] == 0


def test_parametric_dedup_only_one_finding(monkeypatch) -> None:
    """If 4 different toggles all match, still only one finding."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if any(t in url for t in ("debug=1", "DEBUG=true", "_debug=1", "trace=1")):
            return _resp(body="Traceback (most recent call last):\n line 1")
        return _resp(body="hello")

    _patch_get(monkeypatch, responder)
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    parametric = [f for f in findings if "Parametric" in f.get("title", "")
                  or "Debug mode toggleable" in f.get("title", "")]
    assert len(parametric) == 1


# ---------------------------------------------------------------------------
# Framework page findings
# ---------------------------------------------------------------------------


def test_spring_actuator_env_finding(monkeypatch) -> None:
    """`/actuator/env` returning JSON with `systemProperties` → medium."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if url.endswith("/actuator/env"):
            return _resp(
                body='{"activeProfiles":["prod"],"systemProperties":{"java.version":"17"}}',
                headers={"content-type": "application/json"},
            )
        return _resp(status=404)

    _patch_get(monkeypatch, responder)
    out = debug_endpoint_check("https://app.example.com/")
    findings = _findings_from_tracer()
    framework = [f for f in findings if "Framework debug page" in f.get("title", "")]
    assert len(framework) == 1
    assert framework[0]["severity"] == "medium"
    assert "/actuator/env" in framework[0]["endpoint"]


def test_symfony_profiler_finding(monkeypatch) -> None:
    """`/_profiler/` returning Symfony Profiler title → medium."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if url.endswith("/_profiler/"):
            return _resp(body="<html><title>Symfony Profiler</title></html>")
        return _resp(status=404)

    _patch_get(monkeypatch, responder)
    debug_endpoint_check("https://app.example.com/")
    findings = _findings_from_tracer()
    framework = [f for f in findings if "_profiler" in f.get("endpoint", "")]
    assert len(framework) == 1
    assert framework[0]["severity"] == "medium"


def test_apache_server_status_finding(monkeypatch) -> None:
    """`/server-status` returning Apache title → medium."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if url.endswith("/server-status"):
            return _resp(body="<html><title>Apache Status</title></html>")
        return _resp(status=404)

    _patch_get(monkeypatch, responder)
    debug_endpoint_check("https://app.example.com/")
    findings = _findings_from_tracer()
    framework = [f for f in findings if "/server-status" in f.get("endpoint", "")]
    assert len(framework) == 1


def test_swagger_ui_finding(monkeypatch) -> None:
    """`/swagger-ui` with `Swagger UI` title → medium."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if url.endswith("/swagger-ui"):
            return _resp(body="<html><title>Swagger UI</title></html>")
        return _resp(status=404)

    _patch_get(monkeypatch, responder)
    debug_endpoint_check("https://app.example.com/")
    findings = _findings_from_tracer()
    swagger = [f for f in findings if "/swagger-ui" in f.get("endpoint", "")]
    assert len(swagger) == 1


def test_prometheus_metrics_finding(monkeypatch) -> None:
    """`/metrics` returning `# HELP` lines → medium prometheus_metrics finding."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        # Match the prometheus root /metrics path only (not /actuator/metrics).
        if url.rstrip("/").endswith("//metrics") or url.endswith("/metrics") and "/actuator" not in url:
            return _resp(body="# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\n")
        return _resp(status=404)

    _patch_get(monkeypatch, responder)
    debug_endpoint_check("https://app.example.com/")
    findings = _findings_from_tracer()
    metrics = [
        f for f in findings
        if f.get("endpoint", "").endswith("/metrics")
        and "/actuator" not in f.get("endpoint", "")
    ]
    assert len(metrics) == 1


def test_framework_404_no_finding(monkeypatch) -> None:
    """All framework paths return 404 → no framework findings."""
    _patch_get(monkeypatch, lambda u, h: _resp(status=404, body="not found"))
    out = debug_endpoint_check("https://app.example.com/api/users")
    findings = _findings_from_tracer()
    framework = [f for f in findings if "Framework debug page" in f.get("title", "")]
    assert framework == []


def test_framework_dedup_by_label(monkeypatch) -> None:
    """Multiple actuator paths returning JSON → only one finding per label."""
    actuator_body = (
        '{"_links":{"self":{"href":"http://x/actuator"},"actuator":{"href":"http://x/actuator"}}}'
    )

    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "/actuator" in url:
            return _resp(body=actuator_body, headers={"content-type": "application/json"})
        return _resp(status=404)

    _patch_get(monkeypatch, responder)
    debug_endpoint_check("https://app.example.com/api/users")
    findings = _findings_from_tracer()
    actuator_findings = [f for f in findings if "spring_actuator" in f.get("description", "")]
    # Per-label dedup: at most one finding per (host, label)
    assert len(actuator_findings) == 1


# ---------------------------------------------------------------------------
# Error-trigger findings
# ---------------------------------------------------------------------------


def test_error_trigger_bleeds_trace_low(monkeypatch) -> None:
    """Single-quote payload triggers a stack trace → low finding."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "strix_probe=%27" in url or "strix_probe='" in url:
            return _resp(
                status=500,
                body="Traceback (most recent call last):\n  File '/app.py', line 99",
            )
        return _resp(body="hello world")

    _patch_get(monkeypatch, responder)
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    err = [f for f in findings if "Error-trigger" in f.get("title", "")]
    assert len(err) == 1
    assert err[0]["severity"] == "low"


def test_error_trigger_no_change_no_finding(monkeypatch) -> None:
    """All error triggers return same body → no finding."""
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    err = [f for f in findings if "Error-trigger" in f.get("title", "")]
    assert err == []


def test_error_trigger_dedup_only_one_finding(monkeypatch) -> None:
    """Multiple error payloads bleeding traces → only ONE finding."""
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "strix_probe=" in url:
            return _resp(body="Traceback (most recent call last):\n  File '/x.py', line 1")
        return _resp(body="hello")

    _patch_get(monkeypatch, responder)
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    err = [f for f in findings if "Error-trigger" in f.get("title", "")]
    assert len(err) == 1


# ---------------------------------------------------------------------------
# Baseline-trace marker subtraction
# ---------------------------------------------------------------------------


def test_baseline_already_has_trace_no_finding(monkeypatch) -> None:
    """If the baseline body already contains a trace marker (legacy
    error template), parametric/error toggles that produce the SAME
    marker should not flag — only NEW markers count."""
    baseline_body = (
        "Traceback (most recent call last):\n  File '/legacy.py', line 1"
    )

    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        # Same content for baseline AND probes — no delta.
        return _resp(body=baseline_body)

    _patch_get(monkeypatch, responder)
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    parametric = [f for f in findings if "Parametric" in f.get("title", "")]
    err = [f for f in findings if "Error-trigger" in f.get("title", "")]
    assert parametric == []
    assert err == []


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_finding_carries_description_plain_and_recommended_action(monkeypatch) -> None:
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "debug=1" in url:
            return _resp(
                body="Traceback (most recent call last):\nat ...",
                headers={"x-debug-token": "abc"},
            )
        return _resp(body="hello")

    _patch_get(monkeypatch, responder)
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    findings = _findings_from_tracer()
    assert findings, "expected at least one finding"
    f = findings[0]
    assert f.get("description_plain")
    assert f.get("recommended_action")
    assert f.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# check.completed event
# ---------------------------------------------------------------------------


def test_check_completed_emitted(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    debug_endpoint_check("https://app.example.com/api/users")
    summary = _check_summary()
    assert "debug_bleed" in summary.get("by_category", {})


def test_check_result_vulnerable_when_finding_emitted(monkeypatch) -> None:
    def responder(url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "debug=1" in url:
            return _resp(
                body="Traceback (most recent call last):\nat ...",
                headers={"x-debug-token": "abc"},
            )
        return _resp(body="hello")

    _patch_get(monkeypatch, responder)
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    summary = _check_summary()
    assert summary["by_category"]["debug_bleed"]["vulnerable"] >= 1


def test_check_result_not_vulnerable_when_no_finding(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    summary = _check_summary()
    assert summary["by_category"]["debug_bleed"]["not_vulnerable"] >= 1


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    out = debug_endpoint_check("https://app.example.com/api/users")
    assert set(out.keys()) >= {
        "success", "target_url", "target_host", "baseline",
        "parametric_probes", "framework_probes", "error_probes",
        "findings_emitted",
    }
    # baseline summary
    assert set(out["baseline"].keys()) >= {
        "status", "body_length", "skipped", "trace_markers",
    }


def test_parametric_probe_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    out = debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    assert out["parametric_probes"]
    p = out["parametric_probes"][0]
    assert set(p.keys()) >= {
        "param", "url", "status", "body_length",
        "new_trace_markers", "debug_header", "skipped",
    }


def test_framework_probe_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(status=404))
    out = debug_endpoint_check("https://app.example.com/")
    assert out["framework_probes"]
    p = out["framework_probes"][0]
    assert set(p.keys()) >= {
        "path", "label", "url", "status", "body_length",
        "matched_markers", "skipped",
    }


def test_error_probe_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda u, h: _resp(body="hello"))
    out = debug_endpoint_check(
        "https://app.example.com/api/users", skip_framework_pages=True
    )
    assert out["error_probes"]
    p = out["error_probes"][0]
    assert set(p.keys()) >= {
        "label", "url", "status", "body_length",
        "new_trace_markers", "skipped",
    }


# ---------------------------------------------------------------------------
# MITRE technique tag
# ---------------------------------------------------------------------------


def test_mitre_technique_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("debug_endpoint_check")
    assert "T1592" in techniques


# ---------------------------------------------------------------------------
# Header / body matchers — unit tests on pure helpers
# ---------------------------------------------------------------------------


def test_trace_markers_hit_traceback() -> None:
    body = "Traceback (most recent call last):\n  File '/x', line 1"
    assert de_module._trace_markers_in(body)


def test_trace_markers_hit_php_on_line() -> None:
    body = "Fatal error in /var/www/x.php on line 42"
    assert de_module._trace_markers_in(body)


def test_trace_markers_hit_java_at() -> None:
    body = "  at com.example.Foo.bar(Foo.java:42)"
    assert de_module._trace_markers_in(body)


def test_trace_markers_empty_body() -> None:
    assert de_module._trace_markers_in("") == []


def test_page_markers_hit_actuator_links() -> None:
    body = '{"_links":{"self":{"href":"x"},"actuator":{"href":"x"}}}'
    hits = de_module._page_markers_in(body)
    assert "spring_actuator" in hits


def test_page_markers_hit_swagger_title() -> None:
    body = "<html><title>Swagger UI</title></html>"
    hits = de_module._page_markers_in(body)
    assert "swagger_ui" in hits


def test_has_debug_header_x_debug_token() -> None:
    assert de_module._has_debug_header({"x-debug-token": "a"})


def test_has_debug_header_x_powered_by() -> None:
    assert de_module._has_debug_header({"x-powered-by": "PHP/7.4"})


def test_has_debug_header_none() -> None:
    assert de_module._has_debug_header({"x-other": "v"}) is None


def test_append_query_first_param() -> None:
    out = de_module._append_query("https://x.com/path", "debug", "1")
    assert out == "https://x.com/path?debug=1"


def test_append_query_extra_param() -> None:
    out = de_module._append_query("https://x.com/path?a=1", "debug", "1")
    assert "a=1" in out and "debug=1" in out
