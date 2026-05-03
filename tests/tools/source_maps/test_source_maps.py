"""Tests for source_map_probe.

Hermetic — `_http_get` is mocked. Tests cover:
- HTML script-src harvesting (same-origin filter, off-origin drop)
- Bundle-name candidate probing
- Source-map JSON validation (v3 shape)
- Secret-indicator regex on sourcesContent
- Severity escalation (medium → high) on secret hit
- description_plain / recommended_action populated
- Cluster-A composition (excluded path → recorded in errors)
- 404 / non-JSON / non-source-map JSON all handled gracefully
- `extra_urls` accepted; off-origin extras dropped
- Cookie / source body content NEVER fully echoed in findings
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety
from strix.tools.source_maps import source_maps as sm


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
    tracer = Tracer("sm-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com"}]})
    yield


def _patch_get(monkeypatch, responses):
    """responses: dict url → response dict."""
    log: list[str] = []

    def fake(url, *, max_bytes=8 * 1024 * 1024):
        log.append(url)
        return responses.get(url, {"status": 404, "headers": {}, "body": ""})

    monkeypatch.setattr(sm, "_http_get", fake)
    return log


# Minimal valid v3 source-map.
_VALID_MAP = json.dumps({
    "version": 3,
    "file": "app.js",
    "sources": ["src/app.tsx", "src/utils.ts", "src/api/client.ts"],
    "names": [],
    "mappings": "AAAA",
})

# Source-map with sourcesContent that contains secret indicators.
_MAP_WITH_SECRET = json.dumps({
    "version": 3,
    "file": "config.js",
    "sources": ["src/config.ts", "src/safe.ts"],
    "sourcesContent": [
        "export const API_KEY = 'sk_live_VERY_SENSITIVE_TOK_xyz123';\n"
        "export const ENDPOINT = 'https://api.example.com';\n",
        "export const greeting = 'hello';",
    ],
    "names": [],
    "mappings": "AAAA",
})

_MAP_WITH_SOURCES_CONTENT_NO_SECRET = json.dumps({
    "version": 3,
    "file": "safe.js",
    "sources": ["src/safe.ts"],
    "sourcesContent": ["export const greeting = 'hello world';"],
    "names": [],
    "mappings": "AAAA",
})


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_target_rejected() -> None:
    out = sm.source_map_probe("")
    assert out["success"] is False


def test_invalid_scheme_rejected() -> None:
    out = sm.source_map_probe("ftp://app.example.com")
    assert out["success"] is False


def test_bare_hostname_gets_https(monkeypatch) -> None:
    log = _patch_get(monkeypatch, {})
    sm.source_map_probe("app.example.com")
    # The first probe is the HTML root.
    assert log[0].startswith("https://app.example.com")


# ---------------------------------------------------------------------------
# HTML script-src harvesting
# ---------------------------------------------------------------------------


def test_script_src_harvest_same_origin(monkeypatch) -> None:
    """`<script src>` URLs from the HTML get probed at `<src>.map`."""
    html = (
        "<html><body>"
        "<script src='/static/js/main.abc.js'></script>"
        "<script src='/static/js/vendor.def.js'></script>"
        "<script src='https://cdn.example.com/lib.js'></script>"  # off-origin → dropped
        "</body></html>"
    )
    main_map = "https://app.example.com/static/js/main.abc.js.map"
    vendor_map = "https://app.example.com/static/js/vendor.def.js.map"
    log = _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": html,
            },
            main_map: {"status": 200, "headers": {}, "body": _VALID_MAP},
            vendor_map: {"status": 404, "headers": {}, "body": ""},
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    # main.js.map probed (and was a hit).
    assert main_map in log
    # vendor.js.map probed (404).
    assert vendor_map in log
    # off-origin lib.js → no `.map` probe.
    assert not any("cdn.example.com" in u for u in log)
    assert len(out["hits"]) == 1
    assert out["hits"][0]["url"] == main_map


def test_html_non_html_response_no_harvest(monkeypatch) -> None:
    """When target serves JSON / plain text (not HTML), no script-src harvest."""
    log = _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "application/json"},
                "body": '{"hello": "world"}',
            },
        },
    )
    sm.source_map_probe("https://app.example.com")
    # Only the bundle-name candidates probed; no script harvest happened.
    # The first call is the HTML root, then candidates.
    assert "https://app.example.com" in log
    # No `.json.map` or any harvest-derived URL — only the curated list.
    for url in log[1:]:
        assert url.endswith(".js.map")


def test_data_javascript_srcs_dropped(monkeypatch) -> None:
    html = (
        "<html><body>"
        "<script src='data:text/javascript,alert(1)'></script>"
        "<script src='javascript:void(0)'></script>"
        "<script src='/app.js'></script>"
        "</body></html>"
    )
    log = _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": html,
            },
        },
    )
    sm.source_map_probe("https://app.example.com")
    assert any(u.endswith("app.js.map") for u in log)
    assert not any("data:" in u or "javascript:" in u for u in log)


# ---------------------------------------------------------------------------
# Bundle-name candidate probing
# ---------------------------------------------------------------------------


def test_bundle_name_candidates_probed(monkeypatch) -> None:
    """When the HTML has no scripts, the curated candidate list still gets probed."""
    log = _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "<html></html>",
            },
        },
    )
    sm.source_map_probe("https://app.example.com")
    # All curated candidates got probed.
    for path in sm._BUNDLE_NAME_CANDIDATES:
        assert any(u.endswith(path) for u in log), f"missing candidate: {path}"


# ---------------------------------------------------------------------------
# Source-map JSON validation
# ---------------------------------------------------------------------------


def test_invalid_json_no_finding(monkeypatch) -> None:
    """A 200 response that's not JSON (e.g. served as HTML 404 page) → no finding."""
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "<html></html>",
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": "<!DOCTYPE html><html>Not Found</html>",
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    assert out["hits"] == []


def test_json_but_not_source_map_no_finding(monkeypatch) -> None:
    """JSON without the v3 source-map shape → no finding."""
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": '{"some": "other json", "version": 1}',
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    assert out["hits"] == []


def test_valid_source_map_emits_medium_finding(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": _VALID_MAP,
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    assert len(out["hits"]) == 1
    hit = out["hits"][0]
    assert hit["url"] == "https://app.example.com/app.js.map"
    assert hit["source_count"] == 3
    assert hit["has_sources_content"] is False

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r["severity"] == "medium"
    assert r["category"] == "info_disclosure"
    assert r["cwe"] == "CWE-540"
    # Plain-English fields populated.
    assert r["description_plain"]
    assert r["recommended_action"]
    assert r["fix_time_estimate"] == "1hr"


# ---------------------------------------------------------------------------
# Secret detection in sourcesContent
# ---------------------------------------------------------------------------


def test_secret_in_sources_content_escalates_to_high(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": _MAP_WITH_SECRET,
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    hit = out["hits"][0]
    assert hit["has_sources_content"] is True
    assert len(hit["secret_hits"]) >= 1
    # Only the file with the secret is flagged.
    assert any("config.ts" in h["file"] for h in hit["secret_hits"])

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r["severity"] == "high"
    assert r["category"] == "secret_leak"
    assert r["verification_status"] == "needs_review"


def test_sources_content_no_secret_stays_medium(monkeypatch) -> None:
    """sourcesContent present but no secret indicators → medium, not high."""
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": _MAP_WITH_SOURCES_CONTENT_NO_SECRET,
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    hit = out["hits"][0]
    assert hit["has_sources_content"] is True
    assert hit["secret_hits"] == []
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports[0]["severity"] == "medium"


def test_secret_snippet_is_bounded_and_no_full_source(monkeypatch) -> None:
    """Per credentials-feedback memory: the leaked source value must NOT
    appear in full in finding output. Snippets are length-capped."""
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": _MAP_WITH_SECRET,
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    # Snippets must be ≤120 chars.
    for h in out["hits"][0]["secret_hits"]:
        assert len(h["snippet"]) <= 120
    # No full source body returned anywhere.
    serialized = json.dumps(out)
    # The secret string itself can appear in the snippet (that's the point —
    # we're showing the agent what we found), but the full pre-minified source
    # must not be returned.
    assert "export const ENDPOINT" not in serialized


# ---------------------------------------------------------------------------
# extra_urls
# ---------------------------------------------------------------------------


def test_extra_urls_probed(monkeypatch) -> None:
    log = _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
        },
    )
    sm.source_map_probe(
        "https://app.example.com",
        extra_urls="/internal/admin.js.map,/static/chunk-abc.js.map",
    )
    assert "https://app.example.com/internal/admin.js.map" in log
    assert "https://app.example.com/static/chunk-abc.js.map" in log


def test_extra_urls_off_origin_dropped(monkeypatch) -> None:
    log = _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
        },
    )
    sm.source_map_probe(
        "https://app.example.com",
        extra_urls="https://attacker.com/payload.js.map",
    )
    assert not any("attacker.com" in u for u in log)


# ---------------------------------------------------------------------------
# Cluster-A composition + error paths
# ---------------------------------------------------------------------------


def test_excluded_path_recorded_in_errors(monkeypatch) -> None:
    """When a candidate URL matches --exclude-path, recorded in errors[],
    no finding emitted."""
    def fake(url, *, max_bytes=8 * 1024 * 1024):
        if url == "https://app.example.com/app.js.map":
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        if url == "https://app.example.com":
            return {"status": 200, "headers": {"content-type": "text/html"}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}

    monkeypatch.setattr(sm, "_http_get", fake)
    out = sm.source_map_probe("https://app.example.com")
    excluded_errors = [e for e in out["errors"] if "exclude-path" in e.get("error", "")]
    assert len(excluded_errors) == 1
    assert excluded_errors[0]["url"] == "https://app.example.com/app.js.map"


def test_unreachable_target_no_crash(monkeypatch) -> None:
    """All probes return error → no findings, structured success result."""
    def fake(url, *, max_bytes=8 * 1024 * 1024):
        return {"status": 0, "headers": {}, "body": "", "error": "conn refused"}

    monkeypatch.setattr(sm, "_http_get", fake)
    out = sm.source_map_probe("https://app.example.com")
    assert out["success"] is True
    assert out["hits"] == []
    assert len(out["errors"]) > 0


# ---------------------------------------------------------------------------
# Stats + check events
# ---------------------------------------------------------------------------


def test_stats_populated(monkeypatch) -> None:
    html = "<html><script src='/app.js'></script><script src='/vendor.js'></script></html>"
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": html,
            },
            "https://app.example.com/app.js.map": {
                "status": 200, "headers": {}, "body": _VALID_MAP,
            },
        },
    )
    out = sm.source_map_probe("https://app.example.com")
    assert out["stats"]["scripts_from_html"] == 2
    assert out["stats"]["hits_count"] == 1
    # Candidate count = bundle-name list + any unique script-derived URLs
    # (here `/app.js.map` collapses with the curated `/app.js.map`).
    assert out["stats"]["candidates"] >= len(sm._BUNDLE_NAME_CANDIDATES)


def test_check_event_emitted(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            "https://app.example.com": {
                "status": 200, "headers": {"content-type": "text/html"}, "body": "",
            },
        },
    )
    sm.source_map_probe("https://app.example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "source_map_probe" in summary["by_category"]
