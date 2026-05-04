"""Tests for threat_feed_ingest.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- Input validation (missing URL, non-http URL)
- Format detection (MISP / STIX 2.x bundle / TAXII 2.1 collection /
  unknown)
- MISP extractor: walks `response[].Event.Attribute[]` and
  `response.Event.Attribute[]` shapes, normalises types, handles
  composite values (`domain|ip`)
- STIX extractor: parses `pattern` field for ipv4-addr / domain-name
  / url / file:hashes.SHA-256 / email-addr
- max_records cap
- Auth: Bearer-style token sent verbatim, Basic auth base64-encoded
- Target-filter matching: IP exact, domain equality, domain suffix,
  URL hostname extraction
- Per-(type, value) dedup on findings
- 4xx / 5xx responses → graceful failure (with stale-cache fallback)
- Invalid JSON → graceful failure
- network error → graceful failure (with stale-cache fallback)
- Cache hit returns from_cache=True without HTTP call (but re-emits
  findings against cached indicators)
- Cache disabled via env
- Stale-cache served on network failure
- Single info finding per match with description_plain +
  recommended_action
- check.completed event emission
- Result schema integrity
"""

from __future__ import annotations

import base64
import json
import sys
import time
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.threat_feed.threat_feed_ingest  # noqa: F401

tf_module = sys.modules["strix.tools.threat_feed.threat_feed_ingest"]
threat_feed_ingest = tf_module.threat_feed_ingest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    monkeypatch.delenv("STRIX_THREAT_FEED_NO_CACHE", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("tf-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=30.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(tf_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_missing_url_rejected() -> None:
    out = threat_feed_ingest("")
    assert out["success"] is False


def test_non_http_url_rejected() -> None:
    out = threat_feed_ingest("misp.example.org/feed")
    assert out["success"] is False
    assert "absolute" in out["error"]


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def test_format_detection_misp_response_array() -> None:
    payload = {"response": [{"Event": {"id": "1", "Attribute": []}}]}
    assert tf_module._detect_format(payload) == "misp"


def test_format_detection_misp_event_root() -> None:
    payload = {"Event": {"id": "1", "info": "Test", "Attribute": []}}
    assert tf_module._detect_format(payload) == "misp"


def test_format_detection_stix2_bundle() -> None:
    payload = {"type": "bundle", "objects": [{"type": "indicator"}]}
    assert tf_module._detect_format(payload) == "stix2_bundle"


def test_format_detection_taxii2_collection() -> None:
    payload = {"objects": [{"id": "indicator--abc-123", "type": "indicator", "pattern": "[]"}]}
    assert tf_module._detect_format(payload) == "taxii2_collection"


def test_format_detection_unknown() -> None:
    assert tf_module._detect_format({"random": "data"}) == "unknown"
    assert tf_module._detect_format([]) == "unknown"
    assert tf_module._detect_format("string") == "unknown"


# ---------------------------------------------------------------------------
# MISP extractor
# ---------------------------------------------------------------------------


def _misp_response(attributes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "response": [{
            "Event": {
                "id": "42",
                "info": "Test event",
                "threat_level_id": "1",
                "Attribute": attributes,
            }
        }]
    }


def test_misp_extracts_ip_attribute() -> None:
    payload = _misp_response([
        {"type": "ip-src", "value": "1.2.3.4", "comment": "C2"}
    ])
    iocs = tf_module._extract_misp(payload, cap=100)
    assert len(iocs) == 1
    assert iocs[0]["type"] == "ip"
    assert iocs[0]["value"] == "1.2.3.4"
    assert iocs[0]["source"] == "misp"
    assert iocs[0]["event_id"] == "42"


def test_misp_extracts_multiple_ioc_types() -> None:
    payload = _misp_response([
        {"type": "ip-dst", "value": "5.6.7.8"},
        {"type": "domain", "value": "evil.example"},
        {"type": "url", "value": "https://evil.example/payload"},
        {"type": "sha256", "value": "abc123"},
    ])
    iocs = tf_module._extract_misp(payload, cap=100)
    types = {i["type"] for i in iocs}
    assert {"ip", "domain", "url", "sha256"} == types


def test_misp_skips_unknown_types() -> None:
    payload = _misp_response([
        {"type": "ip-src", "value": "1.2.3.4"},
        {"type": "weird-unknown-type", "value": "xyz"},
    ])
    iocs = tf_module._extract_misp(payload, cap=100)
    assert len(iocs) == 1


def test_misp_composite_domain_ip() -> None:
    """`domain|ip` type with `evil.com|1.2.3.4` value → use domain part."""
    payload = _misp_response([
        {"type": "domain|ip", "value": "evil.example|1.2.3.4"},
    ])
    iocs = tf_module._extract_misp(payload, cap=100)
    assert iocs[0]["type"] == "domain"
    assert iocs[0]["value"] == "evil.example"


def test_misp_attribute_at_response_root() -> None:
    """Some MISP queries return `{response: {Attribute: [...]}}`."""
    payload = {
        "response": {
            "Attribute": [
                {"type": "ip-src", "value": "1.2.3.4"},
            ]
        }
    }
    iocs = tf_module._extract_misp(payload, cap=100)
    assert len(iocs) == 1


def test_misp_event_at_root() -> None:
    payload = {"Event": {"id": "1", "Attribute": [{"type": "ip-dst", "value": "5.6.7.8"}]}}
    iocs = tf_module._extract_misp(payload, cap=100)
    assert len(iocs) == 1


def test_misp_extractor_respects_cap() -> None:
    payload = _misp_response([
        {"type": "ip-src", "value": f"1.2.3.{i}"} for i in range(20)
    ])
    iocs = tf_module._extract_misp(payload, cap=5)
    assert len(iocs) == 5


# ---------------------------------------------------------------------------
# STIX extractor
# ---------------------------------------------------------------------------


def _stix_indicator(pattern: str, indicator_id: str = "indicator--abc-123") -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": indicator_id,
        "spec_version": "2.1",
        "pattern": pattern,
        "labels": ["malicious-activity"],
        "valid_from": "2024-12-01T00:00:00Z",
        "name": "Test indicator",
    }


def test_stix_extracts_ipv4() -> None:
    payload = {
        "type": "bundle",
        "objects": [_stix_indicator("[ipv4-addr:value = '1.2.3.4']")]
    }
    iocs = tf_module._extract_stix2(payload, cap=100)
    assert iocs[0]["type"] == "ip"
    assert iocs[0]["value"] == "1.2.3.4"


def test_stix_extracts_domain() -> None:
    payload = {
        "type": "bundle",
        "objects": [_stix_indicator("[domain-name:value = 'evil.example']")]
    }
    iocs = tf_module._extract_stix2(payload, cap=100)
    assert iocs[0]["type"] == "domain"
    assert iocs[0]["value"] == "evil.example"


def test_stix_extracts_url() -> None:
    payload = {
        "type": "bundle",
        "objects": [_stix_indicator("[url:value = 'https://evil.example/']")]
    }
    iocs = tf_module._extract_stix2(payload, cap=100)
    assert iocs[0]["type"] == "url"


def test_stix_extracts_sha256_hash() -> None:
    payload = {
        "type": "bundle",
        "objects": [_stix_indicator("[file:hashes.'SHA-256' = 'abcd1234']")]
    }
    iocs = tf_module._extract_stix2(payload, cap=100)
    assert iocs[0]["type"] == "sha256"
    assert iocs[0]["value"] == "abcd1234"


def test_stix_extracts_email() -> None:
    payload = {
        "type": "bundle",
        "objects": [_stix_indicator("[email-addr:value = 'bad@evil.example']")]
    }
    iocs = tf_module._extract_stix2(payload, cap=100)
    assert iocs[0]["type"] == "email"


def test_stix_skips_non_indicators() -> None:
    payload = {
        "type": "bundle",
        "objects": [
            {"type": "malware", "id": "malware--xxx", "name": "Foo"},
            _stix_indicator("[ipv4-addr:value = '1.2.3.4']"),
        ],
    }
    iocs = tf_module._extract_stix2(payload, cap=100)
    assert len(iocs) == 1
    assert iocs[0]["type"] == "ip"


def test_stix_object_path_helper() -> None:
    assert tf_module._stix_object_path_to_ioc_type("ipv4-addr:value") == "ip"
    assert tf_module._stix_object_path_to_ioc_type("ipv6-addr:value") == "ip"
    assert tf_module._stix_object_path_to_ioc_type("domain-name:value") == "domain"
    assert tf_module._stix_object_path_to_ioc_type("url:value") == "url"
    assert tf_module._stix_object_path_to_ioc_type("email-addr:value") == "email"
    assert tf_module._stix_object_path_to_ioc_type("file:hashes.'SHA-256'") == "sha256"
    assert tf_module._stix_object_path_to_ioc_type("file:hashes.'MD5'") == "md5"
    assert tf_module._stix_object_path_to_ioc_type("unknown:thing") is None


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------


def test_bearer_token_sent_verbatim(monkeypatch) -> None:
    captured: list[str] = []

    def responder(url, headers):
        captured.append(headers.get("Authorization", ""))
        return _resp(status=200, body=json.dumps({"response": []}))

    _patch_http(monkeypatch, responder)
    threat_feed_ingest("https://misp.example.org/feed", auth_token="API-KEY-123")
    assert captured == ["API-KEY-123"]  # MISP-style: no "Bearer" prefix


def test_basic_auth_base64_encoded(monkeypatch) -> None:
    captured: list[str] = []

    def responder(url, headers):
        captured.append(headers.get("Authorization", ""))
        return _resp(status=200, body=json.dumps({"objects": []}))

    _patch_http(monkeypatch, responder)
    threat_feed_ingest("https://taxii.example.org/feed", auth_basic="user:secret")
    assert captured
    assert captured[0].startswith("Basic ")
    decoded = base64.b64decode(captured[0].split(" ", 1)[1]).decode("ascii")
    assert decoded == "user:secret"


def test_token_wins_over_basic(monkeypatch) -> None:
    captured: list[str] = []

    def responder(url, headers):
        captured.append(headers.get("Authorization", ""))
        return _resp(status=200, body=json.dumps({"response": []}))

    _patch_http(monkeypatch, responder)
    threat_feed_ingest(
        "https://misp.example.org/feed",
        auth_token="TOKEN-WINS",
        auth_basic="user:secret",
    )
    assert captured == ["TOKEN-WINS"]


# ---------------------------------------------------------------------------
# Target-filter matching
# ---------------------------------------------------------------------------


def test_target_filter_matches_ip_exact() -> None:
    parsed = tf_module._normalize_target_filter("1.2.3.4")
    assert parsed == ("ip", "1.2.3.4")
    assert tf_module._matches_target(
        {"type": "ip", "value": "1.2.3.4"}, "ip", "1.2.3.4",
    )
    assert not tf_module._matches_target(
        {"type": "ip", "value": "1.2.3.5"}, "ip", "1.2.3.4",
    )


def test_target_filter_domain_equality() -> None:
    assert tf_module._matches_target(
        {"type": "domain", "value": "example.com"}, "domain", "example.com",
    )


def test_target_filter_domain_suffix() -> None:
    assert tf_module._matches_target(
        {"type": "domain", "value": "evil.example.com"}, "domain", "example.com",
    )
    # NOT a suffix — "kexample.com" doesn't end with ".example.com".
    assert not tf_module._matches_target(
        {"type": "domain", "value": "kexample.com"}, "domain", "example.com",
    )


def test_target_filter_url_hostname_extracted() -> None:
    assert tf_module._matches_target(
        {"type": "url", "value": "https://evil.example.com/path"},
        "domain", "example.com",
    )


def test_target_filter_url_other_origin_no_match() -> None:
    assert not tf_module._matches_target(
        {"type": "url", "value": "https://kexample.com/path"},
        "domain", "example.com",
    )


def test_target_filter_strips_url_scheme() -> None:
    parsed = tf_module._normalize_target_filter("https://app.example.com/")
    assert parsed == ("domain", "app.example.com")


def test_target_filter_invalid_returns_none() -> None:
    assert tf_module._normalize_target_filter("") is None
    assert tf_module._normalize_target_filter(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# End-to-end: emit findings on match
# ---------------------------------------------------------------------------


def test_misp_match_emits_info_finding(monkeypatch) -> None:
    body = json.dumps(_misp_response([
        {"type": "domain", "value": "phish.example.com", "comment": "Phishing kit"},
    ]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = threat_feed_ingest(
        "https://misp.example.org/feed",
        target_filter="example.com",
    )
    assert out["matched_count"] == 1
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r["severity"] == "info"
    assert r["category"] == "threat_feed_match"
    assert r["cwe"] == "CWE-200"
    assert "phish.example.com" in r["title"]


def test_no_target_filter_no_findings(monkeypatch) -> None:
    body = json.dumps(_misp_response([
        {"type": "ip-src", "value": "1.2.3.4"},
        {"type": "domain", "value": "evil.example"},
    ]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = threat_feed_ingest("https://misp.example.org/feed")
    assert out["record_count"] == 2
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_per_match_dedup(monkeypatch) -> None:
    """Same IoC appearing twice in feed → ONE finding."""
    body = json.dumps(_misp_response([
        {"type": "domain", "value": "evil.example.com"},
        {"type": "domain", "value": "evil.example.com"},  # duplicate
        {"type": "domain", "value": "evil.example.com"},  # duplicate
    ]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = threat_feed_ingest(
        "https://misp.example.org/feed",
        target_filter="example.com",
    )
    assert out["matched_count"] == 1
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    body = json.dumps(_misp_response([
        {"type": "ip-src", "value": "1.2.3.4"},
    ]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    threat_feed_ingest(
        "https://misp.example.org/feed",
        target_filter="1.2.3.4",
    )
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain")
        assert r.get("recommended_action")
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# max_records cap
# ---------------------------------------------------------------------------


def test_max_records_cap(monkeypatch) -> None:
    body = json.dumps(_misp_response([
        {"type": "ip-src", "value": f"10.0.0.{i}"} for i in range(50)
    ]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = threat_feed_ingest(
        "https://misp.example.org/feed",
        max_records=10,
    )
    assert out["record_count"] == 10


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


def test_4xx_no_cache_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=403, body="forbidden"))
    out = threat_feed_ingest("https://misp.example.org/feed", auth_token="bad")
    assert out["success"] is False
    assert "403" in out["error"]


def test_5xx_no_cache_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=500, body="ise"))
    out = threat_feed_ingest("https://misp.example.org/feed")
    assert out["success"] is False


def test_invalid_json_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = threat_feed_ingest("https://misp.example.org/feed")
    assert out["success"] is False
    assert "JSON" in out["error"]


def test_unknown_format_succeeds_with_zero_indicators(monkeypatch) -> None:
    """Unknown format JSON → success but no indicators extracted."""
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=json.dumps({"random": "data"})))
    out = threat_feed_ingest("https://misp.example.org/feed")
    assert out["success"] is True
    assert out["feed_format"] == "unknown"
    assert out["record_count"] == 0


def test_network_error_no_cache_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: {
        "status": 0, "headers": {}, "body": "", "error": "DNS failure",
    })
    out = threat_feed_ingest("https://misp.example.org/feed")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    body = json.dumps(_misp_response([
        {"type": "ip-src", "value": "1.2.3.4"},
    ]))
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out1 = threat_feed_ingest("https://misp.example.org/feed", auth_token="k")
    assert out1["from_cache"] is False
    pre = len(log)

    out2 = threat_feed_ingest("https://misp.example.org/feed", auth_token="k")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_re_emits_findings_on_filter_match(monkeypatch) -> None:
    """When a cache hit happens with target_filter, findings are re-emitted
    against the cached IoCs (tracer state isn't preserved in cache)."""
    body = json.dumps(_misp_response([
        {"type": "ip-src", "value": "1.2.3.4"},
    ]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))

    # First call without filter → cache populated, no findings.
    threat_feed_ingest("https://misp.example.org/feed", auth_token="k")
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []

    # Reset tracer to count findings from second call.
    tracer = tracer_module.get_global_tracer()
    tracer.vulnerability_reports.clear()  # type: ignore[attr-defined]

    out2 = threat_feed_ingest(
        "https://misp.example.org/feed", auth_token="k",
        target_filter="1.2.3.4",
    )
    assert out2["from_cache"] is True
    assert out2["matched_count"] == 1
    reports = tracer.get_existing_vulnerabilities()
    assert len(reports) == 1


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_THREAT_FEED_NO_CACHE", "1")
    body = json.dumps(_misp_response([{"type": "ip-src", "value": "1.2.3.4"}]))
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    threat_feed_ingest("https://misp.example.org/feed")
    pre = len(log)
    threat_feed_ingest("https://misp.example.org/feed")
    assert len(log) > pre


def test_cache_key_distinct_per_auth(monkeypatch) -> None:
    """Different auth tokens → different cache slots."""
    body = json.dumps(_misp_response([{"type": "ip-src", "value": "1.2.3.4"}]))
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))

    threat_feed_ingest("https://misp.example.org/feed", auth_token="key-a")
    pre = len(log)
    threat_feed_ingest("https://misp.example.org/feed", auth_token="key-b")
    assert len(log) > pre


def test_stale_cache_served_on_failure(monkeypatch) -> None:
    fail_now = [False]
    body = json.dumps(_misp_response([{"type": "ip-src", "value": "1.2.3.4"}]))

    def responder(url, headers):
        if fail_now[0]:
            return {"status": 0, "headers": {}, "body": "", "error": "network unreachable"}
        return _resp(status=200, body=body)

    _patch_http(monkeypatch, responder)
    out1 = threat_feed_ingest("https://misp.example.org/feed", auth_token="k")
    assert out1["from_cache"] is False

    cache_path = tf_module._cache_path(
        "https://misp.example.org/feed",
        tf_module._auth_fingerprint("k", ""),
    )
    old_mtime = time.time() - 2 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True
    out2 = threat_feed_ingest("https://misp.example.org/feed", auth_token="k")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    body = json.dumps(_misp_response([{"type": "ip-src", "value": "1.2.3.4"}]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    threat_feed_ingest("https://misp.example.org/feed")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "threat_feed_ingest" in summary["by_category"]
    assert summary["by_category"]["threat_feed_ingest"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable_on_match(monkeypatch) -> None:
    body = json.dumps(_misp_response([{"type": "ip-src", "value": "1.2.3.4"}]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    threat_feed_ingest("https://misp.example.org/feed", target_filter="1.2.3.4")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["threat_feed_ingest"]
    assert cat["vulnerable"] == 1


def test_check_event_inconclusive_on_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=500))
    threat_feed_ingest("https://misp.example.org/feed")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["threat_feed_ingest"]
    assert cat["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    body = json.dumps(_misp_response([{"type": "ip-src", "value": "1.2.3.4"}]))
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = threat_feed_ingest("https://misp.example.org/feed")
    for k in ("success", "feed_url", "feed_format", "fetched_at",
              "from_cache", "indicators", "record_count",
              "target_filter", "matched_count", "findings_emitted"):
        assert k in out


def test_auth_fingerprint_stable_and_distinct() -> None:
    """Fingerprint is stable across calls but distinct between auth shapes."""
    fp1 = tf_module._auth_fingerprint("token-a", "")
    fp2 = tf_module._auth_fingerprint("token-a", "")
    fp3 = tf_module._auth_fingerprint("token-b", "")
    fp4 = tf_module._auth_fingerprint("", "user:pass")
    fp5 = tf_module._auth_fingerprint("", "")
    assert fp1 == fp2
    assert fp1 != fp3
    assert fp1 != fp4
    assert fp5 == "anon"
