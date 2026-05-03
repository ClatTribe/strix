"""Tests for domain_reputation.

Hermetic — `_http_request`, `_resolve_ips`, `_query_spamhaus_dbl`,
`_query_spamhaus_zen` are monkeypatched. Tests cover:

- Target classification (domain / IP / URL strip / invalid / private IP)
- IP reversal helper (RBL query format)
- Per-source severity derivation
- URLhaus active vs historical → high vs low
- Spamhaus DBL listed → medium
- Spamhaus ZEN listed (per IP) → low
- Google Safe Browsing flagged → medium; skipped without key
- AbuseIPDB confidence bands → high / medium / low / none; skipped without key
- Per-source dedup
- Multi-IP scan when target is domain (resolved IPs probed)
- Clean target → no findings
- Cache hit returns from_cache=True
- Cache disabled via env
- Stale cache served on full-source failure (fail-open)
- §11 UX baseline (description_plain + recommended_action + needs_review)
- check.completed event emission
- Result schema integrity
- URL-input normalized to hostname
- Private IP rejected
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.domain_reputation.domain_reputation  # noqa: F401

dr_module = sys.modules["strix.tools.domain_reputation.domain_reputation"]
domain_reputation = dr_module.domain_reputation


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
    monkeypatch.delenv("STRIX_DOMAIN_REP_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_GSB_KEY", raising=False)
    monkeypatch.delenv("STRIX_ABUSEIPDB_KEY", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("dr-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(method, url, *, headers=None, body="", timeout=12.0):
        log.append({
            "method": method, "url": url,
            "headers": dict(headers or {}), "body": body,
        })
        return responder(method, url, body, dict(headers or {}))

    monkeypatch.setattr(dr_module, "_http_request", fake)
    return log


def _patch_dns(monkeypatch, *, resolve_ips=None, dbl_listed=False, dbl_codes=None,
               zen_listed_ips=None):
    """Patch DNS-related helpers."""
    monkeypatch.setattr(dr_module, "_resolve_ips", lambda d, timeout=4.0: list(resolve_ips or []))

    def fake_dbl(domain, timeout=4.0):
        if dbl_listed:
            return {
                "listed": True,
                "codes": dbl_codes or ["127.0.1.2"],
                "kinds": ["spam"],
            }
        return {"listed": False}

    monkeypatch.setattr(dr_module, "_query_spamhaus_dbl", fake_dbl)

    listed_ips = set(zen_listed_ips or [])

    def fake_zen(ip, timeout=4.0):
        if ip in listed_ips:
            return {"listed": True, "codes": ["127.0.0.4"], "kinds": ["XBL (exploit)"]}
        return {"listed": False}

    monkeypatch.setattr(dr_module, "_query_spamhaus_zen", fake_zen)


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------


def test_classify_domain() -> None:
    assert dr_module._classify_target("example.com") == ("domain", "example.com")


def test_classify_ip() -> None:
    assert dr_module._classify_target("1.1.1.1") == ("ip", "1.1.1.1")


def test_classify_url_strips_to_hostname() -> None:
    assert dr_module._classify_target("https://app.example.com/path") == ("domain", "app.example.com")


def test_classify_uppercase_normalizes_to_lowercase() -> None:
    assert dr_module._classify_target("Example.COM") == ("domain", "example.com")


def test_classify_trailing_dot_stripped() -> None:
    assert dr_module._classify_target("example.com.") == ("domain", "example.com")


def test_classify_private_ip_rejected() -> None:
    assert dr_module._classify_target("10.0.0.1")[0] == "invalid"
    assert dr_module._classify_target("127.0.0.1")[0] == "invalid"
    assert dr_module._classify_target("192.168.1.1")[0] == "invalid"


def test_classify_empty_rejected() -> None:
    assert dr_module._classify_target("")[0] == "invalid"
    assert dr_module._classify_target("   ")[0] == "invalid"
    assert dr_module._classify_target(None)[0] == "invalid"  # type: ignore[arg-type]


def test_classify_malformed_rejected() -> None:
    assert dr_module._classify_target("not a domain")[0] == "invalid"


# ---------------------------------------------------------------------------
# IP reversal
# ---------------------------------------------------------------------------


def test_reverse_ip() -> None:
    assert dr_module._reverse_ip("1.2.3.4") == "4.3.2.1"
    assert dr_module._reverse_ip("8.8.4.4") == "4.4.8.8"


def test_reverse_ip_rejects_v6() -> None:
    assert dr_module._reverse_ip("2001:db8::1") is None


def test_reverse_ip_rejects_invalid() -> None:
    assert dr_module._reverse_ip("not-an-ip") is None


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def test_urlhaus_severity_active_high() -> None:
    assert dr_module._urlhaus_severity({"listed": True, "status": "active"}) == "high"


def test_urlhaus_severity_historical_low() -> None:
    assert dr_module._urlhaus_severity({"listed": True, "status": "historical"}) == "low"


def test_urlhaus_severity_clean_none() -> None:
    assert dr_module._urlhaus_severity({"listed": False}) is None


def test_dbl_severity_listed_medium() -> None:
    assert dr_module._spamhaus_dbl_severity({"listed": True}) == "medium"
    assert dr_module._spamhaus_dbl_severity({"listed": False}) is None


def test_zen_severity_listed_low() -> None:
    assert dr_module._spamhaus_zen_severity({"listed": True}) == "low"
    assert dr_module._spamhaus_zen_severity({"listed": False}) is None


def test_gsb_severity_listed_medium() -> None:
    assert dr_module._gsb_severity({"listed": True}) == "medium"
    assert dr_module._gsb_severity({"listed": False}) is None


def test_abuseipdb_severity_bands() -> None:
    assert dr_module._abuseipdb_severity({"listed": True, "abuse_confidence": 80}) == "high"
    assert dr_module._abuseipdb_severity({"listed": True, "abuse_confidence": 50}) == "medium"
    assert dr_module._abuseipdb_severity({"listed": True, "abuse_confidence": 10}) == "low"
    assert dr_module._abuseipdb_severity({"listed": True, "abuse_confidence": 0}) is None
    assert dr_module._abuseipdb_severity({"listed": False}) is None


# ---------------------------------------------------------------------------
# URLhaus integration — active listing → high
# ---------------------------------------------------------------------------


def test_urlhaus_active_emits_high(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "urlhaus-api.abuse.ch" in url:
            return _resp(status=200, body=json.dumps({
                "query_status": "ok",
                "url_count": 5,
                "urlhaus_reference": "https://urlhaus.abuse.ch/host/example.com/",
                "urls": [
                    {"url_status": "online"},
                    {"url_status": "online"},
                    {"url_status": "offline"},
                    {"url_status": "online"},
                    {"url_status": "offline"},
                ],
            }))
        return _resp(status=200, body="{}")

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("malicious.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high
    assert "URLhaus" in high[0]["title"]
    assert high[0]["category"] == "malicious_target"
    assert high[0]["cwe"] == "CWE-453"
    assert out["sources"]["urlhaus"]["status"] == "active"


def test_urlhaus_historical_only_emits_low(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "urlhaus-api.abuse.ch" in url:
            return _resp(status=200, body=json.dumps({
                "query_status": "ok",
                "urlhaus_reference": "https://urlhaus.abuse.ch/...",
                "urls": [
                    {"url_status": "offline"},
                    {"url_status": "offline"},
                ],
            }))
        return _resp(status=200, body="{}")

    _patch_http(monkeypatch, http_responder)
    domain_reputation("oldmalware.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    assert all(r["severity"] != "high" for r in reports)
    low = [r for r in reports if r["severity"] == "low" and "URLhaus" in r["title"]]
    assert low


def test_urlhaus_clean_no_finding(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("clean.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["sources"]["urlhaus"]["listed"] is False


def test_urlhaus_invalid_json_recorded_as_error(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "urlhaus-api.abuse.ch" in url:
            return _resp(status=200, body="not json")
        return _resp(status=200, body="{}")

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("example.com")
    assert "urlhaus" in out["source_errors"]


# ---------------------------------------------------------------------------
# Spamhaus DBL — domain only
# ---------------------------------------------------------------------------


def test_spamhaus_dbl_listed_emits_medium(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[], dbl_listed=True)

    def http_responder(method, url, body, headers):
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("listed.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium" and "DBL" in r["title"]]
    assert medium


def test_spamhaus_dbl_skipped_for_ip(monkeypatch) -> None:
    """For IP targets, DBL is skipped (DBL only takes domains)."""
    _patch_dns(monkeypatch, resolve_ips=[], dbl_listed=False)

    def http_responder(method, url, body, headers):
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("1.1.1.1")
    assert out["sources"]["spamhaus_dbl"].get("skipped") is True


# ---------------------------------------------------------------------------
# Spamhaus ZEN — IP only, multi-IP for domain
# ---------------------------------------------------------------------------


def test_spamhaus_zen_listed_per_ip_emits_low(monkeypatch) -> None:
    _patch_dns(
        monkeypatch,
        resolve_ips=["1.1.1.1"],
        zen_listed_ips=["1.1.1.1"],
    )

    def http_responder(method, url, body, headers):
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    zen = [r for r in reports if r["severity"] == "low" and "ZEN" in r["title"]]
    assert zen
    assert "1.1.1.1" in zen[0]["title"]


def test_spamhaus_zen_runs_per_resolved_ip(monkeypatch) -> None:
    """For a domain that resolves to 3 IPs, ZEN runs against each."""
    _patch_dns(
        monkeypatch,
        resolve_ips=["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        zen_listed_ips=["8.8.8.8"],
    )

    def http_responder(method, url, body, headers):
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("example.com")
    assert len(out["sources"]["spamhaus_zen"]) == 3
    listed_entries = [e for e in out["sources"]["spamhaus_zen"] if e["listed"]]
    assert len(listed_entries) == 1
    assert listed_entries[0]["ip"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------


def test_gsb_skipped_without_key(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "safebrowsing.googleapis" in url:
            pytest.fail("GSB should be skipped without STRIX_GSB_KEY")
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("example.com")
    assert out["sources"]["google_safe_browsing"]["skipped"] is True
    assert "STRIX_GSB_KEY" in out["sources"]["google_safe_browsing"]["reason"]


def test_gsb_flagged_emits_medium(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GSB_KEY", "test-gsb-key")
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "safebrowsing.googleapis" in url:
            assert "key=test-gsb-key" in url
            return _resp(status=200, body=json.dumps({
                "matches": [
                    {"threatType": "MALWARE"},
                    {"threatType": "SOCIAL_ENGINEERING"},
                ],
            }))
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("malicious.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium" and "Google" in r["title"]]
    assert medium


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


def test_abuseipdb_skipped_without_key(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "abuseipdb" in url:
            pytest.fail("AbuseIPDB should be skipped without STRIX_ABUSEIPDB_KEY")
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("1.1.1.1")
    assert out["sources"]["abuseipdb"][0].get("skipped") is True


def test_abuseipdb_high_confidence_emits_high(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ABUSEIPDB_KEY", "test-key")
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "abuseipdb" in url:
            assert headers.get("Key") == "test-key"
            return _resp(status=200, body=json.dumps({
                "data": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 42,
                    "lastReportedAt": "2024-12-01T12:00:00Z",
                    "countryCode": "US",
                },
            }))
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high" and "AbuseIPDB" in r["title"]]
    assert high


def test_abuseipdb_medium_confidence_emits_medium(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ABUSEIPDB_KEY", "test-key")
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "abuseipdb" in url:
            return _resp(status=200, body=json.dumps({
                "data": {"abuseConfidenceScore": 50, "totalReports": 5},
            }))
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium" and "AbuseIPDB" in r["title"]]
    assert medium


# ---------------------------------------------------------------------------
# Per-source dedup
# ---------------------------------------------------------------------------


def test_per_source_dedup_urlhaus_one_finding(monkeypatch) -> None:
    """URLhaus reports many URLs but tool emits ONE URLhaus finding."""
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "urlhaus-api.abuse.ch" in url:
            return _resp(status=200, body=json.dumps({
                "query_status": "ok",
                "urls": [{"url_status": "online"}] * 20,
                "urlhaus_reference": "https://urlhaus.abuse.ch/host/x/",
            }))
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    urlhaus_findings = [r for r in reports if "URLhaus" in r["title"]]
    assert len(urlhaus_findings) == 1


# ---------------------------------------------------------------------------
# Clean target → no findings
# ---------------------------------------------------------------------------


def test_clean_target_no_findings(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out = domain_reputation("clean.example")
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])
    log = _patch_http(monkeypatch, lambda m, u, b, h: _resp(
        status=200, body=json.dumps({"query_status": "no_results"}),
    ))

    out1 = domain_reputation("example.com")
    assert out1["from_cache"] is False
    pre_count = len(log)

    out2 = domain_reputation("example.com")
    assert out2["from_cache"] is True
    assert len(log) == pre_count


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_DOMAIN_REP_NO_CACHE", "1")
    _patch_dns(monkeypatch, resolve_ips=[])
    log = _patch_http(monkeypatch, lambda m, u, b, h: _resp(
        status=200, body=json.dumps({"query_status": "no_results"}),
    ))

    domain_reputation("example.com")
    pre = len(log)
    domain_reputation("example.com")
    assert len(log) > pre


def test_stale_cache_served_on_full_failure(monkeypatch) -> None:
    """All sources fail → stale cache served (fail-open)."""
    _patch_dns(monkeypatch, resolve_ips=[])
    fail_now = [False]  # toggles between first scan + second scan

    def http_responder(method, url, body, headers):
        if fail_now[0]:
            # Second scan: every source errors.
            return {"status": 0, "headers": {}, "body": "", "error": "network unreachable"}
        # First scan: clean response → populate cache.
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    out1 = domain_reputation("example.com")
    assert out1["from_cache"] is False

    # Make cache stale.
    cache_path = dr_module._cache_path("example.com")
    old_mtime = time.time() - 10 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    # Switch responder into failure mode for the second scan.
    fail_now[0] = True

    out2 = domain_reputation("example.com")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GSB_KEY", "k")
    monkeypatch.setenv("STRIX_ABUSEIPDB_KEY", "k")
    _patch_dns(
        monkeypatch,
        resolve_ips=["1.1.1.1"],
        dbl_listed=True,
        zen_listed_ips=["1.1.1.1"],
    )

    def http_responder(method, url, body, headers):
        if "urlhaus-api.abuse.ch" in url:
            return _resp(status=200, body=json.dumps({
                "query_status": "ok",
                "urls": [{"url_status": "online"}],
            }))
        if "safebrowsing.googleapis" in url:
            return _resp(status=200, body=json.dumps({
                "matches": [{"threatType": "MALWARE"}],
            }))
        if "abuseipdb" in url:
            return _resp(status=200, body=json.dumps({
                "data": {"abuseConfidenceScore": 90, "totalReports": 100},
            }))
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("very-bad.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) >= 4  # urlhaus + dbl + zen + gsb + abuseipdb
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "malicious_target"
        assert r["cwe"] == "CWE-453"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])
    _patch_http(monkeypatch, lambda m, u, b, h: _resp(
        status=200, body=json.dumps({"query_status": "no_results"}),
    ))
    domain_reputation("clean.example")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "domain_reputation" in summary["by_category"]
    assert summary["by_category"]["domain_reputation"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])

    def http_responder(method, url, body, headers):
        if "urlhaus-api.abuse.ch" in url:
            return _resp(status=200, body=json.dumps({
                "query_status": "ok",
                "urls": [{"url_status": "online"}],
            }))
        return _resp(status=200, body=json.dumps({"query_status": "no_results"}))

    _patch_http(monkeypatch, http_responder)
    domain_reputation("malicious.example")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["domain_reputation"]["vulnerable"] == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_dns(monkeypatch, resolve_ips=[])
    _patch_http(monkeypatch, lambda m, u, b, h: _resp(
        status=200, body=json.dumps({"query_status": "no_results"}),
    ))
    out = domain_reputation("example.com")
    for k in ("success", "target", "target_type", "queried_at", "from_cache",
              "sources", "source_errors", "findings_emitted"):
        assert k in out
    for k in ("urlhaus", "spamhaus_dbl", "spamhaus_zen", "google_safe_browsing",
              "abuseipdb", "resolved_ips"):
        assert k in out["sources"]


def test_invalid_target_returns_failure(monkeypatch) -> None:
    out = domain_reputation("not-a-thing")
    assert out["success"] is False


def test_private_ip_rejected(monkeypatch) -> None:
    out = domain_reputation("10.0.0.1")
    assert out["success"] is False
