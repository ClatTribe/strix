"""Tests for hibp_breach_check.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- Domain normalization (apex / URL strip / case / trailing dot /
  invalid)
- Per-breach scoring helpers (passwords / recent / mass / sensitive)
- Date parsing
- Filtering (IsFabricated / IsSpamList / IsRetired dropped)
- Severity tier mapping (3+→high, 2→medium, else→low)
- Sort order (severity, recency, pwn_count)
- Per-severity dedup (top 5 per tier in description)
- High / medium / low finding emission tied to score
- HIBP 403 → graceful with stale-cache fallback
- HIBP 200 + empty array → no findings
- HIBP unexpected status → graceful
- HIBP invalid JSON → graceful
- User-Agent header sent (HIBP requires it)
- Cache hit returns from_cache=True
- Stale cache served on network failure
- Cache disabled by env
- §11 UX baseline (description_plain + recommended_action)
- check.completed events
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.hibp_breach.hibp_breach_check  # noqa: F401

hb_module = sys.modules["strix.tools.hibp_breach.hibp_breach_check"]
hibp_breach_check = hb_module.hibp_breach_check


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
    monkeypatch.delenv("STRIX_HIBP_NO_CACHE", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("hb-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=15.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(hb_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _breach(
    *,
    name: str = "TestBreach",
    title: str | None = None,
    breach_date: str = "2024-06-15",
    pwn_count: int = 100_000,
    data_classes: list[str] | None = None,
    is_fabricated: bool = False,
    is_spam: bool = False,
    is_retired: bool = False,
    is_sensitive: bool = False,
) -> dict[str, Any]:
    return {
        "Name": name,
        "Title": title or name,
        "Domain": "example.com",
        "BreachDate": breach_date,
        "PwnCount": pwn_count,
        "DataClasses": data_classes or ["Email addresses"],
        "IsFabricated": is_fabricated,
        "IsSpamList": is_spam,
        "IsRetired": is_retired,
        "IsSensitive": is_sensitive,
        "IsVerified": True,
    }


def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _days_ago_str(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Domain normalization
# ---------------------------------------------------------------------------


def test_normalize_apex() -> None:
    assert hb_module._normalize_domain("example.com") == "example.com"


def test_normalize_uppercase() -> None:
    assert hb_module._normalize_domain("Example.COM") == "example.com"


def test_normalize_trailing_dot() -> None:
    assert hb_module._normalize_domain("example.com.") == "example.com"


def test_normalize_url_strips_to_hostname() -> None:
    assert hb_module._normalize_domain("https://app.example.com/path") == "app.example.com"


def test_normalize_rejects_invalid() -> None:
    assert hb_module._normalize_domain("") is None
    assert hb_module._normalize_domain("not a domain") is None
    assert hb_module._normalize_domain("a." * 200) is None  # > 253 chars
    assert hb_module._normalize_domain(None) is None  # type: ignore[arg-type]


def test_invalid_domain_top_level_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    out = hibp_breach_check("not-a-domain")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Date / scoring helpers
# ---------------------------------------------------------------------------


def test_parse_breach_date_iso() -> None:
    d = hb_module._parse_breach_date("2024-06-15")
    assert d is not None
    assert d.year == 2024
    assert d.month == 6


def test_parse_breach_date_invalid() -> None:
    assert hb_module._parse_breach_date("not-a-date") is None
    assert hb_module._parse_breach_date(None) is None
    assert hb_module._parse_breach_date("") is None


def test_has_passwords() -> None:
    assert hb_module._has_passwords(["Email addresses", "Passwords"]) is True
    assert hb_module._has_passwords(["Email addresses", "Password hashes"]) is True
    assert hb_module._has_passwords(["Email addresses", "Names"]) is False
    assert hb_module._has_passwords([]) is False
    assert hb_module._has_passwords(None) is False


def test_score_breach_passwords_only() -> None:
    score, _ = hb_module._score_breach(_breach(
        breach_date="2010-01-01",
        pwn_count=1000,
        data_classes=["Email addresses", "Passwords"],
    ))
    assert score == 1


def test_score_breach_recent_passwords_mass_sensitive() -> None:
    score, _ = hb_module._score_breach(_breach(
        breach_date=_days_ago_str(90),
        pwn_count=5_000_000,
        data_classes=["Email addresses", "Passwords"],
        is_sensitive=True,
    ))
    assert score == 4


def test_score_to_severity_bands() -> None:
    assert hb_module._score_to_severity(4) == "high"
    assert hb_module._score_to_severity(3) == "high"
    assert hb_module._score_to_severity(2) == "medium"
    assert hb_module._score_to_severity(1) == "low"
    assert hb_module._score_to_severity(0) == "low"


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_filter_drops_fabricated() -> None:
    breaches = [
        _breach(name="Real", is_fabricated=False),
        _breach(name="Fake", is_fabricated=True),
    ]
    out = hb_module._process_breaches(breaches)
    assert {b["name"] for b in out} == {"Real"}


def test_filter_drops_spam_list() -> None:
    breaches = [
        _breach(name="RealBreach"),
        _breach(name="SpamList", is_spam=True),
    ]
    out = hb_module._process_breaches(breaches)
    assert {b["name"] for b in out} == {"RealBreach"}


def test_filter_drops_retired() -> None:
    breaches = [
        _breach(name="Live"),
        _breach(name="Retired", is_retired=True),
    ]
    out = hb_module._process_breaches(breaches)
    assert {b["name"] for b in out} == {"Live"}


def test_filter_keeps_genuine_only() -> None:
    breaches = [_breach(name=f"OK{i}") for i in range(3)]
    out = hb_module._process_breaches(breaches)
    assert len(out) == 3


# ---------------------------------------------------------------------------
# Sort order
# ---------------------------------------------------------------------------


def test_processed_sorted_high_first() -> None:
    breaches = [
        _breach(name="OldSmall", breach_date="2010-01-01", pwn_count=100,
                data_classes=["Email addresses"]),
        _breach(name="MassRecentPwd", breach_date=_days_ago_str(30),
                pwn_count=5_000_000, data_classes=["Email addresses", "Passwords"]),
        _breach(name="RecentMid", breach_date=_days_ago_str(60),
                pwn_count=50_000, data_classes=["Email addresses"]),
    ]
    out = hb_module._process_breaches(breaches)
    assert out[0]["name"] == "MassRecentPwd"
    assert out[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Tool integration — HIGH finding
# ---------------------------------------------------------------------------


def test_high_score_emits_high_finding(monkeypatch) -> None:
    body = json.dumps([
        _breach(
            name="Breach1",
            breach_date=_days_ago_str(60),
            pwn_count=10_000_000,
            data_classes=["Email addresses", "Passwords"],
            is_sensitive=True,
        ),
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = hibp_breach_check("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high
    assert high[0]["category"] == "breach_exposure"
    assert high[0]["cwe"] == "CWE-200"
    assert out["findings_emitted"] == 1
    assert out["breaches"][0]["score"] == 4


def test_medium_score_emits_medium_finding(monkeypatch) -> None:
    """Breach with score=2 → medium finding."""
    body = json.dumps([
        _breach(
            name="Breach1",
            breach_date=_days_ago_str(60),  # +1 recent
            pwn_count=5_000_000,  # +1 mass
            data_classes=["Email addresses"],  # no passwords
            is_sensitive=False,
        ),
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    hibp_breach_check("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium"]
    assert medium
    assert all(r["severity"] != "high" for r in reports)


def test_low_score_emits_low_finding(monkeypatch) -> None:
    """Old breach without passwords → score=0 → low finding."""
    body = json.dumps([
        _breach(
            name="OldBreach",
            breach_date="2008-01-01",  # not recent
            pwn_count=1000,  # not mass
            data_classes=["Email addresses"],  # no passwords
        ),
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    hibp_breach_check("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    low = [r for r in reports if r["severity"] == "low"]
    assert low


# ---------------------------------------------------------------------------
# Per-severity dedup
# ---------------------------------------------------------------------------


def test_per_severity_dedup_one_finding_per_tier(monkeypatch) -> None:
    """5 high-tier breaches → ONE high finding (with top 5 listed)."""
    body = json.dumps([
        _breach(
            name=f"HighBreach{i}",
            breach_date=_days_ago_str(30),
            pwn_count=5_000_000,
            data_classes=["Email addresses", "Passwords"],
            is_sensitive=True,
        )
        for i in range(7)
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    hibp_breach_check("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"
    # Description should mention the 7 breaches and list ≤5 names.
    assert "7 high-severity breach" in reports[0]["title"].lower() or \
           "7 high" in reports[0]["title"]


def test_multiple_severity_tiers_emit_multiple_findings(monkeypatch) -> None:
    """One breach per tier → 3 findings (one per tier)."""
    body = json.dumps([
        _breach(  # high
            name="HighBreach",
            breach_date=_days_ago_str(30), pwn_count=5_000_000,
            data_classes=["Email addresses", "Passwords"], is_sensitive=True,
        ),
        _breach(  # medium
            name="MediumBreach",
            breach_date=_days_ago_str(60), pwn_count=5_000_000,
            data_classes=["Email addresses"],
        ),
        _breach(  # low
            name="OldLowBreach",
            breach_date="2008-01-01", pwn_count=1000,
            data_classes=["Email addresses"],
        ),
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    hibp_breach_check("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    severities = {r["severity"] for r in reports}
    assert severities == {"high", "medium", "low"}


# ---------------------------------------------------------------------------
# No breaches
# ---------------------------------------------------------------------------


def test_empty_response_no_findings(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    out = hibp_breach_check("clean.example")
    assert out["success"] is True
    assert out["breach_count"] == 0
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_only_fabricated_no_findings(monkeypatch) -> None:
    body = json.dumps([
        _breach(name="Fake1", is_fabricated=True),
        _breach(name="Fake2", is_fabricated=True),
        _breach(name="Spam", is_spam=True),
        _breach(name="Old", is_retired=True),
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = hibp_breach_check("example.com")
    assert out["breach_count"] == 0
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


def test_403_no_cache_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=403, body="forbidden"))
    out = hibp_breach_check("example.com")
    assert out["success"] is False
    assert "403" in out["error"]


def test_unexpected_status_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=500, body="server error"))
    out = hibp_breach_check("example.com")
    assert out["success"] is False
    assert "500" in out["error"]


def test_invalid_json_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = hibp_breach_check("example.com")
    assert out["success"] is False
    assert "JSON" in out["error"]


def test_404_treated_as_no_breaches(monkeypatch) -> None:
    """HIBP returns 404 sometimes; treat as no breaches (not error)."""
    _patch_http(monkeypatch, lambda u, h: _resp(status=404, body=""))
    out = hibp_breach_check("clean.example")
    assert out["success"] is True
    assert out["breach_count"] == 0


def test_network_error_no_cache_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: {
        "status": 0, "headers": {}, "body": "", "error": "DNS failure",
    })
    out = hibp_breach_check("example.com")
    assert out["success"] is False
    assert "DNS failure" in out["error"]


# ---------------------------------------------------------------------------
# User-Agent enforcement
# ---------------------------------------------------------------------------


def test_user_agent_header_sent(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    hibp_breach_check("example.com")
    assert "User-Agent" in log[0]["headers"]
    assert log[0]["headers"]["User-Agent"]


def test_url_includes_domain(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    hibp_breach_check("contoso.com")
    assert "domain=contoso.com" in log[0]["url"]
    assert "haveibeenpwned.com" in log[0]["url"]


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    out1 = hibp_breach_check("example.com")
    assert out1["from_cache"] is False
    pre = len(log)

    out2 = hibp_breach_check("example.com")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_HIBP_NO_CACHE", "1")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    hibp_breach_check("example.com")
    pre = len(log)
    hibp_breach_check("example.com")
    assert len(log) > pre


def test_stale_cache_served_on_network_error(monkeypatch) -> None:
    """Populate cache, then force network error → stale cache served."""
    fail_now = [False]
    body = json.dumps([_breach(name="Cached")])

    def responder(url, headers):
        if fail_now[0]:
            return {"status": 0, "headers": {}, "body": "", "error": "network unreachable"}
        return _resp(status=200, body=body)

    _patch_http(monkeypatch, responder)
    out1 = hibp_breach_check("example.com")
    assert out1["from_cache"] is False

    # Make cache stale.
    cache_path = hb_module._cache_path("example.com")
    old_mtime = time.time() - 30 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True

    out2 = hibp_breach_check("example.com")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


def test_stale_cache_served_on_403(monkeypatch) -> None:
    """403 response + stale cache → serve stale."""
    fail_now = [False]

    def responder(url, headers):
        if fail_now[0]:
            return _resp(status=403, body="forbidden")
        return _resp(status=200, body="[]")

    _patch_http(monkeypatch, responder)
    out1 = hibp_breach_check("example.com")
    assert out1["from_cache"] is False

    cache_path = hb_module._cache_path("example.com")
    old_mtime = time.time() - 30 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True

    out2 = hibp_breach_check("example.com")
    assert out2["from_cache"] is True
    assert "403" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    body = json.dumps([
        _breach(  # high
            name="HighBreach",
            breach_date=_days_ago_str(30), pwn_count=5_000_000,
            data_classes=["Email addresses", "Passwords"], is_sensitive=True,
        ),
        _breach(  # medium
            name="MediumBreach",
            breach_date=_days_ago_str(60), pwn_count=5_000_000,
            data_classes=["Email addresses"],
        ),
    ])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    hibp_breach_check("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "breach_exposure"
        assert r["cwe"] == "CWE-200"
        assert r.get("verification_status") == "verified"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="[]"))
    hibp_breach_check("clean.example")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "hibp_breach" in summary["by_category"]
    assert summary["by_category"]["hibp_breach"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    body = json.dumps([_breach(
        breach_date=_days_ago_str(30), pwn_count=5_000_000,
        data_classes=["Email addresses", "Passwords"], is_sensitive=True,
    )])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    hibp_breach_check("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["hibp_breach"]
    assert cat["vulnerable"] == 1


def test_check_event_inconclusive_on_403(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=403, body=""))
    hibp_breach_check("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["hibp_breach"]
    assert cat.get("inconclusive", 0) == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    body = json.dumps([_breach()])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = hibp_breach_check("example.com")
    for k in ("success", "domain", "queried_at", "from_cache",
              "breach_count", "breaches", "findings_emitted"):
        assert k in out
    if out["breaches"]:
        for k in ("name", "title", "breach_date", "pwn_count",
                  "data_classes", "has_passwords", "is_recent",
                  "is_mass", "is_sensitive", "score", "severity"):
            assert k in out["breaches"][0]
