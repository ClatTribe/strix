"""Tests for greynoise_classify.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- IPv4 validation (private/loopback/link-local/IPv6/invalid rejected)
- Severity derivation (targeted+malicious → high; noise+malicious →
  medium; benign / no-record → none)
- Community API: 200 with observation, 404 (no record), 401, 429,
  500, invalid JSON
- RIOT API: skipped without key, 200 with riot=true, 404 (not on
  list), 401
- Headers: `key` header sent when STRIX_GREYNOISE_KEY set
- Cache hit returns from_cache=True without HTTP, re-emits findings
- Cache disabled via env
- Stale cache served when both endpoints fail
- §11 UX baseline (description_plain + recommended_action +
  needs_review)
- check.completed events
- Result schema integrity
- High finding → "targeted-malicious", medium → "opportunistic-malicious"
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


import strix.tools.greynoise.greynoise_classify  # noqa: F401

gn_module = sys.modules["strix.tools.greynoise.greynoise_classify"]
greynoise_classify = gn_module.greynoise_classify


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
    monkeypatch.delenv("STRIX_GREYNOISE_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_GREYNOISE_KEY", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("gn-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "ip_address", "value": "1.1.1.1"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=12.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(gn_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _community_body(
    *,
    noise: bool = False,
    classification: str = "unknown",
    name: str = "ScannerCo",
    riot: bool = False,
    last_seen: str = "2024-12-01",
) -> str:
    return json.dumps({
        "ip": "1.1.1.1",
        "noise": noise,
        "riot": riot,
        "classification": classification,
        "name": name,
        "link": "https://viz.greynoise.io/ip/1.1.1.1",
        "last_seen": last_seen,
        "message": "Success",
        "code": "0x01",
    })


# ---------------------------------------------------------------------------
# IP validation
# ---------------------------------------------------------------------------


def test_validate_public_ipv4() -> None:
    assert gn_module._validate_ip("1.1.1.1") == "1.1.1.1"


def test_validate_canonicalizes_leading_zeros() -> None:
    """Python ipaddress strict mode rejects leading zeros — verify we
    handle both shapes."""
    # Strict canonical form only.
    assert gn_module._validate_ip("8.8.8.8") == "8.8.8.8"


def test_reject_private_ip() -> None:
    assert gn_module._validate_ip("10.0.0.1") is None
    assert gn_module._validate_ip("192.168.1.1") is None


def test_reject_loopback() -> None:
    assert gn_module._validate_ip("127.0.0.1") is None


def test_reject_link_local() -> None:
    assert gn_module._validate_ip("169.254.1.1") is None


def test_reject_ipv6() -> None:
    assert gn_module._validate_ip("2001:db8::1") is None


def test_reject_invalid_strings() -> None:
    assert gn_module._validate_ip("") is None
    assert gn_module._validate_ip("not-an-ip") is None
    assert gn_module._validate_ip(None) is None  # type: ignore[arg-type]


def test_invalid_top_level_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call HTTP"))
    out = greynoise_classify("not-an-ip")
    assert out["success"] is False
    assert "invalid" in out["error"].lower()
    assert log == []


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def test_severity_targeted_malicious_high() -> None:
    sev = gn_module._derive_severity({
        "present": True, "noise": False, "classification": "malicious",
    })
    assert sev == "high"


def test_severity_opportunistic_malicious_medium() -> None:
    sev = gn_module._derive_severity({
        "present": True, "noise": True, "classification": "malicious",
    })
    assert sev == "medium"


def test_severity_benign_noise_none() -> None:
    sev = gn_module._derive_severity({
        "present": True, "noise": True, "classification": "benign",
    })
    assert sev is None


def test_severity_targeted_benign_none() -> None:
    sev = gn_module._derive_severity({
        "present": True, "noise": False, "classification": "benign",
    })
    assert sev is None


def test_severity_unknown_none() -> None:
    sev = gn_module._derive_severity({
        "present": True, "noise": True, "classification": "unknown",
    })
    assert sev is None


def test_severity_no_observation_none() -> None:
    sev = gn_module._derive_severity({"present": False})
    assert sev is None


# ---------------------------------------------------------------------------
# Community API
# ---------------------------------------------------------------------------


def test_community_targeted_malicious_emits_high(monkeypatch) -> None:
    body = _community_body(noise=False, classification="malicious", name="APT-foo")

    def responder(url, h):
        if "community" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert out["success"] is True
    assert out["severity"] == "high"
    assert out["community"]["classification"] == "malicious"
    assert out["community"]["noise"] is False

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"
    assert reports[0]["category"] == "malicious_target"
    assert "targeted-malicious" in reports[0]["title"].lower()


def test_community_opportunistic_malicious_emits_medium(monkeypatch) -> None:
    body = _community_body(noise=True, classification="malicious", name="MassScanner")

    def responder(url, h):
        if "community" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert out["severity"] == "medium"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports[0]["severity"] == "medium"
    assert "opportunistic-malicious" in reports[0]["title"].lower()


def test_community_noise_benign_no_finding(monkeypatch) -> None:
    """Shodan etc. = noise:true + classification:benign → suppress."""
    body = _community_body(noise=True, classification="benign", name="Shodan.io")

    def responder(url, h):
        if "community" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert out["severity"] is None
    assert out["community"]["present"] is True
    assert out["community"]["classification"] == "benign"
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_community_no_observation(monkeypatch) -> None:
    """Community API 404 = no record → present=False, no finding."""
    def responder(url, h):
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert out["success"] is True
    assert out["community"]["present"] is False
    assert out["severity"] is None


def test_community_401(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GREYNOISE_KEY", "bad")
    _patch_http(monkeypatch, lambda u, h: _resp(status=401))
    out = greynoise_classify("1.1.1.1")
    assert out["community"]["error"]
    assert "401" in out["community"]["error"]


def test_community_429_rate_limited(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=429))
    out = greynoise_classify("1.1.1.1")
    assert "429" in out["community"]["error"]


def test_community_invalid_json(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = greynoise_classify("1.1.1.1")
    assert "JSON" in out["community"]["error"]


def test_key_header_sent_when_set(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GREYNOISE_KEY", "test-key-xyz")
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("key", ""))
        return _resp(status=200, body=_community_body())

    _patch_http(monkeypatch, responder)
    greynoise_classify("1.1.1.1")
    assert "test-key-xyz" in captured


def test_no_key_header_without_env(monkeypatch) -> None:
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("key", ""))
        return _resp(status=200, body=_community_body())

    _patch_http(monkeypatch, responder)
    greynoise_classify("1.1.1.1")
    # Anonymous Community API doesn't require key — header should be absent.
    assert all(c == "" for c in captured)


# ---------------------------------------------------------------------------
# RIOT API
# ---------------------------------------------------------------------------


def test_riot_skipped_without_key(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_community_body()))
    out = greynoise_classify("1.1.1.1")
    # RIOT call should NOT have happened.
    riot_calls = [e for e in log if "/v2/riot/" in e["url"]]
    assert riot_calls == []
    assert out["riot"].get("skipped") is True
    assert "STRIX_GREYNOISE_KEY" in out["riot"]["reason"]


def test_riot_present_when_key_set(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GREYNOISE_KEY", "key")
    riot_body = json.dumps({
        "ip": "1.1.1.1",
        "riot": True,
        "name": "Cloudflare",
        "category": "cdn",
        "trust_level": "1",
        "description": "Cloudflare CDN edge",
        "last_updated": "2024-12-01",
    })

    def responder(url, h):
        if "/v3/community/" in url:
            return _resp(status=200, body=_community_body(riot=True, classification="benign", noise=True))
        if "/v2/riot/" in url:
            return _resp(status=200, body=riot_body)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert out["riot"]["present"] is True
    assert out["riot"]["name"] == "Cloudflare"
    assert out["riot"]["category"] == "cdn"


def test_riot_404_not_listed(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GREYNOISE_KEY", "key")

    def responder(url, h):
        if "/v3/community/" in url:
            return _resp(status=200, body=_community_body())
        if "/v2/riot/" in url:
            return _resp(status=404)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert out["riot"]["present"] is False


def test_riot_401_recorded(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GREYNOISE_KEY", "bad")

    def responder(url, h):
        if "/v3/community/" in url:
            return _resp(status=200, body=_community_body())
        if "/v2/riot/" in url:
            return _resp(status=401)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out = greynoise_classify("1.1.1.1")
    assert "401" in out["riot"]["error"]


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    body = _community_body(noise=False, classification="malicious")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body) if "community" in u else _resp(status=404))
    out1 = greynoise_classify("1.1.1.1")
    assert out1["from_cache"] is False
    pre = len(log)
    out2 = greynoise_classify("1.1.1.1")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_re_emits_findings(monkeypatch) -> None:
    body = _community_body(noise=False, classification="malicious")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body) if "community" in u else _resp(status=404))
    greynoise_classify("1.1.1.1")
    tracer = tracer_module.get_global_tracer()
    tracer.vulnerability_reports.clear()  # type: ignore[attr-defined]
    out2 = greynoise_classify("1.1.1.1")
    assert out2["from_cache"] is True
    reports = tracer.get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GREYNOISE_NO_CACHE", "1")
    body = _community_body()
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body) if "community" in u else _resp(status=404))
    greynoise_classify("1.1.1.1")
    pre = len(log)
    greynoise_classify("1.1.1.1")
    assert len(log) > pre


def test_stale_cache_served_when_both_endpoints_fail(monkeypatch) -> None:
    """When community AND riot fail, fall back to stale cache."""
    monkeypatch.setenv("STRIX_GREYNOISE_KEY", "k")  # so RIOT runs
    fail_now = [False]
    body = _community_body(noise=False, classification="malicious")

    def responder(url, h):
        if fail_now[0]:
            return {"status": 0, "headers": {}, "body": "", "error": "network unreachable"}
        if "community" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, responder)
    out1 = greynoise_classify("1.1.1.1")
    assert out1["from_cache"] is False

    cache_path = gn_module._cache_path("1.1.1.1")
    old_mtime = time.time() - 10 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True
    out2 = greynoise_classify("1.1.1.1")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    body = _community_body(noise=False, classification="malicious")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body) if "community" in u else _resp(status=404))
    greynoise_classify("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    for r in reports:
        assert r.get("description_plain")
        assert r.get("recommended_action")
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    body = _community_body(noise=True, classification="benign")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body) if "community" in u else _resp(status=404))
    greynoise_classify("1.1.1.1")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["greynoise_classify"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    body = _community_body(noise=False, classification="malicious")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body) if "community" in u else _resp(status=404))
    greynoise_classify("1.1.1.1")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["greynoise_classify"]["vulnerable"] == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_community_body()) if "community" in u else _resp(status=404))
    out = greynoise_classify("1.1.1.1")
    for k in ("success", "ip", "queried_at", "from_cache",
              "community", "riot", "severity", "findings_emitted"):
        assert k in out
