"""Tests for otx_lookup.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- IoC type detection (IPv4/IPv6/domain/md5/sha1/sha256/url/CVE,
  invalid/private rejected)
- OTX endpoint construction per IoC type (URL-encoded for URL type)
- Severity derivation (≥3 → high, 1-2 → medium, 0 → none)
- No STRIX_OTX_KEY → success=False, no HTTP
- 404 → no_data=True, success
- 401 / non-200 / invalid JSON / network → graceful failure with
  stale-cache fallback
- Successful query → pulses extracted, finding emitted at correct
  severity
- Pulses curated subset preserved (id/name/author/modified/tags/etc.)
- General fields curated subset preserved (country_code/asn/etc.)
- Cache hit returns from_cache=True, re-emits findings
- Cache disabled via env
- Stale cache served on failure
- X-OTX-API-KEY header sent
- §11 UX (description_plain + recommended_action + needs_review)
- check.completed events
- Result schema integrity
- Top 5 pulses cap
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any
from urllib.parse import quote

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.otx_lookup.otx_lookup  # noqa: F401

otx_module = sys.modules["strix.tools.otx_lookup.otx_lookup"]
otx_lookup = otx_module.otx_lookup


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
    monkeypatch.delenv("STRIX_OTX_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_OTX_KEY", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("otx-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=15.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(otx_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _otx_body(
    *,
    pulse_count: int = 0,
    pulses: list[dict[str, Any]] | None = None,
    indicator: str = "1.2.3.4",
    indicator_type: str = "IPv4",
    country_code: str = "US",
) -> str:
    return json.dumps({
        "indicator": indicator,
        "type": indicator_type,
        "country_code": country_code,
        "asn": "AS15169",
        "pulse_info": {
            "count": pulse_count,
            "pulses": pulses or [],
        },
    })


def _pulse(
    *,
    name: str = "Test Campaign",
    author: str = "researcher42",
    pulse_id: str = "abc123",
    tags: list[str] | None = None,
    description: str = "Test threat campaign description",
    modified: str = "2024-12-01T00:00:00",
) -> dict[str, Any]:
    return {
        "id": pulse_id,
        "name": name,
        "author": {"username": author},
        "modified": modified,
        "created": "2024-11-01T00:00:00",
        "tags": tags or ["malware", "apt"],
        "description": description,
        "TLP": "white",
        "industries": ["technology"],
        "targeted_countries": ["United States"],
    }


# ---------------------------------------------------------------------------
# IoC type detection
# ---------------------------------------------------------------------------


def test_detect_ipv4() -> None:
    assert otx_module._detect_ioc_type("8.8.8.8") == ("IPv4", "8.8.8.8")


def test_detect_ipv6() -> None:
    out = otx_module._detect_ioc_type("2001:4860:4860::8888")
    assert out is not None
    assert out[0] == "IPv6"


def test_detect_private_ip_rejected() -> None:
    assert otx_module._detect_ioc_type("10.0.0.1") is None
    assert otx_module._detect_ioc_type("127.0.0.1") is None


def test_detect_domain() -> None:
    assert otx_module._detect_ioc_type("example.com") == ("domain", "example.com")


def test_detect_md5() -> None:
    h = "44d88612fea8a8f36de82e1278abb02f"
    assert otx_module._detect_ioc_type(h) == ("file-md5", h)


def test_detect_sha1() -> None:
    h = "3395856ce81f2b7382dee72602f798b642f14140"
    assert otx_module._detect_ioc_type(h) == ("file-sha1", h)


def test_detect_sha256() -> None:
    h = "a" * 64
    assert otx_module._detect_ioc_type(h) == ("file-sha256", h)


def test_detect_url() -> None:
    out = otx_module._detect_ioc_type("https://evil.example/payload.exe")
    assert out == ("url", "https://evil.example/payload.exe")


def test_detect_cve() -> None:
    out = otx_module._detect_ioc_type("cve-2021-44228")
    assert out == ("cve", "CVE-2021-44228")


def test_detect_invalid() -> None:
    assert otx_module._detect_ioc_type("") is None
    assert otx_module._detect_ioc_type("not-a-thing") is None
    assert otx_module._detect_ioc_type(None) is None  # type: ignore[arg-type]


def test_invalid_top_level_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call"))
    out = otx_lookup("not-a-thing")
    assert out["success"] is False
    assert log == []


# ---------------------------------------------------------------------------
# Endpoint construction
# ---------------------------------------------------------------------------


def test_endpoint_ipv4() -> None:
    url = otx_module._otx_endpoint_for("IPv4", "1.2.3.4")
    assert url.endswith("/IPv4/1.2.3.4/general")


def test_endpoint_ipv6() -> None:
    url = otx_module._otx_endpoint_for("IPv6", "2001:db8::1")
    assert url.endswith("/IPv6/2001:db8::1/general")


def test_endpoint_domain() -> None:
    url = otx_module._otx_endpoint_for("domain", "example.com")
    assert url.endswith("/domain/example.com/general")


def test_endpoint_file() -> None:
    url = otx_module._otx_endpoint_for("file-md5", "abc123")
    assert url.endswith("/file/abc123/general")


def test_endpoint_url_encoded() -> None:
    url = otx_module._otx_endpoint_for("url", "https://evil.example/path")
    expected = quote("https://evil.example/path", safe="")
    assert url.endswith(f"/url/{expected}/general")


def test_endpoint_cve() -> None:
    url = otx_module._otx_endpoint_for("cve", "CVE-2021-44228")
    assert url.endswith("/cve/CVE-2021-44228/general")


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def test_severity_high_at_3() -> None:
    assert otx_module._derive_severity(3) == "high"


def test_severity_high_at_10() -> None:
    assert otx_module._derive_severity(10) == "high"


def test_severity_medium_1_or_2() -> None:
    assert otx_module._derive_severity(1) == "medium"
    assert otx_module._derive_severity(2) == "medium"


def test_severity_none_at_zero() -> None:
    assert otx_module._derive_severity(0) is None


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_no_api_key_returns_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call HTTP"))
    out = otx_lookup("8.8.8.8")
    assert out["success"] is False
    assert "STRIX_OTX_KEY" in out["error"]
    assert log == []


def test_apikey_header_sent(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "test-otx-key")
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("X-OTX-API-KEY", ""))
        return _resp(status=200, body=_otx_body())

    _patch_http(monkeypatch, responder)
    otx_lookup("8.8.8.8")
    assert captured == ["test-otx-key"]


# ---------------------------------------------------------------------------
# Successful queries
# ---------------------------------------------------------------------------


def test_high_severity_emits_high_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(
        pulse_count=5,
        pulses=[
            _pulse(name=f"Campaign {i}", pulse_id=f"id-{i}")
            for i in range(5)
        ],
    )
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = otx_lookup("1.2.3.4")
    assert out["success"] is True
    assert out["pulse_count"] == 5
    assert out["severity"] == "high"
    assert len(out["pulses"]) == 5

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"
    assert reports[0]["category"] == "malicious_target"
    assert reports[0]["cwe"] == "CWE-453"


def test_medium_severity_emits_medium_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(pulse_count=2, pulses=[_pulse(), _pulse(pulse_id="2")])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = otx_lookup("evil.example")
    assert out["severity"] == "medium"


def test_no_pulses_no_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(pulse_count=0, pulses=[])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = otx_lookup("safe.example")
    assert out["pulse_count"] == 0
    assert out["severity"] is None
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_pulses_capped_at_5(monkeypatch) -> None:
    """Even when OTX returns 20 pulses, we keep only top 5 in result."""
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(
        pulse_count=20,
        pulses=[_pulse(pulse_id=f"p-{i}") for i in range(20)],
    )
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = otx_lookup("1.2.3.4")
    assert out["pulse_count"] == 20
    assert len(out["pulses"]) == 5  # capped


def test_pulse_curated_subset_preserved(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(
        pulse_count=1,
        pulses=[_pulse(
            name="APT29 Q4",
            author="alice",
            pulse_id="pulse-99",
            tags=["apt29", "ssh"],
            description="Lateral-movement campaign",
            modified="2024-12-15",
        )],
    )
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = otx_lookup("1.2.3.4")
    p = out["pulses"][0]
    assert p["id"] == "pulse-99"
    assert p["name"] == "APT29 Q4"
    assert p["author"] == "alice"
    assert p["tags"] == ["apt29", "ssh"]
    assert p["modified"] == "2024-12-15"


def test_general_subset_preserved(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(country_code="RU")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = otx_lookup("1.2.3.4")
    assert out["general"]["country_code"] == "RU"
    assert out["general"]["asn"] == "AS15169"


# ---------------------------------------------------------------------------
# 404 / errors
# ---------------------------------------------------------------------------


def test_404_no_data_success(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=404))
    out = otx_lookup("1.2.3.4")
    assert out["success"] is True
    assert out["no_data"] is True
    assert out["pulse_count"] == 0


def test_401_no_cache_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "bad")
    _patch_http(monkeypatch, lambda u, h: _resp(status=401))
    out = otx_lookup("1.2.3.4")
    assert out["success"] is False


def test_invalid_json_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = otx_lookup("1.2.3.4")
    assert out["success"] is False


def test_network_error_no_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: {"status": 0, "headers": {}, "body": "", "error": "DNS"})
    out = otx_lookup("1.2.3.4")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(pulse_count=5, pulses=[_pulse() for _ in range(5)])
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out1 = otx_lookup("1.2.3.4")
    assert out1["from_cache"] is False
    pre = len(log)
    out2 = otx_lookup("1.2.3.4")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_re_emits_findings(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(pulse_count=5, pulses=[_pulse() for _ in range(5)])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    otx_lookup("1.2.3.4")
    tracer = tracer_module.get_global_tracer()
    tracer.vulnerability_reports.clear()  # type: ignore[attr-defined]
    out2 = otx_lookup("1.2.3.4")
    assert out2["from_cache"] is True
    reports = tracer.get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_NO_CACHE", "1")
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body()
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    otx_lookup("1.2.3.4")
    pre = len(log)
    otx_lookup("1.2.3.4")
    assert len(log) > pre


def test_stale_cache_served_on_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    fail_now = [False]
    body = _otx_body(pulse_count=5, pulses=[_pulse() for _ in range(5)])

    def responder(url, h):
        if fail_now[0]:
            return _resp(status=500)
        return _resp(status=200, body=body)

    _patch_http(monkeypatch, responder)
    out1 = otx_lookup("1.2.3.4")
    assert out1["from_cache"] is False

    cache_path = otx_module._cache_path("IPv4", "1.2.3.4")
    old_mtime = time.time() - 12 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True
    out2 = otx_lookup("1.2.3.4")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(pulse_count=5, pulses=[_pulse() for _ in range(5)])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    otx_lookup("1.2.3.4")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    for r in reports:
        assert r.get("description_plain")
        assert r.get("recommended_action")
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_otx_body()))
    otx_lookup("1.2.3.4")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["otx_lookup"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    body = _otx_body(pulse_count=5, pulses=[_pulse() for _ in range(5)])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    otx_lookup("1.2.3.4")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["otx_lookup"]["vulnerable"] == 1


def test_check_event_inconclusive_without_key(monkeypatch) -> None:
    otx_lookup("1.2.3.4")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["otx_lookup"]["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OTX_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_otx_body()))
    out = otx_lookup("1.2.3.4")
    for k in ("success", "ioc", "ioc_type", "otx_url", "queried_at",
              "from_cache", "pulse_count", "severity", "pulses",
              "general", "findings_emitted"):
        assert k in out
