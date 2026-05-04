"""Tests for vt_reputation.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- IoC type detection (md5/sha1/sha256/sha512/ip/domain/url, with
  rejection of private IPs / invalid shapes)
- VT endpoint construction per IoC type (URL base64-encoded)
- Severity derivation (high ≥10 / medium ≥3 / low ≥1 / none = 0)
- No STRIX_VT_KEY → success=False with clear error, no HTTP
- 401 → graceful failure with stale-cache fallback
- 404 → no_data=True, success
- non-200 / invalid JSON → graceful
- Successful IP / domain / URL / hash queries → finding emitted at
  correct severity
- Flagging engine list extracted from per-engine results
- Attributes subset (country_code / as_owner / categories) preserved
- Cache hit returns from_cache=True without HTTP, re-emits findings
- Cache disabled via env
- Stale-cache served on failure
- §11 UX (description_plain + recommended_action + needs_review)
- check.completed events
- Result schema integrity
- x-apikey header sent
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


import strix.tools.vt_reputation.vt_reputation  # noqa: F401

vt_module = sys.modules["strix.tools.vt_reputation.vt_reputation"]
vt_reputation = vt_module.vt_reputation


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
    monkeypatch.delenv("STRIX_VT_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_VT_KEY", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("vt-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=15.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(vt_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _vt_body(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 0,
    undetected: int = 70,
    flagging_engines: list[str] | None = None,
    reputation: int = 0,
    attributes_extra: dict[str, Any] | None = None,
) -> str:
    results = {}
    for name in flagging_engines or []:
        results[name] = {"category": "malicious", "result": "trojan.foo"}
    attrs: dict[str, Any] = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": 0,
        },
        "last_analysis_results": results,
        "last_analysis_date": 1700000000,
        "reputation": reputation,
    }
    if attributes_extra:
        attrs.update(attributes_extra)
    return json.dumps({"data": {"attributes": attrs}})


# ---------------------------------------------------------------------------
# IoC type detection
# ---------------------------------------------------------------------------


def test_detect_md5() -> None:
    out = vt_module._detect_ioc_type("44d88612fea8a8f36de82e1278abb02f")
    assert out == ("hash-md5", "44d88612fea8a8f36de82e1278abb02f")


def test_detect_sha1() -> None:
    out = vt_module._detect_ioc_type("3395856ce81f2b7382dee72602f798b642f14140")
    assert out == ("hash-sha1", "3395856ce81f2b7382dee72602f798b642f14140")


def test_detect_sha256() -> None:
    out = vt_module._detect_ioc_type("a" * 64)
    assert out == ("hash-sha256", "a" * 64)


def test_detect_sha512() -> None:
    out = vt_module._detect_ioc_type("a" * 128)
    assert out == ("hash-sha512", "a" * 128)


def test_detect_uppercase_hash_lowered() -> None:
    out = vt_module._detect_ioc_type("ABCDEF" + "0" * 26)  # 32-char hex
    assert out is not None
    assert out[1] == ("ABCDEF" + "0" * 26).lower()


def test_detect_ip() -> None:
    out = vt_module._detect_ioc_type("8.8.8.8")
    assert out == ("ip", "8.8.8.8")


def test_detect_private_ip_rejected() -> None:
    assert vt_module._detect_ioc_type("10.0.0.1") is None
    assert vt_module._detect_ioc_type("127.0.0.1") is None
    assert vt_module._detect_ioc_type("192.168.1.1") is None


def test_detect_domain() -> None:
    out = vt_module._detect_ioc_type("example.com")
    assert out == ("domain", "example.com")


def test_detect_subdomain() -> None:
    out = vt_module._detect_ioc_type("evil.example.com")
    assert out == ("domain", "evil.example.com")


def test_detect_url_https() -> None:
    out = vt_module._detect_ioc_type("https://evil.example/payload.exe")
    assert out == ("url", "https://evil.example/payload.exe")


def test_detect_url_http() -> None:
    out = vt_module._detect_ioc_type("http://evil.example/")
    assert out == ("url", "http://evil.example/")


def test_detect_invalid() -> None:
    assert vt_module._detect_ioc_type("") is None
    assert vt_module._detect_ioc_type("not a thing") is None
    assert vt_module._detect_ioc_type(None) is None  # type: ignore[arg-type]
    # 33-char hex isn't a known hash length.
    assert vt_module._detect_ioc_type("a" * 33) is None


def test_detect_uppercase_domain_lowered() -> None:
    out = vt_module._detect_ioc_type("Example.COM")
    assert out == ("domain", "example.com")


# ---------------------------------------------------------------------------
# Endpoint construction
# ---------------------------------------------------------------------------


def test_endpoint_hash() -> None:
    url = vt_module._vt_endpoint_for("hash-md5", "44d88612fea8a8f36de82e1278abb02f")
    assert url.endswith("/files/44d88612fea8a8f36de82e1278abb02f")


def test_endpoint_ip() -> None:
    url = vt_module._vt_endpoint_for("ip", "1.2.3.4")
    assert url.endswith("/ip_addresses/1.2.3.4")


def test_endpoint_domain() -> None:
    url = vt_module._vt_endpoint_for("domain", "example.com")
    assert url.endswith("/domains/example.com")


def test_endpoint_url_base64_encoded() -> None:
    url = vt_module._vt_endpoint_for("url", "https://evil.example/")
    expected_id = base64.urlsafe_b64encode(b"https://evil.example/").rstrip(b"=").decode("ascii")
    assert url.endswith(f"/urls/{expected_id}")


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def test_severity_high_at_10_malicious() -> None:
    sev, _ = vt_module._derive_severity({"malicious": 10})
    assert sev == "high"


def test_severity_high_at_50() -> None:
    sev, _ = vt_module._derive_severity({"malicious": 50, "suspicious": 5})
    assert sev == "high"


def test_severity_medium_3_to_9() -> None:
    sev, _ = vt_module._derive_severity({"malicious": 3, "suspicious": 0})
    assert sev == "medium"
    sev, _ = vt_module._derive_severity({"malicious": 5, "suspicious": 4})
    assert sev == "medium"


def test_severity_low_1_or_2() -> None:
    sev, _ = vt_module._derive_severity({"malicious": 1, "suspicious": 0})
    assert sev == "low"
    sev, _ = vt_module._derive_severity({"malicious": 0, "suspicious": 2})
    assert sev == "low"


def test_severity_none_when_clean() -> None:
    sev, _ = vt_module._derive_severity({"malicious": 0, "suspicious": 0, "harmless": 50})
    assert sev is None


def test_severity_handles_missing_stats() -> None:
    sev, norm = vt_module._derive_severity({})
    assert sev is None
    assert norm["malicious"] == 0


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_no_api_key_returns_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call HTTP"))
    out = vt_reputation("8.8.8.8")
    assert out["success"] is False
    assert "STRIX_VT_KEY" in out["error"]
    assert log == []


def test_invalid_ioc_top_level_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call HTTP"))
    out = vt_reputation("not-a-thing")
    assert out["success"] is False
    assert "could not classify" in out["error"]
    assert log == []


def test_apikey_header_sent(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "test-key-123")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_vt_body()))
    vt_reputation("8.8.8.8")
    assert log[0]["headers"].get("x-apikey") == "test-key-123"


# ---------------------------------------------------------------------------
# Successful queries
# ---------------------------------------------------------------------------


def test_high_severity_emits_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(
        malicious=15, suspicious=2, harmless=40, undetected=15,
        flagging_engines=["Microsoft", "Kaspersky", "ESET-NOD32"],
        attributes_extra={"country_code": "RU", "as_owner": "EvilHost"},
    )
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = vt_reputation("1.2.3.4")
    assert out["success"] is True
    assert out["severity"] == "high"
    assert out["stats"]["malicious"] == 15
    assert "Microsoft" in out["flagging_engines"]
    assert out["attributes"]["country_code"] == "RU"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"
    assert reports[0]["category"] == "malicious_target"
    assert reports[0]["cwe"] == "CWE-453"


def test_medium_severity_emits_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=4, suspicious=1, flagging_engines=["A", "B", "C", "D", "E"])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    vt_reputation("evil.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports[0]["severity"] == "medium"


def test_low_severity_emits_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=1, flagging_engines=["A"])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    vt_reputation("evil.example")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports[0]["severity"] == "low"


def test_clean_no_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=0, suspicious=0, harmless=70)
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = vt_reputation("safe.example")
    assert out["severity"] is None
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_url_query_uses_base64_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_vt_body()))
    vt_reputation("https://evil.example/payload")
    expected_id = base64.urlsafe_b64encode(
        b"https://evil.example/payload"
    ).rstrip(b"=").decode("ascii")
    assert any(expected_id in entry["url"] for entry in log)


def test_hash_query_uses_files_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_vt_body()))
    h = "44d88612fea8a8f36de82e1278abb02f"
    vt_reputation(h)
    assert any(f"/files/{h}" in entry["url"] for entry in log)


# ---------------------------------------------------------------------------
# Error / 404 handling
# ---------------------------------------------------------------------------


def test_404_no_data_success(monkeypatch) -> None:
    """VT 404 = no data on this IoC; treat as success with no_data=True."""
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=404))
    out = vt_reputation("8.8.8.8")
    assert out["success"] is True
    assert out["no_data"] is True
    assert out["stats"] == {}


def test_401_no_cache_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "bad")
    _patch_http(monkeypatch, lambda u, h: _resp(status=401, body="unauthorized"))
    out = vt_reputation("8.8.8.8")
    assert out["success"] is False


def test_invalid_json_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = vt_reputation("8.8.8.8")
    assert out["success"] is False
    assert "JSON" in out["error"]


def test_network_error_no_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: {"status": 0, "headers": {}, "body": "", "error": "DNS failure"})
    out = vt_reputation("8.8.8.8")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=12, flagging_engines=["A", "B"])
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out1 = vt_reputation("8.8.8.8")
    assert out1["from_cache"] is False
    pre = len(log)
    out2 = vt_reputation("8.8.8.8")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_re_emits_findings(monkeypatch) -> None:
    """Cache hit re-emits findings from cached stats."""
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=12, flagging_engines=["A"])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    vt_reputation("8.8.8.8")
    # Reset tracer to count second-call findings only.
    tracer = tracer_module.get_global_tracer()
    tracer.vulnerability_reports.clear()  # type: ignore[attr-defined]
    out2 = vt_reputation("8.8.8.8")
    assert out2["from_cache"] is True
    reports = tracer.get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_NO_CACHE", "1")
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body()
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    vt_reputation("8.8.8.8")
    pre = len(log)
    vt_reputation("8.8.8.8")
    assert len(log) > pre


def test_stale_cache_served_on_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    fail_now = [False]
    body = _vt_body(malicious=15, flagging_engines=["A"])

    def responder(url, headers):
        if fail_now[0]:
            return _resp(status=500)
        return _resp(status=200, body=body)

    _patch_http(monkeypatch, responder)
    out1 = vt_reputation("8.8.8.8")
    assert out1["from_cache"] is False

    cache_path = vt_module._cache_path("ip", "8.8.8.8")
    old_mtime = time.time() - 12 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True
    out2 = vt_reputation("8.8.8.8")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=15, flagging_engines=["Microsoft"])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    vt_reputation("1.2.3.4")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    for r in reports:
        assert r.get("description_plain")
        assert r.get("recommended_action")
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_vt_body()))
    vt_reputation("safe.example")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert "vt_reputation" in summary["by_category"]
    assert summary["by_category"]["vt_reputation"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    body = _vt_body(malicious=15, flagging_engines=["A"])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    vt_reputation("evil.example")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["vt_reputation"]["vulnerable"] == 1


def test_check_event_inconclusive_without_key(monkeypatch) -> None:
    vt_reputation("8.8.8.8")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["vt_reputation"]["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VT_KEY", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_vt_body()))
    out = vt_reputation("8.8.8.8")
    for k in ("success", "ioc", "ioc_type", "vt_url", "queried_at",
              "from_cache", "stats", "severity", "reputation",
              "flagging_engines", "attributes", "findings_emitted"):
        assert k in out
