"""Tests for attack_surface_intel.

Hermetic — `_http_get` and `_resolve_ips` are monkeypatched. Tests
cover:

- Target classification (domain / IP / URL strip / private IP rejected)
- Both sources skipped without keys
- Shodan-only path (Shodan key, no Censys)
- Censys-only path (Censys creds, no Shodan key)
- Both sources active (full coverage)
- High-risk service detection from product fingerprint
- High-risk service detection from well-known port fallback
- Per-(ip, class) dedup (ssh + telnet → one finding)
- Shodan-tagged CVE → high vulnerable_software finding (with CVE)
- Shodan vulns capped at 20 per IP
- Broad surface threshold (>10 ports → medium)
- Version disclosure → low (one aggregating finding per IP)
- Multi-IP scan when target is domain
- Shodan 401 → recorded source_error
- Censys 401 → recorded source_error
- Shodan 404 → no error, present=False
- Cache behaviour (hit / disabled / stale-served-on-failure)
- §11 UX baseline
- check.completed event emission
- Result schema integrity
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


import strix.tools.attack_surface_intel.attack_surface_intel  # noqa: F401

ai_module = sys.modules["strix.tools.attack_surface_intel.attack_surface_intel"]
attack_surface_intel = ai_module.attack_surface_intel


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
    monkeypatch.delenv("STRIX_ATTACK_SURFACE_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_SHODAN_KEY", raising=False)
    monkeypatch.delenv("STRIX_CENSYS_API_ID", raising=False)
    monkeypatch.delenv("STRIX_CENSYS_API_SECRET", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("ai-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=15.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(ai_module, "_http_get", fake)
    return log


def _patch_dns(monkeypatch, ips: list[str]):
    monkeypatch.setattr(ai_module, "_resolve_ips", lambda d, timeout=4.0: list(ips))


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _shodan_body(
    *,
    ports: list[int] | None = None,
    services: list[dict[str, Any]] | None = None,
    vulns: list[str] | None = None,
    last_update: str = "2024-12-15T10:00:00",
) -> str:
    payload = {
        "ip_str": "1.1.1.1",
        "hostnames": [],
        "domains": [],
        "ports": ports or [],
        "data": services or [],
        "vulns": vulns or [],
        "last_update": last_update,
        "country_code": "US",
        "isp": "Test",
        "org": "TestOrg",
    }
    return json.dumps(payload)


def _censys_body(
    *,
    services: list[dict[str, Any]] | None = None,
    last_updated: str = "2024-12-15T10:00:00Z",
    asn: int = 13335,
) -> str:
    payload = {
        "result": {
            "ip": "1.1.1.1",
            "services": services or [],
            "last_updated_at": last_updated,
            "autonomous_system": {
                "asn": asn,
                "name": "TestAS",
                "country_code": "US",
            },
            "location": {"country": "United States"},
        }
    }
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------


def test_classify_domain() -> None:
    assert ai_module._classify_target("example.com") == ("domain", "example.com")


def test_classify_ip() -> None:
    assert ai_module._classify_target("1.1.1.1") == ("ip", "1.1.1.1")


def test_classify_url_strips() -> None:
    assert ai_module._classify_target("https://app.example.com/") == ("domain", "app.example.com")


def test_classify_uppercase_lowered() -> None:
    assert ai_module._classify_target("Example.COM") == ("domain", "example.com")


def test_classify_private_ip_rejected() -> None:
    assert ai_module._classify_target("10.0.0.1")[0] == "invalid"
    assert ai_module._classify_target("192.168.1.1")[0] == "invalid"


def test_classify_invalid_input() -> None:
    assert ai_module._classify_target("")[0] == "invalid"
    assert ai_module._classify_target("not a domain")[0] == "invalid"


def test_invalid_target_top_level_failure(monkeypatch) -> None:
    out = attack_surface_intel("not-a-domain")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# No keys → both sources skipped
# ---------------------------------------------------------------------------


def test_both_sources_skipped_without_keys(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("Should not call HTTP without keys"))
    out = attack_surface_intel("1.1.1.1")
    assert out["success"] is True
    assert out["per_ip"][0]["shodan"].get("skipped") is True
    assert out["per_ip"][0]["censys"].get("skipped") is True
    assert out["findings_emitted"] == 0
    assert log == []


# ---------------------------------------------------------------------------
# Shodan-only paths
# ---------------------------------------------------------------------------


def test_shodan_high_risk_product_emits_high(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test-shodan")

    body = _shodan_body(
        ports=[22, 27017],
        services=[
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.4", "data": "SSH-2.0-OpenSSH_7.4"},
            {"port": 27017, "transport": "tcp", "product": "MongoDB", "data": "MongoDB 4.0"},
        ],
    )

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    out = attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high_risk = [r for r in reports if "high-risk service" in r["title"].lower()]
    assert high_risk
    assert high_risk[0]["severity"] == "high"
    assert high_risk[0]["category"] == "attack_surface_disclosure"
    assert "MongoDB" in high_risk[0]["description"] or "MongoDB" in high_risk[0]["description_plain"]
    assert "SSH" in high_risk[0]["description"] or "SSH" in high_risk[0]["description_plain"]


def test_shodan_high_risk_port_fallback(monkeypatch) -> None:
    """Service has no product fingerprint but port 6379 → Redis → high."""
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")

    body = _shodan_body(
        ports=[6379],
        services=[{"port": 6379, "transport": "tcp", "data": ""}],  # no product
    )

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" and "Redis" in r["description"] for r in reports)


def test_shodan_dedup_one_high_risk_finding_per_ip(monkeypatch) -> None:
    """SSH + Telnet + RDP exposed → ONE high finding listing all three."""
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    body = _shodan_body(
        ports=[22, 23, 3389],
        services=[
            {"port": 22, "product": "OpenSSH"},
            {"port": 23, "product": "telnetd"},
            {"port": 3389, "product": "rdp"},
        ],
    )

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high_risk = [r for r in reports if "high-risk service" in r["title"].lower()]
    assert len(high_risk) == 1


def test_shodan_vuln_emits_high_per_cve(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    body = _shodan_body(
        ports=[443],
        services=[{"port": 443, "product": "Apache", "version": "2.4.49"}],
        vulns=["CVE-2021-41773", "CVE-2021-42013"],
    )

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    cve_findings = [r for r in reports if "Shodan-tagged" in r["title"]]
    assert len(cve_findings) == 2
    assert all(r["severity"] == "high" for r in cve_findings)
    assert all(r["cwe"] == "CWE-1395" for r in cve_findings)
    cves = {r["cve"] for r in cve_findings}
    assert cves == {"CVE-2021-41773", "CVE-2021-42013"}


def test_shodan_vulns_capped_at_20(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    cves = [f"CVE-2024-{i:05d}" for i in range(50)]
    body = _shodan_body(ports=[443], services=[], vulns=cves)

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    cve_findings = [r for r in reports if "Shodan-tagged" in r["title"]]
    assert len(cve_findings) == 20


def test_shodan_broad_surface_emits_medium(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    ports = [80, 443, 8080, 8443, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097]
    body = _shodan_body(ports=ports, services=[{"port": p} for p in ports])

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    broad = [r for r in reports if "Broad attack surface" in r["title"]]
    assert broad
    assert broad[0]["severity"] == "medium"


def test_shodan_version_disclosure_emits_low(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    body = _shodan_body(
        ports=[80, 443],
        services=[
            {"port": 80, "product": "nginx", "version": "1.18.0"},
            {"port": 443, "product": "Apache", "version": "2.4.49"},
        ],
    )

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    version_findings = [r for r in reports if "version disclosure" in r["title"].lower()]
    assert len(version_findings) == 1
    assert version_findings[0]["severity"] == "low"


def test_shodan_404_no_error(monkeypatch) -> None:
    """Host not in Shodan → no error, present=False."""
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")

    def http_responder(url, headers):
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    out = attack_surface_intel("1.1.1.1")
    assert out["per_ip"][0]["shodan"]["present"] is False
    assert out["per_ip"][0]["shodan"].get("status") == 404
    assert out["per_ip"][0]["shodan"].get("error") is None


def test_shodan_401_recorded_as_error(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "bad-key")

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=401, body="Invalid API key")
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    out = attack_surface_intel("1.1.1.1")
    assert "shodan[1.1.1.1]" in out["source_errors"]
    assert "401" in out["source_errors"]["shodan[1.1.1.1]"]


# ---------------------------------------------------------------------------
# Censys-only paths
# ---------------------------------------------------------------------------


def test_censys_authorization_header_basic(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CENSYS_API_ID", "id123")
    monkeypatch.setenv("STRIX_CENSYS_API_SECRET", "sec456")
    captured: list[str] = []

    def http_responder(url, headers):
        if "censys.io" in url:
            captured.append(headers.get("Authorization", ""))
            return _resp(status=200, body=_censys_body())
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    assert captured
    assert captured[0].startswith("Basic ")
    import base64

    decoded = base64.b64decode(captured[0].split(" ", 1)[1]).decode("ascii")
    assert decoded == "id123:sec456"


def test_censys_high_risk_service_emits_high(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CENSYS_API_ID", "id")
    monkeypatch.setenv("STRIX_CENSYS_API_SECRET", "sec")
    body = _censys_body(services=[
        {"port": 6379, "service_name": "REDIS", "transport_protocol": "TCP",
         "software": [{"product": "Redis", "version": "5.0"}]},
    ])

    def http_responder(url, headers):
        if "censys.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" and "Redis" in r["description"] for r in reports)


def test_censys_401_recorded_as_error(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CENSYS_API_ID", "bad")
    monkeypatch.setenv("STRIX_CENSYS_API_SECRET", "bad")

    def http_responder(url, headers):
        if "censys.io" in url:
            return _resp(status=401, body="unauthorized")
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    out = attack_surface_intel("1.1.1.1")
    assert "censys[1.1.1.1]" in out["source_errors"]


# ---------------------------------------------------------------------------
# Domain-target multi-IP
# ---------------------------------------------------------------------------


def test_domain_resolves_to_multiple_ips(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    _patch_dns(monkeypatch, ["1.1.1.1", "8.8.8.8"])

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=_shodan_body(ports=[6379], services=[
                {"port": 6379, "product": "Redis"},
            ]))
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    out = attack_surface_intel("example.com")
    assert out["resolved_ips"] == ["1.1.1.1", "8.8.8.8"]
    assert len(out["per_ip"]) == 2
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high_risk = [r for r in reports if "high-risk service" in r["title"].lower()]
    # One finding per IP (per-IP dedup).
    assert len(high_risk) == 2


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")

    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_shodan_body()))
    out1 = attack_surface_intel("1.1.1.1")
    assert out1["from_cache"] is False
    pre = len(log)
    out2 = attack_surface_intel("1.1.1.1")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ATTACK_SURFACE_NO_CACHE", "1")
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_shodan_body()))
    attack_surface_intel("1.1.1.1")
    pre = len(log)
    attack_surface_intel("1.1.1.1")
    assert len(log) > pre


def test_stale_cache_served_on_full_failure(monkeypatch) -> None:
    """Both sources error → stale cache served."""
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    monkeypatch.setenv("STRIX_CENSYS_API_ID", "id")
    monkeypatch.setenv("STRIX_CENSYS_API_SECRET", "sec")

    fail_now = [False]

    def http_responder(url, headers):
        if fail_now[0]:
            return {"status": 0, "headers": {}, "body": "", "error": "network unreachable"}
        if "api.shodan.io" in url:
            return _resp(status=200, body=_shodan_body())
        if "censys.io" in url:
            return _resp(status=200, body=_censys_body())
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    out1 = attack_surface_intel("1.1.1.1")
    assert out1["from_cache"] is False

    cache_path = ai_module._cache_path("1.1.1.1")
    old_mtime = time.time() - 10 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True

    out2 = attack_surface_intel("1.1.1.1")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


def test_skipped_sources_dont_trigger_stale_fallback(monkeypatch) -> None:
    """Both sources skipped (no keys) → not treated as failure → no stale-cache fallback."""
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("Should not call HTTP"))
    out = attack_surface_intel("1.1.1.1")
    # Tool succeeds without keys; no error attached.
    assert out["success"] is True
    assert out.get("error") is None
    assert log == []


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")

    body = _shodan_body(
        ports=[22, 6379, 80, 443, 8080, 9000, 9001, 9002, 9003, 9004, 9005, 9006],
        services=[
            {"port": 22, "product": "OpenSSH", "version": "7.4"},
            {"port": 6379, "product": "Redis", "version": "5.0"},
            {"port": 80, "product": "nginx", "version": "1.18.0"},
        ],
        vulns=["CVE-2021-44228"],
    )

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    _patch_http(monkeypatch, lambda u, h: _resp(status=404))
    attack_surface_intel("1.1.1.1")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert "attack_surface_intel" in summary["by_category"]
    assert summary["by_category"]["attack_surface_intel"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SHODAN_KEY", "test")
    body = _shodan_body(ports=[6379], services=[{"port": 6379, "product": "Redis"}])

    def http_responder(url, headers):
        if "api.shodan.io" in url:
            return _resp(status=200, body=body)
        return _resp(status=404)

    _patch_http(monkeypatch, http_responder)
    attack_surface_intel("1.1.1.1")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["attack_surface_intel"]["vulnerable"] == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    out = attack_surface_intel("1.1.1.1")
    for k in ("success", "target", "target_type", "queried_at", "from_cache",
              "resolved_ips", "per_ip", "source_errors", "findings_emitted"):
        assert k in out
    if out["per_ip"]:
        for k in ("ip", "shodan", "censys", "all_ports", "high_risk_services",
                  "broad_surface", "version_disclosure", "shodan_vulns"):
            assert k in out["per_ip"][0]
