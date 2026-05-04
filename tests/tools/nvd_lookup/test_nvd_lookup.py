"""Tests for nvd_lookup.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- CVE normalization (case-insensitive, malformed rejected)
- CVSS extraction (v3.1 → v3.0 → v2.0 preference order, Primary
  type preferred)
- CWE extraction (filters to CWE-<n> + sentinels)
- CPE-match extraction (configurations.nodes.cpeMatch traversal,
  capped at 30)
- References extraction (capped at 10, preserves tags)
- Description extraction (English preferred, fallback to first)
- Severity bands (critical / high / medium / low / none)
- Severity falls back to baseSeverity enum when score missing
- Successful query → finding emitted at correct severity
- Empty vulnerabilities → no_data=True, success
- 404 → fail-open via stale cache (no, actually treats 404 as
  failure since NVD shouldn't 404 for valid CVEs — but we need the
  empty-vulns path)
- 500 / invalid JSON / network error → graceful, stale-cache
  fallback
- Cache hit returns from_cache=True, re-emits findings
- Cache disabled via env
- Stale cache served on failure
- apiKey header sent when STRIX_NVD_KEY set
- §11 UX (description_plain + recommended_action + verified)
- check.completed events
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


import strix.tools.nvd_lookup.nvd_lookup  # noqa: F401

nvd_module = sys.modules["strix.tools.nvd_lookup.nvd_lookup"]
nvd_lookup = nvd_module.nvd_lookup


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
    monkeypatch.delenv("STRIX_NVD_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_NVD_KEY", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("nvd-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=15.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(nvd_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _nvd_body(
    *,
    cve: str = "CVE-2021-44228",
    base_score: float = 10.0,
    base_severity: str = "CRITICAL",
    cwes: list[str] | None = None,
    description: str = "Apache Log4j2 RCE via JNDI lookup.",
    cpe_count: int = 1,
    references: list[str] | None = None,
    metric_version: str = "v31",
) -> str:
    metrics_key = f"cvssMetric{metric_version.upper()}"
    metric_version_label = {
        "v31": "3.1",
        "v30": "3.0",
        "v2": "2.0",
    }.get(metric_version.lower(), "3.1")
    weaknesses = [
        {"description": [{"lang": "en", "value": w}]}
        for w in (cwes or ["CWE-502"])
    ]
    cpe_matches = [
        {
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:apache:log4j:{i}:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.0",
            "versionEndExcluding": "2.15.0",
        }
        for i in range(cpe_count)
    ]
    refs = [{"url": u, "source": "nvd", "tags": ["Patch"]} for u in (references or ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"])]
    return json.dumps({
        "vulnerabilities": [{
            "cve": {
                "id": cve,
                "published": "2021-12-10T10:15:00.000",
                "lastModified": "2024-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "sourceIdentifier": "security@apache.org",
                "descriptions": [{"lang": "en", "value": description}],
                "metrics": {
                    metrics_key: [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": metric_version_label,
                            "vectorString": f"CVSS:{metric_version_label}/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "baseScore": base_score,
                            "baseSeverity": base_severity,
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 6.0,
                    }],
                },
                "weaknesses": weaknesses,
                "configurations": [{
                    "nodes": [{
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": cpe_matches,
                    }],
                }],
                "references": refs,
            },
        }],
    })


# ---------------------------------------------------------------------------
# CVE normalization
# ---------------------------------------------------------------------------


def test_normalize_uppercases() -> None:
    assert nvd_module._normalize_cve("cve-2021-44228") == "CVE-2021-44228"


def test_normalize_rejects_malformed() -> None:
    assert nvd_module._normalize_cve("CVE-foo") is None
    assert nvd_module._normalize_cve("123") is None
    assert nvd_module._normalize_cve("") is None
    assert nvd_module._normalize_cve(None) is None  # type: ignore[arg-type]


def test_invalid_top_level_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call"))
    out = nvd_lookup("not-a-cve")
    assert out["success"] is False
    assert log == []


# ---------------------------------------------------------------------------
# CVSS extraction
# ---------------------------------------------------------------------------


def test_cvss_v31_preferred_over_v30_and_v2() -> None:
    metrics = {
        "cvssMetricV31": [{
            "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"},
        }],
        "cvssMetricV30": [{
            "type": "Primary",
            "cvssData": {"version": "3.0", "baseScore": 8.0, "baseSeverity": "HIGH"},
        }],
        "cvssMetricV2": [{
            "type": "Primary",
            "cvssData": {"version": "2.0", "baseScore": 6.0, "baseSeverity": "MEDIUM"},
        }],
    }
    out = nvd_module._extract_cvss(metrics)
    assert out["version"] == "3.1"
    assert out["base_score"] == 9.8


def test_cvss_falls_back_to_v30_when_v31_missing() -> None:
    metrics = {
        "cvssMetricV30": [{
            "type": "Primary",
            "cvssData": {"version": "3.0", "baseScore": 8.0, "baseSeverity": "HIGH"},
        }],
    }
    out = nvd_module._extract_cvss(metrics)
    assert out["version"] == "3.0"


def test_cvss_falls_back_to_v2_when_v3_missing() -> None:
    metrics = {
        "cvssMetricV2": [{
            "type": "Primary",
            "cvssData": {"version": "2.0", "baseScore": 6.0, "baseSeverity": "MEDIUM"},
        }],
    }
    out = nvd_module._extract_cvss(metrics)
    assert out["version"] == "2.0"


def test_cvss_prefers_primary_over_secondary() -> None:
    metrics = {
        "cvssMetricV31": [
            {
                "type": "Secondary",
                "cvssData": {"version": "3.1", "baseScore": 7.0},
            },
            {
                "type": "Primary",
                "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"},
            },
        ],
    }
    out = nvd_module._extract_cvss(metrics)
    assert out["base_score"] == 9.8


def test_cvss_empty_when_no_metrics() -> None:
    assert nvd_module._extract_cvss({}) == {}
    assert nvd_module._extract_cvss({"cvssMetricV31": []}) == {}


# ---------------------------------------------------------------------------
# CWE extraction
# ---------------------------------------------------------------------------


def test_extract_cwes() -> None:
    weaknesses = [
        {"description": [{"lang": "en", "value": "CWE-502"}]},
        {"description": [{"lang": "en", "value": "CWE-94"}]},
    ]
    out = nvd_module._extract_cwes(weaknesses)
    assert out == ["CWE-502", "CWE-94"]


def test_extract_cwes_dedups() -> None:
    weaknesses = [
        {"description": [{"lang": "en", "value": "CWE-502"}]},
        {"description": [{"lang": "en", "value": "CWE-502"}]},
    ]
    assert nvd_module._extract_cwes(weaknesses) == ["CWE-502"]


def test_extract_cwes_handles_sentinels() -> None:
    weaknesses = [
        {"description": [{"lang": "en", "value": "NVD-CWE-OTHER"}]},
    ]
    assert "NVD-CWE-OTHER" in nvd_module._extract_cwes(weaknesses)


def test_extract_cwes_empty() -> None:
    assert nvd_module._extract_cwes(None) == []
    assert nvd_module._extract_cwes([]) == []
    assert nvd_module._extract_cwes("not-a-list") == []


# ---------------------------------------------------------------------------
# CPE-match extraction
# ---------------------------------------------------------------------------


def test_extract_cpe_matches() -> None:
    configurations = [{
        "nodes": [{
            "cpeMatch": [
                {
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.0",
                    "versionEndExcluding": "2.15.0",
                },
            ],
        }],
    }]
    out = nvd_module._extract_cpe_matches(configurations)
    assert len(out) == 1
    assert out[0]["criteria"].startswith("cpe:2.3:a:apache:log4j")
    assert out[0]["versionEndExcluding"] == "2.15.0"


def test_extract_cpe_dedups_on_criteria() -> None:
    configurations = [{
        "nodes": [{
            "cpeMatch": [
                {"criteria": "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"},
                {"criteria": "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*"},
            ],
        }],
    }]
    assert len(nvd_module._extract_cpe_matches(configurations)) == 1


def test_extract_cpe_capped_at_30() -> None:
    configurations = [{
        "nodes": [{
            "cpeMatch": [
                {"criteria": f"cpe:2.3:a:vendor:product:{i}:*:*:*:*:*:*:*"}
                for i in range(50)
            ],
        }],
    }]
    out = nvd_module._extract_cpe_matches(configurations)
    assert len(out) == 30


# ---------------------------------------------------------------------------
# Description / references extraction
# ---------------------------------------------------------------------------


def test_extract_description_prefers_english() -> None:
    descs = [
        {"lang": "es", "value": "Spanish desc"},
        {"lang": "en", "value": "English desc"},
    ]
    assert nvd_module._extract_description(descs) == "English desc"


def test_extract_description_fallback_to_first() -> None:
    descs = [{"lang": "es", "value": "Spanish only"}]
    assert nvd_module._extract_description(descs) == "Spanish only"


def test_extract_description_empty() -> None:
    assert nvd_module._extract_description([]) == ""
    assert nvd_module._extract_description(None) == ""


def test_extract_references_capped() -> None:
    refs = [{"url": f"https://x.com/{i}", "source": "nvd"} for i in range(20)]
    out = nvd_module._extract_references(refs)
    assert len(out) == 10


def test_extract_references_preserves_tags() -> None:
    refs = [{"url": "https://x.com", "source": "nvd", "tags": ["Patch", "Vendor Advisory"]}]
    out = nvd_module._extract_references(refs)
    assert out[0]["tags"] == ["Patch", "Vendor Advisory"]


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def test_severity_critical_at_9() -> None:
    assert nvd_module._cvss_to_severity(9.0) == "critical"
    assert nvd_module._cvss_to_severity(10.0) == "critical"


def test_severity_high_7_to_9() -> None:
    assert nvd_module._cvss_to_severity(7.0) == "high"
    assert nvd_module._cvss_to_severity(8.9) == "high"


def test_severity_medium_4_to_7() -> None:
    assert nvd_module._cvss_to_severity(4.0) == "medium"
    assert nvd_module._cvss_to_severity(6.9) == "medium"


def test_severity_low_below_4() -> None:
    assert nvd_module._cvss_to_severity(3.9) == "low"
    assert nvd_module._cvss_to_severity(0.1) == "low"


def test_severity_none_at_zero() -> None:
    assert nvd_module._cvss_to_severity(0.0) is None


def test_severity_falls_back_to_enum_when_score_zero() -> None:
    """When score == 0 but baseSeverity = HIGH, use the enum."""
    assert nvd_module._cvss_to_severity(0.0, "HIGH") == "high"
    assert nvd_module._cvss_to_severity(0.0, "CRITICAL") == "critical"


# ---------------------------------------------------------------------------
# Successful queries
# ---------------------------------------------------------------------------


def test_critical_cve_emits_critical_finding(monkeypatch) -> None:
    body = _nvd_body(base_score=10.0, base_severity="CRITICAL", cwes=["CWE-502"])
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = nvd_lookup("CVE-2021-44228")
    assert out["success"] is True
    assert out["severity"] == "critical"
    assert out["cvss"]["base_score"] == 10.0
    assert out["cvss"]["base_severity"] == "CRITICAL"
    assert "CWE-502" in out["cwes"]

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "critical"
    assert reports[0]["cve"] == "CVE-2021-44228"
    assert reports[0]["cwe"] == "CWE-502"


def test_high_cve_emits_high(monkeypatch) -> None:
    body = _nvd_body(base_score=8.5, base_severity="HIGH")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = nvd_lookup("CVE-2024-12345")
    assert out["severity"] == "high"


def test_medium_cve(monkeypatch) -> None:
    body = _nvd_body(base_score=5.0, base_severity="MEDIUM")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = nvd_lookup("CVE-2024-12345")
    assert out["severity"] == "medium"


def test_low_cve(monkeypatch) -> None:
    body = _nvd_body(base_score=3.0, base_severity="LOW")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = nvd_lookup("CVE-2024-12345")
    assert out["severity"] == "low"


def test_empty_vulnerabilities_no_data(monkeypatch) -> None:
    body = json.dumps({"vulnerabilities": []})
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = nvd_lookup("CVE-2099-99999")
    assert out["success"] is True
    assert out["no_data"] is True
    assert out["severity"] is None
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


def test_500_no_cache_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=500))
    out = nvd_lookup("CVE-2021-44228")
    assert out["success"] is False


def test_invalid_json_returns_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = nvd_lookup("CVE-2021-44228")
    assert out["success"] is False


def test_network_error_no_cache(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: {"status": 0, "headers": {}, "body": "", "error": "DNS"})
    out = nvd_lookup("CVE-2021-44228")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    body = _nvd_body()
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out1 = nvd_lookup("CVE-2021-44228")
    assert out1["from_cache"] is False
    pre = len(log)
    out2 = nvd_lookup("CVE-2021-44228")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_re_emits_findings(monkeypatch) -> None:
    body = _nvd_body()
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    nvd_lookup("CVE-2021-44228")
    tracer = tracer_module.get_global_tracer()
    tracer.vulnerability_reports.clear()  # type: ignore[attr-defined]
    out2 = nvd_lookup("CVE-2021-44228")
    assert out2["from_cache"] is True
    reports = tracer.get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "critical"


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_NVD_NO_CACHE", "1")
    body = _nvd_body()
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    nvd_lookup("CVE-2021-44228")
    pre = len(log)
    nvd_lookup("CVE-2021-44228")
    assert len(log) > pre


def test_stale_cache_served_on_failure(monkeypatch) -> None:
    fail_now = [False]
    body = _nvd_body()

    def responder(url, h):
        if fail_now[0]:
            return _resp(status=500)
        return _resp(status=200, body=body)

    _patch_http(monkeypatch, responder)
    out1 = nvd_lookup("CVE-2021-44228")
    assert out1["from_cache"] is False

    cache_path = nvd_module._cache_path("CVE-2021-44228")
    old_mtime = time.time() - 48 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True
    out2 = nvd_lookup("CVE-2021-44228")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# API key header
# ---------------------------------------------------------------------------


def test_apikey_header_sent_when_set(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_NVD_KEY", "test-nvd-key")
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("apiKey", ""))
        return _resp(status=200, body=_nvd_body())

    _patch_http(monkeypatch, responder)
    nvd_lookup("CVE-2021-44228")
    assert captured == ["test-nvd-key"]


def test_apikey_not_sent_without_env(monkeypatch) -> None:
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("apiKey", ""))
        return _resp(status=200, body=_nvd_body())

    _patch_http(monkeypatch, responder)
    nvd_lookup("CVE-2021-44228")
    assert captured == [""]


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    body = _nvd_body()
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    nvd_lookup("CVE-2021-44228")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain")
        assert r.get("recommended_action")
        assert r.get("verification_status") == "verified"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    body = json.dumps({"vulnerabilities": []})
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    nvd_lookup("CVE-2099-99999")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["nvd_lookup"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    body = _nvd_body()
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    nvd_lookup("CVE-2021-44228")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["nvd_lookup"]["vulnerable"] == 1


def test_check_event_inconclusive_on_failure(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda u, h: _resp(status=500))
    nvd_lookup("CVE-2021-44228")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["nvd_lookup"]["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    body = _nvd_body()
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=body))
    out = nvd_lookup("CVE-2021-44228")
    for k in ("success", "cve", "queried_at", "from_cache", "published",
              "last_modified", "status", "source_identifier",
              "description", "cvss", "cwes", "cpe_matches",
              "references", "severity", "findings_emitted"):
        assert k in out


def test_url_includes_cve_id(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_nvd_body()))
    nvd_lookup("CVE-2021-44228")
    assert any("cveId=CVE-2021-44228" in entry["url"] for entry in log)
