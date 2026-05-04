"""Tests for monitoring_posture_check (roadmap §16 / PR #128)."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.monitoring_posture.monitoring_posture  # noqa: F401

mp_module = sys.modules["strix.tools.monitoring_posture.monitoring_posture"]
monitoring_posture_check = mp_module.monitoring_posture_check


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
    tracer = Tracer("monitoring-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _patch_get(monkeypatch, headers: dict[str, str], status: int = 200) -> None:
    def fake(url, *, timeout=8.0):
        return {"status": status, "headers": dict(headers), "body": ""}

    monkeypatch.setattr(mp_module, "_http_get", fake)


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert monitoring_posture_check("")["success"] is False


def test_bare_host_normalised(monkeypatch) -> None:
    _patch_get(monkeypatch, {})
    out = monitoring_posture_check("app.example.com")
    assert out["success"] is True


# ---------------------------------------------------------------------------
# Identifying-headers redaction
# ---------------------------------------------------------------------------


def test_no_identifying_headers_scores_redacted(monkeypatch) -> None:
    _patch_get(monkeypatch, {})  # no Server, no X-Powered-By
    out = monitoring_posture_check("https://app.example.com")
    assert out["identifying_headers"]["redacted"] is True
    assert out["identifying_headers"]["score"] == 1


def test_server_header_present_zeros_score(monkeypatch) -> None:
    _patch_get(monkeypatch, {"server": "nginx/1.21"})
    out = monitoring_posture_check("https://app.example.com")
    assert out["identifying_headers"]["redacted"] is False
    assert "server" in out["identifying_headers"]["leaked_headers"]
    assert out["identifying_headers"]["score"] == 0


def test_x_powered_by_present_zeros_score(monkeypatch) -> None:
    _patch_get(monkeypatch, {"x-powered-by": "Express"})
    out = monitoring_posture_check("https://app.example.com")
    assert out["identifying_headers"]["redacted"] is False
    assert "x-powered-by" in out["identifying_headers"]["leaked_headers"]


# ---------------------------------------------------------------------------
# Monitoring headers
# ---------------------------------------------------------------------------


def test_report_to_header_scores_one_bucket(monkeypatch) -> None:
    _patch_get(monkeypatch, {"report-to": '{"endpoints":[...]}'})
    out = monitoring_posture_check("https://app.example.com")
    assert "report_endpoints" in out["monitoring_headers"]["monitoring_buckets_present"]
    assert out["monitoring_headers"]["score"] == 1


def test_csp_with_report_uri_scores_one_bucket(monkeypatch) -> None:
    """CSP with `report-uri` directive counts even without
    a separate Reporting-Endpoints header."""
    _patch_get(monkeypatch, {
        "content-security-policy": "default-src 'self'; report-uri /csp-violations",
    })
    out = monitoring_posture_check("https://app.example.com")
    assert "csp_reporting" in out["monitoring_headers"]["monitoring_buckets_present"]


def test_nel_header_scores_one_bucket(monkeypatch) -> None:
    _patch_get(monkeypatch, {"nel": '{"max_age":86400}'})
    out = monitoring_posture_check("https://app.example.com")
    assert "nel" in out["monitoring_headers"]["monitoring_buckets_present"]


def test_all_four_monitoring_buckets_max_score(monkeypatch) -> None:
    _patch_get(monkeypatch, {
        "report-to": "x",
        "content-security-policy-report-only": "default-src 'self'",
        "nel": '{"max_age":86400}',
        "server-timing": "db;dur=42",
    })
    out = monitoring_posture_check("https://app.example.com")
    assert out["monitoring_headers"]["score"] == 4


# ---------------------------------------------------------------------------
# Rate-limit detection
# ---------------------------------------------------------------------------


def test_x_ratelimit_headers_score_one(monkeypatch) -> None:
    _patch_get(monkeypatch, {
        "x-ratelimit-limit": "100",
        "x-ratelimit-remaining": "99",
    })
    out = monitoring_posture_check("https://app.example.com")
    assert out["rate_limit"]["score"] == 1
    assert "x-ratelimit-limit" in out["rate_limit"]["rate_limit_headers"]


def test_429_in_burst_scores_one(monkeypatch) -> None:
    """If the burst surface returns 429 even once, rate-limiting
    is presumed configured."""
    call_count = {"n": 0}

    def fake(url, *, timeout=8.0):
        call_count["n"] += 1
        if call_count["n"] >= 3:
            return {"status": 429, "headers": {"retry-after": "60"}, "body": ""}
        return {"status": 200, "headers": {}, "body": ""}

    monkeypatch.setattr(mp_module, "_http_get", fake)

    out = monitoring_posture_check("https://app.example.com")
    assert out["rate_limit"]["saw_429"] is True
    assert out["rate_limit"]["score"] == 1


def test_no_rate_limit_signals(monkeypatch) -> None:
    _patch_get(monkeypatch, {})
    out = monitoring_posture_check("https://app.example.com")
    assert out["rate_limit"]["score"] == 0
    assert out["rate_limit"]["saw_429"] is False


# ---------------------------------------------------------------------------
# Severity ladder
# ---------------------------------------------------------------------------


def test_high_score_emits_info(monkeypatch) -> None:
    """Redacted + 4 monitoring + rate-limit = score 6 → info."""
    _patch_get(monkeypatch, {
        # No Server / X-Powered-By → +1 redaction
        "report-to": "x",
        "content-security-policy-report-only": "x",
        "nel": "x",
        "server-timing": "x",  # +4 monitoring buckets
        "x-ratelimit-limit": "100",  # +1 rate-limit
    })
    out = monitoring_posture_check("https://app.example.com")
    assert out["score"] == 6
    assert out["severity"] == "info"

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "score 6/6" in findings[0]["title"]


def test_medium_score_emits_low(monkeypatch) -> None:
    """Redacted + 1 monitoring + 0 rate-limit = score 2 → low."""
    _patch_get(monkeypatch, {"report-to": "x"})
    out = monitoring_posture_check("https://app.example.com")
    assert out["score"] == 2
    assert out["severity"] == "low"


def test_low_score_emits_medium(monkeypatch) -> None:
    """Server leaked + 0 monitoring + 0 rate-limit = score 0 → medium."""
    _patch_get(monkeypatch, {"server": "nginx/1.21"})
    out = monitoring_posture_check("https://app.example.com")
    assert out["score"] == 0
    assert out["severity"] == "medium"
    findings = _findings()
    assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Always emits exactly one finding
# ---------------------------------------------------------------------------


def test_always_one_finding(monkeypatch) -> None:
    """Whether posture is good or bad, exactly one finding emitted."""
    _patch_get(monkeypatch, {"report-to": "x"})
    monitoring_posture_check("https://app.example.com")
    assert len(_findings()) == 1


# ---------------------------------------------------------------------------
# Schema + MITRE
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, {})
    out = monitoring_posture_check("https://app.example.com")
    assert set(out.keys()) >= {
        "success", "target", "score", "max_score", "severity",
        "identifying_headers", "monitoring_headers", "rate_limit",
        "findings_emitted",
    }
    assert out["max_score"] == 6


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    assert "T1592" in get_tool_mitre_techniques("monitoring_posture_check")


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_skipped_response_handled(monkeypatch) -> None:
    def fake(url, *, timeout=8.0):
        return {"status": 0, "headers": {}, "body": "", "skipped": True}

    monkeypatch.setattr(mp_module, "_http_get", fake)
    out = monitoring_posture_check("https://app.example.com")
    # Skipped path returns success=True with skipped marker.
    assert out["success"] is True
    assert out.get("skipped") is True
