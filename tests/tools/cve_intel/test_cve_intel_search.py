"""Tests for cve_intel_search.

Hermetic — `_http_post` is monkeypatched. Tests cover:

- Input validation (missing tech / version)
- Without `PERPLEXITY_API_KEY` → success=False, clear error, no
  HTTP calls
- Successful Perplexity response → CVEs extracted from content
- Citation array preserved (string + dict shapes)
- Inline URL extraction from content body
- CVE extraction is case-insensitive, deduped, capped at 50
- Cache hit returns from_cache=True without HTTP
- Cache disabled via env
- Stale cache served on Perplexity failure (fail-open)
- 401 → recorded error (auth issue)
- 429 → recorded error (rate-limit)
- Non-200 → recorded error
- Invalid JSON → recorded error
- check.completed event emitted
- Display-only contract: NO findings emitted
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


import strix.tools.cve_intel.cve_intel_search  # noqa: F401

ci_module = sys.modules["strix.tools.cve_intel.cve_intel_search"]
cve_intel_search = ci_module.cve_intel_search


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
    monkeypatch.delenv("STRIX_CVE_INTEL_NO_CACHE", raising=False)
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("ci-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, body="", timeout=60.0):
        log.append({
            "url": url, "headers": dict(headers or {}), "body": body,
        })
        return responder(url, dict(headers or {}), body)

    monkeypatch.setattr(ci_module, "_http_post", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _perplexity_body(content: str, citations: list[Any] | None = None) -> str:
    return json.dumps({
        "choices": [{"message": {"content": content}}],
        "citations": citations or [],
    })


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_missing_tech_rejected(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "test-key")
    log = _patch_http(monkeypatch, lambda u, h, b: pytest.fail("should not be called"))
    out = cve_intel_search("", "1.0.0")
    assert out["success"] is False
    assert log == []


def test_missing_version_rejected(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "test-key")
    log = _patch_http(monkeypatch, lambda u, h, b: pytest.fail("should not be called"))
    out = cve_intel_search("Apache", "")
    assert out["success"] is False
    assert log == []


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_no_api_key_returns_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h, b: pytest.fail("should not be called"))
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is False
    assert "PERPLEXITY_API_KEY" in (out.get("error") or "")
    # No HTTP traffic — short-circuit before any network call.
    assert log == []


def test_with_api_key_makes_request(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "test-key-123")
    log = _patch_http(
        monkeypatch,
        lambda u, h, b: _resp(status=200, body=_perplexity_body("No CVEs found.")),
    )
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is True
    assert len(log) == 1
    assert log[0]["headers"].get("Authorization") == "Bearer test-key-123"
    assert log[0]["url"].startswith("https://api.perplexity.ai/")


# ---------------------------------------------------------------------------
# CVE extraction
# ---------------------------------------------------------------------------


def test_extract_cves_from_content() -> None:
    out = ci_module._extract_cves(
        "The major CVEs are CVE-2021-44228 (Log4Shell) and CVE-2021-45046."
    )
    assert out == ["CVE-2021-44228", "CVE-2021-45046"]


def test_extract_cves_case_insensitive() -> None:
    out = ci_module._extract_cves("cve-2021-44228 and CVE-2021-44228")
    assert out == ["CVE-2021-44228"]


def test_extract_cves_dedups() -> None:
    out = ci_module._extract_cves(
        "CVE-2021-44228 appears in para 1. Later, CVE-2021-44228 reappears."
    )
    assert out == ["CVE-2021-44228"]


def test_extract_cves_empty() -> None:
    assert ci_module._extract_cves("") == []
    assert ci_module._extract_cves("No CVEs found.") == []


def test_extract_cves_capped_at_50() -> None:
    cves = " ".join(f"CVE-2024-{i:05d}" for i in range(100))
    out = ci_module._extract_cves(cves)
    assert len(out) == 50


def test_extract_inline_urls() -> None:
    content = (
        "See https://nvd.nist.gov/vuln/detail/CVE-2021-44228 for details. "
        "Also https://logging.apache.org/log4j/2.x/security.html."
    )
    out = ci_module._extract_inline_urls(content)
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in out
    assert "https://logging.apache.org/log4j/2.x/security.html" in out


def test_extract_inline_urls_strips_trailing_punct() -> None:
    content = "See https://example.com/foo.html, then https://example.com/bar."
    out = ci_module._extract_inline_urls(content)
    assert "https://example.com/foo.html" in out
    assert "https://example.com/bar" in out


def test_extract_inline_urls_dedups() -> None:
    content = "https://x.com/a and again https://x.com/a"
    out = ci_module._extract_inline_urls(content)
    assert out == ["https://x.com/a"]


# ---------------------------------------------------------------------------
# Successful response → structured result
# ---------------------------------------------------------------------------


def test_success_returns_extracted_cves(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    perplexity_content = (
        "## Vulnerabilities for log4j 2.14.1\n\n"
        "**CVE-2021-44228** (Log4Shell, critical): Remote code execution "
        "via JNDI lookup. Fixed in 2.15.0. PoC: https://github.com/kozmer/log4j-shell-poc\n\n"
        "**CVE-2021-45046** (high): Incomplete fix for Log4Shell. Fixed in 2.16.0. "
        "See https://logging.apache.org/log4j/2.x/security.html"
    )
    body = _perplexity_body(
        perplexity_content,
        citations=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ],
    )
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))
    out = cve_intel_search("log4j", "2.14.1")
    assert out["success"] is True
    assert "CVE-2021-44228" in out["cves"]
    assert "CVE-2021-45046" in out["cves"]
    assert len(out["citations"]) == 2
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in out["citations"]
    # Inline URLs in summary body extracted.
    assert any("github.com/kozmer" in u for u in out["inline_urls"])
    assert out["summary"] == perplexity_content
    assert out["from_cache"] is False


def test_citations_dict_shape_supported(monkeypatch) -> None:
    """Some Perplexity responses use dict citations: [{url: ...}]."""
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = json.dumps({
        "choices": [{"message": {"content": "CVE-2024-12345"}}],
        "citations": [
            {"url": "https://example.com/a", "title": "Adv"},
            {"url": "https://example.com/b"},
        ],
    })
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))
    out = cve_intel_search("test", "1.0.0")
    assert out["citations"] == ["https://example.com/a", "https://example.com/b"]


def test_no_cves_in_response(monkeypatch) -> None:
    """Perplexity confirms no CVEs — tool succeeds with empty cves[]."""
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = _perplexity_body("No publicly-disclosed CVEs affect this version.")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))
    out = cve_intel_search("safe-lib", "1.0.0")
    assert out["success"] is True
    assert out["cves"] == []


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


def test_401_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "bad-key")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=401, body="unauthorized"))
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is False
    assert "401" in out["error"]


def test_429_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=429, body="rate limited"))
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is False
    assert "429" in out["error"]


def test_non_200_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=503, body="ise"))
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is False


def test_invalid_json_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body="not json"))
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is False
    assert "JSON" in out["error"]


def test_network_error_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    _patch_http(monkeypatch, lambda u, h, b: {
        "status": 0, "headers": {}, "body": "", "error": "DNS failure",
    })
    out = cve_intel_search("Apache", "2.4.49")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = _perplexity_body("CVE-2024-1")
    log = _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))

    out1 = cve_intel_search("Apache", "2.4.49")
    assert out1["from_cache"] is False
    pre = len(log)

    out2 = cve_intel_search("Apache", "2.4.49")
    assert out2["from_cache"] is True
    assert len(log) == pre  # no new HTTP calls


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CVE_INTEL_NO_CACHE", "1")
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = _perplexity_body("CVE-2024-1")
    log = _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))
    cve_intel_search("Apache", "2.4.49")
    pre = len(log)
    cve_intel_search("Apache", "2.4.49")
    assert len(log) > pre


def test_stale_cache_served_on_failure(monkeypatch) -> None:
    """Populate cache, then force network error → stale cache served."""
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    fail_now = [False]
    body = _perplexity_body("CVE-2024-1")

    def responder(u, h, b):
        if fail_now[0]:
            return {"status": 0, "headers": {}, "body": "", "error": "network unreachable"}
        return _resp(status=200, body=body)

    _patch_http(monkeypatch, responder)
    out1 = cve_intel_search("Apache", "2.4.49")
    assert out1["from_cache"] is False

    cache_path = ci_module._cache_path("Apache", "2.4.49", ci_module._DEFAULT_MODEL)
    old_mtime = time.time() - 24 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True

    out2 = cve_intel_search("Apache", "2.4.49")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


def test_cache_key_distinct_per_model(monkeypatch) -> None:
    """Same (tech, version) but different model → different cache slot."""
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = _perplexity_body("CVE-2024-1")
    log = _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))

    cve_intel_search("Apache", "2.4.49", model="sonar-pro")
    pre = len(log)
    cve_intel_search("Apache", "2.4.49", model="sonar")
    # Different model → cache miss → another HTTP call.
    assert len(log) == pre + 1


# ---------------------------------------------------------------------------
# Display-only contract
# ---------------------------------------------------------------------------


def test_no_findings_emitted(monkeypatch) -> None:
    """Tool must NEVER emit findings — display-only enrichment."""
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = _perplexity_body(
        "CRITICAL: CVE-2021-44228 (Log4Shell) - RCE in Log4j 2.14.1. "
        "Active exploitation in the wild. Patch immediately."
    )
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))
    out = cve_intel_search("log4j", "2.14.1")
    assert out["cves"] == ["CVE-2021-44228"]
    # NO findings emitted — even though the LLM said "CRITICAL".
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=_perplexity_body("none")))
    cve_intel_search("safe", "1.0")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "cve_intel" in summary["by_category"]


def test_check_event_inconclusive_without_key(monkeypatch) -> None:
    cve_intel_search("Apache", "2.4.49")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["cve_intel"]
    assert cat.get("inconclusive", 0) == 1


def test_check_event_inconclusive_on_failure(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=500))
    cve_intel_search("Apache", "2.4.49")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["cve_intel"]
    assert cat.get("inconclusive", 0) == 1


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    body = _perplexity_body("CVE-2024-1")
    _patch_http(monkeypatch, lambda u, h, b: _resp(status=200, body=body))
    out = cve_intel_search("Apache", "2.4.49")
    for k in ("success", "tech", "version", "model", "queried_at",
              "from_cache", "cves", "citations", "inline_urls", "summary"):
        assert k in out


def test_request_payload_includes_user_prompt(monkeypatch) -> None:
    monkeypatch.setenv("PERPLEXITY_API_KEY", "k")
    captured: list[str] = []

    def responder(url, headers, body):
        captured.append(body)
        return _resp(status=200, body=_perplexity_body("none"))

    _patch_http(monkeypatch, responder)
    cve_intel_search("Apache HTTP Server", "2.4.49")
    assert captured
    payload = json.loads(captured[0])
    user_msg = next(m for m in payload["messages"] if m["role"] == "user")
    assert "Apache HTTP Server" in user_msg["content"]
    assert "2.4.49" in user_msg["content"]
