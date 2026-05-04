"""Tests for sigma_rules_for_technique.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- Technique normalization (uppercase, sub-techniques, malformed
  rejected)
- No `STRIX_GITHUB_TOKEN` → success=False, no HTTP
- Successful query → rule list with name/path/html_url/repo/sha
- max_results cap honoured
- max_results clamped to 100 if higher
- 401 / 403 / 422 / 500 / invalid JSON → graceful failure
- Network error → graceful failure
- Cache hit returns from_cache=True without HTTP
- Cache key distinct per (technique, max_results)
- Cache disabled via env
- Stale cache served on failure
- Display-only contract: NO findings emitted
- Authorization Bearer header sent
- Query string includes attack.<technique-lower>
- check.completed events
- Result schema integrity
- github_token override beats env var
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


import strix.tools.sigma_lookup.sigma_lookup  # noqa: F401

sl_module = sys.modules["strix.tools.sigma_lookup.sigma_lookup"]
sigma_rules_for_technique = sl_module.sigma_rules_for_technique


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
    monkeypatch.delenv("STRIX_SIGMA_NO_CACHE", raising=False)
    monkeypatch.delenv("STRIX_GITHUB_TOKEN", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("sl-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_http(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=15.0):
        log.append({"url": url, "headers": dict(headers or {})})
        return responder(url, dict(headers or {}))

    monkeypatch.setattr(sl_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _gh_body(items: list[dict[str, Any]]) -> str:
    return json.dumps({"total_count": len(items), "incomplete_results": False, "items": items})


def _rule_item(*, name: str, path: str | None = None, repo: str = "SigmaHQ/sigma") -> dict[str, Any]:
    path = path or f"rules/web/{name}"
    return {
        "name": name,
        "path": path,
        "html_url": f"https://github.com/SigmaHQ/sigma/blob/master/{path}",
        "url": f"https://api.github.com/repositories/123/contents/{path}",
        "sha": "abc123def456",
        "repository": {"full_name": repo},
    }


# ---------------------------------------------------------------------------
# Technique normalization
# ---------------------------------------------------------------------------


def test_normalize_uppercases() -> None:
    assert sl_module._normalize_technique("t1190") == "T1190"


def test_normalize_subtechnique() -> None:
    assert sl_module._normalize_technique("T1078.004") == "T1078.004"


def test_normalize_rejects_malformed() -> None:
    assert sl_module._normalize_technique("T119") is None  # too short
    assert sl_module._normalize_technique("T11900") is None  # too long
    assert sl_module._normalize_technique("1190") is None  # missing T
    assert sl_module._normalize_technique("TXXXX") is None  # not numeric
    assert sl_module._normalize_technique("") is None
    assert sl_module._normalize_technique(None) is None  # type: ignore[arg-type]


def test_invalid_top_level_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call"))
    out = sigma_rules_for_technique("not-a-technique")
    assert out["success"] is False
    assert log == []


# ---------------------------------------------------------------------------
# Auth gating
# ---------------------------------------------------------------------------


def test_no_token_returns_failure(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda u, h: pytest.fail("should not call HTTP"))
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is False
    assert "STRIX_GITHUB_TOKEN" in out["error"]
    assert log == []


def test_token_from_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "ghp_test")
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("Authorization", ""))
        return _resp(status=200, body=_gh_body([]))

    _patch_http(monkeypatch, responder)
    sigma_rules_for_technique("T1190")
    assert captured == ["Bearer ghp_test"]


def test_explicit_github_token_wins(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "from-env")
    captured: list[str] = []

    def responder(url, h):
        captured.append(h.get("Authorization", ""))
        return _resp(status=200, body=_gh_body([]))

    _patch_http(monkeypatch, responder)
    sigma_rules_for_technique("T1190", github_token="explicit")
    assert "explicit" in captured[0]
    assert "from-env" not in captured[0]


# ---------------------------------------------------------------------------
# Query construction
# ---------------------------------------------------------------------------


def test_query_includes_attack_tag_lowercase(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    sigma_rules_for_technique("T1190")
    # Query string contains attack.t1190 (lowercase).
    assert any("attack.t1190" in entry["url"] for entry in log)


def test_query_subtechnique_lowercase(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    sigma_rules_for_technique("T1078.004")
    assert any("attack.t1078.004" in entry["url"] for entry in log)


def test_query_filters_to_sigmahq(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    sigma_rules_for_technique("T1190")
    assert any("repo:SigmaHQ/sigma" in entry["url"] for entry in log)


def test_query_per_page_honours_max_results(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    sigma_rules_for_technique("T1190", max_results=50)
    assert any("per_page=50" in entry["url"] for entry in log)


def test_max_results_clamped_to_100(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    sigma_rules_for_technique("T1190", max_results=500)
    assert any("per_page=100" in entry["url"] for entry in log)


# ---------------------------------------------------------------------------
# Successful queries
# ---------------------------------------------------------------------------


def test_successful_query_returns_rules(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    items = [
        _rule_item(name="public_exploit_appattack.yml", path="rules/web/public_exploit_appattack.yml"),
        _rule_item(name="apache_log4shell.yml", path="rules/web/apache_log4shell.yml"),
    ]
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body(items)))
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is True
    assert out["rule_count"] == 2
    assert out["rules"][0]["repo"] == "SigmaHQ/sigma"
    assert "html_url" in out["rules"][0]
    assert out["rules"][0]["sha"] == "abc123def456"


def test_max_results_caps_returned_rules(monkeypatch) -> None:
    """If GitHub returns more items than max_results, cap to max_results."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    items = [_rule_item(name=f"rule_{i}.yml") for i in range(50)]
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body(items)))
    out = sigma_rules_for_technique("T1190", max_results=10)
    assert out["rule_count"] == 10


def test_empty_results(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is True
    assert out["rule_count"] == 0
    assert out["rules"] == []


# ---------------------------------------------------------------------------
# HTTP error handling
# ---------------------------------------------------------------------------


def test_401_no_cache_returns_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "bad")
    _patch_http(monkeypatch, lambda u, h: _resp(status=401))
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is False
    assert "401" in out["error"]


def test_403_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=403))
    out = sigma_rules_for_technique("T1190")
    assert "403" in out["error"]
    assert "rate-limited" in out["error"]


def test_422_invalid_query(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=422))
    out = sigma_rules_for_technique("T1190")
    assert "422" in out["error"]


def test_500_no_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=500))
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is False


def test_invalid_json_no_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body="not json"))
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is False


def test_network_error_no_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: {"status": 0, "headers": {}, "body": "", "error": "DNS"})
    out = sigma_rules_for_technique("T1190")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    items = [_rule_item(name="rule.yml")]
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body(items)))
    out1 = sigma_rules_for_technique("T1190")
    assert out1["from_cache"] is False
    pre = len(log)
    out2 = sigma_rules_for_technique("T1190")
    assert out2["from_cache"] is True
    assert len(log) == pre


def test_cache_key_distinct_per_max_results(monkeypatch) -> None:
    """Same technique, different max_results → different cache slots."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    items = [_rule_item(name="rule.yml")]
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body(items)))
    sigma_rules_for_technique("T1190", max_results=10)
    pre = len(log)
    sigma_rules_for_technique("T1190", max_results=20)
    assert len(log) > pre


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SIGMA_NO_CACHE", "1")
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    items = [_rule_item(name="rule.yml")]
    log = _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body(items)))
    sigma_rules_for_technique("T1190")
    pre = len(log)
    sigma_rules_for_technique("T1190")
    assert len(log) > pre


def test_stale_cache_served_on_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    fail_now = [False]
    items = [_rule_item(name="rule.yml")]

    def responder(url, h):
        if fail_now[0]:
            return _resp(status=500)
        return _resp(status=200, body=_gh_body(items))

    _patch_http(monkeypatch, responder)
    out1 = sigma_rules_for_technique("T1190")
    assert out1["from_cache"] is False

    cache_path = sl_module._cache_path("T1190", 20)
    old_mtime = time.time() - 48 * 3600
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    fail_now[0] = True
    out2 = sigma_rules_for_technique("T1190")
    assert out2["from_cache"] is True
    assert "stale cache" in (out2.get("error") or "")


# ---------------------------------------------------------------------------
# Display-only contract
# ---------------------------------------------------------------------------


def test_no_findings_emitted(monkeypatch) -> None:
    """Tool must NEVER emit findings — display-only enrichment."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    items = [_rule_item(name="rule.yml")]
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body(items)))
    sigma_rules_for_technique("T1190")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([])))
    sigma_rules_for_technique("T1190")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["sigma_lookup"]["not_vulnerable"] == 1


def test_check_event_inconclusive_without_token(monkeypatch) -> None:
    sigma_rules_for_technique("T1190")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["sigma_lookup"]["inconclusive"] == 1


def test_check_event_inconclusive_on_failure(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=500))
    sigma_rules_for_technique("T1190")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["sigma_lookup"]["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "k")
    _patch_http(monkeypatch, lambda u, h: _resp(status=200, body=_gh_body([_rule_item(name="r.yml")])))
    out = sigma_rules_for_technique("T1190")
    for k in ("success", "technique", "queried_at", "from_cache",
              "rules", "rule_count", "max_results", "source_errors"):
        assert k in out
    if out["rules"]:
        for k in ("name", "path", "html_url", "url", "sha", "repo"):
            assert k in out["rules"][0]
