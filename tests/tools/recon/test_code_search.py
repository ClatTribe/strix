"""Tests for code_search_for_domain.

Hermetic — every external HTTP call is mocked.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import code_search as cs


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("STRIX_GITLAB_TOKEN", raising=False)
    tracer = Tracer("code-search-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_get_json(monkeypatch, responses_by_url_substr):
    """Patch _http_get_json so each URL substring routes to a fixed response."""

    def fake(url, *, headers=None, params=None):
        for needle, response in responses_by_url_substr.items():
            if needle in url:
                return response
        return (404, None)

    monkeypatch.setattr(cs, "_http_get_json", fake)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_domain_rejected() -> None:
    out = cs.code_search_for_domain("not a domain")
    assert out["success"] is False


def test_unknown_provider_rejected(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    out = cs.code_search_for_domain("example.com", providers="github,bogus")
    assert out["success"] is False
    assert "bogus" in str(out["error"])


def test_no_keys_at_all_returns_clear_error() -> None:
    """No GITHUB token, default-all providers — github silently dropped,
    gitlab works keyless... but if both end up unavailable, error_reason."""
    out = cs.code_search_for_domain("example.com", providers="github")
    # github explicitly requested without key → clear error.
    assert out["success"] is False
    assert "STRIX_GITHUB_TOKEN" in str(out["error_reason"])


# ---------------------------------------------------------------------------
# GitHub provider
# ---------------------------------------------------------------------------


def test_github_happy_path_emits_info_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake-token")
    payload = {
        "total_count": 1,
        "items": [
            {
                "repository": {"full_name": "octo/repo"},
                "path": "config/dev.yml",
                "html_url": "https://github.com/octo/repo/blob/main/config/dev.yml",
                "text_matches": [
                    {"fragment": "host: api.example.com  # internal"}
                ],
            }
        ],
    }
    _patch_get_json(monkeypatch, {"api.github.com": (200, payload)})
    out = cs.code_search_for_domain("example.com", providers="github")
    assert out["success"] is True
    assert out["hit_count"] == 1
    assert out["secret_leak_count"] == 0
    # Subdomain extracted from snippet.
    assert "api.example.com" in out["extracted_subdomains"]

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "info"
    assert reports[0]["category"] == "info_disclosure"


def test_github_secret_indicator_escalates_to_high(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake-token")
    payload = {
        "total_count": 1,
        "items": [
            {
                "repository": {"full_name": "octo/repo"},
                "path": "src/config.py",
                "html_url": "https://github.com/octo/repo/blob/main/src/config.py",
                "text_matches": [
                    {
                        "fragment": (
                            'API_KEY = "abc123" # used for example.com integration'
                        )
                    }
                ],
            }
        ],
    }
    _patch_get_json(monkeypatch, {"api.github.com": (200, payload)})
    out = cs.code_search_for_domain("example.com", providers="github")
    assert out["secret_leak_count"] == 1
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"
    assert reports[0]["category"] == "secret_leak"


def test_github_unauthorized(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "bad-token")
    _patch_get_json(monkeypatch, {"api.github.com": (401, {})})
    out = cs.code_search_for_domain("example.com", providers="github")
    block = out["per_provider"][0]
    assert block["success"] is False
    assert "unauthorized" in block["error"]


def test_github_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    _patch_get_json(monkeypatch, {"api.github.com": (403, {})})
    out = cs.code_search_for_domain("example.com", providers="github")
    block = out["per_provider"][0]
    assert block["success"] is False
    assert "rate_limited" in block["error"]


def test_github_dropped_when_no_token_default(monkeypatch) -> None:
    """Default-all providers without a GitHub token should silently drop github."""
    # GitLab returns empty list (success path, no hits).
    _patch_get_json(monkeypatch, {"gitlab.com": (200, [])})
    out = cs.code_search_for_domain("example.com")
    assert "github" not in out["providers_queried"]
    assert "gitlab" in out["providers_queried"]


# ---------------------------------------------------------------------------
# GitLab provider
# ---------------------------------------------------------------------------


def test_gitlab_happy_path(monkeypatch) -> None:
    payload = [
        {
            "project_id": 42,
            "path": "infra/terraform/main.tf",
            "filename": "main.tf",
            "ref": "main",
            "data": "endpoint = \"https://staging.example.com\"\nversion = 2",
        }
    ]
    _patch_get_json(monkeypatch, {"gitlab.com": (200, payload)})
    out = cs.code_search_for_domain("example.com", providers="gitlab")
    assert out["hit_count"] == 1
    assert "staging.example.com" in out["extracted_subdomains"]


def test_gitlab_keyless_works(monkeypatch) -> None:
    """No STRIX_GITLAB_TOKEN should still let GitLab queries through."""
    _patch_get_json(monkeypatch, {"gitlab.com": (200, [])})
    out = cs.code_search_for_domain("example.com", providers="gitlab")
    assert out["success"] is True
    assert out["hit_count"] == 0


def test_gitlab_429_rate_limit(monkeypatch) -> None:
    _patch_get_json(monkeypatch, {"gitlab.com": (429, {})})
    out = cs.code_search_for_domain("example.com", providers="gitlab")
    block = out["per_provider"][0]
    assert block["error"] == "rate_limited"


# ---------------------------------------------------------------------------
# Subdomain extraction & secret detection
# ---------------------------------------------------------------------------


def test_subdomain_extraction_filters_apex(monkeypatch) -> None:
    """The apex itself should not appear in extracted_subdomains."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    payload = {
        "total_count": 1,
        "items": [
            {
                "repository": {"full_name": "o/r"},
                "path": "x.txt",
                "html_url": "https://github.com/o/r/blob/main/x.txt",
                "text_matches": [
                    {"fragment": "see https://example.com and dev.example.com here"}
                ],
            }
        ],
    }
    _patch_get_json(monkeypatch, {"api.github.com": (200, payload)})
    out = cs.code_search_for_domain("example.com", providers="github")
    assert "dev.example.com" in out["extracted_subdomains"]
    assert "example.com" not in out["extracted_subdomains"]


def test_secret_pattern_variants(monkeypatch) -> None:
    """Different secret-indicator tokens should each escalate severity."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    cases = [
        "AWS_SECRET_KEY=AKIAEXAMPLE for example.com",
        "client_secret = 'abc' # for example.com",
        "Bearer eyJhbG... # talks to example.com",
        "ghp_ABCDEFG # github token used by example.com",
    ]
    for snippet in cases:
        payload = {
            "total_count": 1,
            "items": [
                {
                    "repository": {"full_name": "o/r"},
                    "path": "x.py",
                    "html_url": "https://github.com/o/r/blob/main/x.py",
                    "text_matches": [{"fragment": snippet}],
                }
            ],
        }
        _patch_get_json(monkeypatch, {"api.github.com": (200, payload)})
        out = cs.code_search_for_domain("example.com", providers="github")
        assert out["secret_leak_count"] == 1, f"failed for: {snippet}"


def test_no_secret_in_plain_url_reference(monkeypatch) -> None:
    """A plain URL mention without secret tokens stays at info severity."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    payload = {
        "total_count": 1,
        "items": [
            {
                "repository": {"full_name": "o/r"},
                "path": "README.md",
                "html_url": "https://github.com/o/r/blob/main/README.md",
                "text_matches": [{"fragment": "Visit https://docs.example.com for details"}],
            }
        ],
    }
    _patch_get_json(monkeypatch, {"api.github.com": (200, payload)})
    out = cs.code_search_for_domain("example.com", providers="github")
    assert out["secret_leak_count"] == 0
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# Multi-provider behaviour
# ---------------------------------------------------------------------------


def test_max_results_clamp(monkeypatch) -> None:
    """max_results > 100 should be clamped at the hard cap."""
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    captured_params: list[dict] = []

    def fake(url, *, headers=None, params=None):
        captured_params.append(params or {})
        return (200, {"items": []})

    monkeypatch.setattr(cs, "_http_get_json", fake)
    cs.code_search_for_domain("example.com", providers="github", max_results=999)
    # The sent per_page must be <= 100.
    sent = int(captured_params[0].get("per_page", "0"))
    assert sent <= 100


def test_emits_one_check_per_provider(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_GITHUB_TOKEN", "fake")
    _patch_get_json(
        monkeypatch,
        {"api.github.com": (200, {"items": []}), "gitlab.com": (200, [])},
    )
    cs.code_search_for_domain("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 2
    assert "code_search" in summary["by_category"]
