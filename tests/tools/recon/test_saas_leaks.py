"""Tests for saas_leak_discovery.

Hermetic — Bing API calls are mocked at the _http_get_json layer.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import saas_leaks as sl


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
    monkeypatch.delenv("STRIX_BING_KEY", raising=False)
    tracer = Tracer("saas-leaks-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_bing(monkeypatch, *, status: int = 200, results=None, raw=None):
    """Patch _http_get_json to return a Bing-shaped response.

    `results` is a list of {url, name, snippet}; alternatively pass `raw`
    to inject a custom response body.
    """
    if raw is None:
        raw = {
            "webPages": {
                "value": [
                    {
                        "url": r["url"],
                        "name": r.get("name", ""),
                        "snippet": r.get("snippet", ""),
                    }
                    for r in (results or [])
                ]
            }
        }

    def fake(url, *, headers=None, params=None):
        return (status, raw)

    monkeypatch.setattr(sl, "_http_get_json", fake)


# ---------------------------------------------------------------------------
# Validation & key gating
# ---------------------------------------------------------------------------


def test_empty_org_rejected() -> None:
    out = sl.saas_leak_discovery("")
    assert out["success"] is False


def test_no_bing_key_fails_open() -> None:
    out = sl.saas_leak_discovery("example.com")
    assert out["success"] is False
    assert out["error_reason"] == "no api key configured"


def test_unknown_provider_rejected(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    out = sl.saas_leak_discovery("example.com", providers="trello,bogus")
    assert out["success"] is False
    assert "bogus" in str(out["error"])


# ---------------------------------------------------------------------------
# Happy paths per provider
# ---------------------------------------------------------------------------


def test_trello_hit_emits_info_finding(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(
        monkeypatch,
        results=[
            {
                "url": "https://trello.com/b/abc123/example-roadmap",
                "name": "Example - Product Roadmap",
                "snippet": "Q3 features for Example.com",
            }
        ],
    )
    out = sl.saas_leak_discovery("example.com", providers="trello")
    assert out["success"] is True
    assert out["hit_count"] == 1
    assert out["secret_leak_count"] == 0
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "info"
    assert reports[0]["category"] == "info_disclosure"


def test_pastebin_hit_with_secret_indicator_emits_high(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(
        monkeypatch,
        results=[
            {
                "url": "https://pastebin.com/raw/abcXYZ12",
                "name": "config dump",
                "snippet": "API_KEY=sk_live_abc for example.com production",
            }
        ],
    )
    out = sl.saas_leak_discovery("example.com", providers="pastebin")
    assert out["secret_leak_count"] == 1
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports[0]["severity"] == "high"
    assert reports[0]["verification_status"] == "needs_review"


def test_notion_subdomain_url_pattern(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(
        monkeypatch,
        results=[
            {
                "url": "https://example-team.notion.site/Internal-Runbook-abc123",
                "name": "Internal Runbook",
                "snippet": "Step-by-step deployment for example.com",
            }
        ],
    )
    out = sl.saas_leak_discovery("example.com", providers="notion")
    assert out["hit_count"] == 1


def test_google_docs_pattern_match(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(
        monkeypatch,
        results=[
            {
                "url": "https://docs.google.com/document/d/abc123/edit",
                "name": "Customer Pipeline",
                "snippet": "Customer pipeline for example.com",
            },
            {
                "url": "https://docs.google.com/spreadsheets/d/xyz789/edit",
                "name": "Q3 Numbers",
                "snippet": "Internal Q3 numbers for example.com",
            },
        ],
    )
    out = sl.saas_leak_discovery("example.com", providers="google_docs")
    assert out["hit_count"] == 2


# ---------------------------------------------------------------------------
# Filtering: site:<x> can return tangential pages
# ---------------------------------------------------------------------------


def test_url_pattern_filters_out_non_matching(monkeypatch) -> None:
    """Bing's site:trello.com sometimes returns trello.com homepage / blog
    pages — they should be filtered out by the URL pattern."""
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(
        monkeypatch,
        results=[
            {"url": "https://trello.com/b/abc/example-board", "name": "Board", "snippet": "..."},
            {"url": "https://trello.com/", "name": "Trello home", "snippet": "..."},
            {"url": "https://blog.trello.com/about", "name": "Blog", "snippet": "..."},
        ],
    )
    out = sl.saas_leak_discovery("example.com", providers="trello")
    block = out["per_provider"][0]
    assert block["raw_count"] == 3
    assert len(block["hits"]) == 1
    assert "trello.com/b/" in block["hits"][0]["url"]


# ---------------------------------------------------------------------------
# Bing error paths
# ---------------------------------------------------------------------------


def test_bing_unauthorized(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "bad-key")
    _patch_bing(monkeypatch, status=401, raw={})
    out = sl.saas_leak_discovery("example.com", providers="trello")
    block = out["per_provider"][0]
    assert block["success"] is False
    assert block["error"] == "unauthorized"


def test_bing_rate_limited(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(monkeypatch, status=429, raw={})
    out = sl.saas_leak_discovery("example.com", providers="trello")
    block = out["per_provider"][0]
    assert block["error"] == "rate_limited"


def test_bing_unexpected_status(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(monkeypatch, status=503, raw={})
    out = sl.saas_leak_discovery("example.com", providers="trello")
    block = out["per_provider"][0]
    assert block["error"] == "http_503"


def test_bing_empty_response(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(monkeypatch, status=200, raw={"webPages": {"value": []}})
    out = sl.saas_leak_discovery("example.com", providers="trello")
    assert out["hit_count"] == 0
    block = out["per_provider"][0]
    assert block["success"] is True


# ---------------------------------------------------------------------------
# Multi-provider behaviour
# ---------------------------------------------------------------------------


def test_default_all_providers(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(monkeypatch, results=[])
    out = sl.saas_leak_discovery("example.com")
    assert set(out["providers_queried"]) == {
        "trello", "notion", "google_docs", "google_drive",
        "pastebin", "confluence_cloud", "airtable",
    }


def test_max_results_clamp(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    captured: list[dict] = []

    def fake(url, *, headers=None, params=None):
        captured.append(params or {})
        return (200, {"webPages": {"value": []}})

    monkeypatch.setattr(sl, "_http_get_json", fake)
    sl.saas_leak_discovery(
        "example.com", providers="trello", max_results_per_provider=999
    )
    sent = int(captured[0].get("count", "0"))
    assert sent <= 50


def test_emits_one_check_per_provider(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    _patch_bing(monkeypatch, results=[])
    sl.saas_leak_discovery("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    # 7 providers in default-all.
    assert summary["total"] == 7
    assert "saas_leaks" in summary["by_category"]


def test_dotted_org_name_uses_first_label(monkeypatch) -> None:
    """For 'example.com', the search term should be 'example' (no dot)."""
    monkeypatch.setenv("STRIX_BING_KEY", "fake")
    captured: list[dict] = []

    def fake(url, *, headers=None, params=None):
        captured.append(params or {})
        return (200, {"webPages": {"value": []}})

    monkeypatch.setattr(sl, "_http_get_json", fake)
    sl.saas_leak_discovery("example.com", providers="trello")
    q = captured[0].get("q", "")
    assert '"example"' in q
    assert '"example.com"' not in q
