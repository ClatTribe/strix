"""Tests for discover_cloud_assets.

We mock `http_head` so the suite is hermetic — no network calls.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.tools.recon import cloud_assets


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
    tracer = Tracer("cloud-assets-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})
    yield


def _patch_head(monkeypatch, responses: dict[str, tuple[int, dict[str, str]]]) -> None:
    def fake_head(url: str, **_: Any) -> tuple[int, dict[str, str]]:
        return responses.get(url, (404, {}))

    monkeypatch.setattr(cloud_assets, "http_head", fake_head)


def test_no_org_name_rejected() -> None:
    out = cloud_assets.discover_cloud_assets("")
    assert out["success"] is False


def test_unknown_provider_rejected() -> None:
    out = cloud_assets.discover_cloud_assets("example", providers="lambda,s3")
    assert out["success"] is False
    assert "lambda" in str(out["error"])


def test_no_hits_when_all_404(monkeypatch) -> None:
    _patch_head(monkeypatch, {})  # everything 404
    out = cloud_assets.discover_cloud_assets("example", providers="s3")
    assert out["success"] is True
    assert out["hit_count"] == 0
    assert out["candidates_probed"] > 10  # default wordlist is non-empty
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_public_s3_emits_medium_finding(monkeypatch) -> None:
    _patch_head(
        monkeypatch,
        {"https://example.s3.amazonaws.com/": (200, {"Server": "AmazonS3"})},
    )
    out = cloud_assets.discover_cloud_assets("example.com", providers="s3")
    assert out["hit_count"] == 1
    hit = out["hits"][0]
    assert hit["provider"] == "aws_s3"
    assert hit["status"] == 200
    assert hit["severity"] == "medium"

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "info_disclosure"
    assert reports[0]["severity"] == "medium"


def test_403_s3_emits_info_finding(monkeypatch) -> None:
    _patch_head(
        monkeypatch,
        {"https://example-prod.s3.amazonaws.com/": (403, {"Server": "AmazonS3"})},
    )
    out = cloud_assets.discover_cloud_assets("example", providers="s3")
    assert out["hit_count"] == 1
    assert out["hits"][0]["severity"] == "info"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "info"


def test_extra_suffixes_expand_wordlist(monkeypatch) -> None:
    captured: list[str] = []

    def fake_head(url: str, **_: Any) -> tuple[int, dict[str, str]]:
        captured.append(url)
        return (404, {})

    monkeypatch.setattr(cloud_assets, "http_head", fake_head)
    cloud_assets.discover_cloud_assets(
        "example", providers="s3", extra_suffixes="-customer-data,-tenant-uploads"
    )
    assert any("example-customer-data.s3.amazonaws.com" in u for u in captured)
    assert any("example-tenant-uploads.s3.amazonaws.com" in u for u in captured)


def test_uses_first_label_of_dotted_org(monkeypatch) -> None:
    """For org_name='example.com' the bucket base should be 'example' (no dot)."""
    captured: list[str] = []

    def fake_head(url: str, **_: Any) -> tuple[int, dict[str, str]]:
        captured.append(url)
        return (404, {})

    monkeypatch.setattr(cloud_assets, "http_head", fake_head)
    cloud_assets.discover_cloud_assets("example.com", providers="s3")
    # No URL should contain "example.com" as a bucket name (would be invalid).
    assert not any("example.com.s3.amazonaws.com" in u for u in captured)
    # The base "example" should appear.
    assert any("//example.s3.amazonaws.com" in u for u in captured)


# ---------------------------------------------------------------------------
# PaaS providers
# ---------------------------------------------------------------------------


def test_heroku_hit_emits_info_finding(monkeypatch) -> None:
    _patch_head(monkeypatch, {"https://example.herokuapp.com/": (200, {})})
    out = cloud_assets.discover_cloud_assets("example", providers="heroku")
    assert out["hit_count"] == 1
    hit = out["hits"][0]
    assert hit["provider"] == "heroku"
    assert hit["severity"] == "info"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "info"
    # PaaS finding title differs from storage title.
    assert "Org-named" in reports[0]["title"]


def test_vercel_3xx_treated_as_hit(monkeypatch) -> None:
    """Vercel returns 3xx for active deployments — should still register."""
    _patch_head(monkeypatch, {"https://example.vercel.app/": (308, {})})
    out = cloud_assets.discover_cloud_assets("example", providers="vercel")
    assert out["hit_count"] == 1
    assert out["hits"][0]["provider"] == "vercel"


def test_netlify_404_no_hit(monkeypatch) -> None:
    _patch_head(monkeypatch, {})  # everything 404
    out = cloud_assets.discover_cloud_assets("example", providers="netlify")
    assert out["hit_count"] == 0
    # PaaS candidate set is smaller than storage's, but should still be > 0.
    assert out["candidates_probed"] > 0


def test_github_pages_hit(monkeypatch) -> None:
    _patch_head(monkeypatch, {"https://example.github.io/": (200, {})})
    out = cloud_assets.discover_cloud_assets("example", providers="github_pages")
    assert out["hit_count"] == 1
    assert out["hits"][0]["provider"] == "github_pages"


def test_supabase_401_treated_as_hit(monkeypatch) -> None:
    """Supabase 401 = live project (anon key required). Should be a hit."""
    _patch_head(monkeypatch, {"https://example.supabase.co/": (401, {})})
    out = cloud_assets.discover_cloud_assets("example", providers="supabase")
    assert out["hit_count"] == 1
    assert out["hits"][0]["provider"] == "supabase"


def test_firebase_hosting_hit(monkeypatch) -> None:
    _patch_head(monkeypatch, {"https://example.web.app/": (200, {})})
    out = cloud_assets.discover_cloud_assets("example", providers="firebase")
    assert out["hit_count"] == 1
    assert out["hits"][0]["provider"] == "firebase_hosting"


def test_paas_uses_smaller_candidate_list_than_storage(monkeypatch) -> None:
    """PaaS-provider candidates should be a smaller list than storage."""
    captured_storage: list[str] = []
    captured_paas: list[str] = []

    def fake_head(url: str, **_: Any) -> tuple[int, dict[str, str]]:
        if "s3.amazonaws.com" in url:
            captured_storage.append(url)
        elif "vercel.app" in url:
            captured_paas.append(url)
        return (404, {})

    monkeypatch.setattr(cloud_assets, "http_head", fake_head)
    cloud_assets.discover_cloud_assets("example", providers="s3,vercel")
    assert len(captured_storage) > len(captured_paas)
    assert len(captured_paas) > 0


def test_all_providers_default(monkeypatch) -> None:
    """providers=None should activate all 9 providers."""
    _patch_head(monkeypatch, {})
    out = cloud_assets.discover_cloud_assets("example")
    assert set(out["providers_checked"]) == {
        "s3", "gcs", "azure",
        "heroku", "vercel", "netlify", "github_pages", "firebase", "supabase",
    }


def test_candidates_probed_is_sum_across_providers(monkeypatch) -> None:
    """When multiple providers run, candidates_probed counts each provider's list."""
    _patch_head(monkeypatch, {})
    out_s3 = cloud_assets.discover_cloud_assets("example", providers="s3")
    out_vercel = cloud_assets.discover_cloud_assets("example", providers="vercel")
    out_both = cloud_assets.discover_cloud_assets("example", providers="s3,vercel")
    assert out_both["candidates_probed"] == out_s3["candidates_probed"] + out_vercel["candidates_probed"]
