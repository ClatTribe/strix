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
