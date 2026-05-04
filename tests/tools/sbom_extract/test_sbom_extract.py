"""Tests for sbom_extract (roadmap §16 / PR #131)."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.sbom_extract.sbom_extract  # noqa: F401

sb_module = sys.modules["strix.tools.sbom_extract.sbom_extract"]
sbom_extract = sb_module.sbom_extract


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
    tracer = Tracer("sbom-test")
    set_global_tracer(tracer)
    yield


def _patch_get(monkeypatch, *, body: str, headers: dict[str, str] | None = None) -> None:
    def fake(url, *, timeout=10.0):
        return {"status": 200, "headers": dict(headers or {}), "body": body}

    monkeypatch.setattr(sb_module, "_http_get", fake)


# ---------------------------------------------------------------------------
# CDN URL parsing (pure helper)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected_name,expected_version,expected_cdn",
    [
        ("https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.global.min.js", "vue", "3.4.21", "jsdelivr"),
        ("https://unpkg.com/react@18.3.1/umd/react.production.min.js", "react", "18.3.1", "unpkg"),
        ("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.0/jquery.min.js", "jquery", "3.7.0", "cdnjs"),
        ("https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.min.js", "angularjs", "1.8.3", "google_ajax"),
    ],
)
def test_parse_cdn_url(url: str, expected_name: str, expected_version: str, expected_cdn: str) -> None:
    parsed = sb_module._parse_cdn_url(url)
    assert parsed is not None
    assert parsed["name"] == expected_name
    assert parsed["version"] == expected_version
    assert parsed["cdn"] == expected_cdn


def test_parse_cdn_url_scoped_npm_pkg() -> None:
    """`@angular/core@1.2.3` → name=`@angular/core`, version=`1.2.3`."""
    parsed = sb_module._parse_cdn_url(
        "https://unpkg.com/@angular/core@17.3.0/fesm2022/core.mjs"
    )
    assert parsed is not None
    assert parsed["name"] == "@angular/core"
    assert parsed["version"] == "17.3.0"


def test_parse_cdn_url_unrecognised_returns_none() -> None:
    assert sb_module._parse_cdn_url("https://example.com/static/app.js") is None


# ---------------------------------------------------------------------------
# Header-based backend detection
# ---------------------------------------------------------------------------


def test_server_header_with_version_extracted(monkeypatch) -> None:
    _patch_get(monkeypatch, body="<html></html>", headers={"server": "nginx/1.21.6"})
    out = sbom_extract("https://example.com")
    nginx = next(c for c in out["components"] if c["name"] == "nginx")
    assert nginx["version"] == "1.21.6"
    assert nginx["detected_via"] == "header:server"


def test_x_powered_by_header_extracted(monkeypatch) -> None:
    _patch_get(monkeypatch, body="", headers={"x-powered-by": "Express"})
    out = sbom_extract("https://example.com")
    express = next(c for c in out["components"] if c["name"] == "express")
    assert express["version"] is None  # no version in header
    assert express["detected_via"] == "header:x-powered-by"


def test_server_header_with_extra_tokens(monkeypatch) -> None:
    """`Server: nginx/1.21.0 (Ubuntu)` → first-token parse."""
    _patch_get(monkeypatch, body="", headers={"server": "nginx/1.21.0 (Ubuntu)"})
    out = sbom_extract("https://example.com")
    nginx = next(c for c in out["components"] if c["name"] == "nginx")
    assert nginx["version"] == "1.21.0"


# ---------------------------------------------------------------------------
# CDN-extraction via HTML
# ---------------------------------------------------------------------------


def test_cdn_script_tags_extracted(monkeypatch) -> None:
    body = '''
    <html><head>
      <script src="https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.global.min.js"></script>
      <script src="https://unpkg.com/react@18.3.1/umd/react.production.min.js"></script>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
    </head></html>
    '''
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")

    names = {c["name"] for c in out["components"]}
    assert "vue" in names
    assert "react" in names
    assert "normalize" in names

    vue = next(c for c in out["components"] if c["name"] == "vue")
    assert vue["version"] == "3.4.21"
    assert vue["detected_via"] == "cdn:jsdelivr"
    assert vue["purl"].startswith("pkg:npm/")


def test_dedup_same_package_different_urls(monkeypatch) -> None:
    """Same (name, version) on jsdelivr AND a script tag → ONE component."""
    body = '''
    <script src="https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.global.min.js"></script>
    '''
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    vues = [c for c in out["components"] if c["name"] == "vue"]
    assert len(vues) == 1


def test_no_cdn_urls_no_components(monkeypatch) -> None:
    body = '<script src="/static/app.js"></script>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    # No CDN matches → only header-derived (none here).
    assert out["components_detected"] == 0


# ---------------------------------------------------------------------------
# Frontend framework detection
# ---------------------------------------------------------------------------


def test_react_marker_detected(monkeypatch) -> None:
    body = '<html><body><div data-reactroot></div></body></html>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    react = next(c for c in out["components"] if c["name"] == "react")
    assert react["detected_via"] == "html_marker"


def test_nextjs_marker_detected(monkeypatch) -> None:
    body = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    next_js = next(c for c in out["components"] if c["name"] == "next.js")
    assert next_js["detected_via"] == "html_marker"


def test_angular_marker_detected(monkeypatch) -> None:
    body = '<app-root ng-version="17.3.0"></app-root>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    angular = next(c for c in out["components"] if c["name"] == "angular")
    assert angular is not None


def test_meta_generator_with_version(monkeypatch) -> None:
    """`<meta name="generator" content="WordPress 6.2.1">` → name=wordpress, version=6.2.1."""
    body = '<meta name="generator" content="WordPress 6.2.1">'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    wp = next(c for c in out["components"] if c["name"] == "wordpress")
    assert wp["version"] == "6.2.1"
    assert wp["detected_via"] == "meta_generator"


# ---------------------------------------------------------------------------
# CycloneDX 1.5 envelope
# ---------------------------------------------------------------------------


def test_cyclonedx_envelope_shape(monkeypatch) -> None:
    body = '<script src="https://unpkg.com/react@18.3.1/x.js"></script>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")

    bom = out["cyclonedx"]
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert "serialNumber" in bom
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["name"] == "example.com"
    assert bom["metadata"]["component"]["type"] == "application"


def test_cyclonedx_component_has_purl(monkeypatch) -> None:
    body = '<script src="https://unpkg.com/react@18.3.1/x.js"></script>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    component = out["cyclonedx"]["components"][0]
    assert component["purl"] == "pkg:npm/react@18.3.1"
    assert component["bom-ref"]
    assert component["evidence"]["identity"]["confidence"] == 1.0  # version present


def test_cyclonedx_component_lower_confidence_no_version(monkeypatch) -> None:
    body = '<div data-reactroot></div>'
    _patch_get(monkeypatch, body=body)
    out = sbom_extract("https://example.com")
    component = out["cyclonedx"]["components"][0]
    # No version → 0.7 confidence
    assert component["evidence"]["identity"]["confidence"] == 0.7


def test_cyclonedx_written_to_run_dir(monkeypatch, tmp_path) -> None:
    body = '<script src="https://unpkg.com/react@18.3.1/x.js"></script>'
    _patch_get(monkeypatch, body=body)
    sbom_extract("https://example.com")

    sbom_file = tmp_path / "strix_runs" / "sbom-test" / "sbom.cdx.json"
    assert sbom_file.exists()
    bom = json.loads(sbom_file.read_text())
    assert bom["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "react" for c in bom["components"])


# ---------------------------------------------------------------------------
# URL validation + resilience
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert sbom_extract("")["success"] is False


def test_bare_host_normalised(monkeypatch) -> None:
    _patch_get(monkeypatch, body="")
    out = sbom_extract("example.com")
    assert out["success"] is True


def test_skipped_response_returns_empty_bom(monkeypatch) -> None:
    def fake(url, *, timeout=10.0):
        return {"status": 0, "headers": {}, "body": "", "skipped": True}

    monkeypatch.setattr(sb_module, "_http_get", fake)

    out = sbom_extract("https://example.com")
    assert out["success"] is True
    assert out["components_detected"] == 0
    assert out["cyclonedx"]["bomFormat"] == "CycloneDX"


def test_combined_detection(monkeypatch) -> None:
    """Server header + CDN script + meta generator all combine."""
    body = '''
    <html><head>
      <meta name="generator" content="Hugo 0.115.0">
      <script src="https://unpkg.com/react@18.3.1/x.js"></script>
    </head></html>
    '''
    _patch_get(monkeypatch, body=body, headers={"server": "nginx/1.21.0"})

    out = sbom_extract("https://example.com")
    names = {c["name"] for c in out["components"]}
    assert "nginx" in names
    assert "react" in names
    assert "hugo" in names


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    assert "T1592.002" in get_tool_mitre_techniques("sbom_extract")
