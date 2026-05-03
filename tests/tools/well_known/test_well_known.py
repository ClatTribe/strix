"""Tests for the .well-known/ harvester.

Hermetic — `_http_get` is mocked. Tests cover:
- All 13 standard paths probed (incl. legacy on / off)
- security.txt parsing (RFC 9116 fields)
- openid-configuration parsing (only useful keys retained)
- apple-app-site-association parsing
- 404 / 401 / 403 silently skipped (not findings)
- 200 hit → finding emitted with description_plain populated where applicable
- Cluster-A composition (excluded path → recorded in errors[], no finding)
- Origin extraction from URL with path / bare hostname / port
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety
from strix.tools.well_known import well_known as wk


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
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("wk-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://example.com"}]})
    yield


def _patch_http(monkeypatch, responses):
    """responses: dict keyed by URL → response dict."""
    log: list[str] = []

    def fake_get(url):
        log.append(url)
        return responses.get(url, {"status": 404, "headers": {}, "body": ""})

    monkeypatch.setattr(wk, "_http_get", fake_get)
    return log


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_target_rejected() -> None:
    out = wk.well_known_harvest("")
    assert out["success"] is False


def test_invalid_scheme_rejected(monkeypatch) -> None:
    out = wk.well_known_harvest("ftp://example.com")
    assert out["success"] is False


def test_origin_extraction(monkeypatch) -> None:
    """Path on input URL is stripped — only origin (scheme+host) used for probing."""
    log = _patch_http(monkeypatch, {})
    wk.well_known_harvest("https://example.com/some/page?x=y")
    assert all("/some/page" not in u and "?x=y" not in u for u in log)
    assert all(u.startswith("https://example.com/") for u in log)


def test_bare_hostname_gets_https(monkeypatch) -> None:
    log = _patch_http(monkeypatch, {})
    wk.well_known_harvest("example.com")
    assert all(u.startswith("https://example.com/") for u in log)


# ---------------------------------------------------------------------------
# Path probing
# ---------------------------------------------------------------------------


def test_all_standard_paths_probed(monkeypatch) -> None:
    log = _patch_http(monkeypatch, {})
    wk.well_known_harvest("https://example.com")
    # Should probe all 13 standard paths (including legacy by default).
    paths = [u.replace("https://example.com", "") for u in log]
    expected_paths = [p for p, _, _, _ in wk._WELL_KNOWN_PATHS]
    assert sorted(paths) == sorted(expected_paths)


def test_include_legacy_false_drops_legacy(monkeypatch) -> None:
    log = _patch_http(monkeypatch, {})
    wk.well_known_harvest("https://example.com", include_legacy=False)
    paths = [u.replace("https://example.com", "") for u in log]
    # All probed paths must start with /.well-known/
    assert all(p.startswith("/.well-known/") for p in paths)
    # Legacy paths absent.
    assert "/security.txt" not in paths
    assert "/humans.txt" not in paths


def test_404_paths_silently_skipped(monkeypatch) -> None:
    """404 / 403 / 401 are NOT hits — no finding, no entry in hits[]."""
    _patch_http(monkeypatch, {})  # everything 404 by default
    out = wk.well_known_harvest("https://example.com")
    assert out["hits"] == []
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# security.txt
# ---------------------------------------------------------------------------


SECURITY_TXT_BODY = """\
# Our security disclosure policy
Contact: mailto:security@example.com
Contact: https://example.com/security
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/security/thanks
Canonical: https://example.com/.well-known/security.txt
Expires: 2030-01-01T00:00:00.000Z
Policy: https://example.com/security-policy
Preferred-Languages: en, fr
"""


def test_security_txt_parsed_and_finding_emitted(monkeypatch) -> None:
    _patch_http(
        monkeypatch,
        {
            "https://example.com/.well-known/security.txt": {
                "status": 200,
                "headers": {"content-type": "text/plain"},
                "body": SECURITY_TXT_BODY,
            },
        },
    )
    out = wk.well_known_harvest("https://example.com")
    sec = next(h for h in out["hits"] if h["path"] == "/.well-known/security.txt")
    assert isinstance(sec["parsed"], dict)
    # Multi-value `Contact:` becomes a list.
    assert isinstance(sec["parsed"]["contact"], list)
    assert "mailto:security@example.com" in sec["parsed"]["contact"]
    # Single-value field is a string.
    assert sec["parsed"]["expires"] == "2030-01-01T00:00:00.000Z"
    # Comments dropped.
    assert "# Our security" not in str(sec["parsed"])

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    sec_findings = [r for r in reports if "security.txt" in r.get("title", "").lower()]
    assert len(sec_findings) == 1
    assert sec_findings[0]["severity"] == "info"
    assert sec_findings[0]["category"] == "info_disclosure"
    assert "security@example.com" in sec_findings[0].get("description_plain", "")


def test_security_txt_legacy_root_path(monkeypatch) -> None:
    """Pre-RFC `/security.txt` at root is also probed by default."""
    _patch_http(
        monkeypatch,
        {
            "https://example.com/security.txt": {
                "status": 200,
                "headers": {"content-type": "text/plain"},
                "body": "Contact: mailto:legacy@example.com\n",
            },
        },
    )
    out = wk.well_known_harvest("https://example.com")
    legacy_hit = next(h for h in out["hits"] if h["path"] == "/security.txt")
    assert legacy_hit["parsed"]["contact"] == "mailto:legacy@example.com"


# ---------------------------------------------------------------------------
# openid-configuration
# ---------------------------------------------------------------------------


OPENID_CONFIG = json.dumps({
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/oauth/authorize",
    "token_endpoint": "https://example.com/oauth/token",
    "jwks_uri": "https://example.com/.well-known/jwks.json",
    "userinfo_endpoint": "https://example.com/userinfo",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code", "id_token"],
    "id_token_signing_alg_values_supported": ["RS256", "ES256"],
    # Noise field that should NOT be retained.
    "internal_debug_field": "ignore-me",
})


def test_openid_configuration_parsed(monkeypatch) -> None:
    _patch_http(
        monkeypatch,
        {
            "https://example.com/.well-known/openid-configuration": {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": OPENID_CONFIG,
            },
        },
    )
    out = wk.well_known_harvest("https://example.com")
    oid = next(h for h in out["hits"] if h["path"] == "/.well-known/openid-configuration")
    parsed = oid["parsed"]
    assert parsed["issuer"] == "https://example.com"
    assert parsed["authorization_endpoint"] == "https://example.com/oauth/authorize"
    assert parsed["jwks_uri"] == "https://example.com/.well-known/jwks.json"
    # Noise key dropped.
    assert "internal_debug_field" not in parsed

    # Plain-English summary populated.
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    oid_finding = next(r for r in reports if "OpenID" in r.get("title", ""))
    plain = oid_finding.get("description_plain", "")
    assert "OpenID Connect" in plain or "OAuth" in plain
    assert "https://example.com" in plain


# ---------------------------------------------------------------------------
# Apple / Android / GPC / change-password
# ---------------------------------------------------------------------------


def test_apple_app_site_association_parsed(monkeypatch) -> None:
    body = json.dumps({
        "applinks": {"apps": [], "details": [{"appID": "ABCD.com.example", "paths": ["/x", "/y"]}]},
        "webcredentials": {"apps": ["ABCD.com.example"]},
    })
    _patch_http(
        monkeypatch,
        {
            "https://example.com/.well-known/apple-app-site-association": {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": body,
            },
        },
    )
    out = wk.well_known_harvest("https://example.com")
    aasa = next(h for h in out["hits"] if "apple" in h["path"])
    parsed = aasa["parsed"]
    assert "applinks" in parsed
    # Lists of dicts collapsed to count.
    assert isinstance(parsed["applinks"], (str, dict))


def test_change_password_redirect_captured(monkeypatch) -> None:
    _patch_http(
        monkeypatch,
        {
            "https://example.com/.well-known/change-password": {
                "status": 302,
                "headers": {"location": "https://example.com/account/security"},
                "body": "",
            },
        },
    )
    out = wk.well_known_harvest("https://example.com")
    cp = next(h for h in out["hits"] if h["path"] == "/.well-known/change-password")
    assert cp["parsed"]["location"] == "https://example.com/account/security"


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_excluded_path_recorded_in_errors(monkeypatch) -> None:
    """An excluded well-known path → entry in errors[], no finding."""

    def fake_get(url):
        if "security.txt" in url:
            return {
                "status": 0, "headers": {}, "body": "",
                "skipped": True, "error": None,
            }
        return {"status": 404, "headers": {}, "body": ""}

    monkeypatch.setattr(wk, "_http_get", fake_get)
    out = wk.well_known_harvest("https://example.com")
    excluded_errors = [e for e in out["errors"] if "exclude" in e.get("error", "").lower()]
    assert len(excluded_errors) >= 1
    # Skipped paths don't generate a finding.
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    sec_findings = [r for r in reports if "security.txt" in r.get("title", "").lower()]
    assert sec_findings == []


# ---------------------------------------------------------------------------
# Multi-hit scenario
# ---------------------------------------------------------------------------


def test_multiple_hits_all_emit_findings(monkeypatch) -> None:
    """A target that publishes security.txt + openid-configuration + assetlinks → 3 findings."""
    _patch_http(
        monkeypatch,
        {
            "https://example.com/.well-known/security.txt": {
                "status": 200, "headers": {}, "body": "Contact: mailto:s@example.com\n",
            },
            "https://example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {"content-type": "application/json"},
                "body": '{"issuer":"https://example.com"}',
            },
            "https://example.com/.well-known/assetlinks.json": {
                "status": 200, "headers": {"content-type": "application/json"},
                "body": '[{"relation":["delegate_permission/common.handle_all_urls"]}]',
            },
        },
    )
    out = wk.well_known_harvest("https://example.com")
    assert len(out["hits"]) == 3
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 3
    # All info severity.
    assert all(r["severity"] == "info" for r in reports)


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_one_check_event_emitted(monkeypatch) -> None:
    _patch_http(monkeypatch, {})
    wk.well_known_harvest("https://example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "well_known_harvest" in summary["by_category"]


# ---------------------------------------------------------------------------
# Wrapper UX baseline — every finding must have description_plain +
# recommended_action populated, even when the parser couldn't extract
# structured metadata.
# ---------------------------------------------------------------------------


def test_every_finding_has_plain_and_action(monkeypatch) -> None:
    """When all 13 paths return SPA catch-all HTML (no structured data
    extractable), every emitted finding should still carry a baseline
    description_plain + recommended_action populated from the per-path
    table."""
    catch_all_response = {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": "<!DOCTYPE html><html><body>SPA catch-all</body></html>",
    }
    _patch_http(
        monkeypatch,
        {f"https://example.com{p}": catch_all_response for p, _, _, _ in wk._WELL_KNOWN_PATHS},
    )
    wk.well_known_harvest("https://example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == len(wk._WELL_KNOWN_PATHS)
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"


def test_parser_derived_plain_overrides_baseline(monkeypatch) -> None:
    """When the parser successfully extracts structure (e.g. security.txt
    with a `Contact:` field), the parser-derived `description_plain`
    takes precedence over the baseline."""
    _patch_http(
        monkeypatch,
        {
            "https://example.com/.well-known/security.txt": {
                "status": 200,
                "headers": {"content-type": "text/plain"},
                "body": "Contact: mailto:rich-summary@example.com\n",
            },
        },
    )
    wk.well_known_harvest("https://example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    sec = next(r for r in reports if "security.txt" in r["title"])
    # Parser-derived summary mentions the contact value verbatim.
    assert "rich-summary@example.com" in sec["description_plain"]
    # And the baseline `recommended_action` is still populated.
    assert sec.get("recommended_action")


def test_baseline_table_covers_every_path() -> None:
    """Sanity: every path in _WELL_KNOWN_PATHS has a baseline entry. If
    new paths are added without baseline texts, this test fails."""
    paths_in_probe = {p for p, _, _, _ in wk._WELL_KNOWN_PATHS}
    paths_in_baseline = set(wk._WELL_KNOWN_BASELINE_TEXTS.keys())
    missing = paths_in_probe - paths_in_baseline
    assert not missing, f"missing baseline texts for paths: {missing}"
