"""Tests for sri_audit (roadmap §7.2 / §7.3 SRI nice-to-have).

Hermetic — `_http_get` is monkeypatched. Tests cover:

- URL normalisation
- External script without integrity → medium finding
- External script with integrity but no crossorigin → info
- External script with both integrity + crossorigin → no finding
- External stylesheet without integrity → low finding
- Same-origin script ignored (not a supply-chain risk)
- Inline scripts (<script>...) ignored (no src attribute)
- Multiple references to same CDN URL → ONE finding (per-asset dedup)
- Mixed quote styles + unquoted attributes parsed
- Attribute extraction edge cases
- Non-200 response → inconclusive
- --exclude-path → skipped
- Result schema
- MITRE T1592
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.sri_audit.sri_audit  # noqa: F401

sri_module = sys.modules["strix.tools.sri_audit.sri_audit"]
sri_audit = sri_module.sri_audit


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
    tracer = Tracer("sri-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _patch_get(monkeypatch, body: str, *, status: int = 200, skipped: bool = False):
    def fake(url, *, timeout=10.0):
        if skipped:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        return {"status": status, "headers": {"content-type": "text/html"}, "body": body}

    monkeypatch.setattr(sri_module, "_http_get", fake)


def _findings():
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert sri_audit("")["success"] is False
    assert sri_audit("ftp://x.com/")["success"] is False


def test_bare_host_normalised(monkeypatch) -> None:
    _patch_get(monkeypatch, body="<html><body>ok</body></html>")
    out = sri_audit("app.example.com")
    assert out["success"] is True
    assert out["target_url"].startswith("https://")


# ---------------------------------------------------------------------------
# Script tag detection
# ---------------------------------------------------------------------------


def test_external_script_without_integrity_emits_medium(monkeypatch) -> None:
    body = """
    <html>
      <head>
        <script src="https://cdn.example.org/lib.js"></script>
      </head>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 1
    findings = _findings()
    assert findings[0]["severity"] == "medium"
    assert findings[0]["category"] == "missing_sri"
    assert "cdn.example.org/lib.js" in findings[0]["description"]


def test_external_script_with_integrity_and_crossorigin_no_finding(monkeypatch) -> None:
    body = """
    <html>
      <script src="https://cdn.example.org/lib.js"
              integrity="sha384-abc"
              crossorigin="anonymous"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0


def test_external_script_with_integrity_no_crossorigin_emits_info(monkeypatch) -> None:
    body = """
    <html>
      <script src="https://cdn.example.org/lib.js"
              integrity="sha384-abc"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    findings = _findings()
    info = [f for f in findings if f["severity"] == "info"]
    assert len(info) == 1
    assert "crossorigin" in info[0]["title"]


def test_same_origin_script_ignored(monkeypatch) -> None:
    """Scripts loaded from the same origin aren't supply-chain risks."""
    body = """
    <html>
      <script src="https://app.example.com/static/main.js"></script>
      <script src="/static/other.js"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0


def test_inline_script_ignored(monkeypatch) -> None:
    body = """
    <html>
      <script>console.log('inline');</script>
      <script type="application/javascript">window.foo = 1;</script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0


def test_multiple_references_to_same_cdn_url_one_finding(monkeypatch) -> None:
    """Same CDN URL referenced 3 times → ONE finding (per-asset dedup)."""
    body = """
    <html>
      <script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 1


def test_multiple_distinct_external_scripts(monkeypatch) -> None:
    body = """
    <html>
      <script src="https://cdn-a.example.org/a.js"></script>
      <script src="https://cdn-b.example.org/b.js"></script>
      <script src="https://cdn-c.example.org/c.js"
              integrity="sha384-xyz" crossorigin="anonymous"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    # Two external scripts without integrity → 2 findings;
    # one with integrity+crossorigin → 0.
    assert out["findings_emitted"] == 2


# ---------------------------------------------------------------------------
# Stylesheet tag detection
# ---------------------------------------------------------------------------


def test_external_stylesheet_without_integrity_emits_low(monkeypatch) -> None:
    body = """
    <html>
      <head>
        <link rel="stylesheet" href="https://cdn.example.org/style.css">
      </head>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    findings = _findings()
    assert any(f["severity"] == "low" for f in findings)
    assert any("stylesheet" in f["title"].lower() for f in findings)


def test_link_rel_other_ignored(monkeypatch) -> None:
    """<link rel="icon"> shouldn't trigger SRI findings (it's not loaded as code)."""
    body = """
    <html>
      <head>
        <link rel="icon" href="https://cdn.example.org/favicon.ico">
        <link rel="manifest" href="https://cdn.example.org/manifest.json">
      </head>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0


def test_external_stylesheet_with_integrity_no_finding(monkeypatch) -> None:
    body = """
    <html>
      <link rel="stylesheet" href="https://cdn.example.org/style.css"
            integrity="sha384-abc" crossorigin="anonymous">
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Attribute parsing
# ---------------------------------------------------------------------------


def test_mixed_quote_styles_parsed(monkeypatch) -> None:
    body = """
    <html>
      <script src='https://cdn.example.org/a.js'></script>
      <script src="https://cdn.example.org/b.js"></script>
      <script src=https://cdn.example.org/c.js></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    # All three are external → all three flagged.
    assert out["findings_emitted"] == 3


def test_attribute_order_irrelevant(monkeypatch) -> None:
    """integrity= might appear before src= in the tag — still detected."""
    body = """
    <html>
      <script integrity="sha384-x" crossorigin="anonymous"
              src="https://cdn.example.org/lib.js"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0


def test_relative_url_treated_as_same_origin(monkeypatch) -> None:
    body = """
    <html>
      <script src="../static/main.js"></script>
      <script src="/assets/bundle.js"></script>
    </html>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    # Both relative → same-origin → no findings.
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------


def test_non_200_inconclusive(monkeypatch) -> None:
    _patch_get(monkeypatch, body="", status=404)
    out = sri_audit("https://app.example.com")
    assert out["findings_emitted"] == 0
    assert out["assets_examined"] == 0


def test_excluded_path_skipped(monkeypatch) -> None:
    _patch_get(monkeypatch, body="", skipped=True)
    out = sri_audit("https://app.example.com")
    assert out.get("skipped") is True
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, body="<html></html>")
    out = sri_audit("https://app.example.com")
    assert set(out.keys()) >= {
        "success", "target_url", "target_host",
        "assets_examined", "external_scripts", "external_links",
        "findings_emitted",
    }


def test_external_scripts_recorded(monkeypatch) -> None:
    body = """
    <script src="https://cdn.example.org/a.js" integrity="sha384-x" crossorigin="anonymous"></script>
    <script src="https://cdn.example.org/b.js"></script>
    """
    _patch_get(monkeypatch, body=body)
    out = sri_audit("https://app.example.com")
    assert len(out["external_scripts"]) == 2
    flags = {(s["src"], s["has_integrity"], s["has_crossorigin"]) for s in out["external_scripts"]}
    assert ("https://cdn.example.org/a.js", True, True) in flags
    assert ("https://cdn.example.org/b.js", False, False) in flags


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_ux_fields(monkeypatch) -> None:
    body = """<script src="https://cdn.example.org/lib.js"></script>"""
    _patch_get(monkeypatch, body=body)
    sri_audit("https://app.example.com")
    findings = _findings()
    assert findings
    f = findings[0]
    assert f.get("description_plain")
    assert f.get("recommended_action")
    # SRI is a verified-by-construction zero-FP detector.
    assert f.get("verification_status") == "verified"


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("sri_audit")
    assert "T1592" in techniques


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_parse_attrs_double_quoted() -> None:
    out = sri_module._parse_attrs('src="https://x" integrity="sha384-y"')
    assert out["src"] == "https://x"
    assert out["integrity"] == "sha384-y"


def test_parse_attrs_single_quoted() -> None:
    out = sri_module._parse_attrs("src='https://x'")
    assert out["src"] == "https://x"


def test_parse_attrs_unquoted() -> None:
    out = sri_module._parse_attrs("src=https://x crossorigin=anonymous")
    assert out["src"] == "https://x"
    assert out["crossorigin"] == "anonymous"


def test_parse_attrs_lowercases_keys() -> None:
    out = sri_module._parse_attrs('SRC="x" Integrity="y"')
    assert "src" in out
    assert "integrity" in out


def test_is_external_relative_false() -> None:
    assert sri_module._is_external("/static/a.js", "app.example.com") is False
    assert sri_module._is_external("../assets/b.js", "app.example.com") is False


def test_is_external_same_origin_false() -> None:
    assert sri_module._is_external("https://app.example.com/x.js", "app.example.com") is False


def test_is_external_external_true() -> None:
    assert sri_module._is_external("https://cdn.example.org/x.js", "app.example.com") is True
