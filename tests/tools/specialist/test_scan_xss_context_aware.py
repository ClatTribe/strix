"""End-to-end tests for the context-aware probe flow in `scan_xss`.

Companion to `test_scan_xss.py` (backwards-compat / HTML-body
behaviour) and `test_xss_contexts.py` (classifier unit tests).
These tests stand up mock servers that mimic real reflection
patterns per context, and verify scan_xss now:

  1. Sends a context-detect probe FIRST (alphanumeric canary).
  2. Picks the right breakout cohort.
  3. Detects the breakout when the server doesn't escape the
     context-specific characters.
  4. Does NOT detect when the server escapes them correctly.
  5. Tags the emitted finding with the detected context.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_xss import scan_xss


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-xss-ctx"))
    yield


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


def _extract_q(url: str) -> str:
    from urllib.parse import urlparse, parse_qs

    return parse_qs(urlparse(url).query).get("q", [""])[0]


def _get_emitted_findings() -> list[dict[str, Any]]:
    from strix.telemetry.tracer import get_global_tracer

    return get_global_tracer().get_existing_vulnerabilities()


# ---------------------------------------------------------------------------
# html_attr_double context — reflection inside `value="..."`
# ---------------------------------------------------------------------------


def test_attribute_double_quoted_breakout_detected(monkeypatch) -> None:
    """Server reflects `q` into a double-quoted HTML attribute
    WITHOUT escaping `"`. Phase-3b couldn't detect this — the
    `<script>` payload would land harmless inside the attribute.
    Phase 4 detects the context and fires `"><script>` to escape
    the attribute first."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        # Server emits the raw value into a quoted attribute.
        return {
            "status_code": 200,
            "body": f'<input type="text" name="search" value="{q}">',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search.aspx", params=["q"])

    assert out["status"] == "ok"
    findings = _get_emitted_findings()
    assert len(findings) >= 1
    # Finding's title must reflect the detected attribute context,
    # not generic html_body language.
    assert "attribute" in findings[0]["title"].lower()


def test_attribute_double_quoted_escaped_no_finding(monkeypatch) -> None:
    """Server reflects `q` into a quoted attribute but escapes `"`
    correctly → no breakout, no finding."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        # Proper attribute encoding.
        escaped = q.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
        return {
            "status_code": 200,
            "body": f'<input type="text" value="{escaped}">',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])
    assert out["status"] == "ok"
    assert _get_emitted_findings() == []


# ---------------------------------------------------------------------------
# js_string_double context — reflection inside `"..."` in <script>
# ---------------------------------------------------------------------------


def test_js_string_double_quoted_breakout_detected(monkeypatch) -> None:
    """Server reflects `q` into a JS string literal inside <script>.
    Phase-3b would miss this — the `<script>` payload would just be
    string content. Phase 4 detects js_string_double and fires
    `";STRIX_X(...);//`."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        # Server emits raw value into a JS string literal.
        return {
            "status_code": 200,
            "body": f'<html><script>var query = "{q}";</script></html>',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])

    assert out["status"] == "ok"
    findings = _get_emitted_findings()
    assert len(findings) >= 1
    assert "javascript" in findings[0]["title"].lower()


def test_js_string_double_properly_escaped_no_finding(monkeypatch) -> None:
    """Server JSON-escapes the JS string value → backslash precedes
    the breakout quote → no breakout, no finding."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        # Real JSON-style escape.
        import json
        encoded = json.dumps(q)  # produces `"...\"..."` correctly
        return {
            "status_code": 200,
            "body": f'<html><script>var x = {encoded};</script></html>',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])
    assert _get_emitted_findings() == []


# ---------------------------------------------------------------------------
# url_attr context — reflection inside href / src
# ---------------------------------------------------------------------------


def test_url_attr_javascript_scheme_detected(monkeypatch) -> None:
    """Server reflects `q` into href="...". Phase-3b would miss
    this — javascript:STRIX_X(...) doesn't contain `<` so the
    HTML-body payload set wouldn't trigger. Phase 4 detects
    url_attr and fires the javascript: scheme payload."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        return {
            "status_code": 200,
            "body": f'<a href="{q}">click</a>',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/redirect", params=["q"])

    assert out["status"] == "ok"
    findings = _get_emitted_findings()
    assert len(findings) >= 1
    # URL-bearing-attribute classification must surface in title.
    assert (
        "url" in findings[0]["title"].lower()
        or "href" in findings[0]["title"].lower()
    )


# ---------------------------------------------------------------------------
# Probe budget — context-detect probe doesn't double-emit
# ---------------------------------------------------------------------------


def test_one_finding_per_param_across_contexts(monkeypatch) -> None:
    """Same (path, param) can be detected in multiple contexts in
    one response. Only ONE finding emits — Phase 3b dedup applies."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        # Reflects in BOTH html_body AND attribute context — first
        # context-attack to break out wins.
        return {
            "status_code": 200,
            "body": (
                f'<input value="{q}">'
                f'<div>echo: {q}</div>'
            ),
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])
    assert len(out["findings"]) == 1
    assert len(_get_emitted_findings()) == 1


def test_unreflected_param_skipped_without_attack_probes(monkeypatch) -> None:
    """When the context-detect probe shows the canary isn't reflected
    at all, scan_xss must skip the per-context attack probes
    (cost discipline)."""
    request_count = 0

    def fake_resp(method, url, headers, body, timeout):
        nonlocal request_count
        request_count += 1
        return {
            "status_code": 200,
            "body": "<html>generic page</html>",
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/", params=["q"])
    # Exactly ONE probe sent (context-detect); no follow-up attack
    # probes because the canary wasn't reflected.
    assert request_count == 1
    assert _get_emitted_findings() == []


# ---------------------------------------------------------------------------
# Finding metadata — context tag propagated through
# ---------------------------------------------------------------------------


def test_finding_remediation_mentions_attribute_encoding(monkeypatch) -> None:
    """Per-context remediation: an attribute-context finding's
    remediation_steps must reference attribute-specific encoding
    (`&quot;`), NOT generic HTML-body advice."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        return {
            "status_code": 200,
            "body": f'<input value="{q}">',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_xss(url="http://example.com/x", params=["q"])

    findings = _get_emitted_findings()
    assert len(findings) >= 1
    remediation = findings[0]["remediation_steps"]
    # Must mention attribute-specific encoding, not just html-body.
    assert "&quot;" in remediation or "attribute" in remediation.lower()


def test_finding_remediation_for_js_string_mentions_json_stringify(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        return {
            "status_code": 200,
            "body": f'<script>var x = "{q}";</script>',
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_xss(url="http://example.com/x", params=["q"])

    findings = _get_emitted_findings()
    assert len(findings) >= 1
    remediation = findings[0]["remediation_steps"].lower()
    assert "json.stringify" in remediation or "json-stringify" in remediation


# ---------------------------------------------------------------------------
# JSON content-type short-circuit
# ---------------------------------------------------------------------------


def test_json_response_does_not_emit_html_body_finding(monkeypatch) -> None:
    """When the server returns application/json, scan_xss must NOT
    fire HTML-body breakouts — that's not exploitable. The
    json_reflect cohort has its own payload and only emits when
    text/html is misconfigured."""
    def fake_resp(method, url, headers, body, timeout):
        q = _extract_q(url)
        return {
            "status_code": 200,
            "body": f'{{"results": ["{q}"]}}',
            "headers": {"content-type": "application/json; charset=utf-8"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/api", params=["q"])
    # Server JSON-escapes correctly — no breakout. The test's
    # important assertion: scan_xss did NOT mis-classify as html_body
    # and emit a false finding.
    findings = _get_emitted_findings()
    for f in findings:
        # If any finding emerges it must be the json_reflect cohort,
        # not a misfired html_body cohort.
        assert "json" in f["title"].lower() or "misconfig" in f["description"].lower()
