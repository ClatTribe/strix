"""Tests for dom_xss_static_probe (roadmap §7.2).

Hermetic — `_fetch_bundle` monkeypatched. Tests cover:

- Direct source→sink patterns (high & medium severity)
- Per-(severity, sink, source) dedup
- Cross-bundle dedup
- Negative cases (sources without sinks; sinks without sources)
- Variable-propagation NOT reported (zero-FP discipline)
- Inline content path (no I/O)
- File-path mode
- HTTP failure resilience
- Result schema
- MITRE T1059.007 + T1190 tagged
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.dom_xss_static.dom_xss_static  # noqa: F401

dxs_module = sys.modules["strix.tools.dom_xss_static.dom_xss_static"]
dom_xss_static_probe = dxs_module.dom_xss_static_probe


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
    tracer = Tracer("dom-xss-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _patch_fetch(monkeypatch, body_by_url: dict[str, str], *, status: int = 200) -> None:
    def fake(url: str, *, timeout: float = 15.0) -> dict[str, Any]:
        if url not in body_by_url:
            return {"status": 404, "body": ""}
        return {"status": status, "body": body_by_url[url]}

    monkeypatch.setattr(dxs_module, "_fetch_bundle", fake)


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


# ---------------------------------------------------------------------------
# Tier 1 — code-execution sinks (high severity)
# ---------------------------------------------------------------------------


def test_eval_with_location_hash_emits_high(monkeypatch) -> None:
    bundle = "function go(){eval(location.hash);}"
    _patch_fetch(monkeypatch, {"https://app.example.com/app.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/app.js"])

    assert out["success"] is True
    assert out["bundles_examined"] == 1
    assert out["findings_emitted"] == 1
    findings = _findings()
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["category"] == "dom_xss"
    assert f["cwe"] == "CWE-79"
    assert f["verification_status"] == "pattern_match"
    assert "eval" in f["title"]
    assert "location.hash" in f["title"]


def test_function_constructor_with_document_url_emits_high(monkeypatch) -> None:
    bundle = "var f = new Function(document.URL); f();"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "function_constructor" in findings[0]["title"]


def test_settimeout_string_with_window_name_emits_high(monkeypatch) -> None:
    # `setTimeout(<source>, ...)` — string form is RCE in the page.
    bundle = "setTimeout(window.name, 100);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Tier 2 — HTML-injection sinks (medium severity)
# ---------------------------------------------------------------------------


def test_innerHTML_with_location_hash_emits_medium(monkeypatch) -> None:
    bundle = "el.innerHTML = location.hash.slice(1);"
    _patch_fetch(monkeypatch, {"https://app.example.com/app.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/app.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "innerHTML" in findings[0]["title"]


def test_document_write_with_referrer_emits_medium(monkeypatch) -> None:
    bundle = "document.write(document.referrer);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "document_write" in findings[0]["title"]


def test_jquery_html_with_location_search_emits_medium(monkeypatch) -> None:
    bundle = "$(\"#out\").html(location.search);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "jquery_html" in findings[0]["title"]


def test_react_dangerously_set_inner_html_with_url_emits_medium(monkeypatch) -> None:
    bundle = (
        "const Comp = () => <div dangerouslySetInnerHTML={{__html: location.hash}} />;"
    )
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "dangerously_set_inner_html" in findings[0]["title"]


def test_insertAdjacentHTML_with_location_emits_medium(monkeypatch) -> None:
    bundle = 'el.insertAdjacentHTML("beforeend", location.hash);'
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Negative cases — zero-FP discipline
# ---------------------------------------------------------------------------


def test_source_without_sink_no_finding(monkeypatch) -> None:
    """`location.hash` referenced but never flowed into a sink — no finding."""
    bundle = "var x = location.hash; console.log(x.length);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert out["findings_emitted"] == 0
    assert _findings() == []


def test_sink_without_source_no_finding(monkeypatch) -> None:
    """`innerHTML` written to a constant — no source — no finding."""
    bundle = 'el.innerHTML = "static safe content";'
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert out["findings_emitted"] == 0


def test_variable_propagation_not_reported(monkeypatch) -> None:
    """Zero-FP discipline: var x = source; sink(x); is NOT reported.

    This is an intentional under-coverage choice. Variable-propagation
    requires real AST + dataflow (the §17.1 Validator-agent build).
    Reporting these without proper flow analysis produces too many
    false positives — a `let x = location.hash` 200 lines from a
    SAFE `el.innerHTML = x` (where `x` was reassigned in between) would
    flag.

    Pin the contract: this test FAILS if a future change naively
    cross-references variables.
    """
    bundle = "var x = location.hash;\nel.innerHTML = x;"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    # Tier 1 only — direct source-in-sink expression. No cross-line
    # variable propagation.
    assert out["findings_emitted"] == 0


def test_safe_textcontent_not_flagged(monkeypatch) -> None:
    """`textContent` is the safe alternative — should not be flagged."""
    bundle = "el.textContent = location.hash;"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert out["findings_emitted"] == 0


def test_minified_bundle_with_no_pattern_no_finding(monkeypatch) -> None:
    """Realistic minified bundle without any DOM-XSS pattern — no FPs."""
    bundle = (
        "!function(e,t){\"object\"==typeof exports&&\"object\"==typeof "
        "module?module.exports=t():\"function\"==typeof define&&"
        "define.amd?define([],t):\"object\"==typeof exports?exports.foo=t()"
        ":e.foo=t()}(self,(function(){return function(){\"use strict\";"
        "var e={};return e}()}));"
    )
    _patch_fetch(monkeypatch, {"https://app.example.com/m.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/m.js"])

    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_per_severity_sink_source_dedup(monkeypatch) -> None:
    """Multiple `innerHTML = location.hash` in the same bundle → ONE finding."""
    bundle = (
        "el1.innerHTML = location.hash;\n"
        "el2.innerHTML = location.hash;\n"
        "el3.innerHTML = location.hash;\n"
    )
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 1


def test_cross_bundle_dedup(monkeypatch) -> None:
    """Same pattern across two bundles → ONE finding (cross-bundle dedup)."""
    bundles = {
        "https://app.example.com/a.js": "el.innerHTML = location.hash;",
        "https://app.example.com/b.js": "x.innerHTML = location.hash;",
    }
    _patch_fetch(monkeypatch, bundles)

    out = dom_xss_static_probe(bundle_urls=list(bundles.keys()))

    assert out["bundles_examined"] == 2
    assert out["findings_emitted"] == 1


def test_distinct_sinks_each_get_finding(monkeypatch) -> None:
    """`eval` AND `innerHTML` both fed by `location.hash` → 2 findings (different sinks)."""
    bundle = "eval(location.hash); el.innerHTML = location.hash;"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    severities = sorted(f["severity"] for f in findings)
    assert severities == ["high", "medium"]


def test_distinct_sources_each_get_finding(monkeypatch) -> None:
    """`location.hash` AND `document.referrer` into same sink → 2 findings."""
    bundle = (
        "el.innerHTML = location.hash;\n"
        "x.innerHTML = document.referrer;\n"
    )
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Inline / file mode (no HTTP)
# ---------------------------------------------------------------------------


def test_inline_content_mode_no_io() -> None:
    out = dom_xss_static_probe(
        inline_content={"in-memory": "eval(location.search);"},
        target_url="app.example.com",
    )

    assert out["bundles_examined"] == 1
    assert out["findings_emitted"] == 1
    assert _findings()[0]["severity"] == "high"


def test_file_path_mode(tmp_path) -> None:
    p = tmp_path / "lib.js"
    p.write_text("el.innerHTML = location.hash;")

    out = dom_xss_static_probe(
        bundle_paths=[str(p)],
        target_url="app.example.com",
    )

    assert out["bundles_examined"] == 1
    assert out["findings_emitted"] == 1


def test_file_path_missing_records_error(tmp_path) -> None:
    out = dom_xss_static_probe(
        bundle_paths=[str(tmp_path / "missing.js")],
        target_url="app.example.com",
    )

    assert out["bundles_examined"] == 0
    assert out["findings_emitted"] == 0
    assert "errors" in out


# ---------------------------------------------------------------------------
# HTTP failure resilience
# ---------------------------------------------------------------------------


def test_404_recorded_as_error(monkeypatch) -> None:
    def fake(url: str, *, timeout: float = 15.0) -> dict[str, Any]:
        return {"status": 404, "body": ""}

    monkeypatch.setattr(dxs_module, "_fetch_bundle", fake)

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert out["bundles_examined"] == 0
    assert out["findings_emitted"] == 0
    assert "errors" in out


def test_skipped_response_counted(monkeypatch) -> None:
    def fake(url: str, *, timeout: float = 15.0) -> dict[str, Any]:
        return {"status": 0, "body": "", "skipped": True}

    monkeypatch.setattr(dxs_module, "_fetch_bundle", fake)

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert out["bundles_skipped"] == 1
    assert out["findings_emitted"] == 0


def test_fetch_exception_logged(monkeypatch) -> None:
    def fake(url: str, *, timeout: float = 15.0) -> dict[str, Any]:
        return {"status": 0, "body": "", "error": "connection refused"}

    monkeypatch.setattr(dxs_module, "_fetch_bundle", fake)

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert out["bundles_examined"] == 0
    assert out["errors"]


# ---------------------------------------------------------------------------
# Schema + MITRE
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    bundle = "eval(location.hash);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    assert set(out.keys()) >= {
        "success", "bundles_examined", "bundles_skipped",
        "findings_emitted", "matches",
    }
    assert isinstance(out["matches"], list)
    m = out["matches"][0]
    assert set(m.keys()) >= {
        "severity", "sink_class", "source",
        "source_url", "line", "match", "snippet",
    }


def test_finding_carries_code_locations(monkeypatch) -> None:
    bundle = "// header line\neval(location.hash);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    f = findings[0]
    assert "code_locations" in f
    assert f["code_locations"][0]["file"] == "https://app.example.com/x.js"
    assert f["code_locations"][0]["line"] == 2  # eval is on line 2
    assert "snippet" in f["code_locations"][0]


def test_finding_carries_ux_fields(monkeypatch) -> None:
    bundle = "eval(location.hash);"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    f = findings[0]
    assert f.get("description_plain")
    assert f.get("recommended_action")
    # severity-tailored description
    assert "browser" in f["description_plain"].lower() or "javascript" in f["description_plain"].lower()


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("dom_xss_static_probe")
    assert "T1059.007" in techniques  # JavaScript execution
    assert "T1190" in techniques  # Exploit Public-Facing Application


# ---------------------------------------------------------------------------
# Multi-source coverage smoke test
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,sink_template",
    [
        ("location.hash", "eval({src})"),
        ("location.search", "eval({src})"),
        ("location.href", "eval({src})"),
        ("document.URL", "eval({src})"),
        ("document.documentURI", "eval({src})"),
        ("document.baseURI", "eval({src})"),
        ("document.referrer", "eval({src})"),
        ("document.cookie", "eval({src})"),
        ("window.name", "eval({src})"),
    ],
)
def test_each_named_source_recognized(monkeypatch, source: str, sink_template: str) -> None:
    bundle = sink_template.format(src=source) + ";"
    _patch_fetch(monkeypatch, {"https://app.example.com/x.js": bundle})

    out = dom_xss_static_probe(bundle_urls=["https://app.example.com/x.js"])

    findings = _findings()
    assert len(findings) >= 1, f"failed to detect source {source!r} in {bundle!r}"
    assert source in findings[0]["title"], (
        f"source {source!r} not surfaced in title {findings[0]['title']!r}"
    )
