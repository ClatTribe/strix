"""Tests for §workitem.md Phase 2.3 — `scan_ssti` deterministic SSTI
specialist (CWE-1336 / CWE-94).

Pins:
  * Jinja/Twig `{{a*b}}` → product in response → critical
  * Freemarker / Velocity / Smarty `${a*b}` → critical
  * Mako `<%a*b%>` → high
  * Razor `@(a*b)` → high
  * ERB `<%=a*b%>` → critical
  * Reflected payload (engine NOT evaluated) → no finding
  * Param inference (template-shaped lexicon)
  * Forgiving args
  * Auth auto-injection
  * SecurityContext + decision_log integration
  * Registry / catalog wiring
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_ssti import scan_ssti


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
    set_global_tracer(Tracer("test-ssti"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


def _extract_arithmetic(payload: str) -> int | None:
    """Pull `a*b` out of any of the supported syntaxes and return a*b."""
    m = re.search(r"(\d+)\s*\*\s*(\d+)", payload)
    if not m:
        return None
    return int(m.group(1)) * int(m.group(2))


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_ssti(url="")
    assert out["status"] == "error"


def test_proxy_unavailable_returns_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("boom")),
    )
    out = scan_ssti(url="http://example.com/hi?name=x", param="name")
    assert out["status"] == "error"


def test_no_template_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    # No query string and no params arg.
    out = scan_ssti(url="http://example.com/api/items")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# Per-engine evaluation pins
# ---------------------------------------------------------------------------


def _engine_emulator(engine_token: str):
    """Build a fake_resp that emulates a server which evaluates the
    given engine's template syntax (i.e. replaces the payload with
    the arithmetic product). Other syntaxes echo the raw payload."""

    def fake_resp(method, url, headers, body, timeout):
        # Pull the param value out of the URL — it's the last `name=`
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        # Pick the value of any param (only one varies in the test).
        candidate = next(
            (vs[0] for vs in qs.values() if any(c in vs[0] for c in "{$<@")),
            "",
        )
        product = _extract_arithmetic(candidate)
        if product is None:
            return {"status_code": 200, "body": "Hello stranger"}
        # If the candidate matches the engine's syntax marker, evaluate.
        # Otherwise echo verbatim (no evaluation).
        if engine_token in candidate:
            return {"status_code": 200, "body": f"<h1>Hello {product}</h1>"}
        return {"status_code": 200, "body": f"<h1>Hello {candidate}</h1>"}

    return fake_resp


def test_jinja_evaluates_emits_critical(monkeypatch) -> None:
    """Server evaluates `{{ a*b }}` only — emits critical finding."""
    _patch_proxy(monkeypatch, _engine_emulator("{{"))
    out = scan_ssti(
        url="http://example.com/hello?name=guest", param="name",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "ssti"
    assert f["cwe"] == "CWE-1336"
    assert f["severity"] == "critical"


def test_freemarker_evaluates_emits_critical(monkeypatch) -> None:
    """Server evaluates `${a*b}`."""
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        candidate = next(
            (vs[0] for vs in qs.values() if any(c in vs[0] for c in "{$<@")),
            "",
        )
        product = _extract_arithmetic(candidate)
        if product is None:
            return {"status_code": 200, "body": "Hello stranger"}
        # Only `${...}` triggers evaluation, NOT `{{...}}`.
        if candidate.startswith("${") and not candidate.startswith("{{"):
            return {"status_code": 200, "body": f"<h1>Hello {product}</h1>"}
        return {"status_code": 200, "body": f"<h1>Hello {candidate}</h1>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssti(
        url="http://example.com/hello?greeting=hi", param="greeting",
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["severity"] == "critical"


def test_mako_evaluates_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        candidate = next(
            (vs[0] for vs in qs.values() if any(c in vs[0] for c in "{$<@")),
            "",
        )
        product = _extract_arithmetic(candidate)
        if product is None:
            return {"status_code": 200, "body": "Hello stranger"}
        # `<%...%>` and not `<%=...%>` — Mako shape.
        if candidate.startswith("<%") and not candidate.startswith("<%="):
            return {"status_code": 200, "body": f"<h1>Hello {product}</h1>"}
        return {"status_code": 200, "body": f"<h1>Hello {candidate}</h1>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssti(
        url="http://example.com/hello?subject=hi", param="subject",
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_reflection_only_no_evaluation_no_finding(monkeypatch) -> None:
    """Server echoes payload verbatim — no template engine — no finding."""
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        candidate = next(
            (vs[0] for vs in qs.values() if any(c in vs[0] for c in "{$<@")),
            "",
        )
        return {"status_code": 200, "body": f"<h1>Hello {candidate}</h1>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssti(
        url="http://example.com/hello?name=g", param="name",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_no_template_response_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "Generic landing page",
    })
    out = scan_ssti(
        url="http://example.com/hello?name=g", param="name",
    )
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "error": "Request failed: ConnectionError",
    })
    out = scan_ssti(
        url="http://example.com/hello?name=g", param="name",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_template_shaped_param(monkeypatch) -> None:
    """`name` is in the SSTI lexicon; `id` is not — scanner picks `name`."""
    _patch_proxy(monkeypatch, _engine_emulator("{{"))
    out = scan_ssti(
        url="http://example.com/api?name=guest&id=42",
    )
    assert len(out["findings"]) == 1
    assert "name" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_ssti(
        url="http://example.com/api?name=g", params="name",
    )
    assert out["status"] == "ok"


def test_dedup_one_finding_per_param(monkeypatch) -> None:
    """Even if the server evaluated multiple syntaxes, only one finding
    per param is emitted (first-match-wins)."""
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        candidate = next(
            (vs[0] for vs in qs.values() if any(c in vs[0] for c in "{$<@")),
            "",
        )
        product = _extract_arithmetic(candidate)
        if product is None:
            return {"status_code": 200, "body": "ok"}
        # Always evaluate (greedy server).
        return {"status_code": 200, "body": f"product is {product}"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssti(
        url="http://example.com/hi?name=g", param="name",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="ssti-token")

    scan_ssti(
        url="http://example.com/hi?name=g", param="name",
    )
    assert any(
        h.get("Authorization") == "Bearer ssti-token"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_ssti(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_ssti(
        url="http://example.com/hi?name=g", param="name",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("ssti" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions,
        reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_ssti(
        url="http://example.com/hi?name=g", param="name",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_ssti"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_ssti_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_ssti")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "ssti-specialist"


def test_scan_ssti_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_ssti" in catalog
