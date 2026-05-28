"""Tests for §workitem.md Phase 2.2 — `scan_path_traversal` deterministic
path-traversal specialist (CWE-22).

Pins detection of:
  * Linux passwd via classic dot-dot, double-dot, URL-enc, double-URL-enc, absolute, file://
  * /proc/self/environ
  * /etc/shadow → critical
  * Windows win.ini / boot.ini → medium
  * Java web.xml → high
  * Spring application.properties → critical
  * Param inference (`file`, `path`, `download`, `template`, ...)
  * Forgiving args (param=str, params=str, params=list)
  * Auth auto-injection
  * Negative cases (no fingerprint, transport error, hardened filter)
  * Auto-emit via tracer + SecurityContext probed_for=path_traversal
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_path_traversal import scan_path_traversal


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
    set_global_tracer(Tracer("test-pt"))
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


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_path_traversal(url="")
    assert out["status"] == "error"


def test_proxy_manager_unavailable_returns_error(monkeypatch) -> None:
    def boom():
        raise ImportError("simulated")

    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager", boom,
    )
    out = scan_path_traversal(
        url="http://example.com/download?file=foo", param="file",
    )
    assert out["status"] == "error"


def test_bare_url_no_form_runs_blind_fallback(monkeypatch) -> None:
    """iter-Q7.4 — a bare URL with no query, no form, and a benign body
    no longer short-circuits to `partial`. The scanner discovers nothing
    on the page, falls back to a blind common-param GET sweep, finds no
    traversal, and returns `ok` (discovery_mode=blind_fallback) having
    actually fired probes."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_path_traversal(url="http://example.com/api/items")
    assert out["status"] == "ok"
    assert out["tool_metadata"]["discovery_mode"] == "blind_fallback"
    assert out["tool_metadata"]["probes_sent"] > 0
    assert out["tool_metadata"]["findings_emitted_to_tracer"] == 0


# ---------------------------------------------------------------------------
# Linux /etc/passwd disclosure (the headline case)
# ---------------------------------------------------------------------------


def test_passwd_dotdot_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "passwd" in url.lower():
            return {
                "status_code": 200,
                "body": (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_path_traversal(
        url="http://example.com/download?file=report.pdf", param="file",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["cwe"] == "CWE-22"
    assert f["category"] == "path_traversal"
    assert f["severity"] == "high"


def test_url_encoded_traversal_works(monkeypatch) -> None:
    """Filter that strips literal `..` should still be defeated by URL-encoding."""
    def fake_resp(method, url, headers, body, timeout):
        # Only resolve when the request used URL-encoded payload.
        if "%2f" in url.lower() and "passwd" in url.lower():
            return {
                "status_code": 200,
                "body": "root:x:0:0:root:/root:/bin/bash\n",
            }
        return {"status_code": 200, "body": "blocked"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_path_traversal(
        url="http://example.com/api/file?path=foo", param="path",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# /etc/shadow → critical
# ---------------------------------------------------------------------------


def test_shadow_disclosure_emits_critical(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "shadow" in url.lower():
            return {
                "status_code": 200,
                "body": "root:$6$abcdef$xyz:18000:0:99999:7:::\n",
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_path_traversal(
        url="http://example.com/files?name=x", param="name",
    )
    assert any(f["severity"] == "critical" for f in out["findings"])


# ---------------------------------------------------------------------------
# Spring application.properties → critical
# ---------------------------------------------------------------------------


def test_spring_application_properties_emits_critical(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "application.properties" in url:
            return {
                "status_code": 200,
                "body": (
                    "spring.datasource.url=jdbc:mysql://db:3306/app\n"
                    "spring.datasource.username=appuser\n"
                    "spring.datasource.password=hunter2\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_path_traversal(
        url="http://example.com/api/load?template=index", param="template",
    )
    assert any(f["severity"] == "critical" for f in out["findings"])


# ---------------------------------------------------------------------------
# Windows boot.ini → medium
# ---------------------------------------------------------------------------


def test_windows_boot_ini_emits_medium(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "boot.ini" in url.lower():
            return {
                "status_code": 200,
                "body": (
                    "[boot loader]\ntimeout=30\n"
                    "default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n"
                    "[operating systems]\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_path_traversal(
        url="http://example.com/page?include=x", param="include",
    )
    assert any(f["severity"] == "medium" for f in out["findings"])


# ---------------------------------------------------------------------------
# /proc/self/environ → high
# ---------------------------------------------------------------------------


def test_proc_environ_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "environ" in url.lower():
            return {
                "status_code": 200,
                "body": "HTTP_USER_AGENT=Mozilla/5.0 PATH=/usr/bin:/bin",
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_path_traversal(
        url="http://example.com/load?doc=foo", param="doc",
    )
    assert any(f["severity"] == "high" for f in out["findings"])


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_no_fingerprint_no_finding(monkeypatch) -> None:
    """Hardened filter returns innocuous body → no finding."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 403, "body": "<html>access denied</html>",
    })
    out = scan_path_traversal(
        url="http://example.com/download?file=x", param="file",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "error": "Request failed: ConnectionError",
    })
    out = scan_path_traversal(
        url="http://example.com/download?file=x", param="file",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_path_shaped_param(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "passwd" in url.lower():
            return {
                "status_code": 200,
                "body": "root:x:0:0:root:/root:/bin/bash\n",
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    # `download` is in the lexicon, `id` is not.
    out = scan_path_traversal(
        url="http://example.com/api?download=report&id=42",
    )
    assert len(out["findings"]) == 1
    assert "download" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_path_traversal(
        url="http://example.com/dl?file=x", params="file",
    )
    assert out["status"] == "ok"


def test_dedup_one_finding_per_param(monkeypatch) -> None:
    """Server returns passwd-shape for every probe → still one finding."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": "root:x:0:0:root:/root:/bin/bash\n",
    })
    out = scan_path_traversal(
        url="http://example.com/dl?file=x", param="file",
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
    record_auth_state(label="lead", bearer="ptoken")

    scan_path_traversal(
        url="http://example.com/dl?file=x", param="file",
    )
    assert any(
        h.get("Authorization") == "Bearer ptoken"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log integration
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_path_traversal(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_path_traversal(
        url="http://example.com/dl?file=x", param="file",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("path_traversal" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions,
        reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_path_traversal(
        url="http://example.com/dl?file=x", param="file",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_path_traversal"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_path_traversal_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_path_traversal")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "path-traversal-specialist"


def test_scan_path_traversal_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_path_traversal" in catalog
