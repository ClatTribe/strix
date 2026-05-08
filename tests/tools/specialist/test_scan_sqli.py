"""Tests for §8.5 Phase 3b — `scan_sqli` deterministic specialist.

Pins error-based detection (DB-error fingerprinting) and
boolean-blind detection (true ≠ false ≈ baseline). HTTP probes
mocked at the proxy_manager layer.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest

from strix.tools.specialist.scan_sqli import scan_sqli


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
    set_global_tracer(Tracer("test-sqli"))
    yield


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


def _qs(url: str, name: str) -> str:
    return parse_qs(urlparse(url).query).get(name, [""])[0]


# ---------------------------------------------------------------------------
# Error-based detection
# ---------------------------------------------------------------------------


def test_mysql_error_fingerprint_triggers_finding(monkeypatch) -> None:
    """Probe with `'` returns a MySQL error string → emits finding."""
    def fake_resp(method, url, headers, body, timeout):
        param_value = _qs(url, "id")
        if param_value == "'":
            return {
                "status_code": 500,
                "body": (
                    "<html><body>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL "
                    "server version for the right syntax to use near "
                    "'\\''' at line 1</body></html>"
                ),
            }
        return {"status_code": 200, "body": "<html>ok</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/item.php", params=["id"])

    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "sqli"
    assert f["verification_status"] == "verified"
    assert f["confidence"] == 0.95

    from strix.telemetry.tracer import get_global_tracer

    tracer_findings = get_global_tracer().get_existing_vulnerabilities()
    assert len(tracer_findings) == 1
    assert tracer_findings[0]["cwe"] == "CWE-89"
    assert "MySQL" in tracer_findings[0]["description"]


@pytest.mark.parametrize(
    "fragment,expected_engine",
    [
        ("Microsoft SQL Server error: ", "MSSQL"),
        ("ORA-01756: quoted string not properly terminated", "Oracle"),
        ("postgresql query failed: ERROR: syntax error", "PostgreSQL"),
        ("near \"SELECT\": syntax error", "SQLite"),
    ],
)
def test_other_db_engines_detected(
    monkeypatch, fragment: str, expected_engine: str,
) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if _qs(url, "id") == "'":
            return {"status_code": 500, "body": f"<pre>{fragment}</pre>"}
        return {"status_code": 200, "body": "<html>ok</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/x.php", params=["id"])
    assert len(out["findings"]) == 1
    from strix.telemetry.tracer import get_global_tracer

    f = get_global_tracer().get_existing_vulnerabilities()[0]
    assert expected_engine in f["description"]


# ---------------------------------------------------------------------------
# Boolean-blind detection
# ---------------------------------------------------------------------------


def test_boolean_blind_detection(monkeypatch) -> None:
    """Server doesn't leak SQL errors but distinguishes true/false:
    `' OR '1'='1` returns a longer page than `' OR '1'='2`, and
    `' OR '1'='2` matches baseline → boolean-blind SQLi."""
    def fake_resp(method, url, headers, body, timeout):
        v = _qs(url, "id")
        if v == "' OR '1'='1":
            return {
                "status_code": 200,
                "body": (
                    "<html><body>"
                    "Found 1000 results. Lorem ipsum dolor sit amet, "
                    "consectetur adipiscing elit, sed do eiusmod "
                    "tempor incididunt ut labore et dolore magna "
                    "aliqua." * 5
                    + "</body></html>"
                ),
            }
        if v == "' OR '1'='2":
            return {"status_code": 200, "body": "<html>No results found.</html>"}
        # baseline + error_trigger fall through
        return {"status_code": 200, "body": "<html>No results found.</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/search", params=["id"])

    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "sqli"
    assert f["verification_status"] == "pattern_match"
    assert f["confidence"] == 0.75

    from strix.telemetry.tracer import get_global_tracer

    tf = get_global_tracer().get_existing_vulnerabilities()[0]
    assert "Boolean-blind" in tf["title"]


def test_boolean_blind_not_triggered_when_true_equals_false(monkeypatch) -> None:
    """If true and false branches return identical responses, no
    boolean-blind detection."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "<html>uniform response</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/x", params=["id"])
    assert len(out["findings"]) == 0


def test_boolean_blind_not_triggered_when_baseline_differs_from_false(
    monkeypatch,
) -> None:
    """Pre-condition: baseline ≈ false. If they differ, the response
    variation may be unrelated to the injection. Suppress the
    finding to avoid false positives."""
    def fake_resp(method, url, headers, body, timeout):
        v = _qs(url, "id")
        if v == "strix_baseline_value":
            return {"status_code": 200, "body": "<html>baseline page" * 50 + "</html>"}
        if v == "' OR '1'='1":
            return {"status_code": 200, "body": "<html>true branch big</html>" * 80}
        if v == "' OR '1'='2":
            return {"status_code": 200, "body": "<html>tiny false</html>"}
        return {"status_code": 200, "body": "<html>error</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/x", params=["id"])
    # Baseline doesn't match false → suppress.
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Error-based wins over boolean-blind on same param
# ---------------------------------------------------------------------------


def test_error_based_takes_precedence_no_double_emit(monkeypatch) -> None:
    """If the error-trigger probe surfaces a DB error, scan_sqli
    emits ONCE per param — doesn't also fire the boolean check."""
    def fake_resp(method, url, headers, body, timeout):
        v = _qs(url, "id")
        if v == "'":
            return {"status_code": 500, "body": "Microsoft SQL Server error"}
        return {"status_code": 200, "body": "<html>any</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/x", params=["id"])
    assert len(out["findings"]) == 1
    assert "Error-based" in out["findings"][0]["title"]


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_sqli(url="", params=["id"])
    assert out["status"] == "error"


def test_no_params_no_query_returns_partial() -> None:
    out = scan_sqli(url="http://example.com/")
    assert out["status"] == "partial"


def test_transport_error_does_not_emit(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"error": "Request failed: TimeoutError", "url": url}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(url="http://example.com/x", params=["id"])
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_sqli_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_sqli")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "sqli-specialist"


def test_scan_sqli_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_sqli" in catalog


# ---------------------------------------------------------------------------
# CVSS / severity
# ---------------------------------------------------------------------------


def test_finding_severity_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if _qs(url, "id") == "'":
            return {"status_code": 500, "body": "MySQL: you have an error in your sql syntax"}
        return {"status_code": 200, "body": "<html>ok</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_sqli(url="http://example.com/x", params=["id"])

    from strix.telemetry.tracer import get_global_tracer

    f = get_global_tracer().get_existing_vulnerabilities()[0]
    assert f["severity"] == "high"
