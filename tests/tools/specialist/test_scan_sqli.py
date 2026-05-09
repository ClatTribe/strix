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
# Phase 3c — protocol-aware probing (POST + JSON body, path params)
# ---------------------------------------------------------------------------


def test_post_json_body_sqli_detection(monkeypatch) -> None:
    """The headline Phase 3c case: probe a POST + JSON endpoint.
    Mirrors the Juice Shop login shape that Phase 3b couldn't reach."""
    captured: list[dict[str, Any]] = []

    def fake_resp(method, url, headers, body, timeout):
        # Capture the actual request shape.
        captured.append({
            "method": method, "url": url,
            "headers": dict(headers), "body": body,
        })
        # If the email field contains a `'`, return a MySQL error.
        # (Realistic shape for an unsafely-built JSON-API SQL query.)
        if "'" in body:
            return {
                "status_code": 500,
                "body": (
                    "{\"error\":\"You have an error in your SQL "
                    "syntax; check the manual that corresponds to your "
                    "MySQL server version\"}"
                ),
            }
        return {"status_code": 200, "body": "{\"token\":\"...\"}"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/rest/user/login",
        method="POST",
        params=["email"],
        body_template={"email": "x@example.com", "password": "x"},
    )

    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "sqli"
    assert f["verification_status"] == "verified"

    # Confirm the actual probes WERE POST + JSON.
    assert all(req["method"] == "POST" for req in captured)
    assert all(req["headers"].get("Content-Type") == "application/json"
               for req in captured)
    # Final probe body has the SQLi payload.
    err_probes = [r for r in captured if "'" in r["body"]]
    assert err_probes
    import json as _json
    parsed = _json.loads(err_probes[0]["body"])
    assert "'" in parsed["email"]
    assert parsed["password"] == "x"


def test_post_form_body_sqli_detection(monkeypatch) -> None:
    """Old-school PHP login forms: POST + form-urlencoded."""
    captured: list[dict[str, Any]] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append({
            "method": method, "url": url,
            "headers": dict(headers), "body": body,
        })
        # form-urlencoded `'` is `%27`. Detection works on raw body.
        if "%27" in body or "'" in body:
            return {
                "status_code": 500,
                "body": "Microsoft SQL Server error: unclosed quotation mark",
            }
        return {"status_code": 200, "body": "Welcome"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/login.php",
        method="POST",
        params=["username"],
        body_template={"username": "admin", "password": "x"},
        body_format="form",
    )

    assert len(out["findings"]) == 1
    assert all(req["headers"].get("Content-Type") ==
               "application/x-www-form-urlencoded" for req in captured)


def test_path_param_sqli_detection(monkeypatch) -> None:
    """Path-based IDOR-adjacent SQLi: `/api/Baskets/{id}` style."""
    captured: list[dict[str, Any]] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append({"method": method, "url": url})
        if "'" in url or "%27" in url:
            return {
                "status_code": 500,
                "body": "ORA-00933: SQL command not properly ended",
            }
        return {"status_code": 200, "body": "[]"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/api/Baskets/{id}",
        method="GET",
        params=["id"],
    )
    assert len(out["findings"]) == 1
    # All probes should have substituted SOMETHING into the path.
    assert all("{id}" not in r["url"] for r in captured)


def test_params_inferred_from_body_template_when_omitted(monkeypatch) -> None:
    """Convenience: caller can pass body_template without params and
    we infer the param names from the dict keys."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/api",
        method="POST",
        body_template={"username": "x", "email": "y@z.com"},
    )
    # Both keys probed → status ok (no findings, but didn't error).
    assert out["status"] == "ok"


def test_params_inferred_from_path_placeholder_when_omitted(monkeypatch) -> None:
    """`{id}` in URL with no params arg → infer `id`."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/api/users/{id}",
        method="GET",
    )
    assert out["status"] == "ok"


def test_accepts_param_singular(monkeypatch) -> None:
    """The lead empirically calls scan_sqli with `param="email"`
    (singular) instead of `params=["email"]`. This must NOT TypeError."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/api",
        method="POST",
        param="email",  # singular
        body_template={"email": "x", "password": "y"},
    )
    assert out["status"] == "ok"


def test_accepts_params_as_string(monkeypatch) -> None:
    """Some calls pass `params="email"` (string) instead of a list.
    Must be treated as `params=["email"]`."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/api",
        method="POST",
        params="email",  # string
        body_template={"email": "x", "password": "y"},
    )
    assert out["status"] == "ok"


def test_accepts_body_template_as_json_string(monkeypatch) -> None:
    """The XML tool-call format passes args as strings. The lead
    serialises a dict body_template as a JSON string. The function
    must auto-parse it back to a dict so the param substitution
    works as expected."""
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(body)
        if "'" in body:
            return {"status_code": 500, "body": "you have an error in your sql syntax"}
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_sqli(
        url="http://example.com/api",
        method="POST",
        params=["email"],
        body_template='{"email": "x@example.com", "password": "x"}',  # JSON string!
    )
    assert out["status"] == "ok"
    # If template was parsed correctly, payloads were substituted into
    # the email field (resulting in valid JSON each time).
    import json as _json
    parsed = [_json.loads(b) for b in captured if b.startswith("{")]
    assert parsed, f"no JSON-shaped probes captured: {captured!r}"
    # The error_trigger probe ("'") should produce {"email":"'", "password":"x"}
    err_probes = [p for p in parsed if p.get("email") == "'"]
    assert err_probes
    # The finding should have fired.
    assert len(out["findings"]) == 1


def test_json_finding_target_is_endpoint_not_query_url(monkeypatch) -> None:
    """For body-based detection the emitted finding's `target` must
    be the original URL, not a URL-with-query (no query was used)."""
    def fake_resp(method, url, headers, body, timeout):
        if "'" in body:
            return {"status_code": 500, "body": "you have an error in your sql syntax"}
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_sqli(
        url="http://example.com/api/login",
        method="POST",
        params=["user"],
        body_template={"user": "admin", "pass": "x"},
    )
    from strix.telemetry.tracer import get_global_tracer

    f = get_global_tracer().get_existing_vulnerabilities()[0]
    assert f["target"] == "http://example.com/api/login"
    assert "?" not in f["target"]


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
