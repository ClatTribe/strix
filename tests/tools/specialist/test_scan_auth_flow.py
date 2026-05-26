"""Tests for §8.5 Phase 6 — `scan_auth_flow` auth-aware specialist.

Pins:
  * Default-credential probe + auto-emit on success
  * SecurityContext.AuthState population (cookies + JWT)
  * Partial-signal emission for JWT (routes lead to jwt_audit)
  * Self-registration fallback when default creds fail
  * Negative cases (all creds rejected)
  * Multiple field-name conventions (email/username/user)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_auth_flow import scan_auth_flow


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
    set_global_tracer(Tracer("test-auth-flow"))
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
    out = scan_auth_flow(login_url="")
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Default-credential success path
# ---------------------------------------------------------------------------


def test_juiceshop_default_creds_succeed(monkeypatch) -> None:
    """The Juice Shop default `admin@juice-sh.op` / `admin123` is the
    first pair tried — should succeed in 1 probe."""
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(body)
        data = json.loads(body)
        if data.get("email") == "admin@juice-sh.op" and data.get("password") == "admin123":
            return {
                "status_code": 200,
                "body": json.dumps({
                    "authentication": {
                        "token": "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqcyJ9.signature",
                        "bid": 1,
                        "umail": "admin@juice-sh.op",
                    }
                }),
                "headers": {"Set-Cookie": "token=abc123; Path=/"},
            }
        return {"status_code": 401, "body": '{"error":"Invalid email or password"}'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_auth_flow(login_url="http://example.com/rest/user/login")

    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "auth"
    assert f["cwe"] == "CWE-521"
    assert f["severity"] == "high"
    # Only 1 probe was needed (Juice Shop creds are first in cohort).
    assert len(captured) == 1


def test_default_creds_emits_to_tracer_with_full_finding(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 200,
            "body": json.dumps({"token": "eyJ.payload.sig"}),
            "headers": {"Set-Cookie": "session=xyz"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(login_url="http://example.com/rest/user/login")

    from strix.telemetry.tracer import get_global_tracer
    findings = get_global_tracer().get_existing_vulnerabilities()
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "auth"
    assert f["cwe"] == "CWE-521"
    assert "Default credentials" in f["title"]
    assert f["confidence"] == 1.0
    # PoC includes the working creds.
    assert "admin@juice-sh.op" in f["poc_script_code"] or "admin" in f["poc_script_code"]


def test_session_written_to_security_context(monkeypatch) -> None:
    """After a successful login, the captured cookies and JWT
    should land in SecurityContext.AuthState."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 200,
            "body": json.dumps({"token": "eyJaaaa.bbbb.cccc"}),
            "headers": {"Set-Cookie": "session=abc; Path=/"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(
        login_url="http://example.com/rest/user/login",
        label="admin-user",
    )

    from strix.agents.security_context import get_auth_state
    state = get_auth_state("admin-user")
    assert state is not None
    assert "session" in state.cookies
    assert state.cookies["session"] == "abc"
    assert state.bearer == "eyJaaaa.bbbb.cccc"


def test_jwt_capture_emits_partial_signal_for_jwt_audit(monkeypatch) -> None:
    """Captured JWT should produce a partial signal pointing the
    lead at jwt_audit."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 200,
            "body": json.dumps({"token": "eyJaaaa.bbbb.cccc"}),
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(login_url="http://example.com/login")

    from strix.agents.security_context import list_partial_signals
    sigs = list_partial_signals()
    jwt_sigs = [s for s in sigs if s.category_hint == "jwt"]
    assert len(jwt_sigs) >= 1
    assert "jwt_audit" in jwt_sigs[0].next_probe.lower()


def test_jwt_extracted_from_authorization_header(monkeypatch) -> None:
    """Some endpoints return the JWT in the Authorization response
    header instead of the JSON body."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 200,
            "body": "OK",
            "headers": {"Authorization": "Bearer eyJxxx.yyy.zzz"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(login_url="http://example.com/login")

    from strix.agents.security_context import get_auth_state
    state = get_auth_state("default-creds")
    assert state.bearer == "eyJxxx.yyy.zzz"


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_all_creds_rejected_no_finding(monkeypatch) -> None:
    """Every default cred returns 401 → no finding emitted."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 401, "body": '{"error":"Invalid email or password"}'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_auth_flow(login_url="http://example.com/rest/user/login")

    assert out["status"] == "ok"
    assert len(out["findings"]) == 0
    # All 16 default-cred pairs should have been tried.
    assert out["tool_metadata"]["probes_sent"] >= 16


def test_2xx_with_invalid_marker_not_treated_as_success(monkeypatch) -> None:
    """Some apps return 200 with `{success: false, error: 'invalid'}`.
    Don't false-positive."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 200,
            "body": json.dumps({"success": False, "error": "Invalid credentials"}),
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_auth_flow(login_url="http://example.com/login")
    assert len(out["findings"]) == 0


def test_transport_errors_dont_emit(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"error": "Request failed: ConnectionError", "url": url}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_auth_flow(login_url="http://example.com/login")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Field-name flexibility
# ---------------------------------------------------------------------------


def test_username_field_instead_of_email(monkeypatch) -> None:
    """Some apps use 'username' instead of 'email'."""
    def fake_resp(method, url, headers, body, timeout):
        data = json.loads(body)
        if data.get("username") == "admin" and data.get("password") == "admin":
            return {"status_code": 200, "body": json.dumps({"ok": True})}
        return {"status_code": 401, "body": "invalid"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_auth_flow(
        login_url="http://example.com/login",
        email_field="username",
    )
    assert len(out["findings"]) == 1


def test_body_template_passes_through_extra_fields(monkeypatch) -> None:
    """If the login endpoint requires extra fields (e.g. tenant_id,
    captcha_token), the body_template carries them."""
    captured_bodies: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_bodies.append(json.loads(body))
        return {"status_code": 401, "body": "invalid"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(
        login_url="http://example.com/login",
        body_template={"tenant_id": "acme", "captcha_token": "skip"},
    )
    # Every probe should preserve the extra fields.
    for b in captured_bodies:
        assert b["tenant_id"] == "acme"
        assert b["captcha_token"] == "skip"


# ---------------------------------------------------------------------------
# Self-registration fallback
# ---------------------------------------------------------------------------


def test_register_fallback_creates_account_then_logs_in(monkeypatch) -> None:
    """When all default creds fail, self-registration fallback fires."""
    state = {"registered_email": None}

    def fake_resp(method, url, headers, body, timeout):
        data = json.loads(body)
        if "/register" in url or "/Users/" in url or "/signup" in url:
            # Accept registration.
            state["registered_email"] = data.get("email")
            return {"status_code": 201, "body": json.dumps({"id": 1, "email": data.get("email")})}
        # Login: only the registered email + password matches.
        if (state["registered_email"]
            and data.get("email") == state["registered_email"]
            and data.get("password","").startswith("Strix_")):
            return {
                "status_code": 200,
                "body": json.dumps({"token": "eyJregistered.x.y"}),
            }
        return {"status_code": 401, "body": "invalid"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(
        login_url="http://example.com/rest/user/login",
        try_register=True,
    )

    # State should now have 'registered-user' label.
    from strix.agents.security_context import get_auth_state
    s = get_auth_state("registered-user")
    assert s is not None
    assert s.bearer == "eyJregistered.x.y"


# ---------------------------------------------------------------------------
# Coverage tracking
# ---------------------------------------------------------------------------


def test_records_endpoint_as_probed_for_auth(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 401, "body": "invalid"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_auth_flow(login_url="http://example.com/rest/user/login")

    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("auth" in e.probed_for for e in eps)


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_auth_flow_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_auth_flow")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "auth-flow-specialist"


def test_scan_auth_flow_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_auth_flow" in catalog
