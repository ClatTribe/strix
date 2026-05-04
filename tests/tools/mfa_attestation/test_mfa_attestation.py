"""Tests for mfa_attestation_check (roadmap §16 / PR #132)."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.mfa_attestation.mfa_attestation  # noqa: F401

mfa_module = sys.modules["strix.tools.mfa_attestation.mfa_attestation"]
mfa_attestation_check = mfa_module.mfa_attestation_check


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
    tracer = Tracer("mfa-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _patch_get(monkeypatch, responder: callable) -> None:
    def fake(url, *, timeout=8.0):
        return responder(url)

    monkeypatch.setattr(mfa_module, "_http_get", fake)


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert mfa_attestation_check("")["success"] is False


def test_bare_host_normalised(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 404, "headers": {}, "body": ""})
    out = mfa_attestation_check("app.example.com")
    assert out["success"] is True


# ---------------------------------------------------------------------------
# Helper: body token scan
# ---------------------------------------------------------------------------


def test_scan_body_for_mfa_tokens() -> None:
    scan = mfa_module._scan_body_for_mfa_tokens
    assert "two-factor" in scan("Two-Factor Authentication required")
    assert "totp" in scan("Enter your TOTP code")
    assert "webauthn" in scan("Use WebAuthn")
    assert scan("nothing here") == []


def test_scan_response_json_for_mfa_keys() -> None:
    scan = mfa_module._scan_response_json_for_mfa_keys
    keys = scan('{"mfa_required": true, "factor_types": ["totp"]}')
    assert "mfa_required" in keys

    keys2 = scan('{"data": {"requires_otp": true}}')
    assert "requires_otp" in keys2


def test_scan_response_json_garbage_returns_empty() -> None:
    scan = mfa_module._scan_response_json_for_mfa_keys
    assert scan("not json") == []
    assert scan("") == []


# ---------------------------------------------------------------------------
# Login-page MFA tokens
# ---------------------------------------------------------------------------


def test_login_page_mfa_tokens_detected(monkeypatch) -> None:
    """Login page mentioning Two-Factor / Authenticator → +1 score."""
    def responder(url):
        if url.endswith("/login"):
            return {
                "status": 200,
                "headers": {},
                "body": "<html><body>Sign in with your password and Two-Factor Authentication code</body></html>",
            }
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")

    assert "two-factor" in out["login_tokens"]
    assert out["score"] >= 1


def test_login_page_no_mfa_terminology(monkeypatch) -> None:
    """Plain login form with no MFA terminology → no token signal."""
    def responder(url):
        if url.endswith("/login"):
            return {
                "status": 200,
                "headers": {},
                "body": "<form><input name=email><input name=password type=password></form>",
            }
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert out["login_tokens"] == []


# ---------------------------------------------------------------------------
# Login-API challenge response
# ---------------------------------------------------------------------------


def test_login_api_challenge_keys_detected(monkeypatch) -> None:
    """Login response JSON with `mfa_required: true` → +1."""
    challenge_body = json.dumps({"mfa_required": True, "factor_types": ["totp"]})

    def responder(url):
        if url.endswith("/auth/login"):
            return {"status": 200, "headers": {}, "body": challenge_body}
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")

    assert "mfa_required" in out["challenge_keys"]


def test_login_api_with_only_webauthn_challenge(monkeypatch) -> None:
    challenge_body = json.dumps({"webauthn_challenge": "base64-bytes"})

    def responder(url):
        if url.endswith("/login"):
            return {"status": 200, "headers": {}, "body": challenge_body}
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert "webauthn_challenge" in out["challenge_keys"]


# ---------------------------------------------------------------------------
# WebAuthn / FIDO2 header
# ---------------------------------------------------------------------------


def test_webauthn_in_www_authenticate_detected(monkeypatch) -> None:
    def responder(url):
        if url.endswith("/login"):
            return {
                "status": 401,
                "headers": {"www-authenticate": "WebAuthn realm=\"app\""},
                "body": "",
            }
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")

    assert out["webauthn_header"] is True


def test_no_webauthn_header_no_signal(monkeypatch) -> None:
    def responder(url):
        if url.endswith("/login"):
            return {
                "status": 401,
                "headers": {"www-authenticate": "Basic realm=\"app\""},
                "body": "",
            }
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert out["webauthn_header"] is False


# ---------------------------------------------------------------------------
# MFA-setup endpoint discovery
# ---------------------------------------------------------------------------


def test_mfa_setup_endpoint_2xx_detected(monkeypatch) -> None:
    def responder(url):
        if "/account/security" in url:
            return {"status": 200, "headers": {}, "body": "Security settings"}
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert "/account/security" in out["mfa_setup_paths"]


def test_mfa_setup_endpoint_401_counts(monkeypatch) -> None:
    """401 (auth required) still proves the endpoint exists."""
    def responder(url):
        if "/settings/2fa" in url:
            return {"status": 401, "headers": {}, "body": ""}
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert "/settings/2fa" in out["mfa_setup_paths"]


def test_mfa_setup_endpoint_404_does_not_count(monkeypatch) -> None:
    """404 means the endpoint genuinely doesn't exist → no signal."""
    _patch_get(monkeypatch, lambda url: {"status": 404, "headers": {}, "body": ""})
    out = mfa_attestation_check("https://app.example.com")
    assert out["mfa_setup_paths"] == []


# ---------------------------------------------------------------------------
# Severity ladder
# ---------------------------------------------------------------------------


def test_max_score_emits_info(monkeypatch) -> None:
    """All 4 signals present → score 4 → info."""
    # /login returns valid JSON challenge body (so the JSON-parse
    # detector fires). Body-token detector fires on the JSON
    # values too because lower-cased "two-factor" appears.
    challenge_body = json.dumps({
        "mfa_required": True,
        "factor_types": ["totp", "two-factor", "webauthn"],
    })

    def responder(url):
        if url.endswith("/login"):
            return {
                "status": 200,
                "headers": {"www-authenticate": "WebAuthn"},
                "body": challenge_body,
            }
        if "/account/security" in url:
            return {"status": 200, "headers": {}, "body": "settings"}
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert out["score"] == 4
    assert out["severity"] == "info"

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


def test_partial_score_emits_low(monkeypatch) -> None:
    """1-2 signals → low."""
    def responder(url):
        if url.endswith("/login"):
            return {
                "status": 200,
                "headers": {},
                "body": "<p>Use Authenticator app to sign in</p>",
            }
        return {"status": 404, "headers": {}, "body": ""}

    _patch_get(monkeypatch, responder)
    out = mfa_attestation_check("https://app.example.com")
    assert out["score"] == 1
    assert out["severity"] == "low"


def test_zero_score_emits_medium(monkeypatch) -> None:
    """No MFA signals on any auth surface → medium (auditor red flag)."""
    _patch_get(monkeypatch, lambda url: {"status": 404, "headers": {}, "body": ""})
    out = mfa_attestation_check("https://app.example.com")
    assert out["score"] == 0
    assert out["severity"] == "medium"

    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["cwe"] == "CWE-308"


# ---------------------------------------------------------------------------
# Always exactly one finding
# ---------------------------------------------------------------------------


def test_always_one_finding(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 200, "headers": {}, "body": "TOTP"})
    mfa_attestation_check("https://app.example.com")
    assert len(_findings()) == 1


# ---------------------------------------------------------------------------
# Schema + MITRE
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 404, "headers": {}, "body": ""})
    out = mfa_attestation_check("https://app.example.com")
    assert set(out.keys()) >= {
        "success", "target", "score", "max_score", "severity",
        "login_tokens", "challenge_keys", "webauthn_header",
        "mfa_setup_paths", "paths_probed", "findings_emitted",
    }
    assert out["max_score"] == 4


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    assert "T1592" in get_tool_mitre_techniques("mfa_attestation_check")


def test_skipped_response_does_not_crash(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 0, "headers": {}, "body": "", "skipped": True})
    out = mfa_attestation_check("https://app.example.com")
    assert out["success"] is True
    assert out["score"] == 0
