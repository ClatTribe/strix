"""Tests for `scan_api_mass_assignment` — OWASP API3."""

from __future__ import annotations

from typing import Any

import pytest

from strix.agents.security_context import (
    AuthState, SecurityContext, get_security_context,
)
from strix.tools.specialist.scan_api_mass_assignment import (
    _AUTHZ_FIELDS,
    _ID_FIELDS,
    _instantiate_path,
    _is_write_method,
    _response_accepts_injection,
    scan_api_mass_assignment,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_API_MASS_ASSIGNMENT_DISABLED", raising=False)
    import strix.agents.security_context as sc_mod
    monkeypatch.setattr(sc_mod, "_global_context", SecurityContext())


def _seed_user_a() -> None:
    ctx = get_security_context()
    ctx.auth_states["user-a"] = AuthState(label="user-a", bearer="alice-tok")


def _endpoint(
    *, url: str, method: str = "POST",
    auth_required: bool = True, params: list | None = None,
) -> dict[str, Any]:
    return {
        "url": url, "method": method,
        "auth_required": auth_required,
        "params": params or [],
        "tags": [], "operation_id": "",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_is_write_method() -> None:
    assert _is_write_method("POST") is True
    assert _is_write_method("PUT") is True
    assert _is_write_method("PATCH") is True
    assert _is_write_method("GET") is False
    assert _is_write_method("DELETE") is False  # DELETE doesn't take body


def test_response_accepts_injection_echo_signal() -> None:
    """Strongest signal: response body echoes the injected field
    + value."""
    accepted, reason = _response_accepts_injection(
        body_a_status=200, body_a_text='{"username": "alice"}',
        body_b_status=200,
        body_b_text='{"username": "alice", "is_admin": true}',
        injected_field="is_admin", injected_value=True,
    )
    assert accepted is True
    assert "echoes" in reason


def test_response_accepts_injection_baseline_diff_signal() -> None:
    """Server rejected baseline (400) but accepted with the
    injected field (200) — clear signal."""
    accepted, reason = _response_accepts_injection(
        body_a_status=400, body_a_text='{"error": "missing field"}',
        body_b_status=200, body_b_text='{"ok": true}',
        injected_field="is_admin", injected_value=True,
    )
    assert accepted is True
    assert "baseline rejected" in reason


def test_response_accepts_injection_rejected() -> None:
    """Server returned 4xx on injection → no finding."""
    accepted, reason = _response_accepts_injection(
        body_a_status=200, body_a_text='{}',
        body_b_status=400, body_b_text='{"error": "unknown field"}',
        injected_field="is_admin", injected_value=True,
    )
    assert accepted is False


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_mass_assignment_positive_echo() -> None:
    """Server echoes injected `is_admin: true` back → critical."""
    _seed_user_a()
    baseline_body = '{"username": "alice"}'
    echoed_body = '{"username": "alice", "is_admin": true}'

    def fetcher(*, url, method, headers, json_body, timeout):
        # If json_body contains the injection, echo it back.
        if json_body and json_body.get("is_admin") is True:
            return 200, echoed_body
        return 200, baseline_body

    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users", method="POST")],
        auth_label="user-a", confirm_mutation=True,
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-915"


def test_mass_assignment_positive_baseline_diff() -> None:
    """Baseline rejected (400) but injection accepted (200) →
    high or critical depending on the field."""
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        if json_body and json_body.get("role") == "admin":
            return 200, '{"ok": true}'
        return 400, '{"error": "missing field"}'

    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users", method="POST")],
        auth_label="user-a", confirm_mutation=True,
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "critical"   # role=admin


def test_mass_assignment_negative_when_rejected() -> None:
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        # Server rejects ANY injection.
        if json_body and any(
            k in json_body
            for k in ("is_admin", "role", "is_superuser")
        ):
            return 400, '{"error": "unknown field"}'
        return 200, '{"ok": true}'

    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users", method="POST")],
        auth_label="user-a", confirm_mutation=True,
        _fetcher=fetcher,
    )
    assert result["findings"] == []


def test_skips_read_methods() -> None:
    _seed_user_a()
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users", method="GET")],
        auth_label="user-a", confirm_mutation=True,
        _fetcher=lambda **k: (200, ""),
    )
    assert result["findings"] == []
    assert result["tool_metadata"]["skipped"]["read_only"] == 1


# ---------------------------------------------------------------------------
# Safety + failure modes
# ---------------------------------------------------------------------------


def test_confirm_mutation_required() -> None:
    """The whole tool refuses to run without explicit opt-in."""
    _seed_user_a()
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users")],
        auth_label="user-a",   # confirm_mutation=False by default
    )
    assert result["status"] == "error"
    assert "confirm_mutation" in result["error"]


def test_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_API_MASS_ASSIGNMENT_DISABLED", "1")
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users")],
        confirm_mutation=True,
    )
    assert result["status"] == "error"
    assert "kill_switch" in result["error"]


def test_id_fields_disabled_by_default() -> None:
    """probe_id_fields=False (the default) means user_id/account_id
    aren't tried. Verify by passing only an `id`-field-shaped
    fetcher and observing no finding."""
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        if json_body and "user_id" in json_body:
            return 200, '{"user_id": 1, "ok": true}'
        return 400, '{"error": "missing user_id"}'

    # Disable EVERY probe source — canonical authz, canonical id,
    # AND schema-aware. With all three off, there are no probe
    # fields and the tool returns error. (Default is
    # probe_schema_aware=True, which keeps the run alive when
    # endpoints have schema info; explicitly turn it off here.)
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/users", method="POST")],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=False, probe_id_fields=False,
        probe_schema_aware=False,
        _fetcher=fetcher,
    )
    # No probe fields → returns error
    assert result["status"] == "error"


def test_id_fields_enabled_finds_owner_rewrite() -> None:
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        if json_body and "user_id" in json_body:
            return 200, '{"user_id": 1, "created": true}'
        return 400, '{"error": "x"}'

    result = scan_api_mass_assignment(
        endpoints=[_endpoint(url="https://api/v1/orders", method="POST")],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=False, probe_id_fields=True,
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"   # id field
