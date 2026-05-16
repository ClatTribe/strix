"""Tests for `scan_api_bfla` — OWASP API5 (Broken Function Level
Authorization) probe.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.agents.security_context import (
    AuthState, SecurityContext, get_security_context,
)
from strix.tools.specialist.scan_api_bfla import (
    _looks_admin_only,
    scan_api_bfla,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_API_BFLA_DISABLED", raising=False)
    import strix.agents.security_context as sc_mod
    monkeypatch.setattr(sc_mod, "_global_context", SecurityContext())


def _seed_admin_and_viewer() -> None:
    ctx = get_security_context()
    ctx.auth_states["admin"] = AuthState(label="admin", bearer="admin-tok")
    ctx.auth_states["viewer"] = AuthState(label="viewer", bearer="viewer-tok")


def _endpoint(
    *, url: str, method: str = "GET",
    auth_required: bool = True,
    tags: list[str] | None = None,
    operation_id: str = "",
) -> dict[str, Any]:
    return {
        "url": url,
        "method": method,
        "auth_required": auth_required,
        "params": [],
        "tags": tags or [],
        "operation_id": operation_id,
    }


# ---------------------------------------------------------------------------
# Admin-shape detection
# ---------------------------------------------------------------------------


def test_admin_path_marker_detected() -> None:
    assert _looks_admin_only(_endpoint(url="https://api/v1/admin/users")) is True


def test_admin_tag_detected() -> None:
    assert _looks_admin_only(_endpoint(
        url="https://api/v1/users", tags=["admin"],
    )) is True


def test_admin_operation_id_detected() -> None:
    assert _looks_admin_only(_endpoint(
        url="https://api/v1/x", operation_id="adminDeleteUser",
    )) is True


def test_non_admin_endpoint_not_flagged() -> None:
    assert _looks_admin_only(_endpoint(
        url="https://api/v1/users", tags=["users"],
        operation_id="listUsers",
    )) is False


# ---------------------------------------------------------------------------
# BFLA detection
# ---------------------------------------------------------------------------


def test_bfla_positive_critical_on_admin_endpoint() -> None:
    """A viewer role getting the same response as admin from an
    `/admin/*` endpoint → critical BFLA."""
    _seed_admin_and_viewer()
    same_body = '{"users": ["alice", "bob"]}'

    def fetcher(*, url, method, headers, timeout):
        return 200, same_body

    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/admin/users")],
        admin_label="admin", role_labels=["viewer"],
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-285"


def test_bfla_positive_high_on_non_admin_marked_endpoint() -> None:
    """Same-body match on a non-admin-marked endpoint = high
    (not critical) BFLA."""
    _seed_admin_and_viewer()
    same_body = '{"data": "shared"}'

    def fetcher(*, url, method, headers, timeout):
        return 200, same_body

    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/reports/quarterly")],
        admin_label="admin", role_labels=["viewer"],
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "high"


def test_bfla_negative_when_viewer_blocked() -> None:
    _seed_admin_and_viewer()

    def fetcher(*, url, method, headers, timeout):
        if headers.get("Authorization") == "Bearer admin-tok":
            return 200, '{"data": "secret"}'
        return 403, '{"error": "forbidden"}'

    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/admin/secrets")],
        admin_label="admin", role_labels=["viewer"],
        _fetcher=fetcher,
    )
    assert result["findings"] == []


def test_partial_bfla_emits_info_for_human_review() -> None:
    """Viewer got 2xx but body differs from admin → ambiguous;
    info-severity for human review."""
    _seed_admin_and_viewer()

    def fetcher(*, url, method, headers, timeout):
        if headers.get("Authorization") == "Bearer admin-tok":
            return 200, '{"users": ["alice", "bob"], "internal": true}'
        return 200, '{"users": ["alice"]}'   # filtered view

    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/users")],
        admin_label="admin", role_labels=["viewer"],
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "info"
    assert f["verification_status"] == "needs_review"


def test_skips_anonymous_endpoints() -> None:
    _seed_admin_and_viewer()
    result = scan_api_bfla(
        endpoints=[_endpoint(
            url="https://api/v1/admin/users", auth_required=False,
        )],
        admin_label="admin", role_labels=["viewer"],
        _fetcher=lambda **kw: (200, ""),
    )
    assert result["findings"] == []


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_missing_admin_session_returns_error() -> None:
    ctx = get_security_context()
    ctx.auth_states["viewer"] = AuthState(
        label="viewer", bearer="viewer-tok",
    )
    # No admin session.
    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/admin/x")],
        admin_label="admin", role_labels=["viewer"],
    )
    assert result["status"] == "error"
    assert "scan_multi_role_auth" in result["error"]


def test_missing_role_sessions_returns_error() -> None:
    ctx = get_security_context()
    ctx.auth_states["admin"] = AuthState(label="admin", bearer="x")
    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/admin/x")],
        admin_label="admin", role_labels=["viewer", "member"],
    )
    assert result["status"] == "error"


def test_kill_switch_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_API_BFLA_DISABLED", "1")
    result = scan_api_bfla(
        endpoints=[_endpoint(url="https://api/v1/admin/x")],
    )
    assert result["status"] == "error"
    assert "kill_switch" in result["error"]
