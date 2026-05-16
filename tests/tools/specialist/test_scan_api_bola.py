"""Tests for `scan_api_bola` — OWASP API1 (Broken Object Level
Authorization) probe.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.agents.security_context import (
    AuthState, SecurityContext, get_security_context,
)
from strix.tools.specialist.scan_api_bola import (
    _instantiate_path,
    scan_api_bola,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_API_BOLA_DISABLED", raising=False)
    # Reset the global SecurityContext singleton so test sessions
    # don't leak between cases.
    import strix.agents.security_context as sc_mod
    monkeypatch.setattr(sc_mod, "_global_context", SecurityContext())


def _seed_sessions() -> None:
    ctx = get_security_context()
    ctx.auth_states["user-a"] = AuthState(
        label="user-a", bearer="alice-token",
    )
    ctx.auth_states["user-b"] = AuthState(
        label="user-b", bearer="bob-token",
    )


# ---------------------------------------------------------------------------
# Path-param substitution
# ---------------------------------------------------------------------------


def test_instantiate_path_single_param() -> None:
    out = _instantiate_path(
        "https://api/v1/users/{id}", {"id": "42"},
    )
    assert out == "https://api/v1/users/42"


def test_instantiate_path_multiple_params() -> None:
    out = _instantiate_path(
        "https://api/users/{user_id}/orders/{order_id}",
        {"user_id": "42", "order_id": "100"},
    )
    assert out == "https://api/users/42/orders/100"


def test_instantiate_path_no_params_passes_through() -> None:
    out = _instantiate_path("https://api/health", {})
    assert out == "https://api/health"


def test_instantiate_path_missing_substitution_returns_none() -> None:
    out = _instantiate_path("https://api/users/{id}", {})
    assert out is None


# ---------------------------------------------------------------------------
# BOLA detection
# ---------------------------------------------------------------------------


def _endpoint(
    *, url: str, method: str = "GET", auth_required: bool = True,
) -> dict[str, Any]:
    return {
        "url": url,
        "method": method,
        "auth_required": auth_required,
        "params": [],
        "tags": [],
        "operation_id": "",
    }


def test_bola_positive_when_accessor_reads_owner_record() -> None:
    """Same response body shape to two different users → BOLA."""
    _seed_sessions()
    same_body = '{"id": 42, "name": "Alice"}'

    def fetcher(*, url, method, headers, timeout):
        # Both sessions get the same body — BOLA positive.
        return 200, same_body

    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/users/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "42"},
        _fetcher=fetcher,
    )
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-639"
    assert "BOLA" in f["title"]


def test_bola_negative_when_accessor_blocked() -> None:
    _seed_sessions()

    def fetcher(*, url, method, headers, timeout):
        # Owner gets 200; accessor gets 403.
        if headers.get("Authorization") == "Bearer alice-token":
            return 200, '{"id": 42, "name": "Alice"}'
        return 403, '{"error": "forbidden"}'

    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/users/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "42"},
        _fetcher=fetcher,
    )
    assert result["findings"] == []


def test_bola_negative_when_bodies_differ() -> None:
    """Both get 200 but with different bodies (accessor sees
    their own scoped data) → not BOLA."""
    _seed_sessions()

    def fetcher(*, url, method, headers, timeout):
        if headers.get("Authorization") == "Bearer alice-token":
            return 200, '{"id": 42, "name": "Alice"}'
        return 200, '{"id": 99, "name": "Bob"}'  # different body

    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/users/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "42"},
        _fetcher=fetcher,
    )
    assert result["findings"] == []


# ---------------------------------------------------------------------------
# Endpoint-shape filtering
# ---------------------------------------------------------------------------


def test_skips_endpoints_without_path_params() -> None:
    """No `{...}` placeholder = no BOLA surface here."""
    _seed_sessions()

    def fetcher(*, url, method, headers, timeout):
        return 200, "same"

    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/health")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1"},
        _fetcher=fetcher,
    )
    assert result["findings"] == []
    assert result["tool_metadata"]["skipped_no_path_params"] == 1


def test_skips_anonymous_endpoints() -> None:
    """BOLA only applies to auth-walled endpoints."""
    _seed_sessions()

    def fetcher(*, url, method, headers, timeout):
        return 200, "same"

    result = scan_api_bola(
        endpoints=[
            _endpoint(
                url="https://api/v1/products/{id}",
                auth_required=False,
            ),
        ],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1"},
        _fetcher=fetcher,
    )
    assert result["findings"] == []
    assert result["tool_metadata"]["skipped_anonymous"] == 1


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_missing_endpoints_returns_error() -> None:
    _seed_sessions()
    result = scan_api_bola(
        endpoints=[],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "42"},
    )
    assert result["status"] == "error"


def test_missing_owner_ids_returns_error() -> None:
    _seed_sessions()
    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/u/{id}")],
        owner_ids=None,
    )
    assert result["status"] == "error"


def test_accessor_session_not_captured_returns_error() -> None:
    """Without scan_multi_role_auth seeding the accessor session,
    we can't test BOLA. Bail clearly."""
    ctx = get_security_context()
    ctx.auth_states["user-a"] = AuthState(
        label="user-a", bearer="alice-token",
    )
    # NO user-b seeded.
    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/u/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1"},
    )
    assert result["status"] == "error"
    assert "scan_multi_role_auth" in result["error"]


def test_kill_switch_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_API_BOLA_DISABLED", "1")
    result = scan_api_bola(
        endpoints=[_endpoint(url="https://api/u/{id}")],
        owner_ids={"id": "1"},
    )
    assert result["status"] == "error"
    assert "kill_switch" in result["error"]
