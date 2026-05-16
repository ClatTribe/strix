"""Tests for the BOLA depth extension — partial-leak + list-endpoint
detection paths in `scan_api_bola.py`.

The original `scan_api_bola` collapsed BOLA detection to exact-hash
match of owner vs accessor responses. That misses two of the most
common real-world BOLA shapes:

  1. **Partial leak** — accessor gets a 200 whose body is NOT an
     exact match to owner's, but owner-identifying ID values
     appear in the accessor's response (subset of fields, or
     owner's record rendered inside a multi-record response).
  2. **List endpoint** — endpoints with NO path param (e.g.
     `GET /orders`) that return every user's records.

These tests pin both paths.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.specialist.scan_api_bola import (
    _accessor_response_leaks_owner_ids,
    scan_api_bola,
)


# ---------------------------------------------------------------------------
# Test scaffolding (mirrors test_scan_api_bola.py)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path):
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-bola-partial-list"))
    yield


def _seed_users():
    from strix.agents.security_context import AuthState, get_security_context

    ctx = get_security_context()
    ctx.auth_states["user-a"] = AuthState(label="user-a", bearer="a-token")
    ctx.auth_states["user-b"] = AuthState(label="user-b", bearer="b-token")


def _endpoint(
    *, url: str, method: str = "GET", auth: bool = True,
) -> dict[str, Any]:
    return {
        "url": url, "method": method, "auth_required": auth,
        "params": [],
    }


# ---------------------------------------------------------------------------
# _accessor_response_leaks_owner_ids — unit tests
# ---------------------------------------------------------------------------


def test_high_entropy_id_matches_anywhere() -> None:
    """UUIDs / slugs are unambiguous enough that bare substring
    match is safe."""
    body = '{"user_uuid": "abc-def-uuid-12345", "name": "x"}'
    leaks, matched = _accessor_response_leaks_owner_ids(
        body, ["abc-def-uuid-12345"],
    )
    assert leaks is True
    assert matched == ["abc-def-uuid-12345"]


def test_numeric_id_requires_json_framing() -> None:
    """Numeric IDs must appear in JSON-framed positions, not as
    substrings of unrelated numbers (timestamps, byte counts)."""
    # Should match — quoted form
    leaks, _ = _accessor_response_leaks_owner_ids(
        '{"order_id": "42"}', ["42"],
    )
    assert leaks is True

    # Should match — bare numeric framed as JSON value
    leaks, _ = _accessor_response_leaks_owner_ids(
        '{"order_id": 42, "x": 100}', ["42"],
    )
    assert leaks is True

    # Should match — array-of-IDs payload
    leaks, _ = _accessor_response_leaks_owner_ids(
        '{"ids": [42, 99]}', ["42"],
    )
    assert leaks is True


def test_numeric_id_does_not_match_substring() -> None:
    """`42` should NOT match `1042` (timestamp suffix) or `4242`
    (other numeric)."""
    leaks, _ = _accessor_response_leaks_owner_ids(
        '{"timestamp": 1759241042, "count": 4242}', ["42"],
    )
    assert leaks is False


def test_empty_body_returns_no_leak() -> None:
    assert _accessor_response_leaks_owner_ids("", ["42"]) == (False, [])


def test_empty_owner_id_values_returns_no_leak() -> None:
    assert _accessor_response_leaks_owner_ids(
        '{"x": 1}', [],
    ) == (False, [])


def test_non_string_owner_ids_skipped() -> None:
    """Defensive — caller might accidentally pass None or other."""
    leaks, matched = _accessor_response_leaks_owner_ids(
        '{"id": "42"}', ["", "  ", "42"],  # type: ignore[list-item]
    )
    assert leaks is True
    assert matched == ["42"]


def test_multiple_owner_ids_all_matched() -> None:
    body = '{"order_id": "1001", "user_id": "abc-uuid"}'
    leaks, matched = _accessor_response_leaks_owner_ids(
        body, ["1001", "abc-uuid", "99"],
    )
    assert leaks is True
    assert set(matched) == {"1001", "abc-uuid"}


# ---------------------------------------------------------------------------
# End-to-end — partial-leak detection
# ---------------------------------------------------------------------------


def test_partial_leak_bola_detected(monkeypatch) -> None:
    """Owner sees full record; accessor sees a profile-shaped
    subset that still contains owner's ID. Exact-hash check
    fails; partial-leak check fires."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        # Owner gets the full record.
        if headers.get("Authorization") == "Bearer a-token":
            return 200, (
                '{"order_id": "1001", "amount": 500, '
                '"customer_email": "owner@example.com", '
                '"address": "Owner St"}'
            )
        # Accessor gets a partial view — still leaks owner's ID.
        if headers.get("Authorization") == "Bearer b-token":
            return 200, (
                '{"order_id": "1001", "amount": 500}'
            )
        return 401, "{}"

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert out["status"] == "ok"
    findings = out["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert "Partial-leak" in f["title"]
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-639"
    assert any("partial-leak" in r.lower() for r in f["reasoning_trace"])


def test_partial_leak_skipped_when_exact_match_fires(monkeypatch) -> None:
    """When the exact-hash check fires (full BOLA), we don't ALSO
    emit a partial-leak finding for the same endpoint — single
    finding-per-endpoint discipline."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        # Owner + accessor both get IDENTICAL response → exact-hash hits.
        return 200, '{"order_id": "1001", "amount": 500}'

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert len(out["findings"]) == 1
    # Title is the full-BOLA wording, not partial-leak.
    assert "Partial-leak" not in out["findings"][0]["title"]
    assert "read user-a's record" in out["findings"][0]["title"]


def test_partial_leak_no_finding_when_id_absent(monkeypatch) -> None:
    """Accessor gets a 200 but body doesn't contain owner's IDs
    → no finding. This is the correct outcome for an endpoint
    that returns the accessor's OWN record."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        if headers.get("Authorization") == "Bearer a-token":
            return 200, '{"order_id": "1001"}'
        return 200, '{"order_id": "2002"}'

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert len(out["findings"]) == 0


def test_partial_leak_no_finding_when_accessor_403(monkeypatch) -> None:
    """403/401 on accessor probe → proper authz, no finding."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        if headers.get("Authorization") == "Bearer a-token":
            return 200, '{"order_id": "1001"}'
        return 403, '{"error": "forbidden"}'

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders/{id}")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# End-to-end — list-endpoint detection
# ---------------------------------------------------------------------------


def test_list_endpoint_bola_detected(monkeypatch) -> None:
    """`GET /orders` returns owner-only IDs in accessor's list
    response → list-endpoint BOLA. This is the canonical
    "endpoint returned everyone's records" pattern."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        # Both users get a list response that includes owner's
        # order ID. Server didn't filter by tenant.
        return 200, (
            '{"orders": ['
            '{"id": 1001, "amount": 500},'
            '{"id": 2002, "amount": 100}'
            ']}'
        )

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert out["status"] == "ok"
    findings = out["findings"]
    assert len(findings) == 1
    assert "List-endpoint BOLA" in findings[0]["title"]
    assert findings[0]["severity"] == "high"
    assert any(
        "list-endpoint" in r.lower()
        for r in findings[0]["reasoning_trace"]
    )


def test_list_endpoint_no_finding_when_accessor_only_sees_own_records(
    monkeypatch,
) -> None:
    """Server properly filters: owner sees [1001], accessor sees
    [2002]. No owner IDs in accessor body → no finding."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        if headers.get("Authorization") == "Bearer a-token":
            return 200, '{"orders": [{"id": 1001}]}'
        return 200, '{"orders": [{"id": 2002}]}'

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert len(out["findings"]) == 0


def test_list_endpoint_disabled_via_kwarg(monkeypatch) -> None:
    """`probe_list_endpoints=False` → no-path-param endpoints are
    skipped entirely (pre-PR behaviour). Backwards-compat for
    callers that want strict path-param-only testing."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        return 200, '{"orders": [{"id": 1001}]}'

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        probe_list_endpoints=False,
        _fetcher=fetcher,
    )
    # No path param, list-endpoint probing OFF → no findings, no
    # network calls beyond the existing skip-counting.
    assert len(out["findings"]) == 0
    assert out["tool_metadata"]["list_endpoint_probed"] == 0


def test_list_endpoint_skipped_for_non_GET(monkeypatch) -> None:
    """POST/PUT on no-path-param endpoints aren't list-fetches —
    skip them rather than firing requests with no body."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        return 200, '{"orders": [{"id": 1001}]}'

    out = scan_api_bola(
        endpoints=[_endpoint(
            url="https://api/v1/orders",
            method="POST",
        )],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert out["tool_metadata"]["list_endpoint_probed"] == 0
    assert len(out["findings"]) == 0


def test_list_endpoint_skipped_when_anonymous(monkeypatch) -> None:
    """Endpoints without `auth_required` are not BOLA candidates —
    they're public by design."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        return 200, '{"orders": [{"id": 1001}]}'

    out = scan_api_bola(
        endpoints=[_endpoint(
            url="https://api/v1/public-orders",
            auth=False,
        )],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert out["tool_metadata"]["list_endpoint_probed"] == 0


def test_list_endpoint_skipped_when_owner_probe_fails(monkeypatch) -> None:
    """If owner can't even hit the endpoint (404 / 500), we can't
    compare — skip with evidence note. Avoids false positives on
    misconfigured endpoints."""
    _seed_users()

    call_count = [0]

    def fetcher(*, url, method, headers, timeout):
        call_count[0] += 1
        if headers.get("Authorization") == "Bearer a-token":
            return 500, "{}"
        return 200, '{"orders": [{"id": 1001}]}'

    out = scan_api_bola(
        endpoints=[_endpoint(url="https://api/v1/orders")],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert len(out["findings"]) == 0
    # Owner failed → didn't reach accessor probe → only 1 call.
    assert call_count[0] == 1


# ---------------------------------------------------------------------------
# Multi-endpoint — partial + list combine
# ---------------------------------------------------------------------------


def test_mixed_endpoints_each_detection_path_fires(monkeypatch) -> None:
    """One endpoint with path param (partial leak), one without
    (list endpoint). Both findings emit."""
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        if "{id}" in url:
            pass  # template-substitution should never leak {id}
        if "/orders/1001" in url:
            # Path-param endpoint — accessor sees subset with ID.
            if headers.get("Authorization") == "Bearer a-token":
                return 200, '{"order_id": "1001", "email": "a@x"}'
            return 200, '{"order_id": "1001"}'
        if url.endswith("/orders"):
            # List endpoint — accessor sees both records.
            return 200, '{"orders": [{"id": 1001}, {"id": 2002}]}'
        return 404, "{}"

    out = scan_api_bola(
        endpoints=[
            _endpoint(url="https://api/v1/orders/{id}"),
            _endpoint(url="https://api/v1/orders"),
        ],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert len(out["findings"]) == 2
    titles = {f["title"] for f in out["findings"]}
    assert any("Partial-leak" in t for t in titles)
    assert any("List-endpoint" in t for t in titles)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_metadata_reports_list_endpoint_probe_count(monkeypatch) -> None:
    _seed_users()

    def fetcher(*, url, method, headers, timeout):
        return 200, '{"orders": []}'

    out = scan_api_bola(
        endpoints=[
            _endpoint(url="https://api/v1/orders"),
            _endpoint(url="https://api/v1/transactions"),
        ],
        owner_label="user-a", accessor_label="user-b",
        owner_ids={"id": "1001"},
        _fetcher=fetcher,
    )
    assert out["tool_metadata"]["list_endpoint_probed"] == 2
