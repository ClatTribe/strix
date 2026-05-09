"""Tests for §workitem.md Phase 4.1 — `scan_idor` (CWE-639 / CWE-862).

Pins:
  * Numeric / UUID path-segment ID detection
  * Owner baseline + accessor cross-read → IDOR finding
  * Anon cross-read → missing-auth (CWE-862) finding
  * Sensitive markers (creditcard, ssn) → critical
  * Owner cannot read own resource → skipped (no false positive)
  * Auth-state preconditions enforced (owner_label / accessor_label
    must be in AuthState — partial otherwise)
  * Forgiving args (`url=` / `urls=` / `urls=[...]`)
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_idor import (
    _extract_id_locations,
    _is_id_segment,
    _looks_like_user_data,
    _swap_id_in_url,
    scan_idor,
)


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
    set_global_tracer(Tracer("test-idor"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _populate_two_users() -> None:
    """Seed AuthState with user-a + user-b sessions."""
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="user-a", bearer="user_a_token", notes="test")
    record_auth_state(label="user-b", bearer="user_b_token", notes="test")


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


# ---------------------------------------------------------------------------
# Helper / unit functions
# ---------------------------------------------------------------------------


def test_is_id_segment_numeric() -> None:
    assert _is_id_segment("42")
    assert _is_id_segment("12345")
    assert _is_id_segment("0")


def test_is_id_segment_uuid() -> None:
    assert _is_id_segment("550e8400-e29b-41d4-a716-446655440000")
    assert _is_id_segment("550E8400-E29B-41D4-A716-446655440000")


def test_is_id_segment_hex_objectid() -> None:
    assert _is_id_segment("507f1f77bcf86cd799439011")  # MongoDB ObjectId


def test_is_id_segment_negative() -> None:
    assert not _is_id_segment("users")
    assert not _is_id_segment("")
    assert not _is_id_segment("foo-bar")
    assert not _is_id_segment("api")


def test_extract_id_locations_path_numeric() -> None:
    locs = _extract_id_locations("http://example.com/api/users/42/profile")
    assert ("path", "42") in locs


def test_extract_id_locations_query() -> None:
    locs = _extract_id_locations("http://example.com/api/baskets?id=99")
    assert ("query:id", "99") in locs


def test_extract_id_locations_no_id() -> None:
    locs = _extract_id_locations("http://example.com/api/products")
    assert locs == []


def test_swap_id_in_path() -> None:
    new = _swap_id_in_url("http://x.com/api/users/42/profile", "42", "99")
    assert new == "http://x.com/api/users/99/profile"


def test_looks_like_user_data_identical() -> None:
    body = '{"id":42,"name":"alice","email":"a@x.com"}'
    similar, ratio = _looks_like_user_data(body, body)
    assert similar
    assert ratio == 1.0


def test_looks_like_user_data_unrelated() -> None:
    a = '{"id":42,"name":"alice","email":"a@x.com","data":"' + ("x" * 200) + '"}'
    b = '{"error":"forbidden","status":403}'
    similar, ratio = _looks_like_user_data(a, b)
    assert not similar


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_no_urls_returns_partial(monkeypatch) -> None:
    _populate_two_users()
    out = scan_idor()
    assert out["status"] == "partial"


def test_owner_label_missing_returns_partial(monkeypatch) -> None:
    """Only user-b captured; owner_label=user-a → partial with helpful msg."""
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="user-b", bearer="b_token")
    out = scan_idor(url="http://example.com/api/users/42")
    assert out["status"] == "partial"
    assert "user-a" in out["error"]


def test_accessor_label_missing_returns_partial() -> None:
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="user-a", bearer="a_token")
    out = scan_idor(url="http://example.com/api/users/42")
    assert out["status"] == "partial"
    assert "user-b" in out["error"]


# ---------------------------------------------------------------------------
# IDOR detection — accessor reads owner's data
# ---------------------------------------------------------------------------


def test_idor_detected_when_accessor_reads_owners_data(monkeypatch) -> None:
    """Owner GET returns user data; accessor GET (with their own
    session) returns the SAME data → IDOR."""
    _populate_two_users()
    owner_body = (
        '{"id":42,"name":"Alice","email":"alice@example.com",'
        '"address":"123 Main St","phone":"555-0101",'
        '"orders":[{"id":1,"item":"laptop"},{"id":2,"item":"phone"}]}'
    )

    def fake_resp(method, url, headers, body, timeout):
        # Both owner and accessor get the same body — server doesn't
        # check ownership.
        return {"status_code": 200, "body": owner_body, "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_idor(url="http://example.com/api/users/42", test_anon=False)
    assert out["status"] == "ok"
    assert any(f["category"] == "idor" for f in out["findings"])
    f = next(f for f in out["findings"] if f["category"] == "idor")
    assert f["cwe"] == "CWE-639"


def test_idor_critical_when_response_has_pii(monkeypatch) -> None:
    """Sensitive markers in body → critical severity."""
    _populate_two_users()
    pii_body = (
        '{"id":42,"name":"Alice","creditcard":"4111-1111-1111-1111",'
        '"ssn":"111-22-3333","cvv":"123","tax_id":"99-9999999"}'
    )

    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": pii_body, "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_idor(url="http://example.com/api/users/42", test_anon=False)
    assert any(f["severity"] == "critical" for f in out["findings"])


def test_owner_cannot_read_own_resource_skipped(monkeypatch) -> None:
    """Owner GET returns 401 — IDOR can't be confirmed (broken endpoint),
    no finding emitted, no false positive."""
    _populate_two_users()

    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 401, "body": '{"error":"unauthorized"}', "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_idor(url="http://example.com/api/users/42")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_authz_enforced_no_finding(monkeypatch) -> None:
    """Owner GET → 200 + body; accessor GET → 403 → no IDOR (correct behaviour)."""
    _populate_two_users()
    owner_body = '{"id":42,"name":"Alice","email":"alice@example.com",' + ('x' * 100) + '}'

    def fake_resp(method, url, headers, body, timeout):
        auth = (headers or {}).get("Authorization", "")
        if "user_a_token" in auth:
            return {"status_code": 200, "body": owner_body, "headers": {}}
        # accessor (user-b) gets 403; anon also gets 403.
        return {"status_code": 403, "body": '{"error":"forbidden"}', "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_idor(url="http://example.com/api/users/42")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Missing-auth detection (anon reads owner's resource)
# ---------------------------------------------------------------------------


def test_missing_auth_detected_when_anon_reads_owner_data(monkeypatch) -> None:
    """Anon GET returns owner's data → CWE-862 missing auth."""
    _populate_two_users()
    owner_body = '{"id":42,"name":"Alice","email":"alice@example.com",' + ('x' * 200) + '}'

    def fake_resp(method, url, headers, body, timeout):
        # Server doesn't check auth — every request gets owner's data.
        return {"status_code": 200, "body": owner_body, "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_idor(url="http://example.com/api/users/42")
    # Two findings emitted: one IDOR (user-b), one missing-auth (anon).
    cats = [f["category"] for f in out["findings"]]
    assert "missing_auth" in cats
    f = next(f for f in out["findings"] if f["category"] == "missing_auth")
    assert f["cwe"] == "CWE-862"


def test_test_anon_false_skips_missing_auth_probe(monkeypatch) -> None:
    """`test_anon=False` skips the anon probe."""
    _populate_two_users()
    owner_body = '{"id":42,"name":"Alice"}' + ('-' * 200)
    headers_seen: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        headers_seen.append(dict(headers or {}))
        return {"status_code": 200, "body": owner_body, "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    scan_idor(url="http://example.com/api/users/42", test_anon=False)
    # No anon probe — every request had an Authorization header.
    auth_hdrs = [h.get("Authorization") for h in headers_seen]
    assert all(a is not None for a in auth_hdrs)


# ---------------------------------------------------------------------------
# URLs without ID segments are skipped
# ---------------------------------------------------------------------------


def test_url_without_id_segment_skipped(monkeypatch) -> None:
    _populate_two_users()
    request_count = [0]

    def fake_resp(method, url, headers, body, timeout):
        request_count[0] += 1
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_idor(url="http://example.com/api/products")
    # No ID segment → no fetches.
    assert request_count[0] == 0
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Forgiving args + multi-URL
# ---------------------------------------------------------------------------


def test_urls_string_accepted(monkeypatch) -> None:
    _populate_two_users()
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "x" * 200, "headers": {},
    })
    out = scan_idor(urls="http://example.com/api/users/1")
    assert out["status"] == "ok"


def test_dedup_one_finding_per_url_accessor(monkeypatch) -> None:
    """Even if both heuristics triggered, one finding per (url, accessor)."""
    _populate_two_users()
    body = '{"id":42,"name":"Alice"}' + ('x' * 200)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_idor(url="http://example.com/api/users/42", test_anon=False)
    # Exactly one IDOR finding (user-b → user-a's data).
    idor_count = sum(1 for f in out["findings"] if f["category"] == "idor")
    assert idor_count == 1


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_idor(monkeypatch) -> None:
    _populate_two_users()
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": "no", "headers": {},
    })
    scan_idor(url="http://example.com/api/users/42")
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("idor" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    _populate_two_users()
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": "no", "headers": {},
    })
    scan_idor(url="http://example.com/api/users/42")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_idor"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_idor_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_idor")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "idor-specialist"


def test_scan_idor_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_idor" in catalog
