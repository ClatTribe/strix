"""Tests for the authorization-matrix prober.

Hermetic — `_send_with_role` is mocked. Tests cover:
- Endpoint + role normalization (string / dict / JSON variants)
- Per-cell event emission shape
- Unauthenticated-bypass detection (CWE-862)
- Vertical-privilege-escalation detection (CWE-285)
- Admin-path heuristics + override
- Cell cap honored
- Cluster-A composition (excluded paths short-circuit)
- Role headers NEVER appear in findings
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.authz_matrix import authz_matrix as am
from strix.tools.proxy import http_safety


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
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("authz-matrix-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com"}]})
    yield


def _patch_send(monkeypatch, responses):
    """responses: dict keyed by (role_name, url) → dict response."""
    log: list[dict[str, Any]] = []

    def fake_send(method, url, role_headers, timeout):
        # Identify role by header signature; tests pass distinguishable
        # tokens so we can route.
        role_name = "unauth"
        for v in role_headers.values():
            if isinstance(v, str):
                if "admin" in v.lower():
                    role_name = "admin"
                elif "user" in v.lower():
                    role_name = "user"
        log.append({"role": role_name, "url": url, "method": method, "headers": role_headers})
        key = (role_name, url)
        return responses.get(key, {"status_code": 404, "body": "", "headers": {}})

    monkeypatch.setattr(am, "_send_with_role", fake_send)
    return log


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def test_normalize_endpoints_from_dict_list() -> None:
    out = am._normalize_endpoints([
        {"url": "https://x/a", "method": "GET"},
        {"url": "https://x/a", "method": "GET"},  # dup
        {"url": "https://x/b", "method": "POST"},
    ])
    assert len(out) == 2
    assert {"url": "https://x/b", "method": "POST"} in out


def test_normalize_endpoints_from_strings() -> None:
    out = am._normalize_endpoints(["https://x/a", "https://x/b"])
    assert all(e["method"] == "GET" for e in out)


def test_normalize_endpoints_from_json_string() -> None:
    raw = json.dumps([{"url": "https://x/a", "method": "GET"}])
    out = am._normalize_endpoints(raw)
    assert out == [{"url": "https://x/a", "method": "GET"}]


def test_normalize_endpoints_invalid_returns_empty() -> None:
    assert am._normalize_endpoints({"not": "a list"}) == []
    assert am._normalize_endpoints([{"missing": "url"}, 42, None]) == []
    assert am._normalize_endpoints(None) == []


def test_normalize_roles_assigns_default_privilege() -> None:
    out = am._normalize_roles([
        {"name": "unauth", "headers": {}},
        {"name": "user", "headers": {"X-User": "alice"}},
        {"name": "admin", "headers": {"X-Admin": "1"}, "privilege": 100},
    ])
    by_name = {r["name"]: r for r in out}
    assert by_name["unauth"]["privilege"] == 0
    assert by_name["user"]["privilege"] == 50
    assert by_name["admin"]["privilege"] == 100


def test_normalize_roles_sorts_by_privilege() -> None:
    out = am._normalize_roles([
        {"name": "admin", "headers": {}, "privilege": 100},
        {"name": "user", "headers": {}, "privilege": 50},
        {"name": "unauth", "headers": {}},
    ])
    assert [r["name"] for r in out] == ["unauth", "user", "admin"]


def test_normalize_roles_drops_invalid_entries() -> None:
    out = am._normalize_roles([
        {"name": "good", "headers": {}},
        {"name": "", "headers": {}},
        {"headers": {}},
        "not a dict",
        None,
    ])
    assert [r["name"] for r in out] == ["good"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_no_endpoints_rejected() -> None:
    out = am.authz_matrix_check(endpoints="[]", roles=json.dumps([{"name": "u", "headers": {}}]))
    assert out["success"] is False


def test_no_roles_rejected() -> None:
    out = am.authz_matrix_check(
        endpoints=json.dumps([{"url": "https://x/a", "method": "GET"}]),
        roles="[]",
    )
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Unauthenticated bypass detection
# ---------------------------------------------------------------------------


def test_unauth_bypass_detected_when_responses_match(monkeypatch) -> None:
    url = "https://app.example.com/api/secret-data"
    _patch_send(monkeypatch, {
        ("unauth", url): {"status_code": 200, "body": "secret-data-contents", "headers": {}},
        ("user", url): {"status_code": 200, "body": "secret-data-contents", "headers": {}},
    })
    out = am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "unauth", "headers": {}},
            {"name": "user", "headers": {"Cookie": "session=user-tok"}, "privilege": 50},
        ]),
    )
    assert out["success"] is True
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "missing_authorization"
    assert reports[0]["severity"] == "high"
    assert reports[0]["cwe"] == "CWE-862"
    assert "unauth" in reports[0]["description"]
    # CRITICAL: header values must NOT appear in any finding.
    assert "user-tok" not in json.dumps(reports[0])


def test_unauth_no_bypass_when_unauth_gets_401(monkeypatch) -> None:
    url = "https://app.example.com/api/secret-data"
    _patch_send(monkeypatch, {
        ("unauth", url): {"status_code": 401, "body": "Unauthorized", "headers": {}},
        ("user", url): {"status_code": 200, "body": "secret-data", "headers": {}},
    })
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "unauth", "headers": {}},
            {"name": "user", "headers": {"Cookie": "session=user-tok"}, "privilege": 50},
        ]),
    )
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_unauth_no_bypass_when_signatures_differ(monkeypatch) -> None:
    """unauth gets 200 but with different body length (e.g. public landing
    page vs. authenticated content) — not a bypass."""
    url = "https://app.example.com/dashboard"
    _patch_send(monkeypatch, {
        ("unauth", url): {"status_code": 200, "body": "Welcome (please log in)", "headers": {}},
        ("user", url): {"status_code": 200, "body": "Hi alice — your dashboard", "headers": {}},
    })
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "unauth", "headers": {}},
            {"name": "user", "headers": {"Cookie": "session=user-tok"}, "privilege": 50},
        ]),
    )
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# Vertical privilege escalation
# ---------------------------------------------------------------------------


def test_vertical_priv_esc_detected_on_admin_path(monkeypatch) -> None:
    url = "https://app.example.com/admin/users"
    same = {"status_code": 200, "body": "[{user1}, {user2}]", "headers": {}}
    _patch_send(monkeypatch, {
        ("user", url): same,
        ("admin", url): same,
    })
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "user", "headers": {"Cookie": "session=user-tok"}, "privilege": 50},
            {"name": "admin", "headers": {"Cookie": "session=admin-tok"}, "privilege": 100},
        ]),
    )
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "improper_authorization"
    assert reports[0]["cwe"] == "CWE-285"
    assert "admin-shaped" in reports[0]["description"]


def test_vertical_priv_esc_NOT_detected_on_non_admin_path(monkeypatch) -> None:
    """Same response across roles on a NON-admin path is normal (e.g.
    /api/me probably returns content for both user roles). Don't flag it."""
    url = "https://app.example.com/api/profile"
    same = {"status_code": 200, "body": "{profile}", "headers": {}}
    _patch_send(monkeypatch, {
        ("user", url): same,
        ("admin", url): same,
    })
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "user", "headers": {"Cookie": "session=user-tok"}, "privilege": 50},
            {"name": "admin", "headers": {"Cookie": "session=admin-tok"}, "privilege": 100},
        ]),
    )
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_vertical_priv_esc_NOT_detected_when_403(monkeypatch) -> None:
    """user gets 403, admin gets 200 — proper authorization. Don't flag."""
    url = "https://app.example.com/admin/users"
    _patch_send(monkeypatch, {
        ("user", url): {"status_code": 403, "body": "Forbidden", "headers": {}},
        ("admin", url): {"status_code": 200, "body": "[{user1}]", "headers": {}},
    })
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "user", "headers": {"Cookie": "session=user-tok"}, "privilege": 50},
            {"name": "admin", "headers": {"Cookie": "session=admin-tok"}, "privilege": 100},
        ]),
    )
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_admin_path_heuristic_covers_common_keywords(monkeypatch) -> None:
    """Each default-pattern keyword should trigger priv-esc detection."""
    same = {"status_code": 200, "body": "x", "headers": {}}
    for keyword in ("admin", "internal", "private", "manage", "superuser", "staff", "_admin", "sudo", "root"):
        url = f"https://app.example.com/{keyword}/something"
        # Reset tracer between cases.
        Tracer("test-" + keyword).save_run_data()
        from strix.telemetry.tracer import Tracer as T, set_global_tracer as sgt
        new_t = T(f"hp-{keyword}")
        sgt(new_t)
        new_t.set_scan_config({"targets": [{"value": "x"}]})

        _patch_send(monkeypatch, {("user", url): same, ("admin", url): same})
        am.authz_matrix_check(
            endpoints=json.dumps([{"url": url, "method": "GET"}]),
            roles=json.dumps([
                {"name": "user", "headers": {"Cookie": "user-tok"}, "privilege": 50},
                {"name": "admin", "headers": {"Cookie": "admin-tok"}, "privilege": 100},
            ]),
        )
        assert len(new_t.get_existing_vulnerabilities()) == 1, (
            f"keyword '{keyword}' did not trigger priv-esc detection"
        )


def test_admin_path_pattern_override(monkeypatch) -> None:
    """`/api/v1/secret/users` isn't admin-shaped by default, but the
    operator can override the patterns."""
    url = "https://app.example.com/api/v1/secret/users"
    same = {"status_code": 200, "body": "x", "headers": {}}
    _patch_send(monkeypatch, {("user", url): same, ("admin", url): same})
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "user", "headers": {"Cookie": "user-tok"}, "privilege": 50},
            {"name": "admin", "headers": {"Cookie": "admin-tok"}, "privilege": 100},
        ]),
        admin_path_patterns=r"/api/v1/secret/.*",
    )
    assert len(tracer_module.get_global_tracer().get_existing_vulnerabilities()) == 1


# ---------------------------------------------------------------------------
# Cell cap + check events
# ---------------------------------------------------------------------------


def test_max_cells_cap_honored(monkeypatch) -> None:
    """4 endpoints × 2 roles = 8 cells; cap at 3 should stop early."""
    log = _patch_send(monkeypatch, {})
    am.authz_matrix_check(
        endpoints=json.dumps([
            {"url": f"https://app.example.com/p{i}", "method": "GET"} for i in range(4)
        ]),
        roles=json.dumps([
            {"name": "unauth", "headers": {}},
            {"name": "user", "headers": {"Cookie": "user-tok"}, "privilege": 50},
        ]),
        max_cells=3,
    )
    assert len(log) == 3


def test_check_events_emitted_per_cell(monkeypatch, tmp_path) -> None:
    url = "https://app.example.com/api/x"
    _patch_send(monkeypatch, {
        ("user", url): {"status_code": 200, "body": "ok", "headers": {}},
    })
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([{"name": "user", "headers": {"Cookie": "user-tok"}, "privilege": 50}]),
    )
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "authorization" in summary["by_category"]


# ---------------------------------------------------------------------------
# Cluster-A composition: excluded paths short-circuit
# ---------------------------------------------------------------------------


def test_excluded_path_skipped_during_matrix(monkeypatch) -> None:
    """When a request hits an exclude-path, the cell is recorded as
    skipped and produces an inconclusive check event — not vulnerable
    or not_vulnerable."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/api/billing/*"]))
    # Use a manager stub that lets http_safety run.
    class FakeManager:
        def send_simple_request(self, method, url, headers=None, timeout=30):
            from strix.tools.proxy.http_safety import (
                excluded_response, inject_auth_headers, is_path_excluded,
            )
            excluded, glob = is_path_excluded(url)
            if excluded:
                return excluded_response(url, glob or "")
            inject_auth_headers(headers or {})
            return {"status_code": 200, "body": "ok", "headers": {}}

    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: FakeManager(),
    )
    url = "https://app.example.com/api/billing/charge"
    out = am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "POST"}]),
        roles=json.dumps([{"name": "user", "headers": {"Cookie": "user-tok"}, "privilege": 50}]),
    )
    cell = out["cells"][0]
    assert cell["skipped"] is True
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_result"]["inconclusive"] >= 1


# ---------------------------------------------------------------------------
# Header-value confidentiality
# ---------------------------------------------------------------------------


def test_role_headers_never_appear_in_findings(monkeypatch) -> None:
    """Critical: even when findings reference roles, the header VALUES must
    not leak into finding bodies (per credentials-feedback memory)."""
    url = "https://app.example.com/admin/secrets"
    same = {"status_code": 200, "body": "secret-list", "headers": {}}
    _patch_send(monkeypatch, {("user", url): same, ("admin", url): same})
    am.authz_matrix_check(
        endpoints=json.dumps([{"url": url, "method": "GET"}]),
        roles=json.dumps([
            {"name": "user", "headers": {"Cookie": "VERY_SENSITIVE_USER_TOK_xyz"}, "privilege": 50},
            {"name": "admin", "headers": {"Authorization": "Bearer SECRET_ADMIN_BEARER_abc"}, "privilege": 100},
        ]),
    )
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    body = json.dumps(reports[0])
    assert "VERY_SENSITIVE_USER_TOK_xyz" not in body
    assert "SECRET_ADMIN_BEARER_abc" not in body
    # Role *names* are fine.
    assert "user" in body or "admin" in body
