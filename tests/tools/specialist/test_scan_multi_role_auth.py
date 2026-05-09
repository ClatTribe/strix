"""Tests for §workitem.md Phase 3.1 — `scan_multi_role_auth` orchestrator.

Pins:
  * anon role: implicit baseline written to AuthState
  * default-creds: cohort iteration → success captures session
  * admin alias: admin-shaped username also recorded under `admin`
    + emits CWE-798 critical finding
  * user-a + user-b: distinct sessions with distinct emails
  * Defensive: empty login_url → error
  * Per-role opt-in (`roles=["default-creds"]` skips registrations)
  * SecurityContext + decision_log integration
  * `next_probes_suggested` mentions IDOR when both user-a + user-b captured
  * Registry / catalog wiring
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_multi_role_auth import (
    _is_admin_shaped,
    scan_multi_role_auth,
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
    set_global_tracer(Tracer("test-mra"))
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
# _is_admin_shaped helper
# ---------------------------------------------------------------------------


def test_is_admin_shaped_pure_admin() -> None:
    assert _is_admin_shaped("admin")
    assert _is_admin_shaped("Admin")
    assert _is_admin_shaped("administrator")
    assert _is_admin_shaped("root")
    assert _is_admin_shaped("superuser")


def test_is_admin_shaped_admin_email() -> None:
    assert _is_admin_shaped("admin@juice-sh.op")
    assert _is_admin_shaped("ADMIN@example.com")
    assert _is_admin_shaped("root@host.local")


def test_is_admin_shaped_non_admin() -> None:
    assert not _is_admin_shaped("alice")
    assert not _is_admin_shaped("alice@example.com")
    assert not _is_admin_shaped("user1")
    assert not _is_admin_shaped("")
    assert not _is_admin_shaped(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_login_url_returns_error() -> None:
    out = scan_multi_role_auth(login_url="")
    assert out["status"] == "error"


def test_proxy_unavailable_returns_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("boom")),
    )
    out = scan_multi_role_auth(login_url="http://example.com/login")
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# anon baseline always recorded
# ---------------------------------------------------------------------------


def test_anon_role_recorded_even_when_login_fails(monkeypatch) -> None:
    """Anon must always succeed — it's the baseline, no requests required."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": '{"error":"invalid"}', "headers": {},
    })
    out = scan_multi_role_auth(
        login_url="http://example.com/login",
        roles=["anon"],
    )
    assert out["status"] == "ok"
    assert "anon" in out["tool_metadata"]["captured_roles"]
    from strix.agents.security_context import get_auth_state
    assert get_auth_state("anon") is not None


# ---------------------------------------------------------------------------
# Default-creds happy path
# ---------------------------------------------------------------------------


def test_default_creds_success_captures_session(monkeypatch) -> None:
    """First default-creds attempt succeeds → session captured under
    `default-creds`."""
    def fake_resp(method, url, headers, body, timeout):
        # Login attempts: succeed on the first one.
        return {
            "status_code": 200,
            "body": json.dumps({
                "authentication": {"token": "eyJtoken.body.sig"},
                "data": {"id": 1},
            }),
            "headers": {"Set-Cookie": "session=abc123; Path=/"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["default-creds"],
    )
    assert "default-creds" in out["tool_metadata"]["captured_roles"]
    from strix.agents.security_context import get_auth_state
    state = get_auth_state("default-creds")
    assert state is not None
    assert state.bearer == "eyJtoken.body.sig"


def test_admin_shaped_default_creds_emits_critical(monkeypatch) -> None:
    """When the default-cred cohort succeeds with the FIRST entry
    (`admin@juice-sh.op` — admin-shaped), the session is also recorded
    under `admin` AND a CWE-798 critical finding is emitted."""
    def fake_resp(method, url, headers, body, timeout):
        # Always-200 means the first cohort entry (admin-shaped) wins.
        return {
            "status_code": 200,
            "body": json.dumps({
                "authentication": {"token": "eyJadmin.body.sig"},
            }),
            "headers": {"Set-Cookie": "session=admin; Path=/"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["default-creds", "admin"],
    )
    captured = out["tool_metadata"]["captured_roles"]
    assert "default-creds" in captured
    assert "admin" in captured
    # Admin-default-creds → critical finding.
    titles = [f["title"] for f in out["findings"]]
    assert any("admin" in t.lower() for t in titles)
    assert any(f["severity"] == "critical" for f in out["findings"])


def test_default_creds_failure_no_session(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": '{"error":"invalid"}', "headers": {},
    })
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["default-creds"],
    )
    assert "default-creds" not in out["tool_metadata"]["captured_roles"]
    from strix.agents.security_context import get_auth_state
    assert get_auth_state("default-creds") is None


# ---------------------------------------------------------------------------
# Self-registration → user-a / user-b
# ---------------------------------------------------------------------------


def test_user_a_registers_and_logs_in(monkeypatch) -> None:
    """Register POST returns 201, login POST returns 200 with JWT."""
    def fake_resp(method, url, headers, body, timeout):
        if "register" in url or "Users" in url or "signup" in url:
            return {"status_code": 201, "body": '{"id":42}', "headers": {}}
        # Login.
        return {
            "status_code": 200,
            "body": json.dumps({"authentication": {"token": "eyJa.b.c"}}),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["user-a"],
    )
    assert "user-a" in out["tool_metadata"]["captured_roles"]
    from strix.agents.security_context import get_auth_state
    state = get_auth_state("user-a")
    assert state is not None
    assert state.bearer == "eyJa.b.c"


def test_user_a_and_user_b_get_distinct_sessions(monkeypatch) -> None:
    """Both registrations succeed; the two sessions are independent."""
    seen_emails: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        # Tag each registration with the email used.
        if isinstance(body, str):
            try:
                payload = json.loads(body)
            except Exception:
                payload = {}
            email = payload.get("email")
            if "register" in url or "Users" in url or "signup" in url:
                seen_emails.append(email or "")
                return {"status_code": 201, "body": '{}', "headers": {}}
        # Login: derive a JWT-shaped token from a hash of the email
        # (the JWT regex requires `.X.Y.Z` with only [A-Za-z0-9_-]).
        try:
            payload = json.loads(body) if isinstance(body, str) else {}
        except Exception:
            payload = {}
        email = payload.get("email", "anon")
        token_segment = "tok" + str(abs(hash(email)) % 10**12)
        return {
            "status_code": 200,
            "body": json.dumps({
                "authentication": {
                    "token": f"eyJalg.{token_segment}.sig"
                },
            }),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["user-a", "user-b"],
    )
    captured = out["tool_metadata"]["captured_roles"]
    assert "user-a" in captured
    assert "user-b" in captured
    # Two registrations happened with two distinct emails.
    assert len(seen_emails) >= 2
    assert seen_emails[0] != seen_emails[1]
    # AuthState entries differ.
    from strix.agents.security_context import get_auth_state
    state_a = get_auth_state("user-a")
    state_b = get_auth_state("user-b")
    assert state_a is not None
    assert state_b is not None
    assert state_a.bearer != state_b.bearer


def test_registration_failure_no_session_recorded(monkeypatch) -> None:
    """Register endpoint always 400 → user-a / user-b never captured."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 400, "body": '{"error":"signups disabled"}', "headers": {},
    })
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["user-a", "user-b"],
    )
    captured = out["tool_metadata"]["captured_roles"]
    assert "user-a" not in captured
    assert "user-b" not in captured


# ---------------------------------------------------------------------------
# next_probes_suggested
# ---------------------------------------------------------------------------


def test_idor_hint_when_both_users_captured(monkeypatch) -> None:
    """When user-a AND user-b are captured, next_probes mentions
    scan_idor — the lead's onramp to Phase 4.1."""
    def fake_resp(method, url, headers, body, timeout):
        if "register" in url or "Users" in url or "signup" in url:
            return {"status_code": 201, "body": '{}', "headers": {}}
        return {
            "status_code": 200,
            "body": json.dumps({"authentication": {"token": "eyJa.b.c"}}),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["user-a", "user-b"],
    )
    suggested = " ".join(out["next_probes_suggested"]).lower()
    assert "idor" in suggested or "user-a" in suggested


def test_admin_hint_when_admin_captured(monkeypatch) -> None:
    """When admin is captured, next_probes mentions /admin missing-auth."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": json.dumps({"authentication": {"token": "eyJa.b.c"}}),
        "headers": {},
    })
    out = scan_multi_role_auth(
        login_url="http://example.com/rest/user/login",
        roles=["default-creds", "admin"],
    )
    suggested = " ".join(out["next_probes_suggested"]).lower()
    assert "admin" in suggested


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_multi_role_auth(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": "no", "headers": {},
    })
    scan_multi_role_auth(
        login_url="http://example.com/login", roles=["anon"],
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("multi_role_auth" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": "no", "headers": {},
    })
    scan_multi_role_auth(
        login_url="http://example.com/login", roles=["anon"],
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_multi_role_auth"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Roles arg controls which phases run
# ---------------------------------------------------------------------------


def test_roles_subset_skips_other_phases(monkeypatch) -> None:
    """`roles=["anon"]` should skip default-creds + user-a + user-b
    (no login / register requests sent)."""
    request_count = [0]

    def fake_resp(method, url, headers, body, timeout):
        request_count[0] += 1
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    scan_multi_role_auth(
        login_url="http://example.com/login", roles=["anon"],
    )
    # No HTTP traffic — anon doesn't probe.
    assert request_count[0] == 0


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_multi_role_auth_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_multi_role_auth")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "multi-role-auth-specialist"


def test_scan_multi_role_auth_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_multi_role_auth" in catalog
