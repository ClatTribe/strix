"""Tests for iter-28.6 — default-credentials probe."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from strix.tools.default_creds_probe.probe_default_creds import (
    _DEFAULT_CREDS,
    _LOGIN_PATH_FALLBACKS,
    _detect_field_names,
    _detect_login_form,
    _is_login_success,
    probe_default_creds,
)


# ---------------------------------------------------------------------------
# Anti-overfit: credential list must be generic SecLists
# ---------------------------------------------------------------------------

def test_credentials_are_industry_defaults_not_sut_specific():
    creds = set(_DEFAULT_CREDS)
    # Industry standards must be present
    assert ("admin", "admin") in creds
    assert ("root", "root") in creds
    assert ("admin", "password") in creds
    # NO SUT-specific credentials permitted
    forbidden = {
        ("admin", "juiceshop"), ("bkimminich", "letmein"),
        ("juiceshop", "admin"), ("ashish", "anything"),
    }
    assert not (creds & forbidden), (
        f"credential list contains SUT-specific entries (overfit): "
        f"{creds & forbidden}"
    )


def test_credentials_size_reasonable():
    """Cap is implicit — we don't want a 10000-entry list that DoSes
    the SUT. 100-200 industry defaults max."""
    assert 30 <= len(_DEFAULT_CREDS) <= 200


def test_login_paths_are_industry_conventions():
    p = set(_LOGIN_PATH_FALLBACKS)
    assert "/login" in p
    assert "/api/auth/login" in p
    # No SUT-specific paths
    assert "/rest/user/login" not in p   # juice-shop specific
    assert "/api/Users" not in p          # juice-shop signup, not login


# ---------------------------------------------------------------------------
# _is_login_success — heuristic
# ---------------------------------------------------------------------------

def test_success_when_set_cookie_with_session():
    r = MagicMock(status_code=200, text="welcome", headers={
        "set-cookie": "sessionId=abcd; Path=/",
    })
    r.json = MagicMock(side_effect=ValueError)
    ok, ev = _is_login_success(r)
    assert ok
    assert "sessionid" in ev.lower()


def test_success_when_json_has_access_token():
    r = MagicMock(status_code=200, text='{"access_token": "abc"}', headers={})
    r.json = MagicMock(return_value={"access_token": "abc"})
    ok, ev = _is_login_success(r)
    assert ok


def test_failure_on_401():
    r = MagicMock(status_code=401, text="", headers={})
    r.json = MagicMock(side_effect=ValueError)
    ok, ev = _is_login_success(r)
    assert not ok


def test_failure_on_body_marker_even_with_200():
    """Many login endpoints return 200 with 'invalid credentials' in
    the body — must NOT be a false positive."""
    r = MagicMock(
        status_code=200,
        text='{"error": "Invalid Email or Password."}',
        headers={"set-cookie": "tracking=xyz"},  # tracking cookie != session
    )
    r.json = MagicMock(return_value={"error": "Invalid Email or Password."})
    ok, ev = _is_login_success(r)
    assert not ok


def test_success_on_post_login_redirect():
    r = MagicMock(status_code=302, text="", headers={"Location": "/dashboard"})
    r.json = MagicMock(side_effect=ValueError)
    ok, ev = _is_login_success(r)
    assert ok


def test_failure_on_redirect_back_to_login():
    """302 to /login is the failure-redirect pattern."""
    r = MagicMock(
        status_code=302, text="", headers={"Location": "/login?error=1"},
    )
    r.json = MagicMock(side_effect=ValueError)
    ok, ev = _is_login_success(r)
    assert not ok


# ---------------------------------------------------------------------------
# _detect_login_form — form-shape detection
# ---------------------------------------------------------------------------

def test_detect_login_form_picks_shortest_candidate():
    """Login forms have fewer fields than register forms — picker
    must prefer the shortest matching form."""
    forms = [
        # Registration form (5 fields)
        {"action": "/register", "method": "POST", "inputs": [
            {"name": "email"}, {"name": "password"},
            {"name": "firstName"}, {"name": "lastName"}, {"name": "tos"},
        ]},
        # Login form (2 fields)
        {"action": "/login", "method": "POST", "inputs": [
            {"name": "email"}, {"name": "password"},
        ]},
    ]
    f = _detect_login_form(forms)
    assert f["action"] == "/login"


def test_detect_login_form_skips_get_forms():
    forms = [{"action": "/search", "method": "GET", "inputs": [
        {"name": "q"}, {"name": "password"},  # bogus password field on search
    ]}]
    assert _detect_login_form(forms) is None


def test_detect_login_form_none_when_no_match():
    assert _detect_login_form([]) is None
    assert _detect_login_form(None) is None


# ---------------------------------------------------------------------------
# _detect_field_names
# ---------------------------------------------------------------------------

def test_field_names_default_to_username_password():
    form = {"inputs": [{"name": "foo"}, {"name": "bar"}]}
    u, p = _detect_field_names(form)
    assert (u, p) == ("username", "password")


def test_field_names_picks_email_field():
    form = {"inputs": [
        {"name": "emailAddress"}, {"name": "passwd"},
    ]}
    u, p = _detect_field_names(form)
    assert u == "emailAddress"
    assert p == "passwd"


# ---------------------------------------------------------------------------
# probe_default_creds — top-level
# ---------------------------------------------------------------------------

def test_rejects_empty_target():
    out = probe_default_creds(target_url="")
    assert out["success"] is False
    assert "target_url required" in out["reason"]


def test_rejects_non_http_url():
    out = probe_default_creds(target_url="ftp://app:3000")
    assert out["success"] is False


@patch("strix.tools.default_creds_probe.probe_default_creds.requests.post")
def test_finds_admin_admin(mock_post):
    """When `admin/admin` is accepted, the tool stops + returns."""
    def _post(url, data=None, json=None, **kwargs):
        username = (data or json or {}).get("username")
        password = (data or json or {}).get("password")
        r = MagicMock(status_code=401, text="", headers={})
        r.json = MagicMock(side_effect=ValueError)
        if username == "admin" and password == "admin":
            r = MagicMock(status_code=200, text="welcome admin", headers={
                "set-cookie": "session=abc; Path=/; HttpOnly",
            })
            r.json = MagicMock(side_effect=ValueError)
        return r
    mock_post.side_effect = _post

    out = probe_default_creds(
        target_url="http://app:3000",
        login_url="http://app:3000/api/login",
        max_attempts=10,
    )
    assert out["success"] is True
    assert out["status"] == "ok"
    assert out["credential_found"] == {"username": "admin", "password": "admin"}
    assert out["endpoint_used"] == "http://app:3000/api/login"


@patch("strix.tools.default_creds_probe.probe_default_creds.requests.post")
def test_no_default_credential_returns_partial(mock_post):
    """If none accepted, status=partial with attempts_made."""
    r = MagicMock(status_code=401, text="Invalid credentials", headers={})
    r.json = MagicMock(side_effect=ValueError)
    mock_post.return_value = r

    out = probe_default_creds(
        target_url="http://app:3000",
        login_url="http://app:3000/login",
        max_attempts=5,
    )
    assert out["success"] is True
    assert out["status"] == "partial"
    assert out["credential_found"] is None
    assert out["attempts_made"] >= 5


@patch("strix.tools.default_creds_probe.probe_default_creds.requests.post")
def test_finds_login_via_crawl_form_when_no_login_url(mock_post):
    """When `login_url` is None but `forms` has a login-shaped entry,
    the tool uses that form's action."""
    def _post(url, data=None, json=None, **kwargs):
        r = MagicMock(status_code=401, text="invalid", headers={})
        r.json = MagicMock(side_effect=ValueError)
        if url == "http://app:3000/auth/login":
            user = (data or json or {}).get("emailAddress")
            pwd = (data or json or {}).get("passwd")
            if user == "admin" and pwd == "admin":
                r = MagicMock(status_code=200, text="ok", headers={
                    "set-cookie": "session=xyz",
                })
                r.json = MagicMock(side_effect=ValueError)
        return r
    mock_post.side_effect = _post

    forms = [{
        "action": "/auth/login",
        "method": "POST",
        "inputs": [
            {"name": "emailAddress"},
            {"name": "passwd"},
        ],
    }]
    out = probe_default_creds(
        target_url="http://app:3000",
        forms=forms,
    )
    assert out["success"] is True
    assert out["status"] == "ok"
    assert out["endpoint_used"] == "http://app:3000/auth/login"
    assert out["username_field"] == "emailAddress"
    assert out["password_field"] == "passwd"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("probe_default_creds"))
