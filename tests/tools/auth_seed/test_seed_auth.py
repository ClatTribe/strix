"""Tests for iter-28.4 — shape-driven auth seed primitive."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.auth_seed.seed_auth import (
    _BEARER_RESPONSE_KEYS,
    _build_payload,
    _extract_credential,
    _form_looks_like_registration,
    _generate_candidate_endpoints,
    _generate_test_account,
    seed_auth,
)


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    """Each test starts with no STRIX_AUTH_* set."""
    monkeypatch.delenv("STRIX_AUTH_BEARER", raising=False)
    monkeypatch.delenv("STRIX_AUTH_COOKIE", raising=False)
    yield


# ---------------------------------------------------------------------------
# _generate_test_account
# ---------------------------------------------------------------------------

def test_generate_test_account_unique():
    a, b = _generate_test_account(), _generate_test_account()
    assert a != b
    assert a["email"].endswith("@strix.test")
    assert a["username"].startswith("strix-seed-")


def test_generate_test_account_meets_complexity():
    """Password must beat default-cred rules so we don't trip our
    own SUT's password-strength validation (or our own
    default_creds_probe down the line)."""
    creds = _generate_test_account()
    pw = creds["password"]
    assert len(pw) >= 20
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)


# ---------------------------------------------------------------------------
# _form_looks_like_registration — the shape detector
# ---------------------------------------------------------------------------

def test_form_shape_matches_classic_register():
    form = {
        "method": "POST",
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
        ],
    }
    assert _form_looks_like_registration(form)


def test_form_shape_matches_username_variant():
    form = {
        "method": "POST",
        "inputs": [
            {"name": "userName", "type": "text"},
            {"name": "passwd", "type": "password"},
        ],
    }
    assert _form_looks_like_registration(form)


def test_form_shape_rejects_get_method():
    """GET 'register' forms are almost always search/filter, not register."""
    form = {
        "method": "GET",
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
        ],
    }
    assert not _form_looks_like_registration(form)


def test_form_shape_rejects_login_only():
    """A POST with email + remember_me (no password) is search/login-ui."""
    form = {
        "method": "POST",
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "remember", "type": "checkbox"},
        ],
    }
    assert not _form_looks_like_registration(form)


def test_form_shape_rejects_empty_form():
    assert not _form_looks_like_registration({"method": "POST", "inputs": []})


# ---------------------------------------------------------------------------
# _build_payload — must populate role-detected fields + sensible defaults
# ---------------------------------------------------------------------------

def test_payload_routes_email_password_to_correct_fields():
    creds = {"email": "x@x.test", "username": "xx", "password": "pw"}
    form = {
        "inputs": [
            {"name": "userEmail", "type": "email"},
            {"name": "passwd", "type": "password"},
            {"name": "firstName", "type": "text"},
        ],
    }
    body = _build_payload(form, creds)
    assert body["userEmail"] == "x@x.test"
    assert body["passwd"] == "pw"
    assert body["firstName"] == "strix-seed"  # unknown text field default


def test_payload_handles_checkbox_tos():
    creds = {"email": "x@x.test", "username": "xx", "password": "pw"}
    form = {
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
            {"name": "acceptTos", "type": "checkbox"},
        ],
    }
    body = _build_payload(form, creds)
    assert body["acceptTos"] == "on"


def test_payload_skips_hidden_csrf():
    """Hidden fields are usually CSRF tokens — skip rather than send 'strix-seed'
    which would fail validation server-side."""
    creds = {"email": "x@x.test", "username": "xx", "password": "pw"}
    form = {
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
            {"name": "csrf_token", "type": "hidden"},
        ],
    }
    body = _build_payload(form, creds)
    assert "csrf_token" not in body


# ---------------------------------------------------------------------------
# _extract_credential — JWT / Bearer / cookie extraction
# ---------------------------------------------------------------------------

def test_extract_credential_top_level_token():
    r = MagicMock()
    r.json = MagicMock(return_value={"token": "abc.def.ghi"})
    r.text = '{"token": "abc.def.ghi"}'
    r.headers = {}
    r.raw = MagicMock(spec=[])  # no get_all
    out = _extract_credential(r)
    assert out["bearer"] == "abc.def.ghi"


def test_extract_credential_nested_data_token():
    r = MagicMock()
    r.json = MagicMock(
        return_value={"data": {"accessToken": "nested-jwt-here"}},
    )
    r.text = ""
    r.headers = {}
    r.raw = MagicMock(spec=[])
    out = _extract_credential(r)
    assert out["bearer"] == "nested-jwt-here"


def test_extract_credential_jwt_regex_fallback():
    """When the response is a non-standard envelope but contains a
    JWT-shaped string anywhere in the body, regex catches it."""
    jwt = "eyJhbGciOi.eyJzdWIiOi.signature"
    r = MagicMock()
    r.json = MagicMock(side_effect=ValueError("not json"))
    r.text = f"Welcome! Your session is {jwt} valid for 24h."
    r.headers = {}
    r.raw = MagicMock(spec=[])
    out = _extract_credential(r)
    assert out["bearer"] == jwt


def test_extract_credential_set_cookie():
    r = MagicMock()
    r.json = MagicMock(side_effect=ValueError("not json"))
    r.text = ""
    r.headers = {"set-cookie": "session=abcd1234; Path=/; HttpOnly"}
    r.raw = MagicMock(spec=[])  # raw doesn't expose get_all → headers fallback
    out = _extract_credential(r)
    assert out["cookie"] == "session=abcd1234"


def test_extract_credential_none_when_no_match():
    r = MagicMock()
    r.json = MagicMock(return_value={"status": "ok", "user_id": 42})
    r.text = '{"status": "ok", "user_id": 42}'
    r.headers = {}
    r.raw = MagicMock(spec=[])
    out = _extract_credential(r)
    assert out == {}


# ---------------------------------------------------------------------------
# _generate_candidate_endpoints
# ---------------------------------------------------------------------------

def test_candidates_prefer_crawl_forms():
    forms = [
        {
            "action": "/api/Users/",
            "method": "POST",
            "inputs": [
                {"name": "email", "type": "email"},
                {"name": "password", "type": "password"},
            ],
        },
    ]
    cands = _generate_candidate_endpoints("http://app:3000", forms)
    assert len(cands) == 1
    assert cands[0][0] == "http://app:3000/api/Users/"


def test_candidates_fallback_to_well_known_paths():
    cands = _generate_candidate_endpoints("http://app:3000", forms=[])
    assert len(cands) >= 10  # well-known fallback list
    urls = [c[0] for c in cands]
    # Spot-check a few standards
    assert "http://app:3000/register" in urls
    assert "http://app:3000/api/v1/users" in urls


def test_candidates_skip_get_form_when_falling_back():
    """A GET-method form doesn't count; fallback path list fires."""
    forms = [{"action": "/", "method": "GET", "inputs": []}]
    cands = _generate_candidate_endpoints("http://app:3000", forms)
    assert len(cands) >= 10  # fell through to fallback list


# ---------------------------------------------------------------------------
# seed_auth — top-level
# ---------------------------------------------------------------------------

def test_seed_auth_rejects_empty_target():
    out = seed_auth(target_url="")
    assert out["success"] is False
    assert "target_url required" in out["reason"]


def test_seed_auth_idempotent_when_already_seeded(monkeypatch):
    monkeypatch.setenv("STRIX_AUTH_BEARER", "existing-jwt")
    out = seed_auth(target_url="http://app:3000")
    assert out["success"] is True
    assert "cached" in out["endpoint_used"]
    assert out["credential_kind"] == "bearer"


@patch("strix.tools.auth_seed.seed_auth.requests.post")
def test_seed_auth_happy_path_sets_env(mock_post, monkeypatch):
    monkeypatch.delenv("STRIX_AUTH_BEARER", raising=False)
    resp = MagicMock()
    resp.status_code = 201
    resp.json = MagicMock(return_value={"token": "new.jwt.here"})
    resp.text = '{"token": "new.jwt.here"}'
    resp.headers = {}
    resp.raw = MagicMock(spec=[])
    mock_post.return_value = resp

    forms = [{
        "action": "/api/Users/",
        "method": "POST",
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
        ],
    }]
    out = seed_auth(target_url="http://app:3000", forms=forms)
    assert out["success"] is True
    assert out["credential_kind"] == "bearer"
    assert os.environ.get("STRIX_AUTH_BEARER") == "new.jwt.here"
    # Cleanup so other tests aren't polluted
    monkeypatch.delenv("STRIX_AUTH_BEARER", raising=False)


@patch("strix.tools.auth_seed.seed_auth.requests.post")
def test_seed_auth_all_candidates_fail(mock_post, monkeypatch):
    monkeypatch.delenv("STRIX_AUTH_BEARER", raising=False)
    mock_post.return_value = MagicMock(
        status_code=404, text="", json=MagicMock(side_effect=ValueError),
        headers={}, raw=MagicMock(spec=[]),
    )
    out = seed_auth(target_url="http://app:3000")
    assert out["success"] is False
    assert out["status"] == "partial"
    assert "no successful registration" in out["reason"]


def test_seed_auth_registered():
    """Regression-guard the tool registry entry."""
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("seed_auth"))
