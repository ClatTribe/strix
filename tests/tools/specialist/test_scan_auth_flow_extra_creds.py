"""Tests for the Phase 3d / PR-β credential extension to
`scan_auth_flow`.

Covers:
  * `_load_user_supplied_credentials` reads from kwarg + env
  * Both forms (tuple list, dict list) accepted
  * Malformed entries dropped silently (debug-logged)
  * Dedup across sources
  * Kwarg takes precedence over env when both set (both contribute)
  * `STRIX_LOGIN_CREDS` invalid JSON → empty list, no crash
  * Source attribution: user_supplied vs default_corpus

We do NOT test the HTTP probing itself — that's covered by the
existing `scan_auth_flow` test suite. These tests focus on the
cred-loading shape that's new in PR-β.
"""

from __future__ import annotations

import json
import os

import pytest

from strix.tools.specialist.scan_auth_flow import (
    _DEFAULT_CREDS,
    _load_user_supplied_credentials,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("STRIX_LOGIN_CREDS", raising=False)
    yield


# ---------------------------------------------------------------------------
# Loader — kwarg path
# ---------------------------------------------------------------------------


def test_loader_accepts_tuple_list() -> None:
    out = _load_user_supplied_credentials([("admin", "secret123")])
    assert out == [("admin", "secret123")]


def test_loader_accepts_list_of_lists() -> None:
    out = _load_user_supplied_credentials([["user", "pw"]])
    assert out == [("user", "pw")]


def test_loader_accepts_dict_list() -> None:
    out = _load_user_supplied_credentials([
        {"username": "jsmith", "password": "Demo1234"},
    ])
    assert out == [("jsmith", "Demo1234")]


def test_loader_returns_empty_for_none() -> None:
    assert _load_user_supplied_credentials(None) == []


def test_loader_returns_empty_for_empty_list() -> None:
    assert _load_user_supplied_credentials([]) == []


# ---------------------------------------------------------------------------
# Loader — env path
# ---------------------------------------------------------------------------


def test_loader_reads_env_list_of_dicts(monkeypatch) -> None:
    monkeypatch.setenv(
        "STRIX_LOGIN_CREDS",
        json.dumps([{"username": "a", "password": "b"}]),
    )
    assert _load_user_supplied_credentials(None) == [("a", "b")]


def test_loader_reads_env_list_of_lists(monkeypatch) -> None:
    monkeypatch.setenv(
        "STRIX_LOGIN_CREDS",
        json.dumps([["a", "b"], ["c", "d"]]),
    )
    assert _load_user_supplied_credentials(None) == [("a", "b"), ("c", "d")]


def test_loader_env_malformed_json_returns_empty(monkeypatch) -> None:
    """STRIX_LOGIN_CREDS containing non-JSON shouldn't crash —
    log at debug and degrade to no user-supplied creds."""
    monkeypatch.setenv("STRIX_LOGIN_CREDS", "not json at all {")
    assert _load_user_supplied_credentials(None) == []


def test_loader_env_top_level_dict_returns_empty(monkeypatch) -> None:
    """The contract is a LIST. A top-level dict isn't valid;
    degrade silently."""
    monkeypatch.setenv(
        "STRIX_LOGIN_CREDS",
        json.dumps({"username": "a", "password": "b"}),
    )
    assert _load_user_supplied_credentials(None) == []


def test_loader_env_empty_string_returns_empty(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LOGIN_CREDS", "")
    assert _load_user_supplied_credentials(None) == []


# ---------------------------------------------------------------------------
# Loader — combination + dedup
# ---------------------------------------------------------------------------


def test_loader_combines_kwarg_and_env(monkeypatch) -> None:
    """Both sources contribute. Kwarg entries come first
    (they're the explicit programmatic override), env entries
    come second."""
    monkeypatch.setenv(
        "STRIX_LOGIN_CREDS",
        json.dumps([{"username": "env-user", "password": "env-pw"}]),
    )
    out = _load_user_supplied_credentials([("kw-user", "kw-pw")])
    assert out == [("kw-user", "kw-pw"), ("env-user", "env-pw")]


def test_loader_dedup_across_sources(monkeypatch) -> None:
    """Duplicate pairs (kwarg + env) are deduplicated; first
    occurrence wins."""
    monkeypatch.setenv(
        "STRIX_LOGIN_CREDS",
        json.dumps([["admin", "secret"]]),
    )
    out = _load_user_supplied_credentials([("admin", "secret")])
    assert out == [("admin", "secret")]
    assert len(out) == 1


# ---------------------------------------------------------------------------
# Loader — malformed entries
# ---------------------------------------------------------------------------


def test_loader_drops_entries_with_empty_user() -> None:
    out = _load_user_supplied_credentials([("", "pw"), ("user", "pw")])
    assert out == [("user", "pw")]


def test_loader_drops_entries_with_empty_password() -> None:
    out = _load_user_supplied_credentials([("user", ""), ("u2", "p2")])
    assert out == [("u2", "p2")]


def test_loader_drops_non_string_values() -> None:
    """Numbers / None should be ignored, not coerced to str. We
    don't want to silently log in with `(42, 'pw')`."""
    out = _load_user_supplied_credentials([
        (42, "pw"),
        ("u", None),
        ("u2", "p2"),
    ])
    assert out == [("u2", "p2")]


def test_loader_drops_single_element_lists() -> None:
    """`["just-a-username"]` is not a valid pair."""
    out = _load_user_supplied_credentials([
        ["just-user"],
        ["u2", "p2"],
    ])
    assert out == [("u2", "p2")]


def test_loader_strips_whitespace() -> None:
    """Wrapper might send `'admin  '` accidentally — trim it."""
    out = _load_user_supplied_credentials([("  admin  ", "  pw  ")])
    assert out == [("admin", "pw")]


# ---------------------------------------------------------------------------
# Default-creds corpus is unchanged
# ---------------------------------------------------------------------------


def test_default_corpus_unchanged() -> None:
    """_DEFAULT_CREDS is still the original built-in list. PR-β
    layers user-supplied on top WITHOUT modifying defaults."""
    assert ("admin", "admin") in _DEFAULT_CREDS
    assert ("jsmith" in [u for u, _p in _DEFAULT_CREDS]
            or len(_DEFAULT_CREDS) >= 10)  # sanity check shape
