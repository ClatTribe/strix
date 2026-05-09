"""Tests for §8.5 Phase 3c — `_request_builders.build_request`.

Pins the protocol-expansion logic that lets `scan_xss`, `scan_sqli`,
and any future deterministic specialist probe POST forms, JSON
bodies, and path params — not just GET-with-querystring.
"""

from __future__ import annotations

import json

import pytest

from strix.tools.specialist._request_builders import (
    build_request,
    is_path_param_url,
)


# ---------------------------------------------------------------------------
# Path-param detection
# ---------------------------------------------------------------------------


def test_is_path_param_url_finds_placeholder() -> None:
    assert is_path_param_url("http://x/api/Baskets/{id}", "id") is True
    assert is_path_param_url("http://x/users/{name}/posts", "name") is True


def test_is_path_param_url_no_placeholder() -> None:
    assert is_path_param_url("http://x/api/Baskets/123", "id") is False
    assert is_path_param_url("http://x/users?name=foo", "name") is False


def test_is_path_param_url_other_placeholder() -> None:
    """Doesn't false-match on a different placeholder name."""
    assert is_path_param_url("http://x/users/{name}", "id") is False


# ---------------------------------------------------------------------------
# Query-string mode (Phase 3b — must still work)
# ---------------------------------------------------------------------------


def test_get_query_string_unchanged_from_phase_3b() -> None:
    method, url, headers, body = build_request(
        url="http://x/search",
        method="GET",
        param_name="q",
        payload="<script>alert(1)</script>",
    )
    assert method == "GET"
    assert "q=" in url
    assert "%3Cscript" in url or "<script" in url  # urlencoded
    assert body == ""
    assert headers == {}


def test_get_query_preserves_other_params() -> None:
    _, url, _, _ = build_request(
        url="http://x/search?lang=en",
        method="GET",
        param_name="q",
        payload="X",
        other_params={"page": "1"},
    )
    assert "lang=en" in url
    assert "page=1" in url
    assert "q=X" in url


# ---------------------------------------------------------------------------
# Path-param mode
# ---------------------------------------------------------------------------


def test_path_param_substitution() -> None:
    """`{id}` in URL is replaced with the payload."""
    _, url, _, body = build_request(
        url="http://x/api/Baskets/{id}",
        method="GET",
        param_name="id",
        payload="' OR 1=1--",
    )
    assert "{id}" not in url
    # SQL chars should survive (only path-special chars are encoded).
    assert "'" in url
    assert "OR" in url
    assert body == ""


def test_path_param_with_slash_in_payload_encoded() -> None:
    """A `/` in payload would break path structure → encoded."""
    _, url, _, _ = build_request(
        url="http://x/users/{name}",
        method="GET",
        param_name="name",
        payload="alice/bob",
    )
    assert "alice/bob" not in url
    assert "alice%2Fbob" in url


# ---------------------------------------------------------------------------
# JSON body mode (the big Phase 3c addition)
# ---------------------------------------------------------------------------


def test_post_json_body_substitution() -> None:
    """Phase 3c headline: probe a POST JSON endpoint."""
    method, url, headers, body = build_request(
        url="http://x/rest/user/login",
        method="POST",
        param_name="email",
        payload="' OR 1=1--",
        body_template={"email": "x@example.com", "password": "x"},
    )
    assert method == "POST"
    assert url == "http://x/rest/user/login"
    assert headers["Content-Type"] == "application/json"
    parsed = json.loads(body)
    assert parsed == {"email": "' OR 1=1--", "password": "x"}


def test_json_body_default_format_is_json() -> None:
    """`body_format='auto'` + dict template → JSON."""
    _, _, headers, body = build_request(
        url="http://x/api",
        method="POST",
        param_name="q",
        payload="X",
        body_template={"q": "default", "extra": 42},
    )
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {"q": "X", "extra": 42}


def test_json_body_template_not_mutated_across_probes() -> None:
    """The caller's template is reused across multiple payloads. The
    builder must deep-copy so a previous probe's payload doesn't
    leak into the next one."""
    template = {"q": "default", "page": 1}
    build_request(
        url="http://x/", method="POST", param_name="q",
        payload="FIRST", body_template=template,
    )
    build_request(
        url="http://x/", method="POST", param_name="q",
        payload="SECOND", body_template=template,
    )
    # Template should be unchanged.
    assert template == {"q": "default", "page": 1}


def test_json_body_param_not_in_template_logs_but_doesnt_crash(caplog) -> None:
    """If the caller specifies a param name not present in the
    template, send the original template as-is (baseline-equivalent).
    Don't raise — that would kill the probe loop."""
    _, _, headers, body = build_request(
        url="http://x/api",
        method="POST",
        param_name="not_in_template",
        payload="X",
        body_template={"q": "test"},
    )
    assert json.loads(body) == {"q": "test"}


# ---------------------------------------------------------------------------
# Form body mode
# ---------------------------------------------------------------------------


def test_post_form_body_substitution() -> None:
    method, _, headers, body = build_request(
        url="http://x/login.php",
        method="POST",
        param_name="username",
        payload="admin' --",
        body_template={"username": "admin", "password": "x"},
        body_format="form",
    )
    assert method == "POST"
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    # urlencoded
    assert "username=admin%27" in body
    assert "password=x" in body


def test_form_body_unicode_safe() -> None:
    _, _, _, body = build_request(
        url="http://x/", method="POST", param_name="q",
        payload="ünicode", body_template={"q": ""},
        body_format="form",
    )
    assert "%C3%BC" in body  # ü urlencoded


# ---------------------------------------------------------------------------
# Raw string body
# ---------------------------------------------------------------------------


def test_raw_string_body_placeholder_substitution() -> None:
    """`body_template` as a string with `{param}` placeholder for
    cases where neither JSON nor form-encoded fits (e.g. XML, custom
    formats)."""
    _, _, headers, body = build_request(
        url="http://x/soap",
        method="POST",
        param_name="user",
        payload="admin' OR 1=1--",
        body_template="<envelope><user>{user}</user></envelope>",
        extra_headers={"Content-Type": "text/xml"},
    )
    # Caller-supplied content type wins; builder doesn't override.
    assert headers["Content-Type"] == "text/xml"
    assert body == "<envelope><user>admin' OR 1=1--</user></envelope>"


# ---------------------------------------------------------------------------
# Header forwarding
# ---------------------------------------------------------------------------


def test_extra_headers_forwarded() -> None:
    _, _, headers, _ = build_request(
        url="http://x/api",
        method="POST",
        param_name="q",
        payload="X",
        body_template={"q": "default"},
        extra_headers={"Authorization": "Bearer token123"},
    )
    assert headers["Authorization"] == "Bearer token123"
    assert headers["Content-Type"] == "application/json"  # added by builder


def test_caller_content_type_wins_over_builder() -> None:
    """If the caller already sets Content-Type, builder doesn't
    overwrite. Lets users probe e.g. `application/graphql` endpoints
    even when passing a dict template."""
    _, _, headers, _ = build_request(
        url="http://x/graphql",
        method="POST",
        param_name="q",
        payload="X",
        body_template={"q": "{ users { id } }"},
        extra_headers={"Content-Type": "application/graphql"},
    )
    assert headers["Content-Type"] == "application/graphql"


# ---------------------------------------------------------------------------
# Method normalization
# ---------------------------------------------------------------------------


def test_method_uppercased() -> None:
    method, _, _, _ = build_request(
        url="http://x/", method="post",
        param_name="q", payload="X",
        body_template={"q": ""},
    )
    assert method == "POST"


def test_method_default_is_get() -> None:
    method, _, _, _ = build_request(
        url="http://x/?q=t", method="",
        param_name="q", payload="X",
    )
    assert method == "GET"
