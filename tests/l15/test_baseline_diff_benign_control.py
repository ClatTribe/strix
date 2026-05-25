"""iter-30.5 — benign-shape control payload for fire_and_diff.

These tests verify the iter-30.5 fix to baseline_diff:
- `generate_benign_control` produces shape-matched safe payloads
- `fire_and_diff` auto-uses the generator on POST/PUT/PATCH when
  caller supplies `shape` and didn't pass an explicit control_payload
- Explicit control_payload still wins
- GET-shaped requests don't get a synthetic body
- Benign values never contain attack-alphabet characters
"""

from __future__ import annotations

import re
from unittest.mock import patch, MagicMock

import pytest

from strix.l15.baseline_diff import (
    generate_benign_control,
    fire_and_diff,
)


# ---------------------------------------------------------------------------
# generate_benign_control — pure function tests
# ---------------------------------------------------------------------------

def test_json_post_shape_returns_json_kwarg():
    out = generate_benign_control("json", "POST", params=["username", "password"])
    assert out == {"json": {"username": "benign", "password": "benign"}}


def test_form_post_shape_returns_data_kwarg():
    out = generate_benign_control("form", "POST", params=["name"])
    assert out == {"data": {"name": "benign"}}


def test_multipart_treated_as_form():
    out = generate_benign_control("multipart", "POST", params=["upload"])
    assert out == {"data": {"upload": "benign"}}


def test_graphql_returns_minimal_query():
    out = generate_benign_control("graphql", "POST", params=None)
    assert "json" in out
    assert "query" in out["json"]
    # Must be a syntactically minimal query
    assert "__typename" in out["json"]["query"]


def test_xml_returns_xml_body_with_content_type_override():
    out = generate_benign_control("xml", "POST", params=None)
    assert "data" in out
    assert out["data"].startswith("<")
    assert "headers_override" in out
    assert out["headers_override"]["Content-Type"] == "application/xml"


def test_get_method_returns_none_no_body_needed():
    """GET / HEAD / OPTIONS don't need a benign body."""
    assert generate_benign_control("json", "GET", ["q"]) is None
    assert generate_benign_control("json", "HEAD") is None
    assert generate_benign_control("json", "OPTIONS") is None


def test_unknown_shape_returns_none():
    """Caller falls back to no-body baseline when shape is unknown."""
    assert generate_benign_control("path", "POST") is None
    assert generate_benign_control(None, "POST") is None
    assert generate_benign_control("totally_invented", "POST") is None


def test_no_params_falls_back_to_q():
    out = generate_benign_control("json", "POST")
    assert out == {"json": {"q": "benign"}}


def test_empty_params_falls_back_to_q():
    out = generate_benign_control("json", "POST", params=[])
    assert out == {"json": {"q": "benign"}}


def test_filters_non_string_params():
    out = generate_benign_control("json", "POST", params=["valid", 42, None, "also_valid"])
    assert out == {"json": {"valid": "benign", "also_valid": "benign"}}


def test_filters_empty_string_params():
    out = generate_benign_control("json", "POST", params=["", "real"])
    assert out == {"json": {"real": "benign"}}


def test_put_and_patch_methods_get_body():
    """PUT/PATCH also get auto-generated body."""
    assert generate_benign_control("json", "PUT", ["x"]) == {"json": {"x": "benign"}}
    assert generate_benign_control("json", "PATCH", ["x"]) == {"json": {"x": "benign"}}


# ---------------------------------------------------------------------------
# Anti-overfit: benign values must NOT contain attack-alphabet characters
# ---------------------------------------------------------------------------

_ATTACK_TOKENS = (
    "'", '"', "`", "<", ">", "{", "}", "(", ")",
    ";", "$", "|", "&", "\\", "/*", "*/", "--",
    "../", "..\\",
)


def test_benign_value_has_no_attack_alphabet():
    """The benign string must contain ZERO attack-alphabet
    characters — if it did, the baseline + attack would no longer
    diff cleanly."""
    from strix.l15.baseline_diff import _BENIGN_VALUE
    for tok in _ATTACK_TOKENS:
        assert tok not in _BENIGN_VALUE, (
            f"_BENIGN_VALUE contains attack token {tok!r}"
        )


def test_xml_envelope_contains_no_attack_payload():
    out = generate_benign_control("xml", "POST")
    # The data string is XML — angle brackets ARE expected. We're
    # checking it doesn't contain SQL/XXE/SSRF tokens.
    bad = ("' OR ", "SELECT ", "<!ENTITY", "SYSTEM", "http://169.254", "file://")
    for tok in bad:
        assert tok.lower() not in out["data"].lower(), (
            f"benign XML envelope contains attack token {tok!r}"
        )


# ---------------------------------------------------------------------------
# fire_and_diff — auto-generate benign control on POST when shape supplied
# ---------------------------------------------------------------------------

def test_fire_and_diff_uses_benign_control_when_shape_supplied():
    """When method=POST + shape=json + no control_payload, fire_and_diff
    auto-generates a benign JSON baseline. Verify by mocking _capture
    and inspecting the kwargs of the FIRST call (the baseline)."""
    with patch("strix.l15.baseline_diff._capture") as mock_capture:
        mock_capture.return_value = {
            "status": 200, "size": 100, "time_ms": 10,
            "body": "ok", "body_hash": "h1", "location": "",
        }
        fire_and_diff(
            url="http://app/api/login", method="POST",
            attack_payload={"json": {"username": "' OR 1=1--"}},
            shape="json", params=["username", "password"],
        )

    calls = mock_capture.call_args_list
    assert len(calls) == 2
    # First call = baseline. Its kwargs should include the benign body.
    baseline_call = calls[0]
    assert "json" in baseline_call.kwargs
    assert baseline_call.kwargs["json"] == {
        "username": "benign", "password": "benign",
    }


def test_fire_and_diff_explicit_control_overrides_auto():
    """When caller provides control_payload explicitly, it wins
    (auto-generation only fires when control_payload is None)."""
    explicit_control = {"json": {"name": "explicit-override"}}
    with patch("strix.l15.baseline_diff._capture") as mock_capture:
        mock_capture.return_value = {
            "status": 200, "size": 100, "time_ms": 10,
            "body": "ok", "body_hash": "h1", "location": "",
        }
        fire_and_diff(
            url="http://app/api/x", method="POST",
            control_payload=explicit_control,
            attack_payload={"json": {"name": "attack"}},
            shape="json", params=["name"],
        )

    baseline_call = mock_capture.call_args_list[0]
    assert baseline_call.kwargs["json"] == {"name": "explicit-override"}


def test_fire_and_diff_no_shape_supplied_falls_back_to_no_body():
    """When neither shape nor control_payload is supplied, baseline
    still goes out with no body (preserves iter-29.2 GET-pattern)."""
    with patch("strix.l15.baseline_diff._capture") as mock_capture:
        mock_capture.return_value = {
            "status": 200, "size": 100, "time_ms": 10,
            "body": "ok", "body_hash": "h1", "location": "",
        }
        fire_and_diff(
            url="http://app/x", method="POST",
            attack_payload={"data": {"q": "attack"}},
        )

    baseline_call = mock_capture.call_args_list[0]
    # No `json` or `data` in baseline call kwargs → no-body
    assert "json" not in baseline_call.kwargs
    assert "data" not in baseline_call.kwargs


def test_fire_and_diff_get_method_ignores_shape_for_baseline():
    """GET method baseline is always no-body regardless of shape."""
    with patch("strix.l15.baseline_diff._capture") as mock_capture:
        mock_capture.return_value = {
            "status": 200, "size": 100, "time_ms": 10,
            "body": "ok", "body_hash": "h1", "location": "",
        }
        fire_and_diff(
            url="http://app/users?q=test", method="GET",
            attack_payload={},
            shape="json", params=["q"],
        )

    baseline_call = mock_capture.call_args_list[0]
    assert "json" not in baseline_call.kwargs
    assert "data" not in baseline_call.kwargs


def test_fire_and_diff_xml_baseline_merges_content_type_header():
    """For XML shape, the benign baseline includes Content-Type:
    application/xml so the server parses it correctly."""
    with patch("strix.l15.baseline_diff._capture") as mock_capture:
        mock_capture.return_value = {
            "status": 200, "size": 100, "time_ms": 10,
            "body": "ok", "body_hash": "h1", "location": "",
        }
        fire_and_diff(
            url="http://app/soap", method="POST",
            attack_payload={"data": "<xxe>...</xxe>"},
            shape="xml",
            headers={"X-Bench": "1"},
        )

    baseline_call = mock_capture.call_args_list[0]
    assert "data" in baseline_call.kwargs
    headers = baseline_call.kwargs.get("headers") or {}
    assert headers.get("Content-Type") == "application/xml"
    # User-supplied header X-Bench should also be preserved in merge
    assert headers.get("X-Bench") == "1"


# ---------------------------------------------------------------------------
# Regression: existing fire_and_diff signature still works without shape
# ---------------------------------------------------------------------------

def test_fire_and_diff_backwards_compat_no_shape_kwarg():
    """Calls that pre-date iter-30.5 (no shape= kwarg) still work."""
    with patch("strix.l15.baseline_diff._capture") as mock_capture:
        mock_capture.return_value = {
            "status": 200, "size": 100, "time_ms": 10,
            "body": "ok", "body_hash": "h1", "location": "",
        }
        # No `shape=` — should behave as iter-29.2 did
        signal = fire_and_diff(
            url="http://app/test?q=x", method="GET",
            attack_payload={},
        )
        # Returns a DiffSignal (no crash)
        assert signal is not None
