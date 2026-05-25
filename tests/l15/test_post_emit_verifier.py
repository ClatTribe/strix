"""Tests for iter-32.4 — post-emission verifier."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from strix.l15 import post_emit_verifier
from strix.l15.post_emit_verifier import (
    _CATEGORY_TO_VULN_CLASS,
    _UPGRADEABLE_STATUSES,
    _build_attack_kwargs,
    _build_attack_url,
    is_enabled,
    try_post_emit_verify,
)


# ---------------------------------------------------------------------------
# is_enabled — env-gate
# ---------------------------------------------------------------------------

def test_is_enabled_default_off():
    """No env var → disabled. Safe default."""
    os.environ.pop("STRIX_L15_POST_EMIT_VERIFY", None)
    assert is_enabled() is False


def test_is_enabled_when_env_set_to_truthy():
    for v in ("1", "true", "TRUE", "yes", "on", "On"):
        os.environ["STRIX_L15_POST_EMIT_VERIFY"] = v
        assert is_enabled() is True, f"failed for {v!r}"
    os.environ.pop("STRIX_L15_POST_EMIT_VERIFY", None)


def test_is_enabled_when_env_set_to_falsy():
    for v in ("0", "false", "no", "off", ""):
        os.environ["STRIX_L15_POST_EMIT_VERIFY"] = v
        assert is_enabled() is False, f"failed for {v!r}"
    os.environ.pop("STRIX_L15_POST_EMIT_VERIFY", None)


# ---------------------------------------------------------------------------
# try_post_emit_verify — gating
# ---------------------------------------------------------------------------

def test_skips_when_verification_status_not_upgradeable():
    """Already-verified findings shouldn't be re-probed."""
    report = {
        "verification_status": "verified",
        "endpoint": "http://app/api/x",
        "category": "sqli",
    }
    assert try_post_emit_verify(report) is False
    assert report["verification_status"] == "verified"


def test_skips_when_no_endpoint():
    """Code-target findings (file but no endpoint) can't be probed."""
    report = {
        "verification_status": "pattern_match",
        "file": "app.py", "line": 22,
        "category": "sqli",
    }
    assert try_post_emit_verify(report) is False


def test_skips_when_endpoint_not_http():
    """Targets like `repo://x` or relative paths aren't probable."""
    for bad_endpoint in ("/api/x", "file:///etc/passwd", "ssh://x", "repo://r"):
        report = {
            "verification_status": "pattern_match",
            "endpoint": bad_endpoint,
            "category": "sqli",
        }
        assert try_post_emit_verify(report) is False


def test_skips_when_category_not_in_known_set():
    """Unsupported categories pass through unchanged."""
    report = {
        "verification_status": "pattern_match",
        "endpoint": "http://app/x",
        "category": "cache_deception",  # not in _CATEGORY_TO_VULN_CLASS
    }
    assert try_post_emit_verify(report) is False


def test_skips_when_no_payload_found(monkeypatch):
    """If payload_bins returns empty for the (shape, vuln_class) tuple,
    nothing to probe with."""
    monkeypatch.setattr(post_emit_verifier, "_pick_attack_payload", lambda *a, **k: None)
    report = {
        "verification_status": "pattern_match",
        "endpoint": "http://app/api/x",
        "category": "sqli",
    }
    assert try_post_emit_verify(report) is False


# ---------------------------------------------------------------------------
# try_post_emit_verify — happy path (mock fire_and_diff)
# ---------------------------------------------------------------------------

def test_upgrades_when_signal_above_threshold(monkeypatch):
    """When fire_and_diff returns a high-score signal, the finding's
    verification_status flips to verified."""
    monkeypatch.setattr(
        post_emit_verifier, "_classify_endpoint_shape",
        lambda *a, **k: ("json", ["q"]),
    )
    monkeypatch.setattr(
        post_emit_verifier, "_pick_attack_payload",
        lambda *a, **k: "' OR 1=1--",
    )
    fake_signal = MagicMock()
    fake_signal.score = 0.85
    with patch("strix.l15.baseline_diff.fire_and_diff", return_value=fake_signal), \
         patch("strix.l15.baseline_diff.score_signal", return_value=0.85):
        report = {
            "verification_status": "pattern_match",
            "endpoint": "http://app/api/users",
            "method": "GET",
            "category": "sqli",
        }
        upgraded = try_post_emit_verify(report)
        assert upgraded is True
        assert report["verification_status"] == "verified"
        # Auditable reasoning_trace line added
        assert any("post-emit-verify" in line for line in report["reasoning_trace"])


def test_does_not_upgrade_when_signal_below_threshold(monkeypatch):
    monkeypatch.setattr(
        post_emit_verifier, "_classify_endpoint_shape",
        lambda *a, **k: ("json", ["q"]),
    )
    monkeypatch.setattr(
        post_emit_verifier, "_pick_attack_payload",
        lambda *a, **k: "test",
    )
    fake_signal = MagicMock()
    fake_signal.score = 0.1
    with patch("strix.l15.baseline_diff.fire_and_diff", return_value=fake_signal), \
         patch("strix.l15.baseline_diff.score_signal", return_value=0.1):
        report = {
            "verification_status": "pattern_match",
            "endpoint": "http://app/api/users",
            "method": "GET",
            "category": "sqli",
        }
        upgraded = try_post_emit_verify(report)
        assert upgraded is False
        assert report["verification_status"] == "pattern_match"


def test_swallows_exceptions_returns_false(monkeypatch):
    """Verifier errors must never break the emission path."""
    def _boom(*a, **k):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(post_emit_verifier, "_classify_endpoint_shape", _boom)
    report = {
        "verification_status": "pattern_match",
        "endpoint": "http://app/x",
        "category": "sqli",
    }
    upgraded = try_post_emit_verify(report)
    assert upgraded is False


# ---------------------------------------------------------------------------
# _build_attack_kwargs / _build_attack_url
# ---------------------------------------------------------------------------

def test_build_attack_kwargs_json_post():
    out = _build_attack_kwargs("json", "POST", ["username"], "' OR 1=1--")
    assert out == {"json": {"username": "' OR 1=1--"}}


def test_build_attack_kwargs_form_post():
    out = _build_attack_kwargs("form", "POST", ["q"], "<script>")
    assert out == {"data": {"q": "<script>"}}


def test_build_attack_kwargs_json_get_has_empty_kwargs():
    """GET requests don't have a body."""
    out = _build_attack_kwargs("json", "GET", ["q"], "x")
    assert out == {}


def test_build_attack_kwargs_xml_uses_data():
    out = _build_attack_kwargs("xml", "POST", [], "<xxe/>")
    assert out == {"data": "<xxe/>"}


def test_build_attack_kwargs_graphql_wraps_in_variables():
    out = _build_attack_kwargs("graphql", "POST", [], "1' OR 1=1")
    assert "json" in out
    assert "query" in out["json"]
    assert out["json"]["variables"]["id"] == "1' OR 1=1"


def test_build_attack_url_get_appends_payload_to_query():
    out = _build_attack_url("http://app/search?q=test", "GET", ["q"], "' OR 1=1")
    assert "q=%27+OR+1%3D1" in out or "q=' OR 1=1" in out or "1=1" in out


def test_build_attack_url_post_unchanged():
    out = _build_attack_url("http://app/api/users", "POST", ["u"], "<script>")
    assert out == "http://app/api/users"


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = Path(post_emit_verifier.__file__)
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi", "erev0s", "juice-shop",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in post_emit_verifier"


def test_category_map_has_canonical_vuln_classes():
    """The mapping must only reference canonical vuln_class names that
    the iter-29.3 payload_bins module knows about."""
    from strix.l15.payload_bins import list_available_combinations
    available_vc = {vc for (_shape, vc) in list_available_combinations()}
    for category, vuln_class in _CATEGORY_TO_VULN_CLASS.items():
        assert vuln_class in available_vc, (
            f"category {category!r} maps to unknown vuln_class {vuln_class!r}"
        )


# ---------------------------------------------------------------------------
# Tracer integration — env gate respected
# ---------------------------------------------------------------------------

def test_tracer_invokes_post_emit_verifier_when_env_set(monkeypatch):
    """When STRIX_L15_POST_EMIT_VERIFY=1, tracer calls the verifier
    after L1.5 hooks. We stub the verifier to track invocation."""
    from strix.telemetry.tracer import Tracer

    called = {"count": 0}

    def _stub(report):
        called["count"] += 1
        return False  # don't upgrade

    monkeypatch.setattr(post_emit_verifier, "try_post_emit_verify", _stub)
    monkeypatch.setenv("STRIX_L15_POST_EMIT_VERIFY", "1")

    tr = Tracer(run_name="post_emit_verify_smoke")
    tr.add_vulnerability_report(
        title="t", severity="high",
        endpoint="http://app/x",
        category="sqli",
    )
    assert called["count"] >= 1


def test_tracer_does_not_invoke_when_env_unset(monkeypatch):
    """When env unset, the verifier is never called — preserves
    existing behavior + cost envelope."""
    from strix.telemetry.tracer import Tracer

    called = {"count": 0}
    def _stub(report):
        called["count"] += 1
        return False

    monkeypatch.setattr(post_emit_verifier, "try_post_emit_verify", _stub)
    monkeypatch.delenv("STRIX_L15_POST_EMIT_VERIFY", raising=False)

    tr = Tracer(run_name="post_emit_verify_off")
    tr.add_vulnerability_report(
        title="t", severity="high",
        endpoint="http://app/x",
        category="sqli",
    )
    assert called["count"] == 0
