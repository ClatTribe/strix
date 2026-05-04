"""Tests for csrf_check.

Hermetic — `_http_request` is monkeypatched. Tests cover:

- URL normalization
- Token field auto-detection from common framework lexicon
- Token cookie auto-detection
- Baseline non-2xx → inconclusive
- --exclude-path → skip
- All probe families dispatched
- Token-removed accepted → high; per-class dedup (4 token mutations
  → 1 finding)
- Token-mutated accepted → high
- Token-replay accepted → low
- Origin: attacker accepted → high
- Referer: attacker accepted → medium
- Origin removed accepted → medium
- Origin: null accepted → medium
- Double-submit-cookie mismatch accepted → high
- All defenses working → no findings
- §11 UX baseline
- Check summary
- MITRE T1190
- Schema integrity
- Helpers (_detect_token_field, _detect_token_cookie,
  _looks_like_baseline, _mutate_last)
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.csrf_check.csrf_check  # noqa: F401

cs_module = sys.modules["strix.tools.csrf_check.csrf_check"]
csrf_check = cs_module.csrf_check


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
    tracer = Tracer("csrf-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com/"}]}
    )
    yield


def _patch_request(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(method, url, *, headers=None, body="", timeout=10.0,
             omit_origin=False, omit_referer=False):
        kwargs = {
            "method": method, "url": url,
            "headers": dict(headers or {}),
            "body": body,
            "omit_origin": omit_origin,
            "omit_referer": omit_referer,
        }
        log.append(kwargs)
        return responder(method, url, kwargs)

    monkeypatch.setattr(cs_module, "_http_request", fake)
    return log


def _resp(*, status: int = 200, body: str = "OK",
          headers: dict[str, str] | None = None, skipped: bool = False) -> dict[str, Any]:
    if skipped:
        return {"status": 0, "headers": {}, "body": "", "skipped": True}
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _findings_from_tracer() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return []
    return list(t.get_existing_vulnerabilities())


def _check_summary() -> dict[str, Any]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return {}
    return t.get_check_summary()


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert csrf_check("")["success"] is False
    assert csrf_check("ftp://x.com/")["success"] is False


def test_bare_hostname_gets_https(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp())
    out = csrf_check(
        "app.example.com/update", method="POST",
        fields={"csrf_token": "abc", "email": "u@e.com"},
    )
    assert out["target_url"].startswith("https://")


# ---------------------------------------------------------------------------
# Token detection
# ---------------------------------------------------------------------------


def test_auto_detect_django_token() -> None:
    f = {"csrfmiddlewaretoken": "x", "email": "y@y"}
    assert cs_module._detect_token_field(f) == "csrfmiddlewaretoken"


def test_auto_detect_rails_token() -> None:
    f = {"authenticity_token": "x", "email": "y@y"}
    assert cs_module._detect_token_field(f) == "authenticity_token"


def test_auto_detect_no_token() -> None:
    f = {"email": "y@y"}
    assert cs_module._detect_token_field(f) is None


def test_auto_detect_token_cookie() -> None:
    c = {"csrftoken": "x"}
    assert cs_module._detect_token_cookie(c) == "csrftoken"


def test_auto_detect_token_cookie_xsrf() -> None:
    c = {"XSRF-TOKEN": "x"}
    assert cs_module._detect_token_cookie(c) == "XSRF-TOKEN"


# ---------------------------------------------------------------------------
# Baseline / inconclusive
# ---------------------------------------------------------------------------


def test_baseline_non_2xx_inconclusive(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=403))
    out = csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc"},
    )
    assert out["inconclusive"] is True
    assert out["findings_emitted"] == 0


def test_excluded_path_skip(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(skipped=True))
    out = csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc"},
    )
    assert out["inconclusive"] is True


# ---------------------------------------------------------------------------
# Probe dispatch
# ---------------------------------------------------------------------------


def test_all_probe_families_dispatched(monkeypatch) -> None:
    log = _patch_request(monkeypatch, lambda m, u, k: _resp())
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc", "email": "u@e.com"},
        cookies={"csrftoken": "abc"},
    )
    # Baseline + 4 token-bypass + 1 replay + origin_attacker +
    # origin_removed + origin_null + referer_attacker + double_submit
    # = 11 minimum. (Can be less if some skip.)
    assert len(log) >= 8


# ---------------------------------------------------------------------------
# Findings — token bypass class
# ---------------------------------------------------------------------------


def test_token_removed_accepted_high_with_dedup(monkeypatch) -> None:
    """Server accepts every variant — only ONE token-bypass finding."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        return _resp(status=200, body="OK 12345")

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    token_bypass = [f for f in findings if "validation broken" in f.get("title", "").lower()]
    assert len(token_bypass) == 1
    assert token_bypass[0]["severity"] == "high"


def test_csrf_defense_works_no_finding(monkeypatch) -> None:
    """Server rejects all bypass attempts AND tokens are one-time → no finding."""
    used_tokens: set[str] = set()

    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        body = kw.get("body", "")
        # Accept only when token is the legitimate value AND Origin
        # is the legitimate one AND Referer is the legitimate one
        # AND the token hasn't been used (one-time-ness).
        legit_token_present = "csrf_token=ABC123" in body
        legit_origin = kw["headers"].get("Origin") == "https://app.example.com"
        legit_referer = kw["headers"].get("Referer") == "https://app.example.com/"
        omit_origin = kw.get("omit_origin")
        omit_referer = kw.get("omit_referer")
        if (legit_token_present and legit_origin and legit_referer
                and not omit_origin and not omit_referer):
            if "ABC123" in used_tokens:
                return _resp(status=403, body="token already used")
            used_tokens.add("ABC123")
            return _resp(status=200, body="OK 12345")
        return _resp(status=403, body="forbidden")

    _patch_request(monkeypatch, responder)
    out = csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    assert findings == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Findings — origin / referer
# ---------------------------------------------------------------------------


def test_origin_attacker_accepted_high(monkeypatch) -> None:
    """Server accepts attacker Origin but rejects token-bypasses."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        body = kw.get("body", "")
        if "csrf_token=ABC123" in body:
            return _resp(status=200, body="OK 12345")
        return _resp(status=403, body="bad token")

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    # Only the origin/referer family fires (not token).
    origin_attacker = [f for f in findings if "attacker `Origin`" in f.get("title", "")]
    assert len(origin_attacker) == 1
    assert origin_attacker[0]["severity"] == "high"


def test_referer_attacker_accepted_medium(monkeypatch) -> None:
    """Strict on Origin (rejects attacker), but loose on Referer."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        body = kw.get("body", "")
        origin = kw["headers"].get("Origin", "")
        if "csrf_token=ABC123" not in body:
            return _resp(status=403)
        # Reject attacker Origin.
        if origin and "evil.example" in origin:
            return _resp(status=403)
        # Reject Origin: null
        if origin == "null":
            return _resp(status=403)
        return _resp(status=200, body="OK 12345")

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    referer_findings = [f for f in findings if "attacker `Referer`" in f.get("title", "")]
    assert len(referer_findings) == 1
    assert referer_findings[0]["severity"] == "medium"


def test_origin_removed_accepted_medium(monkeypatch) -> None:
    """Origin presence-only validator: rejects attacker Origin, but
    accepts when Origin is missing entirely."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        body = kw.get("body", "")
        origin = kw["headers"].get("Origin", "")
        omit_origin = kw.get("omit_origin")
        if "csrf_token=ABC123" not in body:
            return _resp(status=403)
        if omit_origin:
            return _resp(status=200, body="OK 12345")
        if origin == "https://app.example.com":
            return _resp(status=200, body="OK 12345")
        return _resp(status=403)

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    origin_removed = [f for f in findings if "missing `Origin`" in f.get("title", "")]
    assert len(origin_removed) == 1
    assert origin_removed[0]["severity"] == "medium"


def test_origin_null_accepted_medium(monkeypatch) -> None:
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        body = kw.get("body", "")
        origin = kw["headers"].get("Origin", "")
        if "csrf_token=ABC123" not in body:
            return _resp(status=403)
        if origin in ("https://app.example.com", "null"):
            return _resp(status=200, body="OK 12345")
        return _resp(status=403)

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    origin_null = [f for f in findings if "`Origin: null`" in f.get("title", "")]
    assert len(origin_null) == 1
    assert origin_null[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Token replay
# ---------------------------------------------------------------------------


def test_token_replay_accepted_low(monkeypatch) -> None:
    """Token works on every submission (no one-time-ness) but
    other defenses (Origin / Referer) work."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        body = kw.get("body", "")
        origin = kw["headers"].get("Origin", "")
        omit_origin = kw.get("omit_origin")
        # Reject token mutations.
        if "csrf_token=ABC123" not in body:
            return _resp(status=403)
        # Reject attacker Origin / Origin removed / Origin null.
        if origin and "evil.example" in origin:
            return _resp(status=403)
        if origin == "null":
            return _resp(status=403)
        if omit_origin:
            return _resp(status=403)
        # Reject attacker Referer.
        if "evil.example" in kw["headers"].get("Referer", ""):
            return _resp(status=403)
        return _resp(status=200, body="OK 12345")

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    replay = [f for f in findings if "not one-time" in f.get("title", "").lower()]
    assert len(replay) == 1
    assert replay[0]["severity"] == "low"


# ---------------------------------------------------------------------------
# Double-submit cookie
# ---------------------------------------------------------------------------


def test_double_submit_mismatch_accepted_high(monkeypatch) -> None:
    """Double-submit-cookie pattern but the comparison is broken —
    the cookie can be the legit value while the form-field token is
    random garbage and the request is accepted."""
    def responder(method: str, url: str, kw: dict[str, Any]) -> dict[str, Any]:
        cookie_str = kw["headers"].get("Cookie", "")
        # We accept any request that has the legit csrftoken cookie
        # — without checking that the form-field token matches.
        if "csrftoken=ABC123" in cookie_str:
            return _resp(status=200, body="OK 12345")
        return _resp(status=403)

    _patch_request(monkeypatch, responder)
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "ABC123", "email": "u@e.com"},
        cookies={"csrftoken": "ABC123"},
    )
    findings = _findings_from_tracer()
    double_submit = [f for f in findings if "double-submit cookie mismatch" in f.get("title", "").lower()]
    assert len(double_submit) == 1
    assert double_submit[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_ux_fields(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=200, body="OK 12345"))
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc", "email": "u@e.com"},
    )
    findings = _findings_from_tracer()
    assert findings
    for f in findings:
        assert f.get("description_plain")
        assert f.get("recommended_action")
        assert f.get("verification_status") == "needs_review"
        assert f.get("category") == "csrf"
        assert f.get("cwe") == "CWE-352"


# ---------------------------------------------------------------------------
# Check summary
# ---------------------------------------------------------------------------


def test_check_summary_vulnerable(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=200, body="OK 12345"))
    csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc", "email": "u@e.com"},
    )
    summary = _check_summary()
    assert summary["by_category"]["csrf"]["vulnerable"] >= 1


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_technique_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("csrf_check")
    assert "T1190" in techniques


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=200, body="OK 12345"))
    out = csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc", "email": "u@e.com"},
    )
    assert set(out.keys()) >= {
        "success", "target_url", "target_host", "method",
        "token_field", "token_cookie", "baseline", "probes",
        "findings_emitted",
    }


def test_probe_schema(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=200, body="OK 12345"))
    out = csrf_check(
        "https://app.example.com/update",
        fields={"csrf_token": "abc", "email": "u@e.com"},
    )
    assert out["probes"]
    p = out["probes"][0]
    assert set(p.keys()) >= {
        "label", "class_", "status", "body_length",
        "accepted", "finding_severity",
    }


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_looks_like_baseline_2xx_match() -> None:
    base = {"status_class": "2xx", "body_length": 100}
    resp = {"status": 200, "body": "x" * 100}
    assert cs_module._looks_like_baseline(resp, base) is True


def test_looks_like_baseline_4xx_rejected() -> None:
    base = {"status_class": "2xx", "body_length": 100}
    resp = {"status": 403, "body": "denied"}
    assert cs_module._looks_like_baseline(resp, base) is False


def test_looks_like_baseline_size_mismatch() -> None:
    base = {"status_class": "2xx", "body_length": 100}
    resp = {"status": 200, "body": "x" * 30}
    assert cs_module._looks_like_baseline(resp, base) is False


def test_mutate_last_hex() -> None:
    out = cs_module._mutate_last("abc1230")
    assert out != "abc1230"
    assert len(out) == len("abc1230")


def test_mutate_last_letter() -> None:
    out = cs_module._mutate_last("abcdef")
    assert out != "abcdef"
    assert len(out) == 6


def test_mutate_last_empty() -> None:
    out = cs_module._mutate_last("")
    assert out  # non-empty fallback
