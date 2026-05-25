"""Tests for iter-29.2 — baseline-and-diff verifier."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from strix.l15.baseline_diff import (
    DEFAULT_SIZE_DELTA_PCT,
    DEFAULT_TIME_DELTA_ABS_MS,
    DEFAULT_TIME_DELTA_MULT,
    ERROR_TOKEN_TO_VULN_CLASS,
    DiffSignal,
    diff_responses,
    fire_and_diff,
    score_signal,
)


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_error_tokens_are_documented_backend_strings():
    """ERROR_TOKEN_TO_VULN_CLASS entries must be documented backend
    error fragments, not SUT-specific output."""
    must_have_drivers = ("SQLSTATE", "ORA-", "Traceback (most recent call last)")
    for token in must_have_drivers:
        assert token in ERROR_TOKEN_TO_VULN_CLASS


def test_source_has_no_fixture_specific_strings():
    """Anti-overfit: verifier source must not name any fixture."""
    src = Path(__file__).resolve().parents[2] / "strix" / "l15" / "baseline_diff.py"
    text = src.read_text().lower()
    forbidden = ("juice-shop", "juiceshop", "vampi", "crapi",
                 "nodegoat", "webgoat", "vibe-app", "nginx-vuln")
    for f in forbidden:
        assert f not in text


# ---------------------------------------------------------------------------
# Signal: new error token
# ---------------------------------------------------------------------------

def test_new_error_token_in_payload_response_scores_high():
    baseline = {"status": 200, "size": 1000, "time_ms": 50,
                "body": "<html>welcome</html>", "location": ""}
    payload = {"status": 200, "size": 1100, "time_ms": 60,
               "body": "<html>SQLSTATE[42000]: Syntax error</html>", "location": ""}
    sig = diff_responses(baseline, payload)
    assert "sqli" in sig.new_error_classes
    assert "SQLSTATE" in sig.new_error_tokens
    assert sig.score >= 0.5


def test_existing_error_token_in_baseline_does_not_trip():
    """Token present in BOTH baseline and payload = no new signal."""
    baseline = {"status": 200, "size": 1000, "time_ms": 50,
                "body": "<html>SQLSTATE[42000] tutorial page</html>",
                "location": ""}
    payload = {"status": 200, "size": 1000, "time_ms": 50,
               "body": "<html>SQLSTATE[42000] tutorial page (payload)</html>",
               "location": ""}
    sig = diff_responses(baseline, payload)
    assert sig.new_error_tokens == []
    assert sig.new_error_classes == []


# ---------------------------------------------------------------------------
# iter-30.4 — success-leak token detection
# ---------------------------------------------------------------------------

def test_success_token_etc_passwd_leak_scores_as_path_traversal():
    """When /etc/passwd content appears in payload response, that's
    path-traversal success — should score 0.5."""
    baseline = {"status": 200, "size": 500, "time_ms": 30,
                "body": "<html>not found</html>", "location": ""}
    payload = {"status": 200, "size": 800, "time_ms": 30,
               "body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
               "location": ""}
    from strix.l15.baseline_diff import diff_responses
    sig = diff_responses(baseline, payload)
    assert "path-traversal" in sig.new_success_classes
    assert sig.score >= 0.5


def test_success_token_jwt_in_response_scores_as_sqli():
    """When baseline response has no auth token but payload response
    DOES, that's SQLi-login auth bypass success."""
    baseline = {"status": 401, "size": 50, "time_ms": 30,
                "body": '{"error":"invalid"}', "location": ""}
    payload = {"status": 200, "size": 800, "time_ms": 30,
               "body": '{"access_token":"eyJhbGciOi.eyJzdWIi.sig","user_id":1}',
               "location": ""}
    from strix.l15.baseline_diff import diff_responses
    sig = diff_responses(baseline, payload)
    assert "sqli" in sig.new_success_classes
    assert sig.score >= 0.5


def test_success_token_cmd_injection_uid_output():
    """`uid=0(root)` in payload body indicates command-injection success."""
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 600, "time_ms": 30,
               "body": "ok\nuid=0(root) gid=0(root) groups=0(root)",
               "location": ""}
    from strix.l15.baseline_diff import diff_responses
    sig = diff_responses(baseline, payload)
    assert "cmd-injection" in sig.new_success_classes


def test_success_token_ssrf_imds_response():
    """AWS IMDS response markers indicate SSRF success."""
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 2000, "time_ms": 30,
               "body": '{"ami-id":"ami-1234","instance-id":"i-abc"}',
               "location": ""}
    from strix.l15.baseline_diff import diff_responses
    sig = diff_responses(baseline, payload)
    assert "ssrf" in sig.new_success_classes


def test_success_token_existing_in_baseline_does_not_trip():
    """Token in both → not a new signal."""
    baseline = {"status": 200, "size": 500, "time_ms": 30,
                "body": '{"access_token":"abc"} — login already present', "location": ""}
    payload = {"status": 200, "size": 600, "time_ms": 30,
               "body": '{"access_token":"abc"} — login already present',
               "location": ""}
    from strix.l15.baseline_diff import diff_responses
    sig = diff_responses(baseline, payload)
    assert sig.new_success_classes == []


def test_traceback_token_classifies_as_code_exec():
    baseline = {"status": 200, "size": 500, "time_ms": 30,
                "body": "<html>ok</html>", "location": ""}
    payload = {"status": 500, "size": 800, "time_ms": 30,
               "body": "Traceback (most recent call last):\n  File ...\n",
               "location": ""}
    sig = diff_responses(baseline, payload)
    assert "code-exec" in sig.new_error_classes


def test_spring_whitelabel_error_classifies_as_code_exec():
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 500, "size": 1200, "time_ms": 30,
               "body": "<title>Whitelabel Error Page</title>", "location": ""}
    sig = diff_responses(baseline, payload)
    assert "code-exec" in sig.new_error_classes


# ---------------------------------------------------------------------------
# Signal: status class change
# ---------------------------------------------------------------------------

def test_status_class_change_2xx_to_5xx_scores():
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 500, "size": 1000, "time_ms": 30, "body": "err", "location": ""}
    sig = diff_responses(baseline, payload)
    assert sig.status_class_changed is True
    assert sig.score >= 0.3


def test_same_status_class_does_not_trip():
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 201, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    sig = diff_responses(baseline, payload)
    assert sig.status_class_changed is False


# ---------------------------------------------------------------------------
# Signal: time-based (blind injection)
# ---------------------------------------------------------------------------

def test_time_based_signal_requires_both_thresholds():
    """3× ratio alone isn't enough; must ALSO be ≥2s absolute, to
    avoid 10ms→50ms false positives."""
    # 50ms → 150ms — 3× ratio but only +100ms abs → SHOULD NOT trip time signal
    baseline = {"status": 200, "size": 500, "time_ms": 50, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 500, "time_ms": 150, "body": "ok", "location": ""}
    sig = diff_responses(baseline, payload)
    # neither ratio (3x is ON the threshold) and time delta (100ms < 2s) — no time-based score
    assert "time-based signal" not in " ".join(sig.reasons)


def test_time_based_signal_legit_5s_delay():
    """Classic time-based SQLi: SLEEP(5) — both thresholds cleared."""
    baseline = {"status": 200, "size": 500, "time_ms": 50, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 500, "time_ms": 5050, "body": "ok", "location": ""}
    sig = diff_responses(baseline, payload)
    assert any("time-based" in r for r in sig.reasons)
    assert sig.score >= 0.3


# ---------------------------------------------------------------------------
# Signal: body-size delta
# ---------------------------------------------------------------------------

def test_size_delta_past_threshold_scores():
    baseline = {"status": 200, "size": 1000, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 1500, "time_ms": 30, "body": "ok2", "location": ""}
    sig = diff_responses(baseline, payload)
    assert sig.size_delta_pct == 0.5
    assert sig.score >= 0.2


def test_size_delta_under_threshold_does_not_trip():
    baseline = {"status": 200, "size": 1000, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 1100, "time_ms": 30, "body": "ok2", "location": ""}
    sig = diff_responses(baseline, payload)
    # 10% delta — under threshold; should not trip size signal alone
    # (body_hash_changed still trips at 0.1; check size NOT in reasons)
    assert not any("body size delta" in r for r in sig.reasons)


# ---------------------------------------------------------------------------
# Signal: redirect target change
# ---------------------------------------------------------------------------

def test_redirect_target_change_scores():
    baseline = {"status": 302, "size": 0, "time_ms": 30,
                "body": "", "location": "/dashboard"}
    payload = {"status": 302, "size": 0, "time_ms": 30,
               "body": "", "location": "http://evil.com/"}
    sig = diff_responses(baseline, payload)
    assert sig.redirect_target_changed is True
    assert sig.score >= 0.2


# ---------------------------------------------------------------------------
# Signal: combined / cap
# ---------------------------------------------------------------------------

def test_score_caps_at_1():
    """All signals firing should still cap at 1.0."""
    baseline = {"status": 200, "size": 500, "time_ms": 50, "body": "ok", "location": "/a"}
    payload = {"status": 500, "size": 5000, "time_ms": 6000,
               "body": "SQLSTATE error trace", "location": "/b"}
    sig = diff_responses(baseline, payload)
    assert sig.score == 1.0


def test_no_signal_returns_zero_score():
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    sig = diff_responses(baseline, payload)
    assert sig.score == 0.0
    assert sig.reasons == []


def test_body_hash_only_change_low_score():
    """Body content changed but size identical → subtle echo signal,
    score only 0.1."""
    baseline = {"status": 200, "size": 100, "time_ms": 30, "body": "x" * 100,
                "body_hash": "h1", "location": ""}
    payload = {"status": 200, "size": 100, "time_ms": 30, "body": "y" * 100,
               "body_hash": "h2", "location": ""}
    sig = diff_responses(baseline, payload)
    assert sig.score == 0.1


# ---------------------------------------------------------------------------
# DiffSignal serialization
# ---------------------------------------------------------------------------

def test_to_dict_json_serializable():
    import json
    baseline = {"status": 200, "size": 500, "time_ms": 30, "body": "ok", "location": ""}
    payload = {"status": 500, "size": 1000, "time_ms": 30,
               "body": "SQLSTATE error", "location": ""}
    sig = diff_responses(baseline, payload)
    d = sig.to_dict()
    json.dumps(d)
    assert d["score"] >= 0.5


# ---------------------------------------------------------------------------
# fire_and_diff end-to-end
# ---------------------------------------------------------------------------

@patch("strix.l15.baseline_diff.requests.request")
def test_fire_and_diff_baseline_no_body(mock_req):
    """control_payload=None → baseline fired with no body."""
    def _mk(status, body, time_ms=30):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.content = body.encode()
        r.headers = {}
        return r
    mock_req.side_effect = [_mk(200, "ok"), _mk(200, "SQLSTATE err")]

    sig = fire_and_diff(
        "http://app/x",
        attack_payload={"json": {"q": "' OR 1=1--"}},
    )
    assert "sqli" in sig.new_error_classes


@patch("strix.l15.baseline_diff.requests.request")
def test_fire_and_diff_handles_request_failure(mock_req):
    """When the request raises, we get a synthetic capture so the
    diff machinery doesn't crash."""
    mock_req.side_effect = requests.ConnectionError("refused")
    sig = fire_and_diff(
        "http://app/x", attack_payload={"json": {"q": "x"}},
    )
    # Both calls failed — no signal
    assert sig.score == 0.0


# ---------------------------------------------------------------------------
# score_signal idempotency
# ---------------------------------------------------------------------------

def test_score_signal_idempotent():
    """Calling score_signal twice on the same signal must not double-score."""
    sig = DiffSignal(
        status_class_changed=True, status_delta=300,
        size_delta_pct=0.5,
    )
    score_signal(sig)
    s1 = sig.score
    score_signal(sig)
    assert sig.score == s1
