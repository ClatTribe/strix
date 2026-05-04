"""Tests for race_condition_check (roadmap §7.2 important).

Hermetic — `_http_request_sync` and `_run_race_round` are
monkeypatched. Tests cover:

- URL validation
- Baseline failure → inconclusive
- Endpoint correctly serialises (round 1 ≤ tolerated) → no finding
- Round 1 race + Round 2 reproduces → high finding
- Round 1 race + Round 2 doesn't reproduce → no finding (zero-FP)
- Custom tolerated_success_count
- Cluster-A `--exclude-path` skip
- §11 UX
- verification_status="verified" (zero-FP via N+1)
- Result schema
- MITRE T1190
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.race_check.race_check  # noqa: F401

rc_module = sys.modules["strix.tools.race_check.race_check"]
race_condition_check = rc_module.race_condition_check


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
    tracer = Tracer("race-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _patch_http_sync(monkeypatch, responder):
    def fake(method, url, *, headers=None, body="", timeout=10.0):
        return responder(method, url, headers, body)

    monkeypatch.setattr(rc_module, "_http_request_sync", fake)


def _patch_race_round(monkeypatch, round_results: list[list[dict[str, Any]]]):
    """Replace `_run_race_round` to return pre-canned per-round results.
    `round_results[i]` is the list returned for round i+1."""
    state = {"i": 0}

    def fake(method, url, *, headers, body, n, timeout):
        i = state["i"]
        state["i"] += 1
        if i < len(round_results):
            return round_results[i]
        return [{"status": 0, "body_length": 0, "error": "no canned"}] * n

    monkeypatch.setattr(rc_module, "_run_race_round", fake)


def _resp(*, status: int = 200, body: str = "OK", skipped: bool = False) -> dict[str, Any]:
    if skipped:
        return {"status": 0, "headers": {}, "body": "", "skipped": True}
    return {"status": status, "headers": {}, "body": body}


def _findings():
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert race_condition_check("")["success"] is False
    assert race_condition_check("ftp://x")["success"] is False


# ---------------------------------------------------------------------------
# Baseline / skip cases
# ---------------------------------------------------------------------------


def test_baseline_failure_inconclusive(monkeypatch) -> None:
    """Baseline returns 403 → can't measure race → inconclusive."""
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=403))
    out = race_condition_check(
        target_url="https://app.example.com/redeem",
    )
    assert out["inconclusive"] is True
    assert out["findings_emitted"] == 0


def test_excluded_path_no_op(monkeypatch) -> None:
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(skipped=True))
    out = race_condition_check(
        target_url="https://app.example.com/redeem",
    )
    assert out["inconclusive"] is True


# ---------------------------------------------------------------------------
# Endpoint correctly serialises → no finding
# ---------------------------------------------------------------------------


def test_serialised_endpoint_no_finding(monkeypatch) -> None:
    """Round 1: only 1 of 30 concurrent requests succeeds → endpoint
    correctly serialises → no finding."""
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200, body="OK 12345"))

    # 1 success, 29 failures (409 conflict).
    round1 = (
        [{"status": 200, "body_length": 8, "error": None}]
        + [{"status": 409, "body_length": 20, "error": None}] * 29
    )
    _patch_race_round(monkeypatch, [round1])

    out = race_condition_check(
        target_url="https://app.example.com/redeem", concurrency=30,
    )
    assert out["race_confirmed"] is False
    assert out["findings_emitted"] == 0
    # Round 2 not run (round 1 already showed safe behaviour).
    assert len(out["rounds"]) == 1


# ---------------------------------------------------------------------------
# Real race: both rounds confirm
# ---------------------------------------------------------------------------


def test_race_confirmed_both_rounds_high(monkeypatch) -> None:
    """Round 1: 7/30 succeed. Round 2: 8/30 succeed. → race confirmed."""
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200, body="OK 12345"))

    round1 = (
        [{"status": 200, "body_length": 8, "error": None}] * 7
        + [{"status": 409, "body_length": 20, "error": None}] * 23
    )
    round2 = (
        [{"status": 200, "body_length": 8, "error": None}] * 8
        + [{"status": 409, "body_length": 20, "error": None}] * 22
    )
    _patch_race_round(monkeypatch, [round1, round2])

    out = race_condition_check(
        target_url="https://app.example.com/redeem", concurrency=30,
    )
    assert out["race_confirmed"] is True
    assert out["findings_emitted"] == 1
    findings = _findings()
    assert findings[0]["severity"] == "high"
    assert findings[0]["category"] == "race_condition"
    assert findings[0]["cwe"] == "CWE-362"


# ---------------------------------------------------------------------------
# Round 1 race but Round 2 doesn't reproduce → no finding (zero-FP)
# ---------------------------------------------------------------------------


def test_round1_race_round2_serialises_no_finding(monkeypatch) -> None:
    """Round 1: 5/30 succeed (looks like a race). Round 2: only 1
    succeeds → flaky, not a real race → NO FINDING.

    This is the canonical zero-FP test: serial-but-fast endpoints
    can show race-shaped behaviour on a single round; the N+1
    verification weeds them out."""
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200, body="OK 12345"))

    round1 = (
        [{"status": 200, "body_length": 8, "error": None}] * 5
        + [{"status": 409, "body_length": 20, "error": None}] * 25
    )
    round2 = (
        [{"status": 200, "body_length": 8, "error": None}]
        + [{"status": 409, "body_length": 20, "error": None}] * 29
    )
    _patch_race_round(monkeypatch, [round1, round2])

    out = race_condition_check(
        target_url="https://app.example.com/redeem", concurrency=30,
    )
    assert out["race_confirmed"] is False
    assert out["findings_emitted"] == 0
    assert len(out["rounds"]) == 2  # round 2 was attempted


# ---------------------------------------------------------------------------
# tolerated_success_count
# ---------------------------------------------------------------------------


def test_tolerated_success_count_2(monkeypatch) -> None:
    """tolerated=2 means up to 2 concurrent successes is OK
    (e.g. add-comment endpoints). 3 successes → race."""
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200, body="OK"))

    # Round 1: 2 successes (within tolerance) → no race.
    round1 = (
        [{"status": 200, "body_length": 2, "error": None}] * 2
        + [{"status": 409, "body_length": 5, "error": None}] * 28
    )
    _patch_race_round(monkeypatch, [round1])

    out = race_condition_check(
        target_url="https://app.example.com/comment",
        tolerated_success_count=2, concurrency=30,
    )
    assert out["race_confirmed"] is False
    # Round 2 not run (round 1 within tolerance).
    assert len(out["rounds"]) == 1


def test_tolerated_success_count_2_violation(monkeypatch) -> None:
    """tolerated=2; round 1: 5 successes; round 2: 4 successes →
    race confirmed."""
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200, body="OK"))

    round1 = (
        [{"status": 200, "body_length": 2, "error": None}] * 5
        + [{"status": 409, "body_length": 5, "error": None}] * 25
    )
    round2 = (
        [{"status": 200, "body_length": 2, "error": None}] * 4
        + [{"status": 409, "body_length": 5, "error": None}] * 26
    )
    _patch_race_round(monkeypatch, [round1, round2])

    out = race_condition_check(
        target_url="https://app.example.com/comment",
        tolerated_success_count=2, concurrency=30,
    )
    assert out["race_confirmed"] is True


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_ux_fields(monkeypatch) -> None:
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200, body="OK"))

    n = 10
    full_round = [{"status": 200, "body_length": 2, "error": None}] * n
    _patch_race_round(monkeypatch, [full_round, full_round])

    race_condition_check(
        target_url="https://app.example.com/redeem", concurrency=n,
    )
    findings = _findings()
    assert findings
    f = findings[0]
    assert f.get("description_plain")
    assert f.get("recommended_action")
    # Zero-FP: N+1 verification → verified.
    assert f.get("verification_status") == "verified"


# ---------------------------------------------------------------------------
# Strix nonce on probe
# ---------------------------------------------------------------------------


def test_strix_nonce_in_probe_headers(monkeypatch) -> None:
    captured_headers: list[dict[str, str]] = []

    def race_responder(method, url, *, headers, body, n, timeout):
        captured_headers.append(dict(headers))
        return [{"status": 200, "body_length": 2, "error": None}] * n

    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200))
    monkeypatch.setattr(rc_module, "_run_race_round", race_responder)

    race_condition_check(
        target_url="https://app.example.com/redeem", concurrency=10,
    )
    assert captured_headers
    h = captured_headers[0]
    assert "X-Strix-Race-Nonce" in h
    assert len(h["X-Strix-Race-Nonce"]) == 8  # 4-byte hex


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_http_sync(monkeypatch, lambda m, u, h, b: _resp(status=200))
    _patch_race_round(monkeypatch, [
        [{"status": 200, "body_length": 2, "error": None}],
    ])
    out = race_condition_check(
        target_url="https://app.example.com/redeem", concurrency=2,
    )
    assert set(out.keys()) >= {
        "success", "target_url", "target_host", "method",
        "baseline", "rounds", "tolerated_success_count",
        "race_confirmed", "findings_emitted",
    }


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("race_condition_check")
    assert "T1190" in techniques


# ---------------------------------------------------------------------------
# _count_successes helper
# ---------------------------------------------------------------------------


def test_count_successes_exact_status_class_and_length() -> None:
    base = {"status_class": "2xx", "body_length": 100}
    results = [
        {"status": 200, "body_length": 100, "error": None},
        {"status": 200, "body_length": 90, "error": None},   # within ±25%
        {"status": 200, "body_length": 50, "error": None},   # outside ±25%
        {"status": 409, "body_length": 100, "error": None},  # 4xx
        {"status": 0, "body_length": 0, "error": "timeout"},  # error
    ]
    assert rc_module._count_successes(results, base) == 2


def test_count_successes_zero_baseline_length() -> None:
    """Baseline body_length=0 → length comparison skipped, status-class is sufficient."""
    base = {"status_class": "2xx", "body_length": 0}
    results = [
        {"status": 200, "body_length": 50, "error": None},
        {"status": 200, "body_length": 1000, "error": None},
        {"status": 409, "body_length": 0, "error": None},
    ]
    assert rc_module._count_successes(results, base) == 2
