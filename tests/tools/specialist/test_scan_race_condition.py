"""Tests for masterroadmap §1 — `scan_race_condition` (TOCTOU
parallel-fire detector).

Pins:
  * Baseline + parallel-fire two-phase shape
  * Single-success → no finding
  * Multi-success > expected_max → high-severity finding
  * 5x-over → high; 2x-over → medium
  * Explicit success_status_codes allow-list
  * success_field JSON extraction
  * Concurrency / timeout / cooldown caps
  * URL / method validation
  * Baseline failure short-circuits cleanly"""

from __future__ import annotations

import pytest

from strix.tools.specialist.scan_race_condition import (
    _Response,
    _default_http,
    _extract_field,
    _is_success,
    scan_race_condition,
)


# ---------------------------------------------------------------------------
# Tracer isolation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    set_global_tracer(Tracer("test-race"))
    yield


# ---------------------------------------------------------------------------
# _is_success
# ---------------------------------------------------------------------------


def test_explicit_success_codes_wins() -> None:
    """When success_status_codes is given, it's the only check."""
    r = _Response(status=201, body="", elapsed=0.01)
    assert _is_success(
        r, success_status_codes=(200, 201), baseline_status=200,
    )
    assert not _is_success(
        r, success_status_codes=(200,), baseline_status=200,
    )


def test_baseline_match_classifies_2xx_3xx() -> None:
    """No explicit allow-list → matches baseline status + 2xx/3xx."""
    base = 200
    assert _is_success(
        _Response(status=200, body="", elapsed=0.01),
        success_status_codes=None, baseline_status=base,
    )
    # 4xx is never success.
    assert not _is_success(
        _Response(status=400, body="", elapsed=0.01),
        success_status_codes=None, baseline_status=base,
    )


def test_error_or_no_status_is_not_success() -> None:
    assert not _is_success(
        _Response(status=None, body="", elapsed=0, error="timeout"),
        success_status_codes=None, baseline_status=200,
    )
    assert not _is_success(
        _Response(status=None, body="", elapsed=0),
        success_status_codes=(200,), baseline_status=200,
    )


# ---------------------------------------------------------------------------
# _extract_field (dotted-path JSON walker)
# ---------------------------------------------------------------------------


def test_extract_field_walks_nested_keys() -> None:
    body = '{"data": {"balance": 100}}'
    assert _extract_field(body, "data.balance") == 100


def test_extract_field_missing_returns_none() -> None:
    body = '{"data": {}}'
    assert _extract_field(body, "data.missing") is None


def test_extract_field_invalid_json_returns_none() -> None:
    assert _extract_field("not json", "x") is None


def test_extract_field_empty_inputs_safe() -> None:
    assert _extract_field("", "x") is None
    assert _extract_field('{"x": 1}', "") is None


# ---------------------------------------------------------------------------
# Parallel-fire dispatch — race detected
# ---------------------------------------------------------------------------


def _stub_http_factory(responses_per_call):
    """Build a fake HTTP that returns one queued response per call,
    cycling through a list."""
    counter = {"n": 0}

    def _fake(method, url, *, headers, body, timeout):
        idx = counter["n"]
        counter["n"] += 1
        if idx < len(responses_per_call):
            return responses_per_call[idx]
        # Cycle if we run out.
        return responses_per_call[-1]

    return _fake


def test_all_concurrent_succeed_emits_finding(monkeypatch) -> None:
    """20 parallel responses all return 200 → race condition
    detected; finding emitted; status=ok."""
    ok = _Response(status=200, body='{"ok": true}', elapsed=0.01)
    fake_http = _stub_http_factory([ok] * 100)  # baseline + 20 parallel

    result = scan_race_condition(
        url="https://example.com/api/redeem",
        body='{"code": "PROMO50"}',
        concurrency=20,
        expected_max_successes=1,
        cooldown_seconds=0,
        _http=fake_http,
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["total_successes"] == 20
    assert result["tool_metadata"]["findings_emitted"] == 1
    assert any(
        "race" in (e or "").lower()
        for e in (result.get("evidence") or [])
    )


def test_single_success_does_not_emit(monkeypatch) -> None:
    """When only the baseline succeeds (the parallel fire all hit
    a rate-limit / 409), no finding emitted."""
    success_then_conflict = [
        _Response(status=200, body="{}", elapsed=0.01),  # baseline
    ] + [
        _Response(status=409, body="conflict", elapsed=0.01)
        for _ in range(50)  # parallel batch
    ]
    fake_http = _stub_http_factory(success_then_conflict)

    result = scan_race_condition(
        url="https://example.com/api/redeem",
        body='{}', concurrency=20, expected_max_successes=1,
        cooldown_seconds=0, _http=fake_http,
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["findings_emitted"] == 0


def test_severity_high_when_5x_over(monkeypatch) -> None:
    """5+ successes when expected_max=1 → high severity (>= 5x cap)."""
    ok = _Response(status=200, body="{}", elapsed=0.01)
    fake_http = _stub_http_factory([ok] * 30)

    result = scan_race_condition(
        url="https://example.com/api/redeem",
        body="{}", concurrency=10, expected_max_successes=1,
        cooldown_seconds=0, _http=fake_http,
    )
    # 10 successes >= 1 * 5 → high
    assert result["tool_metadata"]["total_successes"] == 10
    # Severity reflected in the FindingDraft.
    findings = result.get("findings") or []
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_severity_medium_when_just_over(monkeypatch) -> None:
    """2 successes when expected_max=1 → medium severity."""
    # First 2 parallel succeed; remaining 8 fail. Total = 2 successes
    # in the parallel phase → 2 > 1 = race, but 2 < 5*1 = medium.
    responses = [
        _Response(status=200, body="{}", elapsed=0.01),  # baseline
        _Response(status=200, body="{}", elapsed=0.01),
        _Response(status=200, body="{}", elapsed=0.01),
    ] + [
        _Response(status=429, body="", elapsed=0.01)
        for _ in range(20)
    ]
    fake_http = _stub_http_factory(responses)

    result = scan_race_condition(
        url="https://example.com/api/redeem",
        body="{}", concurrency=10, expected_max_successes=1,
        cooldown_seconds=0, _http=fake_http,
    )
    assert result["tool_metadata"]["total_successes"] == 2
    findings = result.get("findings") or []
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# success_field extraction
# ---------------------------------------------------------------------------


def test_success_field_captured_in_metadata(monkeypatch) -> None:
    """When `success_field` is set, the field value is extracted
    from each response + surfaced in tool_metadata."""
    responses = [
        _Response(
            status=200,
            body=f'{{"balance": {n}}}',
            elapsed=0.01,
        )
        for n in range(25)
    ]
    fake_http = _stub_http_factory(responses)

    result = scan_race_condition(
        url="https://example.com/api/withdraw",
        body='{"amount": 100}',
        concurrency=10, expected_max_successes=1,
        success_field="balance",
        cooldown_seconds=0, _http=fake_http,
    )
    assert result["status"] == "ok"
    meta = result["tool_metadata"]
    assert meta["success_field"] == "balance"
    # baseline value extracted independently.
    assert meta["baseline_field_value"] == 0
    # Sample of field values from successful parallel responses.
    assert isinstance(meta["field_values_sample"], list)
    assert len(meta["field_values_sample"]) > 0


# ---------------------------------------------------------------------------
# Explicit success_status_codes
# ---------------------------------------------------------------------------


def test_explicit_success_codes_overrides_baseline(monkeypatch) -> None:
    """Operator passes success_status_codes=[201,202]; baseline
    returns 200 → baseline succeeds (still classified) only when
    its status is in the list. The 201 parallel responses all
    count as successful."""
    responses = [
        _Response(status=200, body="{}", elapsed=0.01),  # baseline
    ] + [
        _Response(status=201, body="{}", elapsed=0.01)
        for _ in range(20)
    ]
    fake_http = _stub_http_factory(responses)

    result = scan_race_condition(
        url="https://example.com/api/create",
        body="{}", concurrency=10, expected_max_successes=1,
        success_status_codes=[201, 202],
        cooldown_seconds=0, _http=fake_http,
    )
    # Only the 201s count; baseline 200 is NOT in the allow-list
    # but the baseline-failure check only triggers on `error`.
    # Result: 10 of 10 parallel succeed → finding.
    assert result["tool_metadata"]["total_successes"] == 10
    assert result["tool_metadata"]["findings_emitted"] == 1


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_empty_url_errors() -> None:
    result = scan_race_condition(url="")
    assert result["status"] == "error"
    assert "url required" in result["error"].lower()


def test_invalid_url_errors() -> None:
    result = scan_race_condition(url="not-a-url")
    assert result["status"] == "error"


def test_unsupported_method_errors() -> None:
    result = scan_race_condition(
        url="https://x/", method="TRACE",
    )
    assert result["status"] == "error"
    assert "unsupported method" in result["error"].lower()


# ---------------------------------------------------------------------------
# Concurrency / timeout caps
# ---------------------------------------------------------------------------


def test_concurrency_capped_at_max(monkeypatch) -> None:
    """concurrency=200 is clamped to 50."""
    ok = _Response(status=200, body="{}", elapsed=0.01)
    fake_http = _stub_http_factory([ok] * 100)

    result = scan_race_condition(
        url="https://example.com/api/x", body="{}",
        concurrency=200,  # overrides hard cap
        expected_max_successes=1,
        cooldown_seconds=0, _http=fake_http,
    )
    assert result["tool_metadata"]["concurrency"] == 50


def test_concurrency_minimum_floored_at_two(monkeypatch) -> None:
    """concurrency=0 → clamped to 2 (you can't 'race' with 1)."""
    ok = _Response(status=200, body="{}", elapsed=0.01)
    fake_http = _stub_http_factory([ok] * 5)

    result = scan_race_condition(
        url="https://example.com/api/x", body="{}",
        concurrency=0,
        expected_max_successes=1,
        cooldown_seconds=0, _http=fake_http,
    )
    assert result["tool_metadata"]["concurrency"] == 2


# ---------------------------------------------------------------------------
# Baseline failure
# ---------------------------------------------------------------------------


def test_baseline_failure_short_circuits(monkeypatch) -> None:
    """Baseline error → return status=error immediately without
    firing the parallel batch."""
    calls = {"n": 0}

    def _fake(method, url, *, headers, body, timeout):
        calls["n"] += 1
        return _Response(
            status=None, body="", elapsed=0.0, error="conn refused",
        )

    result = scan_race_condition(
        url="https://example.com/api/x",
        body="{}", concurrency=10, cooldown_seconds=0,
        _http=_fake,
    )
    assert result["status"] == "error"
    assert "baseline request failed" in result["error"].lower()
    # ONE call total — the parallel batch never ran.
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


def test_specialist_registered() -> None:
    """The specialist must be discoverable through the registry."""
    from strix.tools.specialist.registry import list_specialist_tools
    assert "scan_race_condition" in list_specialist_tools()
