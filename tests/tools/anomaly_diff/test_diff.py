"""Unit tests for `strix.tools.anomaly_diff.diff`."""

from __future__ import annotations

import pytest

from strix.baselines.capture import EndpointBaseline
from strix.tools.anomaly_diff.diff import (
    CLASS_ERROR_STRING_PRESENT,
    CLASS_HEADER_SET_CHANGE,
    CLASS_LATENCY_OUTLIER,
    CLASS_LENGTH_OUTLIER,
    CLASS_NEW_KEYS_IN_JSON,
    CLASS_STATUS_FLIP,
    diff_against_baseline,
)


def _baseline(
    *, status: dict[int, int] | None = None,
    p50_lat: float = 100.0, p99_lat: float = 200.0,
    p50_body: int = 512, p99_body: int = 1024,
    ct: str = "application/json",
    keys: list[str] | None = None,
) -> EndpointBaseline:
    return EndpointBaseline(
        endpoint="GET /x",
        samples=5,
        status_distribution=status or {200: 5},
        latency_p50_ms=p50_lat, latency_p99_ms=p99_lat,
        body_length_p50=p50_body, body_length_p99=p99_body,
        content_type=ct,
        response_keys=keys or ["id", "name"],
        captured_at="2026-05-10T00:00:00Z",
    )


def _resp(
    status: int = 200, body: str = '{"id":1,"name":"x"}',
    ct: str = "application/json",
    lat: float = 100.0,
) -> dict:
    return {
        "status": status, "body": body,
        "headers": {"Content-Type": ct},
        "latency_ms": lat,
    }


# ---------------------------------------------------------------------------
# status_flip
# ---------------------------------------------------------------------------


def test_status_flip_fires_on_unseen_status() -> None:
    b = _baseline(status={200: 5})
    v = diff_against_baseline(_resp(status=500), b)
    assert CLASS_STATUS_FLIP in v.classes
    assert v.severity == "high"


def test_status_flip_does_not_fire_on_seen_status() -> None:
    b = _baseline(status={200: 5})
    v = diff_against_baseline(_resp(status=200), b)
    assert CLASS_STATUS_FLIP not in v.classes


def test_status_flip_does_not_fire_when_in_distribution() -> None:
    """Even if a status is rare in the distribution, if it was
    seen at least once we don't flag it."""
    b = _baseline(status={200: 4, 401: 1})
    v = diff_against_baseline(_resp(status=401), b)
    assert CLASS_STATUS_FLIP not in v.classes


# ---------------------------------------------------------------------------
# length_outlier
# ---------------------------------------------------------------------------


def test_length_outlier_fires_for_huge_body() -> None:
    b = _baseline(p50_body=512, p99_body=1024)
    v = diff_against_baseline(_resp(body="x" * 10000), b)
    assert CLASS_LENGTH_OUTLIER in v.classes


def test_length_outlier_fires_for_tiny_body() -> None:
    """A body 0.3× p50 fires too — could be a stripped error
    response or a truncated payload."""
    b = _baseline(p50_body=512, p99_body=1024)
    v = diff_against_baseline(_resp(body="x" * 50), b)
    assert CLASS_LENGTH_OUTLIER in v.classes


def test_length_outlier_does_not_fire_within_range() -> None:
    b = _baseline(p50_body=512, p99_body=1024)
    v = diff_against_baseline(_resp(body="x" * 700), b)
    assert CLASS_LENGTH_OUTLIER not in v.classes


# ---------------------------------------------------------------------------
# latency_outlier_3sigma
# ---------------------------------------------------------------------------


def test_latency_outlier_fires_above_3x_p99() -> None:
    b = _baseline(p99_lat=100.0)
    v = diff_against_baseline(_resp(lat=500.0), b)
    assert CLASS_LATENCY_OUTLIER in v.classes


def test_latency_outlier_does_not_fire_within_threshold() -> None:
    b = _baseline(p99_lat=100.0)
    v = diff_against_baseline(_resp(lat=200.0), b)
    assert CLASS_LATENCY_OUTLIER not in v.classes


# ---------------------------------------------------------------------------
# new_keys_in_json
# ---------------------------------------------------------------------------


def test_new_keys_in_json_fires_for_added_key() -> None:
    b = _baseline(keys=["id", "name"])
    v = diff_against_baseline(
        _resp(body='{"id":1,"name":"x","secret_token":"abc"}'), b,
    )
    assert CLASS_NEW_KEYS_IN_JSON in v.classes
    assert "secret_token" in v.metadata.get("new_keys", [])


def test_new_keys_in_json_doesnt_fire_when_subset() -> None:
    """A response with fewer keys is NOT new-keys; that's
    schema removal, not addition."""
    b = _baseline(keys=["id", "name", "email"])
    v = diff_against_baseline(_resp(body='{"id":1}'), b)
    assert CLASS_NEW_KEYS_IN_JSON not in v.classes


def test_new_keys_in_json_doesnt_fire_for_non_json() -> None:
    """If the baseline + probe are both HTML, we skip the JSON
    keys check entirely."""
    b = _baseline(ct="text/html", keys=[])
    v = diff_against_baseline(
        _resp(body="<html>x</html>", ct="text/html"), b,
    )
    assert CLASS_NEW_KEYS_IN_JSON not in v.classes


# ---------------------------------------------------------------------------
# error_string_present
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error_body", [
    "syntax error at or near WHERE",
    "unexpected token",
    "SQLSTATE[42P01]",
    "ORA-00942: table or view does not exist",
    "PG::SyntaxError",
    "Traceback (most recent call last):\n  File \"app.py\"",
    "java.lang.NullPointerException at com.example",
    "Stack trace:\n#0 /app/Controller.php",
    "<title>Internal Server Error</title>",
])
def test_error_string_present_fires_on_known_pattern(error_body: str) -> None:
    b = _baseline()
    v = diff_against_baseline(_resp(body=error_body), b)
    assert CLASS_ERROR_STRING_PRESENT in v.classes
    assert v.severity == "high"


def test_error_string_does_not_fire_on_generic_word_error() -> None:
    """Generic 'error' alone is not a signal — would FP every
    `{"error": "validation failed"}` API response."""
    b = _baseline()
    v = diff_against_baseline(
        _resp(body='{"error": "validation failed"}'), b,
    )
    assert CLASS_ERROR_STRING_PRESENT not in v.classes


# ---------------------------------------------------------------------------
# header_set_change
# ---------------------------------------------------------------------------


def test_header_set_change_fires_on_content_type_swap() -> None:
    b = _baseline(ct="application/json")
    v = diff_against_baseline(
        _resp(body="<html>x</html>", ct="text/html"), b,
    )
    assert CLASS_HEADER_SET_CHANGE in v.classes


def test_header_set_change_does_not_fire_for_same_type() -> None:
    b = _baseline(ct="application/json")
    v = diff_against_baseline(_resp(ct="application/json"), b)
    assert CLASS_HEADER_SET_CHANGE not in v.classes


# ---------------------------------------------------------------------------
# Aggregate severity
# ---------------------------------------------------------------------------


def test_aggregate_severity_picks_max() -> None:
    """status_flip (high) + header_set_change (low) → high."""
    b = _baseline(status={200: 5}, ct="application/json")
    v = diff_against_baseline(
        _resp(status=500, body="<html>x</html>", ct="text/html"), b,
    )
    assert v.severity == "high"


def test_no_baseline_samples_produces_empty_verdict() -> None:
    """A baseline with samples=0 means we have no 'normal' to
    diff against. Diff returns empty — better than false-
    positiving every probe."""
    b = _baseline()
    b.samples = 0
    v = diff_against_baseline(_resp(status=999), b)
    assert v.classes == []


def test_empty_response_dict_doesnt_crash() -> None:
    """Defensive — caller passing nothing useful shouldn't crash.
    May produce findings (empty body IS divergent from a baseline
    with non-zero p50), but the crucial guarantee is no exception."""
    b = _baseline()
    v = diff_against_baseline({}, b)  # must not raise
    assert isinstance(v.classes, list)
    assert isinstance(v.severity, str)


def test_non_dict_response_returns_empty_verdict() -> None:
    """A non-dict response (None, str, list) returns empty
    classes — the diff layer rejects unparseable input."""
    b = _baseline()
    assert diff_against_baseline(None, b).classes == []  # type: ignore[arg-type]
    assert diff_against_baseline("not a dict", b).classes == []  # type: ignore[arg-type]
