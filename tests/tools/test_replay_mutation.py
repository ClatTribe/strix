"""Tests for §workitem.md Phase 5.5 — replay-with-mutation orchestrator.

Pins:
  * Per-param specialist routing — SQLi/XSS run on every param;
    SSRF only runs on URL-shaped params; IDOR only on URLs with
    numeric/UUID segments
  * Aggregate result shape — endpoints_replayed, specialists_invoked,
    findings_count, per_specialist breakdown
  * Bounded fan-out (max_endpoints)
  * Empty inputs → graceful results
  * Specialist failure → error counter, no abort
  * `families` filter narrows the matrix
  * Lead catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.replay_mutation.replay_mutation import (
    _has_id_segment,
    _params_match_lexicon,
    _SPECIALIST_PARAM_LEXICON,
    replay_mutation_on_endpoints,
)


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-replay"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_has_id_segment_numeric() -> None:
    assert _has_id_segment("http://example.com/api/users/42")


def test_has_id_segment_uuid() -> None:
    assert _has_id_segment(
        "http://example.com/api/orders/"
        "550e8400-e29b-41d4-a716-446655440000"
    )


def test_has_id_segment_negative() -> None:
    assert not _has_id_segment("http://example.com/api/products")


def test_params_match_lexicon_with_lexicon() -> None:
    matched = _params_match_lexicon(
        ["url", "id", "page"],
        {"url", "target", "host"},
    )
    assert matched == ["url"]


def test_params_match_lexicon_none_returns_all() -> None:
    matched = _params_match_lexicon(["a", "b"], None)
    assert matched == ["a", "b"]


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_invalid_endpoints_returns_error() -> None:
    out = replay_mutation_on_endpoints(endpoints="not a list")  # type: ignore[arg-type]
    assert out["status"] == "error"


def test_empty_endpoints_returns_zero_counts(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = replay_mutation_on_endpoints(endpoints=[])
    assert out["status"] == "ok"
    assert out["endpoints_replayed"] == 0
    assert out["specialists_invoked"] == 0
    assert out["findings_count"] == 0


# ---------------------------------------------------------------------------
# Mutation matrix dispatch
# ---------------------------------------------------------------------------


def test_dispatch_all_param_bound_specialists_for_generic_endpoint(
    monkeypatch,
) -> None:
    """An endpoint with a generic `q` param should run scan_xss,
    scan_sqli, and the various injection specialists. SSRF should
    NOT fire (no URL-shaped param)."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok no payload echoed", "headers": {},
    })
    endpoints = [{
        "method": "GET",
        "url": "http://example.com/search?q=test",
        "params": ["q"],
    }]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints,
        # Subset to just the families that should match `q`.
        families=["scan_sqli", "scan_xss", "scan_ssrf"],
    )
    # SQLi + XSS were called (lexicon=None means any param), but SSRF
    # was skipped (q isn't in SSRF lexicon).
    per = out["per_specialist"]
    assert per["scan_sqli"]["calls"] == 1
    assert per["scan_xss"]["calls"] == 1
    assert per["scan_ssrf"]["calls"] == 0


def test_dispatch_url_shaped_param_triggers_ssrf(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok no payload echoed", "headers": {},
    })
    endpoints = [{
        "method": "GET",
        "url": "http://example.com/proxy?url=https://example.org",
        "params": ["url"],
    }]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints, families=["scan_ssrf"],
    )
    assert out["per_specialist"]["scan_ssrf"]["calls"] == 1


def test_idor_only_runs_on_id_shaped_url(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": "no", "headers": {},
    })
    # Plant user-a + user-b sessions so scan_idor's preconditions pass.
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="user-a", bearer="a_tok")
    record_auth_state(label="user-b", bearer="b_tok")

    endpoints = [
        {
            "method": "GET",
            "url": "http://example.com/api/users/42",
            "params": [],
        },
        {
            "method": "GET",
            "url": "http://example.com/api/products",
            "params": [],
        },
    ]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints, families=["scan_idor"],
    )
    # Only the user/42 URL has an ID segment.
    assert out["per_specialist"]["scan_idor"]["calls"] == 1


def test_secrets_in_response_runs_per_endpoint(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": '{"hello":"world"}', "headers": {},
    })
    endpoints = [
        {"method": "GET", "url": "http://example.com/api/a", "params": []},
        {"method": "GET", "url": "http://example.com/api/b", "params": []},
    ]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints, families=["scan_secrets_in_response"],
    )
    # One call per endpoint (URL-bound, not param-bound).
    assert out["per_specialist"]["scan_secrets_in_response"]["calls"] == 2


# ---------------------------------------------------------------------------
# Findings aggregation + hit counting
# ---------------------------------------------------------------------------


def test_hits_counted_when_specialist_returns_findings(monkeypatch) -> None:
    """Mock SQLi to return a finding when probed; replay should
    record a hit + aggregate the finding."""
    def fake_resp(method, url, headers, body, timeout):
        # SQLi payloads contain `'` or `OR`. Trigger a SQL-error-shaped response.
        if any(t in url for t in ("'", "%27", "OR+", "OR%20")):
            return {
                "status_code": 500,
                "body": "SQL error: You have an error in your SQL syntax",
                "headers": {},
            }
        return {"status_code": 200, "body": "ok no payload", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    endpoints = [{
        "method": "GET",
        "url": "http://example.com/items?id=1",
        "params": ["id"],
    }]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints, families=["scan_sqli"],
    )
    assert out["per_specialist"]["scan_sqli"]["hits"] >= 1
    assert out["findings_count"] >= 1


def test_misses_counted_when_specialist_returns_nothing(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok no payload", "headers": {},
    })
    endpoints = [{
        "method": "GET",
        "url": "http://example.com/search?q=hello",
        "params": ["q"],
    }]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints, families=["scan_xss"],
    )
    assert out["per_specialist"]["scan_xss"]["misses"] == 1
    assert out["per_specialist"]["scan_xss"]["hits"] == 0


# ---------------------------------------------------------------------------
# max_endpoints cap
# ---------------------------------------------------------------------------


def test_max_endpoints_caps_fanout(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    endpoints = [
        {"method": "GET",
         "url": f"http://example.com/api/items?id={i}",
         "params": ["id"]}
        for i in range(50)
    ]
    out = replay_mutation_on_endpoints(
        endpoints=endpoints,
        families=["scan_sqli"],
        max_endpoints=5,
    )
    assert out["endpoints_replayed"] == 5
    assert out["per_specialist"]["scan_sqli"]["calls"] == 5


# ---------------------------------------------------------------------------
# Specialist failures
# ---------------------------------------------------------------------------


def test_unknown_family_recorded_as_error(monkeypatch) -> None:
    """Requesting a nonexistent specialist family — the orchestrator
    routes the call but the registry returns 'not registered', which
    is counted as an error rather than aborting."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    # Note: this test only triggers the error path when the family is
    # in `_SPECIALIST_PARAM_LEXICON` but not actually registered.
    # We add a fake entry to the lexicon for this test.
    monkeypatch.setitem(
        _SPECIALIST_PARAM_LEXICON, "scan_nonexistent", None,
    )
    out = replay_mutation_on_endpoints(
        endpoints=[{"url": "http://x/?q=1", "params": ["q"]}],
        families=["scan_nonexistent"],
    )
    assert out["per_specialist"]["scan_nonexistent"]["errors"] == 1


# ---------------------------------------------------------------------------
# Lead catalog wiring
# ---------------------------------------------------------------------------


def test_replay_mutation_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "replay_mutation_on_endpoints" in catalog
    assert "replay_mutation_from_har_file" in catalog
    assert "replay_mutation_from_burp_file" in catalog
