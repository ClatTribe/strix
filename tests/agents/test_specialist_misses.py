"""Tests for §workitem.md Phase 5.3 — counter-example logging.

Pins:
  * Caught finding + prior miss on same endpoint → counter-example logged
  * Different tool than the catcher (no self-reporting)
  * relation_kind = "shared_param" when params overlap
  * relation_kind = "same_endpoint" when params don't overlap
  * No prior miss → nothing logged
  * Persistence to <run_dir>/specialist_misses.jsonl
  * Endpoint normalization (query string stripped — same path = same endpoint)
  * Filters (missed_by_tool, endpoint_substring)
  * Best-effort: malformed input doesn't raise
  * Registry hook fires on real specialist invocation chain
"""

from __future__ import annotations

import json

import pytest

from strix.agents.specialist_misses import (
    SpecialistMiss,
    list_misses,
    record_caught_finding,
    reset_misses,
)
from strix.agents.specialist_telemetry import (
    record_specialist_call,
    reset_telemetry,
)


@pytest.fixture(autouse=True)
def _reset_buffers() -> None:
    reset_telemetry()
    reset_misses()
    yield
    reset_telemetry()
    reset_misses()


# ---------------------------------------------------------------------------
# Same-endpoint detection
# ---------------------------------------------------------------------------


def test_caught_finding_with_prior_miss_logs_counter_example() -> None:
    """scan_xss missed the endpoint; scan_sqli caught a finding there
    later → counter-example logged."""
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/api/items?id=1",
        params=["id"],
        result={"status": "ok", "findings": []},
    )
    miss_ids = record_caught_finding(
        endpoint="http://example.com/api/items?id=1",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={
            "title": "SQL injection in `id`",
            "severity": "high",
            "cwe": "CWE-89",
            "category": "sqli",
        },
        caught_params=["id"],
    )
    assert len(miss_ids) == 1
    misses = list_misses()
    assert len(misses) == 1
    m = misses[0]
    assert m.missed_by_tool == "scan_xss"
    assert m.caught_by_tool == "scan_sqli"
    assert m.caught_finding["cwe"] == "CWE-89"


def test_no_prior_miss_no_counter_example_logged() -> None:
    """Caught a finding but nothing missed before → empty result."""
    miss_ids = record_caught_finding(
        endpoint="http://example.com/api/items",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
    )
    assert miss_ids == []
    assert list_misses() == []


def test_self_reporting_excluded() -> None:
    """A specialist's own prior miss on the SAME tool doesn't count
    as a counter-example — only OTHER tools' misses do."""
    record_specialist_call(
        tool_name="scan_sqli",
        category="sqli-specialist",
        target="http://example.com/api/items",
        params=["id"],
        result={"status": "ok", "findings": []},
    )
    record_caught_finding(
        endpoint="http://example.com/api/items",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
        caught_params=["id"],
    )
    # No counter-example — same tool, same target.
    assert list_misses() == []


# ---------------------------------------------------------------------------
# relation_kind discrimination
# ---------------------------------------------------------------------------


def test_relation_shared_param_when_params_overlap() -> None:
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/api/items",
        params=["q", "id"],
        result={"status": "ok", "findings": []},
    )
    record_caught_finding(
        endpoint="http://example.com/api/items",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
        caught_params=["id"],  # overlaps with `id` from miss
    )
    misses = list_misses()
    assert misses[0].relation_kind == "shared_param"


def test_relation_same_endpoint_when_params_disjoint() -> None:
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/api/items",
        params=["q"],
        result={"status": "ok", "findings": []},
    )
    record_caught_finding(
        endpoint="http://example.com/api/items",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
        caught_params=["id"],
    )
    misses = list_misses()
    assert misses[0].relation_kind == "same_endpoint"


# ---------------------------------------------------------------------------
# Endpoint normalization
# ---------------------------------------------------------------------------


def test_query_string_stripped_for_endpoint_match() -> None:
    """Two URLs with identical paths but different query strings
    map to the same endpoint."""
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/api/items?id=1&page=2",
        params=["id"],
        result={"status": "ok", "findings": []},
    )
    record_caught_finding(
        endpoint="http://example.com/api/items?id=99",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
        caught_params=["id"],
    )
    misses = list_misses()
    assert len(misses) == 1
    assert misses[0].endpoint == "http://example.com/api/items"


def test_different_path_no_match() -> None:
    record_specialist_call(
        tool_name="scan_xss",
        category="xss-specialist",
        target="http://example.com/api/users",
        result={"status": "ok", "findings": []},
    )
    record_caught_finding(
        endpoint="http://example.com/api/products",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
    )
    assert list_misses() == []


# ---------------------------------------------------------------------------
# Multi-miss aggregation
# ---------------------------------------------------------------------------


def test_multiple_prior_misses_yield_multiple_counter_examples() -> None:
    """Three different tools missed the endpoint; one tool then
    caught a finding → three counter-examples logged."""
    for tool in ("scan_xss", "scan_path_traversal", "scan_ssti"):
        record_specialist_call(
            tool_name=tool, category=tool + "-specialist",
            target="http://example.com/api/items",
            params=["id"],
            result={"status": "ok", "findings": []},
        )
    miss_ids = record_caught_finding(
        endpoint="http://example.com/api/items",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "x"},
        caught_params=["id"],
    )
    assert len(miss_ids) == 3
    missed_tools = {m.missed_by_tool for m in list_misses()}
    assert missed_tools == {"scan_xss", "scan_path_traversal", "scan_ssti"}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persist_to_run_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    record_specialist_call(
        tool_name="scan_xss", category="xss-specialist",
        target="http://example.com/x",
        result={"status": "ok", "findings": []},
    )
    record_caught_finding(
        endpoint="http://example.com/x",
        caught_by_tool="scan_sqli",
        caught_by_category="sqli-specialist",
        caught_finding={"title": "Test", "cwe": "CWE-89"},
    )
    log_path = tmp_path / "specialist_misses.jsonl"
    assert log_path.exists()
    line = log_path.read_text().splitlines()[0]
    parsed = json.loads(line)
    assert parsed["missed_by_tool"] == "scan_xss"
    assert parsed["caught_by_tool"] == "scan_sqli"


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_filter_by_missed_by_tool() -> None:
    record_specialist_call(
        tool_name="scan_xss", category="x", target="http://a/",
        result={"status": "ok"},
    )
    record_specialist_call(
        tool_name="scan_path_traversal", category="x", target="http://a/",
        result={"status": "ok"},
    )
    record_caught_finding(
        endpoint="http://a/", caught_by_tool="scan_sqli",
        caught_by_category="x", caught_finding={"title": "x"},
    )
    filtered = list_misses(missed_by_tool="scan_xss")
    assert len(filtered) == 1


def test_filter_by_endpoint_substring() -> None:
    record_specialist_call(
        tool_name="scan_xss", category="x",
        target="http://example.com/api/items",
        result={"status": "ok"},
    )
    record_specialist_call(
        tool_name="scan_xss", category="x",
        target="http://other.test/api/users",
        result={"status": "ok"},
    )
    record_caught_finding(
        endpoint="http://example.com/api/items",
        caught_by_tool="scan_sqli", caught_by_category="x",
        caught_finding={"title": "x"},
    )
    record_caught_finding(
        endpoint="http://other.test/api/users",
        caught_by_tool="scan_sqli", caught_by_category="x",
        caught_finding={"title": "y"},
    )
    filtered = list_misses(endpoint_substring="example.com")
    assert len(filtered) == 1


# ---------------------------------------------------------------------------
# Best-effort robustness
# ---------------------------------------------------------------------------


def test_record_with_invalid_endpoint_does_not_raise() -> None:
    miss_ids = record_caught_finding(
        endpoint=None,  # type: ignore[arg-type]
        caught_by_tool="scan_sqli",
        caught_by_category="x",
        caught_finding={"title": "x"},
    )
    assert miss_ids == []


def test_record_with_no_caught_params_still_works() -> None:
    """When caller doesn't pass caught_params, relation_kind defaults
    to same_endpoint."""
    record_specialist_call(
        tool_name="scan_xss", category="x", target="http://a/",
        params=["id"],
        result={"status": "ok"},
    )
    record_caught_finding(
        endpoint="http://a/",
        caught_by_tool="scan_sqli", caught_by_category="x",
        caught_finding={"title": "x"},
        caught_params=None,
    )
    misses = list_misses()
    assert len(misses) == 1
    assert misses[0].relation_kind == "same_endpoint"


# ---------------------------------------------------------------------------
# Registry hook integration
# ---------------------------------------------------------------------------


def test_registry_hook_logs_counter_example_end_to_end(monkeypatch) -> None:
    """When scan_xss runs and misses, then scan_sqli runs and catches
    a finding at the same endpoint, the registry hook should
    automatically log a counter-example."""
    from unittest.mock import MagicMock

    # Fake proxy that returns either a clean response (for xss) or
    # a SQL-error fingerprint (for sqli) based on the URL.
    sqli_error_body = (
        "Server error: SQLException: You have an error in your SQL "
        "syntax near 'OR 1=1'"
    )

    def fake_resp(method, url, headers, body, timeout):
        # scan_sqli's payloads include `'`, OR clauses, etc.
        if any(t in url for t in ("'", "%27", "OR+", "OR%20")):
            return {
                "status_code": 500,
                "body": sqli_error_body,
                "headers": {},
            }
        return {"status_code": 200, "body": "no payload echoed", "headers": {}}

    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=fake_resp)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )

    # Ensure tracer is non-None so emit_finding works.
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test"))

    reset_telemetry()
    reset_misses()

    # 1. scan_xss runs + misses on the endpoint.
    from strix.tools.specialist.scan_xss import scan_xss
    scan_xss(url="http://example.com/api/items?id=1", param="id")

    # 2. scan_sqli runs + catches a finding on the same endpoint.
    from strix.tools.specialist.scan_sqli import scan_sqli
    scan_sqli(url="http://example.com/api/items?id=1", param="id")

    misses = list_misses()
    # Counter-example present: scan_xss missed, scan_sqli caught.
    assert any(
        m.missed_by_tool == "scan_xss" and m.caught_by_tool == "scan_sqli"
        for m in misses
    )
