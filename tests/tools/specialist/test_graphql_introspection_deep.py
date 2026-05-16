"""Tests for `graphql_introspection_deep`."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.tools.specialist.graphql_introspection_deep import (
    _build_alias_dos_query,
    _extract_mutations,
    _extract_query_root_field,
    _parse_introspection,
    graphql_introspection_deep,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_GRAPHQL_DEEP_DISABLED", raising=False)


_SAMPLE_SCHEMA: dict[str, Any] = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {
            "name": "Query", "kind": "OBJECT",
            "fields": [
                {"name": "__typename", "args": []},
                {"name": "users", "args": []},
                {"name": "user", "args": [{"name": "id"}]},
            ],
        },
        {
            "name": "Mutation", "kind": "OBJECT",
            "fields": [
                {"name": "createUser", "args": []},
                {"name": "deleteUser", "args": []},
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_build_alias_dos_query() -> None:
    out = _build_alias_dos_query("__typename", alias_count=3)
    assert "a0: __typename" in out
    assert "a1: __typename" in out
    assert "a2: __typename" in out
    # Aliased into a single query block.
    assert out.startswith("{")
    assert out.rstrip().endswith("}")


def test_parse_introspection_valid() -> None:
    body = json.dumps({"data": {"__schema": _SAMPLE_SCHEMA}})
    out = _parse_introspection(body)
    assert out is not None
    assert out["queryType"]["name"] == "Query"


def test_parse_introspection_malformed() -> None:
    assert _parse_introspection("not json") is None
    assert _parse_introspection(
        json.dumps({"data": {}})
    ) is None


def test_extract_query_root_field_prefers_typename() -> None:
    field = _extract_query_root_field(_SAMPLE_SCHEMA)
    assert field == "__typename"


def test_extract_query_root_field_falls_back_to_argless() -> None:
    schema = {
        "queryType": {"name": "Q"},
        "types": [{
            "name": "Q",
            "fields": [
                {"name": "needs_args", "args": [{"name": "x"}]},
                {"name": "free", "args": []},
            ],
        }],
    }
    assert _extract_query_root_field(schema) == "free"


def test_extract_mutations() -> None:
    out = _extract_mutations(_SAMPLE_SCHEMA)
    assert out == ["createUser", "deleteUser"]


def test_extract_mutations_none_when_no_mutation_type() -> None:
    schema = {"queryType": {"name": "Q"}, "types": []}
    assert _extract_mutations(schema) == []


# ---------------------------------------------------------------------------
# End-to-end detection
# ---------------------------------------------------------------------------


def _make_fetcher(
    *, intro_body: str | None = None,
    intro_latency_ms: float = 80.0,
    alias_status: int = 200,
    alias_latency_ms: float = 80.0,
    deep_status: int = 200,
    deep_latency_ms: float = 80.0,
    mutation_response: dict | None = None,
):
    """Build a fetcher closure that returns different responses
    based on the query body."""
    intro_body = intro_body or json.dumps(
        {"data": {"__schema": _SAMPLE_SCHEMA}}
    )

    def fetcher(*, url, headers, json_body, timeout):
        query = (json_body or {}).get("query", "")
        if "__schema" in query and "ofType" not in query:
            return 200, intro_body, intro_latency_ms
        if "a0:" in query:  # alias-DoS probe
            return alias_status, '{"data":{"a0":"X"}}', alias_latency_ms
        if "ofType" in query:  # deep-nested probe
            return deep_status, '{"data":{"__schema":{}}}', deep_latency_ms
        if "mutation" in query:
            body = json.dumps(mutation_response or {"data": {"createUser": "ok"}})
            return 200, body, 50.0
        return 200, "{}", 50.0

    return fetcher


def test_introspection_disabled_returns_no_findings() -> None:
    fetcher = _make_fetcher(intro_body='{"errors": ["disabled"]}')
    result = graphql_introspection_deep(
        endpoint="https://api/graphql", _fetcher=fetcher,
    )
    assert result["findings"] == []


def test_introspection_enabled_emits_finding() -> None:
    fetcher = _make_fetcher()
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
        # Disable all secondary probes to isolate introspection finding.
        probe_alias_dos=False, probe_deep_nesting=False,
        probe_mutation_auth=False,
        _fetcher=fetcher,
    )
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["category"] == "graphql_introspection"
    assert f["severity"] == "medium"


def test_alias_dos_detected_on_high_latency() -> None:
    """Alias-DoS finding fires when the aliased query is much
    slower than the baseline introspection."""
    fetcher = _make_fetcher(
        intro_latency_ms=50.0,
        alias_status=200, alias_latency_ms=2000.0,   # 40x slower
    )
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
        probe_alias_dos=True, probe_deep_nesting=False,
        probe_mutation_auth=False,
        _fetcher=fetcher,
    )
    alias_findings = [
        f for f in result["findings"]
        if f["category"] == "graphql_alias_dos"
    ]
    assert len(alias_findings) == 1
    assert alias_findings[0]["severity"] == "high"


def test_alias_dos_not_detected_on_fast_response() -> None:
    """If aliases are handled fast, no DoS finding."""
    fetcher = _make_fetcher(
        intro_latency_ms=80.0,
        alias_status=200, alias_latency_ms=85.0,   # essentially same
    )
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
        probe_alias_dos=True, probe_deep_nesting=False,
        probe_mutation_auth=False,
        _fetcher=fetcher,
    )
    alias_findings = [
        f for f in result["findings"]
        if f["category"] == "graphql_alias_dos"
    ]
    assert alias_findings == []


def test_deep_nesting_detected() -> None:
    fetcher = _make_fetcher(
        intro_latency_ms=50.0,
        deep_status=200, deep_latency_ms=1500.0,
    )
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
        probe_alias_dos=False, probe_deep_nesting=True,
        probe_mutation_auth=False,
        _fetcher=fetcher,
    )
    deep_findings = [
        f for f in result["findings"]
        if f["category"] == "graphql_depth_dos"
    ]
    assert len(deep_findings) == 1


def test_unauth_mutation_detected() -> None:
    """When a mutation responds with `{data: ...}` (no `errors`
    key) anonymously, flag it."""
    fetcher = _make_fetcher(
        mutation_response={"data": {"createUser": "ok"}},  # no errors
    )
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
        probe_alias_dos=False, probe_deep_nesting=False,
        probe_mutation_auth=True,
        _fetcher=fetcher,
    )
    unauth_findings = [
        f for f in result["findings"]
        if f["category"] == "graphql_unauth_mutation"
    ]
    # 2 mutations × no-error → 2 findings
    assert len(unauth_findings) == 2


def test_mutation_with_errors_no_finding() -> None:
    """Mutations that return an `errors` key (validation /
    auth-rejection) are properly gated."""
    fetcher = _make_fetcher(
        mutation_response={"errors": [{"message": "unauthorized"}]},
    )
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
        probe_alias_dos=False, probe_deep_nesting=False,
        probe_mutation_auth=True,
        _fetcher=fetcher,
    )
    unauth_findings = [
        f for f in result["findings"]
        if f["category"] == "graphql_unauth_mutation"
    ]
    assert unauth_findings == []


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_GRAPHQL_DEEP_DISABLED", "1")
    result = graphql_introspection_deep(
        endpoint="https://api/graphql",
    )
    assert result["status"] == "error"
    assert "kill_switch" in result["error"]


def test_empty_endpoint_rejected() -> None:
    result = graphql_introspection_deep(endpoint="")
    assert result["status"] == "error"
