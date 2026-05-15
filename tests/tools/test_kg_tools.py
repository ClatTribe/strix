"""Tests for the §3 knowledge-graph CRUD tools.

The underlying graph is exhaustively tested in
`tests/agents/test_knowledge_graph.py`. This file pins the tool
surface: JSON parsing, type validation, return shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import knowledge_graph as kg
from strix.tools.workflow import kg_tools


@pytest.fixture(autouse=True)
def _reset_kg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kg.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


def test_create_node_with_props() -> None:
    result = kg_tools.kg_create_node(
        type="Surface",
        props_json='{"url": "/login", "method": "POST"}',
    )
    assert result["success"] is True
    assert result["node"]["id"] == "N-001"
    assert result["node"]["props"]["url"] == "/login"


def test_create_node_invalid_type_returns_error() -> None:
    result = kg_tools.kg_create_node(type="MagicBox")
    assert result["success"] is False
    assert "invalid node type" in result["error"]


def test_create_node_malformed_json_returns_error() -> None:
    result = kg_tools.kg_create_node(type="Surface", props_json="not-json")
    assert result["success"] is False
    assert "JSON" in result["error"]


def test_create_node_non_object_json_returns_error() -> None:
    result = kg_tools.kg_create_node(type="Surface", props_json="[1, 2]")
    assert result["success"] is False


def test_create_edge_happy_path() -> None:
    a = kg_tools.kg_create_node(type="Vuln")
    b = kg_tools.kg_create_node(type="Surface")
    result = kg_tools.kg_create_edge(
        type="AFFECTS",
        source=a["node"]["id"],
        target=b["node"]["id"],
        props_json='{"confidence": 0.9}',
    )
    assert result["success"] is True
    assert result["edge"]["id"] == "E-001"
    assert result["edge"]["props"]["confidence"] == 0.9


def test_create_edge_unknown_source_returns_error() -> None:
    n = kg_tools.kg_create_node(type="Surface")
    result = kg_tools.kg_create_edge(
        type="AFFECTS",
        source="N-999",
        target=n["node"]["id"],
    )
    assert result["success"] is False
    assert "source node" in result["error"]


def test_query_nodes_by_type() -> None:
    kg_tools.kg_create_node(type="Surface")
    kg_tools.kg_create_node(type="Vuln")
    result = kg_tools.kg_query_nodes(type="Surface")
    assert result["total"] == 1
    assert result["nodes"][0]["type"] == "Surface"


def test_query_nodes_with_filter() -> None:
    kg_tools.kg_create_node(type="Surface", props_json='{"url": "/a"}')
    kg_tools.kg_create_node(type="Surface", props_json='{"url": "/b"}')
    result = kg_tools.kg_query_nodes(
        type="Surface", filters_json='{"url": "/a"}',
    )
    assert result["total"] == 1


def test_query_nodes_malformed_filter_returns_error() -> None:
    result = kg_tools.kg_query_nodes(filters_json="not-json")
    assert result["success"] is False


def test_query_paths_direct_chain() -> None:
    a = kg_tools.kg_create_node(type="Vuln")
    b = kg_tools.kg_create_node(type="Vuln")
    kg_tools.kg_create_edge(
        type="CHAINS_TO",
        source=a["node"]["id"],
        target=b["node"]["id"],
    )
    result = kg_tools.kg_query_paths(
        start_id=a["node"]["id"],
        end_id=b["node"]["id"],
    )
    assert result["total"] == 1
    assert result["paths"][0] == [a["node"]["id"], b["node"]["id"]]


def test_query_paths_with_edge_type_filter() -> None:
    a = kg_tools.kg_create_node(type="Vuln")
    b = kg_tools.kg_create_node(type="Surface")
    kg_tools.kg_create_edge(
        type="AFFECTS", source=a["node"]["id"], target=b["node"]["id"],
    )
    # AFFECTS allowed
    affects_result = kg_tools.kg_query_paths(
        start_id=a["node"]["id"], end_id=b["node"]["id"],
        edge_types="AFFECTS",
    )
    assert affects_result["total"] == 1
    # LEAKS only — no path
    leaks_result = kg_tools.kg_query_paths(
        start_id=a["node"]["id"], end_id=b["node"]["id"],
        edge_types="LEAKS",
    )
    assert leaks_result["total"] == 0


def test_kg_stats_returns_breakdown() -> None:
    kg_tools.kg_create_node(type="Surface")
    kg_tools.kg_create_node(type="Surface")
    kg_tools.kg_create_node(type="Vuln")
    result = kg_tools.kg_stats()
    assert result["enabled"] is True
    assert result["node_count"] == 3
    assert result["node_types"]["Surface"] == 2
