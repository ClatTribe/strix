"""Tests for the §3 persistent typed knowledge graph.

Covers:
  * Type enforcement — only canonical node/edge types accepted
  * CRUD invariants (add_node, add_edge, update_node, get)
  * Query filters — type + property equality, AND-conjunction
  * Path queries — BFS, max_hops, edge-type restriction, cycle avoidance
  * neighbors() in/out/both
  * Persistence to `<run_dir>/kg.json` (atomic via .tmp)
  * Load from disk — restores adjacency lists + ID counters
  * Kill switch (STRIX_KG_DISABLED) + persistence-off
  * Telemetry snapshot
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.agents import knowledge_graph as kg


@pytest.fixture(autouse=True)
def _reset_kg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kg.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_KG_PERSIST", raising=False)


# ---------------------------------------------------------------------------
# Type enforcement
# ---------------------------------------------------------------------------


def test_unknown_node_type_rejected() -> None:
    g = kg.get_kg()
    with pytest.raises(ValueError) as exc:
        g.add_node(type="MagicBox")  # type: ignore[arg-type]
    assert "invalid node type" in str(exc.value)


def test_unknown_edge_type_rejected() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Surface")
    b = g.add_node(type="Vuln")
    with pytest.raises(ValueError):
        g.add_edge(type="POKES", source=a.id, target=b.id)  # type: ignore[arg-type]


def test_edge_to_unknown_node_rejected() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Surface")
    with pytest.raises(ValueError) as exc:
        g.add_edge(type="AFFECTS", source=a.id, target="N-999")
    assert "target node" in str(exc.value)


# ---------------------------------------------------------------------------
# CRUD invariants
# ---------------------------------------------------------------------------


def test_add_node_assigns_sequential_ids() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Surface")
    b = g.add_node(type="Vuln")
    assert a.id == "N-001"
    assert b.id == "N-002"


def test_add_edge_assigns_sequential_ids() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Surface")
    b = g.add_node(type="Vuln")
    e1 = g.add_edge(type="AFFECTS", source=b.id, target=a.id)
    assert e1.id == "E-001"


def test_update_node_merges_props() -> None:
    g = kg.get_kg()
    n = g.add_node(type="Surface", props={"url": "/login"})
    g.update_node(n.id, props={"method": "POST"})
    refetched = g.get_node(n.id)
    assert refetched is not None
    assert refetched.props == {"url": "/login", "method": "POST"}


def test_update_unknown_returns_none() -> None:
    g = kg.get_kg()
    assert g.update_node("N-999", props={"x": 1}) is None


# ---------------------------------------------------------------------------
# Query — nodes
# ---------------------------------------------------------------------------


def test_query_nodes_by_type() -> None:
    g = kg.get_kg()
    g.add_node(type="Surface", props={"url": "/a"})
    g.add_node(type="Surface", props={"url": "/b"})
    g.add_node(type="Vuln", props={"cwe": "CWE-79"})
    surfaces = g.query_nodes(type="Surface")
    assert len(surfaces) == 2


def test_query_nodes_property_filter_and_conjunction() -> None:
    g = kg.get_kg()
    g.add_node(type="Surface", props={"url": "/a", "method": "GET"})
    g.add_node(type="Surface", props={"url": "/a", "method": "POST"})
    g.add_node(type="Surface", props={"url": "/b", "method": "GET"})
    matches = g.query_nodes(
        type="Surface", filters={"url": "/a", "method": "POST"},
    )
    assert len(matches) == 1
    assert matches[0].props["url"] == "/a"


def test_query_nodes_no_filter_returns_all() -> None:
    g = kg.get_kg()
    g.add_node(type="Surface")
    g.add_node(type="Vuln")
    assert len(g.query_nodes()) == 2


# ---------------------------------------------------------------------------
# Query — edges
# ---------------------------------------------------------------------------


def test_query_edges_by_type_and_endpoints() -> None:
    g = kg.get_kg()
    s = g.add_node(type="Surface")
    v1 = g.add_node(type="Vuln")
    v2 = g.add_node(type="Vuln")
    g.add_edge(type="AFFECTS", source=v1.id, target=s.id)
    g.add_edge(type="AFFECTS", source=v2.id, target=s.id)
    g.add_edge(type="CHAINS_TO", source=v1.id, target=v2.id)

    affects = g.query_edges(type="AFFECTS")
    assert len(affects) == 2

    src_v1 = g.query_edges(source=v1.id)
    assert len(src_v1) == 2

    tgt_v2 = g.query_edges(target=v2.id)
    assert len(tgt_v2) == 1


# ---------------------------------------------------------------------------
# Path queries
# ---------------------------------------------------------------------------


def test_path_query_finds_direct_edge() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Vuln")
    g.add_edge(type="CHAINS_TO", source=a.id, target=b.id)
    paths = g.query_paths(start_id=a.id, end_id=b.id)
    assert paths == [[a.id, b.id]]


def test_path_query_finds_multihop() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Vuln")
    c = g.add_node(type="Vuln")
    g.add_edge(type="CHAINS_TO", source=a.id, target=b.id)
    g.add_edge(type="CHAINS_TO", source=b.id, target=c.id)
    paths = g.query_paths(start_id=a.id, end_id=c.id)
    assert paths == [[a.id, b.id, c.id]]


def test_path_query_respects_max_hops() -> None:
    g = kg.get_kg()
    nodes = [g.add_node(type="Vuln") for _ in range(5)]
    for i in range(4):
        g.add_edge(type="CHAINS_TO", source=nodes[i].id, target=nodes[i + 1].id)
    # max_hops=2 → cannot reach end (4 hops away)
    assert g.query_paths(start_id=nodes[0].id, end_id=nodes[4].id, max_hops=2) == []
    # max_hops=4 → can reach
    found = g.query_paths(start_id=nodes[0].id, end_id=nodes[4].id, max_hops=4)
    assert len(found) == 1


def test_path_query_edge_type_filter() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Surface")
    g.add_edge(type="AFFECTS", source=a.id, target=b.id)
    g.add_edge(type="LEAKS", source=a.id, target=b.id)
    only_affects = g.query_paths(
        start_id=a.id, end_id=b.id, edge_types=["AFFECTS"],
    )
    assert len(only_affects) == 1
    only_leaks = g.query_paths(
        start_id=a.id, end_id=b.id, edge_types=["LEAKS"],
    )
    assert len(only_leaks) == 1


def test_path_query_avoids_cycles() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Vuln")
    g.add_edge(type="CHAINS_TO", source=a.id, target=b.id)
    g.add_edge(type="CHAINS_TO", source=b.id, target=a.id)  # cycle
    paths = g.query_paths(start_id=a.id, end_id=a.id, max_hops=4)
    # No self-loop path (would re-visit `a`); empty results.
    assert paths == []


def test_path_query_unknown_endpoints_returns_empty() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    assert g.query_paths(start_id="N-999", end_id=a.id) == []
    assert g.query_paths(start_id=a.id, end_id="N-999") == []


# ---------------------------------------------------------------------------
# Neighbors
# ---------------------------------------------------------------------------


def test_neighbors_out_direction() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Surface")
    g.add_edge(type="AFFECTS", source=a.id, target=b.id)
    out = g.neighbors(a.id, direction="out")
    assert len(out) == 1
    assert out[0].id == b.id


def test_neighbors_in_direction() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Surface")
    g.add_edge(type="AFFECTS", source=a.id, target=b.id)
    in_ = g.neighbors(b.id, direction="in")
    assert in_[0].id == a.id


def test_neighbors_both() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Surface")
    b = g.add_node(type="Vuln")
    c = g.add_node(type="Credential")
    g.add_edge(type="AFFECTS", source=b.id, target=a.id)
    g.add_edge(type="GRANTS_ACCESS_TO", source=c.id, target=a.id)
    both = g.neighbors(a.id, direction="both")
    ids = sorted(n.id for n in both)
    assert ids == [b.id, c.id]


def test_neighbors_edge_type_filter() -> None:
    g = kg.get_kg()
    a = g.add_node(type="Vuln")
    b = g.add_node(type="Surface")
    c = g.add_node(type="Secret")
    g.add_edge(type="AFFECTS", source=a.id, target=b.id)
    g.add_edge(type="LEAKS", source=a.id, target=c.id)
    affects_only = g.neighbors(a.id, direction="out", edge_type="AFFECTS")
    assert len(affects_only) == 1
    assert affects_only[0].type == "Surface"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_writes_kg_json(tmp_path: Path) -> None:
    g = kg.get_kg()
    g.add_node(type="Surface", props={"url": "/login"})
    out = tmp_path / "kg.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["version"] == 1
    assert len(data["nodes"]) == 1
    assert data["nodes"][0]["type"] == "Surface"


def test_persistence_atomic_writes_no_partial(tmp_path: Path) -> None:
    """The .tmp file should be cleaned up — only kg.json remains."""
    g = kg.get_kg()
    g.add_node(type="Vuln")
    assert (tmp_path / "kg.json").exists()
    assert not (tmp_path / "kg.json.tmp").exists()


def test_load_kg_from_disk_restores_state(
    tmp_path: Path,
) -> None:
    g = kg.get_kg()
    a = g.add_node(type="Surface", props={"url": "/x"})
    b = g.add_node(type="Vuln", props={"cwe": "CWE-79"})
    g.add_edge(type="AFFECTS", source=b.id, target=a.id)

    # Reset in-memory state; reload from disk.
    kg.reset_for_testing()
    loaded = kg.load_kg_from_disk()
    assert loaded is not None
    assert loaded.stats()["node_count"] == 2
    assert loaded.stats()["edge_count"] == 1
    # IDs preserved
    assert loaded.get_node("N-001") is not None
    assert loaded.get_edge("E-001") is not None
    # Adjacency restored — next_link queries still work
    out = loaded.neighbors(b.id, direction="out")
    assert out[0].id == a.id


def test_load_when_no_file_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    kg.reset_for_testing()
    assert kg.load_kg_from_disk() is None


def test_persist_disabled_skips_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_KG_PERSIST", "0")
    g = kg.get_kg()
    g.add_node(type="Surface")
    assert not (tmp_path / "kg.json").exists()


def test_persist_without_run_dir_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    g = kg.get_kg()
    g.add_node(type="Surface")  # must not raise


# ---------------------------------------------------------------------------
# Kill switch + telemetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch_telemetry_shape(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", val)
    stats = kg.get_kg_stats()
    assert stats == {"enabled": False, "node_count": 0, "edge_count": 0}


def test_stats_breakdown_by_type() -> None:
    g = kg.get_kg()
    g.add_node(type="Surface")
    g.add_node(type="Surface")
    g.add_node(type="Vuln")
    stats = kg.get_kg_stats()
    assert stats["enabled"] is True
    assert stats["node_count"] == 3
    assert stats["node_types"]["Surface"] == 2
    assert stats["node_types"]["Vuln"] == 1


# ---------------------------------------------------------------------------
# P4 — CI delta-scan seed loader
# ---------------------------------------------------------------------------


def test_load_kg_from_disk_accepts_explicit_path(tmp_path: Path) -> None:
    """load_kg_from_disk(path) loads from arbitrary location — not
    just <run_dir>/kg.json (the canonical resume location)."""
    seed_dir = tmp_path / "previous_run"
    seed_dir.mkdir()
    g_orig = kg.get_kg()
    a = g_orig.add_node(type="Surface", props={"url": "/x"})
    b = g_orig.add_node(type="Vuln", props={"cwe": "CWE-89"})
    g_orig.add_edge(type="AFFECTS", source=b.id, target=a.id)

    seed_file = seed_dir / "kg.json"
    import json as _json
    seed_file.write_text(_json.dumps(g_orig.to_dict()))

    kg.reset_for_testing()
    loaded = kg.load_kg_from_disk(seed_file)
    assert loaded is not None
    assert loaded.stats()["node_count"] == 2
    assert loaded.stats()["edge_count"] == 1


def test_load_seed_kg_from_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_KG_SEED_PATH", raising=False)
    assert kg.load_seed_kg_from_env() is None


def test_load_seed_kg_from_env_missing_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_KG_SEED_PATH", str(tmp_path / "nope.json"))
    assert kg.load_seed_kg_from_env() is None


def test_load_seed_kg_from_env_happy_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """STRIX_KG_SEED_PATH points at a valid kg.json → loader
    populates the singleton before scan start; subsequent
    `get_kg()` returns the seeded graph and new nodes compose
    with prior state."""
    g = kg.get_kg()
    g.add_node(type="Surface", props={"url": "/seed"})
    g.add_node(type="Vuln", props={"cwe": "CWE-79"})

    seed_path = tmp_path / "prior_kg.json"
    import json as _json
    seed_path.write_text(_json.dumps(g.to_dict()))

    kg.reset_for_testing()
    monkeypatch.setenv("STRIX_KG_SEED_PATH", str(seed_path))
    loaded = kg.load_seed_kg_from_env()
    assert loaded is not None
    assert loaded.stats()["node_count"] == 2

    g_after = kg.get_kg()
    assert g_after is loaded
    g_after.add_node(type="Surface", props={"url": "/new"})
    assert g_after.stats()["node_count"] == 3


def test_load_seed_kg_from_env_respects_kill_switch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """STRIX_KG_DISABLED=1 overrides — seed is NOT loaded."""
    seed_path = tmp_path / "prior.json"
    seed_path.write_text('{"version":1,"nodes":[],"edges":[]}')
    monkeypatch.setenv("STRIX_KG_SEED_PATH", str(seed_path))
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    assert kg.load_seed_kg_from_env() is None


def test_load_seed_kg_from_env_malformed_seed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Malformed seed file → warning logged, None returned. Scan
    continues with empty KG."""
    seed_path = tmp_path / "broken.json"
    seed_path.write_text("{not valid json")
    monkeypatch.setenv("STRIX_KG_SEED_PATH", str(seed_path))
    assert kg.load_seed_kg_from_env() is None
