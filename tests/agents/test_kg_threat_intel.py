"""Tests for the P4 ThreatIntel KG projection — alternative shape
for scanners that emit observations about assets (vt_reputation,
kev_diff, hibp_breach, etc.) rather than Vuln→Surface findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents import kg_emit


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kg.reset_for_testing()
    kg_emit.reset_surface_cache_for_testing()
    kg_emit.reset_asset_cache_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Schema — new node + edge types are accepted
# ---------------------------------------------------------------------------


def test_threat_intel_node_type_allowed() -> None:
    g = kg.get_kg()
    node = g.add_node(
        type="ThreatIntel",
        props={"source": "vt", "verdict": "malicious"},
    )
    assert node.type == "ThreatIntel"


def test_observed_edge_type_allowed() -> None:
    g = kg.get_kg()
    ti = g.add_node(type="ThreatIntel", props={"source": "vt"})
    asset = g.add_node(type="Asset", props={"type": "domain", "value": "x"})
    edge = g.add_edge(type="OBSERVED", source=ti.id, target=asset.id)
    assert edge.type == "OBSERVED"


def test_existing_types_still_valid() -> None:
    """Regression check — extending taxonomy didn't break old types."""
    g = kg.get_kg()
    g.add_node(type="Surface")
    g.add_node(type="Vuln")
    g.add_node(type="ThreatIntel", props={"source": "vt"})
    stats = g.stats()
    assert stats["node_types"]["Surface"] == 1
    assert stats["node_types"]["Vuln"] == 1
    assert stats["node_types"]["ThreatIntel"] == 1


# ---------------------------------------------------------------------------
# record_threat_intel_in_kg helper
# ---------------------------------------------------------------------------


def test_basic_record_creates_threat_intel_asset_observed() -> None:
    """Records ThreatIntel + Asset + OBSERVED triple."""
    ti_id, asset_id = kg_emit.record_threat_intel_in_kg(
        source="vt_reputation",
        asset_type="domain",
        asset_value="evil.example.com",
        verdict="malicious",
        score=0.85,
        detail="42/70 engines flagged",
        finding_id="F-001",
    )
    assert ti_id is not None
    assert asset_id is not None

    g = kg.get_kg()
    ti = g.get_node(ti_id)
    assert ti is not None
    assert ti.type == "ThreatIntel"
    assert ti.props["source"] == "vt_reputation"
    assert ti.props["verdict"] == "malicious"
    assert ti.props["score"] == 0.85
    assert ti.props["detail"] == "42/70 engines flagged"
    assert ti.props["finding_id"] == "F-001"

    asset = g.get_node(asset_id)
    assert asset is not None
    assert asset.type == "Asset"
    assert asset.props["type"] == "domain"
    assert asset.props["value"] == "evil.example.com"

    edges = g.query_edges(type="OBSERVED", source=ti_id, target=asset_id)
    assert len(edges) == 1


def test_multiple_observations_same_asset_dedup() -> None:
    """vt_reputation + domain_reputation both flag the same
    domain → 1 Asset, 2 ThreatIntel, 2 OBSERVED edges."""
    ti1, asset1 = kg_emit.record_threat_intel_in_kg(
        source="vt_reputation",
        asset_type="domain",
        asset_value="evil.com",
        verdict="malicious",
    )
    ti2, asset2 = kg_emit.record_threat_intel_in_kg(
        source="domain_reputation",
        asset_type="domain",
        asset_value="evil.com",
        verdict="suspicious",
    )
    # Same Asset node — dedup worked.
    assert asset1 == asset2
    # Two distinct ThreatIntel nodes.
    assert ti1 != ti2

    g = kg.get_kg()
    assert g.stats()["node_types"]["Asset"] == 1
    assert g.stats()["node_types"]["ThreatIntel"] == 2
    assert g.stats()["edge_types"]["OBSERVED"] == 2


def test_different_asset_types_different_assets() -> None:
    """Same value but different asset_type → different Assets."""
    _, a1 = kg_emit.record_threat_intel_in_kg(
        source="vt", asset_type="domain", asset_value="x.example.com",
        verdict="malicious",
    )
    _, a2 = kg_emit.record_threat_intel_in_kg(
        source="vt", asset_type="url", asset_value="x.example.com",
        verdict="malicious",
    )
    assert a1 != a2


def test_record_omits_optional_fields_when_none() -> None:
    """score / detail / finding_id are optional — they shouldn't
    appear on the node when not supplied."""
    ti_id, _ = kg_emit.record_threat_intel_in_kg(
        source="kev_diff",
        asset_type="cve_id",
        asset_value="CVE-2024-12345",
        verdict="kev_listed",
    )
    node = kg.get_kg().get_node(ti_id)
    assert node is not None
    assert "score" not in node.props
    assert "detail" not in node.props
    assert "finding_id" not in node.props


def test_kill_switch_returns_none_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    ti, asset = kg_emit.record_threat_intel_in_kg(
        source="vt", asset_type="domain", asset_value="x",
        verdict="malicious",
    )
    assert ti is None
    assert asset is None
    assert kg.get_kg().stats()["node_count"] == 0


# ---------------------------------------------------------------------------
# Query patterns enabled by the new types
# ---------------------------------------------------------------------------


def test_query_observations_about_one_asset() -> None:
    """The lead can ask 'show me everything threat-intel said
    about this domain' via `kg.neighbors(asset_id, direction='in',
    edge_type='OBSERVED')`."""
    _, asset_id = kg_emit.record_threat_intel_in_kg(
        source="vt", asset_type="domain", asset_value="evil.com",
        verdict="malicious",
    )
    kg_emit.record_threat_intel_in_kg(
        source="hibp", asset_type="domain", asset_value="evil.com",
        verdict="breached",
    )
    kg_emit.record_threat_intel_in_kg(
        source="kev_diff", asset_type="cve_id",
        asset_value="CVE-2024-99999", verdict="kev_listed",
    )

    g = kg.get_kg()
    incoming = g.neighbors(asset_id, direction="in", edge_type="OBSERVED")
    assert len(incoming) == 2   # vt + hibp, NOT the kev observation
    sources = sorted(n.props.get("source") for n in incoming)
    assert sources == ["hibp", "vt"]


def test_query_threat_intel_by_source() -> None:
    """`query_nodes(type='ThreatIntel', filters={'source': 'vt'})`
    finds every vt observation."""
    kg_emit.record_threat_intel_in_kg(
        source="vt", asset_type="domain", asset_value="a.com",
        verdict="malicious",
    )
    kg_emit.record_threat_intel_in_kg(
        source="vt", asset_type="domain", asset_value="b.com",
        verdict="suspicious",
    )
    kg_emit.record_threat_intel_in_kg(
        source="hibp", asset_type="email", asset_value="x@y.com",
        verdict="breached",
    )

    g = kg.get_kg()
    vt_obs = g.query_nodes(type="ThreatIntel", filters={"source": "vt"})
    assert len(vt_obs) == 2


def test_chain_query_asset_to_vuln_through_observations() -> None:
    """The graph supports cross-projection queries: a Vuln on a
    Surface that's hosted by an Asset that's flagged in
    ThreatIntel. Demonstrates the projections compose."""
    g = kg.get_kg()
    # Vuln side
    v = g.add_node(type="Vuln", props={"cwe": "CWE-79", "category": "xss"})
    s = g.add_node(type="Surface", props={"url": "https://app.evil.com/x"})
    g.add_edge(type="AFFECTS", source=v.id, target=s.id)
    # ThreatIntel side
    a = g.add_node(type="Asset", props={"type": "domain", "value": "app.evil.com"})
    ti = g.add_node(type="ThreatIntel", props={"source": "vt", "verdict": "malicious"})
    g.add_edge(type="OBSERVED", source=ti.id, target=a.id)
    # Bridge — Surface hosted-on Asset
    g.add_edge(type="RUNS_ON", source=s.id, target=a.id)

    paths = g.query_paths(start_id=v.id, end_id=a.id, max_hops=3)
    # Vuln → Surface → Asset
    assert any(p == [v.id, s.id, a.id] for p in paths)
