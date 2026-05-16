"""Tests for `record_dependency_in_kg` — the producer-side helper
that populates the `Dependency` KG nodes consumed by the CVE-
relevance evaluator (`strix.agents.exploit_builder.cve_relevance`).

Coverage:
  * Basic emit shape + canonical name normalisation
  * Dedup behaviour: same (name, version, ecosystem) → one node;
    different versions / ecosystems → distinct nodes
  * Re-emission merges `cve_ids` + `sources` additively
  * Kill switch (`STRIX_KG_DISABLED=1`) returns None
  * Bad inputs (empty / non-string name) return None without raising
  * Inventory-from-KG read path picks the emitted node up correctly
"""

from __future__ import annotations

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents.exploit_builder.cve_relevance import (
    get_asset_inventory_from_kg,
)
from strix.agents.kg_emit import (
    record_dependency_in_kg,
    reset_dependency_cache_for_testing,
)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    kg.reset_for_testing()
    reset_dependency_cache_for_testing()
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Basic emit
# ---------------------------------------------------------------------------


def test_basic_emit_creates_dependency_node() -> None:
    node_id = record_dependency_in_kg(
        name="log4j-core",
        version="2.14.0",
        ecosystem="maven",
        source="sca_lockfiles",
    )
    assert node_id is not None
    node = kg.get_kg().get_node(node_id)
    assert node is not None
    assert node.type == "Dependency"
    assert node.props["name"] == "log4j-core"   # canonical
    assert node.props["name_raw"] == "log4j-core"
    assert node.props["version"] == "2.14.0"
    assert node.props["ecosystem"] == "maven"
    assert "sca_lockfiles" in node.props["sources"]


def test_emit_canonicalises_namespaced_names() -> None:
    """Maven coords + Java FQN both collapse to the artifact name."""
    node_id = record_dependency_in_kg(
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.0",
        ecosystem="maven",
    )
    node = kg.get_kg().get_node(node_id)
    assert node.props["name"] == "log4j-core"
    # Raw name preserved for evidence trail.
    assert node.props["name_raw"] == "org.apache.logging.log4j:log4j-core"


def test_emit_handles_npm_scope() -> None:
    node_id = record_dependency_in_kg(
        name="@babel/core",
        version="7.20.0",
        ecosystem="npm",
    )
    node = kg.get_kg().get_node(node_id)
    assert node.props["name"] == "core"


def test_emit_without_version_still_succeeds() -> None:
    """Some fingerprinters recognise the product but not the
    version. We still want the node in the KG (relevance
    evaluator handles version-unknown via PRODUCT_MATCH)."""
    node_id = record_dependency_in_kg(
        name="nginx", source="fingerprint_tech_stack",
    )
    node = kg.get_kg().get_node(node_id)
    assert node.props["name"] == "nginx"
    assert "version" not in node.props


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_same_pkg_version_ecosystem_dedupes_to_one_node() -> None:
    a = record_dependency_in_kg(name="log4j", version="2.14.0", ecosystem="maven")
    b = record_dependency_in_kg(name="log4j", version="2.14.0", ecosystem="maven")
    assert a == b
    assert kg.get_kg().stats()["node_types"].get("Dependency") == 1


def test_different_versions_are_distinct_nodes() -> None:
    a = record_dependency_in_kg(name="log4j", version="2.14.0", ecosystem="maven")
    b = record_dependency_in_kg(name="log4j", version="2.17.1", ecosystem="maven")
    assert a != b
    assert kg.get_kg().stats()["node_types"].get("Dependency") == 2


def test_different_ecosystems_are_distinct_nodes() -> None:
    """Same name + version in two ecosystems = two distinct
    runtimes (rare but real — npm + pypi packages can share names)."""
    a = record_dependency_in_kg(name="ws", version="8.0.0", ecosystem="npm")
    b = record_dependency_in_kg(name="ws", version="8.0.0", ecosystem="pypi")
    assert a != b


def test_re_emission_merges_cve_ids_additively() -> None:
    """SCA discovers log4j → emits with CVE-2021-44228. Later, a
    separate scanner discovers the same package and surfaces an
    additional CVE. Both should accumulate on the node."""
    node_id = record_dependency_in_kg(
        name="log4j", version="2.14.0", ecosystem="maven",
        source="sca_lockfiles", cve_ids=["CVE-2021-44228"],
    )
    record_dependency_in_kg(
        name="log4j", version="2.14.0", ecosystem="maven",
        source="cve_intel_search", cve_ids=["CVE-2021-45046"],
    )
    node = kg.get_kg().get_node(node_id)
    assert set(node.props["cve_ids"]) == {"CVE-2021-44228", "CVE-2021-45046"}
    assert set(node.props["sources"]) == {"sca_lockfiles", "cve_intel_search"}


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_empty_name_returns_none() -> None:
    assert record_dependency_in_kg(name="", version="1.0") is None
    assert record_dependency_in_kg(name="   ", version="1.0") is None


def test_non_string_name_returns_none() -> None:
    assert record_dependency_in_kg(name=None) is None       # type: ignore[arg-type]
    assert record_dependency_in_kg(name=12345) is None      # type: ignore[arg-type]


def test_kg_disabled_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    assert record_dependency_in_kg(
        name="log4j", version="2.14.0", ecosystem="maven",
    ) is None


# ---------------------------------------------------------------------------
# End-to-end with inventory reader
# ---------------------------------------------------------------------------


def test_emitted_node_visible_to_inventory_reader() -> None:
    """The whole point of the helper: emit on the producer side,
    read on the consumer side via `get_asset_inventory_from_kg()`."""
    record_dependency_in_kg(
        name="log4j-core",
        version="2.14.0",
        ecosystem="maven",
        source="sca_lockfiles",
    )
    inventory = get_asset_inventory_from_kg()
    products = {(e.product, e.version, e.ecosystem) for e in inventory}
    assert ("log4j-core", "2.14.0", "maven") in products
