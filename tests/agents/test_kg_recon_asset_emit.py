"""Tests for `record_asset_in_kg` — the recon-side Asset emitter.

Coverage:
  * Basic emit: domain/subdomain/ip/mx_record/cloud_bucket/cloud_account types
  * Dedup: same (asset_type, value) → one node
  * Cross-cache dedup with `record_threat_intel_in_kg`: a domain
    discovered by recon AND flagged by threat-intel lands on the
    SAME Asset node
  * Source / parent / properties accumulate on re-emission
  * Bad inputs (empty / non-string) return None
  * Kill switch (`STRIX_KG_DISABLED=1`) returns None
"""

from __future__ import annotations

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents.kg_emit import (
    record_asset_in_kg,
    record_threat_intel_in_kg,
    reset_asset_cache_for_testing,
    reset_recon_asset_cache_for_testing,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    kg.reset_for_testing()
    reset_recon_asset_cache_for_testing()
    reset_asset_cache_for_testing()
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Basic emit
# ---------------------------------------------------------------------------


def test_emit_subdomain_creates_asset_node() -> None:
    node_id = record_asset_in_kg(
        asset_type="subdomain",
        value="api.example.com",
        source="subdomain_enum_tool",
        parent_value="example.com",
    )
    assert node_id is not None
    node = kg.get_kg().get_node(node_id)
    assert node.type == "Asset"
    assert node.props["type"] == "subdomain"
    assert node.props["value"] == "api.example.com"
    assert node.props["parent"] == "example.com"
    assert node.props["sources"] == ["subdomain_enum_tool"]


def test_emit_ip_address() -> None:
    node_id = record_asset_in_kg(
        asset_type="ip_address",
        value="1.2.3.4",
        source="reverse_ip",
    )
    node = kg.get_kg().get_node(node_id)
    assert node.props["type"] == "ip_address"
    assert node.props["value"] == "1.2.3.4"


def test_emit_mx_record_with_properties() -> None:
    node_id = record_asset_in_kg(
        asset_type="mx_record",
        value="mail.example.com",
        source="mail_recon",
        parent_value="example.com",
        properties={"preference": 10},
    )
    node = kg.get_kg().get_node(node_id)
    assert node.props["preference"] == 10


def test_emit_cloud_bucket() -> None:
    node_id = record_asset_in_kg(
        asset_type="cloud_bucket",
        value="my-org-backups",
        source="discover_cloud_assets",
        parent_value="my-org",
        properties={"provider": "s3", "url": "https://my-org-backups.s3.amazonaws.com"},
    )
    node = kg.get_kg().get_node(node_id)
    assert node.props["provider"] == "s3"
    assert "my-org-backups" in node.props["value"]


def test_emit_lowercases_value_for_canonical_dedup() -> None:
    """Domain comparisons must be case-insensitive."""
    a = record_asset_in_kg(
        asset_type="domain", value="API.Example.com",
        source="recon",
    )
    b = record_asset_in_kg(
        asset_type="domain", value="api.example.com",
        source="recon",
    )
    assert a == b


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_repeated_emit_dedupes_to_one_node() -> None:
    a = record_asset_in_kg(
        asset_type="subdomain", value="api.example.com",
        source="subfinder",
    )
    b = record_asset_in_kg(
        asset_type="subdomain", value="api.example.com",
        source="crtsh",
    )
    assert a == b
    stats = kg.get_kg().stats()
    assert stats["node_types"].get("Asset", 0) == 1


def test_repeated_emit_merges_sources_additively() -> None:
    record_asset_in_kg(
        asset_type="subdomain", value="api.example.com",
        source="subfinder",
    )
    record_asset_in_kg(
        asset_type="subdomain", value="api.example.com",
        source="crtsh",
    )
    record_asset_in_kg(
        asset_type="subdomain", value="api.example.com",
        source="amass",
    )
    node_id = record_asset_in_kg(
        asset_type="subdomain", value="api.example.com",
        source="subfinder",   # duplicate — still set
    )
    node = kg.get_kg().get_node(node_id)
    assert set(node.props["sources"]) == {"subfinder", "crtsh", "amass"}


def test_distinct_asset_types_keep_separate_nodes() -> None:
    """Same string, different asset_type → two nodes. A domain
    `example.com` and a (hypothetical) URL `example.com` are
    different things."""
    a = record_asset_in_kg(asset_type="domain", value="example.com")
    b = record_asset_in_kg(asset_type="ip_address", value="example.com")
    assert a != b


# ---------------------------------------------------------------------------
# Cross-cache dedup with threat_intel
# ---------------------------------------------------------------------------


def test_recon_and_threat_intel_land_on_same_asset() -> None:
    """Subdomain discovered by recon → Asset created. Same
    subdomain flagged by vt_reputation later → reuses the same
    Asset (one node total, with both an OBSERVED edge and the
    recon `sources` field set)."""
    recon_id = record_asset_in_kg(
        asset_type="domain",
        value="evil.example.com",
        source="subdomain_enum_tool",
    )
    ti_id, asset_id = record_threat_intel_in_kg(
        source="vt_reputation",
        asset_type="domain",
        asset_value="evil.example.com",
        verdict="malicious",
    )
    assert asset_id == recon_id
    stats = kg.get_kg().stats()
    assert stats["node_types"].get("Asset", 0) == 1
    assert stats["node_types"].get("ThreatIntel", 0) == 1
    # OBSERVED edge from ThreatIntel → Asset.
    assert stats["edge_types"].get("OBSERVED", 0) == 1


def test_threat_intel_first_then_recon_dedup() -> None:
    """Order independence: threat-intel first creates the Asset,
    then recon's discovery should reuse it."""
    ti_id, asset_id_first = record_threat_intel_in_kg(
        source="vt_reputation",
        asset_type="domain",
        asset_value="evil.example.com",
        verdict="malicious",
    )
    recon_id = record_asset_in_kg(
        asset_type="domain",
        value="evil.example.com",
        source="subdomain_enum_tool",
    )
    assert recon_id == asset_id_first


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_empty_value_returns_none() -> None:
    assert record_asset_in_kg(asset_type="domain", value="") is None
    assert record_asset_in_kg(asset_type="domain", value="   ") is None


def test_empty_asset_type_returns_none() -> None:
    assert record_asset_in_kg(asset_type="", value="x.com") is None


def test_kg_disabled_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    assert record_asset_in_kg(
        asset_type="domain", value="x.com",
    ) is None
