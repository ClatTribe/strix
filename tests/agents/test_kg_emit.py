"""Tests for the §3 KG-population helper used by specialist scanners.

Covers:
  * URL canonicalisation — query/fragment stripped
  * Idempotent Surface dedup — same (url, param, method) → one node
  * Vuln + AFFECTS edge emitted per finding
  * KG kill switch (STRIX_KG_DISABLED) — helper returns (None, None)
  * Defensive: bad KG state never raises
  * Optional props (db_engine, detection_kind, confidence) wired through
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
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# URL canonicalisation
# ---------------------------------------------------------------------------


def test_canonicalise_strips_query_and_fragment() -> None:
    out = kg_emit._canonicalise_url("https://app/login?u=x&p=y#section")
    assert out == "https://app/login"


def test_canonicalise_keeps_path() -> None:
    out = kg_emit._canonicalise_url("https://app/api/v1/users/")
    assert out == "https://app/api/v1/users/"


def test_canonicalise_handles_invalid_input() -> None:
    # Should not raise.
    assert kg_emit._canonicalise_url("") == ""


# ---------------------------------------------------------------------------
# Basic emission
# ---------------------------------------------------------------------------


def test_emits_vuln_surface_and_affects() -> None:
    vuln_id, surface_id = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/login?username=x",
        param="username",
        cwe="CWE-89",
        severity="high",
        category="sqli",
        detection_kind="boolean",
    )
    assert vuln_id is not None
    assert surface_id is not None

    # Vuln node carries CWE, severity, category, detection_kind, finding_id
    g = kg.get_kg()
    vuln = g.get_node(vuln_id)
    assert vuln is not None
    assert vuln.type == "Vuln"
    assert vuln.props["cwe"] == "CWE-89"
    assert vuln.props["severity"] == "high"
    assert vuln.props["category"] == "sqli"
    assert vuln.props["detection_kind"] == "boolean"
    assert vuln.props["finding_id"] == "F-001"

    # Surface node carries canonicalised url + param + method
    surface = g.get_node(surface_id)
    assert surface is not None
    assert surface.type == "Surface"
    assert surface.props["url"] == "https://app/login"
    assert surface.props["param"] == "username"
    assert surface.props["method"] == "GET"

    # AFFECTS edge from Vuln to Surface
    edges = g.query_edges(type="AFFECTS", source=vuln_id, target=surface_id)
    assert len(edges) == 1
    assert edges[0].props.get("detected_via") == "boolean"


def test_severity_lowercased() -> None:
    """Vuln.severity is stored lowercased even if caller passes
    upper/mixed case — chain queries match on lowercase."""
    vuln_id, _ = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/x", param="p",
        cwe="CWE-79", severity="CRITICAL", category="xss",
    )
    assert vuln_id is not None
    vuln = kg.get_kg().get_node(vuln_id)
    assert vuln is not None
    assert vuln.props["severity"] == "critical"


def test_optional_props_passed_through() -> None:
    vuln_id, _ = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/x", param="id",
        cwe="CWE-89", severity="high", category="sqli",
        db_engine="postgres", confidence=0.95,
    )
    vuln = kg.get_kg().get_node(vuln_id)  # type: ignore[arg-type]
    assert vuln is not None
    assert vuln.props["db_engine"] == "postgres"
    assert vuln.props["confidence"] == 0.95


# ---------------------------------------------------------------------------
# Surface dedup
# ---------------------------------------------------------------------------


def test_same_surface_dedup_across_findings() -> None:
    """Ten boolean probes against /login?u=... → one Surface, ten Vulns."""
    surface_ids: set[str] = set()
    for i in range(10):
        vuln_id, surface_id = kg_emit.record_finding_in_kg(
            finding_id=f"F-{i:03d}",
            url=f"https://app/login?try={i}",
            param="username",
            cwe="CWE-89", severity="high", category="sqli",
        )
        assert vuln_id is not None
        assert surface_id is not None
        surface_ids.add(surface_id)

    assert len(surface_ids) == 1, (
        "Surface dedup failed — should be one node per (url, param, method)"
    )
    g = kg.get_kg()
    assert g.stats()["node_types"].get("Vuln") == 10
    assert g.stats()["node_types"].get("Surface") == 1
    # 10 AFFECTS edges, all pointing at the same surface
    affects = g.query_edges(type="AFFECTS")
    assert len(affects) == 10
    targets = {e.target for e in affects}
    assert len(targets) == 1


def test_different_params_different_surfaces() -> None:
    """Same URL, different params → different Surface nodes."""
    _, s1 = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/login", param="username",
        cwe="CWE-89", severity="high", category="sqli",
    )
    _, s2 = kg_emit.record_finding_in_kg(
        finding_id="F-002",
        url="https://app/login", param="password",
        cwe="CWE-89", severity="high", category="sqli",
    )
    assert s1 != s2


def test_different_methods_different_surfaces() -> None:
    _, s1 = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/login", param="username",
        cwe="CWE-89", severity="high", category="sqli",
        method="GET",
    )
    _, s2 = kg_emit.record_finding_in_kg(
        finding_id="F-002",
        url="https://app/login", param="username",
        cwe="CWE-89", severity="high", category="sqli",
        method="POST",
    )
    assert s1 != s2


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "yes", "ON"])
def test_kill_switch_returns_none_pair(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", val)
    vuln_id, surface_id = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/x", param="p",
        cwe="CWE-89", severity="high", category="sqli",
    )
    assert vuln_id is None
    assert surface_id is None


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_missing_finding_id_still_emits() -> None:
    """A finding with no tracer ID can still populate the KG —
    chain-planning doesn't need finding_id, only the graph shape."""
    vuln_id, surface_id = kg_emit.record_finding_in_kg(
        finding_id=None,
        url="https://app/x", param="p",
        cwe="CWE-89", severity="high", category="sqli",
    )
    assert vuln_id is not None
    assert surface_id is not None
    vuln = kg.get_kg().get_node(vuln_id)
    assert vuln is not None
    assert "finding_id" not in vuln.props


def test_kg_chain_path_query_finds_two_findings_on_same_surface() -> None:
    """End-to-end: two findings on /login → KG path SQLi-Vuln →
    Surface ← XSS-Vuln. Both findings reachable from Surface via
    AFFECTS (incoming edges)."""
    sqli_id, surface_id = kg_emit.record_finding_in_kg(
        finding_id="F-001",
        url="https://app/login", param="username",
        cwe="CWE-89", severity="high", category="sqli",
    )
    xss_id, surface_id_2 = kg_emit.record_finding_in_kg(
        finding_id="F-002",
        url="https://app/login", param="username",
        cwe="CWE-79", severity="medium", category="xss",
    )
    # Same surface — dedup worked.
    assert surface_id == surface_id_2

    g = kg.get_kg()
    # Two distinct Vuln nodes pointing at one Surface.
    affects = g.query_edges(target=surface_id)  # type: ignore[arg-type]
    sources = {e.source for e in affects}
    assert sources == {sqli_id, xss_id}
