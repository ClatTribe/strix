"""Unit tests for `strix.finding_chains.correlator`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.finding_chains.chain import Finding
from strix.finding_chains.correlator import (
    _UnionFind,
    build_chains,
    write_finding_chains,
)


def _f(**kwargs) -> Finding:
    return Finding(
        id=kwargs.get("id", "f"),
        title=kwargs.get("title", "X"),
        category=kwargs.get("category", "sqli"),
        severity=kwargs.get("severity", "medium"),
        cwe=kwargs.get("cwe"),
        target=kwargs.get("target", ""),
        endpoint=kwargs.get("endpoint", ""),
        description=kwargs.get("description", ""),
        cve=kwargs.get("cve"),
        package=kwargs.get("package", ""),
        metadata=kwargs.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# UnionFind
# ---------------------------------------------------------------------------


def test_union_find_basic() -> None:
    uf = _UnionFind()
    uf.union("a", "b")
    uf.union("b", "c")
    uf.union("d", "e")
    assert uf.find("a") == uf.find("c")
    assert uf.find("d") == uf.find("e")
    assert uf.find("a") != uf.find("d")


def test_union_find_idempotent() -> None:
    uf = _UnionFind()
    uf.union("a", "b")
    uf.union("a", "b")  # again
    assert uf.find("a") == uf.find("b")


# ---------------------------------------------------------------------------
# build_chains — connected components
# ---------------------------------------------------------------------------


def test_build_chains_empty_input() -> None:
    assert build_chains([]) == []


def test_build_chains_singletons_excluded() -> None:
    """Findings with no links should NOT appear as chains —
    they're already in the source artifact."""
    findings = [
        _f(id="a", category="sqli", target="https://x.com"),
        _f(id="b", category="xss", target="https://y.com"),
    ]
    chains = build_chains(findings)
    assert chains == []


def test_build_chains_links_two_findings_into_one_chain() -> None:
    """Classic SCA + DAST pair: both reference lodash, share
    CWE family, same target → one chain of size 2."""
    sca = _f(
        id="sca-1",
        title="Vulnerable dependency `npm:lodash@4.17.20`",
        category="vulnerable_dependency",
        cwe="CWE-1321",
        target="https://app.com",
        package="npm:lodash",
    )
    dast = _f(
        id="dast-1",
        title="Prototype pollution at /api/merge",
        category="deserialization",
        cwe="CWE-502",
        target="https://app.com",
    )
    chains = build_chains([sca, dast])
    assert len(chains) == 1
    c = chains[0]
    assert c.size == 2
    assert set(c.finding_ids) == {"sca-1", "dast-1"}
    assert c.chain_type in ("sca_dast", "mixed")


def test_build_chains_transitive_closure() -> None:
    """A↔B and B↔C → all three in one chain."""
    a = _f(
        id="a",
        title="Vulnerable dependency `npm:lodash@4.17.20`",
        category="vulnerable_dependency",
        package="npm:lodash",
        cwe="CWE-1321",
        target="https://app.com",
    )
    b = _f(
        id="b",
        title="strix-eval rule fired",
        category="sast",
        cwe="CWE-94",
        description="dangerouslySetInnerHTML; calls lodash.merge",
        target="https://app.com",
    )
    c = _f(
        id="c",
        title="cmd_injection at /api/calc",
        category="cmd_injection",
        cwe="CWE-94",
        target="https://app.com",
    )
    chains = build_chains([a, b, c])
    # a links to b via SCA→SAST package match.
    # b links to c via SAST→DAST CWE family.
    # → all three in one chain.
    assert len(chains) == 1
    assert chains[0].size == 3
    assert set(chains[0].finding_ids) == {"a", "b", "c"}


def test_build_chains_multiple_independent_chains() -> None:
    """Two separate clusters → two chains."""
    # Cluster 1: SCA + DAST on app.com
    a = _f(id="a", category="vulnerable_dependency",
           cwe="CWE-89", target="https://app.com")
    b = _f(id="b", category="sqli",
           cwe="CWE-89", target="https://app.com")
    # Cluster 2: SCA + DAST on other.com
    c = _f(id="c", category="vulnerable_dependency",
           cwe="CWE-79", target="https://other.com")
    d = _f(id="d", category="xss",
           cwe="CWE-79", target="https://other.com")
    chains = build_chains([a, b, c, d])
    assert len(chains) == 2
    sizes = sorted(ch.size for ch in chains)
    assert sizes == [2, 2]


def test_chain_severity_is_max_across_findings() -> None:
    a = _f(id="a", category="vulnerable_dependency", cwe="CWE-89",
           target="https://x.com", severity="medium")
    b = _f(id="b", category="sqli", cwe="CWE-89",
           target="https://x.com", severity="critical")
    chains = build_chains([a, b])
    assert chains[0].severity == "critical"


def test_chain_id_stable_across_runs() -> None:
    findings = [
        _f(id="a", category="vulnerable_dependency", cwe="CWE-89",
           target="https://x.com"),
        _f(id="b", category="sqli", cwe="CWE-89",
           target="https://x.com"),
    ]
    c1 = build_chains(findings)[0].chain_id
    c2 = build_chains(findings)[0].chain_id
    assert c1 == c2
    assert c1.startswith("chain-")


def test_chain_categories_union_across_findings() -> None:
    a = _f(id="a", category="vulnerable_dependency",
           cwe="CWE-1321", target="https://x.com")
    b = _f(id="b", category="deserialization",
           cwe="CWE-502", target="https://x.com")
    chains = build_chains([a, b])
    assert set(chains[0].categories) == {
        "vulnerable_dependency", "deserialization",
    }


def test_chain_findings_ordered_by_severity_descending() -> None:
    a = _f(id="a", category="vulnerable_dependency",
           cwe="CWE-89", target="https://x.com", severity="medium")
    b = _f(id="b", category="sqli",
           cwe="CWE-89", target="https://x.com", severity="critical")
    chains = build_chains([a, b])
    # Critical-severity finding (`b`) should appear first.
    assert chains[0].finding_ids[0] == "b"


def test_min_chain_size_filters_chains() -> None:
    """`min_chain_size=3` with a 2-finding chain → no output."""
    a = _f(id="a", category="vulnerable_dependency",
           cwe="CWE-89", target="https://x.com")
    b = _f(id="b", category="sqli",
           cwe="CWE-89", target="https://x.com")
    assert build_chains([a, b], min_chain_size=3) == []


# ---------------------------------------------------------------------------
# write_finding_chains
# ---------------------------------------------------------------------------


def test_write_finding_chains_round_trip(tmp_path: Path) -> None:
    a = _f(id="a", category="vulnerable_dependency", cwe="CWE-89",
           target="https://x.com")
    b = _f(id="b", category="sqli", cwe="CWE-89",
           target="https://x.com")
    chains = build_chains([a, b])
    out_path = tmp_path / "finding_chains.json"
    written = write_finding_chains(chains, out_path)
    assert written == out_path.resolve() or written == out_path
    doc = json.loads(out_path.read_text())
    assert doc["schema_version"] == 1
    assert len(doc["chains"]) == 1
    assert doc["chains"][0]["size"] == 2
    assert doc["stats"]["total_chains"] == 1


def test_write_finding_chains_creates_parent_dirs(tmp_path: Path) -> None:
    chains = []
    out = tmp_path / "deep" / "nested" / "chains.json"
    write_finding_chains(chains, out)
    assert out.exists()
