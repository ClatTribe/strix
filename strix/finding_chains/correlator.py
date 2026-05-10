"""Build `FindingChain` entries from a normalised finding set.

Algorithm:
  1. Run every linker in `LINKER_REGISTRY` over the finding
     list; collect all `ChainLink` records.
  2. Union-find over (Finding.id, ChainLink) edges → connected
     components. Each component = one chain.
  3. For each component, compute aggregates: max severity,
     category union, narrative one-liner, chain type.
  4. Singletons (components of size 1) are NOT emitted as chains
     — they're ordinary findings; the caller already has them.

Output: list of `FindingChain`. Stable `chain_id` is derived
from the sorted finding-id tuple via SHA-1 (so re-running on
the same input gives the same chain ids).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Iterable

from strix.finding_chains.chain import (
    ChainLink,
    Finding,
    FindingChain,
)
from strix.finding_chains.links import LINKER_REGISTRY


logger = logging.getLogger(__name__)


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------


class _UnionFind:
    """Tiny DSU over string keys. Path compression + union-by-rank."""

    def __init__(self):
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def add(self, x: str) -> None:
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: str) -> str:
        # Path compression.
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> None:
        self.add(a)
        self.add(b)
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1


# ---------------------------------------------------------------------------
# Aggregate computation
# ---------------------------------------------------------------------------


def _max_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max(
        ((f.severity or "info").lower() for f in findings),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
    )


def _chain_type(categories: list[str]) -> str:
    """Classify the chain by the categories it spans."""
    s = set(categories)
    sca = "vulnerable_dependency" in s
    sast = "sast" in s
    iac = "misconfig" in s or "open_redirect" in s
    anomaly = "anomaly" in s
    dast = bool(
        s - {"vulnerable_dependency", "sast", "misconfig",
             "open_redirect", "anomaly", "license_violation",
             "malicious_dependency"}
    )
    if sca and dast and sast:
        return "sca_sast_dast"
    if sca and dast:
        return "sca_dast"
    if sast and dast:
        return "sast_dast"
    if iac and dast:
        return "iac_dast"
    if sca and sast:
        return "sca_sast"
    if anomaly and dast:
        return "anomaly_dast"
    return "mixed"


def _narrative(findings: list[Finding], chain_type: str) -> str:
    """One-line narrative for the chain. Wrappers render this
    as the chain header in the UI."""
    by_cat: dict[str, list[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    parts: list[str] = []
    # Order categories so the narrative reads "code-side first,
    # runtime-side second" — matches how reviewers think.
    for cat in (
        "vulnerable_dependency", "sast", "misconfig", "open_redirect",
        "info_disclosure", "anomaly",
    ):
        if cat in by_cat:
            for f in by_cat[cat][:1]:
                parts.append(f.title[:80])
            del by_cat[cat]
    # Remaining categories (runtime exploits etc.).
    for cat, items in by_cat.items():
        for f in items[:1]:
            parts.append(f.title[:80])
    return " → ".join(parts) if parts else f"chain ({chain_type})"


def _chain_id(finding_ids: list[str]) -> str:
    """Stable id derived from the sorted finding-id tuple."""
    key = "|".join(sorted(finding_ids))
    h = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    return f"chain-{h}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_chains(
    findings: Iterable[Finding],
    *,
    min_chain_size: int = 2,
) -> list[FindingChain]:
    """Run every linker over `findings`, build chains via
    union-find, return list of `FindingChain` of size
    >= `min_chain_size`.

    Singletons are excluded by default — the caller already has
    each individual finding via the existing emit path; this
    artifact is specifically about the cross-category groupings.
    """
    findings_list = list(findings)
    if not findings_list:
        return []

    by_id: dict[str, Finding] = {f.id: f for f in findings_list}

    # Run linkers, collect all links.
    all_links: list[ChainLink] = []
    for linker in LINKER_REGISTRY:
        try:
            all_links.extend(linker(findings_list))
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "finding_chains: linker %s failed: %s",
                linker.__name__, e, exc_info=True,
            )

    # Union-find over the link set.
    uf = _UnionFind()
    for f in findings_list:
        uf.add(f.id)
    for link in all_links:
        if link.finding_a in by_id and link.finding_b in by_id:
            uf.union(link.finding_a, link.finding_b)

    # Group by component root.
    components: dict[str, list[str]] = {}
    for f in findings_list:
        root = uf.find(f.id)
        components.setdefault(root, []).append(f.id)

    # Index links by component for emitting per-chain edges.
    links_by_root: dict[str, list[ChainLink]] = {}
    for link in all_links:
        if link.finding_a in by_id and link.finding_b in by_id:
            root = uf.find(link.finding_a)
            links_by_root.setdefault(root, []).append(link)

    # Build FindingChain per component.
    out: list[FindingChain] = []
    for root, ids in components.items():
        if len(ids) < min_chain_size:
            continue
        members = [by_id[i] for i in ids]
        # Order by severity descending so the wrapper renders
        # the highest-priority finding first.
        members.sort(
            key=lambda f: -_SEVERITY_RANK.get(
                (f.severity or "info").lower(), 0,
            ),
        )
        ordered_ids = [m.id for m in members]
        cats = sorted(set(m.category for m in members if m.category))
        ctype = _chain_type([m.category for m in members])
        out.append(FindingChain(
            chain_id=_chain_id(ordered_ids),
            finding_ids=ordered_ids,
            severity=_max_severity(members),
            summary=_narrative(members, ctype),
            categories=cats,
            links=links_by_root.get(root, []),
            chain_type=ctype,
        ))

    # Sort chains: highest severity → largest size → stable
    # chain_id for tie-break.
    out.sort(key=lambda c: (
        -_SEVERITY_RANK.get(c.severity, 0),
        -c.size,
        c.chain_id,
    ))
    return out


def write_finding_chains(
    chains: list[FindingChain],
    output_path: str | Path,
) -> Path:
    """Serialise + write the chains as `finding_chains.json`."""
    p = Path(output_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema_version": 1,
        "chains": [c.to_dict() for c in chains],
        "stats": {
            "total_chains": len(chains),
            "by_chain_type": _by_type_counts(chains),
            "by_severity": _by_severity_counts(chains),
        },
    }
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return p


def _by_type_counts(chains: list[FindingChain]) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in chains:
        out[c.chain_type] = out.get(c.chain_type, 0) + 1
    return out


def _by_severity_counts(chains: list[FindingChain]) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in chains:
        out[c.severity] = out.get(c.severity, 0) + 1
    return out
