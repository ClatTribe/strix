"""Dataclasses for the chain artifact.

`Finding` is a normalised view of one emitted finding —
extracted from `vulnerabilities/*.md` or `vulnerabilities.json`
or an in-memory tracer report. The normaliser handles the
multiple input shapes; the linkers + correlator only see
`Finding`.

`ChainLink` is one binary edge between two findings, produced
by a linker (`name` identifies which heuristic fired).

`FindingChain` is the connected-component output: all findings
that share a transitive link, plus rollup aggregates for the
wrapper.

All shapes are JSON-serialisable so the artifact round-trips
through `finding_chains.json`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """Normalised view of one emitted finding."""
    id: str                  # stable ID — usually the tracer's report_id
    title: str
    category: str            # canonical category (sqli / vulnerable_dependency / etc.)
    severity: str            # info | low | medium | high | critical
    cwe: str | None = None    # "CWE-NNN" or None
    target: str = ""          # repo path / URL / IP
    endpoint: str = ""        # specific resource — file:line or /api/path
    description: str = ""
    cve: str | None = None    # SCA findings have this
    package: str = ""         # SCA-specific extracted package name
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title,
            "category": self.category, "severity": self.severity,
            "cwe": self.cwe, "target": self.target,
            "endpoint": self.endpoint, "description": self.description,
            "cve": self.cve, "package": self.package,
            "metadata": dict(self.metadata),
        }


@dataclass
class ChainLink:
    """One binary edge between two findings."""
    finding_a: str            # Finding.id
    finding_b: str            # Finding.id
    link_type: str            # which linker fired (e.g. 'sca_to_dast_cwe')
    confidence: float         # 0.0 - 1.0
    rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_a": self.finding_a,
            "finding_b": self.finding_b,
            "link_type": self.link_type,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


@dataclass
class FindingChain:
    """One connected component of correlated findings."""
    chain_id: str
    finding_ids: list[str]    # order: highest severity first
    severity: str             # max across the chain
    summary: str              # one-line narrative
    categories: list[str]     # union of categories represented
    links: list[ChainLink]    # the edges that built the chain
    chain_type: str = ""      # 'sca_dast' | 'sast_dast' | 'iac_dast' | 'mixed'

    @property
    def size(self) -> int:
        return len(self.finding_ids)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "finding_ids": list(self.finding_ids),
            "severity": self.severity,
            "summary": self.summary,
            "categories": list(self.categories),
            "links": [l.to_dict() for l in self.links],
            "chain_type": self.chain_type,
            "size": self.size,
        }
