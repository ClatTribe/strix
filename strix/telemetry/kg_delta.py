"""engine-wishlist §8 — `kg_delta.jsonl` emission.

The engine already builds a rich cross-resource graph internally
(`cloud_attack_paths.CloudGraph` with CloudResource /
CloudIdentity / CloudPolicy nodes and can_assume / attached_to /
exposed_to_internet / grants_access_to / has_policy edges). PRs
#297 / #299 / #310 / #311 populate it for AWS / Azure / GCP
including multi-account fan-out. Multi-account already unions
cross-account edges into one graph spanning an AWS Organisation.

**None of this graph crosses the engine → wrapper boundary as
structured data today.** §6 + §4 get the wrapper finding-level
cross-target reasoning ("same CVE in N services → 1 root finding,
N affected"). §8 adds **path-level cross-target reasoning** —
"this repo's deploy IAM role can reach that account's S3 bucket
exposed at that endpoint" — by emitting per-scan graph deltas
the wrapper's KG store can union across all scans in a project.

## Op vocabulary

Two op-types per line:

```jsonl
{"op": "add_node", "kind": "CloudResource", "id": "arn:aws:s3:::x", "attrs": {...}, "scan_id": "...", "project_id": "...", "source": "..."}
{"op": "add_edge", "type": "can_assume", "src": "arn:...:user/y", "dst": "arn:...:role/z", "evidence": "...", "scan_id": "...", "project_id": "..."}
```

Node kinds (mirrors `CloudGraph`'s internal vocabulary):

  * `CloudResource` — buckets, instances, lambdas, etc.
  * `CloudIdentity` — IAM principals, managed identities,
    service accounts.
  * `CloudPolicy` — policy documents / role definitions.
  * `Repository`, `ContainerImage`, `Endpoint`, `Service`
    — cross-target-type nodes the wrapper can stamp post-hoc
    when project_id is set.

Edge types:

  * `can_assume`, `attached_to`, `exposed_to_internet`,
    `grants_access_to`, `has_policy` — existing intra-account
    edges from `CloudGraph`.
  * `deploys_to`, `pulls_from`, `runs_in`, `ingests_from`
    — cross-target-type edges (wrapper-stamped post-hoc when
    project_id is set).

## Scope hygiene (engine boundary)

The engine ONLY emits deltas. It does NOT:

  * Persist the cross-scan graph (wrapper's KG store does).
  * Do cross-scan graph union (wrapper does, scoped by
    project_id).
  * Answer path queries (wrapper does).
  * Compute cross-target reachability (wrapper does).

The single-scan attack-path detection (`patterns.py` matching
against `CloudGraph`) stays per-scan and unchanged. §8 is purely
about making the same graph state consumable for cross-scan
reasoning at the wrapper.

## Compatibility

Additive artefact. Scans that don't build a graph (single-repo
SAST etc) emit nothing. Same structural-data discipline as §4.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal


logger = logging.getLogger(__name__)


# Edge vocabulary — these are the existing CloudGraph edge kinds
# the engine already produces internally. Future cross-target-type
# edges (deploys_to / pulls_from / runs_in / ingests_from) get
# emitted by other producers; the writer doesn't enforce a
# closed set so the wrapper can extend without engine releases.
_INTRA_ACCOUNT_EDGES = frozenset({
    "can_assume",
    "attached_to",
    "exposed_to_internet",
    "grants_access_to",
    "has_policy",
})


@dataclass
class KgNodeDelta:
    """`{"op": "add_node", ...}` row."""

    kind: str
    id: str
    attrs: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    scan_id: str | None = None
    project_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "op": "add_node",
            "kind": self.kind,
            "id": self.id,
            "attrs": dict(self.attrs),
        }
        if self.source:
            out["source"] = self.source
        if self.scan_id:
            out["scan_id"] = self.scan_id
        if self.project_id:
            out["project_id"] = self.project_id
        return out


@dataclass
class KgEdgeDelta:
    """`{"op": "add_edge", ...}` row.

    `dst=None` is legal — it encodes the "exposed_to_internet"
    edge in `CloudGraph` which has no concrete target node (the
    target is the internet abstraction).
    """

    type: str
    src: str
    dst: str | None
    evidence: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    scan_id: str | None = None
    project_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "op": "add_edge",
            "type": self.type,
            "src": self.src,
            "dst": self.dst,
        }
        if self.evidence:
            out["evidence"] = self.evidence
        if self.attrs:
            out["attrs"] = dict(self.attrs)
        if self.source:
            out["source"] = self.source
        if self.scan_id:
            out["scan_id"] = self.scan_id
        if self.project_id:
            out["project_id"] = self.project_id
        return out


# ---------------------------------------------------------------------------
# CloudGraph → deltas
# ---------------------------------------------------------------------------


def _node_kind(node: Any) -> str:
    """Map an engine-internal node object to its `kind` field for
    the delta vocabulary. Falls back to the class name when the
    node is a future / unknown type."""
    cls_name = type(node).__name__
    # The internal class names already match the wishlist vocab.
    if cls_name in ("CloudResource", "CloudIdentity", "CloudPolicy"):
        return cls_name
    return cls_name


def _node_attrs(node: Any) -> dict[str, Any]:
    """Render the engine-internal node's serialisable state as
    `attrs`. Uses the node's `to_dict()` when available; falls
    back to dataclass-field extraction."""
    if hasattr(node, "to_dict") and callable(node.to_dict):
        try:
            d = node.to_dict()
            if isinstance(d, dict):
                # Drop the node identity from attrs — it's encoded
                # in the row's `id` field.
                d.pop("node_key", None)
                d.pop("arn", None)
                return d
        except Exception:  # noqa: BLE001
            pass
    # Best-effort dataclass projection.
    try:
        from dataclasses import asdict, is_dataclass  # noqa: PLC0415
        if is_dataclass(node):
            d = asdict(node)
            d.pop("node_key", None)
            d.pop("arn", None)
            return d
    except Exception:  # noqa: BLE001
        pass
    return {}


def from_cloud_graph(
    graph: Any,
    *,
    scan_id: str | None = None,
    project_id: str | None = None,
    source_prefix: str = "cloud_attack_paths",
) -> tuple[list[KgNodeDelta], list[KgEdgeDelta]]:
    """Walk a `CloudGraph` and emit one node delta per node + one
    edge delta per edge.

    `source` per-row encodes provenance (`<source_prefix>:nodes`
    / `<source_prefix>:edges`) so the wrapper can attribute
    graph state back to the engine module that produced it.

    Returns `(node_deltas, edge_deltas)` so the writer / tracer
    consume them as a flat stream.
    """
    nodes: list[KgNodeDelta] = []
    edges: list[KgEdgeDelta] = []

    if graph is None:
        return nodes, edges

    # Nodes
    try:
        node_iter: Iterable[Any] = graph.nodes()
    except Exception as e:  # noqa: BLE001
        logger.debug("kg_delta: graph.nodes() failed: %s", e)
        node_iter = []
    for node in node_iter:
        node_id = getattr(node, "node_key", None) or getattr(node, "arn", None)
        if not node_id:
            continue
        nodes.append(KgNodeDelta(
            kind=_node_kind(node),
            id=str(node_id),
            attrs=_node_attrs(node),
            source=f"{source_prefix}:nodes",
            scan_id=scan_id,
            project_id=project_id,
        ))

    # Edges
    try:
        edge_iter: Iterable[Any] = graph.edges()
    except Exception as e:  # noqa: BLE001
        logger.debug("kg_delta: graph.edges() failed: %s", e)
        edge_iter = []
    for edge in edge_iter:
        from_key = getattr(edge, "from_key", None)
        to_key = getattr(edge, "to_key", None)
        kind = getattr(edge, "kind", None)
        if not from_key or not kind:
            continue
        attrs_tup = getattr(edge, "attributes", None) or ()
        try:
            attrs = dict(attrs_tup)
        except (TypeError, ValueError):
            attrs = {}
        edges.append(KgEdgeDelta(
            type=str(kind),
            src=str(from_key),
            dst=str(to_key) if to_key is not None else None,
            attrs=attrs,
            source=f"{source_prefix}:edges",
            scan_id=scan_id,
            project_id=project_id,
        ))

    return nodes, edges


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def emit_kg_deltas(
    run_dir: Path,
    nodes: list[KgNodeDelta],
    edges: list[KgEdgeDelta],
) -> Path | None:
    """Write `kg_delta.jsonl` to `run_dir`. Returns the path or
    None when there's nothing to emit (per the §8 contract: no
    forced empty file).

    Order: all `add_node` rows first, then `add_edge`. The
    wrapper's reader is order-agnostic but emitting nodes first
    means an `add_edge` never references an unknown id within
    the same scan's delta.
    """
    if not nodes and not edges:
        return None
    out_path = run_dir / "kg_delta.jsonl"
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for n in nodes:
                f.write(json.dumps(n.to_dict(), ensure_ascii=False))
                f.write("\n")
            for e in edges:
                f.write(json.dumps(e.to_dict(), ensure_ascii=False))
                f.write("\n")
    except OSError as err:
        logger.warning(
            "emit_kg_deltas: write failed (%s): %s", out_path, err,
        )
        return None
    return out_path
