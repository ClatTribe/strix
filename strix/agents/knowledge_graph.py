"""Persistent typed knowledge graph (§3 of strixredteam.md).

The existing `chaining_graph.py` walks the finding list looking
for known A→B patterns after-the-fact. Useful for reporting but
not a planning substrate the agent can query forward.

This module adds a typed graph the agent populates while testing
and queries to find unexplored chains. The shape matches the
§3 doc's AppSec-tuned node/edge taxonomy.

## Nodes (canonical types)

| Type | Properties (illustrative) |
|---|---|
| `Surface` | url, method, params, auth_state |
| `Asset` | type (repo/domain/url/ip), value |
| `Vuln` | cwe, owasp, severity, confidence, verification_status, finding_id |
| `Credential` | username, source, scope |
| `Secret` | type (api-key, jwt, db), source_finding |
| `Dependency` | name, version, ecosystem, cve_ids |
| `Role` | name, capabilities |

## Edges (canonical types)

| Edge | Meaning |
|---|---|
| `AFFECTS` | Vuln → Surface / Dependency |
| `REACHABLE_FROM` | Surface → Surface (auth chain) |
| `LEAKS` | Vuln → Secret / Credential |
| `GRANTS_ACCESS_TO` | Credential → Surface |
| `CHAINS_TO` | Vuln → Vuln (replaces in-memory chain edges) |
| `RUNS_ON` | Surface → Asset |
| `USES` | Surface → Dependency |
| `PIVOTED_FROM` | Vuln → Vuln (target found by exploit-pivoting from source) |
| `EXPLOITS` | Exploit → Vuln (MOAK-style synthesised exploit attached to a CVE Vuln) |

The taxonomies are **enforced** by `add_node` / `add_edge` —
unknown types are rejected so the graph stays queryable.

## Persistence

The graph lives in `<run_dir>/kg.json` (one JSON file). On the
ClatTribe AppSec scale (a single target run typically ≤500 nodes,
≤2K edges) this is well under a megabyte and the serialise/
deserialise cost is negligible.

Append-after-mutation: every `add_node` / `add_edge` /
`update_node` triggers a write. Crash-safe by virtue of being
single-file (no partial writes possible because we write
atomically via `Path.write_text`).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_KG_DISABLED` | unset | Kill switch — graph operations no-op |
| `STRIX_KG_PERSIST` | "1" | Set to "0" to skip kg.json writes (in-memory only) |
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


logger = logging.getLogger(__name__)


NodeType = Literal[
    "Surface",
    "Asset",
    "Vuln",
    "Credential",
    "Secret",
    "Dependency",
    "Role",
    # P4 — threat-intel projection. Scanners like vt_reputation,
    # kev_diff, nvd_lookup, hibp_breach, otx_lookup, etc. produce
    # observations that don't fit the Vuln→Surface→AFFECTS triple.
    # `ThreatIntel` records the source + verdict; `OBSERVED`
    # connects it to the Asset it concerns.
    "ThreatIntel",
    # Depth-of-attack — synthesised exploit artifact (MOAK-style
    # CVE exploit-synthesiser output). Props include: cve,
    # exploit_script_path, captured_flag_path, judge_score,
    # is_genuine.
    "Exploit",
]
EdgeType = Literal[
    "AFFECTS",
    "REACHABLE_FROM",
    "LEAKS",
    "GRANTS_ACCESS_TO",
    "CHAINS_TO",
    "RUNS_ON",
    "USES",
    # P4 — ThreatIntel → Asset (the observation's subject).
    "OBSERVED",
    # Depth-of-attack — Vuln → Vuln, recording that the target Vuln
    # was discovered by post-exploit pivoting from the source Vuln's
    # captured proof-of-impact. Distinct from `CHAINS_TO` which is a
    # narrative correlation at report-time; `PIVOTED_FROM` is a
    # forward attack edge — the source's exploit *caused* the target
    # to be found.
    "PIVOTED_FROM",
    # Depth-of-attack — Exploit → Vuln, recording that a synthesised
    # MOAK-style working exploit was built for a Vuln node carrying
    # a CVE. The Exploit node holds the captured flag + judge score.
    "EXPLOITS",
]


_VALID_NODE_TYPES: frozenset[str] = frozenset({
    "Surface", "Asset", "Vuln", "Credential",
    "Secret", "Dependency", "Role",
    "ThreatIntel", "Exploit",
})
_VALID_EDGE_TYPES: frozenset[str] = frozenset({
    "AFFECTS", "REACHABLE_FROM", "LEAKS", "GRANTS_ACCESS_TO",
    "CHAINS_TO", "RUNS_ON", "USES",
    "OBSERVED", "PIVOTED_FROM", "EXPLOITS",
})


@dataclass
class GraphNode:
    """One vertex in the KG. `id` is auto-assigned (`N-001`,
    `N-002`, ...). `props` is open-schema — the type system gates
    on `type`, not on the property keys."""
    id: str
    type: NodeType
    props: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    """One directed edge. `id` is auto-assigned (`E-001`, ...).
    `props` carries optional metadata (confidence, evidence-finding-id,
    discovered-by-tool, etc.)."""
    id: str
    type: EdgeType
    source: str  # Node id
    target: str  # Node id
    props: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class KnowledgeGraph:
    """The graph itself. Process-global singleton via `get_kg()`."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        # Adjacency lists for forward + reverse traversal.
        self._out_edges: dict[str, list[str]] = {}  # node_id → edge_ids
        self._in_edges: dict[str, list[str]] = {}
        self._next_node_id = 1
        self._next_edge_id = 1

    # ---- mutations ----------------------------------------------------

    def add_node(
        self, *, type: NodeType, props: dict[str, Any] | None = None,  # noqa: A002
    ) -> GraphNode:
        if type not in _VALID_NODE_TYPES:
            raise ValueError(
                f"invalid node type {type!r}; allowed: {sorted(_VALID_NODE_TYPES)}"
            )
        with self._lock:
            node_id = f"N-{self._next_node_id:03d}"
            self._next_node_id += 1
            node = GraphNode(id=node_id, type=type, props=dict(props or {}))
            self._nodes[node_id] = node
            self._out_edges[node_id] = []
            self._in_edges[node_id] = []
        _persist(self)
        return node

    def add_edge(
        self,
        *,
        type: EdgeType,  # noqa: A002
        source: str,
        target: str,
        props: dict[str, Any] | None = None,
    ) -> GraphEdge:
        if type not in _VALID_EDGE_TYPES:
            raise ValueError(
                f"invalid edge type {type!r}; allowed: {sorted(_VALID_EDGE_TYPES)}"
            )
        with self._lock:
            if source not in self._nodes:
                raise ValueError(f"source node not found: {source}")
            if target not in self._nodes:
                raise ValueError(f"target node not found: {target}")
            edge_id = f"E-{self._next_edge_id:03d}"
            self._next_edge_id += 1
            edge = GraphEdge(
                id=edge_id, type=type, source=source, target=target,
                props=dict(props or {}),
            )
            self._edges[edge_id] = edge
            self._out_edges.setdefault(source, []).append(edge_id)
            self._in_edges.setdefault(target, []).append(edge_id)
        _persist(self)
        return edge

    def update_node(
        self,
        node_id: str,
        *,
        props: dict[str, Any] | None = None,
    ) -> GraphNode | None:
        """Merge new props into the node. Returns None if unknown."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node is None:
                return None
            if props:
                node.props.update(props)
                node.updated_at = time.time()
        _persist(self)
        return node

    # ---- queries ------------------------------------------------------

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge | None:
        return self._edges.get(edge_id)

    def query_nodes(
        self,
        *,
        type: NodeType | None = None,  # noqa: A002
        filters: dict[str, Any] | None = None,
    ) -> list[GraphNode]:
        """Filter nodes by type + property equality. `filters` is
        AND-conjunction: every key/value pair must match. None
        values match anything."""
        with self._lock:
            results = list(self._nodes.values())
        if type is not None:
            results = [n for n in results if n.type == type]
        if filters:
            results = [
                n for n in results
                if all(n.props.get(k) == v for k, v in filters.items())
            ]
        return sorted(results, key=lambda n: n.id)

    def query_edges(
        self,
        *,
        type: EdgeType | None = None,  # noqa: A002
        source: str | None = None,
        target: str | None = None,
    ) -> list[GraphEdge]:
        with self._lock:
            results = list(self._edges.values())
        if type is not None:
            results = [e for e in results if e.type == type]
        if source is not None:
            results = [e for e in results if e.source == source]
        if target is not None:
            results = [e for e in results if e.target == target]
        return sorted(results, key=lambda e: e.id)

    def query_paths(
        self,
        *,
        start_id: str,
        end_id: str,
        max_hops: int = 6,
        edge_types: list[EdgeType] | None = None,
    ) -> list[list[str]]:
        """BFS for paths from start → end. Returns a list of paths,
        each path is a list of node IDs alternating start..end.
        `max_hops` caps depth; `edge_types` (when given) restricts
        edges considered.

        Order: shortest paths first; ties broken by insertion order.
        Cap at 50 distinct paths to avoid blowing up on dense graphs.
        """
        if start_id not in self._nodes or end_id not in self._nodes:
            return []

        allowed_edge_types: set[str] | None
        allowed_edge_types = set(edge_types) if edge_types else None

        results: list[list[str]] = []
        # BFS queue holds (current_node, path_so_far).
        queue: deque[tuple[str, list[str]]] = deque([(start_id, [start_id])])

        while queue and len(results) < 50:
            current, path = queue.popleft()
            if current == end_id and len(path) > 1:
                results.append(path)
                continue
            if len(path) - 1 >= max_hops:
                continue
            for edge_id in self._out_edges.get(current, []):
                edge = self._edges[edge_id]
                if (
                    allowed_edge_types is not None
                    and edge.type not in allowed_edge_types
                ):
                    continue
                nxt = edge.target
                if nxt in path:
                    continue  # avoid cycles
                queue.append((nxt, [*path, nxt]))
        return results

    def neighbors(
        self,
        node_id: str,
        *,
        direction: Literal["out", "in", "both"] = "out",
        edge_type: EdgeType | None = None,
    ) -> list[GraphNode]:
        """Adjacent nodes. `direction=out` follows outgoing edges
        (default); `in` follows incoming; `both` returns the union."""
        with self._lock:
            collected: set[str] = set()
            if direction in ("out", "both"):
                for eid in self._out_edges.get(node_id, []):
                    e = self._edges[eid]
                    if edge_type is None or e.type == edge_type:
                        collected.add(e.target)
            if direction in ("in", "both"):
                for eid in self._in_edges.get(node_id, []):
                    e = self._edges[eid]
                    if edge_type is None or e.type == edge_type:
                        collected.add(e.source)
            nodes = [self._nodes[nid] for nid in collected if nid in self._nodes]
        return sorted(nodes, key=lambda n: n.id)

    # ---- introspection ------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            node_type_counts: dict[str, int] = {}
            edge_type_counts: dict[str, int] = {}
            for n in self._nodes.values():
                node_type_counts[n.type] = node_type_counts.get(n.type, 0) + 1
            for e in self._edges.values():
                edge_type_counts[e.type] = edge_type_counts.get(e.type, 0) + 1
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "node_types": node_type_counts,
            "edge_types": edge_type_counts,
        }

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "version": 1,
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges.values()],
                "next_node_id": self._next_node_id,
                "next_edge_id": self._next_edge_id,
            }

    def load_dict(self, data: dict[str, Any]) -> None:
        """Restore from a serialised form. Replaces any current state."""
        with self._lock:
            self._nodes = {}
            self._edges = {}
            self._out_edges = {}
            self._in_edges = {}
            for raw in data.get("nodes", []):
                n = GraphNode(
                    id=raw["id"],
                    type=raw["type"],
                    props=raw.get("props", {}),
                    created_at=raw.get("created_at", time.time()),
                    updated_at=raw.get("updated_at", time.time()),
                )
                self._nodes[n.id] = n
                self._out_edges[n.id] = []
                self._in_edges[n.id] = []
            for raw in data.get("edges", []):
                e = GraphEdge(
                    id=raw["id"],
                    type=raw["type"],
                    source=raw["source"],
                    target=raw["target"],
                    props=raw.get("props", {}),
                    created_at=raw.get("created_at", time.time()),
                )
                self._edges[e.id] = e
                if e.source in self._out_edges:
                    self._out_edges[e.source].append(e.id)
                if e.target in self._in_edges:
                    self._in_edges[e.target].append(e.id)
            self._next_node_id = int(data.get("next_node_id", len(self._nodes) + 1))
            self._next_edge_id = int(data.get("next_edge_id", len(self._edges) + 1))

    def reset(self) -> None:
        """Test helper. Production code should never call this."""
        with self._lock:
            self._nodes = {}
            self._edges = {}
            self._out_edges = {}
            self._in_edges = {}
            self._next_node_id = 1
            self._next_edge_id = 1


# ---------------------------------------------------------------------------
# Singleton + config
# ---------------------------------------------------------------------------


_kg: KnowledgeGraph | None = None
_kg_lock = threading.Lock()


def get_kg() -> KnowledgeGraph:
    global _kg  # noqa: PLW0603
    with _kg_lock:
        if _kg is None:
            _kg = KnowledgeGraph()
        return _kg


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_KG_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _persistence_enabled() -> bool:
    raw = os.environ.get("STRIX_KG_PERSIST", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def reset_for_testing() -> None:
    """Reset the module-global graph. Tests MUST call this in
    fixtures."""
    global _kg  # noqa: PLW0603
    with _kg_lock:
        _kg = None


def _resolve_run_dir() -> Path | None:
    """Same lookup pattern as output_tiering / objective_tracker."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None and hasattr(tracer, "get_run_dir"):
            d = tracer.get_run_dir()
            if d is not None:
                return Path(d)
    except Exception:  # noqa: BLE001
        pass
    env_dir = os.environ.get("STRIX_RUN_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return None


def _persist(kg: KnowledgeGraph) -> None:
    """Atomically rewrite `<run_dir>/kg.json`. Best-effort."""
    if not _persistence_enabled():
        return
    run_dir = _resolve_run_dir()
    if run_dir is None:
        return
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / "kg.json"
        tmp = run_dir / "kg.json.tmp"
        tmp.write_text(
            json.dumps(kg.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        tmp.replace(out)
    except OSError as e:
        logger.debug("could not persist kg.json: %s", e)


def load_kg_from_disk(path: Path | str | None = None) -> KnowledgeGraph | None:
    """Restore the singleton from a kg.json file.

    Args:
      path: optional explicit path. When None, defaults to
        `<run_dir>/kg.json` — the canonical resume location.
        Pass an arbitrary path to seed the graph from a previous
        run's artifact (the CI delta-scan use case).

    Returns the loaded graph, or None if no file exists / fails
    to parse."""
    if path is None:
        run_dir = _resolve_run_dir()
        if run_dir is None:
            return None
        path = run_dir / "kg.json"
    else:
        path = Path(path)

    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("could not load kg.json (%s): %s", path, e)
        return None
    kg = get_kg()
    kg.load_dict(data)
    return kg


def load_seed_kg_from_env() -> KnowledgeGraph | None:
    """If `STRIX_KG_SEED_PATH` is set, load that kg.json as the
    starting graph. Used for CI delta-scan: mount the previous
    run's artifact into the sandbox and point this env var at it.

    The seed graph is loaded BEFORE the current scan starts, so
    every new finding emitted during this run is added on top of
    the prior run's surface map. Re-finding a known vuln re-emits
    against the same Surface; novel findings appear as new nodes.

    Returns the loaded graph (the singleton, already populated)
    or None when:
      * the env var is unset, OR
      * the path doesn't exist, OR
      * `STRIX_KG_DISABLED=1` (kill switch wins).

    Best-effort — invalid JSON / unreadable file → returns None
    with a warning log, doesn't abort scan start."""
    if is_disabled():
        return None
    seed_path = os.environ.get("STRIX_KG_SEED_PATH", "").strip()
    if not seed_path:
        return None
    return load_kg_from_disk(seed_path)


def get_kg_stats() -> dict[str, Any]:
    """Telemetry snapshot."""
    if is_disabled():
        return {"enabled": False, "node_count": 0, "edge_count": 0}
    return {"enabled": True, **get_kg().stats()}
