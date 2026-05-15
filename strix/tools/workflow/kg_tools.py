"""Lead-facing knowledge-graph tools (§3 typed KG).

Five tools mirroring Decepticon's KG API shape:

  * `kg_create_node(type, props_json)`         — add a typed vertex
  * `kg_create_edge(type, source, target, ...)` — add a directed edge
  * `kg_query_nodes(type=, filters_json=)`     — typed + property filter
  * `kg_query_paths(start_id, end_id, ...)`   — BFS path search
  * `kg_stats()`                               — node/edge counts by type

Same lazy-import pattern as the other workflow tools so we don't
re-enter `strix.agents.__init__` → `BaseAgent` → `strix.llm`.

Properties (`props`) are passed as JSON-encoded strings because the
strix tool registry's parameter signatures are typed scalars + str.
The dict shape is the wire format documented in
`strix/agents/knowledge_graph.py`.
"""

from __future__ import annotations

import json
from typing import Any

from strix.tools.registry import register_tool


def _kg():
    from strix.agents.knowledge_graph import get_kg  # noqa: PLC0415
    return get_kg()


def _parse_json_props(raw: str | None, field_name: str) -> dict[str, Any] | None:
    """Permissive JSON parse — empty/None returns None; malformed
    returns an error dict the caller can pass back to the agent."""
    if not raw or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON for {field_name}: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError(
            f"{field_name} must be a JSON object, got {type(parsed).__name__}",
        )
    return parsed


@register_tool(sandbox_execution=False, mitre_techniques=[])
def kg_create_node(
    type: str,  # noqa: A002
    props_json: str = "",
) -> dict[str, Any]:
    """Create a typed node in the knowledge graph.

    Args:
      type: one of `Surface`, `Asset`, `Vuln`, `Credential`,
        `Secret`, `Dependency`, `Role`.
      props_json: JSON object encoding the node's properties
        (e.g. `{"url": "/api/users", "method": "GET",
        "auth_state": "authenticated"}` for a Surface).

    Returns:
      `{"success": True, "node": {...}}` with the auto-assigned
      ID (`N-001`) or `{"success": False, "error": ...}`.
    """
    try:
        props = _parse_json_props(props_json, "props_json")
        node = _kg().add_node(type=type, props=props)  # type: ignore[arg-type]
    except ValueError as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "node": node.to_dict()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def kg_create_edge(
    type: str,  # noqa: A002
    source: str,
    target: str,
    props_json: str = "",
) -> dict[str, Any]:
    """Create a typed directed edge between two existing nodes.

    Args:
      type: one of `AFFECTS`, `REACHABLE_FROM`, `LEAKS`,
        `GRANTS_ACCESS_TO`, `CHAINS_TO`, `RUNS_ON`, `USES`.
      source: source node ID (`N-...`).
      target: target node ID (`N-...`).
      props_json: JSON metadata (confidence, evidence finding ID,
        discovered-by-tool, etc.).

    Returns:
      `{"success": True, "edge": {...}}` or
      `{"success": False, "error": ...}`.
    """
    try:
        props = _parse_json_props(props_json, "props_json")
        edge = _kg().add_edge(
            type=type, source=source, target=target, props=props,  # type: ignore[arg-type]
        )
    except ValueError as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "edge": edge.to_dict()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def kg_query_nodes(
    type: str | None = None,  # noqa: A002
    filters_json: str = "",
) -> dict[str, Any]:
    """Find nodes by type and/or property filter.

    Args:
      type: optional node-type filter (one of the canonical types).
      filters_json: JSON object of property-equality filters. All
        keys must match (AND).

    Returns:
      `{"total": <int>, "nodes": [<dict>, ...]}`.
    """
    try:
        filters = _parse_json_props(filters_json, "filters_json")
    except ValueError as e:
        return {"success": False, "error": str(e)}
    nodes = _kg().query_nodes(type=type, filters=filters)  # type: ignore[arg-type]
    return {
        "total": len(nodes),
        "nodes": [n.to_dict() for n in nodes],
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def kg_query_paths(
    start_id: str,
    end_id: str,
    max_hops: int = 6,
    edge_types: str = "",
) -> dict[str, Any]:
    """Find directed paths from `start_id` to `end_id` (BFS,
    shortest-first).

    Args:
      start_id, end_id: node IDs (`N-...`).
      max_hops: maximum path length. Default 6 (a five-step kill chain
        is the longest typically interesting in AppSec).
      edge_types: optional CSV of edge types to restrict to (e.g.
        `LEAKS,GRANTS_ACCESS_TO,REACHABLE_FROM`).

    Returns:
      `{"total": <int>, "paths": [["N-001","N-002","N-003"], ...]}`.
      Empty list when start/end unknown or no path exists. Cap at
      50 distinct paths to avoid blow-up on dense graphs.
    """
    edge_types_list: list[str] | None = None
    if edge_types:
        edge_types_list = [
            t.strip() for t in edge_types.split(",") if t.strip()
        ]

    paths = _kg().query_paths(
        start_id=start_id,
        end_id=end_id,
        max_hops=max_hops,
        edge_types=edge_types_list,  # type: ignore[arg-type]
    )
    return {
        "total": len(paths),
        "paths": paths,
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def kg_stats() -> dict[str, Any]:
    """Quick snapshot: total node/edge counts, broken down by type.
    Useful for the lead to decide "have I built up enough structure
    to query for chains yet?"."""
    from strix.agents.knowledge_graph import get_kg_stats  # noqa: PLC0415
    return get_kg_stats()
