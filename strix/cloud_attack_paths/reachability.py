"""Reachability scoring across the cloud graph.

masterroadmap §5 P0 — Wiz's killer noise-reducer. Operators
staring at 200 cloud findings need the answer to "which of these
is actually reachable from the public internet?". A finding on an
isolated bastion is structurally less urgent than the same
finding on a VM 1 hop from a public load balancer.

## Methodology (v1 — simplified)

Single-pass BFS from the set of internet-exposed resources,
walking the graph's typed edges as undirected for the purposes of
scoring. Each node receives a `reachability` score by BFS depth:

  * depth 0 (resource is `is_public=True` itself)        → **1.0**
  * depth 1 (1 hop from any public resource)             → **0.7**
  * depth 2                                              → **0.4**
  * depth 3                                              → **0.1**
  * unreachable                                          → **0.0**

For attack paths, the path's reachability is the **MAX** across
hops — the chain is as reachable as its most-reachable element,
because the attacker chooses the entry point.

## Why undirected v1

Wiz's reachability uses route tables + NACLs + Security Groups +
ENI attachments to compute precise directional reachability. Our
v1 graph doesn't yet model SG/NACL/route-table edges, so a
directional walk would under-report. The undirected
approximation over-reports — a finding flagged "reachable" by
this scorer might actually be unreachable due to network policy
we don't see. Over-reporting is the safer error: the wrapper
shows operators MORE findings to triage, not fewer.

v2 will add directional walks once the network-edge ingester
lands (SG → resource attachment, route table → subnet → ENI).
Documented as a TODO at the bottom of this file.

## Output shape

`compute_reachability(graph) → dict[node_key, float]`. Caller
typically attaches the score to each AttackPath via
`apply_reachability_to_paths(paths, scores)`.

Path's `reachability_score` attribute (added in this PR) is
populated in `analyze_cloud_attack_paths` when reachability is
computed. The wrapper sorts / filters findings by it.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Iterable

from strix.cloud_attack_paths.graph import (
    CloudEdge,
    CloudGraph,
    CloudResource,
)
from strix.cloud_attack_paths.patterns import AttackPath


logger = logging.getLogger(__name__)


# Depth → score curve. Tuned so:
#   * Direct exposure (1.0) is the alarm-bell case.
#   * 1 hop (0.7) is "the attacker compromises X and pivots to
#     this resource"; still high priority.
#   * 2 hops (0.4) is meaningful but takes attacker work.
#   * 3 hops (0.1) is the "reachable in theory" floor.
#   * 4+ hops (0.0) is structurally isolated for the purposes of
#     scoring — the operator should prioritise lower-hop
#     findings first.
_DEPTH_TO_SCORE: dict[int, float] = {
    0: 1.0, 1: 0.7, 2: 0.4, 3: 0.1,
}
_MAX_DEPTH = 3
_DEFAULT_SCORE = 0.0


# ---------------------------------------------------------------------------
# Core BFS
# ---------------------------------------------------------------------------


def _build_undirected_adjacency(
    graph: CloudGraph,
) -> dict[str, set[str]]:
    """Walk every edge once, build a node-keyed adjacency set.
    Treats edges as undirected for reachability scoring."""
    adj: dict[str, set[str]] = {}
    for e in graph.edges():
        if not e.from_key:
            continue
        adj.setdefault(e.from_key, set())
        if e.to_key:
            adj[e.from_key].add(e.to_key)
            adj.setdefault(e.to_key, set()).add(e.from_key)
    return adj


def _public_seed_set(graph: CloudGraph) -> set[str]:
    """Internet-exposed resources are the BFS seeds. Pulls from
    both the `is_public=True` resource attribute (CSPM /
    discovery-derived) AND the explicit `exposed_to_internet`
    edge (rule-derived) so a finding-only ingester that hasn't
    set the attribute still seeds correctly."""
    seeds: set[str] = set()
    for r in graph.public_resources():
        seeds.add(r.arn)
    return seeds


def compute_reachability(graph: CloudGraph) -> dict[str, float]:
    """BFS from all public resources; return a {node_key →
    reachability_score} map.

    Nodes not reachable within `_MAX_DEPTH` hops get score 0.0
    by absence — caller can `scores.get(arn, 0.0)` safely.
    """
    seeds = _public_seed_set(graph)
    if not seeds:
        return {}

    adj = _build_undirected_adjacency(graph)
    scores: dict[str, float] = {key: 1.0 for key in seeds}
    visited: set[str] = set(seeds)
    queue: deque[tuple[str, int]] = deque(
        (key, 0) for key in seeds
    )

    while queue:
        node, depth = queue.popleft()
        if depth >= _MAX_DEPTH:
            continue
        next_depth = depth + 1
        next_score = _DEPTH_TO_SCORE.get(next_depth, _DEFAULT_SCORE)
        for neighbour in adj.get(node, set()):
            if neighbour in visited:
                continue
            visited.add(neighbour)
            # When a node is reachable through multiple paths,
            # keep the HIGHEST score (shortest path = highest
            # reachability). Because BFS expands in depth order,
            # the first visit already has the highest possible
            # score; later revisits would be lower-depth which
            # we'd want to keep, but we skip via `visited`.
            # Equivalent semantics: take MIN(depth) = MAX(score)
            # which is what BFS gives us natively.
            scores[neighbour] = max(
                scores.get(neighbour, 0.0),
                next_score,
            )
            queue.append((neighbour, next_depth))

    return scores


# ---------------------------------------------------------------------------
# Attack-path scoring
# ---------------------------------------------------------------------------


def score_path(
    path: AttackPath, scores: dict[str, float],
) -> float:
    """Path reachability = MAX of any hop's reachability. The
    attacker picks the most-reachable hop as entry; the rest is
    lateral movement."""
    if not path.hops:
        return _DEFAULT_SCORE
    return max(
        scores.get(h, _DEFAULT_SCORE) for h in path.hops
    )


def apply_reachability_to_paths(
    paths: Iterable[AttackPath], scores: dict[str, float],
) -> None:
    """Mutate each path: stamp `metadata.reachability_score` AND
    set `path.reachability_score` for typed access. Idempotent
    — running twice yields the same result."""
    for p in paths:
        rs = score_path(p, scores)
        # Stash on metadata (JSON-safe surface for wrappers + the
        # tracer report). Also set as a typed attribute so the
        # `AttackPath.reachability_score` access pattern works.
        if p.metadata is None:
            p.metadata = {}
        p.metadata["reachability_score"] = rs
        # Re-bind the dataclass attribute (frozen-or-not-frozen
        # safety: AttackPath isn't frozen, so this assignment
        # works).
        try:
            object.__setattr__(p, "reachability_score", rs)
        except (AttributeError, TypeError):
            # Frozen dataclass safety net — wrappers can still
            # read from metadata.
            pass


# ---------------------------------------------------------------------------
# Severity-blended priority
# ---------------------------------------------------------------------------


_SEVERITY_RANK = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def compute_priority(
    severity: str, reachability_score: float,
) -> float:
    """Blend severity (4 levels) + reachability (continuous 0-1)
    into a single 0-1 priority score the wrapper can sort on.

    Formula: `severity_rank / 4 * 0.7 + reachability * 0.3`. The
    severity dominates (it's the underlying threat); reachability
    is the noise-reducer multiplier.

    A critical-severity finding on an isolated bastion (severity
    1.0 × 0.7 + 0.0 × 0.3 = 0.70) still ranks above a medium-
    severity finding on an internet-exposed asset (0.5 × 0.7 +
    1.0 × 0.3 = 0.65) — correctly. The reachability tier mostly
    breaks ties WITHIN a severity level.
    """
    sev_norm = _SEVERITY_RANK.get(
        (severity or "").lower(), 0,
    ) / 4.0
    rs = max(0.0, min(1.0, reachability_score))
    return round(sev_norm * 0.7 + rs * 0.3, 4)


# ---------------------------------------------------------------------------
# v2 TODO
# ---------------------------------------------------------------------------
#
# Reachability v2 (separate PR) will:
#
#   1. Add network-edge node types — VPC, subnet, route table,
#      ENI, SG, NACL.
#   2. Walk DIRECTIONAL edges only — ingress to a SG with
#      0.0.0.0/0 → instances → attached resources.
#   3. Model the actual SG / NACL rule semantics: a "reachable
#      from internet" port differential between SG inbound rules
#      and route-table internet-gateway targets.
#   4. Add bastion / VPN allow-list awareness — `10.0.0.0/16` is
#      reachable from inside the bastion BUT only if there's an
#      ingress path from the public internet TO the bastion.
#
# The v1 simplified scorer in this file is intentionally
# over-approximating — better to over-flag reachable-looking
# resources than under-flag. Wrappers sort by reachability AND
# severity; v1 noise reduction is meaningful even without
# directional edges.
