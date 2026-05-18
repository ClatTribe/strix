---
name: kg-traversal-patterns
description: Walking Strix's cross-target knowledge graph — node + edge types, BFS queries, path scoring, finding adjacent assets
triggers: [kg, knowledge graph, graph query, bfs, path query, cross-target, kg_query, knowledge_graph]
---

# KG Traversal Patterns

Strix's knowledge graph (`agents/knowledge_graph.py` + `cloud_attack_paths/graph.py` + `kg_delta.jsonl` artifacts) is the substrate that makes cross-target reasoning possible. This skill teaches the agent how to **walk** the KG: which nodes / edges to query, which traversals are cheap vs expensive, how to score paths by reachability and severity. Companion to `cloud_attack_path_traversal.md` (cloud-specific) — this one is the **engine-wide KG**.

## The Typed KG (shipped via Decepticon uplift, PR #240)

### Node types (7)
| Kind | Created by |
|---|---|
| `Surface` | bfs_crawl, openapi_spec_ingest, HAR ingestion |
| `Asset` | cloud_attack_paths/discovery.py, repository import, container_image ingest |
| `Vuln` | every specialist that emits a finding (post-PR #242 kg_emit) |
| `Credential` | secrets_scan, code_search_for_domain |
| `Secret` | secrets_scan, aws_secrets_manager / postgres connection-string detection |
| `Dependency` | sca/scanner.py, sbom_extract |
| `Role` | cloud_attack_paths IAM walkers, repo CODEOWNERS parser |

### Edge types (7 + cross-target additions)
| Edge | Source → Destination | Created when |
|---|---|---|
| `AFFECTS` | Vuln → Surface / Asset | specialist emits finding with code_locations / endpoint |
| `REACHABLE_FROM` | Surface → Surface (internet) | reachability scorer (BFS from public LBs) |
| `LEAKS` | Surface → Credential | secrets_scan finds creds in response body |
| `GRANTS_ACCESS_TO` | Role → Asset | IAM walker (cloud_attack_paths) |
| `CHAINS_TO` | Vuln → Vuln | finding_chains correlator |
| `RUNS_ON` | Asset → Asset (host) | container running on EC2; pod on K8s node |
| `USES` | Asset → Dependency | SCA / SBOM tells which package versions |

Cross-target additions (when `STRIX_PROJECT_ID` is set, per PR #317):
| Edge | Source → Destination | Created when |
|---|---|---|
| `deploys_to` | Repository → Asset | CI / CD config detected |
| `pulls_from` | ContainerImage → Repository | image build manifest analyzed |
| `runs_in` | Repository → Asset | runtime config detected |
| `ingests_from` | Asset → External | data-pipeline config |

## Operational Runbook

### Step 1 — basic queries

Strix's lead-facing tools (in orchestrator mode):

```python
# All nodes of a kind, optionally filtered
kg_query_nodes(type="Vuln", filters={"severity": "critical"})

# All edges of a type
kg_query_edges(type="AFFECTS", filters={"category": "sql_injection"})

# Neighbours of a node
kg_query_neighbors(id="<node_id>", direction="out", edge_type="CHAINS_TO")

# BFS path between two nodes
kg_query_paths(start="<id1>", end="<id2>", max_hops=4, edge_types=["CHAINS_TO", "AFFECTS"])
```

### Step 2 — high-value path queries

**"What's between this public surface and a high-value asset?"**
```python
kg_query_paths(
    start="https://app.example.com",      # Surface (public)
    end="arn:aws:secretsmanager:...",      # Asset (high-value)
    edge_types=["AFFECTS", "CHAINS_TO", "GRANTS_ACCESS_TO"],
    max_hops=5,
)
# Returns: paths showing how an attacker on the public surface reaches the secret
```

**"Which Vulns share a Credential?"**
```python
# Find all Vulns that AFFECT a Surface that LEAKS the same Credential
credential_id = "<cred_id>"
surfaces_leaking = kg_query_neighbors(id=credential_id, direction="in", edge_type="LEAKS")
vulns_affecting = []
for s in surfaces_leaking:
    vulns_affecting.extend(kg_query_neighbors(id=s.id, direction="in", edge_type="AFFECTS"))
# vulns_affecting are correlated; they share the same leaked credential
```

**"Find the shortest path from a leaked repo cred to a public Asset"**
```python
# Use the cross-target edges (when project_id is stamped)
kg_query_paths(
    start="<repo_node_id>",
    end="<public_lb_id>",
    edge_types=["LEAKS", "deploys_to", "GRANTS_ACCESS_TO"],
    max_hops=4,
)
```

### Step 3 — reachability scoring

The `reachability.py` module assigns a `reachability_score` (0-1) to each node based on:
- BFS distance from public surfaces (closer → higher)
- Edge weights (some edges are "harder" to traverse than others)

```python
# Score every Vuln by reachability
for vuln in kg_query_nodes(type="Vuln"):
    score = compute_reachability(vuln.id)
    print(f"{vuln.id}: severity={vuln.severity}, reachability={score:.2f}")

# Combine: final priority = severity × reachability
```

This is the basis of "Wiz-style noise reduction" — a critical vuln on an isolated bastion is lower-priority than a medium vuln on a public LB.

### Step 4 — chain detection

When the orchestrator finishes a scan, `correlate_findings` (PR #294) walks the graph for known chain patterns:

```
Vuln(category=xss) AFFECTS Surface → CHAINS_TO → Vuln(category=cookie_theft) → CHAINS_TO → Vuln(category=idor)
```

The chain becomes a single bundled finding with elevated severity (chain ≥ sum-of-parts).

Known chains worth querying for explicitly:
- `xss → cookie_theft → session_hijack`
- `ssrf → cloud_metadata → iam_credentials → resource_takeover`
- `sql_injection → secret_exfil → cross_target_compromise`
- `prototype_pollution → property_gadget → rce`
- `deserialization → gadget_chain → rce → lateral`

### Step 5 — wrapper-side cross-scan union

Engine emits `kg_delta.jsonl` per scan (PR #318). Wrapper's KG store unions deltas across all scans in a project:

```bash
# Engine emission (read-only at the engine boundary)
cat /var/run/strix/runs/<id>/kg_delta.jsonl | head

# Sample shape:
{"op": "add_node", "kind": "Vuln", "id": "v123", "attrs": {...}, "scan_id": "..."}
{"op": "add_edge", "type": "AFFECTS", "src": "v123", "dst": "surface_456"}
```

The wrapper unions these into one project-wide graph; cross-scan paths reach across multi-target boundaries.

## Pro Tips

1. The KG is **append-only per scan** + **union-on-load wrapper-side**. Don't try to mutate; query and add.
2. `kg_query_paths` with `max_hops=5` is the practical ceiling — paths longer than that are usually too speculative.
3. Edge-type filtering is the most powerful optimisation; un-filtered BFS blows up exponentially on dense graphs.
4. The `evidence` field on each edge is gold for finding context: "AFFECTS via /api/users?id=42 with payload `' OR 1=1--`".
5. The KG is persisted to `<run_dir>/kg.json` per scan; wrapper unions into `kg.json` per project for path-query mode.

## Validation

The KG is correct when:
1. Every Vuln has at least one AFFECTS edge to a Surface or Asset (no floating findings).
2. Every Credential has at least one LEAKS or GRANTS_ACCESS_TO edge.
3. BFS queries return paths only if all edges exist (no phantom edges from stale data).
4. `kg_query_paths(start, end, ...)` is symmetric on directed edges (only finds paths *out* from start).

## Summary

The KG is Strix's reasoning substrate. Query it before dispatching specialists (to know what's already known), traverse it to find chains, and emit deltas so cross-scan reasoning compounds. The cross-target story is only as good as the agent's KG fluency.
