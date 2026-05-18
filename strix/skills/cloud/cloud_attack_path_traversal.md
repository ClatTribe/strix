---
name: cloud-attack-path-traversal
description: How to walk Strix's cloud knowledge graph — node + edge types, BFS path queries, reachability scoring, multi-cloud
triggers: [cloud kg, knowledge graph, attack path, graph traversal, reachability, cloudgraph, can_assume, grants_access]
---

# Cloud Attack-Path Traversal

Strix's cloud capability is **graph-shaped**. `cloud_attack_paths/graph.py` defines a typed KG: nodes are resources / identities / policies; edges are trust / access / network reachability relationships. The 27 attack patterns in `patterns.py` are graph traversals over this KG. This skill teaches the agent (and you) how to read, walk, and extend that graph.

Companion to: `cloud_attack_paths/{graph,patterns,reachability,multi_account,live_probes}.py`.

## Schema

### Node kinds (7 types)

| Kind | Examples |
|---|---|
| `CloudResource` | S3 bucket, RDS instance, Lambda function, EC2 instance, GCS bucket, BigQuery dataset, Azure Storage account |
| `CloudIdentity` | IAM user, IAM role, GCP service account, Azure AD user / group / service principal, federated identity |
| `CloudPolicy` | IAM managed policy, KMS key policy, S3 bucket policy, GCP custom role |
| `NetworkPath` | VPC route, security group rule, NACL rule, GCP firewall rule, Azure NSG rule |
| `TrustEdge` | (often inlined into edges instead of a separate node) |
| `Asset` | Higher-level abstraction: "this resource is part of project X" |
| `Surface` | Public-facing entry point: ELB, ALB, NLB, public IP, custom domain |

### Edge kinds (10 types)

| Edge | Source → Destination | Semantic |
|---|---|---|
| `can_assume` | CloudIdentity → CloudIdentity | Source can `sts:AssumeRole` to destination |
| `attached_to` | CloudPolicy → CloudIdentity | Policy bound to identity |
| `has_policy` | CloudIdentity → CloudPolicy | Inverse of `attached_to` |
| `grants_access_to` | CloudIdentity → CloudResource | Identity can perform actions on resource |
| `exposed_to_internet` | CloudResource → public | Resource reachable from `0.0.0.0/0` |
| `can_pass_role` | CloudIdentity → CloudIdentity | Source can `iam:PassRole` destination to a service |
| `runs_with` | CloudResource → CloudIdentity | Resource executes with attached identity (EC2 instance profile, Lambda execution role) |
| `network_reachable` | CloudResource → CloudResource | A → B over network (SG / NACL / firewall allow) |
| `encrypts` | KMS key → CloudResource | Key encrypts the resource |
| `triggers` | CloudResource → CloudResource | A event fires B (S3 → Lambda, EventBridge → Lambda) |

## The 27 Patterns (categorised)

### Privilege-escalation chains (8)
- `can_assume_chain_to_admin` — multi-hop `can_assume` ending at wildcard-admin
- `pass_role_present` — `can_pass_role` + downstream Lambda/EC2 abuse
- `wildcard_admin_attached` — any identity with `*:*` policy
- `admin_policy_attached_to_iam_user` — admin on a user (should be role)
- `world_assumable_role` — role's trust allows `Principal: "*"`
- `external_trust_without_external_id` — cross-account without `sts:ExternalId`
- `admin_attached_to_compute_with_internet` — public EC2/Lambda + admin SA
- `unused_iam_role_high_priv` — dormant high-priv role (perfect takeover target)

### Public exposure (8)
- `public_storage_credentials_risk` — public S3 + likely credentials in name
- `public_database` — RDS / DynamoDB / Aurora publicly accessible
- `public_secrets_store` — Secrets Manager with `Principal: "*"`
- `public_ecr_repository` — image registry world-readable
- `internet_exposed_compute_with_iam` — public IP + IAM-attached
- `lambda_function_url_no_auth` — `AuthType: NONE` Function URLs
- `azure_storage_public_blob` — Azure container publicly readable
- `gcp_public_bigquery_dataset` — BQ dataset with `allUsers`

### Identity / authn (4)
- `iam_user_active_keys_no_mfa` — programmatic access without MFA enforcement
- `root_unsafe` — root account active / has access keys
- `azure_owner_role_user` — Owner role on Azure user (vs SP)
- `gcp_service_account_owner_role` — GCP SA with primitive Owner

### Cross-account / cross-resource (4)
- `cross_account_s3_share` — S3 shared cross-account without strict conditions
- `secrets_via_environment` — Lambda env containing API keys / DB creds
- `gcp_default_compute_sa_with_internet` — default GCP SA + public exposure
- `overpermissive_secrets_manager_resource_policy` — wide secrets policy

### Crypto / data (3)
- `internet_resource_unencrypted` — public DB without encryption-at-rest
- `default_vpc_with_resources` — default VPC's default-allow rules still active

## Operational Runbook

### Step 1 — populate the graph

```bash
# Per-target discovery
strix --target aws://123456789012 --target-type cloud_account
strix --target gcp://target-project --target-type cloud_account
strix --target azure://subscription-id --target-type cloud_account
```

Each discovery walker (`cloud_attack_paths/{discovery,azure_discovery,gcp_discovery}.py`) populates nodes + edges. With `STRIX_PROJECT_ID` set (PR #317), the wrapper unions multi-cloud graphs into one project KG.

### Step 2 — query the graph

```python
# In Strix's orchestrator mode, the lead uses:
kg_query_nodes(type="CloudResource", filters={"is_public": True})

# Returns: [{"id": "arn:aws:s3:::public-bucket", ...}, ...]

kg_query_paths(
    start="arn:aws:iam::123:user/dev",
    end="arn:aws:iam::123:role/AdminRole",
    edge_types=["can_assume", "can_pass_role"],
    max_hops=4,
)
# Returns: list of paths, each with hops + verification status
```

### Step 3 — run the patterns

```bash
# All 27 patterns
strix cloud_attack_paths.find_attack_paths --graph kg.json

# Or single-pattern
strix cloud_attack_paths.run_pattern --name can_assume_chain_to_admin
```

Each match is an `AttackPath` with:
- `start` — node id of the entry point
- `end` — node id of the high-value target
- `path` — full edge list
- `severity` — derived from pattern + endpoint criticality
- `live_probe_verified` — `true` if verified by live probe; `false` / `pending` otherwise

### Step 4 — reachability scoring

```bash
# Use the graph + a starting point to score every resource by "N hops from public"
strix cloud_attack_paths.reachability \
  --start arn:aws:elasticloadbalancing:...:loadbalancer/app/public-alb \
  --max-hops 5
```

Resources within 1-2 hops of a public surface = higher priority. Resources at 5+ hops = lower priority for the same severity vuln.

### Step 5 — live PoC verification

```bash
# For attack paths flagged static, try to verify exploitability
strix cloud_attack_paths.live_probes --pattern <NAME> --path-id <ID>
```

Probes:
- Anonymous S3 GET (public-bucket pattern)
- RDS TCP handshake (public-DB pattern)
- SQS SendMessage (queue-misconfig)
- Lambda Invoke (function URL no-auth)
- IAM AssumeRole (assume-chain)

Result: `verified` / `not_exploitable_in_practice` (blocked by SCP, MFA, etc.) / `error`.

### Step 6 — emit the chain as a finding

```bash
# Lead agent: read the attack path, build a finding with the full chain
emit_finding \
  --title "Multi-hop privilege escalation to AdministratorAccess" \
  --severity critical \
  --category cloud_attack_path \
  --reasoning_trace '[ ... 4-hop chain in human form ... ]' \
  --remediation_steps "1. Remove can_assume edge from dev-user to ops-role. 2. ..."
```

## Cross-Target Chains (when `STRIX_PROJECT_ID` is set)

The wrapper's KG store unions per-scan deltas (PR #318 — `kg_delta.jsonl`) across the project. New edge types stamped by the wrapper:

| Edge | Source → Destination | Semantic |
|---|---|---|
| `deploys_to` | Repository → CloudResource | CI/CD pushes code from repo to resource |
| `pulls_from` | ContainerImage → Repository | Container built from source in repo |
| `runs_in` | Repository → CloudResource | App code runs on the resource |
| `ingests_from` | CloudResource → External | Service reads from external API |

These let queries like:
- "Show repos with leaked credentials that deploy to public-internet-exposed Lambdas"
- "Show containers built from forked-by-employees-who-left repos"
- "Show BigQuery datasets that ingest from S3 buckets cross-account-shared from unknown accounts"

## Walking the Graph by Hand (when you need to)

```python
# Strix exposes a few helpers via the lead's tool catalog:

# Direct successors of a node
kg_query_neighbors(id="arn:aws:iam::123:role/x", direction="out", edge_type="can_assume")

# All paths between two nodes (BFS)
kg_query_paths(start="x", end="y", max_hops=4)

# Nodes matching a filter
kg_query_nodes(type="CloudIdentity", filters={"has_admin": True})

# Edges matching a filter
kg_query_edges(type="grants_access_to", filters={"resource_kind": "secret"})
```

For ad-hoc complex queries, drop into Python:

```python
from strix.cloud_attack_paths.graph import CloudGraph
g = CloudGraph.load("kg.json")

# Find all "public bucket → IAM read → role admin" chains
for bucket in g.nodes(kind="CloudResource", filters={"is_public": True}):
    for identity in g.predecessors(bucket, edge="grants_access_to"):
        for admin in g.bfs(identity, edges=["can_assume"], max_hops=3):
            if admin.attrs.get("has_admin"):
                print(f"Chain: {bucket.id} → {identity.id} → ... → {admin.id}")
```

## Multi-Cloud Considerations

When the project spans AWS + GCP + Azure (the cloud arc shipped discovery for all three), the graph has heterogeneous node ids:
- AWS: `arn:aws:...`
- GCP: `//<service>.googleapis.com/...`
- Azure: `/subscriptions/<sub>/resourceGroups/<rg>/...`

Cross-cloud edges are rare but possible (Workload Identity Federation, AWS-Azure federation). The patterns currently focus per-cloud; cross-cloud pattern detection is a wishlist item.

## Pro Tips

1. The graph is denormalised by design — resources may appear under multiple ids (resource ARN + alternative friendly name). Prefer the canonical (ARN / GCP resource name) form.
2. Edge directionality matters: `can_assume` is asymmetric (a can assume b ≠ b can assume a). Query in the right direction.
3. BFS without cycle detection blows up on transitive trust loops; the helpers cap hops + dedupe.
4. The `live_probe_verified` field is the canonical "is this exploitable in practice" signal — static patterns flag the *possibility*; live probes confirm.
5. The KG persistence is `kg.json` per scan; multi-scan union is the wrapper's job (`kg_delta.jsonl` consumption).

## Summary

The cloud attack-path KG is a typed graph that turns "27 static checks" into "graph queries about reachability and chain length". Walk it, query it, extend it. Strix's value isn't in any single pattern — it's in the substrate that lets the agent reason about chains.
