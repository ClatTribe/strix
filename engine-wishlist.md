# engine-wishlist.md

What the engine (`ClatTribe/strix`) should add / change to support the wrapper
(`ClatTribe/webappsec`) at organisation scale — 50+ targets per workspace,
continuous monitoring, cost-aware scheduling. This is a hand-off doc going the
**other** direction from [`wrapper-wishlist.md`](wrapper-wishlist.md): asks from
wrapper → engine, not engine → wrapper.

Companion to:
- [`wrapper-wishlist.md`](wrapper-wishlist.md) — engine → wrapper hand-off
- [`roadmap.md`](roadmap.md) — engine-side roadmap (source of truth)

---

## TL;DR

Today's engine assumes a **single human starts a single scan against a single
target**. The wrapper now ships continuous monitoring across 8 target types for
organisations onboarding tens-to-hundreds of assets at a time (PR #128 wrapper-
side asset discovery). Eight engine changes would close the gap between
"the engine works" and "the engine scales economically to enterprise org sizes."

**Recommended landing order** (by leverage ÷ effort):

1. **§5 skip-if-unchanged** — small, idempotent, single biggest cost-flattener
   for daily-cadence orgs.
2. **§4 `assets.discovered.jsonl` emission** — unblocks wrapper-side AWS/GCP
   asset discoverers without us reimplementing the engine's enumeration.
3. **§2 fast first-pass profile** — quick win for bulk-import UX.
4. **§3 target-metadata pass-through** — small surface, big Researcher-context win.
5. **§1 multi-target batch mode** — large, but the economic ceiling on org scale.
6. **§7 shared Researcher cache** — pairs naturally with §1.
7. **§6 project-scoped finding correlation** — mostly handled wrapper-side
   today; only worth filing once cross-scan dedup misses real overlaps.
8. **§8 `kg_delta.jsonl` emission** — biggest single differentiation moat;
   unlocks cross-target attack-path reasoning at the wrapper. Lands after §4
   / §6 because it consumes the same project_id / asset-arn vocabulary they
   establish.

**None of the eight are breaking-shape changes** if shipped additively. Existing
single-target CLI usage keeps working.

---

## 1. Multi-target batch mode

### Problem
`strix -n -t <one-target>` runs one target per invocation. A wrapper org with
200 targets on daily cadence is 200 sandbox cold-starts, 200 separate MOAK
Researcher phases, 200 LLM-context warmups per day. Every per-scan cost
multiplies linearly with target count.

### Ask
Accept a list of targets in a single invocation. Pseudocode:

```bash
strix -n --target-list targets.jsonl \
       --batch-cost-cap 5.00 \
       --output-dir runs/batch_<run_id>/
```

where `targets.jsonl` is one target per line:

```jsonl
{"id": "tgt_a1", "type": "repository", "value": "https://github.com/acme/payments-api", "metadata": {...}}
{"id": "tgt_b2", "type": "web_application", "value": "https://payments.acme.com", "metadata": {...}}
```

Engine internals:

- Single sandbox spin-up shared across all targets in the batch.
- Single MOAK Researcher phase that maps the project (see §7 — shared cache).
- Per-target Builder / Exploiter / Judge runs against the shared context.
- Cost-cap accounting across the batch, not per-target. When the cap is hit
  the engine finishes the in-flight target and exits with a `cost_cap_reached`
  status; remaining targets stay queued for the wrapper to retry.
- `events.jsonl` and `findings.jsonl` get a `target_id` column so the wrapper
  can demux on ingest. The existing per-target artefact layout (run dir per
  target) is preserved as a sibling.

### Why now
Bulk-approve of N discovered assets is the natural endpoint of asset
discovery. Customer approves 50 repos → wrapper enqueues 50 daily scans →
without batch mode that's 50× the LLM bill. With batch mode it's perhaps 2–3×
because the LLM context is shared and Researcher runs once.

### Wrapper workaround without it
Scans run serially in the worker queue. Works (it's what we do today). Doesn't
scale economically.

### Compatibility
The single-target `-t` flag stays as the canonical path. `--target-list` is
purely additive; an absent flag falls through to the existing single-target
behaviour.

---

## 2. Fast first-pass scan profile

### Problem
Standard / quick / deep scan modes assume the agent has a stable, known
target. A newly-discovered repo has no auth, no business-logic understanding,
no prior context. Running standard-mode (let alone deep) on it the first time
spends most of its LLM budget on exploratory work that won't yield findings on
a fresh target.

### Ask
A new `STRIX_SCAN_PROFILE=initial` (or `--profile initial`) mode that ships:

- Surface mapping (subdomains, ports, public endpoints)
- Dependency CVE scan
- Secret scanning
- IaC misconfiguration scan
- **Skips:** MOAK exploit verification, auth bypass probing, business-logic
  reasoning, deep crawl.

Target: 2–5 minutes per asset, ~10% of standard-mode cost. The customer sees
*something* for every newly-imported asset within a single coffee break;
deeper scans run on the regular cadence afterwards.

### Why now
After bulk-approving 50 repos the customer wants the first scan to land
quickly so they trust the system. Today they'd wait an hour+ for the first
batch to complete on standard mode.

### Wrapper workaround
We can set `scan_mode: quick` in the discovered-asset suggested_config, but
quick mode today still invokes MOAK on the surface findings. Saves ~30% —
not enough to make the bulk-import flow feel fast.

### Compatibility
Additive. Existing profiles unchanged.

---

## 3. Target metadata pass-through into scan context

### Problem
The wrapper's `targets.metadata` JSONB carries rich upstream context: GitHub
repo language, AWS resource tags, last-deploy timestamp, dependency manifest
hints, asset owner from CODEOWNERS. The engine doesn't see any of it. The
Researcher phase re-derives stack context from a cold start every time.

### Ask
Accept an optional `STRIX_TARGET_METADATA` env or `--target-metadata-file`
argument pointing at a JSON blob. The engine treats it as Researcher-phase
hints — no schema enforcement, no validation. The Researcher prompt template
can pull from documented keys:

```json
{
  "language": "python",
  "framework_hints": ["django", "celery", "redis"],
  "last_active": "2026-05-12T...",
  "tags": ["prod", "pci-scope"],
  "owner": "@payments-team",
  "deploy_target": "kubernetes"
}
```

When the metadata says "Django + Postgres + PCI scope" the Researcher
prioritises ORM injection, admin-auth bypass, and PCI-DSS-mapped checks. When
it says "static marketing site, no auth" the Researcher skips most of the
auth-related probes.

### Why now
Discovered assets ship with rich upstream metadata. We're throwing it away at
scan time, which means the engine pays full cost to re-derive what we already
know.

### Wrapper workaround
None clean — we can't forward arbitrary metadata as env vars without polluting
the engine namespace.

### Compatibility
Additive optional env / flag. Absent → existing behaviour.

---

## 4. Engine emits `assets.discovered.jsonl` artefact

### Problem
When the engine's CSPM specialist (PRs #290/#291) enumerates AWS resources
during a `cloud_account` scan, that inventory lives in scan-internal state.
The wrapper has to re-enumerate via boto3 to populate its own
`discovered_assets` table for downstream UX (PR #128 — asset discovery for
bulk approval). Same problem coming for GCP and Azure CSPM.

The architectural lesson from PR #31 / #32 (we shipped a regex parser, then
deleted it once we noticed Strix already emitted `code_locations` as structured
data): **if the engine already enumerates it, the wrapper should consume it
rather than re-derive it.**

### Ask
The engine emits a structured `assets.discovered.jsonl` artefact alongside
`events.jsonl` and `findings.jsonl`. One row per discovered scannable resource:

```jsonl
{"type": "repository", "canonical_id": "github:acme/payments-api", "display_name": "acme/payments-api", "attributes": {...}, "suggested_config": {...}, "confidence": "high", "discovered_by": "researcher.recon"}
{"type": "web_application", "canonical_id": "aws:123456789012/elbv2/payments-alb", "display_name": "payments-alb (us-east-1)", "attributes": {"value": "https://payments-alb-...elb.amazonaws.com", "tags": ["prod"]}, "confidence": "high", "discovered_by": "cspm.aws.elbv2"}
```

The wrapper's asset-discovery runner consumes this directly — no parallel
SDK walker required. Field shape is `DiscoveredAsset` from
[`lib/asset-discoverers/types.ts`](https://github.com/ClatTribe/webappsec/blob/main/webapp/frontend/lib/asset-discoverers/types.ts).

### Why now
Phase A asset discovery (PR #128) ships GitHub discovery wrapper-side via
GitHub's REST API. AWS and GCP are next. Without engine emission we'd
reimplement what the CSPM specialist already does, doubling our cloud-API
budget and risking drift between the engine's view of the account and ours.

### Wrapper workaround
Re-enumerate via SDK in `lib/asset-discoverers/aws.ts`. Works; costs double
the upstream API calls; drifts when the engine's enumeration is more
thorough than ours.

### Compatibility
Additive new artefact. Engine runs that don't produce discoveries (e.g.,
single-repo SAST scans) emit an empty file or omit it entirely.

---

## 5. Idempotent scan dedup (skip-if-unchanged)

### Problem
Every scheduled scan runs end-to-end even when the target hasn't changed
since the last successful scan. For a 200-target org on daily cadence where
~95% of assets are quiescent on any given day, that's 95% wasted LLM spend.

This is the **single biggest cost-flattener** for post-onboarding steady
state.

### Ask
Accept a `--skip-if-unchanged` flag (or `STRIX_SKIP_IF_UNCHANGED=1`). On
entry the engine computes a target fingerprint:

| Target type      | Fingerprint                                                       |
| ---------------- | ----------------------------------------------------------------- |
| repository       | `git rev-parse HEAD` of default branch + dep-lockfile hash        |
| web_application  | TLS cert fingerprint + landing-page HTML hash + headers digest    |
| cloud_account    | terraform state hash (when provided) OR resource-tag inventory hash |
| container_image  | image digest (`sha256:...`)                                       |
| api              | OpenAPI/Swagger spec hash + base URL fingerprint                  |
| domain           | DNS record-set hash                                               |

It compares against the prior successful run's fingerprint (stored alongside
the artefact bundle in `run_meta.json`). Identical → return the prior result
immediately with `status: skipped_unchanged`, exit 0 in <5 seconds.

The wrapper already knows how to handle a "skipped" run shape (it's the same
event taxonomy as preflight-failure runs); the new status would surface as
"No changes since last scan — reused finding set from `run_id=xyz`".

### Why now
The discovered-assets bulk-approve flow plus 24h default cadence means a
200-asset org goes from 5 manual scans/week to 200 scheduled scans/day
overnight. Without this flag, that's a ~40× cost jump on day one.

### Wrapper workaround
We could fingerprint targets wrapper-side and skip enqueueing scans. But:
- The engine has better access to per-target-type fingerprintable state
  (terraform state diff, container layer hashes) than the wrapper.
- Wrapper-side skipping means the engine's own "we ran today, here's a
  fresh finding-set" narrative breaks — the auditor pack would have a hole.
- Engine-side `status=skipped_unchanged` keeps the audit trail clean while
  still costing ~$0.

### Compatibility
Additive flag. Existing behaviour unchanged when absent.

---

## 6. Cross-target finding correlation

### Problem
Each scan is hermetic. A vulnerable `lodash@4.17.20` found in repo A and repo
B produces two unrelated findings. A `cloud_attack_path` finding in one cloud
account doesn't reference the sibling account's external trust relationship.

### Ask
Accept an optional `STRIX_PROJECT_ID` env. The engine emits findings with the
`project_id` set on each row. The wrapper's cross-scan dedup ledger (PR #29)
already does some of this via fingerprint matching; engine-emitted project
context would let us tighten it (same lodash dep + same call-site pattern +
same project_id = one root finding with N target references, instead of N
separate findings).

The engine itself doesn't need to *do* the dedup — just emit the context
the wrapper needs to dedup correctly.

### Why now
Once asset discovery onboards 50+ repos for a single project, the
duplicate-finding problem dominates the inbox. The cross-scan ledger handles
exact fingerprint matches today but misses near-matches (same vuln, slightly
different code shape).

### Wrapper workaround
Our existing cross-scan dedup ledger covers exact fingerprints. Engine
context would catch more cases but isn't strictly required to keep shipping.

### Compatibility
Additive. Engine treats missing env as "no project context" and emits
findings as today.

---

## 7. Shared Researcher cache across batched scans

### Problem
The MOAK Researcher phase re-derives stack architecture, framework versions,
and exploit-class priorities every scan. For a project of 50 microservices
the architectural map is largely shared across targets — Researcher pays the
full cost 50× when it could pay it once.

This is the per-target cost win **on top of §1 batch mode**.

### Ask
When `STRIX_PROJECT_ID` is set (see §6) and the batch contains multiple
targets in the same project, the engine runs Researcher once at the start of
the batch and caches the output to
`<workdir>/researcher_cache/<project_id>.json`. Subsequent target scans in
the same batch (and follow-up batched runs within 24h on the same project)
reuse the cache instead of re-running Researcher.

A `--shared-researcher-cache=<run_id>` CLI flag lets the wrapper opt in
explicitly when the project_id-based heuristic isn't enough.

### Why now
For batch-of-50 against a single project this could be 5–10× cheaper than
running Researcher per target. Compounds with §1.

### Wrapper workaround
None — this is purely an engine-internal optimisation.

### Compatibility
Additive. Without the flag and without `STRIX_PROJECT_ID`, Researcher runs
per-target as today.

---

## 8. Knowledge-graph deltas emitted as a first-class artefact

### Problem
The engine already builds a rich cross-resource graph internally — the
`cloud_attack_paths` module's `CloudGraph` (`CloudResource`, `CloudIdentity`,
`CloudPolicy` nodes; `can_assume`, `attached_to`, `exposed_to_internet`,
`grants_access_to`, `has_policy` edges). The multi-cloud discovery work in
PRs #297 / #310 / #311 populates this graph for AWS / Azure / GCP
respectively. Multi-account fan-out (PR #299) already unions cross-account
edges into one graph spanning an AWS Organisation.

**None of this graph crosses the engine → wrapper boundary as structured
data.** The wrapper sees:

- per-finding `code_locations` (PR #32)
- per-finding rule-id + CWE + severity
- per-scan `findings.jsonl` (after §5)
- per-scan `assets.discovered.jsonl` (after §4)
- per-scan `compliance_evidence.json`

What it doesn't see: the **edges** between assets. So §6 (project-id
finding correlation) and §4 (asset enumeration) get the wrapper to:

> *"Same `lodash@4.17.20` CVE found in 50 repos — collapse to one root finding
> with 50 affected services."*  (finding-level cross-target reasoning)

But not to:

> *"This repo's CI pushes to that ECR repo. That image runs in this ECS
> service. That service's IAM role can assume admin in this other AWS
> account. That account holds this public S3 bucket."* (path-level cross-
> target reasoning across an org's whole stack)

The second story is the **single biggest moat** of the engine — it's what
Wiz commercialises at the enterprise tier, and it's what makes the "AI
security engineer for your whole stack" pitch real instead of demoware.
Today we have all the data; we just throw it away at the engine boundary.

### Ask
The engine emits a `kg_delta.jsonl` artefact alongside `events.jsonl` /
`findings.jsonl` / `assets.discovered.jsonl`. One JSON object per line, two
op-types:

```jsonl
{"op": "add_node", "kind": "CloudResource", "id": "arn:aws:s3:::payments-bucket", "attrs": {"is_public": true, "tags": ["prod"], "region": "us-east-1"}, "scan_id": "...", "source": "cspm.aws.s3"}
{"op": "add_node", "kind": "CloudIdentity", "id": "arn:aws:iam::1234:role/ecs-task-payments", "attrs": {"trust_principals": ["ecs.amazonaws.com"]}, "scan_id": "...", "source": "discovery.aws.iam"}
{"op": "add_edge", "type": "can_assume", "src": "arn:aws:iam::5678:user/deployer", "dst": "arn:aws:iam::1234:role/ecs-task-payments", "evidence": "trust_policy.json:7", "scan_id": "..."}
{"op": "add_edge", "type": "grants_access_to", "src": "arn:aws:iam::1234:role/ecs-task-payments", "dst": "arn:aws:s3:::payments-bucket", "evidence": "policy_arn:...", "scan_id": "..."}
```

Node-kind vocabulary mirrors the engine's existing internal graph:
`CloudResource`, `CloudIdentity`, `CloudPolicy`, plus the cross-target-
type additions `Repository`, `ContainerImage`, `Endpoint`, `Service`
(when the wrapper passes `STRIX_PROJECT_ID` per §6).

Edge-type vocabulary mirrors the existing edge constants:
`can_assume`, `attached_to`, `exposed_to_internet`, `grants_access_to`,
`has_policy`, plus new cross-target-type edges the wrapper can stamp
post-hoc: `deploys_to`, `pulls_from`, `runs_in`, `ingests_from`.

The engine never builds the cross-target graph itself. The wrapper's
knowledge-graph store (`lib/kg/`) consumes deltas across all scans in
a project, unions them, and serves the cross-target path queries
(`PATH FROM Repository TO PublicResource WHERE …`) to the UI.

### Why now
- **The data already exists.** PRs #297 / #299 / #310 / #311 already
  enumerate it; we're just discarding it at the artefact boundary.
- **§4 establishes the asset-id vocabulary.** Once `assets.discovered.jsonl`
  is shipping ARNs / canonical-ids for every discovered asset, the
  `kg_delta.jsonl` edges reference the same ids natively — wrapper joins
  are trivial.
- **§6 establishes the project_id vocabulary.** Same project_id stamped on
  every delta means the wrapper's KG store can scope graph union to one
  project naturally.
- **No new engine internals needed.** The graph already exists in
  `CloudGraph`; this ask is purely about emitting it.

### Wrapper workaround
None that gets you path-level reasoning. The wrapper can build a shallow
graph by joining `assets.discovered.jsonl` (nodes) and `findings.jsonl`
(edges-as-findings), but that misses 90% of the edges — most attack-path
edges (`can_assume`, `grants_access_to`) are graph-internal state the
engine never surfaces as findings.

Could we re-derive the graph wrapper-side by re-walking AWS / GCP / Azure
IAM? Yes — and it would be the PR #31/#32 mistake at maximum scale.
Engine already does this; wrapper should consume.

### Scope hygiene
Strictly emission of graph deltas. The engine does not:

- Persist the cross-scan graph (wrapper's KG store does).
- Do cross-scan graph union (wrapper does, scoped by project_id).
- Answer path queries (wrapper does, against its union store).
- Compute reachability or attack-path scoring across the union
  (wrapper does — the engine's per-scan reachability scoring in
  `reachability.py` stays per-scan).

The single-scan attack-path detection (`patterns.py` matching against
`CloudGraph`) stays engine-side and unchanged. §8 is purely about making
the same graph state consumable by the wrapper for cross-scan reasoning.

### Compatibility
Additive new artefact. Scans that don't build a graph (e.g. single-repo
SAST) emit an empty file or omit it entirely. Identical structural-data
discipline as §4.

---

## Cross-references (what we already consume vs. what we still need)

| Engine emission                     | Wrapper consumes today | Asks above                    |
| ----------------------------------- | ---------------------- | ----------------------------- |
| `events.jsonl`                      | Yes (live tail)        | §1 needs `target_id` column   |
| `findings.jsonl` + `code_locations` | Yes (PR #32)           | §6 needs `project_id` column  |
| `run.signature.json` HMAC chain     | Yes (auditor portal)   | —                             |
| `compliance_evidence.json`          | Yes (per-scan ingest)  | —                             |
| `assets.discovered.jsonl`           | **N/A — needs §4**     | §4                            |
| `run_meta.json` fingerprint         | **N/A — needs §5**     | §5                            |
| `kg_delta.jsonl`                    | **N/A — needs §8**     | §8                            |

The pattern from PR #31/#32 holds: **wrapper-side regex parsing of engine
output is a maintenance treadmill against a constantly-evolving format. If the
engine emits it structurally, the wrapper consumes structurally. If the engine
doesn't emit it yet, the right answer is upstream emission, not wrapper
re-derivation.** That's why §4 (`assets.discovered.jsonl`) is ranked second
in landing order despite §5 being smaller — §4 has a structural-data
analogue every other asset discoverer can reuse.

The same principle drives §8: the engine already builds the cross-resource
graph internally; without emission, the wrapper either does without (loses
the path-level cross-target story) or re-walks every cloud SDK to rebuild
what the engine already has (PR #31/#32 mistake at maximum scale).

---

## Out of scope for this wishlist

Things the wrapper handles entirely on its own — engine should NOT take these
on:

- **Tenant isolation** (RLS, org_id, vault encryption, per-org credential
  materialisation). Engine is single-tenant by design; the wrapper makes it
  multi-tenant safely. Don't move this boundary.
- **Audit-log + share-link semantics.** Auditor portal lives wrapper-side;
  engine just emits the signature chain.
- **Findings dedup ledger.** Cross-scan dedup is wrapper-side. Engine emits
  fingerprints; wrapper consolidates.
- **Compliance framework mapping.** Cross-framework `control_mappings` are
  wrapper-side static data. Engine emits per-control verdicts; wrapper does
  the cross-framework rollup.
- **Cross-scan graph union and path queries.** §8 has the engine emit per-
  scan graph deltas; the wrapper's KG store unions them across the project
  and serves path queries to the UI. Engine never persists or queries the
  union itself — `cloud_attack_paths.patterns` matching stays per-scan.

This division of responsibility is the same one stated in
[Architecture.md §1.1](https://github.com/ClatTribe/webappsec/blob/main/Architecture.md):
**Strix is the source of truth for detection; the wrapper is the source of
truth for tenancy, governance, and lifecycle.**
