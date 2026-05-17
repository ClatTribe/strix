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
side asset discovery). Seven engine changes would close the gap between
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

**None of the seven are breaking-shape changes** if shipped additively. Existing
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

## Cross-references (what we already consume vs. what we still need)

| Engine emission                     | Wrapper consumes today | Asks above                    |
| ----------------------------------- | ---------------------- | ----------------------------- |
| `events.jsonl`                      | Yes (live tail)        | §1 needs `target_id` column   |
| `findings.jsonl` + `code_locations` | Yes (PR #32)           | §6 needs `project_id` column  |
| `run.signature.json` HMAC chain     | Yes (auditor portal)   | —                             |
| `compliance_evidence.json`          | Yes (per-scan ingest)  | —                             |
| `assets.discovered.jsonl`           | **N/A — needs §4**     | §4                            |
| `run_meta.json` fingerprint         | **N/A — needs §5**     | §5                            |

The pattern from PR #31/#32 holds: **wrapper-side regex parsing of engine
output is a maintenance treadmill against a constantly-evolving format. If the
engine emits it structurally, the wrapper consumes structurally. If the engine
doesn't emit it yet, the right answer is upstream emission, not wrapper
re-derivation.** That's why §4 (`assets.discovered.jsonl`) is ranked second
in landing order despite §5 being smaller — §4 has a structural-data
analogue every other asset discoverer can reuse.

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

This division of responsibility is the same one stated in
[Architecture.md §1.1](https://github.com/ClatTribe/webappsec/blob/main/Architecture.md):
**Strix is the source of truth for detection; the wrapper is the source of
truth for tenancy, governance, and lifecycle.**
