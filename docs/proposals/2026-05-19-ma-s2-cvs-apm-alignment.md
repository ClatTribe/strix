# MA-S2 alignment — CVS + APM as defensible strengths

**Status:** Proposal · 2026-05-19 · v2 amendment 2026-05-19
**Owner:** ClatTribe/strix
**Tracking:** masterroadmap §10–§11 · engine-wishlist (next refresh)
**Related:** Palantir MA-S2 v1.0 (May 2026) — Mission Assurance Security Standard for Software
**Paired:** [`webappsec/ma-s2-proposal.md`](https://github.com/ClatTribe/webappsec/blob/main/ma-s2-proposal.md) — wrapper-side counterpart

## v2 amendment — what changed

The wrapper-side proposal landed at `webappsec/ma-s2-proposal.md`
shortly after this doc was first written. Reviewing the two
together surfaced three engine gaps the original doc didn't cover,
plus two framing wins worth folding into the engine plan. This
amendment:

1. **Adds three new P1/P2 rows** to the proposed-changes section —
   `dedup_key`, per-attempt `exploit.*` events, stable `artefact_id`
   for evidence files. None block the MA-S2 P0 set; all
   meaningfully improve auditor evidence + cross-scan correlation
   on the wrapper side.
2. **Adds a "Doctrine — signals preserved across the boundary"
   subsection** ([§Doctrine](#doctrine--signals-preserved-across-the-strix--webappsec-boundary))
   mirroring webappsec §4. Raw signals (`raw_cvss`, `raw_severity`,
   `priority_tier`, `discovery_method.is_novel`) are immutable
   across the integration; future engine PRs MUST NOT overwrite
   them.
3. **Replaces the coarse "Non-goals" section** with the granular
   non-asks from webappsec §5 (5 specific items strix MUST NOT
   absorb: tenant tagging, MTTR/SLA telemetry, cross-scan dedup,
   feed-refresh cron, attestation bundling).

The v1 plan (P0-CVS-A/B/C + P0-APM-A/B/C + P1-CVS-D + P1-APM-D)
is unchanged. Sequencing + sizing are unchanged.

## Why this document exists

Palantir published **MA-S2** in May 2026 — a candidate standard for any
software vendor operating in mission-critical environments. The
standard names four control domains and a vendor *fails* if it cannot
demonstrate the required evidence:

| Domain | Name | What it tests |
|---|---|---|
| **CVS** | Continuous AI-Augmented Vulnerability Scanning | per-release scanning, CVSS+EPSS+KEV, AI-novel-vuln discovery, auto-escalation, **contextual** SLAs |
| **APM** | Attack Path Modeling + Adversarial AI Simulation | multi-stage chains, ongoing AI red-teaming, **context-aware** triage, current threat intel |
| INV | Real-Time Software Inventory + Domain Awareness | SBOM at release, runtime reconciliation, env-level visibility, supply chain, air-gap |
| ARO | Autonomous Remediation Orchestration | auto patch deployment, fleet-wide, compliance-aware, suppression with audit, MTTR telemetry |

**Strategic posture:** CVS and APM are where strix earns its keep —
they're vulnerability *identification* and *prioritization*, which is
the engine's job. INV and ARO live almost entirely in webappsec
(inventory, patch orchestration, deployment).

This proposal is the engine-side roadmap to *not just pass* MA-S2 on
CVS+APM but be the reference implementation. Webappsec's own
engine-wishlist covers the wrapper-side controls and joins this doc
where the boundary blurs.

## State of strix today (capability scan)

### CVS — what's already there

| Control | strix today | gap |
|---|---|---|
| **CVS-0.1** Auto container + dep scanning | `scan_sca_lockfiles`, `scan_iac`, `scan_sast`, `scan_nuclei_templates`, `container_image` target type | Container-image scanning is shallow (relies on wrapper's per-release trigger) |
| **CVS-0.2** CVSS + EPSS + KEV | CVSS v3 calc in `create_vulnerability_report`; KEV via `list_actively_exploited_cves`/`lookup_cve_by_id`; threat-intel cache | **EPSS scoring is not enriched onto findings** |
| **CVS-0.3** AI-augmented analysis | The entire specialist architecture — this is strix's reason to exist | Need explicit "novel\_vuln" tagging on findings for attestation |
| **CVS-0.4** Auto detection / mitigation / recall | Detection ✅ via tracer; emit events for Critical+exploitable | No `interim_mitigation_hint` field; recall is webappsec's job but strix doesn't give it a clean signal |
| **CVS-0.5** Contextual SLAs | CVSS-only severity; reachability evidence partial via SAST | **No `contextual_priority` object**; no reachability rollup; no attack-path context wired into priority |

### APM — what's already there

| Control | strix today | gap |
|---|---|---|
| **APM-1.1** Attack path modeling | KG (`knowledge_graph.py`), `chaining_graph.py`, `correlate_findings`, `attack_path_synthesis` skill | **No `attack_paths.jsonl` artifact** for attestation; paths are implicit in the KG |
| **APM-1.2** Adversarial AI simulation | The whole scan is one | **No `simulation_run.json` attestation** (model, prompts hash, MITRE techniques exercised, chains attempted) |
| **APM-1.3** Contextual triage integration | Each finding stands alone; severity is CVSS only | **No attack-path-aware triage** — biggest single gap |
| **APM-1.4** Threat intel integration | CVE/KEV/EPSS partial; MITRE technique tags on tools | **No actor-TTP feed** (nation-state, ransomware groups); no `threat_intel_index.json` |

## Architecture split — strix vs webappsec

| Capability | strix owns | webappsec owns | joint |
|---|---|---|---|
| Per-run vulnerability identification | ● | | |
| Per-finding contextual fields (EPSS, reachability, attack-path) | ● | | |
| Attack-path graph construction (KG, chains) | ● | | |
| Adversarial AI simulation (the scan) | ● | | |
| Attestation artifacts (per-run JSONs) | ● | | |
| Cross-scan correlation / dedupe-over-time | | ● | |
| SLA tracking + breach alerts | | ● | |
| Patch deployment / recall orchestration | | ● | |
| Software inventory (INV-2.1 .. INV-2.5) | | ● | |
| Continuous scheduling (cron, on-deploy) | | ● | |
| Air-gap coverage (INV-2.5, ARO-3.2) | | ● | |
| Compliance evidence aggregation | | ● | |
| EPSS feed refresh | | ● | ● strix consumes |
| Actor-TTP feed refresh | | ● | ● strix consumes |
| Attestation report compilation | | ● | ● strix emits artifacts |

## Proposed strix changes — CVS

### P0-CVS-A — EPSS enrichment on every finding

CVS-0.2 names EPSS explicitly as a *disqualifying deficiency*. We have
the data path (`threat_intel_cache`); we don't enrich emitted findings.

**Engine change:**
- Add an `epss` block to the finding schema in
  `strix/tools/reporting/reporting_actions.py`:
  ```json
  "epss": {
    "score": 0.94,
    "percentile": 0.998,
    "last_updated": "2026-05-18T00:00:00Z"
  }
  ```
- Resolve from the threat-intel cache at finding-emit time. When
  the cache is stale (>7d) or unavailable, emit
  `epss: {score: null, reason: "cache_stale"}` rather than omit —
  attestation needs an *explicit* "we tried."

**Webappsec dependency:** webappsec must keep the threat-intel cache
fresh (daily refresh of FIRST EPSS + CISA KEV). The cache loader
already lives in strix; webappsec triggers the refresh.

**Effort:** S. **Impact:** unblocks CVS-0.2 + CVS-0.5 attestation.

### P0-CVS-B — `contextual_priority` object on every finding

CVS-0.5 explicitly disqualifies vendors who "apply uniform SLAs
based on CVSS alone, without contextual enrichment." We need to emit
the 4 contextual inputs the standard names — not just compute them
internally.

**Engine change:**
- New field on every finding:
  ```json
  "contextual_priority": {
    "raw_cvss": 9.8,
    "raw_severity": "critical",
    "epss_score": 0.94,
    "kev_listed": true,
    "reachability": {
      "source_level": "reachable",       // via SAST taint
      "dependency_level": "called",       // via SCA reach
      "runtime_level": "observed",        // via DAST hit
      "verdict": "reachable"              // worst-case rollup
    },
    "asset_context": {
      "criticality": "high",              // from target_metadata
      "data_sensitivity": "pii",
      "blast_radius": "tenant"            // shared/tenant/single
    },
    "attack_path_membership": [
      "ap-2026-05-19-001",                // APM artifact IDs
      "ap-2026-05-19-007"
    ],
    "max_chained_severity": "critical",
    "priority_tier": "p0_emergency"       // derived from all inputs
  }
  ```
- The `priority_tier` is the engine's recommendation (`p0_emergency`,
  `p1_urgent`, `p2_standard`, `p3_deferrable`, `p4_suppressible`).
  Webappsec uses it to assign SLAs but is free to override.
- Asset context comes from `target_metadata` (engine-wishlist §3
  already plumbs this). Reachability rolls up from
  `scan_sast`, `scan_sca_lockfiles`, and DAST evidence.

**Webappsec dependency:** webappsec passes `target_metadata` with
`criticality` / `data_sensitivity` / `blast_radius` per target
(already plumbed via §3; just needs the schema extended).

**Effort:** M. **Impact:** unblocks CVS-0.5 + plugs into APM-1.3.
This is the single most important change for MA-S2 alignment.

### P0-CVS-C — `interim_mitigation_hint` on Critical/High findings

CVS-0.4 requires the platform to "automatically apply compensating
controls that reduce exposure while full remediation is in progress."
Strix doesn't apply mitigation (that's ARO), but it owns the
*knowledge* of what mitigation is appropriate — the specialist that
just found the bug knows whether network isolation, feature
disablement, or config change is the right fence.

**Engine change:**
- New optional finding field `interim_mitigation_hint`:
  ```json
  "interim_mitigation_hint": {
    "type": "feature_disable",            // | network_isolate | config_change | rate_limit | rule_block
    "target": "/api/admin/export",
    "instructions": "Disable the export endpoint until patch lands.",
    "estimated_blast_reduction": "high",
    "rollback_command": "POST /admin/features {export: true}"
  }
  ```
- Required when severity ≥ HIGH AND KEV-listed OR EPSS > 0.5.
- Specialists pre-populate via their per-category profile (SQLi
  specialist knows "rate-limit the affected param + WAF rule";
  IDOR specialist knows "enforce server-side ownership check or
  block the endpoint").

**Webappsec dependency:** webappsec consumes the hint and routes to
the appropriate ARO action.

**Effort:** M (per specialist; can be incremental).
**Impact:** unblocks CVS-0.4 attestation.

### P1-CVS-D — `novel_vuln` tag for AI-discovered findings

CVS-0.3 requires demonstrating "novel, zero-day-class vulnerabilities
that do not yet have CVE assignments must be discoverable within the
vendor's pipeline." Today strix finds these but doesn't *label* them
as such — making attestation harder.

**Engine change:**
- New finding field `discovery_method`:
  ```json
  "discovery_method": {
    "primary": "ai_specialist",   // | cve_pattern_match | sast_rule | sca_lookup | nuclei_template
    "specialist_category": "idor",
    "is_novel": true,             // true when primary=ai_specialist AND no CVE matched
    "ai_reasoning_evidence": "specialist run id ref"
  }
  ```
- `is_novel=true` findings get a banner in the report + count toward
  the CVS-0.3 attestation metric.

**Effort:** S. **Impact:** CVS-0.3 attestation evidence.

## Proposed strix changes — APM

### P0-APM-A — `attack_paths.jsonl` artifact + KG-derived path enumeration

APM-1.1 requires "the capability to model multi-stage attack paths"
with output "technically integrated into vulnerability prioritization
tooling and decisions." We have the KG; we don't surface paths.

**Engine change:**
- New per-run artifact `<run_dir>/attack_paths.jsonl` — one path
  per line:
  ```json
  {
    "id": "ap-2026-05-19-001",
    "name": "Public SAML SP → admin tenant takeover",
    "max_severity": "critical",
    "stages": [
      {"step": 1, "type": "entry", "finding_id": "f-001", "mitre_technique": "T1190", "description": "SAML XSW on /saml/acs"},
      {"step": 2, "type": "auth_bypass", "finding_id": "f-002", "mitre_technique": "T1078", "description": "tenant-id substitution in IdP response"},
      {"step": 3, "type": "data_access", "finding_id": "f-003", "mitre_technique": "T1530", "description": "cross-tenant Firestore read via tenant_id=*"}
    ],
    "preconditions": ["public_internet_reachable"],
    "impact_summary": "Cross-tenant exfiltration of all customer PII.",
    "confidence": 0.85
  }
  ```
- Source: `chaining_graph.py` + `attack_path_synthesis` skill +
  KG path-finding (`kg_query_paths` already exists).
- One specialist run at the end of the scan (after `correlate_findings`)
  walks the KG and emits paths. Conservative threshold: only emit
  paths with ≥2 stages AND at least one HIGH/CRITICAL stage.

**Effort:** M. **Impact:** APM-1.1 attestation; feeds APM-1.3.

### P0-APM-B — Contextual triage via attack-path membership

APM-1.3 is the single highest-leverage MA-S2 control: "A Critical CVE
in a component that is not reachable from any external attack surface
may be appropriately deprioritized. A Medium CVE in a component that
is the first link in a traversable attack path to a privileged
credential store must be treated as urgent."

This goes far beyond per-finding severity adjustment — it changes
which findings show up at the top of the report.

**Engine change:**
- In `strix/llm/fp_filter.py` (workflow phase 6, just shipped in
  PR #336), add two new contextual rules:
  - **R9 — unreachable_high_downgrade:** if `reachability.verdict ==
    "unreachable"` AND severity ∈ {high, critical} AND no path
    membership → DOWNGRADE to `low`. Recall-safe because
    unreachability is verified by SAST/SCA evidence.
  - **R10 — chain_first_link_upgrade:** if finding is the first
    stage of an attack path AND `max_chained_severity == critical`
    → set `priority_tier=p0_emergency` regardless of raw CVSS.
    UPGRADE only, never DROP.
- Rules run AFTER the `attack_paths` synthesis step (sequenced
  by the workflow phase model).

**Effort:** M (rules + sequencing change in the workflow phases).
**Impact:** APM-1.3 + CVS-0.5 attestation. Improves *signal-to-noise*
of the customer-facing report by an order of magnitude.

### P0-APM-C — `simulation_run.json` attestation artifact

APM-1.2 requires "evidence of adversarial AI simulation." Today strix
runs the simulation but doesn't emit an attestation-grade record.

**Engine change:**
- New per-run artifact `<run_dir>/simulation_run.json`:
  ```json
  {
    "run_id": "scan-...",
    "started_at": "2026-05-19T...",
    "duration_s": 3247,
    "models_used": [
      {"role": "lead", "model": "anthropic/claude-opus-4-7", "version": "..."},
      {"role": "specialist", "model": "anthropic/claude-sonnet-4-6", "version": "..."}
    ],
    "scan_mode": "deep",
    "specialists_dispatched": 14,
    "specialist_categories_exercised": ["sqli", "xss", "idor", "auth", "saml-xsw", ...],
    "mitre_techniques_exercised": ["T1190", "T1078", "T1530", ...],
    "chains_attempted": 22,
    "chains_confirmed": 3,
    "kg_node_count": 187,
    "kg_edge_count": 412,
    "ai_reasoning_calls": 318,
    "deterministic_tool_calls": 1024,
    "novel_findings_count": 5
  }
  ```
- Sourced from `tracer` + `chaining_graph` + `specialist_orchestrator`
  + the v2 step-3 batch counter.

**Effort:** S. **Impact:** APM-1.2 attestation, ready as a single
file customers / regulators can read.

### P1-APM-D — Threat intel index with actor TTPs

APM-1.4 names "nation-state actor TTPs aligned to frameworks such as
MITRE ATT&CK." Today we tag tools with techniques but don't track
which actors are currently using which.

**Engine change:**
- New consumable: `<run_dir>/threat_intel_index.json` — emitted at
  scan start, referenced during specialist dispatch + reporting:
  ```json
  {
    "feed_refreshed_at": "2026-05-18T...",
    "current_priority_actors": [
      {
        "actor": "APT29",
        "techniques": ["T1190", "T1078.004", "T1098.001"],
        "campaigns": ["MUMMY_SPIDER", "..."],
        "last_observed": "2026-05-10"
      }
    ],
    "active_campaigns": [...],
    "newly_added_kev": [
      {"cve_id": "CVE-2026-...", "added": "2026-05-15"}
    ]
  }
  ```
- The lead's system prompt gains a `<threat_intel_priority>` block
  listing the techniques most-relevant to current campaigns
  affecting the target's industry (passed via `target_metadata`).
- Specialist dispatch is biased toward those techniques first.

**Webappsec dependency:** webappsec refreshes the underlying feed
(MITRE ATT&CK navigator, CISA alerts, possibly vendor TI subscriptions)
and writes the index to a known path that strix loads at scan start.

**Effort:** M. **Impact:** APM-1.4 attestation + nudges specialist
selection toward what adversaries actually use today.

## Proposed strix changes — additions from wrapper review (v2 amendment)

The three rows below were not in the original strix#338 draft but
surfaced via [`webappsec/ma-s2-proposal.md`](https://github.com/ClatTribe/webappsec/blob/main/ma-s2-proposal.md)
§3 ("Engine asks not covered by strix#338"). None block the MA-S2
P0 attestation story — strix#338's P0 set is sufficient alone —
but each meaningfully improves auditor evidence + cross-scan
correlation on the wrapper side.

### P1-AUX-A — `dedup_key` per finding

The tracer today drives finding deduplication through an
LLM-based `check_duplicate` call (`strix/llm/dedupe.py`). The
wrapper has its own `cross_scan_dedup_ledger` and currently
joins defensively by hashing. A strong upstream signal would
let the wrapper trust the engine's verdict instead of
re-deriving it.

**Engine change:**
- Add `dedup_key` to every finding emitted via
  `add_vulnerability_report`. Stable hash of:
  `(normalized_cwe, canonical_endpoint, canonical_sink)`.
  Canonicalization rules:
  - `canonical_endpoint` = post-FP-filter's `_request_signature`
    helper output (already shipped in PR #336); strips numeric IDs
    / UUIDs / hex hashes from path segments.
  - `canonical_sink` = the most-specific structural identifier the
    finding payload carries:
    - For SAST: `<file>:<sink_function>` (drop line numbers).
    - For SCA: `<package>@<vulnerable_version_range>`.
    - For DAST: `<param_name>` (or `<request_signature>` when
      param shape ambiguous).
- The wrapper joins by `dedup_key` first; falls back to the
  existing LLM dedupe path only when keys disagree across a
  re-scan.

**Recall-safety:** never affects what gets emitted — only how
findings are correlated downstream. Two findings with the same
`dedup_key` are still both emitted; the wrapper decides how to
merge them.

**Effort:** S. **Impact:** Wrapper-side cross-scan correlation
becomes deterministic. LLM `check_duplicate` calls become a
fallback rather than the primary path.

### P1-AUX-B — Per-attempt `exploit.*` events

strix#338's `simulation_run.json` exposes run-level counters
(`chains_attempted`, `chains_confirmed`). The wrapper wants
per-attempt granularity for the auditor evidence trail: "we
tried these N payloads on this surface, this one worked, the
rest failed because…"

**Engine change:**
- Add three new event types to `events.jsonl`:
  ```json
  {"event": "exploit.attempted",
   "finding_id": "f-003", "technique": "T1190",
   "target_endpoint": "/api/users/{id}",
   "payload_or_command": "<truncated>",
   "started_at": "...",
   "request_artefact_id": "req-2026-05-19-001"}

  {"event": "exploit.succeeded",
   "finding_id": "f-003",
   "response_artefact_id": "resp-2026-05-19-001",
   "evidence": "<one-line evidence summary>"}

  {"event": "exploit.failed",
   "finding_id": "f-003",
   "reason": "WAF blocked",
   "response_artefact_id": "resp-2026-05-19-002"}
  ```
- Emitted by every probe-shaped tool (deterministic specialists +
  the inner-LLM specialist's loop). The granular trail lets the
  wrapper render a per-finding timeline AND lets auditors see
  the negative space ("you probed these N things, here are the
  N-1 you ruled out").

**Recall-safety:** events are write-only; never change finding
emission semantics. Each event references an `artefact_id`
(see P2-AUX-C) so the wrapper can resolve to the captured
request/response file.

**Effort:** M. **Impact:** Richer attestation evidence than
the run-level counters alone. Complementary to
`simulation_run.json`, not a replacement.

### P2-AUX-C — Stable `artefact_id` cross-reference for evidence files

`attack_paths.jsonl` (P0-APM-A) references chain stages by
`finding_id` — but the evidence files those stages depend on
(screenshots, captured requests, captured responses, proof
artifacts) are not referenced anywhere structurally. The
wrapper has to glob the run dir to find them.

**Engine change:**
- Every evidence file the engine writes (`proof_artifact_path`
  in findings, `request_artefact_id` / `response_artefact_id`
  in exploit events, screenshots from browser probes) gets a
  stable `artefact_id` of the shape
  `<kind>-<run_id>-<sequence>` (e.g. `req-scan-2026-05-19-042-007`).
- A new `<run_dir>/artefacts.jsonl` indexes
  `{artefact_id, path_relative_to_run_dir, kind, mime_type,
  size_bytes}` so the wrapper can resolve any structurally-
  referenced ID to a known path in one lookup.
- Existing fields that point at files (e.g. `findings[].proof_artifact_path`)
  get an additional sibling `proof_artefact_id` for the
  structural reference.

**Recall-safety:** purely additive cross-reference; existing
path fields stay.

**Effort:** S (the IDs themselves) + M (back-fill across every
evidence-emitting code path). Land in two PRs — IDs first,
then per-emitter wiring.

## Prioritization

### Customer-applicability reorder (v3 — 2026-05-19)

Mapping MA-S2 Appendix A2 questions to our actual customer base
(SaaS shops, mid-market web/API security, vibe-coded apps, modern
cloud-native deployments — **not** classified-government / DIB)
sharpens the priority list:

| Q | Topic | Applicability | Why |
|---|---|---|---|
| Q0 | AI-novel discovery | 🟢 Universal | Differentiator for every customer |
| Q1 | EPSS + KEV in prio | 🟢 Universal | Modern minimum for vuln-backlog triage |
| Q2 | Real-time inventory | 🟡 Scale-dependent | Multi-env customers care; single-prod-env doesn't |
| Q3 | Multi-stage attack-path sim | 🟢 Universal | The differentiator we lead with |
| Q4 | Patch deployment orchestration | 🟡 Scale-dependent | One-prod-env shops have CI/CD already |
| Q5 | MTTR + responsible person | 🟢 Universal (with reframing) | "Team owns it + MTTR" for SaaS shops |
| Q6 | Air-gap | 🔴 **Not our customer** | Classified / DIB territory only |

**4 of 7 questions are universal** (Q0, Q1, Q3, Q5); **2 are
scale-dependent** (Q2, Q4); **1 is explicitly out of scope** (Q6).
This reshapes the implementation sequence.

### Revised P0 — ship this quarter (answers all universal Qs)

1. **P0-CVS-A** — EPSS enrichment (S) → **Q1** ← ✅ shipped ([#352](https://github.com/ClatTribe/strix/pull/352))
2. **P0-CVS-B** — `contextual_priority` object (M) → **Q1 + Q3** ← biggest single change; reads P0-CVS-A
3. **P0-APM-A** — `attack_paths.jsonl` artifact (M) → **Q3** ← feeds APM-1.3
4. **P0-APM-C** — `simulation_run.json` (S) → **Q0 + Q3** ← cheap, big attestation win; parallel with #3
5. **P0-CVS-D** — `novel_vuln` tag (S) → **Q0** ← **promoted from P1**: Q0 is universal + this is the literal attestation for it (one bit per finding)
6. **P0-APM-B** — Contextual triage rules R9 / R10 (M) → **Q3** ← downstream of #2 + #3

### P1 — ship next quarter (scale-dependent or auxiliary)

7. **P1-CVS-C** — `interim_mitigation_hint` (M) → **Q4** ← **demoted from P0**: Q4 is scale-dependent. Ship when multi-env customers ask.
8. **P1-APM-D** — Threat intel index (M) → **Q3 nuance** ← actor-TTP feed; nice-to-have
9. **P1-AUX-A** — `dedup_key` per finding (S) — v2 amendment
10. **P1-AUX-B** — Per-attempt `exploit.*` events (M) — v2 amendment

### P2 — opportunistic

11. **P2-AUX-C** — Stable `artefact_id` cross-reference (S+M, two PRs) — v2 amendment

### Explicitly out-of-scope for our customer base

- **Q6 air-gap** — strix has no Q6-specific work today (correct). Webappsec's INV-2.5 + ARO-3.3 air-gap variants stay deferred indefinitely. When we have a federal-adjacent customer who needs it, we can add air-gap as a contained capability — but pursuing it now is a distraction from the universal Qs.

### Sequence note

P0-CVS-A → P0-CVS-B → P0-APM-B is the critical path (each reads
the prior). P0-APM-A + P0-APM-C + P0-CVS-D ship in parallel —
no cross-dependency. **After this revised P0 lands, strix answers
4 of 4 universal MA-S2 procurement questions strongly**; webappsec
carries the wrapper side of Q2 + Q4.

## Interaction with the v2 cost-optimization arc

The recall-safe per-workflow-phase plan
([scan-mode-cost-optimization.md](2026-05-19-scan-mode-cost-optimization.md))
is **complementary** to MA-S2:

- The verdict cache (step 2, PR #337) cuts cost on the *same*
  category against similar endpoints; MA-S2's contextual triage
  cuts cost-of-attention on findings the operator doesn't need
  to act on. Both reduce noise in the right places.
- The FP pre-filter (step 1, PR #336) is where MA-S2's R9 / R10
  contextual rules belong — same execution point, same kill
  switch, same recall-canary discipline.
- The batched dispatch (step 3, WIP) is the same architectural
  shape as the proposed APM-A path-enumeration specialist:
  one fresh-context loop, multiple objectives.

**No conflicts.** The MA-S2 changes can land between the v2 steps.

## Attestation artifacts strix must emit (summary)

After all P0 lands, every scan produces (in `<run_dir>/`):

| File | Sources | MA-S2 control |
|---|---|---|
| `findings.json` (existing) | tracer + specialist results | CVS-0.1, CVS-0.2, CVS-0.3, CVS-0.5 |
| `attack_paths.jsonl` (NEW) | KG + chaining_graph | APM-1.1, APM-1.3 |
| `simulation_run.json` (NEW) | tracer + orchestrator | APM-1.2 |
| `coverage.json` (existing) | telemetry | APM-1.4 (technique coverage) |
| `verification.jsonl` (existing) | verification_pipeline | CVS-0.3 evidence |
| `compliance_evidence.json` (existing) | `emit_compliance_evidence` | CVS-0.5, APM-1.3 (audit) |

Webappsec aggregates these across scans + time, layers SLA tracking
on top, produces the customer-facing MA-S2 attestation bundle.

## Doctrine — signals preserved across the strix ↔ webappsec boundary

The proposed P0-CVS-B `contextual_priority` object rolls many
signals into a single nested structure. Some of those signals
are **the engine's authoritative output** — the wrapper layers
its own decisions on top but must NEVER overwrite them. This
section names the immutable signals + the storage shape they
expect on the wrapper side.

**Why this matters:** `contextual_priority` is the most-attractive
target for future engine PRs that want to "improve" the
recommendation by retroactively updating the raw inputs. That
would silently corrupt the boundary contract. The wrapper's
auditor view shows BOTH the engine's verdict and any wrapper-side
override — both signals coexist; neither erases the other.

| Field | Source of truth | Wrapper override pattern |
|---|---|---|
| `contextual_priority.raw_cvss` | Engine (CVSS calculator); set once at finding-emit time, never re-computed | Wrapper stores verbatim in `findings.raw_cvss`. NO override path. |
| `contextual_priority.raw_severity` | Engine; derived from `raw_cvss` per CVSS v3 ranges | Wrapper stores verbatim in `findings.raw_severity`. NO override path. |
| `contextual_priority.priority_tier` (engine's recommendation) | Engine; derived from EPSS + KEV + reachability + asset_context + attack-path membership | Wrapper stores verbatim in `findings.engine_priority_tier`. Wrapper's final decision (after SLA policy) lands in a **separate** `findings.wrapper_priority_tier` jsonb field. Auditor view shows both. |
| `discovery_method.is_novel` (P1-CVS-D) | Engine; set ONLY when `discovery_method.primary == "ai_specialist"` AND no CVE matched | Wrapper surfaces as a UI chip + counts in attestation. NEVER derived from prose; NEVER inferred from category alone. |
| `attack_paths.jsonl[]` (P0-APM-A) | Engine; the KG-derived chain enumeration is authoritative | Wrapper renders + compiles into attestation bundle. Doesn't synthesize paths from finding pairs. |
| `simulation_run.json` (P0-APM-C) | Engine; per-run attestation counters | Wrapper aggregates across runs for trend dashboards. NEVER overwrites the per-run record. |

**Engine-side commitments to preserve the doctrine:**

- `add_vulnerability_report` MUST set `raw_cvss` + `raw_severity`
  in `contextual_priority` exactly once at emit time. The FP filter
  (PR #336) and CWE templates (PR #343) MUST NOT modify these.
  R6 / R7 / R8 of the FP filter operate on `severity` (the
  engine's *final* tier), not `raw_severity` (the immutable
  CVSS-derived value).
- The verification pipeline (PR #336) MUST NOT mutate finding
  fields once emitted. It tracks stage + evidence in a separate
  `verification.jsonl`; the finding's own `severity` /
  `verification_status` is only updated through the existing
  explicit code paths.
- A unit test pinned in `tests/llm/test_fp_filter.py` enforces
  that DOWNGRADE rules leave `raw_severity` unchanged (recall
  canary). Adding new R-rules requires extending that canary.

**Wrapper-side commitments to preserve the doctrine** (from
`webappsec/ma-s2-proposal.md` §4):

- Wrapper's AI urgency triage writes into `findings.urgency_triage`
  jsonb — **never** over `contextual_priority.raw_*` or `.priority_tier`.
- Customer-facing UI surfaces both `engine_priority_tier` and
  `wrapper_priority_tier`. The auditor view labels them clearly.
- The wrapper's RLHF feedback loop labels findings without
  mutating them — the engine signal is the audit trail.

## Coordination with webappsec

The matching webappsec-side proposal must commit to:

1. **Target metadata schema** — extend `target_metadata` with
   `{criticality, data_sensitivity, blast_radius}` per target.
   Strix consumes via the existing engine-wishlist §3 plumbing.
2. **Threat-intel feed refresh** — webappsec keeps EPSS + KEV +
   actor-TTP feeds fresh on a cadence; strix reads them.
3. **Attestation bundle compiler** — webappsec consumes the new
   per-run artifacts + cross-scan SLA telemetry + INV/ARO
   evidence to produce the deliverable bundle.
4. **Continuous scheduling** — webappsec schedules per-release
   strix scans (the CVS-0.1 "per-release" guarantee).
5. **Recall + interim mitigation execution** — webappsec consumes
   `interim_mitigation_hint`s and routes to ARO actions.

## Non-goals (control-domain level)

- **Implementing INV inside strix.** SBOM at release, runtime
  reconciliation, supply chain visibility — these are inventory
  problems, not vulnerability-identification problems. Stays in
  webappsec.
- **Implementing ARO inside strix.** Patch deployment, rollback,
  compliance-aware change management — these are CD problems,
  not pentest problems. Stays in webappsec.
- **Replacing CVSS.** The contextual priority *augments* CVSS,
  not replace. Auditors expect CVSS.
- **One-size-fits-all priority tier.** The engine's `priority_tier`
  is a *recommendation* — webappsec is free to override based on
  customer SLA contracts.

## Explicit non-asks (v2 amendment — granular guardrails)

The control-domain-level non-goals above set the broad scope. The
items below are the **granular wrapper-side guardrails** that
must stay out of the engine even when an "improvement" seems
within reach. Each one was flagged by `webappsec/ma-s2-proposal.md`
§5 because past engine PRs have drifted toward absorbing
tenant-shaped data.

| | Item | Why wrapper-side |
|---|---|---|
| 🚫 | **EPSS / KEV / actor-TTP feed refresh** (the cron, not the lookup) | Public reference data with daily cadence, independent of any specific scan. The wrapper-side cron writes to a known path; the engine reads at scan start (P0-CVS-A, P1-APM-D). Engine code that hits external feed APIs directly is the anti-pattern. |
| 🚫 | **Asset criticality / data sensitivity / blast-radius tagging** | Multi-tenant, customer-declared. Strix is single-tenant by design (per `CLAUDE.md` doctrine — tenant boundaries belong exclusively to the wrapper). The engine consumes via `target_metadata` plumbing (engine-wishlist §3); it must NOT have its own asset classification. |
| 🚫 | **MTTR / SLA-compliance telemetry** | Org-level config + cross-scan, cross-time aggregation. Wrapper-shaped by every dimension. The engine emits per-run timings + per-finding `fix_time_estimate` (P0-CVS-C); the wrapper rolls them up. |
| 🚫 | **Cross-scan / cross-time dedup** | The wrapper's existing `cross_scan_dedup_ledger` is the right place. The engine emits `dedup_key` per P1-AUX-A; the wrapper joins. Engine-side state across scans is the anti-pattern. |
| 🚫 | **Attestation bundle compilation** | Tenant-scoped, signed, time-bounded auditor export. Wrapper-shaped (signing keys, tenant identity, retention). The engine emits per-run artifacts; the wrapper compiles + signs the deliverable. |
| 🚫 | **Per-tenant feature flags / SLA contracts** | Customer-specific configuration. The engine's behaviour is driven by `scan_mode` + `target_metadata`; it must NOT look up tenant-specific flags directly. Anything tenant-shaped enters via `target_metadata`. |
| 🚫 | **Auditor-portal authentication / authorization** | Identity + RBAC are wrapper-shaped end-to-end. The engine's events / artifacts are content; the wrapper decides who can see them. |

**How to use this list:** when proposing a new engine change
(any direction), if it touches a row above, propose it as a
wrapper change instead OR add the rationale here for why this
specific item is a structural exception. Drift into tenant-shaped
state by silent feature-creep is the failure mode this list
prevents.

## Validation plan

- **Schema tests:** every new artifact has a JSONSchema in
  `tests/telemetry/` and a positive-shape test using a fixture
  derived from a benchmark run.
- **Recall canary:** the FP-filter rules R9 / R10 ship with
  canaries pinning that benchmark must_find findings tagged as
  first-link-in-chain are correctly upgraded (and that
  must_find findings on reachable surfaces are never downgraded
  to "low" by R9).
- **Boundary-doctrine canary (v2 amendment):** a unit test in
  `tests/llm/test_fp_filter.py` (and a sibling in
  `tests/tools/test_cwe_templates.py`) pins that DOWNGRADE /
  template-fill paths leave `contextual_priority.raw_cvss` and
  `.raw_severity` **byte-identical** to the value at emit time.
  Adding any new rule that touches the priority object must
  extend this canary.
- **Benchmark sweep:** re-run the full per_target suite after
  each P0 lands; the `recall_must_find` floor remains ≥ 0.80
  per fixture.
- **Attestation walk-through:** generate the full bundle from a
  benchmark scan + walk it against the MA-S2 Appendix A2 procurement
  questions (page 20 of the standard). Every question maps to a
  named artifact field.
- **dedup_key stability (v2 amendment):** unit test pins that
  `dedup_key` is byte-stable across two re-emissions of the
  same finding (same CWE + same canonical endpoint + same
  canonical sink). The wrapper's cross-scan correlation depends
  on this invariant.
- **exploit.* event ordering (v2 amendment):** an integration
  test pins that for every `exploit.succeeded` there is a
  preceding `exploit.attempted` with the matching
  `finding_id` + `request_artefact_id`. Required so the wrapper's
  per-finding timeline can be rendered without holes.

## Appendix — MA-S2 procurement questions, strix coverage

The MA-S2 Appendix A2 lists 7 procurement questions any organization
should ask. After all P0 lands, strix-produced artifacts answer:

| Q | Question (paraphrased) | strix artifact |
|---|---|---|
| [0] | Automated scanning + AI-assisted novel-vuln discovery? | `simulation_run.json` (model + specialist categories) + `findings.json` (`discovery_method.is_novel`) |
| [1] | EPSS + KEV in prioritization? | `findings.json` (`contextual_priority.epss_score`, `.kev_listed`) |
| [2] | Real-time machine-readable inventory? | **webappsec** (INV-2.1 .. INV-2.5) |
| [3] | AI-assisted adversarial simulation across multi-stage paths? | `attack_paths.jsonl` + `simulation_run.json` |
| [4] | Patch deployment orchestration? | **webappsec** (ARO-3.1, ARO-3.2) |
| [5] | Responsible-person + time-to-deploy? | **webappsec** (ARO-3.5, ARO-3.6) |
| [6] | Air-gapped + compliance-constrained envs? | **webappsec** (INV-2.5, ARO-3.3) |

Three of seven are strix's job. The rest are webappsec's. The
boundary is clean.
