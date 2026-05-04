# `usage.md` — wrapper integration guide for Strix

This document is the **wrapper-facing** integration guide for Strix. It is the companion to [`README.md`](README.md) (end-user CLI guide), [`roadmap.md`](roadmap.md) (engine direction), and [`wrapper-wishlist.md`](wrapper-wishlist.md) (per-PR rendering specs).

If you are building a wrapper around Strix — a SaaS dashboard, a self-hosted security console, an AI security engineer composing findings into a casefile — start here. Every section answers a concrete question a wrapper engineer asks during integration:

- _How do I invoke Strix as a subprocess?_ → §1
- _What artifacts does Strix write, and where?_ → §2
- _What events do I consume from the live event stream?_ → §3
- _How does the wrapper write feedback back to the engine?_ → §4
- _How do I compose all of this into a minimum-viable AI security engineer?_ → §5

The `wrapper-wishlist.md` lays out specific rendering tickets per engine PR; this doc is the **operating manual** that ties them together.

---

## TL;DR — the wrapper-engine contract in five lines

1. **Invoke** Strix as a subprocess in non-interactive mode (`strix -n …`); pass scan config via CLI flags + env vars.
2. **Read** the structured run directory (`<runs_dir>/<run_id>/`) — `events.jsonl` for the live stream, `vulnerabilities.json` for findings, `run_meta.json` for scan config, plus the §2 artifact set.
3. **Render** the wrapper-side companions documented in `wrapper-wishlist.md` §10–§16 — confidence bars, provenance badges, hypothesis live-pane, auto-dismiss banners, etc.
4. **Write** wrapper-collected labels back to `feedback.jsonl` and pass `--feedback-from <PATH>` (or set `STRIX_FEEDBACK_FROM` / use `~/.strix/feedback.jsonl` for cross-run).
5. **Re-scan** — the engine consumes the labels, auto-dismisses prior FPs, emits richer trajectories, and the loop closes.

---

## 1. Invocation — running Strix from a wrapper

### 1.1 Recommended invocation

```bash
strix \
  -n \                                      # non-interactive, machine-readable output
  --target https://example.com \            # repeatable for multi-target
  --scan-mode standard \                    # quick / standard / deep
  --scope-mode strict \                     # strict / loose / diff
  --feedback-from /var/run/strix/feedback.jsonl \  # §18 row 2 — RLHF Phase 1
  --output-dir /var/run/strix/runs/<run_id>
```

> The `-n / --non-interactive` flag is the wrapper's primary contract: Strix prints structured findings + the final report, exits with non-zero on findings, and never blocks on a TTY. Without `-n` the CLI hijacks the terminal with a Rich-based UI.

### 1.2 Required environment

```bash
export STRIX_LLM="openai/gpt-5.4"                 # or anthropic/claude-sonnet-4-6, etc.
export LLM_API_KEY="<provider key>"
export STRIX_FP_AUTO_DISMISS="conservative"       # conservative | aggressive | off
export STRIX_FEEDBACK_FROM="/var/run/strix/feedback.jsonl"  # optional alt to --feedback-from
export STRIX_KEV_DISABLED="0"                     # set 1 to skip CISA KEV enrichment in air-gapped runs
```

The wrapper passes these into the engine container (Docker run env, Kubernetes secret mount, etc.). See [`README.md` §Configuration](README.md#configuration) for the full env-var matrix.

### 1.3 Multi-target, authenticated, and scope-controlled scans

```bash
# Multi-target (source code + deployed app)
strix -n -t https://github.com/org/app -t https://app.example.com

# Authenticated grey-box
strix -n -t https://app.example.com \
  --instruction "Authenticate as alice@example.com / hunter2; test only /admin/*"

# PR-diff scope (CI use case)
strix -n -t ./ --scan-mode quick --scope-mode diff --diff-base origin/main

# Vendor-risk mode (compliance / supplier eval)
strix -n -t https://vendor.example.com --vendor-mode

# HAR / Burp project ingestion (§18 row 3)
strix -n -t https://app.example.com \
  --instruction "Use the captured Burp project at /scan/burp.xml as the surface-map seed"
# Engine auto-detects via the `ingest_burp_file` tool.
```

### 1.4 Exit codes

| Exit code | Meaning | Wrapper action |
|---:|---|---|
| 0 | Clean — no findings + run completed cleanly | Mark scan ✅ in dashboard |
| 1 | Findings emitted | Read `vulnerabilities.json`; render findings; trigger triage workflow |
| 2 | CLI usage error | Surface error to operator; do not retry |
| ≥10 | Engine internal error or budget exceeded | Read `run_meta.json` → `status` field; surface; consider retry |

### 1.5 Run identity

The wrapper SHOULD set `--output-dir` to a deterministic per-scan path under the wrapper's filesystem (e.g. `/var/run/strix/runs/<wrapper-scan-id>/`) so the wrapper's own DB joins on a known key. If `--output-dir` is omitted, Strix creates one under the user's home (`~/.strix/runs/<auto-id>/`).

---

## 2. The run directory — what Strix writes, what the wrapper reads

After every `strix` invocation, the run directory contains a stable set of structured artifacts. **Schema-versioned** files carry their own `schema_version` field; bump-on-break, additive-on-extend.

### 2.1 Artifact map

| File | Format | Written when | Wrapper use |
|---|---|---|---|
| `events.jsonl` | JSONL (1 record / event) | Continuously, throughout the run | Live activity stream — `tail -f` for real-time UI |
| `run_meta.json` | JSON | At every `save_run_data()`, finalised at run-end | Scan config snapshot — render config card; persist for audit |
| `run_summary.json` | JSON | At run-end | One-shot summary for indexers / cross-scan analytics |
| `run.signature.json` | JSON | At run-end (when audit-trail signing is on) | Tamper-evidence — verify `event_hash` chain on `events.jsonl` |
| `vulnerabilities.json` | JSON (array of records) | At run-end | Structured finding dump — primary triage queue source |
| `vulnerabilities.csv` | CSV | At run-end | Spreadsheet-friendly; ticketing imports |
| `penetration_test_report.md` | Markdown | At run-end | Human-readable report — render as-is or extract sections |
| `coverage.json` | JSON | At run-end | What categories were tested per (target_type, scan_mode) — render coverage matrix |
| `coverage_attestation.json` | JSON | At run-end | Compliance signature: "we attest the engine ran X checks on Y surfaces" |
| `checks_summary.json` | JSON | At run-end | Per-category counts (`vulnerable` / `not_vulnerable` / `inconclusive`) |
| `surface_map.json` | JSON | After recon phase | Discovered hosts / endpoints / params — surface-map dashboard source |
| `trajectory.jsonl` | JSONL (1 record / finding) | At run-end (RLHF Phase 1 / §18 row 2) | Per-finding reasoning trail — labeler grading + FP-classifier features |
| `active_hypotheses.jsonl` | JSONL (append-only) | Throughout run (§17.6 / §18 row 9) | Cross-specialist hypothesis lifecycle — live-pane source |

### 2.2 Reading `events.jsonl` (the live stream)

Each line is a single JSON object with a stable shape:

```json
{
  "event_id": 0,
  "event_type": "tool.execution.started",
  "timestamp": "2026-05-04T12:34:56.789012+00:00",
  "actor": {
    "agent_id": "agent_4f3a2c1b",
    "agent_name": "auth-attacker-1",
    "agent_category": "auth-attacker",
    "tool_name": "send_request",
    "target": "https://app.example.com",
    "provenance": "framework"
  },
  "payload": { "...event-specific keys..." },
  "status": "started",
  "source": "strix.tool",
  "trace_id": "...",
  "span_id": "...",
  "event_hash": "..."
}
```

Wrapper integration pattern (Node.js example):

```js
const reader = fs.createReadStream(`${runDir}/events.jsonl`);
const rl = readline.createInterface({ input: reader });
for await (const line of rl) {
  if (!line.trim()) continue;
  const ev = JSON.parse(line);
  // Route on event_type — see §3 for the catalog.
  routeEvent(ev);
}
```

For continuous tailing, watch with `chokidar` / `inotify` and reopen on truncation. The file is append-only within a run; cross-run, the wrapper rotates by `run_id`.

### 2.3 Reading `vulnerabilities.json` (the finding stream)

Each entry is a single finding. The §12 quality signals (#137) and §18-row-2 features block (#142) attach to every record:

```json
{
  "id": "vuln-001",
  "title": "Reflected XSS in /search",
  "severity": "medium",
  "category": "xss",
  "cwe": "CWE-79",
  "endpoint": "/search?q=",
  "description": "...",
  "verification_status": "pattern_match",
  "fingerprint": "a1b2c3d4e5f60718",
  "fingerprint_version": 1,
  "reproducibility_token": "0a1b2c3d4e5f6071",
  "confidence": 0.7,
  "reasoning_trace": ["bullet 1", "bullet 2", "..."],
  "counter_proof": {
    "description": "Possible alternative: ...",
    "evidence": "..."
  },
  "features": {
    "schema_version": 1,
    "category": "xss",
    "severity": "medium",
    "severity_ordinal": 3,
    "verification_status": "pattern_match",
    "cwe": "CWE-79",
    "detection_count": 1,
    "is_test_path": false,
    "evidence_length_chars": 320,
    "has_poc_script": false,
    "tool_name": "...",
    "agent_category": "auth-attacker",
    "confidence": 0.7,
    "has_reasoning_trace": true,
    "has_counter_proof": true,
    "has_fingerprint": true
  },
  "auto_dismissed": false,
  "auto_dismissal_reason": null,
  "prior_label_attribution": null
}
```

When the engine auto-dismisses on a prior-FP fingerprint (RLHF Phase 1 / §18 row 2):

```json
{
  "...": "...",
  "verification_status": "could_not_verify",
  "auto_dismissed": true,
  "auto_dismissal_reason": "prior_human_fp",
  "severity_pre_auto_dismissal": "medium",
  "prior_label_attribution": {
    "verdict": "fp",
    "fp_reason": "framework_default_blocked",
    "labeler": {"id": "alice@example.com", "role": "security-lead"},
    "labeled_at": "2026-04-15T13:14:15Z",
    "label_id": "lbl_abc123",
    "scan_run_id": "run-xyz789"
  }
}
```

The wrapper renders auto-dismissed findings with a slate banner per `wrapper-wishlist.md` §15.1.

---

## 3. The event catalog — what the wrapper consumes

The full catalog lives in `events.jsonl`. The wrapper typically routes on `event_type`:

### 3.1 Run lifecycle events

| `event_type` | When | Notable payload |
|---|---|---|
| `run.configured` | Run start | `scan_mode`, `scope_mode`, `model_name`, `targets[]` |
| `run.test_plan` | Pre-recon | The agent's planned attack tree |
| `run.coverage_complete` | At run-end (no gaps) | Confirms full category coverage per (target_type, scan_mode) |
| `run.coverage_gap` | At run-end (gaps exist) | List of `(target_type, scan_mode, category)` triples not exercised |
| `run.summary` | At run-end | Aggregates: total findings, by severity, by category |

### 3.2 Phase + target events

| `event_type` | When | Notable payload |
|---|---|---|
| `phase.entered` / `phase.completed` | Per phase boundary (recon → exploit → validate → report) | `phase_name` |
| `target.started` / `target.completed` | Per target | `target_url`, `target_type` |

### 3.3 Tool execution events (every tool call carries provenance — §18 row 10)

| `event_type` | When | Notable payload |
|---|---|---|
| `tool.execution.started` | Tool call begin | `actor.tool_name`, `actor.target`, `actor.provenance`, `payload.args` |
| `tool.execution.updated` | Mid-call (long tools) | Same |
| `tool.execution.completed` | Tool call end | + `payload.result` |

`actor.provenance` ∈ `{trusted_source, intel_feed, target, operator_input, framework, mixed}` — render badges per `wrapper-wishlist.md` §15.5.

### 3.4 Agent events

| `event_type` | When | Notable payload |
|---|---|---|
| `agent.created` | Specialist spin-up | `actor.agent_id`, `payload.category` |
| `agent.self_audit` | Between phases (§18 row 9) | `phase_completed`, `phase_starting`, `categories_covered`, `categories_skipped`, `stuck_sub_agents`, `concern`, `next_phase_plan` |

### 3.5 Hypothesis lifecycle events (§18 row 9)

| `event_type` | When | Notable payload |
|---|---|---|
| `hypothesis.opened` | Sub-agent posts a working hypothesis | `surface`, `category`, `hypothesis`, `agent_id` |
| `hypothesis.confirmed` | Sub-agent confirms (links to a finding) | `hypothesis_id`, `resolution`, `linked_finding_id` |
| `hypothesis.dismissed` | Sub-agent rules out | `hypothesis_id`, `dismissal_reason` (13-value closed enum) |

Tail with the `active_hypotheses.jsonl` append-only log in parallel — same data, file-shape vs. event-shape.

### 3.6 Finding events

| `event_type` | When | Notable payload |
|---|---|---|
| `finding.created` | Vulnerability emitted | `fingerprint`, `category`, `severity`, finding payload |
| `finding.dismissed` | Agent dismisses an alternative hypothesis (negative evidence) | `surface`, `hypothesis`, `dismissal_reason` |
| `finding.kill_chain` | A multi-step kill-chain assembled from primitives | `chain_steps[]` |
| `finding.auto_dismissed` | Engine auto-dismissed on prior-FP fingerprint (§18 row 2) | `fingerprint`, `auto_dismissal_reason`, `prior_label_attribution`, `severity_pre_auto_dismissal` |

### 3.7 Ingestion events (§18 row 3)

| `event_type` | When | Notable payload |
|---|---|---|
| `traffic.ingested` | After `ingest_har_file` / `ingest_burp_file` runs | `source_format`, `requests_imported`, `unique_endpoints`, `new_endpoints_added`, `auth_classes_detected[]` |

---

## 4. Wrapper-side writeback — closing the FP loop

The engine reads exactly one structured artifact from the wrapper: `feedback.jsonl`. Writing this file is how the wrapper teaches the engine to stop re-emitting known FPs.

### 4.1 Schema (one record per labelled finding)

```json
{
  "schema_version": 1,
  "finding_fingerprint": "a1b2c3d4e5f60718",
  "verdict": "fp",
  "fp_reason": "framework_default_blocked",
  "severity_correction": null,
  "notes": "Internal: this WAF rule already blocks the payload.",
  "labeler": {"id": "alice@example.com", "role": "security-lead"},
  "labeled_at": "2026-05-04T13:14:15Z",
  "scan_run_id": "run-abc123",
  "label_id": "lbl_xyz789"
}
```

**Closed enums** (mirror engine — `tool_dismiss_finding` / `feedback_loader._VALID_FP_REASONS`):

- `verdict` ∈ `{tp, fp, partial_tp, needs_review, out_of_scope}`
- `fp_reason` ∈ `{input_properly_encoded, framework_default_blocked, csrf_token_validated, auth_enforced, not_reflected, different_origin, out_of_scope, false_positive_signature, compensating_control, intended_behavior, test_fixture, deprecated_path, other}`

`notes` is free-text but **the engine strips it before re-attaching `prior_label_attribution` to a finding** — privacy default. Wrapper UI may surface notes locally; do not assume they propagate into engine artifacts.

### 4.2 Append, don't overwrite

The wrapper appends one JSON line per labelling action. The engine treats the latest-by-`labeled_at` per-fingerprint as the active verdict. Multiple labels per fingerprint = audit trail; the engine picks the most recent.

### 4.3 Discovery order (engine reads first match wins, but unions across all)

1. `--feedback-from <PATH>` CLI flag (highest priority — explicit per scan)
2. `STRIX_FEEDBACK_FROM` env var (fallback)
3. `<run_dir>/feedback.jsonl` (per-run feedback — labels collected during this scan)
4. `~/.strix/feedback.jsonl` (cumulative cross-run — the wrapper's persistent label store)

The engine **unions across all paths** — both per-scan and cumulative apply.

### 4.4 Auto-dismiss policy gate

The wrapper-controlled env var `STRIX_FP_AUTO_DISMISS` decides what the engine does with the labels:

| Policy | Behaviour |
|---|---|
| `conservative` (default) | Auto-dismiss when ≥ 1 FP and zero TPs. Mixed history → don't dismiss. |
| `aggressive` | Auto-dismiss when latest verdict is FP, regardless of prior TPs. |
| `off` | Never auto-dismiss; visibility-only mode. |

Progressive rollout: new wrappers start in `off` (operators see auto-dismissal candidates flagged but not removed), graduate to `conservative`, power users opt into `aggressive`.

### 4.5 Force-show / re-promote pattern

When the operator clicks "Force-show this finding" on an auto-dismissed card, the wrapper writes a new `feedback.jsonl` line with `verdict=tp` (and optionally `fp_reason: null`). On the next scan, the engine sees the latest verdict is TP and stops auto-dismissing. The audit trail is preserved (both labels stay in the file).

---

## 5. Build a Minimum-viable-AI-security-engineer

This section is the **how**: how a wrapper composes the §18 engine primitives into the AI-security-engineer experience documented in [`roadmap.md` §18](roadmap.md#18-minimum-viable-ai-security-engineer-credibility) and [`wrapper-wishlist.md` §15 + §16](wrapper-wishlist.md#15-minimum-viable-ai-security-engineer-wrapper-companions-for-engine-18).

The engine ships the substrate. The wrapper composes the experience. Without the composition, the engine work is invisible to non-tech operators.

### 5.1 The five §18 primitives the engine gives you

| §18 row | Engine PR | What you get | Where it lands |
|---|---|---|---|
| 4 — Finding-quality signals | [#137](https://github.com/ClatTribe/strix/pull/137) | `confidence`, `reasoning_trace[]`, `counter_proof`, `reproducibility_token` per finding | `vulnerabilities.json` + `finding.created` event payload |
| 9a — Active hypotheses | [#138](https://github.com/ClatTribe/strix/pull/138) | Cross-specialist shared `active_hypotheses.jsonl` + lifecycle events | `<run_dir>/active_hypotheses.jsonl` + `hypothesis.*` events |
| 9b — Agent self-audit | [#140](https://github.com/ClatTribe/strix/pull/140) | `agent.self_audit` events between phases | `events.jsonl` |
| 10 — Tool-output provenance | [#139](https://github.com/ClatTribe/strix/pull/139) | `actor.provenance` on every `tool.execution.*` event | `events.jsonl` |
| 3 — HAR / Burp ingestion | [#141](https://github.com/ClatTribe/strix/pull/141) | `ingest_har_file` / `ingest_burp_file` tools + `traffic.ingested` events | Tool API + `events.jsonl` |
| 2 — Closed FP feedback loop | [#142](https://github.com/ClatTribe/strix/pull/142) | `trajectory.jsonl`, finding `features` block, `feedback.jsonl` ingestion, auto-dismiss | All of the above + `<run_dir>/trajectory.jsonl` |

### 5.2 The five operator-UX surfaces to compose them into

The order matters — each surface depends on the previous. Build in this order to ship value progressively.

#### 5.2.1 Surface 1 — "The casefile" (per-finding card)

> _The single biggest "is this AI talking to me, or guessing?" tell._

A single component that renders all four §18-row-4 signals + provenance trail + auto-dismiss state inline. This is **the** core artifact the AI security engineer produces. Auditors read top-to-bottom.

```
┌────────────────────────────────────────────────────────────────┐
│ ▣  Reflected XSS in /search                  severity: medium   │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ confidence ████████████░░░░░░  0.72                              │
│ reproducibility token: 0a1b2c3d4e5f6071  (seen 3× across runs)  │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Why we believe this is exploitable:                              │
│ • `q` parameter is reflected unencoded into <script> context     │
│ • `<script>alert(1)</script>` payload returned 200 with body…  │
│ • The CSP header allows `unsafe-inline` (no mitigation)          │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ ⚠ Possible alternative explanation:                              │
│ "The reflection occurs only when the Referer header matches…"   │
│ evidence: [response excerpt]                                      │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Reasoning trail (12 tool calls, 4.1s):                           │
│ ⊙ send_request [target] → /search?q=test                         │
│ ⊙ analyze_response [framework] → reflected, no encode             │
│ ⊙ send_request [target] → /search?q=<svg/onload=…>              │
│ ⊙ … 9 more →                                                     │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ verdict:  ( TP )  ( FP )  ( partial_tp )  ( needs_review )     │
└────────────────────────────────────────────────────────────────┘
```

Components used:
- Top: severity + title (from `vulnerabilities.json`).
- Confidence bar: `confidence` (#137).
- Cross-scan id: `reproducibility_token` (#137) — wrapper-side persistence joins on this.
- Reasoning trace: `reasoning_trace[]` (#137).
- Counter-proof block: `counter_proof` (#137).
- Reasoning trail: collapse the trajectory's `events_compact[]` (#142) — annotate each tool call with its provenance badge (#139).
- Verdict buttons: write to `feedback.jsonl` (#142, §4 above).

When the finding is auto-dismissed (`auto_dismissed: true`):

```
┌────────────────────────────────────────────────────────────────┐
│ AUTO-DISMISSED — labeler marked an identical finding as          │
│ `framework_default_blocked` on 2026-04-15 by alice@example.com.  │
│ severity_pre_auto_dismissal: medium                              │
│                                          [ Force-show / Re-promote ] │
└────────────────────────────────────────────────────────────────┘
```

#### 5.2.2 Surface 2 — "Live engineer working" (in-progress scan view)

> _Looks like watching a senior pen-tester work — replaces the legacy log-tail view._

A real-time pane that consumes `events.jsonl` (tail mode) + `active_hypotheses.jsonl` (poll) + the `agent.self_audit` events. Layout:

```
┌────────────────────────────────────────────────────────────────┐
│ Phase: exploit  ●●○○                  3 specialists active       │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ Open hypotheses (4):                                              │
│ • auth-attacker  /admin       weak-session-fixation     8s ago    │
│ • ssrf-scanner   /api/import  blind-ssrf-via-pdf        12s ago   │
│ • idor-scanner   /api/users   horizontal-priv-escalation 24s ago  │
│ • ssrf-scanner   /api/import  redis-unauth (CONFIRMED)  1m ago →  │
│                                                                   │
│ Active tool calls:                                                │
│ ⊙ auth-attacker  send_request [target]  POST /admin/login        │
│ ⊙ ssrf-scanner   pdf_payload  [framework]  building injection    │
│                                                                   │
│ Self-audit (last):                                                │
│ ✓ Recon → Exploit  covered: subdomain_enum, dns_hygiene,         │
│   cloud_assets, port_scan, fingerprint, surface_map               │
│ ⚠ Skipped: cohort_session_audit  (concern: no cohort detected)   │
└────────────────────────────────────────────────────────────────┘
```

Components used:
- Phase indicator: `phase.entered` / `phase.completed` events.
- Specialist count + open hypotheses: `active_hypotheses.jsonl` filtered by `status="open"` (#138).
- Sister-specialist coordination: render the `is_surface_under_investigation` indicator (#138) as a 🟡 badge on each surface.
- Active tool calls: `tool.execution.started` not yet matched by `tool.execution.completed`; render `actor.provenance` as a badge (#139).
- Self-audit panel: latest `agent.self_audit` event (#140) — gate-breach if `categories_skipped` non-empty.

#### 5.2.3 Surface 3 — "The HAR/Burp on-ramp" (engagement startup)

> _First move on every real pen-test._

Drag-drop UI accepts `.har` + `.xml`, uploads to the engine container, triggers `ingest_har_file` / `ingest_burp_file`. Render the `traffic.ingested` event payload as an immediate uplift card:

```
┌────────────────────────────────────────────────────────────────┐
│ Imported burp-2026-05-04.xml                                     │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ 1,247 requests across 84 unique endpoints                        │
│ 23 endpoints were not in the surface map — added                 │
│ Auth classes detected: bearer, cookie                            │
│                                                                   │
│ ⚠ The following header VALUES were redacted (engine sees names    │
│ only): Authorization, Cookie, Set-Cookie, X-API-Key, X-Auth-Token│
└────────────────────────────────────────────────────────────────┘
```

Components used:
- Import summary: `traffic.ingested` payload (#141).
- Auth-class badges per host: derived from the same payload.
- Redaction notice: static text, drives compliance-team trust.

#### 5.2.4 Surface 4 — "Coverage receipt" (post-scan compliance artefact)

> _Operator hands this to compliance: "here's evidence the engine did its job."_

Append to the bottom of every report. Aggregates across phases, categories, and the §18 primitives:

```
COVERAGE RECEIPT — run-abc123
==========================================
Phases run:        recon → exploit → validate → report (4/4)
Categories tested: 47 / 49      (gaps: 2 — see below)
HAR / Burp ingested: 1 file, 1,247 requests, 84 endpoints
Hypotheses opened: 23  (confirmed: 4, dismissed: 19)
Self-audits:       4   (gate-breaches: 0)
Auto-dismissals:   3   (driven by 3 prior FP labels by alice@…)
Feedback labels written this run: 17 (12 TP, 4 FP, 1 needs_review)

Gaps:
  - cohort_session_audit  (no cohort detected — informational)
  - dom_xss_static_probe  (no JS reflections in surface — clean)
```

Components used:
- Phase / category coverage: `coverage.json` + `run.coverage_complete` / `run.coverage_gap` events.
- HAR/Burp summary: `traffic.ingested` payloads aggregated.
- Hypothesis stats: `active_hypotheses.jsonl` aggregated.
- Self-audits: `agent.self_audit` event count.
- Auto-dismissals: count of `finding.auto_dismissed` events.
- Feedback labels: count of new lines appended to `feedback.jsonl` during this scan.

#### 5.2.5 Surface 5 — "Continuous casefile" (cross-scan stable identity)

> _A continuous casefile, not 47 separate scan reports._

Use the `fingerprint` (stable across runs by §11 design) + `reproducibility_token` (#137) to thread findings across scans. The wrapper persists per-fingerprint state in its own DB:

```sql
CREATE TABLE finding_history (
  fingerprint        TEXT PRIMARY KEY,
  first_seen_run     TEXT NOT NULL,
  first_seen_at      TIMESTAMPTZ NOT NULL,
  last_seen_run      TEXT NOT NULL,
  last_seen_at       TIMESTAMPTZ NOT NULL,
  observation_count  INTEGER NOT NULL DEFAULT 1,
  -- Latest verdict from feedback.jsonl
  verdict            TEXT,
  fp_reason          TEXT,
  labeled_at         TIMESTAMPTZ,
  -- Snapshot of latest engine signals
  latest_confidence  NUMERIC,
  latest_severity    TEXT
);
```

On each scan, the wrapper:
1. Reads `vulnerabilities.json`.
2. Upserts every finding by `fingerprint`, incrementing `observation_count`.
3. Joins on `feedback.jsonl` to pin the latest verdict.
4. Renders the per-finding card with a "seen N× across M runs since [date]" line.

This thread is what turns Strix from "a tool that runs scans" into "an engineer that maintains an ongoing relationship with your target's risk surface." It is purely wrapper persistence — every primitive is already in the engine output.

### 5.3 The progressive-trust rollout

Don't ship all five surfaces at once. The order is calibrated so the wrapper's UX matures as the operator's trust in the engine matures:

| Phase | Surface | Operator state | What changes |
|---|---|---|---|
| 1 | Surface 1 (casefile) + Surface 4 (coverage receipt) | Skeptical; manually triages every finding | Ships the explainability primitives. Operator learns to trust confidence + reasoning + counter-proof. |
| 2 | Surface 2 (live view) + Surface 3 (HAR on-ramp) | Comfortable; uses Strix on real pen-tests | Ships the agent-experience primitives. Operator sees specialist coordination + provenance + ingestion lift. |
| 3 | Surface 5 (continuous casefile) | Trusting; relies on Strix as their primary engineer | Ships the cross-scan thread. Operator stops thinking in "scans" and starts thinking in "ongoing risk surface." |
| 4 | Auto-dismiss `conservative` mode on by default | Trusting; tolerates engine-driven triage | The closed FP loop activates. Today's FPs become tomorrow's auto-dismissals. |

### 5.4 What the engine doesn't give you (yet)

The §18 list also has 5 unshipped rows. Plan UX hooks but don't build until the engine ships:

| §18 row | Status | Wrapper hook |
|---|---|---|
| 1 — Validator agent (white-box → black-box bridge) | unshipped | Reserve a "Validate in browser" button on `verification_status: pattern_match` findings; greys out today, lights up when the engine ships. |
| 5 — Multi-language taint (JS/TS first) | unshipped | Surface JS/TS taint findings under the same code-snippet UI as #108 DOM-XSS. |
| 6 — `llm_app` target type (OWASP LLM Top 10) | unshipped | Add `llm_app` as a target type in the wrapper's scan-config UI; wire the engine flag when shipped. |
| 7 — Public benchmark + regression suite | unshipped | Reserve an "Engine benchmark score" badge on the wrapper's marketing surface. |
| 8 — Browser-automation specialist | unshipped | Surface DOM-XSS / CSP / postMessage findings under their own specialist tag (the engine will start emitting `agent_category=browser-automation`). |

### 5.5 Putting it all together — wrapper invocation example

```python
import json, os, subprocess
from pathlib import Path

def run_scan_with_feedback_loop(target: str, run_id: str) -> dict:
    """End-to-end scan + feedback-loop integration."""
    runs_dir = Path("/var/run/strix/runs") / run_id
    runs_dir.mkdir(parents=True, exist_ok=True)

    # Ensure the per-run feedback file exists (wrapper-collected labels
    # from earlier runs against the same target accumulate here).
    feedback_path = runs_dir / "feedback.jsonl"
    if not feedback_path.exists():
        # Seed from the wrapper's persistent label store.
        seed_feedback_from_wrapper_db(feedback_path, target)

    env = {
        **os.environ,
        "STRIX_LLM": "openai/gpt-5.4",
        "LLM_API_KEY": os.environ["WRAPPER_OPENAI_KEY"],
        "STRIX_FP_AUTO_DISMISS": "conservative",
        "STRIX_FEEDBACK_FROM": str(feedback_path),
    }

    # 1. Invoke
    rc = subprocess.run(
        [
            "strix", "-n",
            "--target", target,
            "--scan-mode", "standard",
            "--feedback-from", str(feedback_path),
            "--output-dir", str(runs_dir),
        ],
        env=env,
        check=False,
    ).returncode

    # 2. Read artifacts
    findings = json.loads((runs_dir / "vulnerabilities.json").read_text())
    trajectories = [
        json.loads(line)
        for line in (runs_dir / "trajectory.jsonl").read_text().splitlines()
        if line.strip()
    ]
    run_meta = json.loads((runs_dir / "run_meta.json").read_text())

    # 3. Persist + render — see §5.2 surfaces.
    upsert_findings_to_wrapper_db(findings, run_id)
    upsert_trajectories(trajectories, run_id)

    # 4. Coverage receipt → render in-app and email.
    return {
        "run_id": run_id,
        "exit_code": rc,
        "finding_count": len(findings),
        "auto_dismissed_count": sum(1 for f in findings if f.get("auto_dismissed")),
        "vendor_risk": run_meta.get("vendor_risk"),
        "compliance_posture": run_meta.get("compliance_posture"),
    }
```

The labelling round-trip — operator clicks `FP` → wrapper appends a line to the operator's per-org `feedback.jsonl` → next scan picks it up via the discovery-order — is the **only** state the wrapper has to manage. Everything else is read-only consumption of engine artifacts.

---

## 6. Versioning + compatibility

- **Schema-versioned files** (`features.schema_version`, `trajectory.jsonl[].schema_version`, `feedback.jsonl[].schema_version`) bump only on **breaking** changes. Additive fields don't bump. The wrapper SHOULD read the version field and degrade gracefully on unknown values.
- **Closed-enum fields** (`verdict`, `fp_reason`, `dismissal_reason`, `provenance`) are documented in `docs/rlhf-design.md`, `roadmap.md` §17.6, and this doc. The wrapper SHOULD treat unknown values as `other` rather than crashing.
- **Event types** are append-only. New event types appear in this doc's §3 catalog as engine PRs ship. Old types are never removed (wrappers built against older engines keep working).
- **CLI flags** are stable contract. Deprecation: a flag stays for ≥ 2 minor releases after a `DeprecationWarning` lands.

The contract is: the wrapper can pin the engine to a specific version and still upgrade fearlessly within a major; major-version bumps come with a migration guide on this page.

---

## 7. Reference

| File | Purpose |
|---|---|
| [`README.md`](README.md) | End-user CLI guide |
| [`roadmap.md`](roadmap.md) | Engine direction; §18 = the minimum-viable-AI-security-engineer priority list |
| [`wrapper-wishlist.md`](wrapper-wishlist.md) | Per-PR wrapper-side rendering / integration spec |
| [`docs/rlhf-design.md`](docs/rlhf-design.md) | Closed FP-loop architecture (Phases 1–N) |
| [`docs/ai-security-engineer-gap-analysis.md`](docs/ai-security-engineer-gap-analysis.md) | The audit that produced §18 |

When in doubt: **read the test file**. Every wrapper-facing primitive in this doc has a corresponding `tests/telemetry/` or `tests/tools/` test that pins its shape.
