# RLHF-driven false-positive reduction — design doc

**Status:** Design / pre-implementation. None of this is shipped yet.
**Owner:** ClatTribe security-engineering.
**Companion repo:** `webappsec/` (wrapper) — UI / labeling / writeback.
**Future companion repo:** `strix-feedback-loop/` (new) — label aggregation, FP-classifier training, DPO.

## TL;DR

Three layers, each with a different deployment / ownership posture:

1. **Strix engine** — emit the data and consume the trained artifacts.
2. **Wrapper (`webappsec/`)** — capture human labels, show the labeler the agent's reasoning trajectory.
3. **New project (`strix-feedback-loop/`)** — aggregate labels across customers, train the FP classifier, ship artifacts back to strix.

The loop closes within one customer (label → next scan auto-dismisses) AND across customers (aggregated labels train a shared classifier).

Don't try to do it in one project — the privacy / latency / deployment shapes diverge sharply.

## Goals

- Reduce false-positive rate on findings without losing TPs.
- Capture the human reviewer's verdict + reason in a structured, aggregable way.
- Close the loop within a customer's deployment (today's labels improve tomorrow's scan in the same customer's strix install).
- Eventually close the loop across customers (privacy-scrubbed shared training set).
- Produce auditor-grade evidence of the human-in-the-loop step (SOC 2 CC4 / CC7 like).

## Non-goals

- Real-time mid-scan re-investigation when a wrapper user disagrees with a finding (defer; the agent loop isn't designed for that).
- Replacing human triage entirely; the goal is to make humans more leveraged, not redundant.
- Auto-merging skill / prompt updates into strix; every change ships through normal code review.
- Differentially-private at-source labeling within a single customer; per-customer label privacy is a deployment concern, not an algorithmic one. Cross-customer aggregation IS DP-grade.

## Architecture

```
┌──────────────────┐    findings + trajectory    ┌──────────────────┐
│      strix       │ ──────────────────────────► │     wrapper      │
│      engine      │                              │   (webappsec)    │
│                  │                              │                  │
│ - findings.json  │                              │ - triage UI      │
│ - events.jsonl   │                              │ - reviewer flow  │
│ - trajectory.    │                              │ - severity-fix   │
│   jsonl   ◄─────────────  feedback.jsonl ─────  │ - trajectory     │
│ - run.signature  │  (labels keyed on fingerprint)│   viewer        │
│                  │                              │                  │
│ - fp_classifier  │ ◄─────  artifact pull ─────  │                  │
│   inference      │                              │                  │
│ - auto_dismiss   │                              │                  │
│ - per-skill rate │                              │                  │
└──────────────────┘                              └──────────────────┘
         ▲                                                 │
         │                                                 │ scrubbed
         │ classifier checkpoint                           │ labels
         │ + skill update suggestions                      ▼
         │                                        ┌──────────────────┐
         └────────────────────────────────────────│ strix-feedback-  │
                                                  │     loop         │
                                                  │   (new repo)     │
                                                  │                  │
                                                  │ - label store    │
                                                  │ - PII scrubber   │
                                                  │ - FP classifier  │
                                                  │   training       │
                                                  │ - DPO / RLHF     │
                                                  │ - skill-update   │
                                                  │   suggestion     │
                                                  │ - drift monitor  │
                                                  └──────────────────┘
```

## End-to-end flow

1. **Scan emits a finding.** Strix attaches deterministic `fingerprint` (already shipped, #14), `trajectory_id`, and a `features` block (new).
2. **Wrapper presents the finding** to a reviewer alongside the agent's investigation trajectory.
3. **Reviewer labels** the finding: `verdict ∈ {tp, fp, partial_tp, needs_review, out_of_scope}`, optional `fp_reason` from the closed enum (mirror of [`dismiss_finding`](../strix/tools/finding_dismissed/finding_dismissed.py) #118), optional `severity_correction`, optional notes.
4. **Wrapper writes `feedback.jsonl`** keyed on fingerprint. Stored next to the run dir AND optionally pushed to a customer-controlled label store.
5. **On the next scan, strix reads `feedback.jsonl`.** When a finding emits with a fingerprint matching a prior `verdict=fp` label, strix auto-dismisses with `dismissal_reason=prior_human_fp` and emits a `finding.auto_dismissed` event. (Auto-dismiss is configurable; default conservative.)
6. **Strix runs an FP classifier** at scan-end against every finding's `features` block. Adds `fp_probability ∈ [0.0, 1.0]`. High-probability findings get demoted (NOT suppressed) to `verification_status=needs_review`.
7. **Wrapper periodically pushes labels** to `strix-feedback-loop` (PII / secret-scrubbed at the wrapper before transmit; opt-in per customer).
8. **`strix-feedback-loop` retrains** the FP classifier on the aggregate set. New checkpoint published.
9. **Strix pulls the latest classifier** at scan start (cached locally; works offline). Loop closes.

The fingerprint chain is the spine — every part of the loop is keyed on it.

## Schemas

### `trajectory.jsonl` (NEW, written by strix at run-end)

One line per finding. Built post-hoc by walking `events.jsonl`.

```json
{
  "schema_version": 1,
  "finding_fingerprint": "a1b2c3d4...",
  "finding_id": "vuln-001",
  "agent_id": "agent_4f3a2c1b",
  "agent_category": "auth-attacker",
  "tool_name": "send_request",
  "category": "sql_injection",
  "severity": "high",
  "events": [
    {"event_id": 12, "type": "tool.execution.started", "timestamp": "..."},
    {"event_id": 13, "type": "tool.execution.updated", "timestamp": "..."},
    {"event_id": 14, "type": "finding.created", "timestamp": "..."}
  ],
  "iterations_to_emit": 3,
  "time_to_emit_seconds": 47.2,
  "tool_calls_in_trajectory": 8,
  "dismissed_alternatives": [
    {"surface": "/api/users/123", "hypothesis": "reflected XSS", "dismissal_reason": "input_properly_encoded"}
  ],
  "exploration_breadth": {
    "unique_endpoints": 12,
    "unique_tools": 4
  }
}
```

### Finding-features block (NEW, attached to each finding)

```json
{
  "features": {
    "category": "sql_injection",
    "severity_ordinal": 4,
    "verification_status": "verified",
    "detection_count": 2,
    "reachability_score": 0.85,
    "is_test_path": false,
    "cwe": "CWE-89",
    "evidence_length_chars": 2340,
    "has_poc_script": true,
    "tool_name": "send_request",
    "agent_category": "auth-attacker",
    "target_type": "web_application",
    "iterations_to_emit": 3,
    "time_to_emit_seconds": 47.2
  }
}
```

The schema is **stable** — a versioned classifier shouldn't get its input shape pulled out from under it. New features are additive (default-zero on absent) and bump `features_schema_version`.

### `feedback.jsonl` (NEW, written by wrapper, read by strix)

The contract between the two layers. JSONL so it's append-friendly and easily diffed.

```json
{
  "schema_version": 1,
  "finding_fingerprint": "a1b2c3d4...",
  "verdict": "fp",
  "fp_reason": "framework_default_blocked",
  "severity_correction": null,
  "notes": "Django CSRF middleware is on; the agent didn't check the middleware list.",
  "labeler": {
    "id": "alice@customer.example",
    "role": "security_engineer"
  },
  "labeled_at": "2026-05-04T09:30:00+00:00",
  "scan_run_id": "run-abc123",
  "label_id": "lbl_8f4d3a2b"
}
```

**`verdict`** ∈ `{tp, fp, partial_tp, needs_review, out_of_scope}`.

**`fp_reason`** uses the same closed enum as [`dismiss_finding`](../strix/tools/finding_dismissed/finding_dismissed.py) (#118) so agent-dismissals and human-FP-labels are aggregable end-to-end:

- `input_properly_encoded`
- `framework_default_blocked`
- `csrf_token_validated`
- `auth_enforced`
- `not_reflected`
- `different_origin`
- `out_of_scope`
- `false_positive_signature`
- `compensating_control`
- `intended_behavior`
- `test_fixture`
- `deprecated_path`
- `other`

## Feature breakdown

### A. Strix (engine) — what to build in this repo

| ID | Feature | Effort | Description |
|---|---|---|---|
| **A1** | Per-finding trajectory capture | M | New `trajectory.jsonl` artifact per run. See schema above. Built post-hoc by walking `events.jsonl` so per-event runtime overhead is zero. New `caused_finding: <fingerprint>` field added to events that led to a finding (lightweight cross-link). |
| **A2** | Finding-feature extraction | S | New `strix/telemetry/finding_features.py`. For each finding, extract a structured features dict (see schema). Lands on the finding as `features` field. **Stable schema** so the classifier's input format doesn't drift. New features are additive; bump `features_schema_version` on changes. |
| **A3** | Feedback ingestion | S | New `--feedback-from <file>` CLI flag + automatic discovery of `~/.strix/feedback.jsonl` and `<run_dir>/feedback.jsonl`. Validated against `feedback.jsonl` schema on load. Loaded into a `fingerprint -> latest_verdict` map at scan start. |
| **A4** | Auto-dismiss on prior-FP fingerprint | S | When a finding emits with a fingerprint that matches a prior `verdict=fp` label and zero `verdict=tp` labels, auto-call [`dismiss_finding`](../strix/tools/finding_dismissed/finding_dismissed.py) (#118) with `dismissal_reason=prior_human_fp` + a `prior_label_attribution` field pointing at the labeler-id. New `finding.auto_dismissed` event. Configurable via `STRIX_FP_AUTO_DISMISS=conservative\|aggressive\|off` (default `conservative`). |
| **A5** | FP-classifier inference | M | New `strix/telemetry/fp_classifier.py`. Loads a pickled classifier from `~/.strix/fp_classifier/<version>.pkl` (small enough — ~MB — to ship inline; lightgbm or sklearn shape). At scan end, scores every finding's `fp_probability`. Stored on the finding. Findings with `fp_probability >= threshold` get **demoted** to `verification_status=needs_review` (NOT suppressed — see Design choices §4). Hand-coded baseline ships first; trained models replace it later via the same loader. |
| **A6** | Per-skill / per-category FP rate | S | Aggregate prior-label `verdict=fp` rate per `(tool_name, category)` tuple. Surface in `run_meta.json["fp_rates"]` with confidence (sample size). Operators see "this tool's FP rate is 15% across N labels — consider tightening". |
| **A7** | Trajectory linkage on existing events | S | Add `caused_finding: <fingerprint>` field to events that led to a finding (`tool.execution.*`, `chat.message`, `finding.created`). Lets the wrapper's trajectory viewer (B2) query "show me everything that led to finding X" without re-walking the full events.jsonl. |

**Total strix-side phase 1 effort:** ~2-3 weeks for one engineer.

### B. Wrapper (`webappsec/`) — what to build in the wrapper repo

| ID | Feature | Description |
|---|---|---|
| **B1** | Per-finding triage UI | TP / FP / partial-TP / needs-review buttons. Closed-enum FP-reason picker. Severity-correction picker. Free-text notes. |
| **B2** | Trajectory viewer | Shows the agent's investigation path for a finding — events tagged with `caused_finding=<fp>`, the dismissed-alternatives, time spent. Labeler grades the reasoning, not just the verdict. |
| **B3** | Reviewer assignment + workflow | Findings get assigned to a security engineer; second-reviewer flow on disagreements; SLA timers per finding. |
| **B4** | Label-conflict resolution | When two reviewers disagree, surface in a tie-break queue. Track inter-rater agreement (Cohen's kappa) per category — when agreement is low, that category's guidance needs revision. |
| **B5** | Feedback writeback to strix | Generate `feedback.jsonl` keyed on fingerprint; ship it back to the strix runs dir for subsequent scans. Optional: push to the central label-store (B7). |
| **B6** | Reviewer audit log | Who labeled what, when, with what justification. SOC 2 evidence — auditors want human-in-the-loop on findings. Composes with strix's signed audit trail (#127). |
| **B7** | Opt-in label sharing | Per-customer toggle: "contribute labels to the shared training set". When ON, labels (privacy-scrubbed, see C2) push to `strix-feedback-loop`. When OFF, labels stay local-only (still feed back into THAT customer's strix install via B5). |

### C. New project: `strix-feedback-loop/` — when to spin it up

The new repo is justified when (a) labels are flowing reliably from at least 2-3 customer deployments, AND (b) the per-customer label volume is enough to make a trained classifier outperform the hand-coded baseline.

| ID | Feature | Description |
|---|---|---|
| **C1** | Multi-customer label store | Per-customer-isolated bucket (cross-customer access prohibited even within the service). Cross-customer aggregation runs as a separate offline job that produces only training-set artifacts, never per-customer reads. Per-tenant encryption-at-rest with customer-controlled keys. |
| **C2** | PII / secret scrubber on training-data ingest | Before a label enters the shared training set, strip: target hostnames (replace with `<host_N>` per-customer), file paths (replace with `<path_N>`), code snippets matching the secret-scan vendor-prefix patterns from #115, IP addresses (replace with `<ip>`), email addresses (replace with `<email>`). Differential-privacy guarantees on the aggregate (`k`-anonymity ≥ 5 across customers per category × dismissal-reason cell). |
| **C3** | FP-classifier training pipeline | Periodic retrain on the aggregate set. Output: a versioned `fp_classifier_v<N>.pkl` artifact + per-version eval report (precision / recall / F1 per category). Strix pulls the latest checkpoint. |
| **C4** | Skill-update suggestion engine | Cluster FPs by `(category, fp_reason)`. When a cluster crosses a threshold ("we keep flagging XSS that gets `framework_default_blocked` 90% of the time"), auto-generate a proposed skill update. Ship as a draft PR to strix for human review. **Never auto-merges.** |
| **C5** | DPO / RLHF on agent trajectories | When trajectory data is rich enough (likely 6-12 months in), pair (TP-trajectory, FP-trajectory) and run DPO. Produces a fine-tuned LLM checkpoint strix can be configured to point at. Highest leverage but highest infrastructure cost — defer until labels are flowing. |

## Why three projects, not one

| Concern | Strix | Wrapper | Feedback-loop |
|---|---|---|---|
| **Deployment** | Customer's sandbox / CI | Customer's app server | ClatTribe-hosted ML infra |
| **Latency** | Per-scan (minutes) | Real-time (humans) | Daily / weekly batch |
| **Data sensitivity** | Sees customer secrets | Sees customer findings | Sees scrubbed aggregates |
| **Code-review velocity** | Conservative (audit) | Fast (UX iteration) | Fast (model iteration) |
| **Tech stack** | Python + LLM + Docker | Web framework | Python + ML / GPU |
| **Public** | Yes (open-source fork) | Customer-deployed | Internal/private |

Mixing these into one repo means the slowest review cadence (audit) gates the fastest iteration cadence (UI), and the strictest data-sensitivity gate (engine) gates the most permissive (ML training).

## Design choices worth flagging

1. **Fingerprint-keyed labels, not finding-id-keyed.** Findings get new IDs every scan; fingerprints are stable across re-scans. A label has to survive re-scans or the loop never closes.

2. **Closed-enum reasons throughout.** TP/FP verdicts alone are useful but `fp_reason` is much more useful. **Reuse the 13-value `dismissal_reason` enum from #118** — same closed enum across `dismiss_finding` (agent-side) and `feedback.jsonl` (human-side) means labels are aggregable end-to-end.

3. **Don't suppress; demote.** A high-FP-probability finding shouldn't disappear — it should drop to `verification_status=needs_review` and get a "low confidence" badge. Disappearing findings make labelers nervous (rightly) and break the auditor's "show me what was checked" question.

4. **Privacy at the schema level, not the deployment level.** PII scrubbing happens before labels leave the customer's wrapper, not inside the central training service. The training service should *receive* already-scrubbed data so it's never *able* to leak even on misconfiguration.

5. **Per-skill FP rate is more actionable than per-finding FP rate.** "Skill X has 40% FP rate on category Y" tells the maintainer what to fix. "Finding 17 was an FP" tells nobody anything beyond the immediate triage.

6. **Auto-dismiss is conservative by default.** Default policy: auto-dismiss when ≥1 prior FP label AND zero prior TP labels for the same fingerprint. Configurable via `STRIX_FP_AUTO_DISMISS`. The wrapper can override (force-show) for specific labelers via a `force_review` field on `feedback.jsonl`.

7. **Trajectory capture is read-only post-walk.** Don't add per-event overhead; the `trajectory.jsonl` is built ONCE at run-end by walking the existing `events.jsonl`. Cheap, stable, optional (gated behind a config flag at first).

8. **The classifier is loaded, not trained, by strix.** Strix never trains. Training lives in `strix-feedback-loop`. Strix loads checkpoints. Keeps strix's deployment shape simple (Python + LLM, no GPU dependency).

9. **Auto-dismiss attribution.** When strix auto-dismisses on a prior-FP label, the dismissal record carries the `labeler.id` and `label_id` of the prior label that caused it. Auditors can trace "why was this dismissed?" back to a specific human's decision.

10. **Demotion is reversible.** If `fp_classifier.demoted_to_needs_review = true` is set on a finding, the wrapper can let the labeler "undo demotion" — restoring the original severity. The undo is itself a label (`verdict=tp`), so it feeds back into the next training cycle.

## Phasing — recommended shipping order

**Phase 1 (now-ish, 1 PR in strix)** — A1, A2, A3, A4. The four foundational pieces. ~2 weeks. At the end of Phase 1, the wrapper can capture labels and the engine will respect them on the next scan. Auto-dismiss on prior-FP fingerprint alone often kills 30-50% of repeat FPs in real deployments.

**Phase 2 (parallelizable, in `webappsec/`)** — B1, B2, B5, B6. The wrapper's labeling UI + writeback + audit log. ~3 weeks of webappsec work. Can be done in parallel with Phase 1.

**Phase 3 (small, in strix)** — A5 with a hand-coded baseline classifier (just heuristics — `verification_status=pattern_match AND detection_count=1 AND reachability_score < 0.3 AND not auth-path-adjacent → fp_probability=0.6`). A6, A7. ~1 week. End of Phase 3: every scan benefits from FP-suppression heuristics, even before any trained model exists. Compounding: each labeled scan tightens the heuristic for the next scan.

**Phase 4 (new repo `strix-feedback-loop/`)** — C1, C2, C3 (FP-classifier training only — no DPO yet). The training pipeline replaces the hand-coded heuristic with a learned one. ~6 weeks for the ML infra. Justified when labels are flowing from ≥2-3 customer deployments and per-customer label volume is in the hundreds per scan.

**Phase 5 (later, in `webappsec/`)** — B3, B4, B7. Multi-reviewer workflow + opt-in label sharing. ~4 weeks.

**Phase 6 (much later)** — C4 (skill-update suggestions), C5 (DPO). Defer until trajectory data is rich enough to make trajectory-pair preference learning meaningful. Likely 6-12 months in.

## Open questions

1. **Conflicting labels across reviewers.** When alice@customer.example labels FP and bob@customer.example labels TP on the same fingerprint, what wins? Proposed: most-recent label wins for auto-dismiss; `fp_classifier` features include `prior_label_disagreement` as a signal. Needs more thought.

2. **Cross-customer fingerprint collisions.** Same fingerprint at different customers — should the labels aggregate? Currently the fingerprint is `(cwe, location, title)`-derived; same fingerprint across customers usually means the SAME class of bug, so aggregating labels makes sense. But location-derived fingerprints can collide spuriously across customers. Worth a deeper look.

3. **Severity-correction without verdict change.** If a labeler says "this is a TP, but you marked it high; it's actually low", does that feed into the FP classifier? Proposed: severity correction is a separate signal (`severity_classifier`), not an FP signal.

4. **Adversarial labelers.** A bad-faith labeler can poison the customer's local model by mass-marking real findings as FP. Mitigations: per-labeler trust scores; require ≥2 labelers for verdicts to flow into auto-dismiss; periodic regression test against a held-out gold set of known-TP findings.

5. **Right-to-be-forgotten on training data.** When a customer churns, their labels get pulled from the training set. The trained model itself is harder — the classifier may have implicitly encoded their data. Proposed: full retrain on customer-churn (acceptable if retraining is daily / weekly anyway).

6. **Continuous-learning regression risk.** New training data could regress the model on a long-stable category. Proposed: every new model checkpoint runs against a frozen eval set; precision drop > 5% on any category blocks rollout.

## Privacy posture

- **Labels never carry the underlying secret.** The `notes` free-text field has the same scrubadub-style sanitization as `events.jsonl` (#127's audit trail). Vendor-prefix-anchored secrets (#115's catalogue) are hard-redacted before write.
- **Customer data stays customer-side until explicit opt-in.** B5 writes `feedback.jsonl` locally; B7 is the toggle that pushes to the central store.
- **PII scrubber runs at the wrapper before transmit.** C2 in the central service is a defense-in-depth — the central service should never *receive* unscrubbed data, even on misconfiguration.
- **Labels carry per-labeler identity** for audit trail (B6) but the central training set strips identity before aggregation (C2).
- **Differential-privacy floor on the shared training set.** `k`-anonymity ≥ 5 per (category × fp_reason) cell — fewer-than-5-customers contributing to a cell drops the cell from the training set rather than risk single-customer leakage.

## What changes in the existing strix codebase

When Phase 1 ships, these files / modules touch:

- **NEW** `strix/telemetry/finding_features.py` — A2 features extractor.
- **NEW** `strix/telemetry/trajectory_capture.py` — A1 post-walk + writer.
- **NEW** `strix/telemetry/fp_classifier.py` — A5 inference (hand-coded baseline at first).
- **NEW** `strix/telemetry/feedback_loader.py` — A3 `feedback.jsonl` parser + validator.
- **MODIFY** `strix/telemetry/tracer.py` — wire trajectory_capture + feedback_loader into `save_run_data`; auto-dismiss check inside `add_vulnerability_report`.
- **MODIFY** `strix/interface/main.py` — `--feedback-from <file>` CLI flag.
- **NEW** `tests/telemetry/test_finding_features.py`, `test_trajectory_capture.py`, `test_fp_classifier.py`, `test_feedback_loader.py`.
- **DOC** this file (`docs/rlhf-design.md`).

## References

- Engine PR for the `dismiss_finding` agent-callable tool + closed-enum dismissal reasons: [#118](https://github.com/ClatTribe/strix/pull/118).
- Engine PR for the canonical-finding fingerprint: #14 (already shipped).
- Engine PR for the cross-tool dedup `detected_by` + `detection_count`: [#98](https://github.com/ClatTribe/strix/pull/98).
- Engine PR for reachability scoring: [#99](https://github.com/ClatTribe/strix/pull/99).
- Engine PR for the cryptographically-signed audit trail: [#127](https://github.com/ClatTribe/strix/pull/127).
- Engine PR for the secret-scan vendor-prefix catalogue (used by C2 scrubber): [#115](https://github.com/ClatTribe/strix/pull/115).
- Wrapper-wishlist (where the `webappsec/` companion items live): [`wrapper-wishlist.md`](../wrapper-wishlist.md).
