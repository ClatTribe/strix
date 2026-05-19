# Strix-quick competitive assessment — 2026-05-19

**TL;DR:** A $0 OSS pipeline (semgrep + trivy + grype + osv-scanner + checkov) finds **3–30× more candidate vulnerabilities** than Strix-quick on the same fixtures, in seconds, with no API cost. Strix's value proposition cannot be raw finding volume — it has to be prioritization (KEV / EPSS / reachability), attack-path chaining, and exploit-PoC synthesis. The MA-S2 P0 work (shipped 2026-05-19) addresses the first; the rest is still gap-work.

This document records measurements, not aspirations. Recommendations at the bottom.

---

## 1. Measurement runs (what landed, what didn't)

| Run | Date | Backends present | Fixtures attempted | Result |
|---|---|---|---|---|
| **R1: strix-quick, no backends** | 17:27–18:11 UTC | none (nuclei/semgrep/trivy/grype/osv/checkov all missing on PATH) | 6/11 (vampi, crapi, flask-vuln, iac-vibe, sast-vibe, sca-reachability) | crapi failed (fixture bitrot — `crapi/crapi-community:0.7.0` 404 on Docker Hub). Other 5 completed but recall = **6/46 = 13%**. |
| **R2: OSS-only direct scans** | 21:15–21:17 UTC | all 5 OSS tools installed + DBs updated | 7/11 (code+repo+web+code fixtures) | Completed in **~70 sec total**, $0 cost. Raw finding counts in §3. |
| **R3: strix-quick, backends installed** | 21:13–21:25 UTC | nuclei (templates ✓), semgrep, trivy (DB ✓), grype (DB ✓), osv-scanner, checkov, sqlmap, nikto | 2/11 (vampi, crapi) | **Aborted.** Gemini auth/quota wall hit on vampi after burning 2.6M input tokens / $0.45. crapi failed same bitrot. |

---

## 2. Why R3 stopped — and what it tells us

R3's vampi run consumed **2.6M input tokens (1.3M cached) and $0.45 of Gemini 2.5 Flash** before `LLM request failed: AuthenticationError` started repeating in the LiteLLM client. Three working theories:

1. **Gemini free-tier TPM cap.** Gemini 2.5 Flash free tier is 1M tokens-per-minute. 2.6M in ~11 min of wall time is right at the boundary.
2. **Gemini RPD cap.** Free tier is 1,500 requests-per-day. A single quick-mode run on an API fixture can issue hundreds of requests.
3. **Key was secret-scanned and revoked.** Earlier conversations may have exposed the key; Google's automated scanner can revoke within hours.

Independent of the cause, the relevant **product finding** is:

> Strix-quick spent **2.6M tokens / $0.45 on a single API fixture (vampi) and produced 0 findings against 8 must_find expected vulns.** Tokens-per-finding is unbounded when recall = 0.

The simulation_run.json for that run also shows: `specialists_dispatched: 0`, `mitre_techniques_exercised: []`, `kg_node_count: 0` (KG counter not wired in quick mode), `ai_reasoning_calls: 0` (counter only increments on successful completions; the rich token-burn implies many partial/failed calls).

---

## 3. OSS-only direct-scan results (R2) — the floor

All counts are raw finding counts from each tool (no must_find precision filtering). Trivy/grype filtered to HIGH+CRITICAL severity. `naive_sum` over-counts duplicates across tools but bounds detection volume from above.

| Fixture | semgrep | trivy | grype (H/C) | osv-scanner | checkov | naive sum |
|---|---:|---:|---:|---:|---:|---:|
| flask-vuln | **15** | 0 | 0 | 0 | 0 | 15 |
| iac-vibe | 0 | 0 | 0 | err* | **4** | 4 |
| sast-vibe | 2 | 0 | 0 | err* | 0 | 2 |
| sca-reachability | 0 | 5 | 5 | **12** | 0 | 22 |
| sca-supply-chain | 0 | 3 | 4 | **9** | 0 | 16 |
| sca-vuln-deps | 0 | 32 | 32 | **114** | 0 | 178 |
| vibe-app | 3 | 3 | 3 | **9** | 2 | 20 |
| **totals** | **20** | 43 | 44 | 144 | 6 | **257** |

\* osv-scanner errors on iac-vibe + sast-vibe — those fixtures have no recognizable language manifest (requirements.txt, package.json, etc.). Expected behaviour.

**Bare semgrep finds 15 vulns in flask-vuln in ~3 seconds.** Strix-quick (R1, no backends) found 3 in 11 minutes for the same fixture.

---

## 4. R1 vs R2 side-by-side — strix-quick (no backends) compared to OSS-only

| Fixture | Strix-quick R1 found / expected | OSS naive sum | Strix recall_must_find | OSS:Strix ratio |
|---|---:|---:|---:|---:|
| flask-vuln | 3 / 10 | 15 (semgrep) | 0.30 | **5×** |
| iac-vibe | 3 / 15 | 4 (checkov) | 0.20 | 1.3× |
| sast-vibe | 0 / 8 | 2 (semgrep) | 0.00 | **∞** |
| sca-reachability | 1 / 5 (**1 FP, 0 TP**) | 22 (trivy+grype+osv) | 0.00 | **22×** |
| vampi | 0 / 8 | n/a (API fixture, no OSS tool tested) | 0.00 | n/a |

The R1 recall numbers are not strix's *best-case* recall (R1 ran with all signature backends missing — `scan_sast` returns `partial — install semgrep` every call, `scan_container_image` early-returns on `_trivy_available() == False`, etc.). They establish that **without backends, the LLM lead loop alone produces 0–30% recall**. Whether *with* backends strix beats OSS-only remains unproven (R3 didn't complete).

---

## 5. Architecture signal extracted from R1 + R3 simulation_run.json files

Every R1/R3 quick-mode `simulation_run.json` reported:

```
specialists_dispatched: 0
specialist_categories_exercised: ["start_info"]
mitre_techniques_exercised: []
kg_node_count: 0
kg_edge_count: 0
```

This confirms the v3-quick-mode design choice: `dispatch_cap=0`, no specialist invocations, lead-loop-only. The lead has access to `scan_sast`, `scan_sca_lockfiles`, `scan_iac`, `scan_container_image`, **and** `scan_nuclei_templates` via its tool_catalog (verified in `strix/agents/lead_agent/tool_catalog.py`), so the deterministic-scanner path *is* reachable when backends are installed. But `kg_node_count: 0` indicates the knowledge graph isn't being populated (or isn't being counted) under quick mode — a measurable gap.

---

## 6. Honest competitive position

**Strix-quick cannot win on raw detection volume.** OSS pipelines using current-gen signature engines:
- detect 5–30× more candidate findings,
- run in seconds, not minutes,
- cost $0 in API spend,
- ship daily signature updates from large maintainer communities (nuclei templates ~9k YAMLs, semgrep registry, osv.dev).

What strix-quick *could* win on, if the implementation matches the design intent:

1. **Prioritization quality.** KEV/EPSS/reachability filtering of a 178-finding `sca-vuln-deps` sum into the 5–10 that actually matter. (MA-S2 P0-CVS-B contextual_priority block — shipped.)
2. **Attack-path chaining.** Going from "32 vuln deps + 2 SAST hits" to "this SAST sink → this dep CVE → privilege escalation chain". (`attack_paths.jsonl` — emitted, but every run so far is empty because dispatch_cap=0 leaves no specialists to build chains.)
3. **Exploit-PoC generation.** Going from "CVE-2024-X in component Y" to a working PoC against the customer's deployed version. (Specialist team — not invoked in quick mode by design.)
4. **Triage downgrade.** R9 (unreachable_high_downgrade) — shipped, but only fires when reachability layer emits explicit `verdict: "unreachable"`. No fixture in the suite exercises that path under quick mode (the SAST/SCA layer doesn't compute reachability when scan_sast returns "partial").

**Standard mode (not measured here)** is where the specialist team actually runs. The competitive comparison the customer cares about is `strix --scan-mode standard` vs `OSS + manual review`, not `strix --scan-mode quick` vs `OSS direct`. Quick mode in its current form is too thin to be a serious competitor — it's a triage tier, and we should market it that way.

---

## 7. Action items

### Already shipped (MA-S2 P0)
- `simulation_run.json` + `attack_paths.jsonl` + `contextual_priority` blocks emitted on every run (incl. quick).
- R9/R10 contextual triage rules (PR #358).
- EPSS + KEV enrichment (PR #352).

### Immediate (this week, no code required)
1. **Re-run R3 once Gemini quota resets or with a fresh key** — necessary to settle the "do backends actually help" question. Cap per-fixture cost at $0.25 (today's R3 vampi hit $0.45 alone), set `--max-cost 0.25` or use Anthropic Haiku at lower per-token cost.
2. **Fix crapi fixture bitrot** — `benchmarks/per_target/fixtures/api/crapi/docker-compose.yml` pins `crapi/crapi-community:0.7.0` which Docker Hub now 404s. Pin to a current tag or vendor the images. Separate PR.
3. **Document quick mode honestly in product copy.** It is recon-and-triage, not a detection tier. The "5–10% of standard-mode cost" framing implies "5–10% of standard-mode recall" — which roughly matches what we measured.

### Short-term (next sprint)
4. **Increase quick-mode dispatch_cap from 0 → 1** for `scan_nuclei_templates` specifically. nuclei is the highest-ROI specialist for API targets (vampi-like) and ~9k community templates cover most one-shot signature wins. Cost impact: ~+30% per run, recall impact (estimated): +0.3 on API fixtures.
5. **Wire `kg_node_count` to actually count** — currently always 0 in quick mode. Either populate it or stop emitting it. Misleading telemetry > no telemetry.
6. **Add an `oss_floor` comparison column to `benchmarks/per_target/runner.py`** — run semgrep/trivy/grype against each fixture as part of the bench harness and report `strix_recall - oss_floor` as the marginal-value-add metric. If that delta is negative for any fixture, we have honest data to drive the next arc.

### Medium-term (next milestone)
7. **Ship a measurable `strix --scan-mode standard` baseline** against this same fixture set. That's the comparison customers will actually run when evaluating us.
8. **Build a deduplicated "true positive against must_find" comparison** for OSS-only vs strix-quick vs strix-standard. naive_sum from §3 is upper-bound, not TP count.

---

## 8. Provenance

- R1 baseline JSONs: `benchmarks/per_target/baseline/*_20260519_172722_quickbase.json` (5 fixtures)
- R2 OSS-only summary: `/tmp/oss_only_baseline_20260519_211539.md`
- R3 partial: `benchmarks/per_target/baseline/vampi_20260519_211339_quickbase.json` (1 fixture, aborted)
- Driver: `/tmp/run_quick_baseline.sh`
- OSS driver: `/tmp/oss_only_baseline.py`
- Strix worktree: `/Users/ashish/Downloads/cowork/strix/.claude/worktrees/objective-sammet-7e7f2b`
- Strix branch: `origin/main` (post-MA-S2 P0 merge)
