# L2 ≤10-tool cap + L2 translation toolkit

**Status:** proposal — pending review
**Owner:** ClatTribe/strix
**Created:** 2026-05-27
**Depends on:** CLAUDE.md §1.5 (product-goal framing, L1 / L2 audience split)
**Related:** iter-37 series (`docs/tool-catalog-rationalization.md`), Q3 (`docs/proposals/2026-05-27-l1-parity-measurement.md`)

---

## 1. The constraint and the audit

### 1.1 Constraint (from the user)

> *"Ensure we optimize in a way that the LLM doesn't have to handle more than 10 tools at a time. It doesn't [do] well with more than 10 tool calls."*

This matches the empirical pattern reported by every LLM-tool-use evaluation: model accuracy degrades steeply once the visible tool count exceeds ~10, regardless of total model capability. Anthropic's own published guidance for Claude tool-use recommends keeping the tool count "small" for production reliability; OpenAI's function-calling docs say the same. The cap is therefore an **architectural invariant**, not an optimization target.

Define it formally:

> **Invariant L2-CAP:** For every asset type, the number of tools visible to the L2 Lead at any point in the scan is ≤ 10. This includes the minimal CORE tools and the per-asset specialist set. It does NOT include tools that fire deterministically in `anchor_prepass` (those execute without the LLM ever seeing them) and does NOT include tools that fire as auto-artifacts inside `finish_scan`.

### 1.2 Current state — does shipped reality honor the invariant?

Audit of `strix/agents/lead_agent/tool_catalog.py:_MINIMAL_TOOLS_BY_TARGET_TYPE` + `_MINIMAL_CORE_TOOLS` as of 2026-05-27 (post iter-37.14):

| Asset type | CORE | Specialist | **Total L2-visible** | Honors L2-CAP? |
|---|---|---|---|---|
| `web_application` | 5 | 8 | **13** | ❌ +3 over cap |
| `api` | 5 | 9 | **14** | ❌ +4 over cap |
| `repository` / `local_code` | 5 | 5 | **10** | ✓ (at the limit) |
| `container_image` | 5 | 2 | **7** | ✓ |
| `ip_address` | 5 | 6 | **11** | ❌ +1 over cap |
| `domain` | 5 | 6 | **11** | ❌ +1 over cap |

**4 of 6 asset types violate the cap.** The two most economically important asset types (`web_application` and `api`) are the worst offenders, at +3 and +4 over.

---

## 2. The deeper problem — wrong tools in L2's catalog

Per CLAUDE.md §1.5, L2 is **the AI security engineer that translates L1 output into action items for non-security audiences (devs, PMs).** That's a *reasoning + prioritization + explanation* job. It is not a detection job — detection belongs to L1 (OSS scanners in the sandbox).

But the current per-asset specialist sets are dominated by **deep-exploit detection tools**:

| Asset | Specialist tools that are deep-exploit detection (= really L1) | Specialist tools that are genuine L2 work |
|---|---|---|
| `web_application` | `scan_sqli_sqlmap`, `scan_xss_dalfox`, `probe_default_creds_hydra`, `scan_fuzz_ffuf`, `scan_smuggling_smuggler` | `scan_idor`, `scan_auth_flow`, `send_request` |
| `api` | `scan_sqli_sqlmap`, `probe_default_creds_hydra`, `scan_fuzz_ffuf`, `scan_api_schemathesis`, `scan_smuggling_smuggler` | `scan_idor`, `scan_auth_flow`, `map_graphql_inql`, `send_request` |
| `repository` / `local_code` | `verify_credentials_trufflehog`, `scan_mobile_mobsfscan` | `build_code_map`, `taint_analysis`, `terminal_execute` |
| `ip_address` | `fingerprint_services_nmap`, `probe_hosts_httpx`, `scan_nuclei_templates`, `tls_audit` | `send_request`, `terminal_execute` |
| `domain` | `enumerate_subdomains_subfinder`, `scan_nuclei_templates`, `scan_dns_hygiene_checkdmarc`, `scan_typosquats_dnstwist` | `domain_recon_pipeline`, `send_request` |

The "deep-exploit detection" column tools are all **thin wrappers around OSS scanners** (sqlmap, dalfox, hydra, ffuf, smuggler, nmap, httpx, nuclei, checkdmarc, dnstwist, schemathesis, mobsfscan). Per the iter-37.x policy + CLAUDE.md §11.1, these belong in `anchor_prepass` where they fire deterministically — not in the LLM's catalog.

**This is the architectural error: by putting deep-exploit detectors in L2's catalog, we:**

1. **Violate the L1/L2 audience split** (CLAUDE.md §1.5). Detection is L1. The lead burns turns deciding *whether* to fire sqlmap on a candidate, when sqlmap should fire as L1 always-on coverage.
2. **Inflate the catalog past the 10-tool cap** and degrade model accuracy on every turn.
3. **Make L1 detection rate dependent on the LLM remembering to call the tool** — which `bench_l2_juiceshop_full` numbers showed is unreliable, and which is the precise problem iter-32.1 / iter-37.2 / iter-37.11 have been chipping at.

### 2.1 What L2 actually needs (the translation toolkit)

Per the §1.5 audience definition, the AI security engineer translating L1 findings to a developer / PM needs to do these jobs:

| L2 job | Currently a tool? | If yes, how? |
|---|---|---|
| **Read L1 output** | ✓ | `list_pending_findings` (CORE) |
| **Reason / scratchpad** | ✓ | `think` (CORE) |
| **Workflow control** | ✓ | `workflow_status` (CORE) |
| **Emit decisions** | ✓ | `create_vulnerability_report` (CORE — upsert via `existing_report_id`) |
| **Terminate** | ✓ | `finish_scan` (CORE) — auto-fires compliance + remediation |
| **Prioritize for THIS customer** | ✗ | Currently implicit (the lead writes severity into `create_vulnerability_report`) — no `prioritize_findings(scoring_context=...)` tool that lets the lead see all findings ranked + then make the customer-specific call |
| **Chain reasoning ("X + Y = account takeover")** | partial | `correlate_at_phase_boundary` fires automatically; no LLM-visible tool to *propose* a chain |
| **Plain-English explanation for the developer** | partial | Embedded inside `create_vulnerability_report.description` — no separate tool, no dedicated quality bench surface |
| **Remediation patch** | ✓ | `generate_remediation_plan` (auto-fires in `finish_scan`) — but mid-scan it's invisible to the lead |
| **Compliance mapping** | ✓ | `emit_compliance_evidence` (auto-fires in `finish_scan`) — same visibility issue |
| **Session-aware authz testing (no OSS substitute)** | ✓ | `scan_idor`, `scan_auth_flow` — genuinely L2-native because they need LLM reasoning about state |
| **Business-logic vulnerability detection (no OSS substitute)** | ✓ | `scan_business_logic` — same reason |
| **HTTP escape hatch** | ✓ | `send_request` — for the cases the prepass didn't cover |

The right-hand column is the L2 catalog under the §1.5 framing. **It contains 0 OSS-wrapper deep-exploit detectors** — those belong in L1.

---

## 3. Proposed reorg — per-asset-type L2 catalog refit

### 3.1 The L2 tool taxonomy (4 buckets, ≤10 total per asset)

```
L2 catalog (≤ 10 tools)
├── CORE (5 — same for every asset type)
│     OBSERVE: workflow_status, list_pending_findings
│     ORIENT:  think
│     ACT:     create_vulnerability_report
│     TERMINATE: finish_scan  (auto-fires compliance + remediation)
│
├── REASONING (1–2 per asset — translation-specific, optional per-asset)
│     propose_chain          ← NEW (currently only auto-fires)
│     prioritize_findings    ← NEW (currently implicit in CV-report severity)
│
├── L2-NATIVE DETECTION (0–3 per asset — only tools requiring LLM state-reasoning)
│     scan_idor              ← session-aware authz (no OSS substitute)
│     scan_auth_flow         ← auth orchestration (no OSS substitute)
│     scan_business_logic    ← app-specific reasoning (no OSS substitute)
│
└── PRIMITIVES (0–2 per asset — escape hatches)
      send_request           ← arbitrary HTTP
      terminal_execute       ← arbitrary shell (repo / IP / container)
```

Everything outside these 4 buckets either fires in `anchor_prepass` (L1 OSS detection) or auto-fires inside `finish_scan` (terminal artifacts).

### 3.2 Per-asset proposed L2 catalog

| Asset | CORE | REASONING | L2-NATIVE DETECTION | PRIMITIVES | **Total** |
|---|---|---|---|---|---|
| `web_application` | 5 | `propose_chain`, `prioritize_findings` | `scan_idor`, `scan_auth_flow`, `scan_business_logic` | `send_request` | **10** ✓ |
| `api` | 5 | `propose_chain`, `prioritize_findings` | `scan_idor`, `scan_auth_flow`, `map_graphql_inql` | `send_request` | **10** ✓ |
| `repository` / `local_code` | 5 | `propose_chain` | `build_code_map`, `taint_analysis`, `scan_business_logic` | `terminal_execute` | **10** ✓ |
| `container_image` | 5 | — | — | `terminal_execute` | **6** ✓ |
| `ip_address` | 5 | `prioritize_findings` | — | `send_request`, `terminal_execute` | **8** ✓ |
| `domain` | 5 | `prioritize_findings` | — | `send_request` | **7** ✓ |

Every asset type now ≤ 10. The remaining headroom (0–4 tools per asset) leaves room for asset-specific additions without breaking the cap.

### 3.3 What moves OUT of L2 (and where)

| Tool | Current home | Moves to | Why |
|---|---|---|---|
| `scan_sqli_sqlmap` | L2 web/api specialist | `anchor_prepass` (web + api) | Deep-exploit detection. Fires when prepass `scan_sqli` flags a candidate. |
| `scan_xss_dalfox` | L2 web specialist | `anchor_prepass` (web) | Same — fires when prepass `scan_xss` flags a candidate. |
| `probe_default_creds_hydra` | L2 web/api specialist | `anchor_prepass` (web + api) | Already in prepass (iter-37.14). Removing the duplicate L2-visible entry. |
| `scan_fuzz_ffuf` | L2 web/api specialist | `anchor_prepass` (web + api) | Already in prepass (iter-37.14). Removing duplicate. |
| `scan_smuggling_smuggler` | L2 web/api specialist | `anchor_prepass` (web + api) | Deep-exploit; should fire as L1 always-on for high-throughput targets. |
| `scan_api_schemathesis` | L2 api specialist | `anchor_prepass` (api) | Already in prepass (iter-37.14). Removing duplicate. |
| `verify_credentials_trufflehog` | L2 repo specialist | `anchor_prepass` (repo) | Already wired alongside SAST/secrets in prepass. Removing duplicate. |
| `scan_mobile_mobsfscan` | L2 repo specialist | `anchor_prepass` (repo) | Same — already prepass-wired in iter-37.14. |
| `fingerprint_services_nmap` | L2 ip specialist | `anchor_prepass` (ip) | nmap is recon; belongs in prepass alongside the existing socket sweep. |
| `probe_hosts_httpx` | L2 ip specialist | `anchor_prepass` (ip) | httpx is recon. |
| `scan_nuclei_templates` | L2 ip + domain specialist | `anchor_prepass` (ip + domain) | nuclei is L0 signature corpus — *the* canonical L1 detection, must fire deterministically. |
| `tls_audit` | L2 ip specialist | `anchor_prepass` (ip) | TLS audit is a single-host probe — should always fire on every IP asset. |
| `enumerate_subdomains_subfinder` | L2 domain specialist | `anchor_prepass` (domain) | Recon. |
| `scan_dns_hygiene_checkdmarc` | L2 domain specialist | `anchor_prepass` (domain) | Single-domain audit — should always fire. |
| `scan_typosquats_dnstwist` | L2 domain specialist | `anchor_prepass` (domain) | Same — always-on for domain assets. |
| `domain_recon_pipeline` | L2 domain specialist | `anchor_prepass` (domain) | Currently the only L2-visible "discovery" tool for domain; moves to deterministic prepass. |

After this reshuffle, **`anchor_prepass.py` becomes the comprehensive L1 detection layer for every asset type**, and the L2 catalog is fully focused on translation + L2-native reasoning.

### 3.4 What moves INTO L2 (the translation toolkit)

Two new LLM-visible tools that don't currently exist:

#### `propose_chain` (new — REASONING bucket)

```python
@register_tool(sandbox_execution=False)  # host-side, reads tracer
def propose_chain(
    *,
    finding_ids: list[str],
    narrative: str,
    impact: str,
    chain_severity: str,  # "critical" / "high" / "medium" / "low"
) -> dict:
    """Propose that two-or-more findings form an exploit chain.

    Use when you spot a multi-step exploit path (e.g. CSRF + open
    redirect = account takeover, or SQLi + file-write = RCE). The
    chain is upserted into run_summary.chains_emitted and feeds
    bench_chains.

    The lead provides:
      - finding_ids: the existing CV-report IDs that compose the chain
      - narrative: 1-2 paragraph plain-English exploit story
        (this is what the developer/PM reads, not the security team)
      - impact: business-impact statement
      - chain_severity: how to rank the chain itself
    """
```

Currently chains are only auto-detected via heuristic post-emit (iter-33.3). Making chain proposal an explicit tool lets the lead emit chains with richer narrative — which is the exact L2-audience deliverable.

#### `prioritize_findings` (new — REASONING bucket)

```python
@register_tool(sandbox_execution=False)
def prioritize_findings(
    *,
    customer_context: dict[str, Any],
) -> dict:
    """Re-rank pending findings for THIS customer's context.

    customer_context can include:
      - industry: 'fintech' / 'healthcare' / 'saas' / ...
      - compliance_targets: ['SOC2', 'PCI-DSS', 'HIPAA', ...]
      - critical_assets: list of endpoint patterns
      - tech_stack_focus: 'authentication' / 'data-exfil' / ...

    Returns the same list of findings re-ordered with a per-finding
    `customer_priority` integer (1 = highest). Does NOT mutate the
    findings themselves — only emits a ranking the lead can cite in
    its narrative.
    """
```

This makes the "prioritize for this customer" job explicit. Currently the lead bakes priority into `severity` and `surface_priority`, which conflates "intrinsic severity" with "this-customer's-priority." The L2 audience (developers + PMs) wants the customer-specific ranking, not the generic CVSS-style severity.

---

## 4. Risks + mitigations

| Risk | Mitigation |
|---|---|
| **Moving deep-exploit tools to prepass = more deterministic L1 runtime cost** — every scan fires sqlmap / dalfox / hydra even when no candidates exist. | Prepass dispatcher already conditions on iter-30 candidate signals (e.g. only fires sqlmap when `scan_sqli` flagged a candidate). The unconditional sweep is bounded; cost is acceptable per iter-37.12 baseline. |
| **L2 loses ability to fire sqlmap/dalfox on demand** — what if the lead wants to deep-exploit a candidate prepass missed? | Add `send_request` as the escape hatch (already in L2 catalog). For the rare "I need sqlmap on a specific endpoint" case, the lead can request it via dispatch_specialist (orchestrator mode) or as a per-PR future addition. |
| **`propose_chain` / `prioritize_findings` become "the LLM does the security engineer's job poorly"** — quality risk. | Both are scored by existing benches: `propose_chain` feeds `bench_chains` (iter-31.2); `prioritize_findings` feeds `bench_severity` (iter-31.3). Quality gate is the same as every other L2 PR. |
| **The L2-CAP invariant gets quietly violated again next iter** | Add a CI test that fails when `get_lead_tool_catalog(target_types=[t])` returns > 10 names for any registered target type. Pinned in `tests/agents/lead_agent/test_l2_cap_invariant.py`. |
| **Existing iter-37.14 added 3 OSS wrappers to MINIMAL — undoing them is a regression of that intent.** | Not undoing the iter-37.14 OSS-wrapper *additions* (the wrappers still ship, just from prepass). The intent of iter-37.14 was "broader/deeper OSS coverage." This proposal preserves that — coverage is now ALWAYS-ON via prepass instead of ON-IF-LLM-REMEMBERS via catalog. |

---

## 5. Iter sequence

| iter | scope | size |
|---|---|---|
| **Q5.1** | CLAUDE.md §1.5.5 — add L2-CAP invariant. Add taxonomy section (4 buckets). Add the per-asset target table. | 1 PR, docs only |
| **Q5.2** | `tests/agents/lead_agent/test_l2_cap_invariant.py` — CI test that fails when any asset's L2 catalog > 10. Run against current (failing) state to confirm the test catches the violation. | 1 PR, ~80 LOC + tests |
| **Q5.3** | Wire `scan_sqli_sqlmap`, `scan_xss_dalfox`, `scan_smuggling_smuggler` into `anchor_prepass._ANCHORS_WEB` / `_ANCHORS_API`. Drop from `_MINIMAL_TOOLS_BY_TARGET_TYPE`. Re-run iter-37.12 baseline. | 1 PR, ~150 LOC |
| **Q5.4** | Wire `fingerprint_services_nmap`, `probe_hosts_httpx`, `tls_audit`, `scan_nuclei_templates` into `_ANCHORS_IP`. Drop from `ip_address` L2 catalog. | 1 PR, ~100 LOC + IP-fixture bench |
| **Q5.5** | Wire `enumerate_subdomains_subfinder`, `scan_dns_hygiene_checkdmarc`, `scan_typosquats_dnstwist`, `scan_nuclei_templates`, `domain_recon_pipeline` into `_ANCHORS_DOMAIN`. Drop from L2 catalog. | 1 PR, ~120 LOC |
| **Q5.6** | New L2 tool: `propose_chain` (REASONING bucket). Wire into `_MINIMAL_TOOLS_BY_TARGET_TYPE` for web/api/repo. Surface in `bench_chains` so the bench can attribute chain emissions to "auto-heuristic" vs "lead-proposed". | 1 PR, ~200 LOC + 20 tests |
| **Q5.7** | New L2 tool: `prioritize_findings` (REASONING bucket). Wire into web/api/ip/domain. | 1 PR, ~250 LOC + 25 tests |
| **Q5.8** | Update `docs/tool-catalog-rationalization.md` + CLAUDE.md §12 to reflect new per-asset counts. | 1 PR, docs only |
| **Q5.9** | Re-run L1 parity benches (Q3.2-Q3.7) to confirm the prepass migration didn't drop detection. | bench-run PR |

**Q5.2 ships before Q5.3-Q5.5** so the CI test is in place and the cap-violations are gated, not silently allowed.

---

## 6. Acceptance criteria

1. `tests/agents/lead_agent/test_l2_cap_invariant.py` passes for every registered asset type.
2. `bench_owasp_benchmark.py` Youden index does NOT regress vs. the pre-Q5 baseline (the deep-exploit tool moves shouldn't change L1 detection — they just change WHERE the tool fires).
3. `bench_l2_juiceshop_full.py` `completion_rate` does NOT regress vs. the iter-37.14 baseline.
4. `bench_chains.py` `chain_detection_rate` IMPROVES once `propose_chain` ships (Q5.6).
5. `bench_severity.py` `severity_tier_accuracy` shows the lead now writes customer-priority into a separate field than intrinsic severity (Q5.7).

The first three are the **non-regression gates** (the L1-audience artifact must stay constant); the last two are the **value-capture gates** (the L2-audience artifact should improve).

---

## 7. Connection to other Q-tracks

* **Q1** (`bench_owasp_benchmark.py` et al.) is the non-regression gate.
* **Q2** (stratified compaction): Q5 reduces the tool count visible to the LLM, which directly reduces the tool-catalog section of the system prompt. Both pull in the same direction — fewer tokens, more focused decisions. Q2.3 (progressive tool disclosure) can be deprioritized after Q5 ships: when the catalog is already ≤10 there's no progressive-disclosure-driven savings to capture.
* **Q3** (L1 parity): Q5 *increases* the surface area Q3 must measure, because the deep-exploit tools moving to prepass means they fire by default and contribute to L1 recall. Q3's parity bench for sqlmap / dalfox / hydra / ffuf becomes load-bearing for Q5's non-regression gate.
* **Q4** (lead-loop parallelism): Q5 trims the lead's surface to 5–10 tools per turn, which makes parallel dispatch decisions simpler. Q4 should land after Q5.

---

## 8. Open questions for review

1. **`scan_business_logic` is currently L2-native** but a recent iter-37 review may demote it. Is it staying in the L2 catalog? (This proposal assumes yes.)
2. **`prioritize_findings` overlaps with the existing `surface_priority` L1.5 hook.** The hook computes a generic priority; the tool computes a customer-specific one. Are we ok with both surfacing, or should we collapse?
3. **`propose_chain` is currently a finding-shape, not a separate concept** — chains live as `chain_summary` blocks inside vulnerability_reports. Should this proposal add a separate `chains` array in `run_summary` (cleaner) or keep the embedded shape (smaller change)?
4. **The orchestrator mode (`STRIX_ORCHESTRATOR_MODE`) already hides probing specialists from the lead and dispatches them in fresh-context sub-agents.** Should orchestrator mode become the default instead of building a parallel "trimmed minimal" path? The decision affects whether Q5 is a catalog refactor or a default-mode flip.

---

## 9. Success criterion

> By the end of Q5.9, every L2 asset-type catalog is ≤ 10 tools, every deep-exploit OSS wrapper fires deterministically in `anchor_prepass` (not on LLM choice), the L2 catalog contains only translation + L2-native-detection + primitive tools, and a CI invariant blocks any future PR that pushes any asset's catalog over the cap.

The L1 audience (security team) keeps its full L1 detection coverage via the prepass migration. The L2 audience (developers, PMs) gets a focused AI-security-engineer that has the right tools (chain proposal, customer prioritization) and doesn't burn turns deciding whether to run sqlmap.

This is the architectural commitment of CLAUDE.md §1.5 made concrete in the catalog.
