# L2 from first principles — what tools actually belong in the catalog

**Status:** proposal — supersedes Q5's reasoning-tool additions where they conflict
**Owner:** ClatTribe/strix
**Created:** 2026-05-27
**Companion to:** `docs/proposals/2026-05-27-l2-tool-cap-and-translation-toolkit.md`, `docs/proposals/2026-05-27-l2-tool-audit.md`

---

## 1. The principle

> **A tool exists when the LLM either CAN'T do the thing or SHOULDN'T do the thing without a system-of-record.**

Specifically, tools belong in the catalog when at least one of these is true:

| Condition | Why a tool is needed |
|---|---|
| **Real-time external data** | LLM training cutoff is stale. Threat feeds, current CVE/EPSS/KEV state, vendor advisories, current compliance control text — all change after training. |
| **Re-trigger a deterministic scan** | The LLM can't run subprocess / network I/O. Re-firing `nuclei` against a new endpoint with new auth, or `scan_idor` with newly captured sessions, requires the tool. |
| **Persistent side-effect** | Committing a finding to `vulnerability_reports`, advancing workflow phase, or terminating the scan are state changes the system-of-record must own. |
| **Reading state the LLM doesn't have** | `workflow_status`, `list_pending_findings` — facts that live outside the conversation context. |

Tools do **NOT** belong in the catalog when:

| Anti-condition | Why it's not a tool |
|---|---|
| **Reasoning over data the LLM already has** | Prioritization, chain narrative assembly, plain-English explanation, remediation prose, severity decision — all pure reasoning. The LLM emits these as part of its response. |
| **Reformatting / templating** | Rendering a finding into markdown, formatting CVSS XML — the LLM is a renderer; no tool needed. |
| **Decisions encoded inline** | "I think this is high severity" is part of the LLM's argument; no tool call needed unless it COMMITS to the system-of-record. |

The framework is **REASON freely; CALL TOOLS for things outside reach.** Q5 had `propose_chain` and `prioritize_findings` as new "tools," but those are reasoning. They become tools ONLY when they commit a structured artifact — and even then the commit can be a parameter on the existing emission tool.

---

## 2. The bucket model — derived from first principles

Walking the principle gives four buckets:

```
L2 catalog (≤ 10 tools per asset)
├── READ STATE        — facts not in conversation context
├── FETCH EXTERNAL    — real-time data the LLM's training cutoff missed
├── RE-DISPATCH       — re-run a deterministic L1 scan with new context
├── COMMIT DECISIONS  — write to the system-of-record (findings, chains, finish)
```

What's missing from the current catalog: **the FETCH EXTERNAL bucket is empty.** Strix has 7 registered real-time tools (`cve_intel_search`, `nvd_lookup`, `kev_diff_check`, `scan_iocs_for_target_threatfox`, `cve_lookup`, `threat_feed_ingest`, `legal_compliance_probe`) and **zero of them are in the post-Q5 minimal L2 catalog**. That's the load-bearing gap.

Without FETCH EXTERNAL, the L2 lead is stuck with whatever the LLM training data remembers about CVEs / threats / compliance — which is months-stale at best. The L2 audience (devs, PMs) reading "CVE-2024-XXXX, severity high" gets no current exploit availability, no KEV status, no current vendor advisory, no compliance mapping that reflects this year's framework version. That's not an AI security engineer; that's a Wikipedia-quote bot.

---

## 3. Per-tool re-evaluation under this lens

Walking the current post-Q5 catalog through the principle:

| Tool | Bucket | Verdict under first principles |
|---|---|---|
| `workflow_status` | READ STATE | ✓ Keep — fact outside context |
| `list_pending_findings` | READ STATE | ✓ Keep — findings ledger outside context |
| `think` | (none — it's not a tool) | ✗ Drop — pure reasoning. The LLM can think in response text. If we want a reasoning audit log, capture the assistant_text turns, don't fake it via a tool. |
| `create_vulnerability_report` | COMMIT | ✓ Keep — persistent side-effect to tracer |
| `finish_scan` | COMMIT | ✓ Keep — terminal commit + auto-fire artifacts |
| `propose_chain` (Q5 new) | (was REASONING — wrong) | ✗ Drop the tool; **add `chain_summary` field to `create_vulnerability_report`** so chain commit is a parameter on the existing emission tool. Saves a slot. |
| `prioritize_findings` (Q5 new) | (was REASONING — wrong) | ✗ Drop the tool; **add `customer_priority: int` field to `create_vulnerability_report`**. The LLM reasons about priority in its turn; the field is the commit. |
| `scan_idor` | RE-DISPATCH | ✓ Keep — runs subprocess probes the LLM can't run inline |
| `scan_auth_flow` | RE-DISPATCH | ✓ Keep — runs HTTP probes + captures session state |
| `scan_business_logic` | RE-DISPATCH | ✓ Keep — runs mutation probes |
| `build_code_map` | READ STATE (file system) | ✓ Keep — file I/O the LLM can't do |
| `taint_analysis` | RE-DISPATCH (in-house SAST) | ✗ Deprecate per Q3 parity bench → replace with semgrep in prepass |
| `map_graphql_inql` | RE-DISPATCH (OSS wrapper) | → Move to prepass per L2 audit |
| `send_request` | RE-DISPATCH (single HTTP) | ✓ Keep — escape hatch for custom HTTP |
| `terminal_execute` | RE-DISPATCH (shell exec) | ✓ Keep — escape hatch for repo / IP / container |

**Tools that disappear under this lens: `think`, `propose_chain`, `prioritize_findings`.**

The reasoning-bucket from Q5 collapses entirely. The work those tools were supposed to do becomes:
- Chain narrative → `create_vulnerability_report.chain_summary` (parameter)
- Customer priority → `create_vulnerability_report.customer_priority` (parameter)
- Reasoning audit trail → captured automatically from `assistant_text` turns (no tool needed)

**Tools that need to be ADDED: FETCH EXTERNAL bucket.** Currently empty. See §4.

---

## 4. What's missing — the FETCH EXTERNAL bucket

The seven registered real-time-data tools, evaluated for L2-catalog fit:

| Existing tool | What it fetches | L2 catalog fit | Action |
|---|---|---|---|
| `cve_lookup` | NVD CVE detail by ID | ⚠️ overlaps `nvd_lookup` | Pick one |
| `nvd_lookup` | NVD CVE/CPE search | ⚠️ overlaps `cve_lookup` | Pick one |
| `cve_intel_search` | CVE intel aggregator (multi-source) | ✓ broader signal | **Keep, prefer over the two NVD wrappers** |
| `kev_diff_check` | CISA KEV catalog membership + EPSS | ✓ specific real-time question | **Promote to L2 minimal** |
| `threat_feed_ingest` | MISP / STIX / TAXII feeds | ⚠️ requires customer's feed URL + token | Keep as op-in (not minimal) |
| `scan_iocs_for_target_threatfox` | ThreatFox IoC match | ⚠️ noisy, requires target IoC list | Keep as op-in |
| `legal_compliance_probe` | Privacy / cookie / consent legal probes | partial-fit | Keep specific to compliance asset class |

The two load-bearing additions for the L2 minimal catalog:

### 4.1 `query_threat_intel(target_or_finding)` — collapsed/renamed

Collapse `cve_lookup` + `nvd_lookup` + `cve_intel_search` + `kev_diff_check` behind one parameterized tool:

```python
@register_tool(sandbox_execution=True)
def query_threat_intel(
    *,
    cve_id: str | None = None,
    cwe_id: str | None = None,
    product: str | None = None,
    version: str | None = None,
    include_kev: bool = True,
    include_epss: bool = True,
    include_advisories: bool = True,
) -> dict:
    """Fetch real-time intelligence for a CVE / CWE / product+version.

    Returns a unified dict:
      {
        cve: {id, description, cvss_v3, published, last_modified, ...},
        kev: {is_listed, date_added, due_date, ransomware_use, ...} | null,
        epss: {score, percentile, date} | null,
        advisories: [{vendor, url, fixed_versions}, ...],
        related_cwes: [...],
        exploit_availability: {public_poc, weaponized, in_metasploit, ...},
      }

    Used when the lead needs to translate "CVE-2024-XXXX detected" into
    "is this actively exploited TODAY, is a patch available, do we have
    PoC code in the wild?"

    Caches per-CVE for 24h to avoid re-hitting NVD on every call.
    """
```

Single tool, multi-source under the hood. The lead asks one question ("tell me about CVE-X") and gets the unified answer. Saves 3 catalog slots vs. exposing the 4 wrappers individually.

### 4.2 `lookup_compliance_mapping(finding_shape, frameworks)`

```python
@register_tool(sandbox_execution=True)
def lookup_compliance_mapping(
    *,
    finding_shape: dict,    # e.g. {"cwe": "CWE-89", "severity": "high"}
    frameworks: list[str],  # ["SOC2", "PCI-DSS", "HIPAA"]
) -> dict:
    """Map a finding to current compliance control IDs.

    Returns:
      {
        "SOC2":     [{"control_id": "CC6.6", "description": "..."}, ...],
        "PCI-DSS":  [{"control_id": "6.5.1", "description": "..."}, ...],
        "HIPAA":    [{"control_id": "164.308(a)(1)(ii)(B)", ...}, ...],
      }

    Backed by a versioned mapping file fetched from a corpus (similar
    to L0's nuclei templates) on a cron — `STRIX_COMPLIANCE_CORPUS_DIR`.
    Stays current as frameworks revise (SOC2 2025 vs 2022, etc.).
    """
```

Today the lead writes compliance mapping into `create_vulnerability_report.description` from memory — which is whatever the LLM training data remembers. Wrong year, wrong version. This tool gives it the current mapping, deterministically.

---

## 5. The from-scratch L2 catalog (proposed)

Universal across asset types (with 1-2 asset-specific slots):

| # | Tool | Bucket | Per-asset visibility |
|---|---|---|---|
| 1 | `workflow_status` | READ STATE | every asset |
| 2 | `list_pending_findings` | READ STATE | every asset |
| 3 | `get_finding(id)` | READ STATE | every asset |
| 4 | `query_threat_intel` | FETCH EXTERNAL | every asset |
| 5 | `lookup_compliance_mapping` | FETCH EXTERNAL | every asset |
| 6 | `rescan(tool_name, target, captured_state)` | RE-DISPATCH | every asset |
| 7 | *(asset-native probe — see §5.1)* | RE-DISPATCH | per asset |
| 8 | *(asset-native primitive — see §5.1)* | RE-DISPATCH | per asset |
| 9 | `create_vulnerability_report` | COMMIT | every asset |
| 10 | `finish_scan` | COMMIT | every asset |

10 tools per asset. Universal shape: **6 universal + 2 asset-specific + 2 commit.**

### 5.1 Per-asset slots (#7 + #8)

| Asset | Slot #7 (probe) | Slot #8 (primitive) |
|---|---|---|
| `web_application` | `scan_idor`, `scan_auth_flow`, `scan_business_logic` (collapsed under `dispatch_l2_probe(kind=...)`) | `send_request` |
| `api` | same — collapsed | `send_request` |
| `repository` / `local_code` | `build_code_map` | `terminal_execute` |
| `container_image` | — | `terminal_execute` |
| `ip_address` | — | `send_request` + `terminal_execute` (8 → 8) |
| `domain` | — | `send_request` |

The 3 L2-native probes (`scan_idor` / `scan_auth_flow` / `scan_business_logic`) collapse under a single `dispatch_l2_probe(kind, **kwargs)` umbrella with kind ∈ {`idor`, `auth_flow`, `business_logic`}. That's 3 → 1 slot. Same shape as `rescan` (#6) but for L2-native probes.

Side benefit: `rescan` is the L1 re-dispatch (sqlmap / dalfox / hydra / etc. — re-fired with new state), `dispatch_l2_probe` is the L2-native re-dispatch (idor / auth / business-logic). Cleanly distinguishes "re-run an OSS tool" from "run a session-aware probe only the LLM can set up."

---

## 6. Comparison — current vs. proposed

### 6.1 Current post-Q5 (per the Q5 proposal table)

| Asset | Total | What the catalog focuses on |
|---|---|---|
| `web_application` | 10 | CORE + reasoning (think, propose_chain, prioritize) + 3 detections + primitive |
| `api` | 10 | same shape |
| `repository` | 10 | CORE + reasoning + 3 detections + primitive |
| `container_image` | 6 | CORE + primitive |
| `ip_address` | 8 | CORE + reasoning + 2 primitives |
| `domain` | 7 | CORE + reasoning + 1 primitive |

Real-time-data bucket: **empty.** Reasoning bucket: 2 tools the LLM doesn't actually need (per first principles).

### 6.2 Proposed (this doc)

| Asset | Total | What the catalog focuses on |
|---|---|---|
| `web_application` | 10 | CORE + FETCH EXTERNAL + rescan + dispatch_l2_probe + send_request + commits |
| `api` | 10 | same |
| `repository` | 10 | CORE + FETCH EXTERNAL + rescan + build_code_map + terminal_execute + commits |
| `container_image` | 9 | CORE + FETCH EXTERNAL + rescan + terminal_execute + commits |
| `ip_address` | 10 | CORE + FETCH EXTERNAL + rescan + send_request + terminal_execute + commits |
| `domain` | 9 | CORE + FETCH EXTERNAL + rescan + send_request + commits |

Real-time-data bucket: **2 tools, always available.** Reasoning bucket: **empty (the LLM reasons in its response, not via tools).**

### 6.3 Side-by-side

| Bucket | Current post-Q5 | Proposed first-principles |
|---|---|---|
| READ STATE | 2 (workflow_status, list_pending_findings) | 3 (+ get_finding) |
| FETCH EXTERNAL | **0** | **2 (query_threat_intel, lookup_compliance_mapping)** |
| RE-DISPATCH (L1) | 0 explicit | **1 (rescan)** |
| RE-DISPATCH (L2-native) | 3 separate tools | 1 (dispatch_l2_probe — collapses 3) |
| REASONING | 3 (think + propose_chain + prioritize_findings) | **0 (dropped — reasoning is in response text)** |
| COMMIT | 2 (create_vulnerability_report, finish_scan) | 2 (same, with added chain_summary + customer_priority fields) |
| PRIMITIVES | 1 (send_request OR terminal_execute) | 1 (same) |
| **Total per asset** | 9–10 | 9–10 |

Same headcount. Strictly better composition. The 3 reasoning slots (think, propose_chain, prioritize_findings) reallocate to 2 FETCH EXTERNAL slots + 1 RE-DISPATCH slot — which are things the LLM actually can't do alone.

---

## 7. Why this is meaningfully different

### 7.1 The Q5 catalog optimized for what's already shaped like a tool

Q5 looked at the existing catalog, asked which tools fit L2, and added two reasoning tools (`propose_chain` + `prioritize_findings`) to fill obvious gaps. That's iterative refactoring. It misses the deeper question: **why are we exposing reasoning as a tool at all?**

### 7.2 The first-principles catalog asks what the LLM is bad at

LLMs are bad at:
- Knowing about events after their training cutoff (need FETCH EXTERNAL)
- Running subprocess / network calls (need RE-DISPATCH)
- Holding facts outside the conversation window (need READ STATE)
- Atomic commitment to a system of record (need COMMIT)

LLMs are good at:
- Reasoning over data they can see (don't need REASONING tools)
- Generating narrative prose (don't need RENDER tools)
- Picking priorities given context (don't need PRIORITIZATION tools)

When we make reasoning a tool, two things go wrong:
1. **The LLM thinks tool-calling is required** for what should be inline reasoning. It wastes turns calling `think` / `propose_chain` / `prioritize_findings` when it could have just produced the output.
2. **The tool's output goes nowhere useful** — `think` persists nothing; `propose_chain` and `prioritize_findings` would persist to `run_summary` but their outputs are identical to what could be parameters on `create_vulnerability_report`.

### 7.3 The L2 audience benefit

Under the proposed catalog, every `create_vulnerability_report` carries:
- `cve_id` → looked up via `query_threat_intel` → current KEV/EPSS state in the description
- `cwe_id` → mapped via `lookup_compliance_mapping` → current SOC2/PCI/HIPAA controls
- `chain_summary` → parameter on the commit, not a separate tool call
- `customer_priority` → parameter on the commit, not a separate tool call

The dev/PM reading the report sees a finding whose metadata is **current as of scan-time** — not whatever the LLM training data remembered about CVE-2024-X six months ago. That's a meaningful improvement in the L2-audience artifact's quality, and it's what the user's framing demands.

---

## 8. Iter sequence (replaces Q5.6 + Q5.7)

| iter | scope | size |
|---|---|---|
| **Q6.1** | Drop `think` from the L2 catalog. Persist `assistant_text` turns to `run_summary.lead_reasoning_trace[]` so the audit log survives. (Or, equivalently, keep `think` as a thin wrapper that just persists.) | ~30 LOC + 5 tests |
| **Q6.2** | Add `query_threat_intel` — collapse `cve_lookup` + `nvd_lookup` + `cve_intel_search` + `kev_diff_check` behind one signature. Cache for 24h. | ~400 LOC + 20 tests |
| **Q6.3** | Add `lookup_compliance_mapping` — backed by a versioned mapping corpus (`STRIX_COMPLIANCE_CORPUS_DIR`) refreshed on cron. | ~250 LOC + 15 tests |
| **Q6.4** | Add `rescan(tool_name, target, captured_state)` — re-dispatch primitive for L1 tools the lead identifies should re-fire with new state. Validates `tool_name` against an allow-list (the same OSS-wrappers that fired in prepass). | ~200 LOC + 15 tests |
| **Q6.5** | Add `dispatch_l2_probe(kind, **kwargs)` — collapse `scan_idor` / `scan_auth_flow` / `scan_business_logic` under one umbrella. | ~150 LOC (refactor) + 15 tests |
| **Q6.6** | Add `get_finding(id)` — single-finding deep read companion to `list_pending_findings`. | ~50 LOC + 5 tests |
| **Q6.7** | Replace Q5's `propose_chain` + `prioritize_findings` plan: extend `create_vulnerability_report` with `chain_summary` + `customer_priority` parameters. Drop the standalone tools from the catalog plan. | ~100 LOC + 10 tests |
| **Q6.8** | Update CLAUDE.md §1.5.6 (bucket model) + §1.5.7 (per-asset table) to reflect first-principles catalog. | docs only |

Total: ~1180 LOC + ~85 tests + 1 docs PR. Approximately the same size as Q5.6 + Q5.7 alone — but covers all the gaps, not just two.

---

## 9. Risks + mitigations

| Risk | Mitigation |
|---|---|
| `query_threat_intel` rate-limits hit on NVD / EPSS APIs in CI bench runs | 24h cache + fixture mode for benches (load from local snapshot). Q3 parity bench already uses this pattern. |
| `lookup_compliance_mapping` corpus drift — frameworks update yearly | Cron pager (like Vulhub corpus iter-Q1.3) flags when corpus is >90d stale |
| `rescan` lets the LLM amplify a destructive scan (e.g. re-fire sqlmap with `--level=5 --risk=3`) | Validate `tool_name` against an allow-list; cap rescans per scan at 5 (similar to iter-29.9 destructive guards) |
| Dropping `think` confuses model trained to expect a scratchpad | Replace with system-prompt directive ("reason in your response text; tools are for external action"). Bench impact measured via `bench_explanation` |
| Collapsing 3 L2-native probes into `dispatch_l2_probe(kind=...)` loses per-probe docstrings | The umbrella tool's docstring enumerates each `kind` with its own kwargs list — same information surface, one slot |

---

## 10. Connection to existing Q-tracks

* **Q5** (≤10 cap + 4-bucket taxonomy): superseded for the REASONING bucket (now empty). CORE, L2-NATIVE DETECTION, PRIMITIVES buckets unchanged. The new FETCH EXTERNAL bucket is the addition.
* **Q3** (L1 parity): unchanged. `query_threat_intel` / `lookup_compliance_mapping` are FETCH-only tools; they don't affect L1 detection recall.
* **Q2** (token reduction): improves further. Dropping the reasoning tools reduces tool-catalog tokens; the LLM no longer wastes turns calling `think`.
* **Q4** (parallelism): improves. The collapsed `dispatch_l2_probe` is naturally parallel-dispatch-friendly (the orchestrator can fire all three `kind` values concurrently when warranted).

---

## 11. Success criterion

> By the end of Q6.8, the L2 catalog is composed entirely of READ STATE + FETCH EXTERNAL + RE-DISPATCH + COMMIT tools. No tool in the catalog exists for "the LLM to do reasoning it could do in response text." Every CV-report emitted carries threat-intel and compliance fields populated by scan-time fetches, not by training-data recall. The ≤10 cap is preserved.

This is the catalog you'd build if you started today, knowing what L1 and L1.5 already give the lead, and treating tools as the LLM's hands rather than its brain.
