# Proposal: quick-mode OSS-first architecture (skip the LLM-driven tool selection)

**Date:** 2026-05-20
**Status:** Draft — ready to implement
**Driver:** Live measurement showed quick mode's LLM-driven tool selection fails to invoke the OSS anchor scans even when explicitly told to. Vanilla OSS would find everything; strix-quick finds nothing.

## The data

After PRs #359 (anchor-scan prompts) + #360 (retry classifier) + #361 (credential-gated failover) + #362 (RPM throttle) all merged, the per-asset-type quick-mode bench produced (Gemini 2.5 Flash, `STRIX_LLM_RPM=8`):

| Fixture | OSS floor (semgrep+trivy+grype+osv+checkov) | Strix-quick `found` | Strix-quick `recall` | Wall time |
|---|---:|---:|---:|---:|
| flask-vuln | **15** | **0** | 0.000 | **98.9 min** |
| vampi | n/a (API target) | 1 (FP — not in must_find) | 0.000 | 6.8 min |
| ip-vulnerable | n/a (IP target) | (in progress) | — | — |
| vibe-app | (deferred) | 0 | — | docker compose failed |
| juiceshop | n/a (HTML target) | 0 | 0.000 | 6h 15min (pre-throttle) |

The smoking gun is flask-vuln's run_summary:
- `duration_seconds: 5931` (98.9 min)
- `findings_summary.total: 0`
- `checks.total: 0`
- `summary_text: "Scanned ... in 98.9m; with no findings."`
- `simulation_run.json.deterministic_tool_calls: 22` (some tools fired)
- `simulation_run.json.ai_reasoning_calls: 0` (no reasoning succeeded)

**Strix made 22 deterministic tool calls in 99 minutes and not one of them was `scan_sast`, `scan_sca_lockfiles`, or `scan_iac`.** The 22 calls were recon primitives (file enumeration, fingerprinting). The LLM-driven decision of "which tool to call next" never picked the anchor scans — despite quick.md (#359) explicitly saying "Phase 0: ALWAYS run these tools first."

Meanwhile, running `semgrep --config p/python ./fixtures/code/flask-vuln/src` directly finds 15 vulns in ~3 seconds at $0 cost.

## Root cause

Quick mode's `iter_cap=12` budgets:
- 1-2 iterations of boot
- 1-2 iterations of recon
- 3-4 iterations of probe
- 2-3 iterations of emission
- 1 iteration for report

Each iteration = 1 LLM call. Each LLM call sends the ~56K-token system prompt (full tool catalog + all skill bodies). For the lead to actually invoke `scan_sast`, it has to:
1. Choose `scan_sast` from ~200+ tool schemas in its catalog
2. Construct the right arguments
3. Emit the tool_call in its response
4. See the results in the next iteration
5. Decide what to do next

Even on a perfect provider, that's 1 LLM call to invoke 1 scanner that takes 3 seconds to run. With 4-5 anchor scans per target type, that's 4-5 LLM calls minimum, each at ~56K input tokens.

**The LLM as a gatekeeper for deterministic tool selection is the wrong architecture for quick mode.** It's appropriate for standard/deep mode where the LLM's judgement adds value (which surface to probe next, when to chain findings, how to craft an exploit PoC). For quick mode's signature-driven detection, the tool sequence is known and deterministic — there's no judgement to apply.

## Proposed architecture

Add a **pre-lead OSS-anchor pass** that runs deterministically before the lead's first LLM call, populates the agent state with findings, and reduces the lead's role to ranking/dedup/format.

### Flow change

**Before (current):**
```
Lead init → Lead LLM call 1 → decide → emit tool_call(scan_sast) → run → Lead LLM call 2 → ...
                ~56K tokens                                                  ~56K tokens
```

**After (proposed):**
```
Lead init → run deterministic anchor pass → inject findings into state → Lead LLM call 1: rank + emit
                no LLM, ~3 seconds per scanner                                ~56K tokens, 1 iteration
```

### The anchor pass

A new module `strix/agents/lead_agent/anchor_prepass.py` exposes:

```python
async def run_oss_anchor_prepass(
    *,
    target_type: str,
    target: str,
    agent_state: AgentState,
    scan_mode: str,
) -> dict[str, Any]:
    """Run the deterministic OSS anchor scans for the target type.
    Populates agent_state.tool_results with the findings. Returns
    a stats dict for telemetry.

    Only fires when scan_mode == "quick" AND target_type is in the
    supported set (local_code / repository / api / web_application /
    web+code / container_image). For domain / ip_address, returns
    immediately — no signature corpus applies."""
```

Per-target-type anchor sequence (from PR #359's quick.md Phase 0):

| target_type | Anchor sequence |
|---|---|
| `local_code` / `repository` | `scan_sca_lockfiles` → `scan_sast` → `scan_iac` → `secrets_scan` |
| `api` | `fingerprint_tech_stack` → `scan_nuclei_templates(tags=[cve])` → `scan_api_bola` → `scan_api_bfla` → `scan_api_mass_assignment` → `scan_api_rate_limit` → `jwt_audit` → `scan_sqli` → `scan_xxe` → `scan_ssrf` → `scan_secrets_in_response` |
| `web_application` | API anchor sequence + `scan_xss` + `cors_deep_check` |
| `web+code` | repository anchor + web anchor in parallel |
| `container_image` | `scan_container_image` → `sbom_extract` |
| `domain` | recon set (`subdomain_enum_tool` + `dns_hygiene_check` + `mail_recon`) — no L1 signature corpus |
| `ip_address` | nmap-based discovery only |

Each tool runs via the existing executor with `sandbox_execution=False` (host shell-out — same path the lead currently uses). Failures are silenced into status=partial — the lead loop can still operate on whatever subset succeeded.

### Lead loop role-change

After the anchor pass, the lead's job is reduced to:
1. Look at the N findings already in `agent_state.tool_results`
2. Apply EPSS / KEV / `contextual_priority` ranking
3. Dedupe across engines (semgrep + nuclei + trivy on same SQLi → 1 finding)
4. Demote FPs (test fixtures, docstrings, unreferenced utilities)
5. Emit final report

This is **3-4 LLM calls maximum**, not 12.

Quick-mode `iter_cap` drops from 12 → 4. `dispatch_specialist` stays at 0.

### Bypass

Two env-var kill switches:

| Env var | Default | Effect |
|---|---|---|
| `STRIX_QUICK_OSS_PREPASS_DISABLED` | unset | Skip the anchor pass, fall through to current lead-only behaviour. For debugging the new path's regressions. |
| `STRIX_QUICK_OSS_PREPASS_TIMEOUT` | 600 | Per-tool timeout. Hard cap on time we'll wait for any single anchor scan. |

### Telemetry

The anchor pass emits a new event `oss_anchor_prepass.completed` with:
- `target_type`
- `tools_run: list[str]` (per-target-type sequence actually invoked)
- `tools_succeeded: list[str]`
- `tools_failed: list[str]` (binary missing, timeout, parse error)
- `findings_count_by_tool: dict[str, int]`
- `total_findings_pre_dedupe: int`
- `wall_time_s: float`

Surfaces in `simulation_run.json` as a top-level `oss_anchor_prepass` block alongside the existing `specialists_dispatched` counter.

## Out of scope (separate PRs)

- **Sandbox-routing of the anchor scans.** Per `docs/proposals/2026-05-19-route-oss-wrappers-through-sandbox.md`, the scan_* wrappers should run inside the sandbox container. Anchor pass uses the same path the lead does today (host subprocess). Switching to sandbox-routing is independent.
- **Standard / deep mode prepass.** Standard and deep modes ALSO benefit from anchor pre-pass — the LLM should focus on chaining / PoC synthesis, not tool selection. But the scope of changes is larger (those modes have dispatch_specialist + chain construction interacting with results). Defer.
- **Native MOAK feed-trigger integration in the prepass.** The MOAK Researcher consumes Dependency nodes from `scan_sca_lockfiles` output. The prepass emits those, so MOAK consumption works automatically — no extra wiring needed.

## Acceptance criteria

- [ ] flask-vuln in quick mode: recall ≥ 0.5 (5/10 must_find) AND wall time ≤ 10 min
- [ ] vampi in quick mode: recall ≥ 0.4 (3/8 must_find) AND wall time ≤ 10 min
- [ ] LLM call count per fixture: ≤ 5 (down from 12+)
- [ ] `simulation_run.json` includes the new `oss_anchor_prepass` block
- [ ] All existing quick-mode behaviour preserved when `STRIX_QUICK_OSS_PREPASS_DISABLED=1`
- [ ] No regression in `pytest tests/agents/lead_agent/ tests/llm/`

## Risks

- **Anchor sequences are hardcoded per target type.** If a customer's target doesn't fit one of the seven types, the prepass falls through and we revert to current behaviour. Not a regression.
- **Findings from the anchor pass duplicate what the lead might emit later.** The dedup logic in `strix/llm/dedupe.py` is what handles this. If dedupe is weak, the customer sees duplicate findings. Existing dedup tests should catch regressions.
- **The anchor scans need their binaries on PATH (or in sandbox per follow-up PR).** When a binary is missing, `scan_*` returns `status=partial` — surfaces clearly in the report, doesn't crash.
- **iter_cap reduction from 12 → 4 might starve standard-mode-shaped quick runs.** No — standard mode has its own iter_cap of 60, untouched. Quick mode's new role is light enough for 4.
