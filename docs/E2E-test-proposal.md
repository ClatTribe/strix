# End-to-end test proposal — asset-type × layer coverage

> The iter-25 / iter-26 correctness audit (PRs #428, #429) caught **four
> real bugs** that the existing test suite missed. Every one of them
> passed unit + integration tests because the tests mocked the layer
> the bug lived in:
>
> | Bug | Iter | What mock hid it |
> | :-- | :--- | :--- |
> | report_id ID-collision after FP drop | 25.1 | tests asserted `len()==0` after drop, never asserted next-id-differs |
> | exploited findings not promoted | 25.5 | unit tests built findings with explicit reachability_score, never tested the missing-score path |
> | iter-cap scaler hardcoded `50` | 26.3 | tests never set `STRIX_SPECIALIST_MAX_ITERATIONS` |
> | `drain_amplify_queue` passed `agent_state=None` to sandbox tools | 26.5 | tests mocked `execute_tool` itself, bypassing the sandbox validator |
>
> All four are the same shape: **a layer above mocked the layer below**.
> The right defence is end-to-end tests that exercise the real
> persistence + sandbox + LLM-routing paths.
>
> This doc proposes the E2E test matrix (asset-type × layer) and the
> sequencing of which tests to write first.

---

## 1. Test taxonomy — what "E2E" means here

Strix has four test tiers today; each catches a different class of bug:

| Tier | Scope | Speed | What it catches | Examples |
| :--- | :--- | :--- | :--- | :--- |
| **Unit** | One function, mocks for I/O | ms | logic errors in pure-function helpers | `test_fp_filter.py`, `test_exploitability.py` |
| **Module integration** | Class boundaries, mocked `subprocess`/`httpx` | ms | wire-up + state mgmt | `test_tracer_integration.py` (existing) |
| **L1.5 / L2 cross-layer** | Real tracer + real hooks, mocked tool outputs | seconds | does L1 emission flow through L1.5 enrichment to L2 catalog correctly | **PROPOSED** |
| **Per-target bench** | Live docker fixture + real L1 tools + real sandbox | minutes | recall/precision on real targets; sandbox availability | `benchmarks/per_target/bench_l1_only.py` (exists) |

The **third tier is the gap.** The bench (tier 4) is too slow to run on every PR; unit/module tier passes too easily on mocks. The cross-layer tier with real tracer + real registry + mocked subprocess is the sweet spot — runs in single-digit seconds, exercises every wire connection.

This proposal targets **tier 3** for every asset-type × layer cell.

### What every E2E test must do

1. **Use the real `Tracer`** (no `Tracer.__new__()` skeletons). Run via the real constructor with a tmpdir for `STRIX_RUN_DIR`.
2. **Use the real tool registry.** Look up tools via `get_tool_by_name(...)`, do not import the function directly.
3. **Mock only at the I/O boundary** — `subprocess.run` for shell tools, `httpx.Client` for network probes, `urllib.request.urlopen` for ruleset fetches. NEVER mock `execute_tool`, `add_vulnerability_report`, or any L1.5 hook function.
4. **Assert on the persisted state**, not the in-memory dict the test passed in. Read back from `tracer.vulnerability_reports[i]["..."]` after the call.
5. **Cover the recall-safe path** — at least one test per layer that injects an exception in the layer below and asserts the upstream call still succeeds.

---

## 2. Asset-type × layer matrix

Six asset types × four layers = 24 cells. Marked status as of post-iter-26-fixes:

| Asset type | L0 (rulesets) | L1 (specialists) | L1.5 (enrichment) | L2 (orchestration) |
| :-- | :-- | :-- | :-- | :-- |
| `web_application` | ⚠ partial | ✅ bench (juiceshop, webgoat) | ⚠ partial (one e2e in `test_tracer_integration`) | ❌ **NO E2E** |
| `api` | ⚠ partial | ✅ bench (vampi, crapi) | ❌ **NO E2E** | ❌ **NO E2E** |
| `repository` | ⚠ partial | ✅ bench (flask-vuln, sast-vibe, sca-*) | ❌ **NO E2E** | ❌ **NO E2E** |
| `host` (ip_address) | n/a | ✅ bench (vulnerable-services) | ❌ **NO E2E** | ❌ **NO E2E** |
| `container_image` | n/a | ✅ bench (nginx-vuln — currently timing out) | ❌ **NO E2E** | ❌ **NO E2E** |
| `binary` | n/a | ❌ no fixture | ❌ **NO E2E** | ❌ **NO E2E** |

**Legend.** ✅ = covered. ⚠ partial = some coverage, gaps. ❌ = no E2E.

The honest read: **L1 is well-covered by the bench, every other cell is patchy.** Specifically:

- **L0** (ruleset cache + custom_signatures injection) only has unit tests. We have never E2E-asserted "cached gitleaks.toml AND scope.yml custom_signatures injected AND gitleaks subprocess picks up the merged config AND the finding emerges with the custom rule_id."
- **L1.5** has unit tests for each hook in isolation. The four merged bugs all lived in cross-hook interactions or in the persistence path. No test asserts the full chain on a real finding.
- **L2** has no E2E at all. The bug where `drain_amplify_queue` couldn't reach sandbox tools is the canonical example — would have been caught by any test that exercised the real executor.

---

## 3. Proposed E2E tests — per cell

Eighteen proposed tests, one per non-empty cell. Each names what it asserts and what it mocks.

### 3.1 L0 — signature corpora + custom_signatures

| ID | Test | Asserts | Mocks |
| :-- | :--- | :--- | :--- |
| **E2E-L0-1** | `test_l0_gitleaks_cached_config_used_by_secrets_scan` | `secrets_scan` invokes gitleaks with `--config <cached>` when `~/.strix/cache/rules/gitleaks.toml` exists | `subprocess.run` |
| **E2E-L0-2** | `test_l0_scope_custom_signatures_compiled_into_gitleaks_toml` | scope.yml with `custom_signatures.secrets: [{id: INTERNAL-DEV-KEY, regex: ...}]` → `compile_gitleaks_config` writes the merged file → `secrets_scan` invokes gitleaks pointing at the compiled variant | `subprocess.run`, `urllib.request.urlopen` |
| **E2E-L0-3** | `test_l0_hadolint_custom_severity_overrides_propagate` | `custom_signatures.dockerfile.severity_overrides: {DL3000: warning}` → compiled `hadolint.yaml.compiled` → `scan_dockerfile_hadolint` argv includes the compiled path | `subprocess.run` |
| **E2E-L0-4** | `test_l0_update_failure_falls_back_to_baked_seed` | `update_gitleaks_rules` with network error → status="partial" → existing cache untouched → next `secrets_scan` still uses the old cached config | `urllib.request.urlopen` |

### 3.2 L1 — deterministic specialists per asset type

Existing bench covers the happy path. Gap: cross-tool-with-mocked-output tests that don't need docker.

| ID | Asset | Test | Asserts | Mocks |
| :-- | :--- | :--- | :--- | :--- |
| **E2E-L1-web-1** | web_application | `test_l1_webapp_anchor_prepass_emits_findings` | given a mocked katana/httpx/dalfox subprocess output, anchor_prepass produces ≥3 findings with correct CWE + endpoint fields | `subprocess.run`, `httpx.Client` |
| **E2E-L1-api-1** | api | `test_l1_api_anchor_prepass_with_openapi_spec` | OpenAPI spec ingest + `scan_api_bola` against a discovered path → BOLA finding emitted with correct endpoint param | `subprocess.run`, `httpx.Client` |
| **E2E-L1-repo-1** | repository | `test_l1_repo_anchor_prepass_sast_sca_secrets` | semgrep + gitleaks + osv-scanner mocked outputs → three findings with the right `discovery_source_tool` set | `subprocess.run` |
| **E2E-L1-host-1** | host | `test_l1_host_anchor_prepass_nmap_then_specialists` | nmap output → port list → triggers per-port specialists → service-version finding emitted | `subprocess.run` |
| **E2E-L1-container-1** | container_image | `test_l1_container_trivy_dockle_grype_corroborate` | three tools find the same CVE → after L1.5 corroborator, ONE critical finding with `corroborated_by: [2]` | `subprocess.run` |

### 3.3 L1.5 — enrichment / join / amplify

These exercise the **full hook chain** on real findings, not individual hooks in isolation. Specifically caught the 4 audit bugs.

| ID | Test | Asserts | Mocks |
| :-- | :--- | :--- | :--- |
| **E2E-L15-1** | `test_l15_full_hook_chain_promotion_path` | SAST + DAST finding on same CWE+surface → root_cause first, then corroborator boosts parent to critical, then exploitability sees the boost → all five enrichment fields land on persisted record | none in L1.5 layer |
| **E2E-L15-2** | `test_l15_fp_drop_does_not_collide_report_id` | (regression for Bug 3) emit FP-dropped finding, then real finding → ids differ + only the real one persists | (none) |
| **E2E-L15-3** | `test_l15_exploited_finding_promotes_to_critical` | (regression for Bug 4) `verification_status=exploited` finding → exploitability bumps severity → critical persisted | (none) |
| **E2E-L15-4** | `test_l15_hook_exception_does_not_block_emission` | monkeypatch one L1.5 hook to raise → all OTHER hooks still run, finding still persists | (raise inside hook) |
| **E2E-L15-5** | `test_l15_systemic_promotion_drops_l2_token_cost` | emit 30 findings of the same rule×file×func → only 1 persisted with `occurrences[29 entries]` AND severity promoted to "systemic issue" tier | (none) |

### 3.4 L2 — orchestration

These are the **most missing** category — none exist today. All must exercise the real tool registry + Lead system prompt rendering.

| ID | Test | Asserts | Mocks |
| :-- | :--- | :--- | :--- |
| **E2E-L2-1** | `test_l2_list_pending_findings_ranks_by_l15_signals` | emit 5 findings with varying surface_priority + exploitability + severity → `list_pending_findings()` returns them in the correct order, noise hidden | (none) |
| **E2E-L2-2** | `test_l2_dispatch_specialist_scales_by_surface_priority` | dispatch against `/admin` target → captures `max_iterations` passed to orchestrator = `base × 3.0 × hygiene_mult` | mock `_orchestrator()` |
| **E2E-L2-3** | `test_l2_dispatch_specialist_respects_env_cap` | (regression for Bug 1) `STRIX_SPECIALIST_MAX_ITERATIONS=120` → critical-surface dispatch gets 216 not 90 | mock `_orchestrator()` |
| **E2E-L2-4** | `test_l2_drain_amplify_queue_routes_agent_state_to_executor` | (regression for Bug 2) call drain with a sentinel agent_state → `execute_tool` receives THAT object, not None | mock `execute_tool` but inspect the kwargs the wrapper actually passed |
| **E2E-L2-5** | `test_l2_stealth_payload_addendum_renders_into_specialist_prompt` | set posture cache with WAF detected → build SQLi specialist prompt → assert STEALTH MODE block appears | (none) |
| **E2E-L2-6** | `test_l2_lead_prompt_addendum_contains_l15_vocabulary` | render the actual Lead system prompt → assert all L1.5 field names appear (exploitability, surface_priority, corroborated_by, pending_confirmations) | (none) |

### 3.5 Asset-type-specific L2 routing

The Lead's tool catalog is filtered per `target_type`. Need one test per type confirming the L1.5-aware tools are present AND the asset-specific anchors fire correctly.

| ID | Asset | Test | Asserts |
| :-- | :--- | :--- | :--- |
| **E2E-L2-web-1** | web_application | `test_l2_web_catalog_includes_l15_tools_and_recon` | `get_lead_tool_catalog(["web_application"])` ⊇ `{list_pending_findings, drain_amplify_queue, execute_adaptive_probe, katana_crawl, probe_hosts_httpx, ...}` |
| **E2E-L2-api-1** | api | `test_l2_api_catalog_includes_l15_tools_and_api_probes` | catalog ⊇ `{list_pending_findings, scan_api_bola, scan_api_bfla, scan_api_rate_limit, ...}` |
| **E2E-L2-repo-1** | repository | `test_l2_repo_catalog_includes_l15_tools_and_sast_sca` | catalog ⊇ `{list_pending_findings, scan_sast, scan_sca_lockfiles, secrets_scan, ...}` |
| **E2E-L2-host-1** | host | `test_l2_host_catalog_includes_l15_tools_and_port_probes` | catalog ⊇ `{list_pending_findings, fingerprint_services_nmap, probe_open_tcp_ports, ...}` |
| **E2E-L2-container-1** | container_image | `test_l2_container_catalog_includes_l15_tools_and_image_scans` | catalog ⊇ `{list_pending_findings, scan_container_image, scan_image_dockle, ...}` |

---

## 4. Implementation plan

### Phase A — regression coverage (Wave 1, immediate)

Land the four regression tests for the bugs we already fixed. Each is small, each prevents a re-regression:

- **E2E-L15-2** (ID collision)
- **E2E-L15-3** (exploited promotion)
- **E2E-L2-3** (env cap)
- **E2E-L2-4** (agent_state plumbing)

Status: regressions for bugs 1 + 2 + 3 + 4 were **all included in their respective fix PRs (#428, #429)**. So Phase A is **done**.

### Phase B — L1.5 cross-hook chain (Wave 2)

The four audit bugs all lived in cross-hook interactions. Build E2E coverage for the full chain:

- **E2E-L15-1** full promotion chain
- **E2E-L15-4** hook-exception passthrough
- **E2E-L15-5** systemic-promotion + token-cost-drop

~3 tests, ~150 LOC. Single PR.

### Phase C — L2 orchestration (Wave 3)

- **E2E-L2-1** ranking
- **E2E-L2-2** depth scaling
- **E2E-L2-5** stealth render
- **E2E-L2-6** prompt-vocab presence

~4 tests, ~250 LOC. Single PR.

### Phase D — Asset-type catalog tests (Wave 4)

Five quick tests asserting the per-target catalog includes the L1.5-aware tools. Pure registry inspection; no mocks needed.

~5 tests, ~150 LOC. Single PR.

### Phase E — L0 / L1 cross-tool tests (Wave 5)

The harder ones. Need to mock subprocess for each tool in the chain AND verify the cache file actually got opened.

~9 tests, ~500 LOC. Two PRs (L0 + L1).

### Total estimated effort

**~21 new E2E tests** (4 already shipped, 17 to write), **~1,050 LOC**, spread over 5 PRs. Time-box: roughly the same as one iter wave.

---

## 5. Anti-pattern guardrails

These are the test smells that let bugs 1-4 ship. Reject any PR that introduces them in L1.5 / L2 code:

| Anti-pattern | Why dangerous | Replacement |
| :-- | :--- | :--- |
| `monkeypatch.setattr("strix.tools.executor.execute_tool", ...)` | Bypasses sandbox + registry validation. Bug 2 lived here. | Mock `subprocess.run` or `httpx.Client` instead — let the executor's real validation run |
| `Tracer.__new__(Tracer)` then manually setting attrs | Skips constructor invariants (`_next_report_seq`). Bug 3 was hidden because the test never tracked the counter. | Use `Tracer(run_name="test")` with `STRIX_RUN_DIR` set |
| Asserting `len(vulnerability_reports) == N` without also asserting the *identities* match | Drops + collisions look identical | Assert on actual id values, not just counts |
| Building findings dict directly + passing to a hook | Skips emission path → never sees full enrichment chain | Use `tracer.add_vulnerability_report(...)` then read back `tracer.vulnerability_reports[i]` |
| Setting `STRIX_X` env vars only in fixtures, never asserting they propagate | The hardcoded-50 bug shipped this way | At least one regression test per env var, set in the test body and assert the configured value reaches the underlying call |

---

## 6. Where existing tests already cover (no duplicate work)

To avoid re-writing what's already there:

- **L0 ETag refresh logic:** `tests/tools/rule_updates/test_common.py` covers fresh / updated / unchanged / partial. **Keep.**
- **L1.5 individual hooks:** `tests/l15/test_fp_filter.py`, `test_root_cause.py`, `test_corroborator.py`, `test_exploitability.py`, `test_posture.py`, etc. **Keep — these catch unit-level errors. The E2E tests proposed above are additive.**
- **L1 happy-path:** `bench_l1_only.py` against 14 fixtures. **Keep — slow but irreplaceable for real recall numbers.**
- **Tool registration:** every iter-22/23/24/25/26 PR includes a `test_registered` assertion. **Keep.**

The proposed E2E tests don't replace these — they layer on top to catch cross-layer bugs that unit tests can't see.

---

## 7. Open questions

- **Per-fixture or per-target-type?** The bench harness has 14 fixtures. Should E2E-L1 tests bind to specific fixtures or use generic-target mocks? Recommendation: **generic mocks** for tier-3, **real fixtures** for tier-4 (bench). Keeps tier 3 fast.

- **CI cost.** ~21 new tests adding ~10-30s each = +5min CI. Acceptable; the bench (tier 4) currently runs only manually anyway.

- **Should patcher get E2E?** The patcher specialist is L2 but not in the matrix above. Recommendation: defer to iter-27 along with the patcher git_blame work (26.10 was prompt-only; patcher's actual commit-message generation isn't testable until we have a real patch flow). Spawn that as a separate task.

- **Mobile / binary asset types.** Mobile was removed in iter-21.5; no E2E needed. Binary has no fixture and no L1 anchor today — defer.
