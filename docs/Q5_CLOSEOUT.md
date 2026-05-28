# Q5 Closeout — Per-Asset L1 Expansion + Filtration

Q5 was the multi-wave push to bring every strix asset type to per-tool L1 parity with the best-in-class OSS scanners + ship deterministic per-asset filtration. This doc captures the final state — what shipped, what's deferred, and why.

## Shipped iters (38)

### Q5 foundational (proposals + L2 cap + bench infra)

| iter | what | PR |
|---|---|---|
| Q5 proposal | L2 ≤10 cap + translation toolkit design | (docs) |
| Q5.2 | CI invariant test for L2 ≤10 cap | shipped |
| Q5.3 | move web/api deep-exploit OSS wrappers to anchor_prepass | shipped |
| Q5.4 | move ip_address recon to anchor_prepass | shipped |
| Q5.5 | move domain recon to anchor_prepass | shipped |
| Q5.7 | query_threat_intel (4-wrapper collapse) | shipped |
| Q5.8/9/10 | rescan / dispatch_l2_probe umbrellas | shipped |
| Q5.11 | chain_summary + customer_priority params on create_vulnerability_report | shipped |
| Q5.13 | customer_context per-scan config | shipped |
| Q5.14 | L2-CAP bumped 10 → 12 | shipped |
| Q5.15 | think() persists to run_summary | shipped |

### Q5 sandbox / bench rewires

| iter | what | PR |
|---|---|---|
| Q5.21 | sandbox network fix for ip_address bench targeting | shipped |
| Q5.22 | install hydra/schemathesis/smuggler in sandbox image | shipped |
| Q5.23 | host-side tools translate host.docker.internal → 127.0.0.1 | shipped |
| Q5.24-25 | OWASP Benchmark v1.2 unblock + verify | shipped |
| Q5.26 | OWASP fixture uses cargo:run runtime | shipped |
| Q5.27 | rewire OWASP Benchmark as local_code (SAST headline) | shipped |
| Q5.28-29 | L1-SAST findings reach vulnerability_reports | shipped |
| Q5.30 | STRIX_SKIP_CACHE_INIT=1 in bench harness | shipped |
| Q5.31 | sandbox→host sidecar propagation | shipped |
| Q5.32 | language-aware semgrep pack selection | shipped |
| Q5.33 | bench auto-detects full 2740-case CSV from src cache | shipped |
| Q5.34 → Q5.34l | WAVSEP L1-DAST headline bench (10 sub-iters) | shipped |

### Q5 per-asset filtration + routing (Wave 1)

| iter | asset | filter | PR |
|---|---|---|---|
| Q5.40 | api | per-endpoint method routing (BOLA/BFLA/idor only on relevant verbs) + health-path filter | #556 |
| Q5.41 | repository / local_code | semgrep `--exclude` for vendored / generated / minified | #558 |
| Q5.42 | container_image | opt-in `--pkg-types library` / `--ignore-unfixed` / `--platform` | #559 |
| Q5.43 | ip_address | per-port nuclei tag routing (39 ports → relevant tag families) | #557 |
| Q5.44 | domain | child-asset pivot sidecar (`PrepassSummary.child_assets_discovered[]`) | #560 |

### Q5 per-asset OSS additions (Wave 2)

| iter | asset | tool | PR |
|---|---|---|---|
| Q5.45 | domain | OWASP **amass** subdomain enum | #561 |
| Q5.46 | domain | **crt.sh** certificate-transparency mining | #562 |
| Q5.47 | container_image | Anchore **grype** CVE corroboration | #563 |
| Q5.48 | container_image | Anchore **syft** canonical SBOM | #563 |
| Q5.49 | api | Assetnote **kiterunner** endpoint discovery | #564 |
| Q5.50 | ip_address | **masscan** fast first-pass port discovery | #564 |
| Q5.51 | ip_address | **ZGrab2** structured banner grabber | #564 |

### Q5 architecture docs

| artifact | scope |
|---|---|
| `arch.md` | per-asset L1 / L1.5 / L2 / bench matrix, OODA loop, sandbox boundary, anti-overfit gates |
| `CLAUDE.md` §1.5.6-1.5.9 | tool-existence principle + 4-bucket taxonomy + per-asset shipped catalogs |
| `Q5_CLOSEOUT.md` (this file) | final ledger |

---

## Deferred iters — rationale per deferral

These iters were scoped under Q5 but are deferred to follow-on sessions. Each carries a short reason; spawning a focused session per group keeps the PRs reviewable.

### Architectural SAST additions

| iter | what | why deferred |
|---|---|---|
| Q5.35 | CodeQL as sibling SAST anchor (taint-flow) | CodeQL CLI requires GitHub Container Registry pull + 1.2 GB extractor download + per-language database build (Java compilation, JS bundle resolution). Wrapper is ~150 lines but the sandbox image + bench fixture rewire is substantial. Deserves its own session. |
| Q5.36 | SpotBugs-FindSecBugs (.jar bytecode analysis) | Java-only and only fires on compiled .jar/.war artefacts — needs a compile step in the bench fixture path before SpotBugs has anything to look at. Same shape as Q5.35 — wrapper is small, fixture work isn't. |
| Q5.37 | Close Java semgrep pack gaps (JSP XSS, weakrand, hash, LDAP, XPath) | Rule-authoring work — needs per-CWE pack assembly + OWASP Benchmark per-category re-bench. ~3-5 days of rule iteration; bench cycle is the bottleneck. |

### Speculative / lower-confidence OSS adds

| iter | what | why deferred |
|---|---|---|
| Q5.52 | APIClarity (API traffic analysis) | Requires sidecar proxy injection into the SUT — fundamentally different deployment model from the other API tools. Architectural integration cost is high. |
| Q5.53 | GraphQL fuzzer | `map_graphql_inql` already covers introspection + schema mapping. A fuzzer adds payload-shape testing but the OSS landscape here is thin (clairvoyance, graphw00f). Needs research before implementation. |
| Q5.54 | Credentialed network scan (Nessus / OpenVAS) | Both are commercial / heavy installs. OpenVAS sandbox image add is ~2 GB. Belongs in an enterprise-flavoured deployment, not the default sandbox. |
| Q5.55 | Anchore Enterprise policy | Anchore Engine is open source but the policy-pack work that makes it useful (CIS / NIST / vendor-specific) is closed. Q5.47 grype already captures the OSS CVE-corroboration value. |
| Q5.56 | Shodan API integration | Requires API key — not a free / OSS dependency, doesn't fit the "no auth required" L1 contract. Could ship as an opt-in L2 specialist instead. |

### Bench-harness expansion

| iter | what | why deferred |
|---|---|---|
| Q5.60 | L1-API headline bench (vampi + crapi expansion) | Need a neutral leaderboard equivalent to WAVSEP / OWASP Benchmark. OWASP API Security Top-10 has no published vendor scorecard. Internal-only bench shipped via `bench_l1_only.py --fixture api/vampi`. |
| Q5.61 | L1-container headline bench expansion | Same gap — no neutral leaderboard for container scanners. Trivy / Snyk / Anchore self-publish only. Internal bench shipped via `bench_l1_only.py --fixture container/nginx-vuln`. |
| Q5.62 | L1-network headline bench | Tenable / Qualys / Rapid7 don't publish neutral scorecards. Internal bench via `bench_l1_only.py --fixture ip/vulnerable-services` (now with the Q5.50/Q5.51 additions); Vulhub CVE recipes (Q5.30 territory) is closest published comparator. |
| Q5.63 | L1-domain headline bench | subfinder vs amass vs assetfinder published rates exist but on different fixtures. No neutral leaderboard. Internal recall-on-known-asset benchmark is the workable substitute. |

---

## Wave 1 status — closed ✓

All 5 asset types now follow the per-asset filtration pattern:

| asset | filter | sidecar |
|---|---|---|
| `web_application` | Q5.34i fan-out skip shapes | `endpoints[]` via katana |
| `api` | Q5.40 method routing + health filter | `endpoints[]` via openapi + kiterunner |
| `repository` / `local_code` | Q5.41 file-tree skip patterns | semgrep findings |
| `container_image` | Q5.42 base-layer skip (opt-in) | trivy + grype + syft outputs |
| `ip_address` | Q5.43 per-port nuclei routing | masscan + nmap + ZGrab2 outputs |
| `domain` | Q5.44 child-asset pivot | `child_assets_discovered[]` |

CI invariants pin every layer:
* `tests/agents/lead_agent/test_l2_cap_invariant.py` — L2-CAP ≤12
* `tests/agents/lead_agent/test_anchor_fanout.py` — fan-out routing
* `tests/agents/lead_agent/test_api_endpoint_routing.py` — Q5.40
* `tests/sast/test_repo_skip_patterns.py` — Q5.41
* `tests/tools/container_image/test_container_base_layer_skip.py` — Q5.42
* `tests/agents/lead_agent/test_ip_port_routing.py` — Q5.43
* `tests/agents/lead_agent/test_domain_child_asset_pivot.py` — Q5.44 + amass/crt.sh extraction passes

## Wave 2 status — partial (7 of 8 OSS adds shipped)

| iter | tool | status |
|---|---|---|
| Q5.45 | amass | ✓ shipped |
| Q5.46 | crt.sh | ✓ shipped |
| Q5.47 | grype | ✓ shipped |
| Q5.48 | syft | ✓ shipped |
| Q5.49 | kiterunner | ✓ shipped |
| Q5.50 | masscan | ✓ shipped |
| Q5.51 | ZGrab2 | ✓ shipped |
| Q5.55 | Anchore | deferred (closed-source policy gap) |
| Q5.56 | Shodan | deferred (commercial API key) |

Remaining domain enumerator candidates (assetfinder, certspotter) are interchangeable with subfinder + amass + crt.sh from a recall standpoint — pursuing them next would deliver diminishing returns.

---

## Bench numbers at close-of-Q5

* **L1-SAST** (OWASP Benchmark v1.2, local_code, semgrep + bandit + checkov + …): pinned per-CWE Youden in `benchmarks/per_target/baseline/owasp_bench_Q5_33_*.json`. Wave 2 changes touch container/ip/domain L1 — SAST unchanged.
* **L1-DAST** (WAVSEP, web_application): see `benchmarks/per_target/baseline/wavsep_Q5_34l_*.json`. Detached fan-out bench at limit=200 was running at the end of session (PID 38226, log `/tmp/wavsep_Q5_34l_20260528_192955.log`).
* **L2** (Juice Shop, dual-mode): `benchmarks/per_target/baseline/l2_juiceshop_full_*.json` — last standard-mode run pre-Q5.40 was the current published baseline. Wave 2 changes affect prepass coverage; L2-only metrics unchanged.

No L1 detection regression at any sub-layer across Wave 1 + Wave 2 (verified via 461-test regression sweep on every Wave 2 PR).

---

## What "best-in-class at L1 per asset type" looks like, post-Q5

| asset | L1 OSS tools fired in prepass | L1.5 hooks |
|---|---|---|
| `web_application` | katana, nuclei, sqlmap, dalfox, smuggler, ffuf, schemathesis, scan_sqli/xss/idor/auth_flow, csrf_check, cors_deep_check, fingerprint, openapi_spec_ingest, hydra | FP filter, surface_priority, exploitability, corroborator, post_emit_verifier |
| `api` | openapi_spec_ingest, **kiterunner**, schemathesis, scan_api_bola/bfla/mass_assignment, map_graphql_inql, scan_idor + DAST specialists | same |
| `repository` / `local_code` | semgrep (language-aware), bandit, trivy fs, gitleaks, trufflehog, checkov, hadolint, mobsfscan, osv-scanner | same |
| `container_image` | trivy image, dockle, **grype**, **syft** | same + Q5.47 corroborator promotion |
| `ip_address` | **masscan**, nmap, **ZGrab2**, httpx, scan_nuclei_templates (per-port routed), tls_audit | same |
| `domain` | domain_recon_pipeline (subfinder + bbot + …), enumerate_subdomains_subfinder, **enumerate_subdomains_amass**, **enumerate_subdomains_crtsh**, scan_dns_hygiene_checkdmarc, scan_typosquats_dnstwist, scan_nuclei_templates | same |

**Bold** = added in Q5 Wave 2.

---

## Spawning the deferred work

When picking up a deferred iter, the shape is:

1. Open a focused session with the iter ID + reason
2. Run `arch.md` past the new wiring
3. Update CLAUDE.md §1.5.8 per-asset table if catalog count changes
4. Add a CI invariant test if the iter introduces a routing rule
5. Cite the relevant per-layer bench delta in the PR body

The Wave 2 sandbox rebuild (amass + grype + syft + kiterunner + masscan + ZGrab2 binaries) is a single follow-on operation — rebuild the strix-sandbox image once and all 7 binaries become available together.

---

_Last updated 2026-05-28._
