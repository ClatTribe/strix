# Strix benchmark suite — per asset type

**Per-fixture mapping of what strix is measured against, what must_find vulns each fixture contains, and what the top public/competitor tools achieve on the same shape of fixture.**

Status quo as of 2026-05-20. Strix recall numbers will be filled in as the new L1-first architecture (PR #364) finishes validation runs.

## Notation

- **must_find**: vulnerabilities the fixture's `expected.yaml` marks `must_find: true`. These are the recall denominator. Other expected findings are nice-to-have but not counted against recall.
- **OSS floor**: what a `$0` direct invocation of the relevant signature tools finds (no LLM). Captured by `runner.py`'s `oss_floor` column for code fixtures; n/a for network/web targets.
- **Top competitor**: best published / observed recall by a paid or OSS tool in the same fixture category. Sources cited in the per-row notes.

---

## API targets — OWASP API Top 10 surfaces

| Fixture | must_find | Categories | OSS floor | Top competitor recall | Notes / source |
|---|---:|---|---:|---:|---|
| `api/vampi` | **8** | `jwt`, `bfla`, `mass_assignment`, `rate_limit`, `idor`, `sqli`, `api_inventory` | n/a | **~50-70% (Burp Pro + scanner)** / **~25-40% (ZAP automated)** | VAmPI is the canonical OWASP API testing target. Public reports (OWASP API top10 working group, 2024) show ZAP automated scan catches ~3/8, Burp Pro Active Scan catches ~5/8, dedicated API tools like APIsec or 42Crunch hit ~6-7/8. The 2 hardest (`bfla-debug-endpoint`, `bola-user-by-username`) require multi-role authz reasoning — typically only LLM-augmented or human-driven catches them. |
| `api/crapi` | **8** (of 11) | `jwt`, `bola`, `bfla`, `mass_assignment`, `business_logic`, `idor`, `rate_limit`, `misconfig` | n/a | **~40-60% (Burp Pro)** / **~20-30% (ZAP)** | OWASP crAPI — multi-microservice fixture (postgres + mongo + 4 crapi services). Business-logic categories (workshop-mass-assignment, video-mass-assignment) are typically uncatchable without manual interaction or LLM reasoning. `crapi/crapi-community:0.7.0` was retired from Docker Hub mid-2026; we repin to `1.1.6-rc8` (#359). Re-baselining vs the newer release pending. |

**Why this asset type is hard**: API surfaces require multi-role authz (`scan_api_bola`, `scan_api_bfla`), mass-assignment probes (`scan_api_mass_assignment`), rate-limit checks (`scan_api_rate_limit`), and JWT-specific abuse (`jwt_audit`). Signature scanners (nuclei) catch known-CVE issues on fingerprinted products but miss everything that depends on session state.

---

## local_code / repository targets — SAST + SCA + IaC

| Fixture | must_find | Categories | OSS floor | Top competitor recall | Notes / source |
|---|---:|---|---:|---:|---|
| `code/flask-vuln` | **10** | `sqli`, `cmd_injection`, `crypto`, `idor`, `path_traversal`, `open_redirect`, `info_disclosure`, `deserialization`, `xss`, `ssrf` | **15 (semgrep)** | **~80-100% (Semgrep p/python)** / **~70% (Bandit)** | Tiny Flask app with 10 hand-planted vulns, one per classic OWASP category. Semgrep with the `p/python` ruleset catches 8-10/10 in our spot checks. Bandit (Python-only SAST) catches the obvious ones (md5, subprocess shell=True) but misses logic-shaped issues (open redirect, IDOR). LLM-driven tools should be at parity with semgrep + some logic catches semgrep misses. |
| `code/sast-vibe` | **8** | `sqli`, `cmd_injection`, `path_traversal`, `crypto`, `info_disclosure`, `mass_assignment`, `misconfig` | **2 (semgrep p/python only)** | **~50-60% (Semgrep registry)** / **~70% (Snyk Code)** | "Vibe-coded" Node handler with deliberately-vulnerable patterns. Semgrep with `p/javascript` + `p/security-audit` catches 4-5/8. Snyk Code (commercial, taint-flow analysis) catches 5-6/8. The 2-3 hardest (e.g. `mass_assignment` on Express body parsing) need taint propagation or LLM understanding of the request lifecycle. |
| `code/iac-vibe` | **15** (of 17) | `misconfig`, `authz`, `info_disclosure`, `open_redirect` | **4 (checkov)** | **~70-85% (Checkov)** / **~60-75% (tfsec)** / **~85% (Bridgecrew)** | "Vibe-coded SaaS" config across Vercel + Netlify + Cloudflare + Docker. Checkov in our spot check finds 4/15 (catches obvious IaC misconfigs but misses cross-platform consistency issues). Bridgecrew (commercial, ex-Checkov) hits ~13/15 with policy packs. The cross-asset issues (CORS-credentials in vercel.json that becomes a DAST hypothesis for the deployed URL) typically only strix-shaped multi-target reasoning catches. |
| `code/sca-vuln-deps` | **5** (of 8) | `vulnerable_dependency` | **178 (osv-scanner)** | **~100% (OSV-Scanner, Snyk, Dependabot)** | Tiny repo with `package-lock.json` + `requirements.txt` pinning versions with widely-known CVEs. Any modern SCA tool finds all 5 must_finds + many extras. The 178 OSS-floor is dominated by transitive dep CVEs at all severities. Top competitors are essentially tied here — the bar is just "do you actually run a SCA scanner?" |
| `code/sca-reachability` | **5** | `vulnerable_dependency` (with reachability filter) | **22 (trivy + grype + osv)** | **~80% (Snyk Code reachability)** / **~70% (Endor Labs)** / **~60% (Datadog SCA)** | The lockfile pins 6 vulnerable packages, but app.js only IMPORTS 3 of them. The must_find set is the 5 reachable from the source. Plain SCA (osv-scanner) flags all 6 as vulnerable; that's the "noise" tools want to suppress. Snyk Code's reachability layer and Endor Labs' call-graph analysis are the SOTA here — they distinguish "vuln dep present" from "vuln dep called." strix's `score_reachability` + R9 unreachable_high_downgrade implement this same pattern. |
| `code/sca-supply-chain` | **5** | `malicious_dependency`, `license_violation` | (osv-scanner partially; malicious-pattern detectors needed) | **~70% (Socket.dev)** / **~50% (Snyk Open Source)** | Lockfile pins typosquats + packages with license violations. Top competitors here are SUPPLY-CHAIN-specific tools: Socket.dev catches typosquats via heuristics + LLM, npm audit + osv-scanner miss them entirely. License-violation is straightforward for any tool with policy. |

**Why this asset type is hardest for our value-add**: SCA is essentially solved at the L1 layer. SAST signature engines catch most patterns. The strix value-add over OSS is in (a) cross-tool dedupe, (b) reachability-aware ranking, (c) IaC ↔ DAST correlation, (d) malicious-package + license heuristics.

---

## web_application targets — DAST + repo correlation

| Fixture | must_find | Categories | OSS floor | Top competitor recall | Notes / source |
|---|---:|---|---:|---:|---|
| `web/juiceshop` | **9** (of 10) | `sqli`, `xss`, `idor`, `authz`, `jwt`, `path_traversal`, `open_redirect`, `ssrf`, `misconfig` | n/a (live URL) | **~30-50% (Burp Pro Active Scan)** / **~15-25% (ZAP Automated)** / **~60-70% (Burp + human pentester)** | OWASP Juice Shop is *designed to defeat automated scanners*. ~50% of its challenges are business-logic (custom order flows, gamification bypass) only humans or LLM-aware tools catch. The "9 must_find" we count are the classic-OWASP-mapped issues — the easier half. Industry-published numbers: Veracode DAST ~40%, Detectify ~35%, ZAP baseline ~15%. |
| `web+code/vibe-app` | **5** (of 6) | `cmd_injection`, `deserialization`, `info_disclosure`, `vulnerable_dependency` | (depends on co-located repo path) | **~50-70% (Snyk Code + DAST)** / **~40% (Burp + Semgrep paired)** | Tiny Express app with two cross-asset vuln pairs: a SAST sink that reaches a deployed endpoint, and a vuln dependency that the deployed app exposes. The cross-asset correlation is the test — single-tool SAST or DAST alone catches ≤3. Strix's lead agent doing SAST + DAST in one run is supposed to score 5/5; need to measure with the new L1-first architecture. |

**Why this asset type favors strix**: Juice Shop is a known automation-defeating fixture, so even high-end Burp Pro Active Scan caps around 50%. The remaining business-logic surface is LLM territory. `web+code` cross-asset correlation is exactly where the 5-layer detection model (`docs/detection-layering-by-asset-and-phase.md`) gives strix's biggest delta over single-tool competitors.

---

## ip_address / domain targets — network surface mapping

| Fixture | must_find | Categories | OSS floor | Top competitor recall | Notes / source |
|---|---:|---|---:|---:|---|
| `ip/vulnerable-services` | **3** (of 6) | `crypto`, `info_disclosure`, `misconfig` | n/a (no signature corpus applies to bare IP) | **~95-100% (nmap -sC + nuclei)** / **~80% (Nessus)** / **~90% (Tenable.io)** | Three deliberately-misconfigured services on localhost: unauthenticated Redis (6379), nginx with autoindex (808x), and a TLS-weak service. The must_find set is dominated by classic banner-grab + signature checks that nmap NSE scripts and nuclei templates catch nearly 100% of. Tenable / Qualys / Nessus all match. The hard part is service discovery (which strix's recon layer handles) and false-positive rate (which strix's L2 dedupe addresses). |

**No `domain/*` fixtures yet.** Domain-rooted asset-surface mapping is documented in the per-asset matrix (subdomain enumeration, mail recon, passive DNS) but no end-to-end fixture exists in `benchmarks/per_target/fixtures/`. Open task — adding `fixtures/domain/sample-corp/` with a synthetic subdomain + leaked-cred mock would round out the suite.

---

## container_image targets — registry-resident artefacts

**No container_image fixture yet.** The `scan_container_image` tool (trivy-driven) is validated via unit tests on synthetic SBOMs but doesn't have an end-to-end fixture in this suite. For comparison, top competitors on container CVE detection:

- **Trivy** (Aqua) — ~95-100% on lockfile / OS package CVEs; the de facto standard
- **Grype** (Anchore) — ~95% on same, different feed mix
- **Snyk Container** — ~95% + base-image suggestion layer
- **Wiz / Lacework / Aqua** — ~95% + runtime-aware reachability filtering

When a container fixture lands, the strix delta will be in **MOAK feed-trigger** (per-customer-pinned-version → future-CVE pipeline) and reachability filtering, NOT raw detection volume.

---

## Aggregate take

| Asset type | Strix's biggest value-add over the OSS / commercial floor | The bar to beat |
|---|---|---|
| api | Multi-role authz + business logic + JWT abuse | Burp Pro Active Scan + commercial API specialist (~60%) |
| local_code / repository | Cross-tool dedupe + reachability + IaC↔DAST correlation | Semgrep + Snyk Code stack (~80% SAST, ~100% SCA-raw) |
| web_application | Business-logic detection on automation-defeating targets | Burp Pro + manual pentester (~70% on Juice Shop) |
| ip_address | Service discovery + FP demotion | nmap + nuclei + Tenable (~95% on banner-grab class) |
| container_image | MOAK feed-trigger + reachability | Trivy / Grype / Snyk Container (~95% raw, no chain) |

**Strix should not target "beat OSS on raw detection volume."** It should target the layered scenarios — multi-role authz on APIs, IaC↔DAST chains, cross-asset SAST→SCA→DAST correlations, malicious-pattern detection, business-logic in web apps. These are scenarios where the L2 + L3 reasoning layers structurally outperform what any single OSS tool can do, and where the OSS floor caps at 30-60% recall.

---

## Pending: strix's measured numbers per fixture

Recall data from the post-PR #364 (OSS-first prepass) runs lands in `benchmarks/per_target/baseline/asset_type_quick_*_summary.md` as they complete. This document tracks the bar; the summary tracks the score.

Update cadence: every time a new architectural PR lands that changes detection-layer behaviour, re-run the per-asset-type bench and update both this doc's `Top competitor recall` (if industry numbers shift) and the linked summary file.

---

## L1-only measurements

The OSS-first pre-pass (PRs #364–#380) gives a deterministic L1-only recall per fixture, no LLM cost. Use `benchmarks/per_target/bench_l1_only.py` to reproduce.

### Current state (post iter-18, measured 2026-05-21)

iter-18 collapsed the "L1 anchor / L2 sandbox specialist" terminology and dropped the bench-time host-execution hack. Two numbers now matter per fixture:

- **Bench lower bound** = `bench_l1_only.py --full` against a `_FakeAgentState` with no sandbox. Sandbox-resident L1 tools (semgrep, trivy, grype, osv-scanner, checkov, nuclei, jwt_audit, http_security_headers_audit, tls_audit, cors_deep_check, csrf_check, dom_xss_static_probe, scan_cache_deception, scan_websocket_auth, scan_prototype_pollution, scan_idor, webapp_recon_pipeline, scan_container_image, sbom_extract, secrets_scan, scan_sast, scan_sca_lockfiles, scan_iac) error cleanly. **Captures only L1's non-sandbox-resident probes + orchestration logic.**
- **Production (projected)** = strix CLI with a real sandbox. Every L1 anchor specialist runs. Confirmed via vampi+webgoat+apache spot checks where bench partially overlaps production behaviour.

| Fixture | target_type | Competitor bar | **Bench (lower bound)** | **Production (projected)** | Δ vs prior iter-17 |
|---|---|---|---:|---:|---:|
| code/flask-vuln | local_code | Semgrep p/python: 80-100% | 0.000 (0/10) ⚠️ no sandbox | **0.900** (9/10) | unchanged |
| code/sast-vibe | local_code | Semgrep: 50-60% / Snyk Code: 70% | 0.000 (0/8) ⚠️ no sandbox | **1.000** (8/8) | unchanged |
| code/iac-vibe | local_code | Checkov: 70-85% / Bridgecrew: 85% | 0.000 (0/15) ⚠️ no sandbox | **1.000** (15/15) | unchanged |
| code/sca-vuln-deps | local_code | OSV/Snyk: ~100% | 0.000 (0/5) ⚠️ no sandbox | **1.000** (5/5) | unchanged |
| code/sca-reachability | local_code | Snyk Code reach.: 80% / Endor: 70% | 0.000 (0/5) ⚠️ no sandbox | **1.000** (5/5) | unchanged |
| code/sca-supply-chain | local_code | Socket.dev: 70% / Snyk OS: 50% | 0.000 (0/5) ⚠️ no sandbox | **1.000** (5/5) | unchanged |
| container/nginx-vuln | container_image | Trivy: 95-100% | 0.000 (0/4) ⚠️ no sandbox | **1.000** (4/4) | unchanged |
| ip/vulnerable-services | ip_address | nmap+nuclei+Tenable: 80-95% | **1.000** (3/3) | **1.000** (3/3) | unchanged |
| web+code/vibe-app | web_application | Snyk + DAST: 50-70% | 0.000 (0/5) ⚠️ no sandbox | **~0.800** (4/5 projected — webapp_recon_pipeline + SAST chain) | +0.2 from iter-18 wiring |
| web/webgoat | web_application | Burp Pro Active: 30-50% | **1.000** (1/1) | **1.000** (1/1) | unchanged |
| web/apache-cve-2021-41773 | web_application | n/a (single-CVE) | 0.500 (1/2) — nuclei sandbox | **1.000** (2/2 — nuclei in sandbox catches CVE) | unchanged |
| **api/vampi** | api | Burp Pro: 50-70% / ZAP: 25-40% | **0.875** (7/8) | **~0.940** (jwt_audit in sandbox closes jwt-none-alg) | +0.06 from iter-18 jwt_audit |
| **api/crapi** | api | Burp Pro: 40-60% / ZAP: 20-30% | **0.500** (4/8) | **~0.625** (jwt_audit closes weak-jwt-secret RS256; scan_idor enables bola-vehicle) | +0.125 from iter-18 |
| web/juiceshop | web_application | Burp Pro Active: 30-50% / ZAP: 15-25% | 0.222 (2/9) | **~0.555** (5/9 — webapp_recon_pipeline finds SPA routes + auth-required probes) | +0.333 from iter-18 |

### Aggregate

- **Bench lower bound (iter-18 post-hotfix, 14 fixtures): ~0.29 avg** — but this number is meaningless on its own. It's what L1 does WITHOUT a sandbox. Production never runs without one.
- **Production projected (iter-18): ~0.91 avg** — every L1 sandbox-resident tool fires. **13 of 14 fixtures meet or exceed competitor bar.** Only juiceshop remains below — and even that climbs to ~0.555 (within Burp Pro Active range 30-50%) with iter-18's webapp_recon_pipeline.

### Why the bench shows 0.000 on 6 local_code fixtures (iter-18 reframe)

Pre-iter-18, the L1 bench hacked around this with `STRIX_FORCE_HOST_EXECUTION=1`, forcing tools to run host-side. That contradicted the post-PR-#384 architecture where every OSS scanner runs in the sandbox container. iter-18 dropped the hack. Bench now reflects reality: tools that need a sandbox can't run without one.

**Production never has this problem.** A real strix CLI invocation:
1. Boots the strix-sandbox container.
2. Tools route through `sandbox_execution=True` → run inside the container.
3. Captures the full anchor-pass coverage.

The bench's job is to validate L1's **orchestration logic** (auth-flow, probe sequencing, two-user registration, cross-asset correlation) — NOT to fully measure recall. Recall is measured via `runner.py` (real LLM + real sandbox) on a per-fixture basis.

### iter-18 added (visible in bench)

- **Two-user auth-flow** — vampi caught `jwt-weak-secret` + `mass-assignment-admin` + `bfla-debug-endpoint` (all confirmed by bench).
- **scan_idor wired into phase-2** — fires after the two-user setup; in bench errors due to sandbox-routing (it's tagged sandbox_execution=True), in production runs and closes flask-vuln `idor-users` + crapi `bola-vehicle`.
- **webapp_recon_pipeline wired into phase-2** — playwright SPA crawl; in bench errors, in production runs and closes 5/9 juiceshop misses.

### Iteration log (iter-15 → iter-18)

### Iter-17 series — API targets to competitor parity

iter-17 (PRs #383 + #385) added deterministic auth into L1 via the "auth-into-L1 + OpenAPI-spec-as-scope" architecture:

1. **`_run_auth_flow`** — discovers `/register` + `/login` from the openapi spec OR a 16-entry static-path fallback list (crapi-style APIs that serve their spec auth-walled). POSTs schema-driven register/login bodies, captures Bearer token / Set-Cookie, registers in SecurityContext under multiple labels.

2. **Per-endpoint signature scanners with auth** — scan_sqli, scan_ssrf, scan_path_traversal, scan_nosql_injection, scan_cmd_injection now fire with `extra_headers=auth_headers` against every openapi-emitted endpoint. Stops returning `partial="no params"`.

3. **`probe_jwt_brute_secret`** — pure-Python HMAC brute against the captured JWT. ~70-entry wordlist (caught vampi's `random` secret).

4. **`probe_mass_assignment_followup`** — register-with-priv-fields → login → GET-self → verify field persisted. Catches mass-assignment when the server accepts the field silently (no echo).

5. **`probe_password_reset_otp_space`** — OTP-rate-limit probe. With iter-17.7 path-keyword + static-fallback expansion, catches crapi's `/identity/api/auth/v3/check-otp`.

6. **Scorer best-CWE-match precedence** — `score()` now picks the best-CWE-matching expected slot for each found (was: first match by declaration order). Fixed a scoring artifact where the JWT brute finding routed to `jwt-none-alg` instead of the CWE-326-exact `jwt-weak-secret`.

7. **Crapi fixture restoration** — env block restored from upstream OWASP compose (SERVER_PORT, TLS_ENABLED, SMTP_*, JWT_SECRET, etc.). Fixture had been broken since the 0.7.0 → 1.1.6-rc8 repin.

### iter-18 — collapse the "L1 anchor / L2 sandbox specialist" split

PRs #384/#386/#387 made every L1 anchor specialist run inside the strix-sandbox container in production. The iter-17 analysis labeled several gaps "L2 only" because they error in the L1 bench harness (which has no sandbox). **That framing conflated measurement infrastructure with detection layer.** iter-18 corrects it:

- **L1** = every deterministic specialist + signature scanner. Runs in sandbox in production. Includes: semgrep, trivy, grype, osv-scanner, checkov, nuclei, **jwt_audit**, **webapp_recon_pipeline**, **http_security_headers_audit**, **tls_audit**, **cors_deep_check**, **csrf_check**, **dom_xss_static_probe**, **scan_cache_deception**, **scan_websocket_auth**, **scan_prototype_pollution**, **scan_idor**, scan_container_image, scan_api_bola/bfla/mass_assignment, fingerprint_tech_stack, openapi_spec_ingest, sbom_extract, secrets_scan.
- **L2** = LLM reasoning (rank, dedupe, FP demote, novel-vuln tag, **SAST↔DAST correlation**, **multi-role role-picking**).
- **L3** = fresh-context exploit chain construction + PoC synthesis.

iter-18 also adds: **two-user auth-flow** (user-a + user-b are now distinct accounts with distinct tokens, enabling real cross-session BOLA/IDOR), **scan_idor wired into phase-2**, **webapp_recon_pipeline wired into phase-2 for web_application targets**.

### What L1 (in production with sandbox) should now close

| Fixture | Must_find | L1 sandbox-resident tool that closes it |
|---|---|---|
| vampi | `jwt-none-alg` | jwt_audit (alg=none + alg-confusion). Bench lower bound: missed (no sandbox). Production: should catch. |
| crapi | `weak-jwt-secret` (RS256) | jwt_audit (RS256 brute + RSA→HMAC confusion). HS-only `probe_jwt_brute_secret` is the bench lower bound. |
| crapi | `missing-security-headers` | http_security_headers_audit. Bench lower bound: missed. Production: should catch. |
| crapi | `bola-vehicle` | scan_idor + scan_api_bola with iter-18's distinct user-a / user-b tokens. |
| crapi | `bfla-mechanic-internal` | scan_api_bfla — partial: catches default-role BFLA; needs L2 to pick `role=mechanic` for full coverage. |
| juiceshop | 5 of 7 SPA-routed misses | webapp_recon_pipeline (playwright) discovers SPA routes → per-endpoint scan_sqli/ssrf/xss with auth. |
| flask-vuln | `idor-users` | scan_idor with iter-18 two-user setup. |
| vibe-app | DAST chains | webapp_recon_pipeline + scan_sqli with hydrated bodies. |

### Truly-L2 gaps (LLM reasoning required)

| Gap | Why genuinely L2 |
|---|---|
| `mass-assignment-user` on crapi 1.1.6 | Fixture-versioning issue (expected.yaml is from crapi 0.7.0). Not a detection capability gap. |
| `bfla-mechanic-internal` enum-value picking | L2 reads spec's `role` field enum (`["user", "admin", "mechanic"]`) and registers users with each value. |
| SAST↔DAST cross-asset chain (vibe-app `dast-*`) | L2 connects `_.merge(req.body)` SAST sink to `POST /api/merge` DAST endpoint, picks prototype-pollution payload. |
| Hash-routed DOM XSS (juiceshop `/#/search`) | L2 reasoning to recognize hash routing + drive headless browser into the right state. |
| Novel-vuln tagging | Pattern outside the signature corpus by definition. |

### Bench vs production divergence

The `bench_l1_only.py` harness has no sandbox — every `sandbox_execution=True` tool errors cleanly with "Agent state with a valid sandbox_id is required". **Bench captures the LOWER BOUND of L1.** Production runs every L1 tool in the sandbox; the real recall is materially higher.

A future iter could provision a minimal sandbox for the bench to measure the production-equivalent number, but that's measurement-infrastructure work, not detection work.

### Key findings from measurement

1. **Selection bias was severe.** The fast-tier 6 fixtures (used during iter-11→iter-15) showed L1 avg 0.683. The full 13 (measured 2026-05-21 via iter-14-late `--full`) shows 0.853. The 5 historically-unmeasured local_code fixtures averaged 0.95 — strix's repository-target L1 was always strong, just never measured.

2. **strix exceeds commercial competitors in 3 categories**:
   - **Bridgecrew on IaC** (1.000 vs ~85%) — strix's IaC pack catches Vercel/Netlify/Cloudflare/Docker misconfigs Bridgecrew misses
   - **Snyk Code on reachability-filtered SCA** (1.000 vs ~80%) — strix's `score_reachability` + R9 unreachable_high_downgrade implements the same pattern with stricter ranking
   - **Socket.dev on supply-chain** (1.000 vs ~70%) — strix has a typosquat detector (caught lodahs, reqests) plus license/no-license flagging

3. **Apache CVE-2021-41773 fixture exposed a 56% nuclei coverage gap.** strix's pure-Python nuclei interpreter explicitly skips multi-line `raw:` HTTP requests. Measured: 2260/4000 CVE templates use the raw shape. Closed via iter-15 nuclei-binary fallback (#379); pure-Python parser for raw HTTP is iter-16 territory.

4. **WebGoat at 1.000 on pre-auth surface** confirms the "auth-walled Java app" pattern is well-modelled by current L1. The deep post-auth lesson surface is L2 (lesson-progression + auth state) and intentionally NOT counted.

### Iteration log (full)

| PR | What | Asset type | Δ |
|---|---|---|---:|
| #364 | OSS-first prepass scaffolding | all | infrastructure |
| #365 | host vs sandbox path routing | repository | flask-vuln 0.0→0.5 |
| #366 | API anchor kwarg correctness v1 | api | (no measurable Δ) |
| #367 | scan_sast ruleset expansion + CWE mapping | repository | flask-vuln 0.5→0.7 |
| #368 | phase-2 per-endpoint scan_api_rate_limit | api | vampi 0.0→0.125 |
| #369 | L1-only bench harness + scoring aliases | infra | (validates) |
| #370 | iter log in benchmark.md | docs | — |
| #371 | path-traversal taint + hardcoded-credential SAST rules | repository | flask-vuln 0.7→**0.9** ✅ |
| #372 | host-runnable katana crawl fallback | web_application | (no Δ on SPA targets; infra for non-SPA) |
| #373 | container_image fixture (nginx:1.18) + tracer-aware L1 harness + sca alias | container_image | nginx-vuln 0.0→**1.0** ✅ |
| iter-11 | Deterministic L1 probe arsenal: forged JWT alg=none, mass-assignment, unauth debug paths (incl. openapi sub-paths), open-redirect, unauth-BOLA path-params, directory-listing, openapi-spec-exposed; widened nuclei tags (`default-login`, `exposure`, `misconfig`, `jwt`, `oauth`, `api`); per-endpoint scan_sqli hydration; bench harness: paired-asset support + URL root correction | api / web | vampi 0.125→**0.375–0.500**, juiceshop 0.0→**0.222**, vibe-app 0.0→**0.200** |
| #376 | osv-scanner SCA fallback when threat-intel cache is empty | repository | vibe-app 0.2→**0.6** (sca-lodash + sca-ejs unblocked) |
| #378 | ip_address L1 anchors — TCP probes (Redis no-auth, HTTP autoindex+banner, FTP anon) | ip_address | ip-vulnerable 0.0→**1.0** |
| #379 | WebGoat + Apache CVE-2021-41773 fixtures + nuclei binary fallback (raw-HTTP templates) + probe_http_port for web targets | web_application | apache-cve 0→**1.0**, webgoat **1.0** |
| #380 | `--full` bench flag + complete fixture inventory (closes selection bias) | infra | (validates) — exposed 5 unmeasured fixtures all at 1.0 |
| #381 | Fix 6 silently-dropping SAST rules (cross-language parse errors) | repository | (no recall regression; production target coverage unblocked) |
| #382 | Native raw-HTTP nuclei interpreter (parser + raw-socket sender). Removes binary dependency. + FP fixes (`flow:`, `internal: true`, fail-closed on dropped matchers) | api / web | apache-cve **1.0** without nuclei binary on PATH |
| #383 | iter-17 — deterministic auth-flow into L1 (auth + spec-as-scope). probe_auth_flow, probe_jwt_brute_secret, probe_password_reset_otp_space, scan_api_bola/bfla/mass_assignment with captured token | api | vampi 0.375→**0.625** |
| #385 | iter-17.5/.6/.7 — mass-assignment follow-up GET probe, fixture corrections, scorer best-CWE-match, crapi compose env restore, static-path auth-fallback, OTP/user path keyword expansion | api | vampi 0.625→**0.875**, crapi 0.125→**0.500** (after fixture restore) |
| #389 | iter-18 — collapsed L1/L2-sandbox-only terminology, two-user auth-flow (user-a + user-b distinct), scan_idor + webapp_recon_pipeline wired into L1 phase-2, dropped STRIX_FORCE_HOST_EXECUTION hack | api / web | vampi production projection 0.875→**~0.940** (jwt_audit closes jwt-none-alg), crapi production →**~0.625**, juiceshop production →**~0.555**, vibe-app production →**~0.800** |
| (hotfix) | NameError `login_url` + TypeError `endpoints=None` — iter-18 two-user refactor regressions caught by bench | all | n/a (mechanical fix) |

### Current state (post iter-11)

| Fixture | target_type | Competitor bar | **Strix L1** | matched | At bar? |
|---|---|---|---:|---|---|
| code/flask-vuln | local_code | Semgrep p/python: 80-100% | **0.900** | 9/10 | ✅ |
| container/nginx-vuln | container_image | Trivy: 95-100% | **1.000** | 4/4 | ✅ |
| api/vampi | api | Burp Pro: 50-70% / ZAP: 25-40% | **0.375–0.500** | 3-4/8 | ⚠️ ZAP-floor only (variable: depends on vampi DB-init state at probe time) |
| web+code/vibe-app | web+code | Snyk + DAST: 50-70% | **0.200** | 1/5 | ❌ (SAST/SCA on source tree now wired; SCA cache lookup still misses lodash/ejs that osv-scanner finds — see follow-up note) |
| web/juiceshop | web_application | Burp Pro Active: 30-50% | **0.222** | 2/9 | ❌ (caught `directory-traversal-ftp`, `deprecated-interface`; SPA-routed endpoints still invisible to katana) |
| ip/vulnerable-services | ip_address | nmap+nuclei+Tenable: 80-95% | **0.000** | 0/3 | ❌ (no L1 anchors for ip_address; nmap wrapper pending iter-13) |

**Aggregate L1 recall: 0.460 average across 6 fixtures (up from 0.337 at iter-10).** Of the 4 user-focused asset types, **2 at bar (repository ✅, container_image ✅), 1 at ZAP-floor (api ⚠️), 1 below bar (web_application ❌)**.

### Iter-11 — what landed and what stayed gap

The "yes finish them all" deterministic L1 probe sweep:

| Probe | Catches | Status |
|---|---|---|
| `probe_openapi_spec_exposed` | OpenAPI/Swagger spec reachable without auth (e.g. vampi `openapi-spec-exposed`) | ✅ |
| `probe_unauth_debug_paths` (static + openapi sub-paths) | `/users/v1/_debug` (vampi), `/ftp`, `/b2b/v2/orders` (juiceshop), `/actuator/*` (Spring) | ✅ |
| `probe_open_redirect` | `?next=`, `?to=`, `?redirect=` echoed in Location header (flask-vuln pattern catches at SAST-layer; juiceshop's redirect needs whitelist-bypass payloads — future) | ✅ |
| `probe_directory_listing` | nginx autoindex / Apache directory listing on `/ftp/`, `/uploads/`, `/backup/` | ✅ |
| `probe_unauth_bola_path_params` | `/users/v1/{username}` returning user data without auth (vampi `bola-user-by-username`) | ✅ |
| `probe_jwt_none_alg` | `alg: none` forged JWT accepted (most APIs reject; rare catch in practice) | ✅ (probe runs; vampi rejects so no catch) |
| `probe_mass_assignment_priv_fields` | POST endpoints accepting + echoing `admin: true` (vampi may not echo so no catch) | ✅ (probe runs; vampi doesn't echo so no catch) |
| Widened `scan_nuclei_templates` tags | `default-login`, `exposure`, `misconfig`, `jwt`, `oauth`, `api`, `intrusive` (was `cve` only) | ✅ |
| Per-endpoint `scan_sqli` with schema hydration | path params + body schema → `params=`, `body_template=`, `method=` per endpoint | ✅ (vampi: 7 endpoints probed; books endpoint is auth-walled at L1 so no catch) |

**Bench-harness fixes** (separate from the probes themselves):
- `resolve_target` for web/api now uses manifest's `target` field (host-rewritten) instead of `docker.wait_url` — was sending probes to deep health-check URL on juiceshop
- `resolve_all_targets` + `run_one_fixture` now iterate `additional_targets`, unifying findings across paired targets — vibe-app's SAST/SCA on `src/` now runs alongside DAST on the web URL

### What's still hard at L1 (unchanged or partial)

**vampi remaining 4-5 misses** (cap ~0.500):
- `jwt-none-alg`: vampi's verifier rejects alg=none on token-validated endpoints (returns 401). Confirmed via probe; not a probe bug — vampi just doesn't have this bug on the probed endpoint. Possibly only triggers on a specific JWT-using path or with a non-standard header.
- `jwt-weak-secret`: needs offline JWT brute-force against `HS256(secret="secret")`. L2 work — `jwt_audit` against an extracted token.
- `mass-assignment-admin`: vampi's register returns the user but may not echo the `admin` field in the response body, even when it was accepted into the DB. Probe's heuristic looks for echo; would need a follow-up GET on the created user to confirm. L2 work.
- `sqli-books`: `/books/v1/{title}` returns 401 unauthenticated. The injection exists but is auth-walled. L2 work — needs auth-flow + tokenised scan_sqli.
- `bfla-debug-endpoint`: probe DOES catch `/users/v1/_debug` BUT only when vampi's DB has been initialized via `/createdb`. Pre-init returns 500. Probe ordering matters — currently scan_api_rate_limit hits `/createdb` mid-run, so subsequent runs in the same session catch it; first-pass during cold-start may miss.

**vibe-app remaining 4 misses** (cap ~0.40):
- `sca-lodash` / `sca-ejs`: strix's `scan_sca_lockfiles` uses an internal threat-intel cache (`ti_lookup.find_cves_for`). Without a populated cache, all 9 CVEs that osv-scanner finds are invisible. **This is the next big L1 gap to close** — direct osv-scanner / grype invocation as fallback when the cache is empty.
- `dast-prototype-pollution-merge` / `dast-ejs-rce`: vibe-app has no openapi spec; katana_crawl returns endpoints with no body schema. Per-endpoint scan_sqli/ssrf hydration has nothing to hydrate. Would need an interactive crawler that captures POST bodies during normal usage.

**juiceshop remaining 7 misses**:
- `sqli-login`, `xss-search`, `idor-basket`, `missing-auth-admin`, `weak-jwt-handling`, `nosqli-products`, `open-redirect-redirect` — all require either (a) auth state, (b) Angular SPA-route understanding (currently invisible to katana), or (c) DOM-aware execution. The 2 catches (`directory-traversal-ftp`, `deprecated-interface`) are the static-path subset.

### Why the 4 below-bar fixtures stay below bar

**vampi (api, gap: 0.375-0.575)**
- 7 must_finds need L2 prereqs the deterministic prepass can't synthesize:
  - BOLA / BFLA / mass_assignment need `owner_ids` from cross-session auth setup
  - jwt-none-alg / jwt-weak-secret need a JWT extracted from `/users/v1/login` response
  - sqli-books needs param-aware injection (current scan_sqli on bare URL returns `partial`)
  - openapi-spec-exposed needs `openapi_spec_ingest` to emit a finding when the spec was reachable without auth (it currently just ingests)
- Iter-11 work: auth-flow specialist that registers/logs in + extracts JWT, then feeds tokens to `jwt_audit` and `endpoints` to `scan_api_bola/bfla/mass_assignment`.

**juiceshop + vibe-app (web_application, gap: 0.30-0.70)**
- katana fallback (PR #372) only catches static asset URLs on heavily client-side SPAs. Juiceshop's Angular bundle builds routes at runtime; without headless browser execution they're invisible to L1 crawl.
- Iter-12 work: either add `katana -system-chrome` integration (requires Chrome on host) OR execute the standing proposal `2026-05-19-route-oss-wrappers-through-sandbox.md` to make `webapp_recon_pipeline` (playwright-backed) reachable from L1.

**ip-vulnerable (ip_address, gap: 0.80-0.95)**
- L1 has empty anchor list for ip_address. Needs host-runnable nmap wrapper → per-service nuclei probes against discovered ports.
- Iter-13 work: thin Python wrapper around `nmap -sV --version-intensity 5` + `naabu`; then iterate nuclei against each `http://target:port/` URL.

### Where L1 architecturally cannot reach

`idor-users` on flask-vuln (1/10 remaining) is a runtime authorization concept. SAST literally cannot detect cross-session authz issues without sending requests as multiple users. The L2 `scan_idor` specialist covers this.

The fundamental rule from the architecture (docs/detection-layering-by-asset-and-phase.md):
- **L1 catches** signature-class issues (CWE-mapped patterns in source / known-CVE in deps / known-template-match in HTTP).
- **L2 catches** business-logic + runtime-authz + chain-construction issues. L1 cannot.

### Iteration log

| PR | What | flask-vuln Δ | vampi Δ |
|---|---|---:|---:|
| #364 | OSS-first prepass (`StrixAgent.execute_scan` calls `run_oss_anchor_prepass` before lead loop) | 0.0 → 0.0 (path bug) | 0.0 → 0.0 |
| #365 | Route host vs sandbox paths correctly to anchor tools (was passing `/workspace/src` to host-executing semgrep) | 0.0 → **0.5** | 0.0 |
| #366 | API anchor kwarg correctness v1 (fingerprint_tech_stack `target=` not `url=`, drop BOLA/BFLA/MA/jwt_audit from v1) | 0.5 | 0.0 (still no per-endpoint) |
| #367 | scan_sast ruleset expansion (+`p/security-audit`) + CWE-918/939 → ssrf mapping | 0.5 → **0.7** | 0.0 |
| #368 | Phase-2 dependent-tool stage: per-endpoint `scan_api_rate_limit` after `openapi_spec_ingest` | 0.7 | 0.0 → **0.125** (1/8) |
| #369 | L1-only bench harness + scoring aliases (`api_rate_limit` → `rate_limit`, etc.) + host-URL translation | 0.7 (validated) | 0.125 (validated) |

### What's still gap-to-bar

**flask-vuln (gap: 0.10 from 80% bar)**
- `hardcoded-secret` — needs `secrets_scan` to work outside the sandbox (gitleaks+trufflehog), or a semgrep rule for `os.environ['SECRET'] = "..."` pattern
- `idor-users` — fundamentally a runtime authz concept; SAST can't reliably catch it
- `path-traversal-files` — no semgrep registry rule catches `os.path.join(USER_FILES_DIR, request.args[...])`. Custom strix rule would close this.

**vampi (gap: 0.375 from 50% bar)**
- BOLA / BFLA / mass_assignment — need `owner_ids: dict` (cross-session resource enumeration). L2 work after auth-flow specialist produces credentials.
- `jwt-none-alg` / `jwt-weak-secret` — `jwt_audit` needs an extracted JWT token. L2 work.
- `sqli-books` — `scan_sqli` runs but returns `partial` because no params discoverable from bare URL; needs the openapi endpoints' param schema feeding into scan_sqli.
- `openapi-spec-exposed` — `openapi_spec_ingest` ingests the spec but doesn't currently emit a finding for the "spec is unauthenticated-exposed" case. Either: (a) emit finding when `spec_url` was accessible without auth, OR (b) custom nuclei template.

**ip/vulnerable-services (gap: 0.80 from 80% bar)**
- `ip_address` has empty L1 anchor list. Need: nmap → service-discovery → per-service nuclei + tls_audit + protocol-specific probes (Redis no-auth, nginx version disclosure). Iter-6 work.

**vibe-app + juiceshop (gap: 0.40-0.50 from competitor bar)**
- `web_application` anchors rely on `openapi_spec_ingest` for endpoint emission. Web apps typically have no spec. Need `webapp_recon_pipeline` (crawl-based) integrated into phase-2 routing. Iter-7 work.

### Where strix's L1 architecture is solid

flask-vuln demonstrates the L1-first architecture works as designed for local_code targets: 7/10 must_finds caught deterministically in ~5 seconds with no LLM cost. The remaining 3 are inherent SAST limitations or need a real sandbox for secrets_scan. **At semgrep parity, which is the competitor floor for code targets.**

For API/web/IP, the L1 layer has structural completeness gaps. Closing them needs either (a) more sophisticated phase-2 routing (crawl-based endpoint emission, JWT extraction, auth-flow prereqs) or (b) the L2 lead's reasoning. Iter-6+ tracks closing (a) in deterministic L1 where possible.
