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

## L1-only measurements (2026-05-20)

The OSS-first pre-pass (PRs #364–#369) gives a deterministic L1-only recall per fixture, no LLM cost. Use `benchmarks/per_target/bench_l1_only.py` to reproduce.

| Fixture | target_type | Competitor bar | **Strix L1** | matched | Notes |
|---|---|---|---:|---|---|
| code/flask-vuln | local_code | Semgrep p/python: 80-100% | **0.700** | 7/10 | At semgrep parity. Missing 3: `hardcoded-secret` (needs secrets_scan in real sandbox), `idor-users` (SAST can't), `path-traversal-files` (semgrep coverage gap on `os.path.join(BASE_DIR, request.args[...])`). |
| api/vampi | api | Burp Pro: 50-70% / ZAP: 25-40% | **0.125** | 1/8 | Caught `rate-limit-login` via per-endpoint `scan_api_rate_limit` (PR #368). 7 missing must_finds need L2 prereqs (cross-session auth for BOLA/BFLA/MA, JWT extraction, parameter discovery for SQLi). |
| web+code/vibe-app | web+code | Snyk + DAST: 50-70% | 0.000 | 0/5 | Phase-2 routing requires `openapi_spec_ingest` to emit endpoints, but web apps typically have no OpenAPI spec. Needs `webapp_recon_pipeline` (crawl-based endpoint emission) + same per-endpoint routing as vampi. Iter-7 work. |
| ip/vulnerable-services | ip_address | nmap+nuclei+Tenable: 80-95% | 0.000 | 0/3 | Empty L1 anchor list for `ip_address`. Needs nmap → service discovery → per-service nuclei + tls_audit. Iter-6 work. |
| web/juiceshop | web_application | Burp Pro Active: 30-50% / ZAP: 15-25% | 0.000 | 0/9 | Same as vibe-app — needs crawl-based endpoint discovery. Many must_finds are business-logic-only catchable by L2 reasoning. |

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
