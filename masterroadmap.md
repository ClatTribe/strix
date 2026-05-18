# Master Roadmap — strix engine + webappsec wrapper

Per-target competitive assessment + proposed work to close the highest-
leverage gaps. Read alongside [`roadmap.md`](roadmap.md) (engine items
already prioritised on the standing roadmap), [`overall.md`](overall.md)
(OODA-loop snapshot), and the
[wrapper-wishlist](../webappsec/wrapper-wishlist.md) (wrapper-side polish
for what the engine already ships).

This doc is the **honest competitive view** — what we're good at, what
we're not, and what to build next to close the deltas that actually lose
deals. Not a marketing brief.

**Snapshot date: 2026-05-18.** Reflects shipping through PR #321
(SAML XSW + SP config audit). Major recent arcs:

- **Cloud attack-paths arc** (PRs #293–#311) — graph + 27 patterns +
  reachability + multi-cloud + multi-account + **agentless VM scan** +
  **CloudTrail CDR**. Closes most of §5.
- **Engine-wishlist arc** (PRs #312–#319) — **all 8 org-scale items
  shipped**: batch mode, Researcher cache, `kg_delta.jsonl`,
  `assets.discovered.jsonl`, skip-if-unchanged, `--profile initial`,
  target-metadata, `STRIX_PROJECT_ID`.
- **Web specialists** (PRs #295–#298, #320, #321) — cache poisoning,
  prototype pollution, websocket auth, race condition / TOCTOU, **SAML
  XSW**. Closes all §1 P0/P1 items.
- **Decepticon uplift** (PRs #233–#244) — typed KG, 5-stage verification
  pipeline, OPPLAN, specialist orchestrator, patcher runtime.
- **Skills System Audit arc** (PRs #323–#331) — 8-phase upgrade of
  `strix/skills/`: 46 → 73 skills, every shipped specialist now has a
  paired skill (parity test pins it), hard 5-cap → env-tunable default
  20, `chains/` meta-skill category for cross-target reasoning,
  KG-driven + discovered-asset-driven + target-type auto-load wired
  into lead-agent boot, `skill.loaded` telemetry, `TEMPLATE.md`.

---

## TL;DR positioning

We are **a co-leader in web + API + external surface** (XBEN benchmark
96% — see [`benchmarks/`](benchmarks/)), **credible against Wiz at
mid-market on cloud** (agentless + CDR + 27 attack patterns shipped),
**at parity on static container scanning**, **trailing on IaC depth**
(hand-written rule corpus vs Checkov's 1000+), and **absent on container
runtime** (no CWPP wrap yet).

The agent + MOAK + KG moat is decisive on novel-chain discovery and
cross-target reasoning. Post-cloud-arc and post-engine-wishlist we no
longer pay the per-target cost penalty that previously blocked
enterprise org-scale. The remaining structural gap is dev-adoption
motion (no IDE plugin yet) and one hard-to-build runtime tier
(container CWPP).

---

## Status legend

| symbol | meaning |
|---|---|
| ✅ | shipped on `main` |
| 🚧 | partial — design landed or rough mitigation in place |
| ⬜ | open — not started |

Effort: **S** ≈ a day, **M** ≈ a week, **L** ≈ a month, **XL** ≈ multi-month.

Priority: **P0** = ship next, **P1** = ship this quarter, **P2** = ship
this half, **P3** = research / opportunistic.

---

## Scoring summary (1-10; 5 = category-average)

Breadth = vulnerability category coverage. Depth = ability to discover
known + unknown vulnerabilities vs the top competitor. Agent = how much
agent reasoning / MOAK leverage applies to that target type.

| Target | Breadth | Depth | Agent | Top competitor | Position |
|---|---|---|---|---|---|
| `web_application` | **9** | **8** | 9 | Burp Suite Enterprise | Co-leader — agent moat on novel chains |
| `api` | **8** | **7** | 8 | Akto.io | Parity on declared APIs; runtime-discovery gap |
| `repository` (SAST + SCA) | **7** | **7** | 9 | Snyk Code + Open Source | Competitive on covered languages |
| `repository` (IaC) | **5** | **5** | 8 | Snyk + Checkov | Trailing — hand-written corpus (~50 vs 1000+) |
| `container_image` static | **8** | **8** | 7 | Aqua Security | At parity (Trivy-wrapped) + KEV/EPSS edge |
| `container_image` runtime | **2** | **2** | — | Aqua / Sysdig | Absent — no CWPP wrap yet |
| `cloud_account` | **8** | **7** | 8 | Wiz | Credible — agentless + CDR + 27 patterns shipped |
| `domain` (external surface) | **9** | **8** | 7 | Detectify / Censys ASM | Leader — 30+ recon sources |
| **Cross-target** | **8** | **8** | 9 | Wiz security graph | Co-leader — typed KG + MOAK + finding chains |
| **Org-scale** | **7** | **6** | — | Snyk / Wiz SaaS tier | Improving fast — engine-wishlist arc just shipped |

---

## 1. `web_application` — **co-leader; coverage gap closed**

### Current state

All §1 P0/P1 items shipped. 35+ specialists cover the OWASP Top 10 +
modern-frontend + edge-infrastructure attack classes that Burp Suite
ships built-in. 5-stage verification pipeline (SCANNED → DETECTED →
VERIFYING → VERIFIED → EXPLOITED → PATCHED) has no Burp equivalent.

The remaining structural gap is **route-level diff-aware scanning** —
the dev-adoption lever that PR comment bots depend on.

### Proposed changes (P0 → P3)

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ✅ | **HTTP request smuggling detector** (CL.TE / TE.TE / TE.CL / TE.0). Single specialist that walks the canonical desync probe matrix. Shipped: `scan_request_smuggling_active`. | M | P0 | Highest-impact missing category for any org with a CDN / proxy / load balancer in front of their app. Burp's flagship feature. |
| ✅ | **Web cache poisoning + cache deception** detector. Shipped: `scan_cache_deception` (PR #296). | M | P0 | Increasingly common attack class. |
| ✅ | **Server-side prototype pollution** detector. Shipped: `scan_prototype_pollution` (PR #297). | M | P1 | Node ecosystem ubiquitous. |
| ✅ | **OAuth / OIDC / SAML deep flow analyzer**. OAuth + OIDC shipped (`scan_oauth`). JWT alg-confusion shipped (`tools/jwt_audit`). **SAML XSW + SP config audit** shipped (`scan_saml_xsw` PR #321 — 8 XSW variants + unsigned/mangled-sig probes + `WantAssertionsSigned` audit + weak-alg detection). | L | P0 | Common audit-failure point. |
| ✅ | **WebSocket / SSE auth probe**. Shipped: `scan_websocket_auth` (PR #298). | M | P1 | Modern apps universally have these endpoints. |
| ✅ | **Race condition / TOCTOU** detector — repeat-fire requests with timing variance against state-changing endpoints. Shipped: `scan_race_condition` (PR #320). | L | P2 | Business-logic attack class hardly anyone covers. Differentiator. |
| 🚧 | **Diff-aware scanning at route granularity** — scan only the routes a PR changes. Engine has scope-mode `diff`; needs route-level filtering (resolve modified file → owning routes via `code_map`, filter the catalog accordingly). | M | P0 | Single biggest determinant of developer adoption. Dev mutes the bot otherwise. **Only §1 item still open.** |
| ⬜ | **SPA auth-flow replay maturity** — macro-style recorded-login replay that survives token refresh, redirects, CAPTCHAs. `replay_mutation_*` + `browser_action` work but feel less battle-tested than Burp's macro recorder. | L | P2 | Closes the last Burp-vs-Strix gap on authenticated SPA scanning. |

### Expected impact on scoring
Breadth 7 → **9** (achieved). Depth 8 → 8. Agent 9 → 9.
Coverage gap with Burp closed. The only remaining §1 item is the dev-
adoption lever, not a vulnerability-coverage hole.

---

## 2. `api` — close the discovery gap vs. Akto

### Current state

Schema-aware mass-assignment + BOLA + BFLA + rate-limit + GraphQL deep +
gRPC reflection + 29-cohort SSRF are at parity with Akto on declared
APIs. **JWT alg-confusion** ships via `tools/jwt_audit`. **HAR / Burp
ingestion** shipped (`ingest_har_file`, `ingest_burp_file`) and seeds
the surface map for any subsequent scan. The remaining gap is
**runtime / traffic-mirror API discovery** — Akto's killer feature for
undocumented endpoints.

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ✅ | **HAR / Burp project ingestion → API surface map**. `ingest_har_file` + `ingest_burp_file` extract endpoints + parameter shapes + auth context; `replay_mutation_from_har_file` + `replay_mutation_from_burp_file` drive subsequent probing. | M | P0 | Shipped. Closest we get to traffic-mirror without a runtime agent. |
| ✅ | **JWT alg-confusion deep probe**. `tools/jwt_audit` covers `alg=none`, RS256↔HS256 confusion, kid path traversal, embedded JWK. | S | P0 | Shipped. |
| ⬜ | **JS bundle endpoint extraction**. Parse compiled JS for fetch / axios / XHR call sites; extract URL patterns; seed the surface map. | M | P1 | Catches endpoints OpenAPI doesn't document. Closes one half of the runtime-discovery gap. |
| ⬜ | **OpenAPI delta detector**. On scheduled scan, compare today's OpenAPI to last week's; surface added/removed/changed endpoints as a finding category. | S | P1 | Akto's "runtime API change detection" without runtime — schedule-based instead. |
| ⬜ | **OAuth scope-creep detector**. Compare claimed scopes vs. accessible endpoints under each scope's token. | M | P2 | Real-world misconfig common at SaaS APIs. |
| ⬜ | **gRPC server-reflection + fuzz**. Reflection ✓ (`scan_api_grpc_reflection`); fuzzing the discovered methods is next. | M | P2 | We discover gRPC services; we don't yet attack them. |
| ⬜ | **Runtime traffic mirroring** via eBPF / Envoy / Istio sidecar adapter. The unambiguous Akto moat. The wrapper-side asset-discovery flow can stand in for some of this via continuous HAR ingestion. | XL | P3 | Akto's killer feature. Heaviest lift; lowest-leverage given HAR ingestion already covers the common case. |

### Expected impact on scoring
Breadth 8 → **8** (achieved on declared APIs). Depth 7 → 8 (JS-bundle
extraction + OpenAPI delta close most of the discovery gap without
shipping eBPF infrastructure).

---

## 3. `repository` — close the IaC + dev-UX gap vs. Snyk

### Current state

SAST (`semgrep_runner` + Python AST taint + `code_map`-aware
calibration), SCA (`sca/scanner.py` + KEV/EPSS enrichment + malicious-
package check + license scan + **reachability scoring**
`sca/reachability.py`), secrets (`secrets_scan` + git-history scan
PR #288), and patcher runtime (`agents/patcher.py` + auto-diff +
`verify_patch` close-loop, PR #243) are competitive on the languages
covered. The two remaining gaps are **IaC rule corpus** (~50 hand-
written rules vs Checkov's 1000+) and **developer UX** (no IDE plugin
yet; auto-fix PR composer exists at the patcher layer but not yet
wired to `gh pr create`).

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **Wrap Checkov as IaC primary engine**. Same pattern as Trivy / Prowler — subprocess wrapper, normalise JSON to `IacFinding`, keep built-in rules as fallback. Instantly adds 1000+ TF + 400+ K8s + 200+ CloudFormation + 100+ Helm rules. Apache 2.0. | M | P0 | **Single biggest leverage move in this section.** Mirrors the strategy that worked for CSPM (Prowler wrap). Eliminates the IaC depth gap overnight. |
| ⬜ | **Wrap kics** as the secondary IaC engine (Rego rules). Lets us union Checkov + kics for breadth + cross-validation. | S | P2 | Free addition once Checkov wrap exists. |
| 🚧 | **Diff-aware scanning at route-level granularity** (shared with §1). | M | P0 | Same item as web side; cross-target. |
| ⬜ | **VS Code + JetBrains IDE plugin**. Inline finding render; one-click "open in strix dashboard." | L | P1 | Snyk's adoption motion. Need this for any chance of organic dev pull. |
| 🚧 | **Auto-fix PRs for high-confidence findings**. Patcher runtime ships (`agents/patcher.py` PR #243 — generates diffs + verifies via probe replay). Missing piece: `gh pr create` composer that drives the patcher output into a real PR. | L | P1 | Single biggest developer-time saver. We have the data + the verification loop; the lift is the auto-PR composer at the wrapper. |
| ⬜ | **CloudFormation / Pulumi / CDK parsers**. Parallel to existing Terraform/K8s/Helm parsers. | M | P2 | Closes the IaC framework coverage gap (most large orgs use one of these alongside or instead of TF). |
| ✅ | **Reachability scoring for SCA** — `sca/reachability.py` shipped. Python-only taint upstream (`tools/taint/taint_analysis.py`). | L | P0 | Shipped for Python. Multi-language extension is the follow-up. |
| ⬜ | **Multi-language taint** (JS/TS, Go, Java, Ruby, PHP, C#) — extend the SCA reachability scorer beyond Python. Tree-sitter or LSP-based extraction. | XL | P0 | Closes the depth-vs-Snyk gap on the languages that produce most CVE noise. |

### Expected impact on scoring
Breadth 7 → 9. Depth 7 → 9 (IaC depth jumps from 5 to 9 with Checkov
wrap). Agent 9 → 9.
Closes the Snyk gap on IaC + dev UX. IDE plugin remains the last
adoption-motion gap.

---

## 4. `container_image` — add runtime, keep static parity

### Current state

Static is solid via `scan_container_image` (Trivy-wrapped) + cosign +
SLSA (PR #286) + KEV/EPSS enrichment + KG dependency emission. The
biggest remaining gap on this target type is **runtime** — no CWPP wrap
yet.

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **SBOM diff across image versions**. On rebuild, compare last-known-good SBOM to current; surface introduced CVEs / removed packages / changed pins as a finding category. | S | P1 | Engine already has SBOM extraction (#131); diff is a small CSV-compare layer. |
| ⬜ | **Layer-level provenance attribution**. For each finding, identify which Docker layer introduced the vulnerable package. Surfaces "this CVE was introduced by `RUN apt-get install foo` in layer 7" so the fix is localised. | M | P2 | Aqua-class polish; sells the engine as "actually useful for fixing images, not just flagging them." |
| ⬜ | **Image-attack-path detection** — analog to `cloud_attack_paths` for images: "vulnerable Python package + USER root + Docker socket mounted → container escape path." Reuse the same graph + pattern abstractions. | M | P2 | Mirrors the cloud-attack-path success against the image substrate. |
| ⬜ | **Runtime container audit via Falco rules**. Apache 2.0. Don't build a CWPP; wrap Falco as the runtime-events engine, ingest its alerts, route into the existing finding pipeline. | L | P3 | **The only credible path to runtime coverage** with our wrap-OSS-leaders strategy. Closes the 2/2 runtime score. |
| ⬜ | **Kube-bench wrap** for K8s cluster runtime audit (CIS Kubernetes sections 1-4 we don't cover today; we cover 5.x via manifests). | M | P2 | Complements the K8s static analysis with the live-cluster slice. |
| ⬜ | **Admission controller integration** — emit findings as `AdmissionReview` denials so customers can block deploys on critical container findings. | M | P3 | Mirrors the GitHub Actions integration on the K8s control plane. |

### Expected impact on scoring
Breadth static 8 → 9, runtime 2 → 7. Depth static 8 → 9, runtime 2 → 6.
Agent 7 → 8.
Closes the static gap with Aqua; partial runtime coverage via Falco /
kube-bench wraps without trying to build a full CWPP from scratch.

---

## 5. `cloud_account` — **credible against Wiz at mid-market**

### Current state

The cloud arc (PRs #293–#311) materially closed the Wiz gap. All four
of Wiz's pricing pillars are now at least partially shipped:

- **CSPM** via `cspm/prowler.py` (Prowler-wrapped, AWS + GCP + Azure)
- **Attack-path graph** (`cloud_attack_paths/`) — 27 patterns across all
  three clouds, with live PoC probes verifying exploitability
- **Reachability scoring** (`cloud_attack_paths/reachability.py`) —
  graph-aware "vuln is N hops from public LB" scoring
- **Agentless VM CVE scanning** (`cloud_attack_paths/agentless_scan.py`)
  via Trivy EBS-snapshot mode — auto-snapshot orchestration in #309
- **Multi-account** (`cloud_attack_paths/multi_account.py`) — AWS
  Organizations auto-enumeration + cross-account assume-role chains
- **CDR** (`cloud_attack_paths/cloudtrail_detection.py`) — deterministic
  rule engine on CloudTrail (root use, MFA-less console login, after-
  hours IAM change, bulk S3 GET, AssumeRole from unknown account,
  StopLogging)

What's left is **per-cloud resource-type depth** (Wiz covers 1000+
types; Strix's coverage is narrower per cloud) and **DSPM** (data
security posture management — sensitive data discovery in cloud stores).

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ✅ | **MOAK cloud node types + ingester** — `CloudResource` / `CloudIdentity` / `CloudPolicy` / `NetworkPath` / `TrustEdge` shipped via `cloud_attack_paths/graph.py` (PR #293). | S | P0 | Foundation; landed. |
| ✅ | **Reachability scoring across the cloud graph** — `cloud_attack_paths/reachability.py` (PR #302). | L | P0 | Shipped. Wiz's killer noise-reducer matched. |
| ✅ | **Live PoC probes for cloud attack paths** — `cloud_attack_paths/live_probes.py` (PR #299). Anonymous S3 GET / RDS handshake / SQS SendMessage / Lambda invoke verifications. | M | P0 | Shipped. Same exploit-synthesis moat as web, now on cloud. |
| ✅ | **Expand attack-path patterns** from 5 → **27** (PRs #300, #307). All three clouds: public-storage-creds-risk, internet-exposed-compute-with-IAM, wildcard-admin, world-assumable-role, public-DB, public-secrets-store, public-ECR, external-trust-without-external-id, pass-role-present, can-assume-chain-to-admin, GCP default compute SA, GCP public BigQuery, Azure public blob, Azure owner role, Lambda function URL no-auth, IAM keys no MFA, cross-account S3 share, unused high-priv role, default VPC, secrets-via-env, overpermissive secrets-manager policy, internet-resource-unencrypted, + more. | M | P0 | Shipped (above masterroadmap's 20+ goal). |
| ✅ | **Cloud asset discovery via boto3 / GCP / Azure SDKs** — `cloud_attack_paths/discovery.py` (AWS, PR #301), `azure_discovery.py` (PR #310), `gcp_discovery.py` (PR #311). | M | P1 | Shipped. Graph is now fully populated, not sparse. |
| ✅ | **Multi-account / organisation-wide traversal** — `cloud_attack_paths/multi_account.py` (PRs #304, #308). AWS Organizations auto-enumeration + cross-account `sts:AssumeRole` chain analysis. | M | P1 | Shipped. Enterprise table stakes met. |
| ✅ | **Agentless VM CVE scanning via EBS snapshots** — `cloud_attack_paths/agentless_scan.py` wraps `trivy vm ebs:<snapshot-id>` (PR #305). Auto-snapshot orchestration in PR #309. | XL | P2 | Shipped. **The Wiz moat — matched.** |
| ✅ | **GCP + Azure attack-path patterns** (PR #303) — equivalent pattern set for GCP IAM bindings + Azure RBAC. | M | P1 | Shipped within the 27-pattern set. |
| ✅ | **Cloud Detection & Response (CDR)** — `cloud_attack_paths/cloudtrail_detection.py` (PR #306). Deterministic rule engine (v1 ships rules; ML baseline is v2). | XL | P3 | Shipped. Wiz's newest moat — caught up. |
| ⬜ | **DSPM (Data Security Posture Management)** — sensitive-data discovery in S3 / GCS / Azure Blob / RDS / BigQuery / Snowflake. Sample objects, classify PII/PHI/PCI via regex + ML, attribute back to the resource. | L | P1 | Wiz's fastest-growing 2025-2026 revenue line. We have the graph; this is the data-content layer on top. |
| ⬜ | **Multi-cloud agentless scan parity** — `trivy vm` also supports Azure Disk + GCP disk snapshots. Extend `auto_snapshot.py` to fan out across all three. | M | P2 | Closes the AWS-only-agentless gap. |
| ⬜ | **Cloud workload sensor (eBPF / Falco)** — optional CWPP overlay that complements the agentless flow. Same wrap pattern as Trivy. | XL | P3 | Closes the runtime side of cloud workloads; mirrors the `container_image` runtime gap. |
| ⬜ | **ML-baseline CDR** — graduate from deterministic CloudTrail rules to learned baselines (per-principal time-of-day / source-IP entropy). | L | P3 | Closes the ML-detection gap with Wiz's CDR. v1 deterministic rules already catch the canonical compromise patterns. |
| ⬜ | **Per-cloud resource-type expansion** — broaden discovery to cover the long tail (App Service, ECS Fargate task IAM, EKS service-account bindings, Azure Functions, GCP Cloud Run). Wiz covers 1000+; Strix covers the top ~50 today. | XL | P2 | Long-tail coverage. Each resource type is small-to-medium effort. |

### Expected impact on scoring
Breadth 6 → **8** (achieved). Depth 6 → **7** (achieved). Agent 6 → 8 (cloud is in the agent loop via KG + MOAK).
Wiz still leads on DSPM, per-cloud resource-type depth, and ML-baseline
CDR. We've moved from "Wiz minus" to "Wiz-equivalent capability at
~1/10th the cost on the moats that matter (agentless + reachability +
attack paths + CDR)." DSPM is the next big move.

---

## Cross-target initiatives

### Org-scale (engine-wishlist — **all 8 items shipped, PRs #312–#319**)

| | Item | PR | Status |
|---|---|---|---|
| ✅ | Multi-target batch mode — shared sandbox + LLM context across N targets | #319 | shipped |
| ✅ | Shared Researcher cache across batched scans | #319 | shipped |
| ✅ | `kg_delta.jsonl` — KG deltas as first-class artifact for cross-scan path queries | #318 | shipped |
| ✅ | `STRIX_PROJECT_ID` stamp on findings + discovered assets — cross-target correlation primitive | #317 | shipped |
| ✅ | Target-metadata pass-through into Researcher context | #316 | shipped |
| ✅ | `--profile initial` — fast first-pass scan mode (~2-5 min, ~10% of standard cost) | #315 | shipped |
| ✅ | `assets.discovered.jsonl` emission — wrapper consumes inventory from CSPM specialists | #314 | shipped |
| ✅ | `--skip-if-unchanged` — exit early on quiescent targets via target fingerprinting | #313 | shipped |

Post-arc economics: a 200-target org on daily cadence pays ~3-4× less
per scan than pre-arc (batch mode + Researcher cache compound), and
~95% of quiescent targets exit in <5 seconds via skip-if-unchanged.

### Compliance + audit (continues from §17.6 wrapper wishlist)

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **NIST CSF 2.0** framework catalog. Released 2024; common-denominator framework auditors map to in 2026. | S | P1 | Biggest procurement-unblock for the lowest effort. |
| ⬜ | **SBOM export (CycloneDX + SPDX)**. Already have the data; surfacing in standard formats unlocks every vendor questionnaire. | S | P1 | Same procurement angle. |
| ⬜ | **Vendor questionnaire auto-fill** (SIG-Lite / CAIQ). Map our existing controls + evidence to the questionnaire fields. | L | P2 | Biggest unbillable engineering hours at mid-size orgs. |
| ⬜ | **OWASP MASVS catalog**. Mobile-specific framework. Requires mobile target type first. | S | P3 | Doesn't unlock buyers we already serve. |

### Agent / MOAK / KG depth (Decepticon uplift mostly ✅)

| | Item | PR | Status |
|---|---|---|---|
| ✅ | Fresh-context specialist orchestration (`specialist_orchestrator.py`) | #233 | shipped |
| ✅ | OPPLAN objective state machine (`agents/objective_tracker.py`) | #239 | shipped |
| ✅ | Persistent typed knowledge graph (`agents/knowledge_graph.py` — 7 node + 7 edge types) | #240 | shipped |
| ✅ | 5-stage verification pipeline (`agents/verification_pipeline.py`) | #241 | shipped |
| ✅ | Skills middleware with progressive disclosure | #236 | shipped |
| ✅ | Tiered tool output management | #235 | shipped |
| ✅ | `strix.scope.yml` engagement scope | #238 | shipped |
| ✅ | Model fallback chain from credentials inventory | #237 | shipped |
| ✅ | Patcher runtime + `verify_patch` (EXPLOITED → PATCHED) | #243 | shipped |
| ✅ | KG specialist adoption (scan_sqli + scan_xss populate Vuln + Surface + AFFECTS) | #242 | shipped |
| ⬜ | **MOAK applied to cloud** — agent-loop reasoning over cloud attack paths ("write the STS-assume → S3-get sequence and execute"). KG + attack-path graph are in place; the agent loop needs to consume them as planning substrate. | L | P0 | Universalises the moat that we already win on web. |
| ⬜ | **Cross-asset KG queries** — "show me findings that share a credential across repo / cloud / container". Engine emits `kg_delta.jsonl` (PR #318); the wrapper's KG store consumes deltas. Cross-asset graph queries are the wrapper-side build. | M | P1 | Justifies the unified-tool positioning vs. point solutions. |
| ⬜ | **Active hypothesis live-view** (engine §138). Show the agent's open hypotheses + self-audit verdicts in the live view. | M | P2 | Demystifies the pipeline. Engineers buy when they understand the reasoning. |
| ⬜ | **RLHF FP feedback loop scaling** (engine §142, partial). Wrapper has the labeler queue; engine ingests via `--feedback-from`. Scale-test against 10k+ findings. Design lives at [`docs/rlhf-design.md`](docs/rlhf-design.md). | L | P1 | Closes the FP-reduction gap with Snyk's mature pipeline. |

### Mobile (new target type — out of current scope but on the horizon)

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **APK / IPA static analysis** wrap of MobSF (Apache 2.0). Manifest audit + permission analysis + secret scan in compiled binaries. | XL | P3 | Required for HIPAA + most SOC 2 if the customer ships mobile. Currently absent from the product. |

### Wrapper-side adoption levers (links into webappsec/wrapper-wishlist.md §17-§18)

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **PR comment bot** — render diff-aware findings inline on GitHub / GitLab PRs. | M | P0 | The way Snyk wins developers. Without this, "diff-aware scanning" is invisible. |
| ⬜ | **VS Code plugin** (continues §3). | L | P1 | Shift-left to the editor. |
| ⬜ | **Slack / Jira native integrations** beyond webhooks. | M | P2 | Operator-routing. |
| ⬜ | **Auto-fix PR composer** — drives patcher output (PR #243) into a real `gh pr create` flow. | M | P0 | Last-mile delivery for the patcher runtime that already ships. |

---

## Top-5 priorities (refreshed 2026-05)

The items below are the highest-leverage moves remaining now that the
cloud arc + engine-wishlist arc + web specialist arc have all landed:

1. **Wrap Checkov for IaC** (§3 P0, M) — single biggest leverage move
   left in the product. Takes IaC breadth from 5 → 8 / depth from 5 → 9
   overnight. Same pattern that worked for CSPM (Prowler wrap).
2. **Diff-aware scanning at route granularity** (§1 + §3 P0, M) — the
   only §1 item still open. Engine has scope-mode `diff`; needs
   route-level filtering via `code_map`. Dev-adoption lever everything
   else hinges on.
3. **MOAK applied to cloud** (§5/agent depth P0, L) — KG + 27 attack
   patterns + reachability are in place; the agent loop needs to
   consume them as planning substrate so it produces verified
   cross-resource exploit chains the way it already does on web.
4. **Auto-fix PR composer + PR comment bot** (wrapper P0, M + M) —
   last-mile delivery for the patcher runtime (PR #243) and diff-aware
   scanning. Without these, the data + verification loop are invisible
   to developers.
5. **DSPM (data security posture)** (§5 P1, L) — Wiz's fastest-growing
   2025-2026 revenue line. We have the cloud graph and the asset
   discovery; this is the data-content layer on top (sample S3 / GCS /
   Azure Blob / BigQuery, classify PII/PHI/PCI, attribute back).

Stretch picks (5-10):

6. **Multi-language SCA reachability** (§3 P0, XL) — extend taint beyond
   Python to JS/TS, Go, Java, Ruby, PHP, C#.
7. **JS bundle endpoint extraction + OpenAPI delta** (§2 P1, M+S) —
   closes the runtime-discovery half of the Akto gap without shipping
   eBPF infrastructure.
8. **VS Code + JetBrains IDE plugin** (§3 P1, L) — Snyk's adoption motion.
9. **Falco wrap for container runtime** (§4 P3, L) — only credible path
   to a non-2/2 runtime score on `container_image`.
10. **NIST CSF 2.0 + SBOM export** (compliance P1, S+S) — biggest
    procurement-unblock for lowest effort.

---

## Prioritisation buckets

### P0 — ship next (this month)

1. **Checkov wrap** (§3) — instant 20× IaC rule corpus.
2. **Diff-aware scanning at route granularity** (§1, §3) — last §1 hole.
3. **MOAK applied to cloud** (§5, agent depth) — universalises the moat.
4. **Auto-fix PR composer + PR comment bot** (wrapper) — last-mile.
5. **Multi-language SCA reachability** (§3) — closes the Snyk depth gap on the
   languages that produce most CVE noise.

### P1 — ship this quarter

DSPM (§5) · JS bundle endpoint extraction · OpenAPI delta · VS Code plugin ·
CloudFormation/Pulumi parsers · SBOM diff · cross-asset KG queries (wrapper
side) · RLHF scale-test · NIST CSF 2.0 · SBOM export · SPA auth-flow replay
maturity · multi-cloud agentless parity (Azure + GCP).

### P2 — ship this half

OAuth scope-creep · gRPC fuzz · layer-level container provenance · image
attack paths · kube-bench wrap · vendor questionnaire auto-fill · active
hypothesis live-view · per-cloud resource-type expansion (Wiz long-tail).

### P3 — research / opportunistic

Runtime traffic mirroring (eBPF / Envoy) · Falco runtime wrap · ML-baseline
CDR · OWASP MASVS · APK/IPA mobile target · cloud workload sensor.

---

## Expected positioning after P0+P1 land

| Target | Today | After P0 | After P0+P1 |
|---|---|---|---|
| `web_application` | Co-leader (br 9 / dp 8) | Leader | Leader |
| `api` | Competitive (br 8 / dp 7) | Leader for declared APIs | Leader (declared + JS-bundle + delta) |
| `repository` (SAST+SCA) | Competitive (br 7 / dp 7) | Leader on covered langs | Leader incl. multi-lang reachability |
| `repository` (IaC) | Behind (br 5 / dp 5) | At parity (Checkov wrap) | Leader on IaC depth via wrapped engines |
| `container_image` static | At parity (br 8 / dp 8) | At parity | Leader on supply chain (SBOM diff + provenance) |
| `container_image` runtime | Absent (br 2 / dp 2) | Absent | Partial (Falco wrap = P3) |
| `cloud_account` | Credible (br 8 / dp 7) | + DSPM | Wiz-equivalent except long-tail resources |
| `domain` (external) | Leader (br 9 / dp 8) | Leader | Leader |
| Cross-target | Co-leader (br 8 / dp 8) | Leader (MOAK-on-cloud + wrapper KG) | Leader |
| Org-scale | Improving (br 7 / dp 6) | + dev-adoption levers | Co-leader |
| Mobile | Absent | Absent | Absent (P3 push) |

**One-line summary**: post-cloud-arc + post-engine-wishlist, the agent +
MOAK + KG moat is **decisive on the targets we already lead** and
**credible on the ones we trail**. The remaining P0 list is 4 large +
4 medium PRs to take us from "credible alternative to Wiz/Snyk/Burp" to
"deliberate choice at mid-market in every category except mobile +
container runtime."

---

## Reference

- [`roadmap.md`](roadmap.md) — engine standing roadmap (granular PR-level items).
- [`AISecurityEngineer.md`](AISecurityEngineer.md) — product mission.
- [`AISecurityEngineerUX.md`](AISecurityEngineerUX.md) — UX north star.
- [webappsec `wrapper-wishlist.md` §17–§18](../webappsec/wrapper-wishlist.md) — wrapper-side polish for the engine arc that already shipped.
- [strix PRs #270–#294](https://github.com/ClatTribe/strix/pulls?q=is%3Apr+is%3Amerged) — the engine arc this roadmap builds on.
