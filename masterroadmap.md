# Master Roadmap — strix engine + webappsec wrapper

Per-target competitive assessment + proposed work to close the highest-
leverage gaps. Read alongside [`roadmap.md`](roadmap.md) (engine items
already prioritised on the standing roadmap) and the
[wrapper-wishlist](../webappsec/wrapper-wishlist.md) (wrapper-side polish
for what the engine already ships).

This doc is the **honest competitive view** — what we're good at, what
we're not, and what to build next to close the deltas that actually lose
deals. Not a marketing brief.

---

## TL;DR positioning

We are **a strong #2 in web + API** where agent reasoning + exploit
synthesis matter, **at parity on static container scanning**, **trailing
in repo (IaC depth)** and **trailing in cloud (reachability + runtime)**.

The MOAK + agent moat is real and unique; it does not yet close the
breadth gap against category leaders. Today we're positioned as a
*credible alternative* — the proposed work in this doc upgrades that to
*deliberate choice* for the mid-market segment we already win and
*credible alternative* for the enterprise segments we currently can't.

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

| Target | Coverage | Depth | Agent | Top competitor | Position |
|---|---|---|---|---|---|
| `web_application` | 7 | 8 | 9 | Burp Suite Enterprise | Close 2nd — coverage gap |
| `api` | 8 | 8 | 8 | Akto.io | Competitive — discovery gap |
| `repository` | 7 | 7 | 9 | Snyk (Code + SCA + IaC) | Behind on IaC depth + dev UX |
| `container_image` static | 8 | 8 | 7 | Aqua Security | At parity on static |
| `container_image` runtime | 4 | 4 | — | Aqua / Sysdig | Absent (no CWPP) |
| `cloud_account` | 6 | 6 | 6 | Wiz | Behind across the board |

---

## 1. `web_application` — close the coverage gap vs. Burp

### Current state

Strong on agent + verified exploits (MOAK Phase B3 live-probe lands a
working PoC against production). Coverage breadth is the gap: we miss
the attack classes that hit modern frontends + edge infrastructure.

### Proposed changes (P0 → P3)

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ✅ | **HTTP request smuggling detector** (CL.TE / TE.TE / TE.CL / TE.0). Single specialist that walks the canonical desync probe matrix. Shipped: `scan_request_smuggling_active`. | M | P0 | Highest-impact missing category for any org with a CDN / proxy / load balancer in front of their app. Burp's flagship feature. |
| ✅ | **Web cache poisoning + cache deception** detector. Shipped: `scan_cache_deception`. | M | P0 | Increasingly common attack class. |
| ✅ | **Server-side prototype pollution** detector. Shipped: `scan_prototype_pollution`. | M | P1 | Node ecosystem ubiquitous. |
| 🚧 | **OAuth / OIDC / SAML deep flow analyzer**. OAuth + OIDC shipped (`scan_oauth`). JWT alg-confusion shipped (`tools/jwt_audit`). **Still open**: SAML signature wrapping (XSW variants) — no specialist today. | L | P0 | Common audit-failure point. SAML still a gap. |
| ✅ | **WebSocket / SSE auth probe**. Shipped: `scan_websocket_auth`. | M | P1 | Modern apps universally have these endpoints. |
| ✅ | **Race condition / TOCTOU** detector — repeat-fire requests with timing variance against state-changing endpoints (transfer / coupon-apply / checkout). Shipped: `scan_race_condition` — baseline + N-parallel-fire + success-rate classification + dotted-path JSON field extraction. | L | P2 | Business-logic attack class hardly anyone covers. Differentiator. |
| 🚧 | **Diff-aware scanning** — scan only the routes a PR changes. Engine already has scope-mode `diff`; needs route-level granularity. | M | P0 | Single biggest determinant of developer adoption per the comparison. Dev mutes the bot otherwise. |

### Expected impact on scoring
Coverage 7 → 9. Depth 8 → 8. Agent 9 → 9.
Closes the gap with Burp on coverage; agent moat stays.

---

## 2. `api` — close the discovery gap vs. Akto

### Current state

Schema-aware mass-assignment + 3-variant BOLA + GraphQL + gRPC + 29-cohort
SSRF are at parity with Akto on declared APIs. The gap is **runtime API
discovery** — Akto's whole sell is "we find APIs you don't know exist by
inspecting traffic."

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **HAR / Burp project ingestion → API surface map**. Operator uploads recorded traffic; engine extracts endpoints + parameter shapes + auth context; surface map drives the subsequent scan. | M | P0 | Closest we can get to traffic-mirror without a runtime agent. Engine PR #141 (per wrapper-wishlist) already roadmapped — bump priority. |
| ⬜ | **JS bundle endpoint extraction**. Parse compiled JS for fetch / axios / XHR call sites; extract URL patterns; seed the surface map. | M | P1 | Catches endpoints OpenAPI doesn't document. Standalone PR. |
| ⬜ | **OpenAPI delta detector**. On scheduled scan: compare today's OpenAPI to last week's; surface added/removed/changed endpoints as a finding category. | S | P1 | Akto's "runtime API change detection" without runtime — schedule-based instead. |
| ⬜ | **JWT alg-confusion deep probe**. Test `alg=none`, RS256↔HS256 confusion, kid path traversal, embedded JWK. | S | P0 | Specific recurring vuln; one rule covers a high-CVSS class. |
| ⬜ | **OAuth scope-creep detector**. Compare claimed scopes vs. accessible endpoints under each scope's token. | M | P2 | Real-world misconfig common at SaaS APIs. |
| ⬜ | **gRPC server-reflection + fuzz**. Reflection ✓; fuzzing the discovered methods is next. | M | P2 | We discover gRPC services; we don't yet attack them. |

### Expected impact on scoring
Coverage 8 → 9. Depth 8 → 9. Agent 8 → 8.
Closes the discovery gap; brings parity-or-better with Akto on declared+discovered API surface.

---

## 3. `repository` — close the IaC + dev-UX gap vs. Snyk

### Current state

SAST + secrets + SCA + Dockerfile + IaC drift correlation are competitive.
The gap is **IaC rule corpus** (Checkov has 1000+; we ship ~20) and
**developer UX** (no diff-aware, no IDE plugin).

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **Wrap Checkov as IaC primary engine**. Same pattern as Trivy / Prowler — subprocess wrapper, normalise JSON to `IacFinding`, keep built-in rules as fallback. Instantly adds 1000+ TF + 400+ K8s + 200+ CloudFormation + 100+ Helm rules. Apache 2.0. | M | P0 | Single biggest leverage move in this section. Mirrors the strategy that worked for CSPM (Prowler wrap). Eliminates the IaC depth gap overnight. |
| ⬜ | **Wrap kics** as the secondary IaC engine (Rego rules). Lets us union Checkov + kics for breadth + cross-validation. | S | P2 | Free addition once Checkov wrap exists. |
| ⬜ | **Diff-aware scanning** (shared with §1). | M | P0 | Same item as web side; cross-target. |
| ⬜ | **VS Code + JetBrains IDE plugin**. Inline finding render; one-click "open in strix dashboard." | L | P1 | Snyk's adoption motion. Need this for any chance of organic dev pull. |
| ⬜ | **Auto-fix PRs for high-confidence findings**. Bump deps (`bump-my-version`-style), add SRI to script tags, add missing security headers, fix common Dockerfile issues. Wraps existing finding+remediation into a `gh pr create` flow. | L | P1 | Single biggest developer-time saver. We have the data; the lift is the auto-PR composer. |
| ⬜ | **CloudFormation / Pulumi / CDK parsers**. Parallel to existing Terraform/K8s/Helm parsers. | M | P2 | Closes the IaC framework coverage gap (most large orgs use one of these alongside or instead of TF). |
| ⬜ | **Reachability scoring for SCA**. Already on the standing roadmap (§99). Bump priority. | L | P0 | "This CVE is in your lockfile but not in your import graph" — the single biggest noise-reducer for SCA. Snyk's recent moat. |

### Expected impact on scoring
Coverage 7 → 9. Depth 7 → 9 (IaC depth jumps from 5 to 9). Agent 9 → 9.
Closes the Snyk gap on IaC + dev UX. Leaves IDE plugin as the last
adoption-motion gap.

---

## 4. `container_image` — add runtime, keep static parity

### Current state

Static is solid via Trivy + cosign + SLSA. The gap is **runtime** —
nothing today.

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **SBOM diff across image versions**. On rebuild: compare last-known-good SBOM to current; surface introduced CVEs / removed packages / changed pins as a finding category. | S | P1 | Engine already has SBOM extraction (#131); diff is a small CSV-compare layer. |
| ⬜ | **Layer-level provenance attribution**. For each finding, identify which Docker layer introduced the vulnerable package. Surfaces "this CVE was introduced by `RUN apt-get install foo` in layer 7" so the fix is localised. | M | P2 | Aqua-class polish; sells the engine as "actually useful for fixing images, not just flagging them." |
| ⬜ | **Image-attack-path detection** — analog to cloud attack paths #293 for images: "vulnerable Python package + USER root + Docker socket mounted → container escape path." | M | P2 | Mirrors the cloud-attack-path success against the image substrate. |
| ⬜ | **Runtime container audit via Falco rules**. Apache 2.0. Don't build a CWPP; wrap Falco as the runtime-events engine, ingest its alerts, route into the existing finding pipeline. | L | P3 | Closes the runtime gap with the same "wrap an OSS leader" pattern Trivy/Prowler proved. |
| ⬜ | **Kube-bench wrap** for K8s cluster runtime audit (CIS Kubernetes sections 1-4 we don't cover today; we cover 5.x via manifests). | M | P2 | Complements the K8s static analysis with the live-cluster slice. |

### Expected impact on scoring
Coverage static 8 → 9, runtime 4 → 7. Depth static 8 → 9, runtime 4 → 6.
Agent 7 → 8.
Closes the static gap with Aqua; partial runtime coverage via Falco/
kube-bench wraps without trying to build a full CWPP from scratch.

---

## 5. `cloud_account` — close the reachability + runtime gap vs. Wiz

### Current state

CSPM (via Prowler) + drift correlation + 5 attack-path patterns. Per the
last analysis, the four pillars that justify Wiz's pricing are:
**agentless VM CVE scanning, reachability scoring, multi-account org-wide,
cloud workload protection (CWPP)**. We have none of these.

### Proposed changes

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **MOAK cloud node types + ingester** — extend the KG with `CloudResource` / `CloudIdentity` / `CloudPolicy` / `NetworkPath` / `TrustEdge` node types. The graph layer already exists (#293); this plumbs it into the main KG so cross-asset queries work. | S | P0 | Foundation for everything below. Already designed in the §17 wishlist. |
| ⬜ | **Reachability scoring across the cloud graph**. Plug cloud edges into the existing §99 reachability scorer. "This vuln is on a VM 3 hops from a public LB" matters more than "this vuln is on an isolated bastion." | L | P0 | Wiz's killer noise-reducer. Single biggest competitive move we can make in this segment. |
| ⬜ | **Live PoC probes for cloud attack paths** — anonymous S3 GET / RDS TCP handshake / SQS SendMessage / Lambda invoke. Verify exploitability of the toxic combinations the graph detects. | M | P0 | Distinguishes "we say this is exploitable" from "we proved it." Same exploit-synthesis moat we have on web, now on cloud. |
| ⬜ | **Expand attack-path patterns** from 5 → 20+. Cover privilege-escalation chains, cross-account confused-deputy patterns, secrets-in-S3-keys variant, Lambda function URL escalation, etc. | M | P0 | 5 patterns is the MVP; Wiz ships dozens. Each pattern is ~50 LOC of graph traversal. |
| ⬜ | **Cloud asset discovery via Prowler enumeration / boto3** — fuller graph without requiring caller-supplied `cloud_assets`. Today the graph is sparse (only resources that triggered checks). | M | P1 | Without this, attack-path detection misses every resource that wasn't already flagged. |
| ⬜ | **Multi-account / organisation-wide traversal**. Single-scan-many-accounts via AWS Organizations; cross-account `sts:AssumeRole` chain analysis. | M | P1 | Enterprise table stakes. |
| ⬜ | **Agentless VM CVE scanning via EBS snapshots**. The Wiz moat. Snapshot every EBS volume in the account, mount read-only, run Trivy filesystem scan, attribute CVEs to running EC2 instances. Apache 2.0 prior art exists. | XL | P2 | The single highest-leverage but heaviest-lift item. Worth it because it reframes the whole CNAPP positioning. |
| ⬜ | **GCP + Azure attack-path patterns**. Today's 5 patterns are AWS-shaped; equivalent set for GCP IAM bindings + Azure RBAC. | M | P1 | Free coverage extension since Prowler already gives us GCP/Azure findings. |
| ⬜ | **Cloud Detection & Response (CDR)** — ingest CloudTrail / Activity Log / Audit Log streams, run anomaly detection, surface "this IAM role was assumed from a new geo" as findings. | XL | P3 | Wiz's newest moat. Furthest from our current capability. |

### Expected impact on scoring
Coverage 6 → 8. Depth 6 → 8. Agent 6 → 9 (cloud joins the agent loop properly).
Doesn't fully close Wiz — they keep agentless VM scanning + runtime — but
**re-prices the deal**. We become "Wiz capability for 1/10th the cost"
instead of "Wiz minus."

---

## Cross-target initiatives

### Compliance + audit (continues from §17.6 wrapper wishlist)

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **NIST CSF 2.0** framework catalog. Released 2024; common-denominator framework auditors map to in 2026. | S | P1 | Biggest procurement-unblock for the lowest effort. |
| ⬜ | **SBOM export (CycloneDX + SPDX)**. Already have the data; surfacing in standard formats unlocks every vendor questionnaire. | S | P1 | Same procurement angle. |
| ⬜ | **Vendor questionnaire auto-fill** (SIG-Lite / CAIQ). Map our existing controls + evidence to the questionnaire fields. | L | P2 | Biggest unbillable engineering hours at mid-size orgs. |
| ⬜ | **OWASP MASVS catalog**. Mobile-specific framework. Requires mobile target type first. | S | P3 | Doesn't unlock buyers we already serve. |

### Agent / MOAK depth

| | Item | Effort | Priority | Why it matters |
|---|---|---|---|---|
| ⬜ | **MOAK applied to cloud** (cross-references §5). Apply the same agent-loop reasoning that produces web/API exploit PoCs to cloud attack paths — "given this 4-hop chain, write the actual STS-assume → S3-get sequence and execute." | L | P0 | Universalises the moat that we already win on web. |
| ⬜ | **Cross-asset KG queries** — "show me findings that share a credential across repo / cloud / container" — already the design intent; needs the cross-asset edges from the cloud KG work. | M | P1 | Justifies the unified-tool positioning vs. point solutions. |
| ⬜ | **Active hypothesis tracking** (engine §138). Show the agent's open hypotheses + self-audit verdicts in the live view. | M | P2 | Demystifies the pipeline. Engineers buy when they understand the reasoning. |
| ⬜ | **RLHF FP feedback loop scaling** (engine §142, partial). The wrapper has the labeler queue; the engine ingests via `--feedback-from`. Scale-test against 10k+ findings. | L | P1 | Closes the FP-reduction gap with Snyk's mature pipeline. |

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

---

## Prioritisation buckets

### P0 — ship next (this month)

The items that turn current losses into wins quickly:

1. **Checkov wrap** (§3) — instant 50× IaC rule corpus.
2. **HTTP request smuggling + cache poisoning + OAuth deep** (§1) — covers the three biggest web coverage gaps.
3. **MOAK cloud node types + reachability scoring + live PoC probes + 20+ attack patterns** (§5) — turns cloud from "competitive at SMB" to "credible against Wiz at mid-market."
4. **HAR / Burp ingestion + JWT alg-confusion** (§2) — closes Akto's discovery moat.
5. **Diff-aware scanning + PR comment bot** (§1, §3, wrapper) — the dev-adoption lever the whole product hinges on.

### P1 — ship this quarter

NIST CSF 2.0 catalog · SBOM export · VS Code plugin · auto-fix PRs · OpenAPI delta · JS bundle endpoint extraction · GCP+Azure attack-path patterns · cloud multi-account · CloudFormation/Pulumi parsers · SBOM diff · MOAK applied to cloud · cross-asset KG queries · RLHF scale-test.

### P2 — ship this half

Race condition detector · WebSocket auth · OAuth scope-creep · gRPC fuzz · layer-level provenance · image attack paths · kube-bench wrap · vendor questionnaire auto-fill · active hypothesis tracking.

### P3 — research / opportunistic

Agentless VM CVE scanning · Cloud Detection & Response · Falco runtime wrap · OWASP MASVS · APK/IPA mobile target.

---

## Expected positioning after P0+P1 land

| Target | Today | After P0 | After P0+P1 |
|---|---|---|---|
| `web_application` | Close 2nd (cov 7) | Leader (cov 9) | Leader |
| `api` | Competitive | Leader for declared+discovered APIs | Leader |
| `repository` | Behind (IaC) | At parity with Snyk on IaC | Leader on IaC depth via wrapped engines |
| `container_image` static | At parity | At parity | Leader on supply chain (cosign + SLSA + SBOM diff) |
| `cloud_account` | Behind | Credible against Wiz at mid-market | Wiz-equivalent except agentless VM scan |
| Mobile | Absent | Absent | Absent (P3 push) |

**One-line summary**: the agent + MOAK moat is *positional* today and
*decisive* after P0 lands. P0 is roughly **4 large + 6 medium PRs**.

---

## Reference

- [`roadmap.md`](roadmap.md) — engine standing roadmap (granular PR-level items).
- [`AISecurityEngineer.md`](AISecurityEngineer.md) — product mission.
- [`AISecurityEngineerUX.md`](AISecurityEngineerUX.md) — UX north star.
- [webappsec `wrapper-wishlist.md` §17–§18](../webappsec/wrapper-wishlist.md) — wrapper-side polish for the engine arc that already shipped.
- [strix PRs #270–#294](https://github.com/ClatTribe/strix/pulls?q=is%3Apr+is%3Amerged) — the engine arc this roadmap builds on.
