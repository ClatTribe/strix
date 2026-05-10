# AI Security Engineer — Wrapper (webappsec) UX Roadmap

This document covers the **product surface** that vibe-coded-app companies log
into. The wrapper lives in `../webappsec/`; this doc tracks features it needs
to expose strix's engine capabilities (documented in
[`AISecurityEngineer.md`](./AISecurityEngineer.md)) to paying customers.

> **Audience**: contributors to `webappsec/`. The phases below are
> customer-visible product features. Engine technical capabilities are out of
> scope here — they live in the engine roadmap.

---

## 1. Vision

> A founder using Cursor to ship a SaaS app should be able to install our
> GitHub App, point it at their repo + production URL, and get:
>
> - **Inline PR comments** every push
> - **A weekly digest** of what changed in their dependency CVE risk
> - **A SOC 2 evidence pack** ready for their auditor
> - **A customer-facing trust page** they can link from their security site
> - **Slack alerts** when production drifts from baseline
>
> All without ever opening a terminal or reading a finding JSON file.

The wrapper is the *experience*; strix is the *engine*. The wrapper must hide
the engine's complexity (specialists, hypotheses, decision logs) and surface
only what a non-security-engineer founder needs to act on.

---

## 2. Personas

### Persona 1 — **Founder/CTO of a vibe-coded SaaS** (primary)
- Building a Next.js SaaS with Cursor + v0
- Team of 1–10
- No dedicated security engineer
- Will pay for SOC 2 (it's a customer requirement)
- Doesn't want to read CVSS vectors
- Lives in GitHub PRs, Slack, and Linear

### Persona 2 — **Growth-stage AppSec engineer** (secondary)
- 50–500 person company that hires their first AppSec engineer
- Reports to CTO or CISO
- Replaces Snyk/Aikido with us
- Wants per-team metrics, fix-rate dashboards, SLA tracking
- Cares about engine internals, not just findings

### Persona 3 — **Compliance/audit lead** (tertiary)
- Maps findings to SOC 2 / ISO controls
- Signs off on auditor-ready evidence packs
- Manages remediation SLAs
- Lives in Vanta/Drata today; we replace them

The wrapper UX must serve all three but **default to Persona 1's mental model**.

---

## 3. Current state of `webappsec/`

> **TODO** for the next webappsec contributor: enumerate what's currently
> built. As of this doc's writing the wrapper exists as a placeholder; the
> phases below assume a near-greenfield UX build.

The wrapper today (rough understanding):
- Backend: TBD framework
- Frontend: TBD
- Auth: TBD (Auth0 / Clerk / WorkOS likely — needs SSO for Persona 2/3)
- Multi-tenant org: TBD
- DB: TBD

Subsequent sections assume a clean slate; if pieces already exist, treat
them as Phase A's starting state.

---

## 4. Core principles

These apply across every wrapper phase:

1. **Hide engine internals from Persona 1**. Specialists, decision logs,
   hypothesis IDs — these are debug artifacts, not customer-facing.
2. **PR-comment first, dashboard second**. Vibe coders live in GitHub; the
   wrapper needs to be where they are.
3. **Severity calibrated for the customer**. Not all CVSS-9 are equal.
   Use Phase 5.3 counter-example data to learn what each customer ignores.
4. **Compliance is a tag, not a separate product**. Every finding is auto-
   tagged with SOC 2 / ISO controls; the compliance dashboard is just a
   filtered view of the existing findings.
5. **Auto-fix where safe, suggest otherwise**. Pixee/Snyk DeepCode-style
   "Apply Fix" PR is the primary remediation path.
6. **Trust by default**. Per-customer data isolation is non-negotiable;
   privacy review gates cross-customer features.
7. **Fast onboarding**. Time-to-first-finding < 5 minutes from signup.

---

## 5. Phase A — Onboarding + GitHub App (foundational)

**Goal**: a founder signs up, installs the GitHub App, and sees their first
finding inline on a PR within 5 minutes.

### Why first
- Without this, we have no UX. Strix is a CLI scanner.
- PR-comment is the single highest-value product surface for the primary
  persona.
- Every subsequent phase assumes the install + repo-connection flow exists.

### Items

#### A.1. Sign-up + auth flow
- Email magic link OR Google OAuth (founders dislike passwords)
- Optional: Microsoft / GitHub OAuth for SSO-required customers
- WorkOS or Clerk for SSO; SAML for enterprise tier later
- Multi-tenant org structure: user → org → repos

#### A.2. GitHub App
- One-click install from a "Connect GitHub" button
- Required permissions:
  - Pull requests: read + write (for PR comments)
  - Contents: read (for repo cloning)
  - Issues: write (for issue creation)
  - Checks: write (for PR-check status)
  - Metadata: read
- Webhook subscriptions: `pull_request`, `push`, `issues`,
  `installation_repositories`
- GitHub App handles billing identity (per-installation pricing)

#### A.3. First-scan trigger
- On `installation` webhook: enqueue initial scan of default branch
- Workflow:
  1. Clone repo to ephemeral storage
  2. Trigger engine: SCA (Phase 6) + SAST (Phase 7) + secrets scan
  3. Stream progress to dashboard via WebSocket
  4. Render findings in-dashboard within 60 seconds
- Skip DAST on initial scan (no production URL captured yet)

#### A.4. Production URL capture
- Onboarding step 2: "What's your production URL?"
- Validates URL is reachable
- Triggers DAST baseline (Phase 9 behavioural baseline + initial specialist
  sweep)
- Schedules recurring scans (default: every 24h)

#### A.5. PR-comment renderer
- On `pull_request` webhook (opened / synchronize):
  1. Get diff via GitHub API
  2. Trigger engine in diff-aware mode (Phase 6.4 / 7.3)
  3. Render new findings as inline PR comments
  4. Render summary as a "Check Run" with status (success/neutral/failure)
- Comment template:
  ```
  ⚠️ **strix found a security issue** (severity: HIGH, CWE-89)
  
  **SQL injection in `req.query.id`** at `pages/api/users.ts:34`
  
  This finding came from: SAST (Semgrep rule sql-injection-express)
  
  **Recommended fix**: parameterize the query
  [Apply Fix] (button — opens auto-fix PR via Phase 12)
  
  See full details: <link to dashboard>
  ```

#### A.6. Dashboard skeleton
- Findings inbox (default view)
- Filters: severity, finding type, repo, branch, status
- Sort: by severity, then by age
- Bulk actions: dismiss, mark fixed, snooze
- Search: full-text + structured

#### A.7. Onboarding UX flow
1. Sign up (email + magic link)
2. Create org (name + size dropdown)
3. Install GitHub App (one click)
4. Select repos to scan (default: all)
5. Capture production URL (optional, can skip)
6. First scan runs (60s) — show progress
7. Findings dashboard

Time-to-first-finding target: < 5 minutes.

### Phase effort
~12 weeks for a small team. ~15,000 LOC across frontend + backend.

### Success criteria
- Onboarding completion rate > 80%
- 90% of new orgs see ≥1 finding within 24 hours
- PR-comment latency < 60s (from webhook to comment posted)

### Engine dependency
- Phase 6 (SCA) shipped + emitting `sca_inventory.json`
- Phase 7 (SAST) shipped + emitting `sast_findings.json` (SARIF)
- Existing Phase 5.5 replay-mutation orchestrator for diff-aware scans

---

## 6. Phase B — Findings inbox + triage UX

**Goal**: customers spend < 1 minute per finding to triage; false-positive
rate < 10% as measured by customer dismissal-rate.

### Why
- Phase A's findings inbox is a crude list. Real triage UX is the difference
  between "useful product" and "noise generator."
- Phase 5.3 counter-example logging needs a UI for customers to mark FPs.

### Items

#### B.1. Severity calibration
- Per-finding card displays:
  - Severity (with CVSS-vector tooltip)
  - Reachability (Phase 6.4 reach analysis result)
  - "Why critical?" prose generated from finding's reasoning_trace
  - Affected file/endpoint with code snippet
  - Linked CVE/CWE
- Severity adjustable by customer (with reason logged → Phase 5.3 telemetry)

#### B.2. Bulk triage actions
- "Dismiss all CWE-X in repo Y" → bulk operation with audit log
- "These are all from generated code" → contextual dismissal
- "Snooze for 30 days" → re-surface after period
- "Assign to teammate" → routes to email/Slack DM

#### B.3. False-positive learning
- When customer dismisses with reason, log to Phase 5.3 misses corpus
- Wrapper-side: surface a "Recently dismissed" view so customers can audit
  their own dismissals
- After 5 dismissals of similar findings, prompt: "Want to auto-dismiss
  future X?" → creates per-customer suppression rule
- Display per-finding: "we saw 5 similar findings; you dismissed 4. Auto-
  dismissed."

#### B.4. Finding lifecycle
- States: `open → triaged → in-progress → fixed → closed` (or `dismissed`)
- Auto-transition: `fixed` when next scan no longer reproduces the finding
- SLA tracking per state (configurable by org)
- Historical view: "this finding was open from 2024-01-15 to 2024-02-03"

#### B.5. Per-finding evidence trail
- Show the engine's reasoning (decision_log walk for this finding)
- Render the chain (Phase 5.2 chaining graph): "this XSS + this CSRF =
  exploit chain"
- Render the PoC (auto-generated cURL command)
- "Verify finding" button → re-runs the specialist that produced it

#### B.6. Per-team / per-repo views
- Persona 2 wants metrics: findings/team, fix-rate/repo, MTTR per severity
- Filter findings by team membership (via GitHub team mapping)
- Per-repo trend chart: open findings over time

#### B.7. Triage shortcuts
- Keyboard navigation (j/k for next/prev, d for dismiss, f for fix)
- Persona 2 lives in the inbox; keyboard-shortcut speed matters

### Phase effort
~8 weeks. ~8,000 LOC.

### Success criteria
- Median triage time < 60s (telemetry on time-from-load to action)
- Customer-reported FP rate < 10%
- ≥80% of dismissed findings have a reason captured

### Engine dependency
- `decision_log.jsonl` (Phase 1.6) — for reasoning trace rendering
- `specialist_misses.jsonl` (Phase 5.3) — for FP learning
- Phase 5.2 chaining graph artifact

---

## 7. Phase C — Compliance layer (SOC 2 / ISO / HIPAA)

**Goal**: replace Vanta/Drata for security-finding evidence collection.

### Why
- Customer's explicit ask
- Vanta makes $200M+ ARR doing this; clear willingness-to-pay
- Differentiator: our findings ARE compliance evidence (not separate)
- Fast path to enterprise revenue (compliance gates SaaS deals > $50K)

### Items

#### C.1. Control mapping
- Every finding auto-tagged with SOC 2 controls:
  - SQLi → CC6.1 (logical access)
  - Hardcoded secret → CC6.7 (encryption)
  - Missing authz → CC6.1, CC6.3
  - SSRF → CC6.6 (boundary protection)
  - Stale dependency → CC7.1 (system monitoring)
- Mappings live in `wrapper/compliance/control_mappings.yaml`
- Cover: SOC 2 Type 1/2, ISO 27001, HIPAA, PCI-DSS, GDPR
- AI-act tags for LLM-feature findings (Phase 8)

#### C.2. Compliance dashboard
- Per-framework view: "SOC 2 status"
- Per-control: pass/fail/in-progress with evidence count
- Quick-glance: "12 controls failing" with click-through to findings
- Filter by audit period (last 12 months for SOC 2 Type 2)

#### C.3. Evidence pack generator
- One-click "Generate auditor pack" → PDF / Markdown / DOCX
- Contains:
  - Executive summary
  - Per-control evidence (findings, scan logs, remediation history)
  - Continuous monitoring proof (Phase 13.4 daemon logs)
  - Auditor-relevant config snapshots (IaC posture from Phase 11)
- Audit-trail JSONL with cryptographic hash chain
  ("prove this scan happened on this date and wasn't tampered with")

#### C.4. Remediation SLAs
- Per-severity SLAs (configurable per org):
  - Critical: 7 days
  - High: 30 days
  - Medium: 90 days
- Auto-track time-in-state per finding
- Slack alerts at 75% / 100% SLA breach
- SLA dashboard for Persona 3 (compliance lead)

#### C.5. Risk register integration
- Each finding can be linked to a risk-register entry
- Custom fields: business impact, likelihood, control owner
- Export to common audit-tooling formats (Drata-style import)

#### C.6. Continuous compliance daemon
- Wraps Phase 13.4 (continuous scanning) + control re-evaluation on every run
- Alerts when previously-passing control starts failing
- Trend chart: "control coverage over time"

#### C.7. Customer-facing trust page (Drata-style)
- Auto-generated subdomain: `<org>.trust.strix.io`
- Shows:
  - Security/compliance certifications (badges from auditor)
  - Continuous monitoring proof
  - Recent security improvements
  - SLA performance
- Customer can share publicly to win enterprise deals
- Branded (logo, colors) on Pro tier; full-custom on Enterprise

#### C.8. Auditor portal
- Read-only access for the customer's auditor
- Time-bounded (auto-expires)
- Filtered to in-scope evidence only
- Audit-log of auditor's accesses

### Phase effort
~10 weeks. ~12,000 LOC.

### Success criteria
- Customers complete SOC 2 audit using our evidence pack (validated with ≥3
  customers)
- Trust page generation latency < 30s
- ≥90% control-mapping accuracy (validated against auditor feedback)

### Engine dependency
- Phase 6, 7, 11 findings — control mapping requires diverse finding types
- `compliance_evidence.json` artifact (engine emits per-finding control tags)

---

## 8. Phase D — Integrations

**Goal**: meet customers where they are. Slack, Linear, Jira, GitHub
annotations.

### Why
- Day-1 customer ask. "Does it integrate with X?" sells deals.
- Vanta has 100+ integrations; ours starts at 0.

### Items

#### D.1. Slack integration
- OAuth install flow
- Slash commands:
  - `/strix scan <repo>` — trigger scan
  - `/strix findings <repo>` — list open findings
  - `/strix dismiss <finding-id>` — quick dismiss with reason
- Real-time alerts:
  - New critical finding → channel post
  - SLA breach → DM to assignee
  - Scan complete → digest in `#security`

#### D.2. Linear integration
- Auto-create Linear issues for findings ≥ severity threshold (configurable)
- Two-way sync: status changes in Linear → finding state updated in strix
- Custom Linear team / project mapping per finding-category

#### D.3. Jira integration
- Same pattern as Linear
- More config: per-project mappings, field mappings, custom workflows

#### D.4. GitHub Code Scanning integration
- Push SARIF to GitHub Security tab
- Customers see findings in their existing GitHub UI
- Plays nicely alongside our PR comments

#### D.5. Webhook endpoint
- Generic outbound webhook for every finding lifecycle event
- HMAC-signed payloads
- Customer-defined targets (Datadog, PagerDuty, custom internal tools)

#### D.6. CLI / API
- `strix-cli scan --repo /path/to/repo` for local CI use
- REST API for custom integrations
- Per-org API keys, rate-limited
- OpenAPI spec for the API

#### D.7. CI integration packs
- GitHub Actions workflow: `uses: strix/scan-action@v1`
- GitLab CI template
- CircleCI orb
- Jenkins plugin
- Pre-commit hook

### Phase effort
~6 weeks. ~6,000 LOC.

### Success criteria
- 80% of paying customers configure ≥1 integration in their first 14 days
- Slack-alerted critical findings have median response < 1 hour

---

## 9. Phase E — Auto-fix PR workflow

**Goal**: customers click "Apply Fix" on a PR comment and get a fix PR
opened automatically.

### Why
- Pixee made auto-fix the wedge that beat traditional SAST
- Vibe coders especially want this — they're already used to AI generating
  code

### Items

#### E.1. "Apply Fix" PR-comment button
- Engine Phase 12 produces `auto_fix_patches.json` with validated patches
- PR comment renders inline button: "Apply Fix (opens PR)"
- Click → wrapper opens a PR-in-PR using GitHub API
- Original PR comment updates to "Fix applied in #123"

#### E.2. Fix-PR template
- Title: `fix(security): patch {finding_summary}`
- Body:
  - Original finding details
  - Patch explanation
  - Confidence + validation results
  - "Reviewed-by: strix-bot" footer
- Linked to original finding via metadata

#### E.3. Bulk fix workflow
- "Apply 10 similar fixes" button on findings inbox
- Single PR with multiple commits, one per fix
- Per-fix confidence gating (skip low-confidence)

#### E.4. Fix preview
- Before clicking "Apply Fix," show diff preview
- Side-by-side: vulnerable code vs patched code
- Render in Monaco editor with syntax highlighting

#### E.5. Auto-fix telemetry
- Track per-customer:
  - Fixes attempted
  - Fixes accepted (PR merged)
  - Fixes rejected (PR closed without merge)
- Customer-facing: "you've fixed 47 findings via auto-fix this month"

#### E.6. Auto-fix safety controls
- Per-org config: "auto-open fix PRs vs require manual click"
- Per-severity gates ("auto-fix critical only on this branch")
- Pause auto-fix during release windows
- Rollback: "revert this fix PR" if regression detected

### Phase effort
~6 weeks. ~6,000 LOC.

### Success criteria
- 30% of findings get auto-fixed (vs manually triaged) within 90 days of
  customer onboarding
- Fix-PR merge rate > 70%
- Zero critical-regression incidents from auto-fixes

### Engine dependency
- Phase 12 (auto-fix codemod library) shipped + emitting validated patches

---

## 10. Phase F — Continuous monitoring dashboard

**Goal**: customers see their security posture trend in real-time, alerted
on regressions.

### Why
- Annual pentest is dead; customers want continuous visibility
- Differentiates from one-shot scanners
- Persona 2 (AppSec engineer) lives in dashboards

### Items

#### F.1. Real-time scan status
- WebSocket-driven dashboard tile:
  - "Last scan: 12 minutes ago"
  - "Scanning now: 3 specialists running"
  - "Queue: 0 pending"
- Visual: progress bars per specialist with hit/miss counts (Phase 5.4 telemetry)

#### F.2. Trend charts
- Open findings over time (per severity)
- Time-to-fix per severity
- Fix-rate per repo
- Coverage per OWASP / CWE category
- Comparison with industry benchmarks (anonymized cross-customer data from
  Phase 13.2)

#### F.3. Drift detection
- Phase 13.4 continuous-scan-deltas drive an alerting daemon
- Customer alerts: "Production drift detected — new endpoint
  `/api/admin` is missing auth"
- Alert routing via Phase D integrations

#### F.4. Compliance posture trend
- "Your SOC 2 readiness: 87% (up from 82% last week)"
- Per-control trend lines

#### F.5. Asset inventory
- Discovered assets (endpoints, dependencies, infra)
- Tag with risk score
- Filter / search / export

#### F.6. Cost / usage metrics (for billing transparency)
- Scans run this month (vs plan limit)
- LLM-fallback specialist costs (Phase 10) per scan
- Storage / retention metrics

### Phase effort
~6 weeks. ~7,000 LOC.

### Success criteria
- Daily-active-user rate ≥ 30% across paying customers
- Drift-detection alert accuracy > 80% (validated FP rate)

### Engine dependency
- `continuous_scan_deltas.jsonl` (Phase 13.4)
- `specialist_telemetry.jsonl` (Phase 5.4)

---

## 11. Phase G — Multi-tenant org features

**Goal**: scale to 50+ person companies (Persona 2/3 customers).

### Why
- Enterprise tier requires per-team isolation, RBAC, SSO
- Pricing tiers depend on this layer
- Gating compliance/audit access

### Items

#### G.1. Org structure
- User → Team → Repo
- Multi-org membership for one user (consultants)
- Org-level settings (default severity, integration configs, billing)

#### G.2. Role-based access control
- Roles: Owner, Admin, Member, Auditor (read-only)
- Permission matrix per resource type
- Audit log of every permission change

#### G.3. SSO / SAML
- WorkOS or Auth0 for enterprise SSO
- SCIM provisioning
- MFA enforcement at org level

#### G.4. Billing surface
- Stripe integration (or Paddle for international VAT handling)
- Tiers:
  - Free: 1 repo, 1 user
  - Pro: 5 repos, 5 users, $X/mo
  - Team: 20 repos, 20 users, $Y/mo
  - Enterprise: unlimited, custom pricing, SSO + SAML
- Usage-based add-ons: LLM-fallback specialist calls (cost passed through)
- Self-service upgrade / downgrade

#### G.5. Audit log
- Every customer action logged
- Filter by user / time / action
- Export for compliance

#### G.6. Data residency
- Enterprise tier: choose US / EU / Singapore region
- Per-region engine instances + per-region storage

#### G.7. Per-team customization
- Severity calibration per team
- Auto-fix rules per team
- Integration configs per team

### Phase effort
~12 weeks. ~12,000 LOC.

### Success criteria
- ≥3 enterprise customers (>$50K ARR each)
- SOC 2 Type 2 certified
- Sub-second tenant context switch in dashboard

---

## 12. Phase H — Customer trust + audit polish

**Goal**: become the security-credential-display layer customers use to
**sell** to their customers.

### Why
- Differentiates from "just a scanner"
- Sales-tool angle — customers use us to win enterprise deals
- Drata's killer feature

### Items

#### H.1. Trust page customization
- Custom domain: `trust.<customer>.com`
- Custom branding (full CSS control on Enterprise)
- Configurable sections (which findings/certs to expose publicly)
- Pre-built templates by industry (SaaS / fintech / healthtech)

#### H.2. Public sub-page modules
- "Security at <Customer>" with:
  - Frameworks (SOC 2, ISO 27001, GDPR, etc.)
  - Recent improvements (anonymized)
  - Subprocessor list
  - Contact form for security questionnaires

#### H.3. Customer-questionnaire automation
- Common security questionnaires (SIG, CAIQ, SOC 2 questionnaire)
- Pre-fill from existing evidence
- Track questionnaire response history

#### H.4. Insurance / cyber-policy export
- Pre-formatted reports for cyber-insurance underwriters
- Reduces the customer's premium when our trust signal correlates with low-
  risk claim history

#### H.5. Auditor handover automation
- Auditor portal (Phase C.8) integrated into a polished workflow
- "Prepare for SOC 2 audit" wizard
- Auto-generated readiness assessment
- Gap analysis with remediation suggestions

#### H.6. Compliance benchmark feed
- Anonymized: "your security posture is in the top 25% of SaaS companies
  your size"
- Driven by Phase 13.2 cross-customer data (privacy-preserving)

### Phase effort
~8 weeks. ~8,000 LOC.

### Success criteria
- ≥30% of Pro+ tier customers configure a public trust page
- Customers report sales-cycle reduction (qualitative survey)

---

## 13. Engine ↔ wrapper API contract

The engine emits typed artifacts; the wrapper consumes them. This contract
must be **versioned and stable**.

### Contract format

```
<run_dir>/
├── vulnerabilities.json         # tracer (engine, existing)              [SHIPPED]
├── vulnerabilities/*.md         # tracer (engine, existing)              [SHIPPED]
├── decision_log.jsonl           # phase 1.6                              [SHIPPED]
├── code_map.json                # phase 1.7                              [SHIPPED]
├── specialist_telemetry.jsonl   # phase 5.4                              [SHIPPED]
├── specialist_misses.jsonl      # phase 5.3                              [SHIPPED]
├── *.sarif                      # phase 7.5 (opt-in via scan_sast)       [SHIPPED, PR #219]
├── finding_chains.json          # §4a v2 cross-category correlation      [SHIPPED, PR #219]
├── compliance_evidence.json     # §4b SOC 2/ISO/PCI/ASVS evidence        [SHIPPED, PR #219]
├── event_stream.jsonl           # phase 9.1 streaming threat intel       [SHIPPED, PR #219]
├── behavioural_baselines.jsonl  # phase 9.2 per-endpoint baselines       [SHIPPED, PR #219]
├── ai_feature_findings.json     # phase 8 (parked)                       [PENDING]
├── llm_fallback_costs.jsonl     # phase 10                               [PENDING]
├── iac_posture.json             # phase 11.4 cloud APIs                  [PENDING — file-based IaC findings ride in vulnerabilities.json today]
├── auto_fix_patches.json        # phase 12                               [PENDING]
└── continuous_scan_deltas.jsonl # phase 13                               [PENDING]
```

### Versioning
- Each artifact has a `schema_version` field
- Wrapper consumers pin to specific schema versions
- Engine bumps schema only with documented migration

### Engine API surface (HTTP, for wrapper integration)
- `POST /scans` — trigger a scan
- `GET /scans/<id>` — scan status
- `GET /scans/<id>/artifacts/<name>` — fetch a typed artifact
- `WS /scans/<id>/stream` — real-time progress updates
- `POST /webhooks/threat-intel` — receive push-feed events

These are the contracts the wrapper relies on. Changes are breaking changes;
treat as public API.

---

## 13a. PR #219 — engine deliverables / wrapper work-list

**Single review surface for the wrapper team.** Everything PR #219
shipped on the engine side that the wrapper now needs to consume,
render, or schedule. Cross-referenced from
[`AISecurityEngineer.md`](./AISecurityEngineer.md) §4a, §4b, §5a,
Phase 6 / 7 / 9 / 11.

This section maps engine deliverables → wrapper work items. Where
this work fits into existing wrapper phases is called out per-item;
some asks expand existing Phase B / C / F scope, others are new.

### 13a.1. New artifacts to subscribe to / render

1. **`finding_chains.json`** (§4a v2 — engine doc) — sits next to
   `vulnerabilities.json`. Each chain has `chain_id`,
   `finding_ids`, `severity` (max), `summary` (one-liner),
   `categories[]`, `chain_type` (`sca_dast` / `sast_dast` /
   `iac_dast` / `sca_sast_dast` / `mixed`).
   - **Wrapper work:** Render as collapsible card grouping N
     findings under one chain header. Don't render constituent
     findings as separate inbox entries when they're part of a
     chain. Chain-type colour scheme (`sca_dast` red, `sast_dast`
     orange, `iac_dast` yellow, `sca_sast_dast` purple, `mixed`
     grey). Per-link rationale (`chain.links[*].rationale`) on
     hover. Sort chains spanning > 2 categories first.
   - **Wrapper phase:** Phase B (findings inbox) extension.

2. **`compliance_evidence.json`** (§4b — engine doc) — per-control
   verdict (`fail` / `warn` / `info` / `pass` / `untested`) for SOC 2
   / ISO 27001 / PCI DSS 4.0 / OWASP ASVS 4.0.
   - **Wrapper work:** Build the compliance tab from this
     artifact. Per-framework summary cards. Per-control
     drill-down: click a control → list of finding IDs that hit
     it (auditor trace). **`untested` coverage-gap surfacing**
     in a separate section: "These controls aren't validated by
     strix; you need other tooling." Auditor-export PDF
     generation (still wrapper-side per §3.1 of engine doc).
     Risk-register integration (`verdict=fail` controls feed the
     wrapper's risk register).
   - **Wrapper phase:** Phase C (compliance) extension /
     foundation.

3. **`event_stream.jsonl`** (Phase 9.1 — engine doc) — bounded ring
   buffer (10k events, atomic rotation). Subscribe via
   tail-since-timestamp. Events: `kev_added` (new CISA KEV
   listing) / `feed_polled` (daemon liveness).
   - **Wrapper work:** Real-time KEV banner ("X new
     KEV-listed CVEs match your dependencies" with click-through
     to relevant SCA findings). Daemon-liveness indicator
     (green / red based on `feed_polled` recency).
   - **Wrapper phase:** Phase F (continuous monitoring) — partial
     Phase F functionality available now via the streaming
     daemon.

4. **`behavioural_baselines.jsonl`** (Phase 9.2 — engine doc) —
   append-only, last-line-wins per endpoint.
   - **Wrapper work:** Endpoint reference panel — for each
     baseline'd endpoint, show captured profile (status
     distribution, latency p50/p99, body-length p50/p99, JSON
     keys) as the "what's normal here" context next to anomaly
     findings.
   - **Wrapper phase:** Phase B (findings inbox detail panel).

5. **SARIF 2.1.0** (Phase 7.5 — engine doc) — opt-in via
   `scan_sast(sarif_output_path=...)`. Calibrated severity in
   `level` + breadcrumb in `properties.calibration`.
   - **Wrapper work:** GitHub Code Scanning native ingest. Pass
     the SARIF path on PR scans; GitHub renders findings inline
     on the PR.
   - **Wrapper phase:** Phase A (PR-comment bot) integration.
     Replaces the original "parse markdown findings" plan.

### 13a.2. New finding categories to add UI for

| Category | Source | UI request | Wrapper phase |
|---|---|---|---|
| `malicious_dependency` | Phase 6.6 | Dedicated section in inbox; subtype-specific iconography (`typosquat` / `install_script` / `known_malicious` / `no_license`). `known_malicious` (OSSF feed match) gets highest-priority block. | Phase B |
| `license_violation` | Phase 6.7 | License tab + auto-rotate-credential CTA for `info_disclosure` family. Pie chart from `tool_metadata.licenses.by_family`. | Phase C |
| `anomaly` | Phase 9.3 | Behavioural tab; per-anomaly-class iconography. `error_string_present` + SQL classes → suggested SQLi pivot button. | Phase B |
| `finding_chain` | §4a v2 | Chain inbox (per §13a.1 above). | Phase B |
| `compliance_violation` | §4b | Compliance tab; per-control card. | Phase C |
| `[iac:vercel]` / `[iac:netlify]` / `[iac:cloudflare]` / `[iac:docker]` prefixed | Phase 11.3 | Group by deploy platform; platform-specific iconography (Vercel triangle / Netlify diamond / Cloudflare orange / Docker blue). | Phase B + Phase F (cloud-posture tile) |

### 13a.3. New per-finding metadata to render

* **Reachability badge** — title contains
  `[reachability=direct_import\|transitive_only\|unused\|unknown]`.
  Default-collapse `unused` / `transitive_only` with a toggle.
  Show original-vs-calibrated severity.
* **KEV badge** — title contains
  `[KEV — actively exploited]`. Always render at top of inbox;
  KEV overrides reachability demotion.
* **Calibration breadcrumb** — SAST findings carry
  `[calibrated:high→critical]` in title when severity changed
  due to route-reachability or test-file demotion.
* **Chain badge** — chain findings prefix `[chain:<chain_type>]`
  e.g. `[chain:sca_dast]`.

### 13a.4. New cron / daemon work for the wrapper

Wrapper provisions / schedules these so customers don't have to:

* **Daily threat-intel refresh** — `python -m
  strix.threat_intel.refresh` (KEV / EPSS / NVD / GHSA / OSSF
  malicious / popular packages). Recommend 1am UTC.
* **5-min KEV streaming daemon** — `python -m
  strix.threat_intel.streaming`. Long-running process under
  systemd / k8s / docker `restart: unless-stopped`. Wrapper
  surfaces "real-time intel ON" indicator from `feed_polled`
  events.
* **SAST registry refresh** — `python -m strix.sast.refresh`
  (semgrep --update). Recommend 1:30am UTC after threat-intel.

**Wrapper phase:** Phase A (onboarding) provisions these via the
sidecar / cron the wrapper deploys per customer.

### 13a.5. New `tool_metadata` aggregates to surface

Each scan's `SpecialistResult` carries dashboard-ready rollups:

* `tool_metadata.reachability.by_status` — pie/bar chart on the
  SCA dashboard tile.
* `tool_metadata.malicious.by_indicator` — typosquat /
  install-script / no-license / known-malicious counts.
* `tool_metadata.licenses.by_family` — license inventory pie
  chart for SOC 2 OPS-3 evidence.
* `tool_metadata.calibration.{bumped,demoted,unchanged}` (SAST)
  — "we filtered N noise findings via reachability" badge.
* `tool_metadata.diff_scope.applied` (SAST) — PR-mode indicator.
* `tool_metadata.summary` (compliance) — per-framework verdict
  counts.

**Wrapper phase:** Phase B (findings inbox metrics tile) +
Phase C (compliance tab summary cards).

### 13a.6. Lead-agent behavioural changes the wrapper should know about

* **POST-SCAN STEPS** — every scan now ends with two extra
  tool calls: `correlate_findings` then
  `emit_compliance_evidence`. Wrapper should expect both
  artifacts to exist after a scan completes; absence indicates
  scan didn't finish cleanly.
* **`category="lead"`** is the canonical agent category
  (legacy `Root Agent` mapping unchanged).
* **Dispatch guard** — `create_agent` is in the lead's
  blocklist; it cannot spawn sub-agents. The wrapper's
  agent-graph view collapses to a single root node.

### 13a.7. Onboarding requests (Phase A extensions)

* **Compliance framework picker** — let the customer choose
  SOC 2 / ISO 27001 / PCI DSS / OWASP ASVS during onboarding;
  pass to `emit_compliance_evidence(frameworks=[...])` to
  scope the artifact.
* **Reachability default** — `with_reachability=True` is
  engine default; wrapper UI toggle for "show all findings
  including unused" (which sets the runtime view filter, not
  the engine arg).
* **`only_reachable=True` checkbox** for zero-noise dep-CVE
  dashboards.
* **License policy** — three checkboxes mapping to
  `license_allow_copyleft` / `license_allow_unknown` /
  `license_allow_weak_copyleft`. Default: copyleft + unknown
  flagged, weak_copyleft allowed.

### 13a.8. Scope clarifications (still wrapper-side, NOT engine)

These remain wrapper concerns per §3.1 of the engine doc:

* Auditor-handover PDF generation
* Customer attestation collection
* Risk register management
* Per-customer dashboard branding
* SOC 2 trust portal
* Bug-bounty triage UX
* Multi-tenant isolation / SSO
* Compliance policy templating

---

## 14. Pricing tier alignment

The wrapper phases enable specific pricing tiers:

| Tier | Phases enabled | Key features |
|---|---|---|
| **Free** | A, B (limited) | 1 repo, 1 user, weekly scans, no compliance |
| **Pro** | A, B, D, E, F | 5 repos, 5 users, daily scans, integrations, auto-fix, dashboards |
| **Team** | + C | + compliance dashboards, evidence packs, SLA tracking, basic trust page |
| **Enterprise** | + G, H | SSO/SAML, RBAC, audit log, data residency, custom trust page, dedicated support |

Engine costs (LLM-fallback, threat-intel polling) flow through as usage-
based add-ons on Pro+ tiers.

---

## 15. Phase order + dependencies

| Sequence | Phase | Engine dep | Customer-value priority |
|---|---|---|---|
| 1 | A — Onboarding + GitHub App | Engine 6, 7 | **highest** |
| 2 | B — Findings inbox + triage | — | high |
| 3 | D — Integrations | — | high |
| 4 | E — Auto-fix PR workflow | Engine 12 | high |
| 5 | C — Compliance layer | Engine 6, 7, 11 | high (revenue gate) |
| 6 | F — Continuous monitoring | Engine 9, 13 | medium |
| 7 | G — Multi-tenant org | — | medium (enterprise gate) |
| 8 | H — Customer trust polish | Engine 13.2 | medium (sales tool) |

**Total wrapper scope**: ~75,000 LOC. ~12 months at small-team pace.

---

## 16. Out of scope

| Excluded | Why |
|---|---|
| Engine specialist development | Lives in `strix/` |
| Marketing site / blog | Different repo |
| Customer support tooling (Intercom etc.) | Buy, don't build |
| Mobile app | Not on roadmap until enterprise demand |
| Self-hosted on-prem | Enterprise feature, post-Series A |
| Custom UI for security researchers | Persona 2/3 covered by existing dashboards |

---

## 17. Open questions

1. **Front-end framework**: Next.js (consistent with our customer base) or
   Remix or plain SPA? Affects every Phase A–H estimate.
2. **State management for real-time UI**: WebSocket via tRPC, or Phoenix
   LiveView, or Inertia.js? Phase F dashboard depends on this.
3. **Trust-page hosting**: same domain as wrapper (subdomain) or separate
   service? CDN strategy for public traffic.
4. **GitHub App vs OAuth App**: GitHub App preferred for finer-grained
   permissions and PR-comment branding, but OAuth App is simpler to ship.
5. **Free tier limits**: how aggressive? Affects funnel + cost.
6. **Compliance framework breadth**: ship SOC 2 first, then ISO; or both
   simultaneously? Customer-driven; SOC 2 first looks defensible.
7. **Cross-customer pattern sharing UX**: opt-in, opt-out, or tiered? Privacy
   review gates this.
8. **LLM-cost passthrough**: do customers see per-scan LLM costs or rolled-up
   subscription? Affects pricing model.

---

## 18. Tracking

- This doc is the strategic plan; tactical sequence belongs in the
  webappsec repo's issue tracker.
- Each phase opens a tracking issue in `webappsec/`.
- Wrapper releases align with engine artifact availability — wrapper PRs
  gate on engine PRs.
- Quarterly review to re-prioritize based on customer feedback.

---

## 19. Companion document

The technical engine roadmap is in [`AISecurityEngineer.md`](./AISecurityEngineer.md).
Read that for what specialists, scanners, and intel sources the engine ships
in support of these wrapper phases.
