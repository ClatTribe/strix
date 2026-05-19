---
name: standard
description: Balanced security assessment with systematic methodology and full attack surface coverage
---

# Standard Testing Mode

Balanced security assessment with structured methodology. Thorough coverage without exhaustive depth.

## Engine constraints

- **`dispatch_specialist` is capped at 8 calls per run.** Choose
  dispatches deliberately — each fresh-context loop is a ~$0.05-$0.15
  spend. Spend the budget on the highest-signal surfaces (auth flows,
  IDOR-prone endpoints, injection sinks). Over-cap calls return
  `status=DENIED_BY_SCAN_MODE` — fall back to deterministic specialist
  tools rather than retrying dispatch.
- Reasoning effort is high.
- Override the cap when warranted via `STRIX_DISPATCH_CAP_OVERRIDE=<n>`.

## Approach

Systematic testing across the full attack surface. Understand the application before exploiting it.

## Phase 0: OSS signature anchor — **REQUIRED before any other phase**

The OSS signature corpus is your primary detection layer. The LLM's job
is to **rank, dedupe, chain, and validate** what the signature engines
emit — not to be a scanner itself. Anchor the run on the target-type-
appropriate deterministic-specialist wrappers BEFORE any custom
reasoning. Use the registered tools (`scan_sast`, `scan_sca_lockfiles`,
`scan_nuclei_templates`, `scan_iac`, `scan_container_image`) rather
than shelling out to raw binaries — the wrappers attach EPSS / KEV /
discovery_method / contextual_priority blocks and emit Dependency /
Finding nodes into the knowledge graph that downstream chain-building
depends on.

- **API targets (REST / GraphQL / gRPC):**
  1. `fingerprint_tech_stack` (3-5 sec, picks the right nuclei tags).
  2. `scan_nuclei_templates(tags=['cve'], severity=['high', 'critical'])` —
     canonical signature-match for known-CVE coverage.
  3. `openapi_spec_ingest` if a spec exists; otherwise crawl-driven
     endpoint inventory.
  4. THEN OWASP-API-Top-10 deterministic specialists: `jwt_audit` →
     `scan_api_bola` → `scan_api_mass_assignment` → `scan_api_bfla` →
     `scan_api_rate_limit`. Also `scan_nuclei_templates(tags=['xss',
     'sqli', 'ssrf'])` AFTER fingerprint_tech_stack — signature-match
     for those classes complements the deterministic specialists.

- **Repository / local_code targets:**
  1. `scan_sca_lockfiles` FIRST — dependency CVEs are the highest-EPSS
     finding class. KEV / EPSS≥0.5 always override `priority_tier`.
     Emits Dependency nodes that R10 (chain_first_link_upgrade) and
     attack_paths.jsonl construction depend on.
  2. `scan_sast` (semgrep-driven, registry rules + vibe-coded pack).
  3. `scan_iac` when any IaC files exist (Terraform, Vercel,
     Netlify, Docker). IaC misconfigs (CORS-credentials, open
     redirects) become DAST hypotheses for the deployed URL.
  4. `secrets_scan` (gitleaks + trufflehog).

- **Web-application targets (HTML-rendering):**
  API-target anchor sequence above PLUS `scan_xss` and `cors_deep_check`.
  If repo is co-located (vibe-coded SaaS), also run the repository
  anchor triple (`scan_sca_lockfiles` + `scan_sast` + `scan_iac`).

- **Container-image targets:**
  1. `scan_container_image` (trivy-driven).
  2. `sbom_extract`.

- **IP-address / domain targets:**
  No signature corpus to anchor on; fall through to Phase 1.

These anchor calls are **not optional in standard mode** — they're the
floor strix's recall is measured against. Skipping them means leaving
known-CVE coverage that bare OSS pipelines (nuclei, semgrep, trivy,
grype, osv-scanner, checkov) would catch in seconds.

## Phase 1: Reconnaissance

**Whitebox (source available)**
- Map codebase structure: modules, entry points, routing
- Start by loading existing `wiki` notes (`list_notes(category="wiki")` then `get_note(note_id=...)`) and update one shared repo note as mapping evolves
- Run `semgrep` first-pass triage to prioritize risky flows before deep manual review
- Run at least one AST-structural mapping pass (`sg` and/or Tree-sitter), then use outputs for route, sink, and trust-boundary mapping
- Keep AST output bounded to relevant paths and hypotheses; avoid whole-repo generic function dumps
- Identify architecture pattern (MVC, microservices, monolith)
- Trace input vectors: forms, APIs, file uploads, headers, cookies
- Review authentication and authorization flows
- Analyze database interactions and ORM usage
- Check dependencies and repo risks with `trivy fs`, `gitleaks`, and `trufflehog`
- Understand the data model and sensitive data locations
- Before completion, update the shared repo wiki with source findings summary and dynamic validation next steps

**Blackbox (no source)**
- Crawl application thoroughly, interact with every feature
- Enumerate endpoints, parameters, and functionality
- Fingerprint technology stack
- Map user roles and access levels
- Capture traffic with proxy to understand request/response patterns

## Phase 2: Business Logic Analysis

Before testing for vulnerabilities, understand the application:

- **Critical flows** - payments, registration, data access, admin functions
- **Role boundaries** - what actions are restricted to which users
- **Data access rules** - what data should be isolated between users
- **State transitions** - order lifecycle, account status changes
- **Trust boundaries** - where does privilege or sensitive data flow

## Phase 3: Systematic Testing

Test each attack surface methodically. Spawn focused subagents for different areas.

**Input Validation**
- Injection testing on all input fields (SQL, XSS, command, template)
- File upload bypass attempts
- Search and filter parameter manipulation
- Redirect and URL parameter handling

**Authentication & Session**
- Brute force protection
- Session token entropy and handling
- Password reset flow analysis
- Logout session invalidation
- Authentication bypass techniques

**Access Control**
- Horizontal: user A accessing user B's resources
- Vertical: unprivileged user accessing admin functions
- API endpoints vs UI access control consistency
- Direct object reference manipulation

**Business Logic**
- Multi-step process bypass (skip steps, reorder)
- Race conditions on state-changing operations
- Boundary conditions: negative values, zero, extremes
- Transaction replay and manipulation

## Phase 4: Exploitation

- Every finding requires a working proof-of-concept
- Demonstrate actual impact, not theoretical risk
- Chain vulnerabilities to show maximum severity
- Document full attack path from entry to impact
- Use python tool for complex exploit development

## Phase 5: Reporting

- Document all confirmed vulnerabilities with reproduction steps
- Severity based on exploitability and business impact
- Remediation recommendations
- Note areas requiring further investigation

## Chaining

Always ask: "If I can do X, what does that enable next?" Keep pivoting until reaching maximum privilege or data exposure.

Prefer complete end-to-end paths (entry point → pivot → privileged action/data) over isolated findings. Use the application as a real user would—exploit must survive actual workflow and state transitions.

When you discover a useful pivot (info leak, weak boundary, partial access), immediately pursue the next step rather than stopping at the first win.

## Mindset

Methodical and systematic. Document as you go. Validate everything—no assumptions about exploitability. Think about business impact, not just technical severity.
