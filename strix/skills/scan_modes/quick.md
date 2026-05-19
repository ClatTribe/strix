---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities
---

# Quick Testing Mode

Time-boxed assessment focused on high-impact vulnerabilities. Prioritize breadth over depth.

## Engine constraints

- **`dispatch_specialist` is disabled in quick mode** (cap = 0). The
  fresh-context specialist loop is the largest cost driver, and quick
  mode trades that depth for breadth + speed. Calls to
  `dispatch_specialist` return `status=DENIED_BY_SCAN_MODE` —
  treat this as "use the deterministic specialist tool directly"
  (e.g. `scan_sqli`, `scan_xss`, `scan_idor`) rather than retrying.
- Reasoning effort is medium.
- Wall-clock target: under 10 minutes per asset.

## Approach

Optimize for fast feedback on critical security issues. Skip exhaustive enumeration in favor of targeted testing on high-value attack surfaces.

## Phase 0: Anchor scans — **REQUIRED before any other phase**

Quick mode without these anchor calls collapses to "LLM reads files and guesses,"
which produces 0–30% recall on benchmarks. The bar is set by free OSS pipelines
running these same tools directly (semgrep finds 15 vulns in flask-vuln in 3
seconds; trivy/grype/osv-scanner one-shot the SCA fixtures). **Strix has to at
least invoke them.**

Anchor the run on the target-type-appropriate deterministic specialist tools
**before** doing any custom reasoning. If a backend is missing (`scan_sast`
returns `status="partial"` etc.), surface that explicitly in your findings —
don't silently move on.

- **API targets (REST / GraphQL / gRPC):**
  1. `fingerprint_tech_stack` first (3-5 sec, picks the right nuclei tags).
  2. `scan_nuclei_templates(tags=['cve'], severity=['high', 'critical'])` —
     this is the canonical signature-match path for known-CVE coverage. Skipping
     it means you cannot detect ~9k known issues that OSS nuclei catches.
  3. `openapi_spec_ingest` if a spec exists, else `fingerprint_tech_stack`-driven
     endpoint inventory.
  4. THEN run the OWASP-API-Top-10 deterministic specialists in priority order:
     `jwt_audit` (token forgery / weak-secret) → `scan_api_bola` (BOLA / IDOR) →
     `scan_api_mass_assignment` → `scan_api_bfla` → `scan_api_rate_limit`.

- **Repository / local_code targets:**
  1. `scan_sca_lockfiles` FIRST — dependency CVEs are the highest-EPSS finding
     class, and `attack_path_membership` chain construction depends on
     Dependency-node emission. KEV / EPSS≥0.5 always override `priority_tier`.
  2. `scan_sast` (Phase 7 — semgrep-driven, registry rules + vibe-coded pack) —
     diff-aware on PR context, fast.
  3. `scan_iac` if any IaC files exist (`vercel.json` / `netlify.toml` /
     `terraform/` / `Dockerfile` / `docker-compose.yml`). Cross-asset:
     IaC misconfigs (CORS-credentials, open redirects) become DAST hypotheses
     for the deployed URL.
  4. `secrets_scan` (always cheap; gitleaks-driven).

- **Web-application targets (HTML-rendering):**
  Same API-target anchor sequence, PLUS `scan_xss` and `cors_deep_check` after
  the nuclei pass. If the repo is co-located (vibe-coded SaaS), also run the
  `scan_sca_lockfiles` + `scan_sast` + `scan_iac` triple from the repo path.

- **Container-image targets:**
  1. `scan_container_image` (trivy-driven, vuln + misconfig + secret scanners).
  2. `sbom_extract` for the dependency manifest.

- **IP-address / domain targets:**
  No signature corpus to anchor on; fall through to Phase 1 (Rapid Orientation).

Skipping these anchors is the single largest recall regression in quick mode.
The lead's tool catalog already exposes them (`strix/agents/lead_agent/tool_catalog.py`)
— this section is the **prompt-level instruction** that they must actually be
called.

## Phase 1: Rapid Orientation

**Whitebox (source available)**
- Focus on recent changes: git diffs, new commits, modified files—these are most likely to contain fresh bugs
- Read existing `wiki` notes first (`list_notes(category="wiki")` then `get_note(note_id=...)`) to avoid remapping from scratch
- Run a fast static triage on changed files first (`semgrep`, then targeted `sg` queries)
- Run at least one lightweight AST pass (`sg` or Tree-sitter) so structural mapping is not skipped
- Keep AST commands tightly scoped to changed or high-risk paths; avoid broad repository-wide pattern dumps
- Run quick secret and dependency checks (`gitleaks`, `trufflehog`, `trivy fs`) scoped to changed areas when possible
- Identify security-sensitive patterns in changed code: auth checks, input handling, database queries, file operations
- Trace user input through modified code paths
- Check if security controls were modified or bypassed
- Before completion, update the shared repo wiki with what changed and what needs dynamic follow-up

**Blackbox (no source)**
- Map authentication and critical user flows
- Identify exposed endpoints and entry points
- Skip deep content discovery—test what's immediately accessible

## Phase 2: High-Impact Targets

Test in priority order:

1. **Authentication bypass** - login flaws, session issues, token weaknesses
2. **Broken access control** - IDOR, privilege escalation, missing authorization
3. **Remote code execution** - command injection, deserialization, SSTI
4. **SQL injection** - authentication endpoints, search, filters
5. **SSRF** - URL parameters, webhooks, integrations
6. **Exposed secrets** - hardcoded credentials, API keys, config files

Skip for quick scans:
- Exhaustive subdomain enumeration
- Full directory bruteforcing
- Low-severity information disclosure
- Theoretical issues without working PoC

## Phase 3: Validation

- Confirm exploitability with minimal proof-of-concept
- Demonstrate real impact, not theoretical risk
- Report findings immediately as discovered

## Chaining

When a strong primitive is found (auth weakness, injection point, internal access), immediately attempt one high-impact pivot to demonstrate maximum severity. Don't stop at a low-context "maybe"—turn it into a concrete exploit sequence that reaches privileged action or sensitive data.

## Operational Guidelines

- Use browser tool for quick manual testing of critical flows
- Use terminal for targeted scans with fast presets (e.g., nuclei with critical/high templates only)
- Use proxy to inspect traffic on key endpoints
- Skip extensive fuzzing—use targeted payloads only
- Create subagents only for parallel high-priority tasks

## Mindset

Think like a time-boxed bug bounty hunter going for quick wins. Prioritize breadth over depth on critical areas. If something looks exploitable, validate quickly and move on. Don't get stuck—if an attack vector isn't yielding results quickly, pivot.
