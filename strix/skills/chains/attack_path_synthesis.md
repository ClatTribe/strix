---
name: attack-path-synthesis
description: Bundling atomic findings into multi-step exploit stories — how the lead writes narrative chains the wrapper renders to customers
triggers: [attack path, exploit story, narrative, chain narrative, kill chain, finding bundle, finding correlation]
---

# Attack Path Synthesis

A list of findings is a checklist; an **attack path** is a story. Customers don't pay for "XSS detected at /comments"; they pay for "an unauthenticated visitor can take over your CEO's account in 3 steps". This skill teaches the lead how to bundle atomic findings into narrative chains, score them, and emit them in a form the wrapper can render to non-technical readers.

Companion to `cross_asset_chains.md` (catalog of chains to look for) — this one is **how to write them up**.

## What an Attack Path Looks Like

Bad:
> Three findings:
> - Medium: XSS at /comments
> - Medium: CSRF token missing on /api/admin/transfer
> - High: IDOR on /api/admin/users/{id}

Good (the synthesised version):
> **End-to-end account takeover** (critical):
> An unauthenticated attacker can take over any user account in 3 steps:
> 1. The attacker injects a malicious script via the /comments endpoint (reflected XSS, CWE-79).
> 2. When an admin views the comment, their session cookie + the CSRF token are exfiltrated to attacker-controlled infrastructure.
> 3. Using the stolen session, the attacker calls /api/admin/users/{id} with arbitrary user IDs (IDOR, CWE-639). They modify password reset tokens to take over any user's account.
>
> **First-step entry point**: /comments accepts POST with `<script>` in body.
> **Time to compromise**: under 5 minutes once the admin views the malicious comment.
> **Fix at**: /comments (HTML-escape user input). Defence-in-depth: enforce CSRF tokens on /api/admin/*; scope cookies to HttpOnly + Secure.

The synthesised version is what the customer signs off; the atomic findings are the evidence.

## The Synthesis Template

Every attack path has 5 components:

### 1. Title (1 sentence)
What it accomplishes for the attacker.
- ✅ "Account takeover via XSS + IDOR chain"
- ✅ "Cross-tenant data exfil via SSRF + cloud-metadata"
- ❌ "Multiple findings observed" (vague)
- ❌ "XSS, IDOR, CSRF" (just listing)

### 2. Entry conditions
What the attacker needs to start.
- "Unauthenticated visitor" — best case for the attacker
- "Authenticated low-priv user" — common
- "Specific role / permission" — narrower
- "Network position (insider, MITM)" — rare but possible

### 3. Steps (numbered, each verifiable)
Each step:
- Names the finding (vuln class + location)
- States what the attacker observes / extracts / achieves
- References the verification evidence (request bytes, response bytes, screenshot)

### 4. Impact statement
What goes wrong if the chain executes.
- Data loss: "all customer records (NAME, EMAIL, PHONE) accessible"
- Business: "fraudulent payments processed under victim's card"
- Compliance: "SOC 2 CC6.1 violation; GDPR Art. 32 violation"
- Operational: "service outage X hours due to attacker-deployed backdoor"

### 5. Remediation (ordered by leverage)
- **Primary fix**: where to stop the entire chain (usually the first step's vuln)
- **Defence in depth**: changes that would block subsequent steps even if primary fails
- **Detection**: what telemetry would catch this chain in production

## Operational Runbook

### Step 1 — collect verified findings

After per-specialist scans complete, query the KG for findings that:
- Are status=verified (not pattern_match, not inconclusive)
- Have AFFECTS / CHAINS_TO edges in the graph

```python
candidates = kg_query_nodes(type="Vuln", filters={"status": "verified"})
```

### Step 2 — find chains
Use `correlate_findings` (PR #294) for pattern-matched chains:
```python
chains = correlate_findings(min_severity="medium", min_steps=2)
```

Each returned chain is a list of Vuln node IDs in execution order.

### Step 3 — pick the highest-leverage chain
Score each candidate chain:
- `severity` (computed via cross_asset_chains.md severity math)
- `entry_difficulty`: unauth (0) < authenticated-low (1) < authenticated-high (2) < insider (3)
- `time_to_compromise`: minutes (3) > hours (2) > days (1) > weeks (0)
- `business_impact`: account-takeover > data-leak > service-disruption > info-disclosure

Top-scoring chains land in the report's executive summary.

### Step 4 — write the narrative

Use the template above. **Hard rules**:
- Each step must be verified (else it's hypothetical, not a chain).
- The chain reads in temporal order: step 1 happens first.
- The narrative names the attacker, victim, system — not abstract pronouns.
- Time-to-compromise estimate is honest; not "instant" unless truly instant.

### Step 5 — attach evidence

For each step, link to:
- The atomic Vuln finding (with its evidence: payload, response, screenshot)
- The corresponding KG edge (which made the step "follow" from the previous)
- Optional: a recorded PoC video / reproduction script

### Step 6 — emit
```bash
emit_finding \
  --title "End-to-end account takeover via XSS → cookie theft → IDOR" \
  --severity critical \
  --category attack_path \
  --description "<narrative from template>" \
  --reasoning_trace '[<step 1 verified>, <step 2 verified>, <step 3 verified>]' \
  --remediation "<ordered list per the template>"
```

## Common Pitfalls

### Speculative chains
**Bad**: "XSS *could* lead to cookie theft *if* there's no HttpOnly flag."
**Good**: "XSS at /comments + cookies are observed without HttpOnly via X-Cookie-Audit header = cookie theft verified."

If a step isn't verified, it's not part of the chain. Demote to "follow-up investigation" instead.

### Conflated paths
**Bad**: "Attackers can do X, OR Y, OR Z."
**Good**: One chain = one path. Multiple chains = multiple attack-path entries. Don't bundle disjunctive options.

### Over-claimed severity
**Bad**: "This is critical because chained vulnerabilities are always critical."
**Good**: Apply the severity math from cross_asset_chains.md. A chain's severity is bounded by its weakest link's verification.

### Generic remediation
**Bad**: "Patch the vulnerabilities and follow OWASP guidelines."
**Good**: Specific fix for the entry-point finding + concrete defence-in-depth recommendations + production-detection telemetry.

## Pro Tips

1. The customer reads the chain narrative first; the technical evidence later. Optimise for the reader.
2. Time-to-compromise is the single most-quoted metric in the report. Make it accurate.
3. One critical-chain finding beats ten medium individual findings in the executive summary.
4. Reference the OWASP Top 10 / MITRE ATT&CK technique IDs in the narrative when natural — auditors look for them.
5. The narrative should be readable by the customer's CEO. Test by removing jargon and seeing if it still hangs together.

## Validation

A synthesised attack path is valid when:
1. Every step is independently verified.
2. The chain's narrative reads in temporal order.
3. Entry conditions are concrete.
4. Impact is specific (data classes, business outcomes, compliance violations).
5. Remediation has primary + defence-in-depth + detection.

## Summary

Attack-path synthesis converts findings into stories. Verified steps; temporal narrative; concrete impact; primary-fix + defence-in-depth. The chain is the product the customer sees; the atomic findings are the substrate.
