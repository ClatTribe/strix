---
name: skill-template
description: |
  Canonical structure for `strix/skills/*` files. Copy this file when
  adding a new skill; fill in the sections below; delete this template
  preamble.
type: template
---

<!-- ============================================================
This is the canonical template for Strix skills. Phase 1A onward,
every new skill follows this structure for consistency + menu
keyword-matching.

Frontmatter REQUIRED fields:
  - name: skill-name-in-kebab-case
  - description: one-line summary (≤ 120 chars), used by the menu

Frontmatter RECOMMENDED fields:
  - triggers: [keyword1, keyword2, ...]  (3-10 keywords for menu match)
  - last_updated: 2026-05-18  (ISO date — Phase 5)
  - version: 1                (integer, bump on significant rewrites)

Skill body REQUIRED sections (in order):
  1. # Title
  2. Intro paragraph — positioning + companion-skill references
  3. ## Attack Surface
  4. ## Detection Channels
  5. ## Operational Runbook (numbered steps with commands)
  6. ## Specific Vulnerability Classes (deep cases)
  7. ## Bypass Techniques (optional but common)
  8. ## Validation (what evidence counts)
  9. ## False Positives (what NOT to flag)
  10. ## Impact
  11. ## Remediation (numbered, ordered by leverage)
  12. ## Pro Tips
  13. ## Summary (one-paragraph rollup)

Target length: 200-400 LOC per skill. Longer for canonical-attack-class
skills (sql_injection.md is ~340 LOC); shorter for narrow technologies.

Style:
  - Concrete commands ALWAYS over abstract advice
  - Real example values: <TARGET>, <ENDPOINT>, <SECRET> placeholders
  - Code blocks tagged with the right language
  - Tables for enumeration; bullets for narrative
  - No marketing language ("powerful", "robust", "industry-leading")
  - No vague refuse-to-claim ("might be possible to attempt")
============================================================ -->

# Skill Title (e.g. "MongoDB Security")

One-paragraph intro: what this skill covers, the *positioning* relative
to peers, and a one-line link to companion skills (e.g. "Companion to
`nosql_injection.md` for app-layer operator-injection patterns").

## Attack Surface

What lives in this domain. Subsections per major surface:

### Subsurface A
- Component / mechanism / endpoint
- Bug pattern that lives there
- Why it matters

### Subsurface B
...

## Detection Channels

How to find a target / fingerprint the technology / identify the bug.

```bash
# Concrete probe command
curl -s '<TARGET>/some-endpoint' | grep -i 'pattern'
```

```bash
# Another probe
example
```

## Operational Runbook

### Step 1 — fingerprint
```bash
command
```

### Step 2 — exploit (or extract / enumerate)
```bash
command
```

(continue with numbered steps; aim for 5-7 steps)

## Specific Vulnerability Classes

### Bug class A
What it is. How to detect. Why it's exploitable.

### Bug class B
...

## Bypass Techniques

- **Trick 1**: how it works, when to use
- **Trick 2**: ...

## Validation

For a finding to be valid:
1. Concrete observable that confirms exploitability.
2. Reproduce from a clean session.
3. Document: what was probed, what response confirmed it.

## False Positives

- Pattern that LOOKS exploitable but isn't, with reason.
- Defence already in place (verify before flagging).

## Impact

- Direct outcome (data class, business effect, compliance violation)
- Lateral / pivot possibilities

## Remediation

1. Primary fix (most leverage).
2. Defence-in-depth.
3. Detection / alerting.

## Pro Tips

1. Tip about ordering or focus.
2. Tip about a common gotcha.
3. Tip about useful tooling.

## Summary

One paragraph: the headline. The customer reads this first.
