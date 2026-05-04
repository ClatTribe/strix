# wrapper-wishlist.md

What `ClatTribe/webappsec` (the SaaS wrapper) should add / change to take advantage of
the engine-side work shipped in the strix fork (PRs #19–#36, focused on domain-target
recon, scan readability, and per-finding context). This is a hand-off doc; it does not
modify engine behavior.

Companion to:
- [`roadmap.md`](roadmap.md) — engine-side roadmap (source of truth for what shipped)
- [`deploy.md`](deploy.md) — how to build the fork as a container image for the wrapper

---

## TL;DR

**Breaking-shape changes**: zero. Every existing artifact, CLI flag, and event still
emits the same shape. All new fields are additive. Old wrapper code keeps working.

**Required for any of this to land**: rebuild the sandbox image
(`docker build -f containers/Dockerfile -t strix-sandbox:local .`). Eight new recon
tools are registered with `sandbox_execution=True`; without the rebuild, the agent
inside the container sees "tool not found".

**Biggest UX wins** (in recommended order):
1. Read `run_summary.json` — drop-in for dashboard cards.
2. Wire new finding categories — without this, new findings render as "Other".
3. Expose `--dns-only` as a UI toggle.
4. Render `target.started/completed` + `run.test_plan` — kills the "blank dashboard until first finding" problem.
5. Add API-key fields to org settings — unlocks code-search and SaaS-leak coverage.
6. Render `agent.created.category` + `finding.kill_chain` — depth features.

---

## 1. Behavioral changes the wrapper must know about

### 1.1 `--preflight` defaults ON ([#29](https://github.com/ClatTribe/strix/pull/29))

Targets that don't resolve / have no port answer now exit `1` in ~5 seconds with a
rich diagnostic panel, instead of running the full agent loop for 10+ minutes finding
nothing.

**Wrapper actions**:
- Distinguish a preflight-failure exit from a scan-error exit when the wrapper polls
  the strix-runs directory or watches `events.jsonl`. The diagnostic panel is on
  stderr; the run will not produce findings.
- (Optional) Pass `--no-preflight` if the wrapper has a use case for forcing the agent
  loop on an unreachable target (e.g., user explicitly asked to scan an offline staging
  host).
- (Optional) Surface the diagnostic panel text in the wrapper UI when preflight fails —
  it explains *why* the scan exited fast (DNS failed / no open ports) which is more
  helpful than "scan failed".

### 1.2 More findings per scan

A typical clean domain now returns ~6 deterministic findings before the LLM agent loop
even finishes. Sources:
- DNS hygiene gaps (missing SPF / weak DKIM / no CAA / no DNSSEC) — 2–4 findings
- Email security depth (DANE / BIMI / SPF lookups / DKIM key strength) — 0–2 findings
- Shared-hosting info finding from reverse-IP — 0–1 finding
- Stale MTA / known-vulnerable mail server — 0–1 finding

**Wrapper actions**:
- Update the category-to-icon mapping (see [§4](#4-new-finding-categories-to-map)).
- Consider a default filter to hide info-severity unless the user opens "show all".
  Public-by-default cloud assets, MX version disclosures, and shared-hosting notes are
  all info-severity and add up fast.
- The dashboard "findings count" badge will be larger than before for the same target.

### 1.3 New CLI flag `--dns-only` ([#30](https://github.com/ClatTribe/strix/pull/30))

Switches a domain scan to passive recon: skips every step that issues HTTP/TCP probes
to the target's own hosts. Useful for compliance-driven sweeps and pre-authorization
surface mapping.

**Wrapper actions**:
- Expose as a "Passive scan / Surface map only" toggle in the new-scan form.
- The `surface_map.json` artifact will carry `dns_only: true` so the run-detail page
  can render a "Passive recon mode" badge.
- The wrapper should set `STRIX_DNS_ONLY=1` on the strix invocation if it prefers env
  forwarding over the CLI flag — both are honored.

---

## 2. New artifacts to read

### 2.1 `run_summary.json` ([#31](https://github.com/ClatTribe/strix/pull/31))

Persisted to `strix_runs/<run_name>/run_summary.json`. Drop-in for dashboard cards.

```json
{
  "schema_version": 1,
  "run_id": "...",
  "run_name": "...",
  "duration_seconds": 123.4,
  "targets": [{"value": "example.com", "type": "domain"}],
  "findings_summary": {
    "total": 6,
    "by_severity": {"medium": 2, "low": 3, "info": 1},
    "by_category": {"email_security": 3, "dns_security": 2, "info_disclosure": 1}
  },
  "top_findings": [
    {"id": "vuln-0001", "title": "...", "severity": "medium", "category": "...", "cwe": "...", "endpoint": "..."}
  ],
  "checks": {
    "total": 38,
    "by_result": {"vulnerable": 5, "not_vulnerable": 28, "inconclusive": 5},
    "by_category": {...}
  },
  "summary_text": "Scanned example.com (domain); in 2.1m; with 6 finding(s): 2 medium, 3 low, 1 info; primarily in email_security, dns_security, info_disclosure; 38 check(s) ran (28 clean, 5 inconclusive)."
}
```

**Wrapper actions**:
- Read this on scan completion for the run-detail card.
- Use `summary_text` verbatim in email digests, Slack notifications, and CI-gate exit
  messages — it's already plain-text-ready (no markdown).
- Use `findings_summary.by_severity` for the severity badges.
- Use `top_findings[≤5]` for the leaderboard widget on the run-detail page.

### 2.2 `surface_map.json.dns_only` ([#30](https://github.com/ClatTribe/strix/pull/30))

The existing `surface_map.json` artifact now carries a top-level `dns_only: bool`
field. Renders a "Passive recon mode" badge on the run header when true.

---

## 3. New events to consume

All events follow the existing `events.jsonl` shape (`{event_type, payload, status, source, ...}`).

### 3.1 `target.started` / `target.completed` ([#32](https://github.com/ClatTribe/strix/pull/32))

Per-target progress with stable `target_id`. Order:

```
run.configured → target.started × N → ... → target.completed × N → run.summary → run.completed
```

`target.completed` payload:
```json
{
  "target_id": "target-0001",
  "value": "example.com",
  "type": "domain",
  "findings": {
    "total": 2,
    "by_severity": {"medium": 1, "low": 1},
    "by_category": {"dns_security": 2}
  },
  "checks": {
    "total": 1,
    "by_category": {"dns_security": 1}
  }
}
```

**Wrapper actions**:
- Render per-target progress bars / chips for multi-target scans.
- Show a per-target finding count next to each target chip on the run page.

### 3.2 `run.test_plan` ([#35](https://github.com/ClatTribe/strix/pull/35))

Fires right after `target.started` events. Lets the dashboard answer "what is this scan
doing?" *before* findings exist — closes the "blank dashboard until first finding" gap.

```json
{
  "schema_version": 1,
  "scan_mode": "deep",
  "dns_only": false,
  "targets": [
    {
      "target_id": "target-0001",
      "value": "example.com",
      "type": "domain",
      "planned_categories": [
        {"name": "dns_security", "description": "DNSSEC / CAA / wildcard / AXFR / open resolver / dangling NS"},
        {"name": "email_security", "description": "SPF / DMARC / DKIM / MTA-STS / DANE / BIMI"},
        ...
      ],
      "skipped_categories": []
    }
  ],
  "summary_text": "Plan: 1 domain target (example.com) with 11 planned check categories."
}
```

**Wrapper actions**:
- Render the `planned_categories` list as a checklist on the run page, ticking off
  items as `check.completed` events come in.
- `summary_text` works for the scan-start notification.

### 3.3 `run.summary` event ([#31](https://github.com/ClatTribe/strix/pull/31))

Same payload as `run_summary.json`, emitted right before `run.completed` in the event
stream. Use whichever is more convenient — file or event.

### 3.4 `agent.created.payload.category` ([#33](https://github.com/ClatTribe/strix/pull/33))

The existing `agent.created` event now carries an optional `category` field. Values are
short role tags: `auth-attacker`, `webapp-attacker`, `sqli-validator`, `xss-specialist`,
`ssrf-scanner`, `webapp-recon`, etc. (lowercase, hyphenated).

**Wrapper actions**:
- The agent-graph view in webappsec currently renders `Investigator #3` with the
  user's instruction echoed back. With this field set, render the named role instead.
- Backwards-compat: existing events without category still work; payload carries
  `category: null`.

### 3.5 `finding.kill_chain` ([#36](https://github.com/ClatTribe/strix/pull/36))

Multi-step findings now ship with an ordered chain. Emitted right after
`finding.created`, **only when the agent supplied a chain** (silence is honest for
single-step pattern matches).

```json
{
  "report_id": "vuln-0001",
  "fingerprint": "...",
  "title": "Default Admin Credentials Lead to Full User Dump",
  "severity": "high",
  "step_count": 3,
  "chain": [
    {"step_number": 1, "type": "recon", "description": "Found /admin", "tool": "http_request", "evidence": "HTTP 200 with login form"},
    {"step_number": 2, "type": "exploitation", "description": "Logged in admin:admin", "evidence": "302 redirect with session cookie"},
    {"step_number": 3, "type": "impact", "description": "Dumped 1247 users via /admin/users"}
  ]
}
```

Step types are clamped to a fixed 7-value set so the wrapper can hardcode an icon per
type:

| `type` | Suggested icon / color |
|---|---|
| `recon` | 🔍 / blue |
| `discovery` | 📋 / blue |
| `exploitation` | 💥 / orange |
| `escalation` | 🔐 / red |
| `lateral_movement` | 🔀 / red |
| `impact` | ☠️ / red |
| `validation` | ✓ / green |

**Wrapper actions**:
- Render as a numbered timeline next to the finding card.
- The same data is also persisted on the report dict in `vulnerabilities.json`
  (`finding.kill_chain` array) — use the file path if the wrapper prefers
  filesystem-driven rendering.
- Join via `report_id` (primary key) or `fingerprint` (stable across re-runs).

---

## 4. New finding categories to map

If webappsec has a hardcoded `category → icon/label/severity-color` table, these are
the new entries domain scans will surface.

| Category | First seen | Suggested label | Notes |
|---|---|---|---|
| `email_security` | [#19](https://github.com/ClatTribe/strix/pull/19) | "Email Security" | SPF / DMARC / DKIM / MTA-STS / DANE / BIMI gaps |
| `dns_security` | [#19](https://github.com/ClatTribe/strix/pull/19) | "DNS Security" | DNSSEC / CAA / wildcard / AXFR / open resolver / dangling NS |
| `info_disclosure` | existing, expanded | "Information Disclosure" | Now also covers cloud assets, reverse-IP shared hosting, SaaS leaks, code references, MX banner version disclosure |
| `subdomain_takeover` | existing, expanded | "Subdomain Takeover" | Provider matrix expanded 13 → 63 |
| `secret_leak` | [#24](https://github.com/ClatTribe/strix/pull/24) | "Leaked Secret" | **High-severity, `verification_status=needs_review`** — render with a "Needs Review" badge |
| `vulnerable_dependency` | [#26](https://github.com/ClatTribe/strix/pull/26) | "Vulnerable Component" | Stale MTA fingerprints (Sendmail / Exim < 4.95 / Postfix 1-2.x / Exchange 6.x) |
| `authentication_bypass` | [#26](https://github.com/ClatTribe/strix/pull/26) | "Authentication Bypass" | Sample-mail Authentication-Results showing fail/softfail |

Categories already in webappsec that now produce more findings: `info_disclosure` (cloud
assets / reverse-IP / SaaS leaks / code references / MX banner), `subdomain_takeover`
(63 providers).

---

## 5. New API keys to surface in org settings

Several new tools are key-gated. They fail-open cleanly (no error, no crash, just an
`error_reason` in the tool result), but webappsec's tier story benefits from offering
them.

| Env var | Engine PR | What it unlocks | Free tier? |
|---|---|---|---|
| `STRIX_GITHUB_TOKEN` | [#24](https://github.com/ClatTribe/strix/pull/24) | Code-search recon (GitHub & GitLab references + secret-leak detection) | Yes — free GitHub PAT, no scopes needed |
| `STRIX_BING_KEY` | [#28](https://github.com/ClatTribe/strix/pull/28) | SaaS leak discovery (Trello / Notion / Google Docs / Pastebin / Confluence / Airtable) | Yes — Bing Web Search API has 1k queries/month free |
| `STRIX_SECURITYTRAILS_KEY` | existing | Passive DNS history (preferred) | Limited free tier |
| `STRIX_VIRUSTOTAL_KEY` | existing | Passive DNS history (fallback) | Limited free tier |
| `STRIX_VIEWDNS_KEY` | [#23](https://github.com/ClatTribe/strix/pull/23) | Reverse-IP optional secondary | Free tier exists |

Webappsec already forwards `STRIX_*` env into the docker runtime (see
`docker_runtime.py`). It just needs UI to let the user supply these per-account.

**Wrapper actions**:
- Add a "Threat Intel & Recon API Keys" section to the org settings page.
- Surface which features each key unlocks (the table above).
- For self-hosted users, document the env-var names; for SaaS users, store keys
  encrypted and inject at scan-spawn time.

---

## 6. Required: rebuild the sandbox image

The fork added 8 new recon tools registered with `sandbox_execution=True`:

| Tool | PR |
|---|---|
| `subdomain_enum` | [#21](https://github.com/ClatTribe/strix/pull/21) |
| `discover_cloud_assets` (PaaS extensions) | [#22](https://github.com/ClatTribe/strix/pull/22) |
| `reverse_ip_discovery` | [#23](https://github.com/ClatTribe/strix/pull/23) |
| `code_search_for_domain` | [#24](https://github.com/ClatTribe/strix/pull/24) |
| `mx_fingerprint` | [#26](https://github.com/ClatTribe/strix/pull/26) |
| `subdomain_takeover_check` (provider expansion) | [#27](https://github.com/ClatTribe/strix/pull/27) |
| `saas_leak_discovery` | [#28](https://github.com/ClatTribe/strix/pull/28) |
| `domain_recon_pipeline` (`dns_only` parameter) | [#30](https://github.com/ClatTribe/strix/pull/30) |
| `spawn_webapp_subteam` | [#34](https://github.com/ClatTribe/strix/pull/34) |

**Without rebuild**: the agent inside the sandbox will see "tool not found" for the new
tools. This bit us in the prior validation re-run before we rebuilt.

**Build command**:
```bash
cd /path/to/strix-fork
git pull
docker build -f containers/Dockerfile -t strix-sandbox:local .
```

(See [`deploy.md`](deploy.md) for the full fork-build flow.)

The webappsec deploy pipeline should:
1. Pull the latest fork (post-merge of these PRs).
2. Run the rebuild command above.
3. Update whatever image tag the wrapper points at (the `STRIX_IMAGE` config).
4. (Optional) Run a smoke-test scan against a known target to verify the new tools
   load.

---

## 7. Recommended migration order

Smallest-blast-radius first:

1. **Rebuild sandbox image** — required for any of this to work.
2. **Read `run_summary.json`** — biggest UX win, drop-in for the dashboard card. ~1 day.
3. **Wire new finding categories** ([§4](#4-new-finding-categories-to-map)) — without this, new findings render as "Other". ~1 day.
4. **Expose `--dns-only` as a UI toggle** — lets users do safe-by-default surface mapping. ~0.5 day.
5. **Render `target.started/completed` + `run.test_plan`** — closes the "blank dashboard until first finding" UX gap. ~2 days.
6. **Add API-key fields to the org settings UI** — unlocks code-search and SaaS-leak coverage. ~2 days.
7. **Render `agent.created.category`** — replaces "Investigator #3" labels with named specialists. ~0.5 day.
8. **Render `finding.kill_chain` timeline** — depth feature. ~2 days.

Total: ~9 wrapper-engineering-days for full coverage of the engine work shipped in this
batch. Steps 1–4 alone deliver most of the visible UX win in <3 days.

---

## 8. Validation checklist before flipping prod traffic to the new image

After the wrapper changes land:

- [ ] Run a reachable domain (`getedunext.com`, `example.com`) — verify 5–10 findings
      appear, all categories render with proper icons.
- [ ] Run an unreachable target (`nx-not-a-real-domain.invalid`) — verify the
      preflight panel surfaces in the wrapper UI and the run exits cleanly without
      consuming LLM tokens.
- [ ] Run a `--dns-only` scan — verify `surface_map.json.dns_only` is `true` and the
      "Passive Recon Mode" badge renders.
- [ ] Verify `run_summary.json` is read on the dashboard within ~1s of run completion.
- [ ] Verify `target.started/completed` events render per-target progress chips.
- [ ] Verify `run.test_plan.summary_text` shows on the scan-start screen before any
      findings.
- [ ] Trigger a finding with `kill_chain` (run a deep web-app scan against a known-vuln
      target) — verify the timeline renders.
- [ ] Verify code-search + SaaS-leak findings surface when API keys are configured;
      verify the absence of those findings doesn't break the UI when keys are missing.

---

## 9. Forward-looking — wrapper UX gaps surfaced by [`overall.md`](overall.md)

Sections §1-§8 above are the integration delta for engine PRs #19-#36. After the §10 expert-pentester audit cycle landed (#71-#76) and the §7.2 web-app expert audit closed (#77-#81), [`overall.md`](overall.md) categorised the architecture through four lenses and surfaced wrapper-UX gaps that aren't covered above. They're collected here so each one has a tracking row; engine-side counterparts live in [`roadmap.md` §17](roadmap.md).

Items are grouped to match `overall.md` §4 (configuration → live-scan → report → wrapper-AI → operational), with **§9.6** capturing gaps `overall.md` *didn't* surface but real customers ask for.

### 9.1 Configuration UX

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Pre-scan profile selector.** "External recon" / "Web pentest" / "API audit" / "Domain audit" / "Compliance scan" / "Deep scan". Each maps to a `scan_mode` + tool-enable subset. Today the wrapper exposes a flat target field; should expose intent. | Today's flat `target` UI hides the configuration richness Strix supports. Profiles let non-tech users say "I want a SOC2 evidence pack" rather than tweak flags. | Wrapper config layer; sends mapped flags to Strix. | M |
| ⬜ | **Threat-intel API-key onboarding wizard.** Walks the user through getting free keys for VT, OTX, GreyNoise, Shodan, Censys, GSB, AbuseIPDB, NVD, Perplexity, HIBP. Detects which keys are present; shows coverage tier explicitly: "you have 5/10 sources configured. Missing: GreyNoise + VT (lower IR-triage signal); Shodan + Censys (no attacker-eye-view of exposed services)." | The §10 threat-intel stack is invisible until the user knows what to configure. The wizard turns "what keys?" into "click here to register". | Wrapper UI; reads configured keys from environment / org settings. | M |
| ⬜ | **Compliance preset toggle.** "PCI-DSS", "SOC 2 readiness", "HIPAA", "ISO 27001", "NIST 800-53". Emphasises specific finding categories in the report and adds compliance-control mappings (when the engine's §16 control-mapping rows ship). | B2B customers buy security tools to check audit boxes. The toggle makes that explicit. | Wrapper renderer + filter layer over engine's `compliance_controls` field (engine §16). | S |
| ⬜ | **Daily-scan workflow.** Schedule recurring scans against the same target. Surface engine's `kev_diff_check` (#75) findings prominently as the daily highlight; pull `cross_target.correlation` (engine §17.1) into a dashboard widget. | Daily scans + KEV-diff + threat-feed-ingest is the single most valuable operational pattern Strix unlocks; today the wrapper doesn't expose it. | Wrapper scheduler + dashboard. | M |
| ⬜ | **Target wizard with `--preflight` integration.** Validates URL/domain/IP/repo, runs preflight before queuing. Avoids the "scan ran 10 min and found nothing because target was down" failure. | `--preflight` (#29) ships engine-side; the wrapper should expose it before queue. | Wrapper pre-scan validator. | S |

### 9.2 Live scan UX (during the run)

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **OODA loop visualisation.** Render the 4-stage loop with the agent's current phase highlighted. Translates `phase.entered` events (engine §11) into a live state machine. | Operators watching a 30-min scan need a live signal. Today the wrapper's scan view is opaque until findings emit. | Wrapper UI consuming `phase.entered` / `phase.completed` events. | M |
| ⬜ | **Tool-call ATT&CK chain visualisation.** Render each `tool.execution.started` event (with `actor.mitre_techniques` from engine #66) as an ATT&CK kill-chain visualisation. Defenders see the simulated attack path live. | The MITRE ATT&CK tagging shipped in #66 is wasted unless visualised. Defenders' SOC teams react to ATT&CK chain views, not flat tool-call logs. | Wrapper UI consuming `tool.execution.started.actor.mitre_techniques`. | M |
| ⬜ | **Per-finding live cards.** As findings emit, render in `priority_label` order with `description_plain` + `recommended_action` prominent. Hide CWE/CVE behind a "show technical details" toggle. Today the wrapper renders findings as a flat list. | Non-tech users (the wrapper's primary persona) need plain-English first; technical details on demand. | Wrapper UI. | S |
| ⬜ | **Coverage progress bar.** From engine's `run.test_plan` (#35) + `check.completed` (#11) events, show "12/14 planned check categories complete." When categories slip to `inconclusive`, surface them prominently. | Today users can't tell whether a clean scan is "we tested everything and it's clean" or "we couldn't test half of it." | Wrapper UI consuming `run.test_plan` + `check.completed`. | S |
| ⬜ | **Live cost meter.** When engine's per-event token usage ships (engine §5 / §17.2), show running $-cost with budget alerts. | Today users have no live cost signal. Wrapper-side budget caps (against engine `--max-cost`) need this widget. | Wrapper UI consuming per-event cost stream. | S |
| ⬜ | **Agent-uncertain inbox.** When engine emits `agent.uncertain` (engine §17.4), wrapper surfaces an in-app prompt asking the operator to confirm/deny a high-stakes branch. If unanswered within timeout, agent proceeds with `confidence=low`. | Closes the human-in-the-loop gap for high-stakes branches without forcing every scan to be supervised. | Wrapper inbox + WebSocket / SSE channel back to engine. | M |

### 9.3 Report UX (post-scan)

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Non-tech report as the default landing page.** Plain-English summary of "what was found" / "what to fix first" / "why it matters". Renders from `description_plain` + `recommended_action` + `priority_label` + `exploitation_in_wild_plain`. Today the default is a CWE/CVE-heavy markdown report. | Wrapper's primary persona is the developer / non-tech user. The default rendering should match. | Wrapper renderer. | S |
| ⬜ | **Tech report behind a toggle.** Full CWE/CVE/CVSS/CPE/ATT&CK technique IDs for security-engineer consumers. | Two-personas-one-report. | Same renderer, alternate template. | S |
| ⬜ | **Compliance overlay.** Cross-reference findings to PCI-DSS / SOC 2 / HIPAA / etc. controls. Pulls from engine's `compliance_controls` field (engine §16). | Auditors review findings *by control*. The wrapper's compliance overlay is the auditor-friendly view. | Wrapper renderer + filter. | M |
| ⬜ | **SIEM-rule export with format converter.** From engine's `sigma_rules_for_technique` (#74), render Sigma rules per finding so the customer's blue team can deploy detection. Add a "copy as SPL / KQL / Lucene / EQL / SumoLogic" widget per rule (sigma-cli converters wrapped in the UI). | Sigma rules are universal; the customer's SIEM speaks one specific dialect. The converter is the last-mile productivity win. | Wrapper UI + sigma-cli subprocess. | M |
| ⬜ | **Triage workflow.** Per-finding "fix" / "won't fix" / "false positive" buttons. Persists `verification_status` updates back to the engine via a triage-feedback file (engine §12 continuous-learning hooks). | Closes the loop on triage. Pairs with engine's continuous-learning hooks. | Wrapper UI + write-back path. | M |
| ⬜ | **Exploit verifier widget.** From engine's `exploit_refs` (#62), per CVE finding show "12 PoCs available across ExploitDB / Metasploit / GitHub." Click → expanded list with stars-as-credibility-signal. | The engine collects this; the wrapper should surface it. Critical for "is this exploitable today?" triage. | Wrapper UI consuming `exploit_refs` finding-decoration. | S |
| ⬜ | **Daily-summary email / Slack / Teams notification.** Subscribers per target receive: KEV-diff findings, new high-severity discoveries, completed-scan list. | Async signal for the daily-scan workflow. | Wrapper notification layer + per-user subscription model. | M |
| ⬜ | **Cross-scan diff.** Between scan N and N+1: new findings, fixed findings, regressions. Today users compare reports manually. | Lets the wrapper become a vuln-tracking system, not just a scan runner. | Wrapper diff renderer; needs a per-finding stable `fingerprint` (engine #14 ships this). | M |
| ⬜ | **Finding-fix verification rescan.** "I fixed CVE-X; rescan only that endpoint to confirm." Targeted rescan without a full re-scope. | Closes the fix-verify loop without paying for a full scan. | Wrapper-side scan-narrowing layer; uses engine's `--seed-url` / `--scope-mode diff` flags. | S |
| ⬜ | **Evidence / screenshot capture per finding.** Auto-capture rendered HTTP request/response for each finding; for browser-driven probes, attach screenshot. Bug-bounty / audit deliverables expect this. | Today findings have URLs and JSON; no rendered evidence. Bug-bounty triage rejects unverified findings. | Wrapper post-scan enrichment layer; runs a headless browser against each finding URL. | M |

### 9.4 Wrapper-side AI features (built ON TOP of engine output)

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Plain-language Q&A on the scan.** "Why is this finding high?" / "How do I fix CVE-X?" / "Which findings are credential-stuffing risks?" RAG over the scan's `events.jsonl` + `vulnerabilities.json`. | Non-tech users don't read JSON. Q&A is the natural interaction. | Wrapper RAG layer; the engine's structured outputs are a clean retrieval corpus. | L |
| ⬜ | **AI-generated executive summary.** 1-paragraph C-suite-friendly summary. Inputs: `run.summary` event + top 5 findings. | C-suite buyers read 1 paragraph; the report is for security teams. | Wrapper LLM call at scan-end. | S |
| ⬜ | **Auto-prioritisation against threat-intel context.** Cross-reference findings against KEV / HIBP / `threat_feed_ingest` data to surface "fix this first because the customer's industry is being actively targeted by APT-X using this CVE." | Severity is rule-based; prioritisation is contextual. The wrapper's AI layer is the right place to do contextual prioritisation. | Wrapper LLM call against engine's threat-intel cache. | M |
| ⬜ | **AI-driven finding-cluster narrative.** Group related findings into a single story (e.g., "Your auth surface has 6 findings: 1 CSRF + 2 weak cookies + 1 HIBP + 2 password-policy → credential-stuffing risk; fix order X, Y, Z"). When engine emits `finding.cluster` events (engine §17.5) the wrapper renders the engine's cluster; otherwise wrapper computes its own. | A wall of 47 findings is unreadable; 5 narratives is. | Wrapper LLM call OR engine `finding.cluster` consumption. | M |
| ⬜ | **Customer-context override.** Let the user paste a "we run on AWS / our threat model says this matters more / our biggest customer is in finance" paragraph; AI re-prioritises findings against that context. | Same finding has different severity at different orgs. The customer-context paragraph is the input to that adjustment. | Wrapper LLM call; passes context as system-prompt to the prioritisation pass. | M |

### 9.5 Operational ergonomics

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Cost dashboard.** From engine's per-event token usage (engine §5), show $X spent per scan, per target. Budget alerts. | Cost transparency is an enterprise sale-blocker. | Wrapper analytics layer. | M |
| ⬜ | **Cache hit-rate monitor.** Across the threat-intel tool caches (`vt_cache`, `otx_cache`, etc.). Helps users understand why repeat scans are fast. | Operational transparency; explains why daily-scan workflow is cheap. | Wrapper reads `~/.strix/<tool>_cache/` stats. | S |
| ⬜ | **Free-tier vs paid-tier coverage.** Explicitly call out which intel sources are free vs paid; recommend upgrades when the user hits free-tier rate limits. Today this is invisible. | Customers don't realise they're hitting limits until findings disappear. | Wrapper rate-limit instrumentation. | S |
| ⬜ | **Run history archive.** Searchable by target, date, finding, CWE, CVE, ATT&CK technique. Engine's `run_meta.json` + `events.jsonl` are sufficient inputs. | Vuln-tracking-system requirement. | Wrapper search index over historical runs. | M |
| ⬜ | **Skill / tool inventory page.** Show what Strix can do, with which keys configured, which version of nuclei templates is in use (from `nuclei_template_update` #68), which threat-intel sources are operational. | This is the wrapper's "demo to a CISO" page. | Wrapper inventory page; reads engine tool registry. | S |

### 9.6 Gaps `overall.md` did NOT surface (real customer asks)

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Multi-user collaboration.** Comment on findings, assign to engineer, mark "in review", @-mention. | Real customers have security teams, not solo operators. Solo-mode UX is an enterprise blocker. | Wrapper collaboration layer (comments / assignments / activity feed). | L |
| ⬜ | **RBAC / SSO / audit logging.** Who can run scans? Who can see results? Who can change org settings? SSO via SAML / OIDC. Audit log for sensitive actions. | Enterprise procurement gate. | Wrapper auth layer + audit-log table. | L |
| ⬜ | **Multi-tenant data-isolation contract.** Documented + tested isolation between customer scans (storage, network, secret material). | Required for SOC 2 readiness on the wrapper itself. | Wrapper architecture review + isolation tests. | M |
| ⬜ | **Auto-PR / auto-ticket integrations.** GitHub PR from a finding (where the engine has a suggested patch — engine §15 "auto-remediation"). Linear / Jira / GitHub Issues ticket creation per finding with severity / priority / fix-time-estimate fields mapped. | Closes the loop from finding to engineering work. | Wrapper integration adapters per platform. | M |
| ⬜ | **SIEM push integration.** Beyond the Sigma-rule export (§9.3), push the findings themselves to Splunk HEC / Elastic / Sentinel webhook in their native shape. | Customer's SOC team consumes findings as events, not as reports. | Wrapper integration adapters. | M |
| ⬜ | **Bug-bounty submission template export.** Per finding, generate a HackerOne / Bugcrowd / Intigriti / YesWeHack-shape submission package: CVSS vector, repro steps, evidence URL, recommended-CWE, suggested-bounty-tier. | Closes the loop from finding to bounty payout. Bug-bounty triage rejects 60%+ of poorly-formatted submissions. | Wrapper renderer + per-platform schema. | M |
| ⬜ | **Per-finding playback / re-execute.** "Re-run this exact probe" button on each finding card. Useful for verifying a fix landed without a full rescan. | Targeted reproducibility. Pairs with `--checkpoint` / `--resume` (engine §17.4). | Wrapper-driven engine call. | S |
| ⬜ | **Customer-data redaction in shared reports.** Before sharing a report externally (with auditor / pentest customer / management), redact PII / hostname / token-shaped strings from the findings. Toggleable per-share. | GDPR / customer-data-protection workflow. Today share-the-report is share-everything. | Wrapper renderer with PII-redaction pass (regex + LLM-judged). | M |
| ⬜ | **Status-page-style public attestation page.** Per customer: a public-facing page that shows "last full scan: 2026-04-15; 0 critical findings open; SBOM available" — without leaking the findings themselves. Used by the customer to signal hygiene to *their* customers. | Vendor-trust signal in B2B sales. The wrapper's customer can point their procurement-process to the page. | Wrapper public renderer + per-customer privacy controls. | M |

---

## 10. Zero-FP rendering — surface the engine's deterministic signals

After PR #98-#104, the engine emits new structured signals the wrapper should
render to give developers / non-tech operators an at-a-glance view of finding
quality. The data is already in `vulnerabilities.json` + `events.jsonl`; this
section is purely about wrapper-side rendering.

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **`detected_by` confidence pip on each finding card.** When a finding has `detection_count ≥ 2`, render a green "high confidence" pip with a tooltip listing the detectors (`semgrep + sql_injection`). | [#98](https://github.com/ClatTribe/strix/pull/98) — `detected_by[]`, `detection_count`, `finding.detection_corroborated` event | Per-finding card; live update on `finding.detection_corroborated` event arrival. |
| ⬜ | **Reachability badge.** "Found in dead code" / "On auth path" / "Route reachable (1-hop)". Pull from `reachability_score` + `reachability_evidence`. Findings demoted to `info` from a higher severity should show the original severity crossed-out alongside the demotion reason. | [#99](https://github.com/ClatTribe/strix/pull/99) — `reachability_score`, `reachability_evidence`, `severity_demoted_from`, `severity_promoted_from_reachability`, `finding.reachability_scored` event | Per-finding card; sortable / filterable column in the findings table. |
| ⬜ | **Supply-chain dependency panel.** Render `external_scripts[]` and `external_links[]` from `sri_audit` runs — third-party CDN list with red/green per-asset SRI status. The polyfill.io supply-chain context belongs in a tooltip ("if this CDN is compromised…"). | [#100](https://github.com/ClatTribe/strix/pull/100) — `sri_audit` returns the structured asset arrays. | Per-target dashboard card; "Supply chain" tab. |
| ⬜ | **CSV-injection probe-matrix table.** Show the 5 payload classes × `payload_in_export` boolean grid. Helps operators see at a glance which payload classes the export endpoint sanitises and which it doesn't. | [#101](https://github.com/ClatTribe/strix/pull/101) — `csv_injection_check.probes[]`. | Per-finding evidence panel. |
| ⬜ | **Race-condition concurrency visualisation.** "Round 1: 7/30 succeeded; Round 2: 8/30 succeeded" rendered as paired histograms. Makes the N+1-verification story legible to non-technical users. | [#102](https://github.com/ClatTribe/strix/pull/102) — `race_condition_check.rounds[]` with per-request status histogram. | Per-finding evidence panel. |
| ⬜ | **Compliance overlay panel.** Toggle (PCI / SOC2 / HIPAA / ISO 27001 / NIST 800-53) renders findings grouped by the controls they implicate. Pulls from `compliance_controls` (engine #103). Pair with a "compliance gap" view: which controls have ZERO findings (i.e. unverified). | [#103](https://github.com/ClatTribe/strix/pull/103) — `compliance_controls`, `data_classification`, `compliance_posture`. | Top-level dashboard tab; per-finding section. |
| ⬜ | **Data-class breach-reporting flag.** When `data_classification ∈ {pii, phi, pci, credentials}` AND severity ≥ medium, render a "BREACH NOTIFICATION REQUIRED?" prompt linking to the customer's IR runbook. GDPR Art. 33 / HIPAA require notification within 72 hours. | [#103](https://github.com/ClatTribe/strix/pull/103) — `data_classification`. | Per-finding card; daily-summary email. |
| ⬜ | **Live cost meter.** Stream `llm.request.completed` events; render a live $-spent counter + per-agent breakdown. Budget alert when `cumulative.cost` crosses configurable threshold (e.g. 80% of `--max-cost`). | [#104](https://github.com/ClatTribe/strix/pull/104) — `llm.request.completed` event with cumulative cost. | Top-bar widget during scan; alert banner at threshold. |
| ⬜ | **Stuck-scan banner.** When `run.heartbeat` events stop arriving for >120 seconds, render a "scan idle" banner with a "cancel" button. The Strix engine's heartbeat throttle is 60s, so 120s = two missed beats. | [#104](https://github.com/ClatTribe/strix/pull/104) — `run.heartbeat` event. | Top-bar widget during scan. |
| ⬜ | **Exit-code-aware completion screen.** Read the documented exit codes for the post-scan summary: 0 = ✅ clean, 1 = ❌ scan failed, 2 = ⚠ findings, 3 = 💸 budget exceeded, 130/143 = 🛑 cancelled. Each maps to a distinct UI state with an action prompt ("Review findings" / "Investigate failure" / "Top up budget" / "Resume"). | [#104](https://github.com/ClatTribe/strix/pull/104) — `strix.interface.exit_codes`. | Post-scan summary screen. |
| ⬜ | **Compliance posture dashboard widget.** Render `compliance_posture.cadence_status` ("In compliance" / "Overdue") + `audit_log_retention_days` + `days_since_last_scan`. Auditor-friendly at-a-glance view. | [#103](https://github.com/ClatTribe/strix/pull/103) — `run_meta.json.compliance_posture`. Wrapper computes `days_since_last_scan` by reading prior runs. | Compliance dashboard tab. |

## 11. Wrapper-side complements to engine zero-FP detectors

These items are the wrapper-side companions to the engine's zero-FP work. Some
extend findings with customer-context the engine deliberately doesn't carry
(threat-model adjustments, data-class overrides). Others provide the operator
flow needed to act on findings (auto-PR a fix, file a Jira ticket, route to
the right team).

| | Item | Notes |
|---|---|---|
| ⬜ | **Auto-PR the SRI fix from a missing-integrity finding.** GitHub PR that adds the `integrity=` + `crossorigin=` attributes to the offending tag with a generated `sha384-...` hash. The engine emits `external_scripts[]` with full asset URLs; the wrapper computes the hash and writes the PR. | Engine has the data; wrapper has the GitHub-app integration. |
| ⬜ | **Auto-PR the CSV-injection fix.** Wrap each round-tripped field write site with the `'`-prefix sanitiser. Detect language from the codebase (Python / Java / Node) and propose the matching idiomatic fix. | Higher complexity than SRI; needs code-mod tooling. |
| ⬜ | **Race-condition fix-pattern selector.** Per-language guidance: "for PostgreSQL use `SELECT ... FOR UPDATE`; for MongoDB use `findAndModify` with `upsert: false`; for Redis use SETNX." Render after every race finding. | Static guidance; the engine's `recommended_action` covers it but the wrapper can structure it as an interactive picker. |
| ⬜ | **Customer threat-model context overlay.** Let users tag specific endpoints / files as "auth path" / "billing path" / "admin path"; the wrapper boosts the engine's reachability score with this user-supplied weight. The engine #99 reachability score is generic; the wrapper adds customer-specific. | Wrapper-side: engine doesn't know what's "billing-critical" without operator input. |
| ⬜ | **Data-class override.** Some endpoints handle PII even when the engine's classifier doesn't catch it. Let users pin `data_classification` per endpoint; the wrapper applies the override on render. | Operator-only knowledge. |
| ⬜ | **Compliance-control evidence pack.** The §10 "Compliance overlay panel" lets operators select controls and emits a PDF / DOCX evidence pack mapping each finding to the framework's control row. Suitable to hand to an auditor without further work. | Renders the engine's `compliance_controls` field as the per-finding evidence trail. |
| ⬜ | **Exit-code-driven CI gate config.** Templates for GitHub Actions / GitLab CI / CircleCI that read Strix's exit codes and gate on configurable thresholds. Default: block on `1` / `3`; warn on `2` (findings); succeed on `0`. | Engine ships the contract; wrapper ships the CI templates. |
| ⬜ | **Heartbeat-driven slack-pipeline notification.** When `run.heartbeat` shows `seconds_idle > N`, post an alert to a configured Slack/Teams webhook. | Wrapper-only — no engine work. |
| ⬜ | **Cost-anomaly detector.** Cross-scan: track `cumulative.cost` per scan. When a scan exceeds 2× the rolling-30-day average, emit a wrapper-side anomaly notification. | Wrapper-only: requires history, which is a wrapper concern. |

---

## 12. Wrapper-side companions to engine PRs #106–#110

The §10/§11 sections covered PRs #98–#104. This section adds the wrapper-
side rendering / integration surface for the next batch shipped in PRs
#106–#110.

### 12.1 Stable lowercase severity (engine #106)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Drop the wrapper's defensive `severity.toLowerCase()` calls.** The engine's machine-readable surfaces (CSV / JSON / events.jsonl) now emit lowercase severity by contract. The wrapper has been defensively `.toLowerCase()`-ing on read; that's now a no-op cost it can drop. | [#106](https://github.com/ClatTribe/strix/pull/106) — every machine-readable surface emits canonical lowercase severity. Markdown still uppercases for display. | Wrapper renderer simplification + a unit test that pins the contract on the wrapper side too (so an upstream regression surfaces fast). |
| ⬜ | **CI severity-gate config templates.** Now that `severity == "high"` is a stable string match, ship GitHub Actions / GitLab CI / CircleCI templates that gate on configurable severity thresholds via a one-liner `jq` filter on `vulnerabilities.json`. | Same. | Wrapper-side CI templates. |

### 12.2 Agent / target context on tool.execution.* (engine #107)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Live-activity pane: "Agent X (auth-attacker) on api.example.com running send_request"** rendered from the new `actor.{agent_name, agent_category, target}` keys on every `tool.execution.*` event. Today the wrapper's live pane shows `agent-1234` + tool name; the new context lets it render a human-readable phrase. | [#107](https://github.com/ClatTribe/strix/pull/107) — `agent_name`, `agent_category`, `target` on every `tool.execution.started` / `tool.execution.updated`. | Live-activity pane redesign — three-column layout (agent role, target, tool). |
| ⬜ | **Per-target tool-call timeline.** Group `tool.execution.*` events by `actor.target` to render a per-target timeline — wrapper user can filter "show only what ran against admin.example.com". | Same — `target` is now a queryable field on every event. | Wrapper analytics + filter UI. |
| ⬜ | **Per-specialist activity dashboard.** Group by `actor.agent_category` (the §1 sub-agent role tag — `auth-attacker` / `ssrf-scanner` / etc.) to render "what each specialist did" per scan. Pairs with engine #89 specialist registry. | Same — `agent_category` is now a queryable field on every event. | Wrapper analytics. |

### 12.3 DOM-XSS static probe (engine #108)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Code-snippet preview on DOM-XSS findings.** Render `code_locations[].snippet` (±1 line context, 320-char-clipped per line) inline on the finding card. Highlight the source token (`location.hash`) and the sink token (`innerHTML`) with distinct colors. | [#108](https://github.com/ClatTribe/strix/pull/108) — `code_locations: [{file, line, snippet}]` with annotated source/sink. | Per-finding evidence panel; syntax-highlighter widget. |
| ⬜ | **"Verify in browser" button.** When a `dom_xss_static_probe` finding has `verification_status=pattern_match`, surface a "Validate via headless browser" action that re-runs the engine's §8.2 Validator on just that finding. | The Validator (§8.2 / §17.1) graduates pattern_match → verified. | Wrapper triage button + engine call. |
| ⬜ | **Per-source / per-sink coverage map.** From the bundle of DOM-XSS findings across a scan, render a 13×10 source×sink matrix showing which combinations the scan exercised. Helps auditors see what was checked. | The engine's `matches[]` carries `source` + `sink_class`. | Wrapper coverage viz. |

### 12.4 Cross-subdomain cookie / JWT scoping (engine #109)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Cohort-scope diagram.** Per scan with ≥2 in-scope subdomains, render a cohort diagram: nodes = subdomains, edges = "shared session cookie" / "JWT accepted". Findings from `cookie_jwt_scoping_check` paint the edges — red for high (cross-acceptance), orange for medium, gray for info. | [#109](https://github.com/ClatTribe/strix/pull/109) — `records[]` with `kind`, `host`, `accepted_by`, etc. | Cohort visualization on the per-target dashboard. |
| ⬜ | **Cookie-attribute matrix.** For every cookie name shared across the cohort, render a Domain × SameSite × Secure × HttpOnly × scope grid per host. Inconsistencies (the §109 medium finding) jump out visually. | Same — `records[]`. | Cohort dashboard matrix. |
| ⬜ | **JWT cross-acceptance N+1 verification rendering.** Render the baseline-401 + authed-200 + body-shape-diff evidence trail per cross-acceptance finding. Makes the "this is a real finding, not a guess" story legible. | Engine emits all four data points (`baseline_status`, `authed_status`, body comparison) on the record. | Per-finding evidence panel. |
| ⬜ | **"Drop Domain= attribute" auto-PR.** When a session cookie has parent-domain scoping, generate a PR that removes the `Domain=` attribute (so the cookie defaults to host-only). Detect framework (Express / Django / Flask / Rails) and propose the framework-idiomatic edit. | Engine record has `host` + `cookie_name` + `domain_attr`. | Wrapper auto-fix integration. |

### 12.5 DNS hygiene bundle (engine #110)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Subdomain scheme badge.** Per subdomain row in the surface map, render a colored badge: 🟢 `https_only` / 🟢 `both` / 🔴 `http_only` / 🟡 `ipv6_only` / ⚪ `neither`. Pulls from `scheme_asymmetry` on every triage result. | [#110](https://github.com/ClatTribe/strix/pull/110) — `scheme_asymmetry` field on triage results. | Surface-map dashboard column. |
| ⬜ | **IPv6 column on the subdomain table.** Show the `ipv6` field next to `ip`. v6-only subdomains (rare today, growing) get visual highlight. | [#110](https://github.com/ClatTribe/strix/pull/110) — `ipv6` field on every triage result. | Surface-map table column. |
| ⬜ | **DKIM selector-coverage chart.** Per email domain, render which of the ~45 selectors were probed and which (if any) returned a key. Highlights gaps in the customer's DKIM coverage. | [#110](https://github.com/ClatTribe/strix/pull/110) — expanded `_DKIM_SELECTORS`; `dkim` check returns `selectors_found`. | Email-security dashboard widget. |
| ⬜ | **IDN-homograph warning banner.** When `org_fingerprint` resolves a punycode candidate (`xn--…`), render a top-banner warning: "An IDN homograph of your domain is registered. Consider defensive registration / SRP." | [#110](https://github.com/ClatTribe/strix/pull/110) — punycode candidates flow through the existing typosquat-resolved finding pipeline. | Wrapper banner + per-finding decoration. |
| ⬜ | **HSTS preload nudge from HTTP-only findings.** When the engine emits a CWE-319 finding for a subdomain serving plaintext HTTP, surface a "Submit `<apex>` to the Chrome HSTS preload list" CTA — that's the long-term cohort-wide fix. | [#110](https://github.com/ClatTribe/strix/pull/110) — `cleartext_transmission` category finding. | Per-finding action button + link to https://hstspreload.org/. |

---

## Reference

- Engine roadmap (source of truth): [`roadmap.md`](roadmap.md)
- Strategic overview (the source for §9): [`overall.md`](overall.md)
- Fork-build guide: [`deploy.md`](deploy.md)
- Engine PRs covered by §1-§8: #19, #20, #21, #22, #23, #24, #25, #26, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36
- Engine PRs informing §9: #41, #42, #44, #46, #47, #48, #49, #52, #53, #55, #56, #57, #58, #59, #60, #61, #62, #63, #64, #65, #66, #67, #68, #69, #71, #72, #73, #74, #75, #76, #77, #78, #79, #80, #81
- Engine PRs informing §10-§11: #98 (cross-tool dedup + detected_by), #99 (reachability scoring), #100 (SRI audit), #101 (CSV-formula injection), #102 (race-condition prober), #103 (compliance control mapping + data classification + posture), #104 (per-event token usage + run.heartbeat + exit-code contract)
- Engine PRs informing §12: #106 (stable lowercase severity), #107 (agent + target context on `tool.execution.*`), #108 (DOM-XSS static probe), #109 (cross-subdomain cookie/JWT scoping), #110 (DNS hygiene bundle — DKIM expansion + IDN homographs + HTTP/HTTPS asymmetry + IPv6/AAAA)
- Engine PRs informing §13: #112 (LLM retry backoff + `llm.retry_attempted`), #113 (`--max-cost` / `--max-input-tokens` self-exit + `run.terminated`), #114 (SIGTERM/SIGINT graceful cancel + `run.cancelled`), #115 (zero-FP `secrets_scan`), #116 (WebSocket handshake audit), #117 (`--branch <ref>`), #118 (`finding.dismissed` event + `dismiss_finding` tool), #119 (DNSSEC algorithm strength + RRSIG hygiene), #120 (SVCB / HTTPS DNS records), #121 (`--quiet` mode), #122 (DNS rebinding feasibility), #123 (`--surface-map-only` recon-only mode), #124 (CIDR / IP-range targets)
- Engine PRs informing §14: #126 (legal-document presence — privacy / cookie / DPA / terms / imprint / accessibility), #127 (cryptographically-signed audit trail — per-event hash chain + HMAC / external signer), #128 (logging / monitoring posture detection — 0-6 score across redaction + reporting + rate-limit), #129 (`--compliance-pack` evidence bundle — 8-file auditor artifact with manifest + signature), #130 (GRC SaaS export shapes — Vanta / Drata / Hyperproof / Secureframe / ServiceNow / generic), #131 (SBOM extraction from web targets — CycloneDX 1.5 from CDN URLs + headers + HTML markers), #132 (MFA enforcement attestation — 4-point posture score per auth surface), #133 (`--vendor-mode` + 0-100 vendor-risk score)

---

## 13. Wrapper-side companions to engine PRs #112–#124

This section adds the wrapper-side rendering / integration surface for
the §4 resilience + §7-§8 zero-FP detector batch shipped in PRs
#112–#124.

### 13.1 Resilience + cost gating (engine #112, #113, #114)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Live "upstream is rate-limited" banner.** When an `llm.retry_attempted` event fires, surface a non-blocking banner showing the upstream status code, retry attempt N/M, and ETA-of-next-retry. Today the wrapper shows nothing while strix is sleeping through a 45s backoff — operators wonder "is it stuck?" | [#112](https://github.com/ClatTribe/strix/pull/112) — `llm.retry_attempted` event with `{attempt, max_retries, wait_seconds, status_code, error_type}`. | Live-pane banner; auto-dismiss on next `llm.request.completed`. |
| ⬜ | **Cost-cap configurator UI.** Per-target / per-org budget input that propagates to `--max-cost` and `--max-input-tokens` on scan launch. Reads back `run.terminated{reason: "budget_exceeded"}` events to flip the run-status-card to "stopped: budget" with a "raise budget" CTA. | [#113](https://github.com/ClatTribe/strix/pull/113) — `run.terminated` event + `EXIT_BUDGET_EXCEEDED (3)`. | Wrapper config layer + run-status renderer. |
| ⬜ | **Cancel button → SIGTERM.** Wire the wrapper's "stop scan" button to send SIGTERM (not SIGKILL) and trust the contract: strix flushes events, emits `run.cancelled`, exits 143. Status card flips to "cancelled" with no half-written state. | [#114](https://github.com/ClatTribe/strix/pull/114) — `run.cancelled` event + `EXIT_SIGTERM (143)`. | Wrapper UI + process-control layer. |

### 13.2 Zero-FP detectors (engine #115, #116, #118, #119, #120, #122)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Secret-scan rotation playbook card.** Each finding from `secrets_scan` gets a vendor-specific rotation playbook ("Rotate AWS access key: aws iam create-access-key …", "Rotate GitHub PAT: …"). Engine emits the masked snippet so the wrapper renders the playbook without the secret value. | [#115](https://github.com/ClatTribe/strix/pull/115) — `secrets_scan` finding with `code_locations[].snippet` (masked). | Per-finding action panel; vendor-keyed playbook templates. |
| ⬜ | **WebSocket cohort visualisation.** When a scan probes ≥2 WebSocket endpoints (CDN + main app + admin app), render a matrix: rows = endpoints, columns = (auth-on-upgrade, origin enforcement, subprotocol echo). Cells colour-coded green/yellow/red. Operators see consistency / inconsistency at a glance. | [#116](https://github.com/ClatTribe/strix/pull/116) — `websocket_audit` records per endpoint. | Per-cohort dashboard widget. |
| ⬜ | **"Investigated and dismissed" panel.** Render `finding.dismissed` events on the per-target dashboard alongside confirmed findings. Group by `dismissal_reason`; let operators filter "show me all `framework_default_blocked` dismissals" to validate that the agent's ruling is consistent with the operator's threat model. | [#118](https://github.com/ClatTribe/strix/pull/118) — `finding.dismissed` event with closed-enum `dismissal_reason`. | Per-target dashboard tab; filterable list. |
| ⬜ | **DNSSEC posture badge.** Per-domain card: ✅ DNSSEC modern algorithm + signatures fresh; ⚠ deprecated algo OR signature ≤7 days; 🔴 broken algo OR signatures expired. Pulls from `_check_dnssec` result + finding emission. | [#119](https://github.com/ClatTribe/strix/pull/119) — DNSSEC algorithm + RRSIG hygiene findings. | Per-domain dashboard card. |
| ⬜ | **Service-binding (SVCB/HTTPS) info card.** Render the structured `_check_svcb_https` output: ALPN protocols, ipvN hints, ECH presence, target aliases. Highlight when ipvN hints could leak origin IPs that should stay behind the CDN. | [#120](https://github.com/ClatTribe/strix/pull/120) — `_check_svcb_https` returns structured `{alpn, ech_configured, ipv4hints, ipv6hints, targets}`. | Per-domain dashboard card. |
| ⬜ | **DNS rebinding × SSRF correlation.** When the engine emits both a "DNS rebinding feasibility" finding (#122) AND any SSRF-shaped finding on the same target, render a correlation badge: "Combined risk: rebinding + SSRF sink → internal-network pivot". Helps operators prioritise the pair. | [#122](https://github.com/ClatTribe/strix/pull/122) + existing SSRF detectors. | Wrapper correlation engine; per-target risk renderer. |

### 13.3 CLI / operator ergonomics (engine #117, #121, #123, #124)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Branch picker on repository scan.** UI dropdown listing the repository's branches; selection passes through as `--branch <ref>`. The wrapper records the resolved ref on the scan-history card so operators can compare scans across branches. | [#117](https://github.com/ClatTribe/strix/pull/117) — `--branch` plumbed through to `target_info.details.branch`. | Wrapper scan-launch UI; scan-history renderer. |
| ⬜ | **CI mode preset.** "Run as CI" toggle that enables `--quiet` + `--non-interactive` + sane defaults. Generates a copy-pasteable CI snippet (GitHub Actions / GitLab CI). | [#121](https://github.com/ClatTribe/strix/pull/121) — `--quiet` flag. | Wrapper preset UI. |
| ⬜ | **"Recon nightly, scan daily" pattern.** Pre-built workflow template that runs `--surface-map-only` on a nightly cron AND triggers targeted scans against the discovered surface daily. Reads `surface_map.json` to drive the targeted scans' scope. | [#123](https://github.com/ClatTribe/strix/pull/123) — `--surface-map-only` mode. | Wrapper workflow templates. |
| ⬜ | **CIDR target preview.** When operator types a CIDR target, preview the host count BEFORE submission ("/24 = 256 hosts; /20 = 4096 (cap)"). Reject inline at the safety cap. | [#124](https://github.com/ClatTribe/strix/pull/124) — engine accepts CIDR with `num_hosts` in target details. | Wrapper target-input validation. |

---

## 14. Wrapper-side companions to engine PRs #126–#133 (Compliance, GRC, audit)

The §13 sections covered PRs #112–#124 (resilience + zero-FP + CLI ergonomics).
This section adds the wrapper-side rendering / integration surface for the
§16 Compliance / GRC / Audit batch shipped in PRs #126–#133.

### 14.1 Legal-document presence (engine #126)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Legal-document compliance card per target.** Per-target card listing the 6 doc classes (privacy / cookie / terms / DPA / imprint / accessibility) with ✅ / ❌ / 🔗 link-rel-discovered. Hover shows the canonical URL. | [#126](https://github.com/ClatTribe/strix/pull/126) — `legal_compliance_probe` returns a structured `documents[]` list. | Per-target compliance dashboard card. |
| ⬜ | **GDPR-class doc absence alert.** When privacy_policy / cookie_policy / dpa is absent, render a top-level alert linking to the wrapper's "publish a privacy policy" walk-through. | [#126](https://github.com/ClatTribe/strix/pull/126) — low-severity finding on absence. | Wrapper alert layer. |

### 14.2 Cryptographically-signed audit trail (engine #127)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Audit-trail verification UI.** Operator pastes/uploads `events.jsonl` + `run.signature.json` + their signing key. Wrapper verifies (a) chain integrity, (b) signature against the chain terminal hash. Surfaces tampering with line-level diff. | [#127](https://github.com/ClatTribe/strix/pull/127) — `audit_trail.verify_signature` + per-event `prev_event_hash` + `event_hash` + `run.signature.json`. | New verification page in the wrapper. |
| ⬜ | **HSM signing UI.** First-class `STRIX_SIGNING_CMD` config — operator selects "AWS KMS" / "Hashicorp Vault Transit" / "GCP KMS" / custom; wrapper generates the appropriate signing command + sets the env var on scan launch. | [#127](https://github.com/ClatTribe/strix/pull/127) — `STRIX_SIGNING_CMD` contract. | Wrapper config layer + per-platform signing command templates. |
| ⬜ | **Signed-bundle preview on share.** When operator shares a run externally (link, downloadable bundle), pre-flight check that the chain is intact + the signature verifies. Block share when verification fails. | [#127](https://github.com/ClatTribe/strix/pull/127). | Wrapper share-flow guard. |

### 14.3 Logging / monitoring posture (engine #128)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Monitoring-posture gauge.** Per-target gauge widget showing the 6-point score (identifying-headers / 4 monitoring buckets / rate-limit). Click to expand the breakdown with per-recommendation action items. | [#128](https://github.com/ClatTribe/strix/pull/128) — `monitoring_posture_check` returns structured `{score, identifying_headers, monitoring_headers, rate_limit}`. | Per-target dashboard widget. |
| ⬜ | **CSP-with-report-uri auto-generator.** When the monitoring score lacks `csp_reporting`, the wrapper offers a one-click "generate a CSP for me" — generates a CSP based on the observed scripts/styles + a `report-uri` to a wrapper-hosted endpoint. | [#128](https://github.com/ClatTribe/strix/pull/128) + wrapper CSP introspection. | Wrapper CSP-generator widget. |

### 14.4 Compliance evidence pack (engine #129)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **One-click "download for auditor" button.** Calls strix with `--compliance-pack <tmp>`; bundles the resulting `<tmp>/<run_id>/` directory into a zip and serves it. Pre-fill auditor-friendly filename: `<customer>-<scan-date>-<run_id>.zip`. | [#129](https://github.com/ClatTribe/strix/pull/129) — `--compliance-pack` flag + bundle layout. | Wrapper download-pipeline UI. |
| ⬜ | **Auditor-share link.** Time-bounded shareable link to the compliance-pack zip; auditor browses inline (manifest.json verifier + control_attestation viewer + findings.csv table). Audit log captures every auditor read. | [#129](https://github.com/ClatTribe/strix/pull/129). | New auditor-share renderer. |
| ⬜ | **Cross-scan attestation diff.** Between scan N and N+1: which controls had findings → which were remediated. Renders the customer's "evidence of remediation" trail across audit cycles. | [#129](https://github.com/ClatTribe/strix/pull/129) — `control_attestation.md` per-control rollup. | Wrapper diff renderer over historical packs. |

### 14.5 GRC SaaS exports (engine #130)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **One-click upload to GRC platform.** Operator picks Vanta / Drata / Hyperproof / Secureframe / ServiceNow; wrapper calls strix with `--export-format <platform>`, takes the resulting JSON, and POSTs to the platform's import endpoint with the operator's API key. | [#130](https://github.com/ClatTribe/strix/pull/130) — per-platform JSON exporters. | Wrapper integration layer per platform. |
| ⬜ | **GRC platform health badges.** Show which platforms are configured (✅ Drata + ✅ Vanta + ❌ ServiceNow) + last-export timestamp per platform. | [#130](https://github.com/ClatTribe/strix/pull/130). | Wrapper config dashboard. |

### 14.6 SBOM (engine #131)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **SBOM viewer + diff.** Render `sbom.cdx.json` as a sortable / filterable table (name / version / purl / detected_via / confidence). Diff across runs to surface "package added in this scan" / "package version changed" / "vulnerable component appeared". | [#131](https://github.com/ClatTribe/strix/pull/131) — `sbom.cdx.json` artifact in run dir. | New SBOM viewer page. |
| ⬜ | **SBOM → GHSA / OSV cross-reference.** Wrapper-side enrichment: every component with `version` is queried against OSV/GHSA at render time, surfacing CVE / KEV indicators alongside the SBOM table. | [#131](https://github.com/ClatTribe/strix/pull/131) + existing CVE-lookup data. | Wrapper enrichment + UI. |
| ⬜ | **CycloneDX export download.** Plain "Download SBOM (CycloneDX 1.5)" button on every web-target run summary. | [#131](https://github.com/ClatTribe/strix/pull/131). | Wrapper download button. |

### 14.7 MFA attestation (engine #132)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **MFA-posture badge.** Per-target badge showing the 4-point MFA score with hover-breakdown (login_tokens / challenge_keys / webauthn_header / mfa_setup_paths). Tied to the auditor's "show me MFA is enforced" question with a one-line attestation copy-paste. | [#132](https://github.com/ClatTribe/strix/pull/132) — `mfa_attestation_check` returns structured score + breakdown. | Per-target dashboard badge + auditor-attestation widget. |
| ⬜ | **WebAuthn migration prompt.** When the score is medium / no WebAuthn header observed, surface a wrapper-side guide: "Most user-friendly + least-phishable MFA = WebAuthn / Passkeys. Walk-through here." | [#132](https://github.com/ClatTribe/strix/pull/132). | Wrapper migration-guide page. |

### 14.8 Vendor-risk score (engine #133)

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Vendor-risk score gauge on every target.** Always shown — `vendor_risk` lands in `run_meta.json` regardless of `--vendor-mode`. Big numeric gauge (0-100) with color-coded band (low_risk green / medium_risk amber / high_risk red). Hover reveals top 3 deduction categories. | [#133](https://github.com/ClatTribe/strix/pull/133) — `run_metadata.vendor_risk` block with deductions_by_category + recommendation. | Per-target dashboard hero widget. |
| ⬜ | **Vendor-onboarding workflow.** Operator imports a vendor list (CSV); wrapper triggers `--vendor-mode` scans against each; produces a sortable table of (vendor, score, band, top_category) for the procurement team. | [#133](https://github.com/ClatTribe/strix/pull/133). | New vendor-onboarding workflow page. |
| ⬜ | **Vendor-score trend chart.** Cross-scan: track the vendor-risk score for a target over time. Useful for ongoing supplier monitoring (SOC 2 CC9.0 / ISO 27001 A.15.2). | [#133](https://github.com/ClatTribe/strix/pull/133). | Wrapper analytics — historical run aggregation. |
| ⬜ | **"Why is this vendor a high_risk?" explainer.** When `band=high_risk`, render a dedicated page summarising: top deduction categories, the specific findings driving each category's deduction, the engine's `recommendation` field, and links to per-finding remediation. | [#133](https://github.com/ClatTribe/strix/pull/133). | Wrapper explainer page. |

---

## 15. Minimum-viable-AI-security-engineer (wrapper companions for engine §18)

The engine's [`roadmap.md`](roadmap.md) §18 picks the top 10 cross-cutting items that, taken together, are the bar Strix needs to clear to be unimpeachable as an AI-native security engineer. **5 of 10 shipped engine-side** in PRs #137 / #138 / #139 / #140 / #141 / #142 (rows 2, 3, 4, 9, 10). This section is the wrapper-side companion: the rendering, ingest, and triage UX the wrapper needs so the operator actually feels the engine improvements.

The pattern across these subsections: the engine emits a structured signal; the wrapper turns it into a glanceable widget, a one-click action, or a feedback artifact the engine reads on the next scan. **Without the wrapper companions, most of the §18 work is invisible to the non-tech operator.**

| Engine §18 row | Engine PR | Wrapper subsection |
|---|---|---|
| 2 — Closed FP feedback loop (RLHF Phase 1) | [#142](https://github.com/ClatTribe/strix/pull/142) | §15.1 |
| 3 — HAR / Burp ingestion | [#141](https://github.com/ClatTribe/strix/pull/141) | §15.2 |
| 4 — Reasoning-trace + confidence + counter-proof | [#137](https://github.com/ClatTribe/strix/pull/137) | §15.3 |
| 9 — Active-hypothesis + agent self-audit | [#138](https://github.com/ClatTribe/strix/pull/138) + [#140](https://github.com/ClatTribe/strix/pull/140) | §15.4 |
| 10 — Tool-output provenance / trust-taint | [#139](https://github.com/ClatTribe/strix/pull/139) | §15.5 |

### 15.1 Closed FP feedback loop (engine #142)

Engine PR #142 ships RLHF Phase 1: per-finding `features` block, post-hoc `trajectory.jsonl`, wrapper-feedback ingestion (`feedback.jsonl` → `--feedback-from`), and auto-dismiss on prior-FP fingerprint. The wrapper closes the loop on three sides: it WRITES the feedback, READS the trajectory + features, and surfaces auto-dismissals so operators trust the loop.

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Triage verdict UI on every finding.** A `tp / fp / partial_tp / needs_review / out_of_scope` button cluster on every finding card. Clicking writes one line to `<run_dir>/feedback.jsonl` (or the cumulative `~/.strix/feedback.jsonl` for cross-run). Verdict closed-enum mirrors engine; FP path also captures one of the 13 closed-enum `fp_reason` values. | [#142](https://github.com/ClatTribe/strix/pull/142) — `feedback.jsonl` schema in [`docs/rlhf-design.md`](docs/rlhf-design.md). Engine reads via `--feedback-from <PATH>` or `STRIX_FEEDBACK_FROM` env. | Wrapper triage page; per-finding action component. |
| ⬜ | **Feedback writeback is the labeler's primary action.** The labeler doesn't write a free-text comment; they pick a verdict + reason from the closed enum. The wrapper persists that as a JSONL line — schema-stable, machine-readable, ready for the engine on next scan. Labeler can supply optional `notes` (free text), but the engine strips notes before re-attaching attribution to a finding artifact (privacy). | Same — engine sanitises `prior_label_attribution`. | Wrapper labeler form — closed-enum dropdown + optional free-text. |
| ⬜ | **Auto-dismissed banner on findings.** When the engine emits a finding with `auto_dismissed=true` + `auto_dismissal_reason="prior_human_fp"`, render a slate-grey banner: "Auto-dismissed — labeler marked an identical finding as `<fp_reason>` on `<labeled_at>`." Show the labeler's role + label_id for traceability. Banner has a "Force-show / re-promote" button that writes a `verdict=tp` label, undoing the auto-dismiss next scan. | Same — engine emits `finding.auto_dismissed` event with `prior_label_attribution` payload. Finding has `auto_dismissed`, `auto_dismissal_reason`, `severity_pre_auto_dismissal`, `prior_label_attribution`. | Per-finding card + force-show action. |
| ⬜ | **FP-loop policy switcher in operator settings.** Operator picks between `conservative` (default — one FP, zero TP), `aggressive` (latest verdict wins), `off`. Wrapper writes `STRIX_FP_AUTO_DISMISS=<value>` into the engine container env. Default UX should show the `conservative` mode is on so operators understand auto-dismissal is happening. | Same — engine reads `STRIX_FP_AUTO_DISMISS` env. | Settings page; per-org config. |
| ⬜ | **Reasoning trail viewer powered by `trajectory.jsonl`.** For each finding, render the per-finding trajectory — the agent that emitted, the tool calls in order, the alternatives that were dismissed (with reasons), the iteration count, the time-to-emit. Helps the labeler decide TP/FP and helps the operator trust the engine. | [#142](https://github.com/ClatTribe/strix/pull/142) — `trajectory.jsonl` written at run-end with `events`, `iterations_to_emit`, `time_to_emit_seconds`, `dismissed_alternatives`, `exploration_breadth`. | Per-finding "How did the engine arrive at this?" panel. |
| ⬜ | **Trajectory health gauge on every scan.** Aggregate trajectory stats render on the run-summary page: median iterations, median time-to-emit, mean exploration breadth. Outliers (e.g. 50+ iterations on one finding) flag as "engine struggled — possible refinement opportunity." | Same — `trajectory.jsonl` + `events.jsonl` aggregation. | Run-summary dashboard widget. |
| ⬜ | **Dismissed-alternative review.** Engine's `trajectory.jsonl[].dismissed_alternatives` lists what the agent considered and rejected (with reason). Render these as a "what we ruled out" section per finding — counter-evidence the operator can sanity-check. Reveals false-negatives ("the agent dismissed this for the wrong reason"). | [#142](https://github.com/ClatTribe/strix/pull/142) + #138 hypothesis-lifecycle events. | Per-finding "alternatives considered" sub-section. |
| ⬜ | **FP-classifier scorecard, post-Phase-2.** When the engine ships the FP-classifier (`docs/rlhf-design.md` Phase 2 / A5, future PR), it'll score every finding's `fp_probability` from the existing `features` block. Wrapper renders this as a 0-100 bar on every finding card; operator can sort by it. The features block is *already* attached to every finding by [#142](https://github.com/ClatTribe/strix/pull/142) — wrapper can pre-build the UI today. | [#142](https://github.com/ClatTribe/strix/pull/142) — `report["features"]` block per finding (schema-versioned). Phase 2 adds `fp_probability`. | Per-finding card; sortable list view. |
| ⬜ | **Cumulative cross-run feedback file.** Wrapper maintains a single `~/.strix/feedback.jsonl` (or per-org equivalent) and propagates it to every scan. The engine's discovery order (explicit → `STRIX_FEEDBACK_FROM` env → `<run_dir>/feedback.jsonl` → `~/.strix/feedback.jsonl`) means cumulative feedback applies cross-run automatically. Wrapper just has to write the file in a stable location and not delete it between runs. | [#142](https://github.com/ClatTribe/strix/pull/142) — engine reads home-fallback path automatically. | Wrapper persistence layer; per-org feedback database. |

### 15.2 HAR / Burp project ingestion (engine #141)

Engine PR #141 ships HAR 1.2 + Burp project XML stream-parsers via `ingest_har_file` / `ingest_burp_file`. The wrapper closes the loop by giving non-tech operators a one-click upload UI and visualising the coverage uplift the ingestion produces.

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **HAR / Burp upload UI.** Drag-drop `.har` / `.xml` file. Wrapper validates size (<= configured max), uploads into the engine container at a known path, then triggers the engine via `ingest_har_file(path)` / `ingest_burp_file(path)` tool. Most pen-tests start with a Burp recording — this is the on-ramp. | [#141](https://github.com/ClatTribe/strix/pull/141) — both tools auto-dedup per (method, canonical-url) and emit `traffic.ingested` event. | Wrapper upload form on the per-target dashboard. |
| ⬜ | **Coverage-uplift summary post-ingest.** When `traffic.ingested` event fires, render a summary card: "Imported `<N>` requests covering `<K>` unique endpoints. `<X>` were not yet in the surface map — added." Operator gets immediate feedback that the upload mattered. | Same — `traffic.ingested` payload has unique-endpoint count + new-endpoint count. | Live-activity pane post-import banner. |
| ⬜ | **Auth-class detection rendering.** Engine detects bearer / basic / cookie auth from the recording's `Authorization` / `Cookie` headers (NAME-only — values are redacted). Wrapper renders a per-host badge: "Bearer detected" / "Cookie session detected." Helps operator confirm the auth flow Burp captured matches what the engine will replay. | [#141](https://github.com/ClatTribe/strix/pull/141) — `auth_class` per host on the import summary. | Surface-map dashboard auth column. |
| ⬜ | **Sensitive-header redaction notice.** Banner: "We redacted these header values: `Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`, `X-XSRF-Token`, `Proxy-Authorization`, `WWW-Authenticate`. The engine sees header NAMES only; the values never enter scan artifacts." Compliance teams ask about this — make the answer visible. | [#141](https://github.com/ClatTribe/strix/pull/141) — engine redacts on ingest (line-level sanitisation). | Upload-confirmation modal. |
| ⬜ | **Param-union UX.** Engine's per-(method, url) dedup unions query+body params across duplicate requests. Wrapper renders the full param-union per endpoint as a list — useful for operator to spot "Burp captured 12 params for /search but only 4 are tested by default." | Same — `traffic.ingested.endpoints[].params` list. | Per-endpoint detail pane. |
| ⬜ | **Burp-project-as-scope-config.** When operator uploads a Burp `.xml` with site-tree filters, wrapper offers to import Burp's scope-include / scope-exclude as the engine's `scope_mode` config. Saves the manual re-config step. | Engine reads scope from CLI flag; wrapper translates Burp scope rules to `--scope-mode` + `--scope-include`. | Wrapper config-import workflow. |

### 15.3 Finding-quality signals (engine #137)

Engine PR #137 ships `confidence` (0.0–1.0), `reasoning_trace` (≤20 bullets × 320 chars), `counter_proof` ({description, evidence}), and `reproducibility_token` per finding. The wrapper closes the loop by rendering each as a glanceable widget so operators can sort, sift, and dedupe by quality.

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Confidence-bar on every finding card.** Render `confidence` as a 0-100 bar with color band (≥0.8 green / 0.5-0.8 amber / <0.5 grey). Defaults follow engine's verification_status mapping (verified=1.0, pattern_match=0.7, inconclusive=0.4, could_not_verify=0.2) but agents can supply explicit values that override. | [#137](https://github.com/ClatTribe/strix/pull/137) — `report["confidence"]`. | Per-finding card primary widget. |
| ⬜ | **Sortable & filterable by confidence.** List-view column. Filter "show only confidence >= 0.7" reduces the auditor's queue to high-quality findings instantly. | Same — finding-level field. | List view UI. |
| ⬜ | **Reasoning-trace bullets rendered inline.** Show all `reasoning_trace[]` bullets directly on the finding card under a "Why we believe this is exploitable" header. Each bullet is ≤320 chars (engine-enforced) so the UI doesn't overflow. The single biggest "is this AI talking to me, or guessing?" tell. | [#137](https://github.com/ClatTribe/strix/pull/137) — `report["reasoning_trace"]: list[str]`, capped at 20 × 320. | Per-finding card body. |
| ⬜ | **Counter-proof block rendering.** When engine attaches `counter_proof: {description, evidence}`, render in a slate-bordered block: "Possible alternative explanation:" + the description + the evidence excerpt. This is the auditor-grade "we considered this might not be a real finding" signal. Increases trust massively. | [#137](https://github.com/ClatTribe/strix/pull/137) — `report["counter_proof"]`, with description ≤1024 chars + evidence ≤2048 chars. | Per-finding card; collapsible counter-proof block. |
| ⬜ | **Reproducibility-token deduplication on the wrapper side.** The engine already merges same-fingerprint findings via `reproducibility_token`. The wrapper can use the token as a stable cross-scan dedup key — same `reproducibility_token` across two scans means "this is the same finding, second observation, not a new one." Show the second observation as "seen 2 times across runs." | [#137](https://github.com/ClatTribe/strix/pull/137) — `report["reproducibility_token"]` (SHA-256 over reasoning_trace + kill_chain + target_state). | Wrapper persistence layer; cross-scan diff UI. |
| ⬜ | **Per-finding "send to Slack with full reasoning" action.** Slack message body is the title + severity + reasoning_trace bullets + counter_proof. The Slack reader gets the full "why" without clicking through. Pairs with §11 reporting integration. | All four #137 fields. | Wrapper Slack/Teams integration. |

### 15.4 Active-hypothesis + agent self-audit (engine #138 + #140)

Engine PR #138 ships shared `active_hypotheses.jsonl` for sister-specialists to coordinate without RPC. PR #140 ships `agent_self_audit` that runs between phases and emits gaps. The wrapper closes the loop by visualising the cross-specialist coordination state and surfacing self-audit verdicts as live-scan health signals.

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Active-hypothesis live-pane.** Per scan, render the rolling list of open hypotheses: status (`open` / `confirmed` / `dismissed`), surface, category, originating agent, hypothesis text. Polls `active_hypotheses.jsonl` (or consumes the `hypothesis.opened/confirmed/dismissed` events). Operator sees what the agents are actively investigating. | [#138](https://github.com/ClatTribe/strix/pull/138) — `<run_dir>/active_hypotheses.jsonl`; `hypothesis.opened` / `.confirmed` / `.dismissed` events. | Live-scan dashboard new pane. |
| ⬜ | **Hypothesis lifecycle timeline.** Per surface (e.g. `/api/login`), render a timeline of hypotheses opened against it across the scan: which agent opened, which confirmed/dismissed, with reasons. Auditor sees the investigation-trail at the surface level (not the per-finding level). | Same — `active_hypotheses.jsonl` keyed by (surface, category). | Per-surface dashboard. |
| ⬜ | **Sister-specialist coordination indicator.** Render a small badge on each surface: "🟡 under investigation" when `is_surface_under_investigation` is true. Helps the operator understand "the engine isn't done with this yet — don't triage as 'no findings here' yet." | [#138](https://github.com/ClatTribe/strix/pull/138) — `is_surface_under_investigation(surface, category?)` API. | Surface-map dashboard column. |
| ⬜ | **Self-audit gate-breach banners.** When the engine emits `agent.self_audit` with stuck sub-agents OR skipped categories, render a banner: "Engine self-audit between `<phase>` and `<next_phase>` flagged: `<concern>`. Categories skipped: `<list>`. Stuck sub-agents: `<list>`." Operator can intervene mid-scan or note the gap on the report. | [#140](https://github.com/ClatTribe/strix/pull/140) — `agent.self_audit` event with `phase_completed`, `categories_covered`, `categories_skipped`, `stuck_sub_agents`, `concern`. | Live-scan dashboard alert; appended to run report. |
| ⬜ | **Per-phase coverage receipt.** After each phase ends, the self-audit event lists `categories_covered`. Wrapper renders this as a coverage receipt: "✅ Phase 1 (recon) — covered: subdomain_enum, dns_hygiene, cloud_assets, port_scan." Builds operator confidence that nothing was silently skipped. | [#140](https://github.com/ClatTribe/strix/pull/140) — `categories_covered` array. | Per-phase progress card. |
| ⬜ | **Phase-skip auditor warning.** If `phase_starting` ever skips one of the canonical 4 phases (recon / exploit / validate / report), or if `categories_skipped` is non-empty without an explanation in `concern`, the wrapper surfaces this as an auditor-visible warning on the report. Compliance asks: "Did the engine actually complete a full phase set?" — this answers it. | Same — engine validates phase against canonical set. | Final report `# Coverage Assertions` augmentation. |

### 15.5 Tool-output provenance / trust-taint (engine #139)

Engine PR #139 ships a 6-value provenance enum (`trusted_source / intel_feed / target / operator_input / framework / mixed`) on every `tool.execution.started/updated` event under `actor.provenance`. The wrapper closes the loop by visualising provenance and alerting when target-controlled output flows into trusted-decision paths (the indirect-prompt-injection class).

| | Item | Engine signal | Wrapper surface |
|---|---|---|---|
| ⬜ | **Provenance badge per tool call in the live-activity pane.** Each tool-call entry gets a colored badge from the 6-value enum: 🟢 trusted_source / 🟢 intel_feed / 🔴 target / 🟠 operator_input / ⚪ framework / 🟠 mixed. Helps operator see at a glance what's safe-to-trust output vs. what's adversary-controlled. | [#139](https://github.com/ClatTribe/strix/pull/139) — `actor.provenance` on every `tool.execution.started/updated`. | Live-activity pane decoration. |
| ⬜ | **Indirect-prompt-injection alert.** When a downstream tool consumes output from an upstream `target`-provenance tool, surface a slate banner: "Engine consumed adversary-controlled response when calling `<downstream_tool>` — content may contain prompt-injection." Pairs with future engine #84 sanitisation. | Same — provenance chain visible across tool calls per agent. | Live-activity pane alert. |
| ⬜ | **Provenance audit trail in the final report.** Append a "# Trust Boundary Crossings" section listing every time target-provenance output flowed into a trusted-decision pathway. Compliance teams reviewing the engine's behavior can audit this — most security tools today have no such concept. | Same — derivable from `events.jsonl` provenance trail. | Final report new section. |
| ⬜ | **Provenance-by-tool reference card.** Operator-settings page renders a table: tool name → declared provenance. Lets the operator audit "are we treating CVE lookup as `trusted_source` correctly? Is there a tool I think should be `target` that's still defaulting to `framework`?" Drives wrapper-side override config. | [#139](https://github.com/ClatTribe/strix/pull/139) — `get_tool_provenance(name)` API on engine. | Wrapper settings reference page. |

---

## 16. Operator UX north-star: the AI-security-engineer storyboard

The §15 components are the building blocks. This section sketches the operator-facing storyboard the wrapper should evolve toward: the AI-security-engineer experience the §18 engine work makes possible, but only if the wrapper composes it.

| | Item | Why it matters |
|---|---|---|
| ⬜ | **"Reasoning + counter-proof + provenance" combined card.** Per finding, single component renders all three quality signals together: confidence bar (top), reasoning trace (middle), counter-proof + provenance trail (bottom). The single card is "the AI security engineer's casefile" — auditor reads top-to-bottom. | This is the core artifact. Engine builds it (§15.1, 15.3, 15.5); wrapper composes it. |
| ⬜ | **"Live engineer working" scan view.** Replaces the legacy log-tail view. Live pane shows: current phase + self-audit verdict + open hypotheses + active tool calls (with provenance badge) + emerging findings. Looks like watching a senior pen-tester work. | Engine emits all the pieces (§15.1, 15.4, 15.5); wrapper assembles. |
| ⬜ | **"Trust the engine progressively" UX.** New users start with auto-dismiss in `off` mode (visibility), graduate to `conservative` (default), power users opt into `aggressive`. UI nudges the upgrade as the labeler's TP/FP queue stabilises. | Engine ships the policy primitives (§15.1); wrapper handles progressive rollout. |
| ⬜ | **"This finding has a stable identity" cross-scan view.** Use `fingerprint` + `reproducibility_token` to thread findings across scans. Operator sees: "this finding was first reported on Jan 5, has been observed in every scan since, was labeled FP once on Feb 12, and was force-shown via re-promote on Feb 14." A continuous casefile, not 47 separate scan reports. | All primitives shipped engine-side; pure wrapper persistence + UI. |
| ⬜ | **"Coverage receipt" on every report.** Final report ends with a coverage receipt: phases run × categories covered × ingested traffic × hypotheses resolved × auto-dismissals × FP-loop labels written. The operator hands this to compliance: "here's evidence the engine did its job." | Engine emits all the primitives (§15.1, 15.2, 15.4); wrapper aggregates. |
