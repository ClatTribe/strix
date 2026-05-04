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

## Reference

- Engine roadmap (source of truth): [`roadmap.md`](roadmap.md)
- Strategic overview (the source for §9): [`overall.md`](overall.md)
- Fork-build guide: [`deploy.md`](deploy.md)
- Engine PRs covered by §1-§8: #19, #20, #21, #22, #23, #24, #25, #26, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36
- Engine PRs informing §9: #41, #42, #44, #46, #47, #48, #49, #52, #53, #55, #56, #57, #58, #59, #60, #61, #62, #63, #64, #65, #66, #67, #68, #69, #71, #72, #73, #74, #75, #76, #77, #78, #79, #80, #81
- Engine PRs informing §10-§11: #98 (cross-tool dedup + detected_by), #99 (reachability scoring), #100 (SRI audit), #101 (CSV-formula injection), #102 (race-condition prober), #103 (compliance control mapping + data classification + posture), #104 (per-event token usage + run.heartbeat + exit-code contract)
