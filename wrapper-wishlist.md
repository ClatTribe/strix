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

## Reference

- Engine roadmap (source of truth): [`roadmap.md`](roadmap.md)
- Fork-build guide: [`deploy.md`](deploy.md)
- Engine PRs covered: #19, #20, #21, #22, #23, #24, #25, #26, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36
