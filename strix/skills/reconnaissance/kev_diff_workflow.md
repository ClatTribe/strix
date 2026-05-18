---
name: kev-diff-workflow
description: Daily-scan workflow using CISA KEV diff — surface newly-actively-exploited CVEs against the asset inventory
triggers: [kev, kev diff, daily scan, actively exploited, cisa, vulnerability prioritisation]
---

# CISA KEV Diff Workflow

CISA's Known Exploited Vulnerabilities (KEV) catalog lists CVEs with **confirmed in-the-wild exploitation**. New entries land daily. The right way to use it isn't "score every CVE against KEV" — it's "**diff today's KEV against my asset inventory + yesterday's KEV; alert on new matches**." That's `kev_diff_check` (PR #75) and the workflow this skill describes.

## Why KEV Matters

| Question | What it tells you |
|---|---|
| "Is CVE-X actively exploited right now?" | KEV is the canonical "yes" signal |
| "Should we patch CVE-X this sprint or next quarter?" | KEV inclusion = this sprint |
| "What's the regulatory ask?" | KEV-included CVEs have a `kev_due_date` for federal civilian agencies (BOD 22-01); private sector cites this in audits |
| "Is the vendor exaggerating CVSS?" | KEV is independent verification — exploitation actually observed |

Compare to plain CVSS: a CVSS-9.8 with no in-the-wild exploitation might wait 90 days. A CVSS-6.5 on KEV gets patched today. KEV is the priority disambiguator.

## How Strix Uses KEV

| Mechanism | What it does |
|---|---|
| **Auto-decoration** (PR #9) | Every CVE finding gets `is_kev`, `kev_due_date`, `kev_ransomware_use`, `kev_added_to_catalog_date` |
| **`kev_diff_check`** (PR #75) | Compares today's KEV catalog vs the last scan's findings; emits a `kev.newly_added` event per match |
| **Daily-scan cadence** | Wrapper schedules `--scan-mode quick --kev-diff-only` daily for cheap KEV-only refreshes |
| **Severity tuning** | `is_kev:true` upgrades finding severity by one bucket (medium → high, high → critical) |

## Operational Runbook

### Step 1 — initial inventory scan

```bash
# Full scan to populate the asset + CVE inventory
strix --target https://app.example.com --scan-mode standard --output-dir runs/initial/
```

Output: `findings.jsonl` with CVE findings, each decorated with `is_kev` from the cached KEV catalog.

### Step 2 — daily KEV-diff cron

```bash
# Wrapper schedules this every morning
strix kev_diff_check \
  --prior-run runs/yesterday/ \
  --kev-source https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

Behaviour:
1. Fetch today's KEV catalog (cached for 24h with stale-fallback).
2. Compare against yesterday's KEV → set of new CVE IDs.
3. Cross-reference new KEV CVEs against `runs/yesterday/findings.jsonl`.
4. For each match, emit a `kev.newly_added` finding event with the prior finding's full context.

### Step 3 — alert routing

```bash
# Wrapper subscribes to kev.newly_added events
strix-runner --watch-events kev.newly_added --route-to slack#sec-alerts

# Or pull from events.jsonl directly
jq -c 'select(.kind == "kev.newly_added")' runs/today/events.jsonl \
  | mail -s 'New KEV match' security@target.com
```

### Step 4 — escalation triggers

```
event: kev.newly_added
fields:
  cve_id: CVE-2025-XXXX
  kev_due_date: 2026-06-15
  kev_ransomware_use: true              ← P0 if true
  affected_targets: [host_a, host_b]
  asset_class: web_application
  prior_severity: high
```

Routing:
- `kev_ransomware_use: true` → page on-call immediately
- `kev_due_date < 30 days` → priority engineering ticket
- Otherwise → next-sprint ticket

### Step 5 — coverage report (weekly)

```bash
# How many KEV CVEs affect the org?
jq -c 'select(.is_kev == true)' runs/today/findings.jsonl | wc -l

# Which assets have the most KEV exposure?
jq -c 'select(.is_kev == true) | .endpoint' runs/today/findings.jsonl | sort | uniq -c | sort -rn

# Time-to-remediation for past KEV findings
# (requires wrapper-side ledger: finding-first-seen vs finding-resolved timestamps)
```

## Workflow Variants

### Variant A — full org-wide daily KEV check (cheap)

Use `--profile initial` + `--skip-if-unchanged` + KEV-only filter:
```bash
strix --target-list assets.jsonl \
      --profile initial \
      --skip-if-unchanged \
      --filter-finding-category dependency_cve,os_cve \
      --kev-only
```

200-target org → ~5 minutes total; 95% of targets exit early via skip-if-unchanged. Only NEW CVE findings surface.

### Variant B — KEV-only verification re-probe

When a KEV match appears, re-probe the specific endpoint to confirm exploitability:
```bash
# The wrapper auto-triggers when kev.newly_added fires
strix --target https://affected-host \
      --scan-mode deep \
      --instruction "Verify CVE-2025-XXXX exploitability with live PoC. KEV ransomware use: true."
```

### Variant C — ransomware-priority subset

```bash
# Filter to KEV entries flagged ransomware
curl -s 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' \
  | jq '.vulnerabilities[] | select(.knownRansomwareCampaignUse == "Known") | .cveID'
```

Cross-reference against findings; ransomware-confirmed entries are the highest priority.

## What KEV Doesn't Tell You

- **Reachability**: KEV says exploitation exists in the wild, not that your specific install is reachable. Combine with `sca/reachability.py` (Python taint) to filter false positives.
- **Compensating controls**: a WAF rule, network segmentation, or feature flag may neutralise a KEV CVE. KEV decoration doesn't track those.
- **Zero-days**: KEV adds CVEs *after* the CVE-ID is published. True 0-days are absent until disclosure.

## False Positives

- CVE-ID matches but the affected version isn't actually deployed — confirm via `sbom_extract` / `scan_sca_lockfiles` version check.
- KEV catalog occasionally retracts entries (rare); stale-fallback might cite a retracted CVE for 24h.
- Multiple CPE matches per CVE — confirm the matching CPE actually corresponds to your stack.

## Pro Tips

1. **Daily cron is the right cadence**: KEV updates daily on the CISA side. Anything less frequent and you miss the first 24h of in-the-wild exploitation.
2. **Patch under-CVSS KEV first**: a CVSS-6.5 on KEV beats a CVSS-9.8 off KEV every time.
3. **Wrapper digest** is the killer feature: morning email "3 new KEV matches affecting your prod" + per-finding remediation steps + priority labels. Snyk doesn't do this proactively; we should.
4. **Combine with EPSS**: KEV is binary (in / out). EPSS is continuous. Together: KEV ∪ EPSS-top-10% covers most actionable exploits.
5. **Cite KEV in fix tickets**: "CVE on CISA KEV catalog (`is_kev=true`, ransomware use: `true`, due date: 2026-06-15)" makes the ticket non-negotiable.

## Validation

1. The `kev_diff_check` artifact lists new KEV entries since the last successful run.
2. `findings.jsonl` rows for affected assets carry `is_kev: true` and full `kev_*` fields.
3. `run_summary.json` reports KEV match count, ransomware-use subset, and overdue-by-due-date subset.

## Summary

KEV is the priority disambiguator. Auto-decorate every CVE; diff daily; route on `kev.newly_added`. Patch KEV-listed CVEs this sprint regardless of CVSS.
