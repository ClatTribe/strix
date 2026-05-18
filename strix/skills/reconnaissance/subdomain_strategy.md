---
name: subdomain-strategy
description: When to use subfinder vs amass vs CT logs vs Wayback vs permutations — pipelined subdomain enumeration for completeness
triggers: [subdomain, subfinder, amass, dnsx, crt.sh, wayback, permutations, dns brute, asset discovery]
---

# Subdomain Enumeration Strategy

A subdomain you don't know about is a subdomain you don't test. Real-world asset discovery uses **multiple complementary sources** chained by deduplication — no single tool catches everything. Strix's `subdomain_enum` (#21) already runs 5 sources in parallel; this skill explains how to reason about which source caught a given asset and when to fall back to additional channels.

## Source Taxonomy

| Source | What it catches | Misses | When to lean on it |
|---|---|---|---|
| **Passive sources** (subfinder + amass passive) | Indexed-by-someone subdomains: VT, Shodan, Censys, SecurityTrails, ChaosDB, GitHub | Brand-new, never-indexed, internal-only | First always — free, fast, no scan signature |
| **Certificate Transparency** (crt.sh, Censys, Google CT) | Anything with a TLS cert ever issued, including expired + revoked | Subdomains never given a cert; staging on plain HTTP | High value for orgs using Let's Encrypt / ACME automation |
| **Wayback Machine + CommonCrawl** (waybackurls) | Anything ever crawled by the Internet Archive or in a CommonCrawl corpus | Recent (< 30 days), private, robot-blocked | Excellent for finding *old* dev / staging hosts the org forgot |
| **DNS brute-force** (dnsx + wordlists) | Active subdomains matching common patterns (api, staging, dev, test, beta, mail, admin) | Random-named subs, obscure patterns | When wordlist + DNS resolver budget is acceptable |
| **Permutation generation** (altdns / dnsgen) | Variations on found names: `staging-api.x.com`, `api-v2.x.com`, `api.us-east.x.com` | Anything not derivable from existing names | Always run after the first pass; cheap win on incidentally-discovered patterns |
| **CT-only post-filter** | Internal-leaning subs in CT logs that resolve internally only | Anything without a cert | Use when target heavily uses Let's Encrypt + internal services |
| **GitHub code search** (`code_search_for_domain`) | Subs referenced in public repos (commits, READMEs, configs) | Private repos | Lookups for the target's GitHub org are essential |
| **JS bundle extraction** | Subs referenced in compiled JS (`fetch("https://api.x.com/v2/...")`) | Subs only used server-side | Run after `bfs_crawl` lands the JS bundle inventory |

## Standard Pipeline (the Strix order)

```
1. subdomain_enum (PR #21)
   ├── subfinder (passive: VT / Censys / SecurityTrails / ...)
   ├── amass passive
   ├── crt.sh (CT logs — PR #48)
   ├── dnsx brute-force with wordlists
   └── permutations (altdns)

2. code_search_for_domain (PR #24) — GitHub org-scoped

3. discover_cloud_assets (PR #22) — S3 / GCS / Azure namespace fan-out

4. reverse_ip_discovery (PR #23) — shared-hosting neighbours

5. bfs_crawl + source_map_probe — JS bundle extraction

6. Iterate: feed any newly discovered subs back through (1) for more permutations
```

## Operational Runbook

### Step 1 — full passive sweep (no DNS noise)

```bash
# Inside the strix sandbox
subfinder -d <TARGET> -all -silent > /tmp/passive.txt
amass enum -passive -d <TARGET> -silent >> /tmp/passive.txt
echo '<TARGET>' | waybackurls | unfurl -u domains >> /tmp/passive.txt

# CT logs (crt.sh is the canonical)
curl -s 'https://crt.sh/?q=%25.<TARGET>&output=json' \
  | jq -r '.[].name_value' | sed 's/^\*\.//' >> /tmp/passive.txt

sort -u /tmp/passive.txt > /tmp/passive_unique.txt
wc -l /tmp/passive_unique.txt
```

### Step 2 — resolve + filter

```bash
# Resolve everything found to filter wildcard responses
dnsx -l /tmp/passive_unique.txt -resp -silent > /tmp/resolved.txt
awk '{print $1}' /tmp/resolved.txt | sort -u > /tmp/live.txt

# Wildcard detection — query a random non-existent sub
dig +short randomXYZ123.<TARGET> | head -1
# If this returns an IP, the target wildcards; filter results matching that IP.
```

### Step 3 — DNS brute-force (budget-permitting)

```bash
# Conservative wordlist (n0kovo's subdomains-top1mil-110000)
# Larger wordlists exist but cost more DNS + rate-limit
WORDLIST=/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

dnsx -d <TARGET> -w "$WORDLIST" -resp -silent -t 50 >> /tmp/resolved.txt
```

### Step 4 — permutation pass

```bash
# Generate permutations from discovered subs
dnsgen /tmp/live.txt > /tmp/perms.txt
# Or altdns:
altdns -i /tmp/live.txt -o /tmp/perms.txt -w /usr/share/seclists/Discovery/DNS/altdns-words.txt

# Resolve the permutation candidates
dnsx -l /tmp/perms.txt -resp -silent -t 50 >> /tmp/resolved.txt
```

### Step 5 — orthogonal sources

```bash
# GitHub code search for the target domain
gh search code "<TARGET>" --json repository,path,textMatches --jq '.[] | "\(.repository.nameWithOwner) \(.path)"'

# Cloud asset namespace fan-out (Strix tool covers this)
strix discover_cloud_assets --domain '<TARGET>'

# Reverse-IP — find neighbours sharing the same hosting IPs
strix reverse_ip_discovery --domain '<TARGET>'
```

### Step 6 — bfs_crawl + JS extraction

```bash
# Crawl the main domain + extract JS bundle URLs
strix bfs_crawl --url 'https://<TARGET>'

# Extract subs from JS bundles
for bundle in $(ls strix_runs/<run_id>/js_bundles/*.js); do
  grep -oE 'https?://[a-zA-Z0-9.-]+\.<TARGET>' "$bundle"
done >> /tmp/from_js.txt
```

### Step 7 — final dedup + handoff

```bash
sort -u /tmp/resolved.txt /tmp/from_js.txt > /tmp/all_subs.txt
wc -l /tmp/all_subs.txt
```

Pass `/tmp/all_subs.txt` to `httpx` for live-host probing + tech-stack fingerprinting.

## Pro Tips

1. **CT-log dedup**: crt.sh returns lots of duplicates and wildcards. `sed 's/^\*\.//' | sort -u` is the canonical cleanup.
2. **Wildcard hosts**: when the target wildcards DNS, brute-force is mostly noise. Switch focus to passive sources + JS extraction.
3. **Internal-leaning subs**: subs with `internal.`, `corp.`, `lab.`, `dev.`, `staging.` prefixes — these usually have weaker security. Flag separately.
4. **Subdomain takeover surface**: subdomains pointing at CNAMEs of decommissioned SaaS (`*.cloudapp.net` without a backing resource) are takeover candidates. Run `scan_subdomain_takeover_active` on the resolved set.
5. **Org-scope vs apex-scope**: enumerate the **organisation's whole apex set** (acquisitions, regional brands) when authorised. Single apex-scope misses 30-60% of real attack surface.
6. **Recursive brute**: discovered `api.example.com`? Re-run brute on `api.example.com` as the new apex.
7. **Cert SAN extraction**: certs include SAN entries listing additional subdomains. Always grep the full SAN list, not just the CN.

## False Positives

- Wildcard DNS records resolving every name to the same IP — filter out before treating as a real find.
- CDN-fronted subs all pointing at the same CDN edge IPs — they're real, but you're testing the CDN not the origin.
- DNS sinkholes returning `127.0.0.1` / `0.0.0.0` for unused names.
- Acquisition-era subs that no longer resolve.

## Validation

1. Confirm each candidate sub *resolves* (dnsx with `-resp` flag).
2. Confirm at least one of: HTTP response from `httpx`, or known service on standard port via `naabu`.
3. Document the **source** that found each sub (passive / CT / brute / permutation / JS / GitHub) — useful for explaining coverage gaps.

## Impact on Subsequent Scans

Subdomain enumeration completeness sets the ceiling on every other test. A 50% subdomain catch rate = 50% of the attack surface unscanned. Time-budget the recon phase deliberately; under-investing here makes the rest of the engagement weaker.

## Summary

No single source catches all subdomains. Run passive + CT + brute + permutation in parallel; iterate with code search, JS extraction, and reverse-IP. The output is the input scope for everything else.
