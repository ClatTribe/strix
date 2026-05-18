---
name: threat-intel-pivoting
description: Choosing the right threat-intel source per question — KEV, EPSS, VT, OTX, HIBP, GreyNoise, NVD, Sigma, Shodan, Censys
triggers: [threat intel, kev, epss, virustotal, otx, hibp, greynoise, shodan, censys, prioritisation]
---

# Threat-Intel Pivoting

Strix ships 18+ threat-intel sources (§10 audit + gap-audit arc, PRs #61-#76). Knowing *which* source answers *which* question is what turns "we have intel" into useful prioritisation. This skill is the routing table.

## Sources Available

### Per CVE
- **CISA KEV** (`is_kev` auto-decorated + `kev_diff_check` PR #75) — is this CVE *actively exploited in the wild* per CISA's catalog? Auto-tag on every CVE finding.
- **NIST NVD** (`nvd_lookup` PR #73) — authoritative CVSS, CWE, CPE matches.
- **OSV.dev** (`cve_lookup` PR #61) — multi-ecosystem CVE matches per `(package, version, ecosystem)`.
- **FIRST EPSS** — probabilistic exploit-prediction score (0-1) per CVE. Auto-decorated.
- **Perplexity** (`cve_intel_search` PR #67) — fresh CVE intel from the open web (post-CVE-publication context).
- **ExploitDB / Metasploit / Nuclei** (`exploit_refs` PR #62) — public PoCs per CVE.
- **Sigma rules** (`sigma_rules_for_technique` PR #74) — detection rules per ATT&CK technique.

### Per host / IP
- **Shodan + Censys** (`attack_surface_intel` PR #65) — open ports, banners, advertised CVEs.
- **GreyNoise** (`greynoise_classify` PR #72) — is this IP **noise** (mass scanner) or **targeted**?
- **VirusTotal** (`vt_reputation` PR #71) — multi-engine consensus on file/URL/IP/domain.
- **AlienVault OTX** (`otx_lookup` PR #76) — pulse activity + actor attribution.
- **AbuseIPDB / Spamhaus / GSB / URLhaus** (`domain_reputation` PR #63) — 5-source IoC reputation.

### Per domain / org
- **HIBP** (`hibp_breach_check` PR #64) — historical breach exposure.
- **Passive DNS** (SecurityTrails / VirusTotal) — historical resolutions.
- **Customer feeds** (`threat_feed_ingest` PR #69) — operator-provided MISP / STIX / TAXII.

### Per ATT&CK technique
- **Sigma rules** (PR #74) — detection-engineering recommendations.
- MITRE ATT&CK technique tags (PR #66) auto-attached to every tool execution.

## Routing Table

### Question: "Is this CVE worth my time right now?"

```
Decision tree:
  is_kev = true?
    → CRITICAL — actively exploited. Treat as P0 regardless of CVSS.
  EPSS > 0.5?
    → HIGH — high probability of exploitation. Prioritise.
  CVSS ≥ 9.0?
    → HIGH but check reachability before celebrating
  ExploitDB / Metasploit / Nuclei has a public PoC?
    → MEDIUM bump in priority — proven exploitable
  Otherwise:
    → Standard CVSS-based triage
```

### Question: "Should we ignore this scanning IP?"

```
GreyNoise classify:
  noise:true, malicious:false → mass scanner. Likely safe to deprioritise alert
  noise:true, malicious:true → known malicious scanner. Block at WAF
  noise:false, malicious:true → TARGETED. Treat as a real incident
  unknown → no signal; combine with other sources
```

### Question: "Has this email/domain been breached before?"

```
HIBP domain check:
  breach_count > 0 + recent + passwords_exposed
    → HIGH — credential stuffing risk; force-rotate
  breach_count > 0 + dated + no passwords
    → LOW — historical context only
  not_found
    → No prior breach data; absence of evidence ≠ evidence of absence
```

### Question: "What's the broader actor context for this IoC?"

```
OTX lookup (`otx_lookup`):
  pulse_count ≥ 3 + has named_actor → HIGH (attribution exists)
  pulse_count 1-2 → MEDIUM (early signal)
  pulse_count 0 → no known context; rely on other sources

VirusTotal:
  malicious_engines ≥ 10 → HIGH consensus
  malicious_engines 3-9 → MEDIUM
  malicious_engines 0-2 → LOW
```

### Question: "How exposed is this host on the public internet?"

```
Shodan + Censys (`attack_surface_intel`):
  - Open ports inventory: SSH (22), RDP (3389), DB ports (3306/5432/27017/6379)
  - Service banners → version → CVE pivot via cve_lookup
  - Certificate SANs → additional subdomains
  - SCADA/IoT ports (502 Modbus, 102 S7) → high-priority flag
```

High-risk service flags (18 patterns):
- Redis on 6379 → `requirepass=` not set → instant RCE via SSRF
- MongoDB on 27017 → auth disabled → full DB dump
- Docker daemon 2375 → exposed unauth API → container escape
- Elasticsearch 9200/9300 → unauth → full data exfil
- Memcached 11211 → DDoS amplifier + cache pollution
- Jenkins 8080 → unauth `/script/` console → RCE
- Kibana 5601 → privilege escalation via dashboards
- RabbitMQ 15672 / Flower 5555 → admin UI without auth
- PHP-FPM 9000 → gopher SSRF → RCE

## Operational Runbook

### Step 1 — cache prime
Strix's threat-intel cache (`strix/threat_intel/cache.py`) keeps responses for 24h by default with stale-fallback. Daily-cadence runs amortise API costs.

```bash
# Force refresh (rarely needed)
STRIX_KEV_DISABLED=0 strix --target ... # KEV refreshes daily
```

### Step 2 — daily KEV diff
```bash
# kev_diff_check (PR #75) compares today's KEV vs last scan's findings
strix kev_diff_check
# Surfaces newly-actively-exploited CVEs that match prior findings
```

### Step 3 — per-finding pivot

For each CVE finding the agent emits:
1. `nvd_lookup` → CVSS + CWE + CPE
2. `cve_lookup` (OSV) → ecosystem match confirmation
3. `is_kev` enrichment (automatic)
4. `EPSS` score (automatic)
5. `exploit_refs` → public PoCs (if EPSS > 0.3 or CVSS > 7)
6. `cve_intel_search` (Perplexity) → fresh context if CVE is recent (< 90 days)
7. `sigma_rules_for_technique` → detection recommendation

### Step 4 — per-IP pivot

For each external-facing IP discovered:
1. `attack_surface_intel` (Shodan + Censys parallel) → ports + banners + CVEs
2. `domain_reputation` (5 IoC sources parallel) → reputation
3. `vt_reputation` → multi-engine consensus
4. `greynoise_classify` → noise vs targeted
5. `otx_lookup` → actor / pulse context

All 5 fire in parallel; cached results mean repeat scans are cheap.

### Step 5 — operator-supplied feeds
```bash
# Ingest customer's MISP / STIX / TAXII (PR #69)
strix threat_feed_ingest --feed-url 'https://misp.customer.com/events/restSearch' \
  --feed-format misp --auth-key '...'
```

Custom feeds get correlated against scan findings — surfaces "this asset is in your watchlist" hits.

## Pro Tips

1. **Always check KEV first**: actively-exploited CVEs are 100× more urgent than theoretical-CVSS-9 findings. The `is_kev` flag is the single most useful signal in modern triage.
2. **EPSS > CVSS for prioritisation**: CVSS is severity (impact + exploitability *score*); EPSS is the probability someone will exploit it. EPSS catches CVEs CVSS underrates and vice versa.
3. **GreyNoise inverts triage**: by classifying mass-internet-background noise as `noise:true`, it lets defenders **ignore** 80% of alerts. Strix uses it to deprioritise IoC findings against well-known scanners.
4. **OTX is best for attribution**: when an IoC has 3+ pulses with named actors, you can write "TA-XXX activity observed" in the report.
5. **Perplexity (`cve_intel_search`) is for fresh CVEs**: when a CVE is < 90 days old, NVD often hasn't been updated; Perplexity catches the blog posts, advisories, and exploit chatter.
6. **Cache warming**: the first scan of the day primes the threat-intel cache for everyone; subsequent scans piggyback on cached data.
7. **Don't echo credentials**: when `threat_feed_ingest` pulls a customer feed, the API key stays in env; Strix never logs it to events.jsonl. Confirm before sharing scan output.

## When to Skip Threat-Intel

- The target is internal-only (no public IP) → IP-reputation sources moot
- Air-gapped environment → set `STRIX_KEV_DISABLED=1`, use local cache only
- Compliance-sensitive scans where cross-referencing external services is restricted (PCI / HIPAA scoping)

## Validation

1. CVE findings carry `is_kev`, `epss_score`, `cvss_v3_score` decorations from the tracer.
2. IP findings carry `vt_engines_malicious`, `greynoise_classification`, `otx_pulse_count` decorations.
3. `run_summary.json` shows the threat-intel cache hit rate.
4. Customer-feed correlations appear as `finding.cross_reference_with_feed` events.

## Summary

18+ sources, one routing table. KEV for "actively exploited", EPSS for probability, NVD for canonical scoring, GreyNoise for noise filtering, OTX for attribution, HIBP for breach history, Shodan + Censys for external exposure, customer feeds for context. Use the right tool for the right question.
