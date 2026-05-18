---
name: asset-discovery-pipeline
description: Full per-target-type asset discovery sequence — web + domain + IP + cloud + repo
triggers: [asset discovery, recon pipeline, scope expansion, attack surface, surface map]
---

# Asset Discovery Pipeline

Asset discovery sets the ceiling on every other test. Skip a subdomain, miss a vuln. Skip a cloud account, miss the IAM chain. This skill describes the full Strix discovery pipeline per target type and the order to run things in for maximum coverage with minimum redundant work.

## Strix's Discovery Surface (summary)

| Target type | Primary discovery tools | Output |
|---|---|---|
| `domain` | `subdomain_enum`, CT logs, passive DNS, `discover_cloud_assets`, GitHub code search | live subdomain list + cloud namespace hits |
| `web_application` | `bfs_crawl`, `well_known_harvest`, `source_map_probe`, `openapi_spec_ingest`, `fingerprint_tech_stack` | endpoint inventory + tech stack |
| `api` | `openapi_spec_ingest`, `ingest_har_file`, `ingest_burp_file`, JS-bundle URL extraction | endpoint + param shapes + auth context |
| `ip_address` | `attack_surface_intel` (Shodan + Censys), `reverse_ip_discovery`, `naabu` | open ports + service banners + neighbours |
| `repository` | `secrets_scan`, `sbom_extract`, `build_code_map`, manifest parsers | dep graph + secret hits + route map |
| `cloud_account` | `cloud_attack_paths/discovery.py` (boto3 + Azure + GCP SDKs), `cspm/prowler.py`, `multi_account.py` | full resource + identity graph |
| `container_image` | `scan_container_image` (Trivy-wrapped), SBOM extraction | layered package + secret inventory |

## Pipeline by Target Type

### 1. Domain target (`-t example.com`)

```
Stage A: surface mapping
  ├── subdomain_enum (5 sources) → live subdomain list
  ├── dns_hygiene_check → SPF/DMARC/CAA/DNSSEC findings
  ├── org_fingerprint → WHOIS + ASN + GitHub-org
  ├── passive_dns_history → historical IPs (rotation hints)
  └── code_search_for_domain → org-scoped GitHub mentions

Stage B: enrichment
  ├── reverse_ip_discovery → shared-hosting neighbours
  ├── mx_fingerprint → mail-server banner + auth headers
  ├── m365_tenant_recon → tenant ID + federation
  └── discover_cloud_assets → S3/GCS/Azure/Heroku/Netlify namespace fan-out

Stage C: live probing
  ├── httpx on the subdomain list → live HTTP services
  ├── subdomain_takeover_check (60+ providers) → dangling-CNAME takeovers
  └── For each live HTTP host: spawn a `web_application` target

Stage D: threat-intel
  ├── vt_reputation, greynoise_classify, otx_lookup → host reputation
  ├── hibp_breach_check → historical breach exposure
  └── threat_feed_ingest → customer's own MISP/STIX/TAXII feeds
```

Time budget: ~5-10 minutes for a medium-size domain. Cost: dominated by DNS resolution + threat-intel API calls (cached).

### 2. Web application target (`-t https://app.example.com`)

```
Stage A: surface mapping
  ├── well_known_harvest (13 standard paths)
  ├── source_map_probe (.js.map exposure)
  ├── bfs_crawl → URL inventory + JS bundles + OpenAPI specs
  ├── fingerprint_tech_stack → tech detection + auto-load skills

Stage B: API surface
  ├── openapi_spec_ingest (if .well-known/openapi.json or /swagger found)
  ├── Manual HAR / Burp import → seeds replay_mutation_*

Stage C: deterministic checks
  ├── tls_audit, http_security_headers_audit
  ├── csrf_check, cors_deep_check, jwt_audit
  └── source_maps, cookie_jwt_scoping_check

Stage D: dispatch specialists (the actual vuln hunt)
  └── dispatch_specialist for each shipped class
```

### 3. API target (`-t https://api.example.com --target-type api`)

```
Stage A: endpoint inventory
  ├── openapi_spec_ingest → primary inventory
  ├── ingest_har_file (when operator supplies HAR)
  ├── ingest_burp_file (when operator supplies .burp project)
  └── (future) JS-bundle endpoint extraction

Stage B: API-specific specialists
  ├── graphql_introspection_deep
  ├── scan_api_grpc_reflection
  ├── scan_api_bola (per documented endpoint)
  ├── scan_api_bfla
  ├── scan_api_mass_assignment
  └── scan_api_rate_limit

Stage C: shared dispatch
  └── scan_sqli, scan_ssrf, scan_idor, ... per endpoint
```

### 4. Cloud account target (`-t aws://123456789012`)

```
Stage A: enumerate
  ├── cspm/prowler.py → AWS Foundations + CIS findings
  ├── cloud_attack_paths/discovery.py → boto3 walk: EC2, IAM, S3, RDS, Lambda, ...
  ├── cloud_attack_paths/multi_account.py → AWS Organizations fan-out
  ├── (per-cloud) azure_discovery / gcp_discovery for non-AWS

Stage B: graph + score
  ├── cloud_attack_paths/patterns.py → 27 attack patterns
  ├── reachability.py → graph-aware "N hops from public" scoring
  ├── live_probes.py → verify exploitability (anonymous S3 GET, etc.)

Stage C: agentless deepening
  ├── agentless_scan.py → Trivy EBS-snapshot for VM CVEs (with auto-snapshot)
  ├── cloudtrail_detection.py → CDR rules on CloudTrail history
  └── drift/correlator.py → IaC declared vs cloud live diff
```

### 5. Repository target (`-t https://github.com/org/repo`)

```
Stage A: inventory
  ├── build_code_map → routes + handlers + ORM models
  ├── sbom_extract → dep tree
  ├── secrets_scan → in-tree + git-history (PR #288)
  └── manifest parsers (package.json, requirements.txt, ...)

Stage B: analysis
  ├── scan_sca_lockfiles + sca/reachability.py (Python)
  ├── scan_sast (semgrep r/security-audit + vibe_coded pack)
  ├── tools/taint/taint_analysis.py (Python AST)
  ├── scan_iac (8 frameworks)
  └── scan_container_image (if Dockerfile present)

Stage C: cross-target hook
  └── Co-located web target? Test secret leaks against prod auth.
```

## Operational Runbook

### Step 1 — choose the target type

```bash
# Strix's auto-detection (preflight)
strix --target https://example.com --target-type auto

# Or force per type
strix --target https://example.com --target-type web_application
strix --target example.com --target-type domain
strix --target aws://123456789012 --target-type cloud_account
strix --target https://github.com/org/repo --target-type repository
strix --target nginx:1.25 --target-type container_image
```

### Step 2 — run the discovery profile

Default scan modes hit different breadth:
- `--profile initial` — 2-5 min, ~10% of standard cost. New asset, surface-only.
- `--scan-mode quick` — quick deterministic checks; no LLM specialist dispatch.
- `--scan-mode standard` — full pipeline with specialist dispatch (default).
- `--scan-mode deep` — extended exploitation phase with verification pipeline.

### Step 3 — multi-target compounding

```bash
# Run the same project across all target types
strix --target https://github.com/org/payments-api \
      --target https://payments.example.com \
      --target aws://123456789012 \
      --target nginx:1.25 \
      --project-id payments-prod
```

`STRIX_PROJECT_ID` (PR #317) tags findings + discovered assets so the wrapper's KG store unions cross-target paths.

### Step 4 — bulk import

```bash
# JSONL batch (PR #319)
cat > /tmp/targets.jsonl <<EOF
{"id": "tgt_a", "type": "repository", "value": "https://github.com/org/payments-api"}
{"id": "tgt_b", "type": "web_application", "value": "https://payments.example.com"}
{"id": "tgt_c", "type": "cloud_account", "value": "aws://123456789012"}
EOF

strix --target-list /tmp/targets.jsonl --batch-cost-cap 5.00
```

One sandbox, one Researcher run, N targets — ~3-4× cheaper than serial scans.

## Pro Tips

1. **Always run the domain-level recon first**: subdomain enumeration sets the scope for everything else. A 30%-incomplete subdomain list silently caps every later test.
2. **Co-locate repo + web targets when possible**: leaked-credential pivots only work when Strix can test the leaked cred against the production auth surface.
3. **Cloud asset discovery is the bridge**: a cloud account scan emits `assets.discovered.jsonl` (PR #314) containing repos / web apps / containers; the wrapper's bulk-approve flow consumes this.
4. **Skip-if-unchanged saves 95%**: on daily-cadence scans, most targets are quiescent. Use `--skip-if-unchanged` (PR #313) — exits in < 5s on no change.
5. **Researcher cache compounds**: for `--project-id <id>` runs, the Researcher phase runs once per project; subsequent target scans reuse the cached architectural map (PR #319).

## Validation

1. Subdomain count > some threshold for the org's size (more is better up to a point).
2. JS-bundle URLs grepped match the subdomain list — confirms the surface map is consistent.
3. `assets.discovered.jsonl` is non-empty for cloud targets.
4. `kg.json` has nodes for every discovered asset class.
5. The lead's `coverage.json` shows the expected `target_type × scan_mode` matrix entries.

## False Positives

- Wildcard DNS records → resolve every random sub to the same IP. Filter before counting as discovered.
- CDN-fronted hosts → real subs but you're testing the CDN, not the origin. Note in the report.
- Test/CI-only subs that aren't in production → flag but de-prioritise.
- Acquisition-era domains that no longer route → exclude from active scope.

## Impact on the Engagement

Asset discovery quality is the ceiling on every later finding. A missed subdomain means missed vulns. A missed cloud account means missed attack paths. Time-budget recon at 20-30% of the engagement before declaring "discovery done."

## Summary

Run discovery first; everything else depends on it. Use the right target type per asset class. Compound across types with `--project-id` for cross-target reasoning. Use batch + skip-if-unchanged for org-scale efficiency.
