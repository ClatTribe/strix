---
name: api_inventory
description: API9 Improper Inventory Management — exposed debug / staging / deprecated / shadow API versions; surface sprawl across env tiers
---

# API Improper Inventory Management

OWASP API Top 10 — **API9:2023**. The org has documented APIs, but *also* has APIs nobody documented: deprecated `/v1` endpoints still serving traffic, debug routes left enabled, staging endpoints reachable from prod, internal-only services exposed externally, dev branches deployed to prod-shaped subdomains. Each of these has a different (usually weaker) security posture than the documented production API.

## Why this matters

Documentation drives security review. An undocumented endpoint:
- Wasn't in the threat model.
- Wasn't pen-tested.
- Wasn't included in the WAF allowlist.
- Probably runs older code.
- Probably has the bug that was fixed in `v2`.

Inventory gaps are where the actual breach lives.

## Attack surface

| Pattern | Example |
|---|---|
| Version-rot | `/api/v1/*` (deprecated, less-hardened) reachable alongside `/api/v2/*` |
| Debug endpoints | `/debug`, `/_debug`, `/admin/debug`, `/health/detailed`, `/__internal__` |
| Beta / preview | `/api/beta/*`, `/api/preview/*`, `/api/canary/*` |
| Internal-only services exposed | `/internal/*`, `/private/*`, `/_/*`, `/_admin/*` |
| Staging in prod | `staging.example.com`, `dev.example.com`, `qa.example.com` reachable + serving real data |
| Region/zone leakage | `eu-1.api.example.com` → leaks regional infrastructure shape |
| Old subdomains pointing at decommissioned services | `legacy.api.example.com` (historic CNAMEs) |
| Framework debug pages | Django `/django-debug-toolbar/`, Flask `/console`, Rails `/_/dump`, Spring Boot Actuator `/actuator/*` |
| Environment endpoints | `/.env`, `/config.yaml`, `/wp-config.php`, `/web.config` |
| Source-map exposure | `/static/app.js.map` reveals full source |
| OpenAPI spec in prod | `/openapi.json`, `/swagger.json`, `/api-docs.json` (not always a finding, but always a recon goldmine) |

## Reconnaissance

### Version enumeration

For every documented API path, probe siblings:

```bash
# If you found /api/v3/users:
for v in v1 v2 v3 v4 beta preview internal admin; do
  echo -n "$v: "
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target/$v/users"
done
```

200s on `v1` / `v2` while the docs only describe `v3` = version-rot. 401 / 403 are also signal — the endpoint exists, just gates access.

### Debug-path probing

```bash
DEBUG_PATHS=(
  /debug /debug.php /_debug /admin/debug /__debug__
  /health /healthz /health/detailed /status /stats /metrics /info
  /actuator /actuator/env /actuator/heapdump /actuator/loggers
  /trace /traces /jolokia
  /console /flask-debug /django-debug-toolbar /_/info
  /server-info /server-status /apc.php /phpinfo.php
)
for path in "${DEBUG_PATHS[@]}"; do
  echo -n "$path: "
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target$path"
done
```

200 + body containing config / env / version data = high-severity disclosure.

### Subdomain inventory

The `subdomain_enum` and `domain_recon_pipeline` tools surface candidates. For API inventory, focus on:

| Pattern | Likely role |
|---|---|
| `staging.*`, `dev.*`, `qa.*`, `test.*` | Non-prod tiers exposed |
| `legacy.*`, `old.*`, `v1.*` | Decommissioned services |
| `internal.*`, `private.*`, `corp.*` | Should NOT be reachable externally |
| `*-canary.*`, `*-blue.*`, `*-green.*` | Active deploy variants — may run different code |

For each non-prod-flavored subdomain reachable from the public internet, that's an inventory finding.

### Source map / artifact exposure

```bash
# Map files reveal source:
for js in $(crawl_map.endpoints | grep '\.js$'); do
  curl -s -o /dev/null -w "%{http_code} $js.map\n" "$js.map"
done

# Build manifests + asset listings:
for path in /static /assets /dist /build /public; do
  curl -s "https://api.target$path/" | head
done
```

### Framework-actuator probes

Spring Boot Actuator exposes JVM internals, env vars, heap dumps:

```bash
for endpoint in env heapdump loggers mappings configprops trace metrics; do
  curl -s "https://api.target/actuator/$endpoint"
done
```

If `/actuator/env` returns env vars including credentials → critical.

### OpenAPI / Swagger / GraphQL introspection in prod

```bash
# Spec endpoints — informational by themselves, but spec contents
# reveal undocumented fields + endpoints:
curl -s https://api.target/openapi.json | jq '.paths | keys'
curl -s https://api.target/swagger.json
curl -s https://api.target/v3/api-docs

# GraphQL introspection (often disabled in prod, but check):
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  https://api.target/graphql
```

The spec frequently lists endpoints absent from external docs — those are inventory gaps even if the spec itself isn't a vuln.

## Exploitation patterns

### 1. Find a vuln in `v1` that was fixed in `v2`

```bash
# Same auth endpoint, two versions:
curl -X POST https://api.target/api/v2/auth/login -d '{"user":"a","pass":"b"}'
# v2: rate-limited, returns 429 after 5 attempts
curl -X POST https://api.target/api/v1/auth/login -d '{"user":"a","pass":"b"}'
# v1: no rate limit (the lockout was added in v2)
```

Probe the same vuln class against `v1` as against `v2` — frequently it's still vulnerable.

### 2. Staging tier serves prod data

```bash
curl -s https://staging.api.target/users/me -H "$PROD_AUTH"
# 200 with real prod user data = staging shares prod DB
# Then test staging for vulns — exploits may grant prod data access
```

### 3. Debug endpoint discloses environment

```bash
curl -s https://api.target/actuator/env | jq '.propertySources[].properties'
# Look for: DATABASE_URL, AWS_ACCESS_KEY, JWT_SECRET, redis URLs, S3 buckets
```

### 4. Source map → reverse-engineer auth flow

```bash
curl -s https://api.target/static/app.js.map | \
  jq -r '.sourcesContent[]' | grep -A3 -B3 "JWT\|secret\|api_key"
```

## Verification

For each surface found:
- Confirm it actually serves traffic (200, or 401/403 with body — 404 means dead).
- Confirm it's NOT in the public docs / OpenAPI spec.
- Confirm what it exposes (data, config, code, just existence).
- Decide severity by what it *enables* — version-rot is dangerous because of follow-on vulns, not on its own.

## Findings to emit

- **Critical** (CWE-200, info_disclosure) — environment / heap-dump / actuator exposes credentials
- **High** (CWE-1108, excessive_attack_surface) — undocumented production-reachable API version with weaker security
- **High** (CWE-489, active_debug_code) — debug endpoint exposes config / DB / env in prod
- **High** (CWE-540, source_code_inclusion) — source-map exposed in prod
- **Medium** (CWE-1059, incomplete_documentation) — staging / dev tier reachable from public internet
- **Medium** — undocumented endpoint discovered in OpenAPI spec but not in public docs
- **Low** — OpenAPI / GraphQL introspection enabled in prod (defense-in-depth concern; not exploitable on its own)

## Mitigation guidance

- Maintain a single source-of-truth API inventory (auto-generated from OpenAPI specs at deploy time)
- Decommission deprecated versions on a schedule; audit traffic before retiring
- Disable framework debug toolbars / actuator / debug routes in prod via build-time flags (NOT runtime config — runtime configs flip)
- Block non-prod-tier subdomains at the WAF / DNS layer for public traffic
- Strip source maps from prod build artifacts (Webpack `devtool: false`, Vite `build.sourcemap: false`)
- Disable GraphQL introspection in prod (`introspection: false`)
- Add a CI check that diffs deployed routes against the API inventory and fails on undocumented routes
- Remove `.env*`, `*.config`, build artifacts from publicly-served paths

## Related skills

- `information_disclosure` — generic disclosure that overlaps inventory issues
- `subdomain_takeover` — when an undocumented subdomain points at an unclaimed third-party
- `business_logic` — when version-rot lets an old workflow be abused
