---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
---

# Information Disclosure

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Attack Surface

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Key Vulnerabilities

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

## Triage Rubric

- **Critical**: Credentials/keys; signed URL secrets; config dumps; unrestricted admin/observability panels
- **High**: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content
- **Medium**: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints
- **Low**: Generic headers, marketing versions, intended documentation without exploit path

## Exploitation Chains

### Credential Extraction
- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access

### Version to CVE
1. Derive precise component versions from headers/errors/bundles
2. Map to known CVEs and confirm reachability
3. Execute minimal proof targeting disclosed component

### Path Disclosure to LFI
1. Paths from stack traces/templates reveal filesystem layout
2. Use LFI/traversal to fetch config/keys

### Schema to Auth Bypass
1. Schema reveals hidden fields/endpoints
2. Attempt requests with those fields; confirm missing authorization

## Operational Runbook

Information disclosure is a wide bucket — separate "artifact discovery" from "intentional-leak" testing.

### Step 1 — DVCS / backup artifacts

```bash
# .git exposed?
curl -sI '<TARGET>/.git/HEAD' | head -3
curl -sI '<TARGET>/.git/config' | head -3
curl -s '<TARGET>/.git/config' 2>/dev/null | head -10

# Clone if accessible (use git-dumper)
git-dumper '<TARGET>/.git/' /tmp/dump

# Backup file patterns
for ext in bak swp old swo orig save tmp; do
  for base in index config app web settings prod main backup db; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "<TARGET>/$base.$ext")
    [[ $code == 200 ]] && echo "/$base.$ext → 200"
  done
done

# DS_Store
curl -s '<TARGET>/.DS_Store' -o /tmp/dsstore && python3 -c "from ds_store import DSStore; [print(e) for e in DSStore.open('/tmp/dsstore')]"
```

### Step 2 — config + source-map exposure

```bash
# Source-map dump
for js in $(curl -s '<TARGET>' | grep -oE '[a-zA-Z0-9._-]+\.js'); do
  curl -s "<TARGET>/$js.map" 2>/dev/null | \
    jq -r '.sourcesContent[]?' 2>/dev/null | grep -iE 'api_key|secret|token|password' | head
done

# Common config endpoint patterns
for path in /actuator/env /actuator/configprops /actuator/heapdump /v1/env /api/config /config.json /.env /metrics; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "<TARGET>$path")
  [[ $code == 200 ]] && echo "$path → 200"
done
```

### Step 3 — verbose-error triggering

```bash
# Trigger DB errors via malformed input
curl -s "<TARGET>/api/users?id='" | tee /tmp/err.txt
curl -s "<TARGET>/api/users?id=null" | tee -a /tmp/err.txt
curl -s "<TARGET>/api/users?id[]=array" | tee -a /tmp/err.txt
curl -s "<TARGET>/api/users?id=$(python3 -c 'print("a"*10000)')" | tee -a /tmp/err.txt

# Search for stack-trace markers
grep -iE 'traceback|stacktrace|at [a-z_]+\(.*:[0-9]+\)|sqlexception|fatal error' /tmp/err.txt
```

### Step 4 — diff probe (owner vs anonymous)

```bash
# Same URL, different actors
for actor in "anon" "low_priv" "owner"; do
  case $actor in
    anon) HDR="" ;;
    low_priv) HDR="-H \"Authorization: Bearer $LOW_TOKEN\"" ;;
    owner) HDR="-H \"Authorization: Bearer $OWNER_TOKEN\"" ;;
  esac
  size=$(eval curl -s -o /dev/null -w "'%{size_download}'" "<TARGET>/api/profile" $HDR)
  echo "$actor → ${size}B"
done

# A larger anon response than expected = leaked authenticated state
```

### Step 5 — schema / introspection

```bash
# OpenAPI / Swagger
curl -s '<TARGET>/openapi.json' | jq '.paths | keys' 2>/dev/null

# GraphQL introspection
curl -s -X POST '<TARGET>/graphql' \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' \
    | jq '.data.__schema.types[]?.name' | head -30
```

### Step 6 — sort findings by impact

| Leak | Severity |
|---|---|
| Live API keys / credentials in responses or JS bundles | **critical** |
| Source code (via .git, source maps, bundle minification reverse) | **high** |
| Internal hostnames / config paths via debug endpoints | **high** |
| Stack traces / framework versions | **medium** |
| Verbose error messages, server headers | **low** |

Document: exact URL, response excerpt with the leak (redact actual key values to last-4-chars + length), and the downstream attack the leak enables.

## Testing Methodology

1. **Build channel map** - Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** - Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** - Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** - DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** - Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible

## Summary

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.
