---
name: openapi-recon
description: Extracting endpoints + schemas + auth context from OpenAPI / Swagger / RAML / API Blueprint specs
triggers: [openapi, swagger, raml, api blueprint, json schema, asyncapi, redoc, spec]
---

# OpenAPI / Swagger Reconnaissance

When an API publishes a specification, that spec is **the canonical endpoint inventory**. Strix's `openapi_spec_ingest` consumes OpenAPI 2.0 (Swagger) / OpenAPI 3.0 / OpenAPI 3.1 / RAML / API Blueprint / AsyncAPI and feeds the resulting surface map into the specialist dispatcher. For API targets, this is the primary discovery channel — better than crawling.

## Where Specs Live

| Standard path | What it serves |
|---|---|
| `/openapi.json` / `/openapi.yaml` | OpenAPI 3.x |
| `/swagger.json` / `/swagger.yaml` | OpenAPI 2.0 |
| `/api-docs` / `/v2/api-docs` / `/v3/api-docs` | springdoc-openapi default |
| `/redoc` / `/redoc.html` | ReDoc UI page; spec linked from within |
| `/swagger-ui.html` / `/swagger-ui/index.html` | Swagger UI; spec referenced via `<script>` |
| `/api/schema` / `/api/schema/swagger-ui/` | Django REST framework default |
| `/__schema` | GraphQL introspection (separate spec format) |
| `/.well-known/openapi` | Suggested standard (RFC draft); rare but real |

Heuristics for discovery:
- Bundle inspection — Strix's `bfs_crawl` finds JS bundles referencing `openapi` URLs.
- HTTP `OPTIONS *` sometimes lists supported routes + their spec URL.
- Service banners (`X-Powered-By: Express`, `X-Frame-Options: ...`) hint at framework default paths.

## What a Spec Tells You

| Field | Recon value |
|---|---|
| `paths` | Full endpoint inventory; for each path, supported methods, parameters, responses |
| `components.schemas` | Object shapes — mass-assignment + IDOR candidates |
| `components.securitySchemes` | Auth model: Bearer, OAuth flow, API key location |
| `servers` | Multiple environment endpoints — `staging.api.x.com` may be in scope you didn't know about |
| `tags` | Logical grouping; `admin` tagged endpoints are high-priority |
| `x-*` extensions | Framework-specific hints (rate-limits, deprecation, internal-only flags) |

## Operational Runbook

### Step 1 — discover the spec

```bash
# Standard path sweep
for path in /openapi.json /openapi.yaml /swagger.json /swagger.yaml \
            /api-docs /v2/api-docs /v3/api-docs /redoc /swagger-ui.html \
            /api/schema/openapi.json /docs /docs.json /.well-known/openapi; do
  curl -s -o /tmp/probe.json -w "%{http_code} %{size_download} %{url_effective}\n" "https://<TARGET>${path}"
done | grep -E '^(200|301|302)'
```

When a UI page lands (e.g. Swagger UI):
```bash
# Find the embedded spec URL
curl -s 'https://<TARGET>/swagger-ui.html' | grep -oE 'url[^"]*"[^"]+"' | head
```

### Step 2 — ingest

```bash
strix openapi_spec_ingest --url 'https://<TARGET>/openapi.json'

# Or feed a local copy if the spec is private but the operator has access
strix openapi_spec_ingest --file ./openapi.yaml
```

Output: `surface_map.json` populated with one entry per (path × method).

### Step 3 — audit the spec for low-hanging recon wins

```bash
# Endpoints tagged 'admin' / 'internal' — high priority
jq '.paths | to_entries[] | select(.value | to_entries[] | .value.tags? // [] | contains(["admin"])) | .key' openapi.json

# Endpoints lacking security scheme (unauthenticated endpoints)
jq '.paths | to_entries[] | select(.value | to_entries[] | .value.security == [] or .value.security == null) | .key' openapi.json

# Path parameters that look like IDs (IDOR candidates)
jq '.paths | keys[] | select(test("\\{[^}]*[Ii]d\\}"))' openapi.json

# Deprecated endpoints (often unmaintained → vulnerable)
jq '.paths | to_entries[] | select(.value | to_entries[] | .value.deprecated == true) | .key' openapi.json
```

### Step 4 — extract schemas

```bash
# All defined schemas (potential mass-assignment surface)
jq '.components.schemas | keys' openapi.json

# Schemas with sensitive-looking fields
jq '.components.schemas | to_entries[] | select(.value.properties | to_entries[] | .key | test("password|secret|token|admin|role|permission"; "i"))' openapi.json
```

Schemas listing fields like `isAdmin`, `role`, `permissions`, `verified`, `email_verified` are mass-assignment candidates if PATCH/POST endpoints accept the full schema body.

### Step 5 — auth scheme audit

```bash
jq '.components.securitySchemes' openapi.json
```

Common findings:
- `type: apiKey, in: query` — API key in URL (logged in proxies, browser history)
- `type: http, scheme: bearer` + no `bearerFormat` — informal JWT; often vulnerable to alg-confusion
- `type: oauth2, flows: implicit` — deprecated flow; flag
- Missing `securitySchemes` entirely → unauthenticated by design

### Step 6 — multi-server discovery

```bash
jq '.servers' openapi.json
# Often reveals additional environments:
# [
#   {"url": "https://api.example.com"},
#   {"url": "https://staging.example.com"},    ← was this in scope?
#   {"url": "https://internal.example.com"}    ← scope expansion!
# ]
```

`staging` / `internal` endpoints commonly have weaker auth + relaxed CORS. Flag and confirm with the operator before scanning out-of-scope hosts.

### Step 7 — feed into specialist dispatch

```bash
# Per-endpoint specialist fan-out
strix --target 'https://<TARGET>/' \
      --target-type api \
      --openapi-spec /tmp/openapi.json \
      --scan-mode standard
```

Each endpoint gets dispatched to relevant specialists (BOLA, BFLA, mass-assignment, SQL/NoSQL/SSRF based on parameter shape, etc.).

## RAML / API Blueprint / AsyncAPI (rarer)

Same shape, different syntax. Strix's `openapi_spec_ingest` accepts:
- **RAML** (`#%RAML 1.0`) — Mulesoft / Anypoint exports
- **API Blueprint** (`FORMAT: 1A`) — Apiary exports
- **AsyncAPI** — WebSocket / Kafka / MQTT specs

For AsyncAPI specifically, the `channels` block lists message topics — feed these into `scan_websocket_auth` for WS targets.

## Pro Tips

1. **Always check `/api-docs` (Spring), `/v2/api-docs` (Spring), `/api/schema/` (DRF)**: framework defaults are huge time-savers.
2. **JS bundles often link the spec**: `bfs_crawl` extracts JS; grep for `openapi`, `swagger.json` URLs in the bundle.
3. **OpenAPI 3.1 added JSON Schema 2020-12 support**: schemas may now embed `if/then/else`, complex `oneOf`, etc. Strix's ingester handles all draft versions.
4. **Spec versions can lie**: an endpoint may have moved / been removed but the spec wasn't updated. Confirm 200 / 4xx vs 404 before dispatching specialists.
5. **`x-internal: true` extensions**: some teams flag internal-only endpoints; treat as high-priority and confirm whether they actually require auth.
6. **GraphQL is its own world**: when the API uses GraphQL, use `graphql_introspection_deep` instead of OpenAPI ingestion.

## False Positives

- Spec describes an endpoint that returns 404 — possibly deprecated; not a real endpoint to scan.
- Spec auth requirement is permissive (`"security": []`) but real endpoint enforces auth — spec is wrong; trust the runtime.
- `servers` listing dev-only endpoints that don't actually resolve.
- Aspirational spec (drafted before implementation) — endpoints don't yet exist.

## Validation

1. Spec parsed successfully (no JSONSchema validation errors).
2. `surface_map.json` shows endpoints + per-endpoint method + params + auth scheme.
3. First dispatched specialist successfully reaches a documented endpoint (200 / 4xx — not 404).
4. Schema-aware specialists (mass-assignment, BOLA) emit findings using the spec's schema definitions as ground truth.

## Impact on Subsequent Scans

- **Complete endpoint inventory** vs ~30-70% via crawling — crawlers miss documented-but-unlinked endpoints.
- **Exact parameter shapes** → richer fuzz / probe payloads.
- **Auth scheme awareness** → correct auth replay per endpoint.
- **Schema-aware mass-assignment** → finds fields that should never be writeable.
- **Multi-server discovery** → reveals additional in-scope hosts.

## Summary

OpenAPI is the API equivalent of a sitemap. Discover the spec via standard paths or JS-bundle grepping, ingest with `openapi_spec_ingest`, audit for low-hanging recon wins (admin tags, deprecated endpoints, weak auth schemes, multiple servers), then feed into specialist dispatch. The single best primitive for API targets after authentication is sorted.
