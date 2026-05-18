---
name: har-burp-ingestion
description: Using HAR / Burp project files to seed API + web scans with real auth context + endpoint inventory
triggers: [har, burp, capture, traffic mirror, postman collection, openapi, browser har, devtools]
---

# HAR / Burp Project Ingestion

When the operator has captured real authenticated traffic against the target (browser DevTools "Save All as HAR", Burp Suite project file, mitmproxy flow dump), that capture is **gold**: real endpoints, real parameter shapes, real auth tokens, real session state. Strix's `ingest_har_file` and `ingest_burp_file` tools turn these captures into the surface map every subsequent specialist scans against.

This is also Strix's answer to Akto's runtime API mirroring — without an eBPF agent, captured traffic is the next best thing.

## When to Use This

| Scenario | Why HAR / Burp |
|---|---|
| **Authenticated SPA**: app behind a complex login (SSO, MFA, CAPTCHA) | The operator logs in once; Strix replays the captured session |
| **Undocumented APIs**: no OpenAPI spec; many endpoints | Capture reveals every endpoint the SPA calls |
| **Stateful flows**: cart, checkout, multi-step wizard | Capture preserves the state chain |
| **Custom auth schemes**: HMAC headers, request signing, time-based tokens | Capture's auth state is just blob bytes; Strix replays verbatim |
| **Mobile API surface**: app + API only callable from mobile | Capture via mitmproxy with the mobile certificate installed |

## Capture Sources

### Browser DevTools HAR

```
1. Open Chrome / Firefox DevTools → Network tab
2. Clear the network log
3. Reload + interact with the app normally (cover the important flows)
4. Right-click → "Save all as HAR with content"
5. Save to har/<flow_name>.har
```

Coverage hint: deliberately exercise admin pages, file uploads, search, checkout, profile-update, password change — the high-value surfaces.

### Burp Suite project file

```
1. Open Burp Suite → File → New Project on disk → save to my_engagement.burp
2. Configure browser to proxy through Burp
3. Browse the app normally; Burp records every request to Site Map + Proxy History
4. File → Save State (or it auto-saves to .burp)
5. Hand .burp to strix
```

### mitmproxy flow dump

```bash
mitmproxy --mode regular --listen-port 8080 -w flows.mitm
# Configure browser/mobile to proxy through localhost:8080
# Use the app normally
# Ctrl-C → flows.mitm is the dump
```

### Postman collection (related but not identical)

```bash
# Postman collections describe the endpoints + variables but lack live capture
# Convert via postman-to-openapi, then use openapi_spec_ingest instead
postman-to-openapi collection.json -o openapi.yaml
```

## Strix Ingestion

### `ingest_har_file`

```bash
# Pull endpoint inventory + auth context out of a HAR
strix ingest_har_file --har-file har/checkout.har

# Output: surface_map.json entries with:
#   - URL templates (parameterised by ID-shaped path segments)
#   - per-endpoint parameter inventory (query + body)
#   - auth header / cookie state
#   - response shapes (for IDOR diff baselining)
```

### `ingest_burp_file`

```bash
strix ingest_burp_file --burp-file my_engagement.burp

# Same shape as HAR, but Burp's Site Map adds:
#   - Comments + tags the operator left
#   - Custom request rules (matched-and-replaced)
#   - Issues already-flagged by Burp's scanner
```

### Driving subsequent scans

```bash
# Replay-mutation across all captured endpoints
strix replay_mutation_from_har_file --har-file checkout.har --mutation idor
strix replay_mutation_from_burp_file --burp-file engagement.burp --mutation sqli

# Or feed the surface map into a full scan
strix --target https://app.example.com \
      --scan-mode standard \
      --har-file checkout.har \
      --burp-file engagement.burp
```

## Operational Runbook

### Step 1 — capture deliberately

Don't just "browse around". Hit the high-value surfaces:
- **Admin pages**: any URL with `/admin`, `/manage`, `/internal`
- **File uploads**: avatar, document, attachment
- **Search**: parametrised queries that look like they hit a DB
- **Checkout / payment**: stateful + financial
- **Profile / password change**: identity-altering
- **Settings / preferences**: persisted across sessions
- **Reports / exports**: server-side rendering / template engines

Cover at least one request per route. Avoid 1000s of duplicates — Strix dedups but capture noise costs runtime.

### Step 2 — sanitise (if sharing)

```bash
# Strip sensitive bodies / cookies before sharing the .har / .burp
# Strix preserves the structure; consumers don't need real credentials

# HAR: jq to strip cookies + auth headers
jq 'del(.log.entries[].request.cookies, .log.entries[].request.headers[] | select(.name | ascii_downcase == "authorization"))' \
  checkout.har > checkout_sanitised.har
```

For Strix's own use, **keep the auth state** — it's what makes the scan authenticated.

### Step 3 — feed into Strix

```bash
strix --target https://app.example.com \
      --scan-mode standard \
      --har-file har/admin_flow.har \
      --har-file har/checkout_flow.har \
      --output-dir runs/$(date +%Y%m%d)/
```

Multiple HARs are unioned; same for multiple Burp projects.

### Step 4 — scope control

```bash
# Restrict to the captured surface (no random crawling)
strix --target https://app.example.com \
      --scope-mode strict \
      --har-file engagement.har

# Or scope to a route prefix
strix --target https://app.example.com \
      --include-path '/admin/*' \
      --include-path '/api/v2/*' \
      --burp-file engagement.burp
```

`--scope-mode strict` prevents the agent from probing endpoints not in the surface map. Use this when the engagement is bounded by SOW.

### Step 5 — confirm coverage

```bash
# How many endpoints did ingestion surface?
cat runs/<id>/surface_map.json | jq '.endpoints | length'

# Per-method breakdown
cat runs/<id>/surface_map.json | jq '.endpoints | group_by(.method) | map({method: .[0].method, count: length})'

# Auth state captured
cat runs/<id>/surface_map.json | jq '.auth_states'
```

## What the Ingester Extracts

### From HAR
- URL templates (with ID-shaped segments parameterised: `/users/42/orders/abc` → `/users/{id}/orders/{order_id}`)
- HTTP method per endpoint
- Query parameter keys + sample values
- Body parameter shape (form-encoded vs JSON vs multipart)
- Request headers (auth state)
- Response status + body length + content-type
- WebSocket upgrade detection

### From Burp
- Everything HAR has, plus:
- Operator's Burp Site Map annotations (`comments` + `highlight`)
- Pre-flagged issues from Burp's passive scanner
- Match-and-replace rules used during capture
- Repeater / Intruder request templates

## Authentication Replay

The captured auth state is the most valuable bit. Strix preserves:
- `Cookie:` headers
- `Authorization:` headers (Bearer / Basic / custom)
- `X-CSRF-Token` / `X-Requested-With` / framework-specific headers
- `set-cookie` chains across login flows (Strix follows the chain)
- WebSocket subprotocol auth (Sec-WebSocket-Protocol)

For tokens with **short TTLs** or **rotation**, the operator may need to re-capture mid-engagement.

## Pro Tips

1. **Capture the failure paths too**: visit `/admin` while logged in as a regular user; Strix learns "this endpoint exists" + "auth state X gets 403". Useful for authz testing.
2. **HAR over Burp for non-tech operators**: browser DevTools requires zero setup; .har files are widely supported.
3. **Burp for adversarial captures**: when you want full control of mid-request mutation history.
4. **mitmproxy for mobile**: install the mitmproxy cert on a test phone; capture the full mobile API surface.
5. **Postman collections complement, not replace**: collections describe intent; HARs describe what actually happened. Use openapi_spec_ingest for the former, HAR ingestion for the latter.
6. **Old HARs decay**: tokens expire; backend changes. Re-capture if the engagement spans more than 1-2 days.

## Validation

1. `surface_map.json` contains the endpoints you exercised during capture.
2. `auth_states` list includes the session cookie + bearer token.
3. The lead's first dispatched specialist successfully replays a captured request (status code matches baseline).
4. `replay_mutation_*` orchestrator emits per-endpoint findings.

## False Positives

- HAR captured against a different environment (staging vs prod) — mismatched origin will fail replay.
- Capture too short to cover the relevant flows — many endpoints unreached.
- Pre-redacted HAR with auth bodies stripped — Strix can't replay authentication.

## Impact on Scan Quality

- **+200-500% endpoint coverage** for SPAs with no OpenAPI spec.
- **Authenticated probing** that would otherwise require complex login automation.
- **Stateful flow coverage** (cart, checkout, multi-step) that crawlers can't reach.
- **Realistic parameter shapes** — the agent doesn't have to guess at body structure.

## Summary

HAR + Burp capture turns the agent from "crawler" to "engineer who's been using the app". For SPAs, undocumented APIs, and stateful flows, this is the highest-leverage discovery primitive after subdomain enumeration. Always offer ingestion as an option to the operator.
