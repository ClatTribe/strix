---
name: broken-function-level-authorization
description: BFLA testing for action-level authorization failures across endpoints, admin functions, and API operations
---

# Broken Function Level Authorization (BFLA)

BFLA is action-level authorization failure: callers invoke functions (endpoints, mutations, admin tools) they are not entitled to. It appears when enforcement differs across transports, gateways, roles, or when services trust client hints. Bind subject × action at the service that performs the action.

## Attack Surface

- Vertical authz: privileged/admin/staff-only actions reachable by basic users
- Feature gates: toggles enforced at edge/UI, not at core services
- Transport drift: REST vs GraphQL vs gRPC vs WebSocket with inconsistent checks
- Gateway trust: backends trust X-User-Id/X-Role injected by proxies/edges
- Background workers/jobs performing actions without re-checking authz

## High-Value Actions

- Role/permission changes, impersonation/sudo, invite/accept into orgs
- Approve/void/refund/credit issuance, price/plan overrides
- Export/report generation, data deletion, account suspension/reactivation
- Feature flag toggles, quota/grant adjustments, license/seat changes
- Security settings: 2FA reset, email/phone verification overrides

## Reconnaissance

### Surface Enumeration

- Admin/staff consoles and APIs, support tools, internal-only endpoints exposed via gateway
- Hidden buttons and disabled UI paths (feature-flagged) mapped to still-live endpoints
- GraphQL schemas: mutations and admin-only fields/types; gRPC service descriptors (reflection)
- Mobile clients often reveal extra endpoints/roles in app bundles or network logs

### Signals

- 401/403 on UI but 200 via direct API call; differing status codes across transports
- Actions succeed via background jobs when direct call is denied
- Changing only headers (role/org) alters access without token change

## Key Vulnerabilities

### Verb Drift and Aliases

- Alternate methods: GET performing state change; POST vs PUT vs PATCH differences; X-HTTP-Method-Override/_method
- Alternate endpoints performing the same action with weaker checks (legacy vs v2, mobile vs web)

### Edge vs Core Mismatch

- Edge blocks an action but core service RPC accepts it directly; call internal service via exposed API route or SSRF
- Gateway-injected identity headers override token claims; supply conflicting headers to test precedence

### Feature Flag Bypass

- Client-checked feature gates; call backend endpoints directly
- Admin-only mutations exposed but hidden in UI; invoke via GraphQL or gRPC tools

### Batch Job Paths

- Create export/import jobs where creation is allowed but finalize/approve lacks authz; finalize others' jobs
- Replay webhooks/background tasks endpoints that perform privileged actions without verifying caller

### Content-Type Paths

- JSON vs form vs multipart handlers using different middleware: send the action via the most permissive parser

## Advanced Techniques

### GraphQL

- Resolver-level checks per mutation/field; do not assume top-level auth covers nested mutations or admin fields
- Abuse aliases/batching to sneak privileged fields; persisted queries sometimes bypass auth transforms

```graphql
mutation Promote($id:ID!){
  a: updateUser(id:$id, role: ADMIN){ id role }
}
```

### gRPC

- Method-level auth via interceptors must enforce audience/roles; probe direct gRPC with tokens of lower role
- Reflection lists services/methods; call admin methods that the gateway hid

### WebSocket

- Handshake-only auth: ensure per-message authorization on privileged events (e.g., admin:impersonate)
- Try emitting privileged actions after joining standard channels

### Multi-Tenant

- Actions requiring tenant admin enforced only by header/subdomain; attempt cross-tenant admin actions by switching selectors with same token

### Microservices

- Internal RPCs trust upstream checks; reach them through exposed endpoints or SSRF; verify each service re-enforces authz

## Bypass Techniques

### Header Trust

- Supply X-User-Id/X-Role/X-Organization headers; remove or contradict token claims; observe which source wins

### Route Shadowing

- Legacy/alternate routes (e.g., /admin/v1 vs /v2/admin) that skip new middleware chains

### Idempotency and Retries

- Retry or replay finalize/approve endpoints that apply state without checking actor on each call

### Cache Key Confusion

- Cached authorization decisions at edge leading to cross-user reuse; test with Vary and session swaps

## Operational Runbook

BFLA is about *actions* (admin endpoints that low-priv users can reach), distinct from IDOR (per-record auth). The probe is: take a high-priv API call → strip auth or swap to low-priv → does the action still succeed?

### Step 1 — capture admin calls

Use a high-priv account to exercise admin features and capture every state-changing call:

```bash
# As ADMIN, hit /admin/users/123/promote (or whatever)
ADMIN_TOKEN="<admin-bearer>"
curl -s -X POST '<TARGET>/api/admin/users/123/promote' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -w '\n=== admin: %{http_code} ===\n'
# Document the request — full URL, method, body, headers.
```

### Step 2 — replay as low-priv

```bash
LOW_TOKEN="<basic-user-bearer>"

# Same call, basic user's token
curl -s -X POST '<TARGET>/api/admin/users/123/promote' \
    -H "Authorization: Bearer $LOW_TOKEN" \
    -w '\n=== low-priv: %{http_code} ===\n'

# If 2xx → BFLA. Low-priv user can promote others to admin.
```

### Step 3 — replay anonymous

```bash
# No auth at all — does the endpoint even check?
curl -s -X POST '<TARGET>/api/admin/users/123/promote' \
    -w '\n=== anon: %{http_code} ===\n'
# 2xx anon → CWE-862 (missing auth entirely). Worse than BFLA.
```

### Step 4 — method-override + spoof headers

```bash
# Some gateways strip auth on non-listed methods or honor override headers
curl -s -X POST '<TARGET>/api/admin/users/123/promote' \
    -H "Authorization: Bearer $LOW_TOKEN" \
    -H "X-HTTP-Method-Override: GET" \
    -H "X-Original-URL: /api/admin/users/123/promote"

# Try common spoofing headers
for hdr in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" \
           "X-Forwarded-Host: localhost" "Host: localhost" \
           "X-Original-URL: /admin/promote" "X-Rewrite-URL: /admin/promote"; do
  curl -s -X POST '<TARGET>/api/admin/users/123/promote' \
       -H "Authorization: Bearer $LOW_TOKEN" \
       -H "$hdr" -w "$hdr → %{http_code}\n"
done
```

### Step 5 — verb-tamper authorization bypass

```bash
# Sometimes only POST is checked; PUT / PATCH / DELETE slip through
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  status=$(curl -s -o /dev/null -X $method '<TARGET>/api/admin/users/123' \
           -H "Authorization: Bearer $LOW_TOKEN" -w '%{http_code}')
  echo "$method → $status"
done
```

### Step 6 — chained background-flow abuse

Many BFLA bugs hide in async pipelines: low-priv submits a job → background worker doesn't re-check role:

```bash
# Submit a batch-promote as low-priv (job-creation often unauthenticated)
JOB=$(curl -s -X POST '<TARGET>/api/jobs' \
    -H "Authorization: Bearer $LOW_TOKEN" \
    -d '{"type":"bulk_promote","payload":{"user_ids":[123]}}' | jq -r '.id')

# Wait for the worker to pick up
sleep 5
curl -s "<TARGET>/api/users/123" -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.role'
```

### Step 7 — record evidence

Document per (action, actor-role) cell:
- HTTP method + URL + body
- The role the action SHOULD require
- The role the test actor had
- Server response (2xx = bug)
- Severity: **critical** when escalates a low-priv user to admin; **high** when it expands data access; **medium** when it grants non-security-sensitive admin features (e.g. analytics).

## Testing Methodology

1. **Build Actor × Action matrix** - Unauth, basic, premium, staff/admin; enumerate actions per role
2. **Obtain tokens/sessions** - For each role
3. **Exercise every action** - Across all transports and encodings (JSON, form, multipart), including method overrides
4. **Vary headers and selectors** - Org/tenant/project; test behind gateway vs direct-to-service
5. **Include background flows** - Job creation/finalization, webhooks, queues; confirm re-validation

## Validation

1. Show a lower-privileged principal successfully invokes a restricted action (same inputs) while the proper role succeeds and another lower role fails
2. Provide evidence across at least two transports or encodings demonstrating inconsistent enforcement
3. Demonstrate that removing/altering client-side gates (buttons/flags) does not affect backend success
4. Include durable state change proof: before/after snapshots, audit logs, and authoritative sources

## False Positives

- Read-only endpoints mislabeled as admin but publicly documented
- Feature toggles intentionally open to all roles for preview/beta with clear policy
- Simulated environments where admin endpoints are stubbed with no side effects

## Impact

- Privilege escalation to admin/staff actions
- Monetary/state impact: refunds/credits/approvals without authorization
- Tenant-wide configuration changes, impersonation, or data deletion
- Compliance and audit violations due to bypassed approval workflows

## Pro Tips

1. Start from the role matrix; test every action with basic vs admin tokens across REST/GraphQL/gRPC
2. Diff middleware stacks between routes; weak chains often exist on legacy or alternate encodings
3. Inspect gateways for identity header injection; never trust client-provided identity
4. Treat jobs/webhooks as first-class: finalize/approve must re-check the actor
5. Prefer minimal PoCs: one request that flips a privileged field or invokes an admin method with a basic token

## Summary

Authorization must bind the actor to the specific action at the service boundary on every request and message. UI gates, gateways, or prior steps do not substitute for function-level checks.
