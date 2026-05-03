---
name: api_top_10
description: OWASP API Security Top 10 (2023) overview — index mapping each item to a focused skill, plus API-specific framing the agent should apply for pure-API targets
---

# OWASP API Security Top 10 (2023) — Skill Index

Use this skill on **pure-API targets** (JSON-only, no HTML, GraphQL, mobile-app backends) — frames the test methodology API-first rather than web-app-first. Load alongside one or two of the focused skills referenced below for concrete attack catalogs.

## Why a separate API view

Web-app skills (`xss`, `csrf`, `idor`) are written assuming HTML responses, browser DOMs, form submissions. Pure-API targets break that:

- No HTML → no reflected XSS in the traditional sense (but JSON-injection is still a thing)
- No browser session → CSRF rarely applies (token-based auth instead of cookies)
- No forms → mass-assignment / BOPLA happens at the JSON property level
- Heavier reliance on auth tokens (JWT / Bearer / API keys)
- Microservice mesh trust assumptions
- Higher cost-per-request (LLM tokens, SMS, third-party APIs)
- Programmatic clients hit limits / batch endpoints in ways human users never do

This skill primes the agent for that framing.

## Top 10 → skill mapping

| OWASP API Top 10 (2023) | Focused skill | Notes |
|---|---|---|
| **API1: Broken Object Level Authorization (BOLA)** | `idor` | Same root cause as web IDOR. `authz_matrix_check` tool detects deterministically when role-set is supplied. |
| **API2: Broken Authentication** | `authentication_jwt` | JWT-specific catalog covers signature confusion / `alg:none` / weak secrets / kid abuse. Generic broken-auth (default creds, sessionfixation) blends in too. |
| **API3: Broken Object Property Level Authorization (BOPLA)** | **`api_bopla` (read-side)** + `mass_assignment` (write-side) | Read-side: response over-discloses fields. Write-side: caller sets fields they shouldn't. Both = full BOPLA coverage. |
| **API4: Unrestricted Resource Consumption** | **`api_resource_consumption`** | Pagination DoS, batch abuse, GraphQL complexity, money-cost amplification. |
| **API5: Broken Function Level Authorization (BFLA)** | `broken_function_level_authorization` | `authz_matrix_check` detects automatically when role-set is supplied. |
| **API6: Unrestricted Access to Sensitive Business Flows** | `business_logic` | Workflow-level abuse (race conditions in checkout, bulk-purchase abuse, referral system gaming) — the `race_conditions` skill is also relevant for the timing slice. |
| **API7: Server-Side Request Forgery (SSRF)** | `ssrf` | Standard SSRF; for the API-API axis (one API consuming another), see `api_unsafe_upstream`. |
| **API8: Security Misconfiguration** | `information_disclosure` + `api_inventory` | Disclosure-shaped misconfigs (CORS wildcards, debug headers, env in stack traces) → `information_disclosure`. Endpoint-shaped misconfigs (debug routes enabled, beta APIs exposed) → `api_inventory`. |
| **API9: Improper Inventory Management** | **`api_inventory`** | Version-rot, debug endpoints, staging-in-prod, source maps, undocumented endpoints. |
| **API10: Unsafe Consumption of APIs** | **`api_unsafe_upstream`** | Blindly trusting upstream API responses; webhook signature verification; hardcoded upstream credentials. |

**Bold** entries are the four API-specific skills introduced for gaps the existing web-app catalog didn't cover. Load a subset along with the existing skills for full API Top 10 coverage in a single agent context.

## API-specific test methodology

### 1. Inventory first

Before touching any specific vuln class, exhaust the endpoint inventory:

```python
# Use the BFS crawler with the OpenAPI spec when available:
bfs_crawl(
    target="https://api.target",
    openapi_url="https://api.target/openapi.json",
    max_pages=500,
)

# Look for inventory gaps (API9):
api_inventory  # version enumeration, debug-path probing
```

Findings here color every subsequent test — an undocumented `v1` endpoint may have ALL the bugs that were fixed in `v3`.

### 2. Authentication + authorization in one matrix

Run `authz_matrix_check` over the inventory with at least 3 roles:

```python
authz_matrix_check(
    endpoints=...,  # crawl output verbatim
    roles=[
        {"name": "unauth", "headers": {}},
        {"name": "user", "headers": {"Authorization": "Bearer USER_TOK"}, "privilege": 50},
        {"name": "admin", "headers": {"Authorization": "Bearer ADMIN_TOK"}, "privilege": 100},
    ],
)
```

Finds API1 (BOLA) + API5 (BFLA) cells in one pass. Surfaces high-value endpoints for the read-side (BOPLA) check.

### 3. BOPLA read-side audit

For each endpoint where multiple roles return 200, eyeball the JSON for over-exposure (see `api_bopla`). Compare detail vs list endpoints — the detail version often has fields the list endpoint hides.

### 4. Resource-consumption audit

For high-cost-shaped endpoints (auth flows, search, exports, anything triggering upstream API calls), test pagination/batch/complexity bounds (see `api_resource_consumption`). Especially target money-cost endpoints (SMS / email / LLM).

### 5. Upstream / cross-API trust audit

For each upstream the API consumes (visible via fingerprinting + JS bundle inspection), test the trust boundary (see `api_unsafe_upstream`). Where SSRF gets you into the internal mesh, identity-assertion forgery becomes practical.

### 6. Standard injection / SSRF / RCE

Same as web (load `sql_injection` / `xss` / `ssrf` / `xxe` / `rce` as needed) — but with API-specific twists:

- **JSON-injection / type confusion** — passing `[null]` where a string is expected, `{}` where a number is expected
- **GraphQL-specific**: introspection (when in prod), depth/width DoS, alias overloading, batched mutation race
- **Mass assignment** through JSON body parameters that aren't documented

## Common API-specific anti-patterns

| Pattern | Test |
|---|---|
| Auth check is in middleware but a route was added without going through it | `authz_matrix_check` — the rogue route appears as `unauth=200` |
| GraphQL exposes types via introspection, exposing fields the REST API filters | Introspection + per-field auth check |
| Batch endpoint loops without applying per-op auth | Submit batch with mixed-victim object IDs; observe |
| Webhook signed with HMAC-MD5 / shared key in plain text in source | `api_unsafe_upstream` reconnaissance |
| API key has admin scope; no rotation; same key per environment | `api_inventory` source-map probe |
| Pagination accepts negative limits → DoS | `api_resource_consumption` pagination test |
| `Set-Cookie` from upstream OAuth provider proxied to client | `api_unsafe_upstream` |

## Findings tagging

When emitting findings, tag with the matching OWASP API Top 10 ID in the description (e.g. "OWASP API3:2023 — Broken Object Property Level Authorization") so the wrapper / auditor can group by the framework. Pairs with the §16 compliance-control mapping work — once that ships, this tagging becomes structured rather than prose.
