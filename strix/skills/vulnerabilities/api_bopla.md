---
name: api_bopla
description: API3 Broken Object Property Level Authorization — read-side excessive data exposure (object properties returned to unauthorized callers); pairs with mass_assignment for write-side
---

# API Broken Object Property Level Authorization (BOPLA, read-side)

OWASP API Top 10 — **API3:2023**. The endpoint correctly authorizes access to the *object* (BOLA passes), but returns *properties of that object* the caller shouldn't see. Hardest BOLA-adjacent class to detect because the response status is normal (200), and the over-exposed fields are buried in legitimate-looking JSON.

Pairs with `mass_assignment` (write-side BOPLA — caller sets fields they shouldn't be able to). This skill is the **read-side**.

## Attack surface

- REST endpoints returning JSON / GraphQL field selections
- `GET /users/me`, `GET /users/{id}`, `GET /orgs/{id}/members`, `GET /tickets/{id}`
- Admin-tier endpoints that ALSO serve regular users with the same shape
- Detail-vs-list discrepancies (`GET /users` returns 5 fields; `GET /users/{id}` returns 30)
- Verbose ORM serializers (Django REST `__all__` / `ModelSerializer`, Rails `as_json`, Sequelize `toJSON`)
- GraphQL fields — every field on a returned type is a potential leak

## High-value sensitive properties

| Category | Example field names |
|---|---|
| Auth secrets | `password_hash`, `password`, `mfa_secret`, `totp_seed`, `recovery_codes`, `api_key`, `session_token` |
| Session metadata | `last_login_ip`, `last_user_agent`, `failed_login_count`, `account_locked_until`, `created_by_admin_id` |
| Internal flags | `is_admin`, `is_staff`, `is_superuser`, `permissions[]`, `feature_flags`, `internal_notes`, `risk_score` |
| Billing | `stripe_customer_id`, `card_last4`, `card_fingerprint`, `subscription_internal_id` |
| PII | `ssn`, `tax_id`, `passport_number`, `dob`, `phone`, `address` (when not the caller's own) |
| Org metadata | `parent_org_id`, `tenant_id`, `created_by`, `internal_owner_email` |

## Reconnaissance

### Discover the endpoint set

```bash
# Use bfs_crawl to populate the endpoint inventory.
# Alternatively, request OpenAPI / Swagger:
curl https://api.target/openapi.json | jq '.paths | keys'
```

### Compare across roles

For each endpoint, request as multiple roles:

| Role | Expected response |
|---|---|
| Owner of the object | All public + private fields |
| Member of the same org but not owner | Public-only |
| Member of a different org | 404 (not own) or 403 |
| Unauthenticated | 401 |

Use `authz_matrix_check` for the row-permission check (BOLA), then *for endpoints where every role gets 200*, eyeball the JSON schema for over-exposure.

### Compare across endpoints

```bash
# Detail endpoint — many fields:
curl -s -H "$AUTH" https://api.target/users/me | jq 'keys' | wc -l
# List endpoint — should expose strictly fewer fields:
curl -s -H "$AUTH" https://api.target/users | jq '.[0] | keys' | wc -l
```

If `GET /users/{id}` returns 30 fields but `GET /users` (list) returns only 5, the list is hiding fields *that exist* — the per-object endpoint exposes them all. Test whether *another user* can fetch your detail endpoint and see the same 30 fields.

## Exploitation patterns

### 1. Enumerate every property on a normal response

Don't just look at the body — pull the schema:

```bash
curl -s -H "$AUTH" "https://api.target/me" | jq 'keys'
# Cross-reference against the OpenAPI spec:
curl -s "https://api.target/openapi.json" | jq '.components.schemas.User.properties | keys'
```

Properties in the spec but **not** in your response = backend filters them. Properties **in your response** but in a "sensitive" naming pattern = potential leak. Properties returned across roles inconsistently = explicit gap.

### 2. GraphQL field-level introspection

```graphql
{
  __type(name: "User") {
    fields { name }
  }
}
```

Then request every field and see which the server actually returns:

```graphql
{ user(id: "$VICTIM_ID") {
    id email passwordHash mfaSecret apiKey internalNotes
} }
```

Backend may silently null-out forbidden fields (good) — or return them (BOPLA).

### 3. Verbose error / debug endpoints

```
GET /api/users/{id}?debug=1
GET /api/users/{id}?include=internal
GET /api/users/{id}?fields=*
GET /api/users/{id}.json (Rails)
```

Verbose-mode parameters frequently bypass field filters.

### 4. Embedded/nested expansion

```
GET /api/orders/123?expand=user
GET /api/orders/123?include=user.password_hash
GET /api/orders/123?fields=user(*)
```

Sub-resource expansion often skips the per-property auth check.

## Verification

For each suspected over-exposed field:

1. Capture the response with the field present.
2. Capture a peer role's response — confirm the field is **gated** for that role.
3. Decide: is the field actually sensitive, or just internal-but-harmless?

False-positive guard: many `id` / `created_at` / `updated_at` fields look "internal" but aren't sensitive. Only flag if disclosure crosses a real privacy / security boundary (auth secrets, billing identifiers, cross-tenant references, PII not in scope of the requesting user).

## Findings to emit

- **High** (CWE-200, info_disclosure) — auth secrets / session tokens / MFA secrets returned
- **High** (CWE-639, BOLA-adjacent) — internal admin flags exposed to non-admin
- **Medium** (CWE-200) — billing identifiers / cross-tenant references exposed
- **Medium** (CWE-359, privacy violation) — PII (SSN / DOB / address) of users other than the caller
- **Low** — internal-but-non-sensitive fields (e.g. `created_by`, `risk_score` of self)

Always set `verification_status="needs_review"` unless you have a peer-role response showing the field was gated correctly for that peer.

## Mitigation guidance (in remediation_steps)

- Define explicit DTOs / response schemas per role; never serialize the full ORM model
- Whitelist fields, don't blacklist — additions to the model auto-leak with blacklists
- Apply per-property authorization at the serializer layer, not just the controller
- Tag sensitive fields in the schema; CI test asserts they never appear in responses below a privilege threshold
- For GraphQL: add field-level auth directives (`@auth(requires: ADMIN)`)

## Related skills

- `idor` — object-level (BOLA, API1)
- `mass_assignment` — write-side BOPLA
- `broken_function_level_authorization` — BFLA (API5)
- `information_disclosure` — adjacent generic disclosure patterns
