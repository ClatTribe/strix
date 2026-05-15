---
name: business-logic
description: Business logic testing for workflow bypass, state manipulation, and domain invariant violations
---

# Business Logic Flaws

Business logic flaws exploit intended functionality to violate domain invariants: move money without paying, exceed limits, retain privileges, or bypass reviews. They require a model of the business, not just payloads.

## Attack Surface

- Financial logic: pricing, discounts, payments, refunds, credits, chargebacks
- Account lifecycle: signup, upgrade/downgrade, trial, suspension, deletion
- Authorization-by-logic: feature gates, role transitions, approval workflows
- Quotas/limits: rate/usage limits, inventory, entitlements, seat licensing
- Multi-tenant isolation: cross-organization data or action bleed
- Event-driven flows: jobs, webhooks, sagas, compensations, idempotency

## High-Value Targets

- Pricing/cart: price locks, quote to order, tax/shipping computation
- Discount engines: stacking, mutual exclusivity, scope (cart vs item), once-per-user enforcement
- Payments: auth/capture/void/refund sequences, partials, split tenders, chargebacks, idempotency keys
- Credits/gift cards/vouchers: issuance, redemption, reversal, expiry, transferability
- Subscriptions: proration, upgrade/downgrade, trial extension, seat counts, meter reporting
- Refunds/returns/RMAs: multi-item partials, restocking fees, return window edges
- Admin/staff operations: impersonation, manual adjustments, credit/refund issuance, account flags
- Quotas/limits: daily/monthly usage, inventory reservations, feature usage counters

## Reconnaissance

### Workflow Mapping

- Derive endpoints from the UI and proxy/network logs; map hidden/undocumented API calls, especially finalize/confirm endpoints
- Identify tokens/flags: stepToken, paymentIntentId, orderStatus, reviewState, approvalId; test reuse across users/sessions
- Document invariants: conservation of value (ledger balance), uniqueness (idempotency), monotonicity (non-decreasing counters), exclusivity (one active subscription)

### Input Surface

- Hidden fields and client-computed totals; server must recompute on trusted sources
- Alternate encodings and shapes: arrays instead of scalars, objects with unexpected keys, null/empty/0/negative, scientific notation
- Business selectors: currency, locale, timezone, tax region; vary to trigger rounding and ruleset changes

### State and Time Axes

- Replays: resubmit stale finalize/confirm requests
- Out-of-order: call finalize before verify; refund before capture; cancel after ship
- Time windows: end-of-day/month cutovers, daylight saving, grace periods, trial expiry edges

## Key Vulnerabilities

### State Machine Abuse

- Skip or reorder steps via direct API calls; verify server enforces preconditions on each transition
- Replay prior steps with altered parameters (e.g., swap price after approval but before capture)
- Split a single constrained action into many sub-actions under the threshold (limit slicing)

### Concurrency and Idempotency

- Parallelize identical operations to bypass atomic checks (create, apply, redeem, transfer)
- Abuse idempotency: key scoped to path but not principal → reuse other users' keys; or idempotency stored only in cache
- Message reprocessing: queue workers re-run tasks on retry without idempotent guards; cause duplicate fulfillment/refund

### Numeric and Currency

- Floating point vs decimal rounding; rounding/truncation favoring attacker at boundaries
- Cross-currency arbitrage: buy in currency A, refund in B at stale rates; tax rounding per-item vs per-order
- Negative amounts, zero-price, free shipping thresholds, minimum/maximum guardrails

### Quotas, Limits, and Inventory

- Off-by-one and time-bound resets (UTC vs local); pre-warm at T-1s and post-fire at T+1s
- Reservation/hold leaks: reserve multiple, complete one, release not enforced; backorder logic inconsistencies
- Distributed counters without strong consistency enabling double-consumption

### Refunds and Chargebacks

- Double-refund: refund via UI and support tool; refund partials summing above captured amount
- Refund after benefits consumed (downloaded digital goods, shipped items) due to missing post-consumption checks

### Feature Gates and Roles

- Feature flags enforced client-side or at edge but not in core services; toggle names guessed or fallback to default-enabled
- Role transitions leaving stale capabilities (retain premium after downgrade; retain admin endpoints after demotion)

## Advanced Techniques

### Event-Driven Sagas

- Saga/compensation gaps: trigger compensation without original success; or execute success twice without compensation
- Outbox/Inbox patterns missing idempotency → duplicate downstream side effects
- Cron/backfill jobs operating outside request-time authorization; mutate state broadly

### Microservices Boundaries

- Cross-service assumption mismatch: one service validates total, another trusts line items; alter between calls
- Header trust: internal services trusting X-Role or X-User-Id from untrusted edges
- Partial failure windows: two-phase actions where phase 1 commits without phase 2, leaving exploitable intermediate state

### Multi-Tenant Isolation

- Tenant-scoped counters and credits updated without tenant key in the where-clause; leak across orgs
- Admin aggregate views allowing actions that impact other tenants due to missing per-tenant enforcement

## Bypass Techniques

- Content-type switching (JSON/form/multipart) to hit different code paths
- Method alternation (GET performing state change; overrides via X-HTTP-Method-Override)
- Client recomputation: totals, taxes, discounts computed on client and accepted by server
- Cache/gateway differentials: stale decisions from CDN/APIM that are not identity-aware

## Special Contexts

### E-commerce

- Stack incompatible discounts via parallel apply; remove qualifying item after discount applied; retain free shipping after cart changes
- Modify shipping tier post-quote; abuse returns to keep product and refund

### Banking/Fintech

- Split transfers to bypass per-transaction threshold; schedule vs instant path inconsistencies
- Exploit grace periods on holds/authorizations to withdraw again before settlement

### SaaS/B2B

- Seat licensing: race seat assignment to exceed purchased seats; stale license checks in background tasks
- Usage metering: report late or duplicate usage to avoid billing or to over-consume

## Chaining Attacks

- Business logic + race: duplicate benefits before state updates
- Business logic + IDOR: operate on others' resources once a workflow leak reveals IDs
- Business logic + CSRF: force a victim to complete a sensitive step sequence

## Operational Runbook

Business-logic abuse doesn't map to a single payload. The flow is: model the intended state machine → identify implicit invariants → probe transitions that the developer didn't expect.

### Step 1 — map the workflow

Pick a high-value workflow (purchase, refund, transfer, invitation, password reset). Document:

```
Step 1: POST /api/cart/add {item_id, qty}
Step 2: POST /api/checkout {address}
Step 3: POST /api/payment {card, amount}   # invariant: amount == cart total
Step 4: GET  /api/order/{id}               # invariant: status=paid before fulfilment
Step 5: POST /api/fulfilment {order_id}    # invariant: only after step 4
```

Each `→` is a transition. Each transition has implicit pre/post-conditions. Each invariant is a target.

### Step 2 — probe step skipping

```bash
# Try going straight from Step 1 to Step 5 (skip payment + checkout entirely)
CART_ID=$(curl -s -X POST '<TARGET>/api/cart/add' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"item_id":1,"qty":1}' | jq -r '.cart_id')

# Skip Steps 2-4. Does fulfilment fire without payment?
curl -s -X POST "<TARGET>/api/fulfilment" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"cart_id\":\"$CART_ID\"}" -w '\n%{http_code}\n'

# 2xx → state machine doesn't enforce step ordering. Free goods.
```

### Step 3 — probe step repetition

```bash
# Apply a single-use coupon, then apply it again
curl -s -X POST '<TARGET>/api/coupon' -H "Authorization: Bearer $TOKEN" -d '{"code":"WELCOME50"}'
curl -s -X POST '<TARGET>/api/coupon' -H "Authorization: Bearer $TOKEN" -d '{"code":"WELCOME50"}'
# Second response 2xx + balance doubled → no one-time check

# Refund an already-refunded order
curl -s -X POST '<TARGET>/api/refund' -H "Authorization: Bearer $TOKEN" -d '{"order_id":"X"}'
curl -s -X POST '<TARGET>/api/refund' -H "Authorization: Bearer $TOKEN" -d '{"order_id":"X"}'
```

### Step 4 — probe parameter tampering

```bash
# Negative quantity → negative price → server credits you
curl -s -X POST '<TARGET>/api/cart/add' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"item_id":1,"qty":-5}'

# Currency manipulation
curl -s -X POST '<TARGET>/api/payment' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"amount":1,"currency":"VND","cart_total":1000000}'
# Server confuses currencies → effectively pay $0.04 USD for $1000 worth

# Decimal overflow / precision tricks
curl -s -X POST '<TARGET>/api/payment' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"amount":0.999999999999999}'   # rounds to 1 in display, 0 in charge

# Discount > 100%
curl -s -X POST '<TARGET>/api/discount' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"percent":150}'
```

### Step 5 — probe state-machine race (overlap with race_conditions.md)

```python
# Fire 10 "transfer money" requests in parallel; if a single deduction
# results in 10 credits, the state machine isn't atomic
import asyncio, httpx
async def transfer(client):
    return await client.post("<TARGET>/api/transfer",
        json={"to":"victim","amount":100},
        headers={"Authorization":"Bearer $TOKEN"})
async def main():
    async with httpx.AsyncClient(http2=True) as c:
        results = await asyncio.gather(*[transfer(c) for _ in range(10)])
        for r in results: print(r.status_code, r.json())
asyncio.run(main())
```

### Step 6 — probe missing actor checks

```bash
# Reset another user's password by tampering the email field
curl -s -X POST '<TARGET>/api/password-reset' \
    -d '{"email":"victim@x"}'    # baseline — sends to victim

curl -s -X POST '<TARGET>/api/password-reset' \
    -d '{"email":"victim@x","redirect":"attacker@x"}'    # extra field — does server honor it?

# Submit on someone else's behalf
curl -s -X POST '<TARGET>/api/feedback' \
    -H "Authorization: Bearer $MY_TOKEN" \
    -d '{"user_id":"victim_id","content":"bad review"}'
```

### Step 7 — high-value workflow library

| Workflow | Probe |
|---|---|
| E-commerce checkout | Coupon stacking; negative qty; price tampering in client-supplied total; address swap post-payment |
| Account creation | Email verification skip; signup with `is_admin` body field; race-create with duplicate emails |
| Password reset | Reuse expired token; submit token without invalidation; replay token in concurrent sessions |
| Currency / wallet | Negative transfer; transfer to self for credits; race-double-spend; currency-symbol confusion |
| Subscription tier upgrade | Downgrade-refund-upgrade cycle; pro-rate calculation manipulation; trial reset via account suspend-unsuspend |
| Multi-factor auth setup | Skip verification step; bind attacker TOTP to victim account via partial state |
| API rate limits | Per-IP vs per-user vs per-API-key — switch identifier mid-burst |
| OAuth flow | State parameter strip; PKCE skip; redirect_uri manipulation; consent screen bypass via direct token request |
| File-upload pipeline | Skip antivirus scan step; race-upload-then-delete-AV-marker; reuse upload-token across users |

### Step 8 — record evidence

Document:
- Workflow diagram (steps + intended invariants)
- The invariant violated
- Reproducible request sequence (curl commands in order)
- Quantified impact (e.g. "applied $50 coupon 30× = $1500 free credit")
- Severity is almost always at least **high** — business-logic vulns cost real money.

## Testing Methodology

1. **Enumerate state machine** - Per critical workflow (states, transitions, pre/post-conditions); note invariants
2. **Build Actor × Action × Resource matrix** - Unauth, basic user, premium, staff/admin; identify actions per role
3. **Test transitions** - Step skipping, repetition, reordering, late mutation
4. **Introduce variance** - Time, concurrency, channel (mobile/web/API/GraphQL), content-types
5. **Validate persistence boundaries** - All services, queues, and jobs re-enforce invariants

## Validation

1. Show an invariant violation (e.g., two refunds for one charge, negative inventory, exceeding quotas)
2. Provide side-by-side evidence for intended vs abused flows with the same principal
3. Demonstrate durability: the undesired state persists and is observable in authoritative sources (ledger, emails, admin views)
4. Quantify impact per action and at scale (unit loss × feasible repetitions)

## False Positives

- Promotional behavior explicitly allowed by policy (documented free trials, goodwill credits)
- Visual-only inconsistencies with no durable or exploitable state change
- Admin-only operations with proper audit and approvals

## Impact

- Direct financial loss (fraud, arbitrage, over-refunds, unpaid consumption)
- Regulatory/contractual violations (billing accuracy, consumer protection)
- Denial of inventory/services to legitimate users through resource exhaustion
- Privilege retention or unauthorized access to premium features

## Pro Tips

1. Start from invariants and ledgers, not UI—prove conservation of value breaks
2. Test with time and concurrency; many bugs only appear under pressure
3. Recompute totals server-side; never accept client math—flag when you observe otherwise
4. Treat idempotency and retries as first-class: verify key scope and persistence
5. Probe background workers and webhooks separately; they often skip auth and rule checks
6. Validate role/feature gates at the service that mutates state, not only at the edge
7. Explore end-of-period edges (month-end, trial end, DST) for rounding and window issues
8. Use minimal, auditable PoCs that demonstrate durable state change and exact loss
9. Chain with authorization tests (IDOR/Function-level access) to magnify impact
10. When in doubt, map the state machine; gaps appear where transitions lack server-side guards

## Summary

Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.
