---
name: race-conditions
description: Race condition testing for TOCTOU bugs, double-spend, and concurrent state manipulation
---

# Race Conditions

Concurrency bugs enable duplicate state changes, quota bypass, financial abuse, and privilege errors. Treat every read–modify–write and multi-step workflow as adversarially concurrent.

## Attack Surface

**Read-Modify-Write**
- Sequences without atomicity or proper locking

**Multi-Step Operations**
- Check → reserve → commit with gaps between phases

**Cross-Service Workflows**
- Sagas, async jobs with eventual consistency

**Rate Limits and Quotas**
- Controls implemented at the edge only

## High-Value Targets

- Payments: auth/capture/refund/void; credits/loyalty points; gift cards
- Coupons/discounts: single-use codes, stacking checks, per-user limits
- Quotas/limits: API usage, inventory reservations, seat counts, vote limits
- Auth flows: password reset/OTP consumption, session minting, device trust
- File/object storage: multi-part finalize, version writes, share-link generation
- Background jobs: export/import create/finalize endpoints; job cancellation/approve
- GraphQL mutations and batch operations; WebSocket actions

## Reconnaissance

### Identify Race Windows

- Look for explicit sequences: "check balance then deduct", "verify coupon then apply", "check inventory then purchase"
- Watch for optimistic concurrency markers: ETag/If-Match, version fields, updatedAt checks
- Examine idempotency-key support: scope (path vs principal), TTL, and persistence (cache vs DB)
- Map cross-service steps: when is state written vs published, what retries/compensations exist

### Signals

- Sequential request fails but parallel succeeds
- Duplicate rows, negative counters, over-issuance, or inconsistent aggregates
- Distinct response shapes/timings for simultaneous vs sequential requests
- Audit logs out of order; multiple 2xx for the same intent; missing or duplicate correlation IDs

## Key Vulnerabilities

### Request Synchronization

- HTTP/2 multiplexing for tight concurrency; send many requests on warmed connections
- Last-byte synchronization: hold requests open and release final byte simultaneously
- Connection warming: pre-establish sessions, cookies, and TLS to remove jitter

### Idempotency and Dedup Bypass

- Reuse the same idempotency key across different principals/paths if scope is inadequate
- Hit the endpoint before the idempotency store is written (cache-before-commit windows)
- App-level dedup drops only the response while side effects (emails/credits) still occur

### Atomicity Gaps

- Lost update: read-modify-write increments without atomic DB statements
- Partial two-phase workflows: success committed before validation completes
- Unique checks done outside a unique index/upsert: create duplicates under load

### Cross-Service Races

- Saga/compensation timing gaps: execute compensation without preventing the original success path
- Eventual consistency windows: act in Service B before Service A's write is visible
- Retry storms: duplicate side effects due to at-least-once delivery without idempotent consumers

### Rate Limits and Quotas

- Per-IP or per-connection enforcement: bypass with multiple IPs/sessions
- Counter updates not atomic or sharded inconsistently; send bursts before counters propagate

### Optimistic Concurrency Evasion

- Omit If-Match/ETag where optional; supply stale versions if server ignores them
- Version fields accepted but not validated across all code paths (e.g., GraphQL vs REST)

### Database Isolation

- Exploit READ COMMITTED/REPEATABLE READ anomalies: phantoms, non-serializable sequences
- Upsert races: use unique indexes with proper ON CONFLICT/UPSERT or exploit naive existence checks
- Lock granularity issues: row vs table; application locks held only in-process

### Distributed Locks

- Redis locks without NX/EX or fencing tokens allow multiple winners
- Locks stored in memory on a single node; bypass by hitting other nodes/regions

## Bypass Techniques

- Distribute across IPs, sessions, and user accounts to evade per-entity throttles
- Switch methods/content-types/endpoints that trigger the same state change via different code paths
- Intentionally trigger timeouts to provoke retries that cause duplicate side effects
- Degrade the target (large payloads, slow endpoints) to widen race windows

## Special Contexts

### GraphQL

- Parallel mutations and batched operations may bypass per-mutation guards
- Ensure resolver-level idempotency and atomicity
- Persisted queries and aliases can hide multiple state changes in one request

### WebSocket

- Per-message authorization and idempotency must hold
- Concurrent emits can create duplicates if only the handshake is checked

### Files and Storage

- Parallel finalize/complete on multi-part uploads can create duplicate or corrupted objects
- Re-use pre-signed URLs concurrently

### Auth Flows

- Concurrent consumption of one-time tokens (reset codes, magic links) to mint multiple sessions
- Verify consume is atomic

## Chaining Attacks

- Race + Business logic: violate invariants (double-refund, limit slicing)
- Race + IDOR: modify or read others' resources before ownership checks complete
- Race + CSRF: trigger parallel actions from a victim to amplify effects
- Race + Caching: stale caches re-serve privileged states after concurrent changes

## Operational Runbook

Once a state-changing endpoint is identified (apply coupon, redeem credit, transfer funds, redeem one-time invite), this is the canonical race-condition exploitation flow.

### Step 1 — establish baseline + invariant

```bash
# What's the rule? "Coupon can be applied once per account" / "max 1 transfer per minute"
# Capture the legitimate single-request behavior
curl -s -X POST '<TARGET>/api/apply-coupon' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code":"SAVE50"}' | jq .

# Read the account state — credits / balance / status before
BEFORE=$(curl -s '<TARGET>/api/account' -H "Authorization: Bearer $TOKEN" | jq -r '.credits')
echo "Before: $BEFORE"
```

### Step 2 — Burp Turbo Intruder / Python concurrent baseline

The single-packet attack (HTTP/2 frames sent in one TCP packet) gives the smallest possible time-of-check window:

```python
# Python (httpx + asyncio) — fire N requests in parallel
import asyncio, httpx, time

URL = "<TARGET>/api/apply-coupon"
TOKEN = "<bearer>"
N = 30   # number of parallel requests

async def fire(client, i):
    return await client.post(URL,
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"code": "SAVE50"},
    )

async def main():
    async with httpx.AsyncClient(http2=True, timeout=15.0) as client:
        start = time.perf_counter()
        results = await asyncio.gather(*[fire(client, i) for i in range(N)])
        for i, r in enumerate(results):
            print(f"{i:02d} {r.status_code} {r.json().get('credits')}")

asyncio.run(main())
```

### Step 3 — Burp Turbo Intruder (more reliable than Python for true single-packet)

```python
# Burp Turbo Intruder script
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30,
                            requestsPerConnection=30, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req)
    # Send all 30 in a single TCP packet (HTTP/2 frame coalescing)
    engine.start(timeout=10)

def handleResponse(req, interesting):
    table.add(req)
```

### Step 4 — measure the violation

```bash
# Re-read account state — did the invariant hold?
AFTER=$(curl -s '<TARGET>/api/account' -H "Authorization: Bearer $TOKEN" | jq -r '.credits')
echo "After 30 parallel applies: $AFTER (expected $(($BEFORE + 50)), got $AFTER)"
```

If 30 parallel "apply coupon" requests resulted in 30 × $50 credits → **TOCTOU race confirmed**.

### Step 5 — common high-value races

| Target | Race window | Impact |
|---|---|---|
| Discount/coupon apply | between "has this user used it?" check and write | Free unlimited credit |
| Currency transfer between accounts | between balance-read and balance-write | Double-spend / overdraft |
| One-time invitation redeem | between "is invite unused?" and "mark used" | Multiple accounts claim same invite |
| Per-resource quota (file uploads / API calls) | between counter-read and counter-write | Bypass rate limits |
| Password-reset token use | between "is token valid?" and "invalidate token" | Multiple sessions hijacked |
| Account creation w/ uniqueness | between "does this email exist?" and INSERT | Duplicate accounts → split-brain |
| Email change confirmation | between "is this confirmation token fresh?" and write | Bind email to attacker |

### Step 6 — second-order race (state mutation across endpoints)

When a single endpoint's race is patched but the *workflow* between two endpoints isn't atomic:

```bash
# Endpoint A: deduct balance
# Endpoint B: credit recipient
# If A succeeds but B fails (network blip), is the money refunded?
# Race: fire A 30× while B is artificially slow → 30 deductions, only 1 credit
```

Test with deliberate delays / network throttling between the two phases.

### Step 7 — record evidence

Document:
- Single-request baseline (proves intended behavior)
- Parallel-request response set (status codes, returned values)
- Final state (account balance, credit count, redemption status)
- Calculation of impact (e.g. "30 requests × $50 = $1500 extracted in <100ms")

Severity scales with extractable value. Anything that mints currency / credits / privileged tokens is **critical**.

## Testing Methodology

1. **Model invariants** - Conservation of value, uniqueness, maximums for each workflow
2. **Identify reads/writes** - Where they occur (service, DB, cache)
3. **Baseline** - Single requests to establish expected behavior
4. **Concurrent requests** - Issue parallel requests with identical inputs; observe deltas
5. **Scale and synchronize** - Ramp up parallelism, use HTTP/2, align timing (last-byte sync)
6. **Cross-channel** - Test across web, API, GraphQL, WebSocket
7. **Confirm durability** - Verify state changes persist and are reproducible

## Validation

1. Single request denied; N concurrent requests succeed where only 1 should
2. Durable state change proven (ledger entries, inventory counts, role/flag changes)
3. Reproducible under controlled synchronization (HTTP/2, last-byte sync) across multiple runs
4. Evidence across channels (e.g., REST and GraphQL) if applicable
5. Include before/after state and exact request set used

## False Positives

- Truly idempotent operations with enforced ETag/version checks or unique constraints
- Serializable transactions or correct advisory locks/queues
- Visual-only glitches without durable state change
- Rate limits that reject excess with atomic counters

## Impact

- Financial loss (double spend, over-issuance of credits/refunds)
- Policy/limit bypass (quotas, single-use tokens, seat counts)
- Data integrity corruption and audit trail inconsistencies
- Privilege or role errors due to concurrent updates

## Pro Tips

1. Favor HTTP/2 with warmed connections; add last-byte sync for precision
2. Start small (N=5–20), then scale; too much noise can mask the window
3. Target read–modify–write code paths and endpoints with idempotency keys
4. Compare REST vs GraphQL vs WebSocket; protections often differ
5. Look for cross-service gaps (queues, jobs, webhooks) and retry semantics
6. Check unique constraints and upsert usage; avoid relying on pre-insert checks
7. Use correlation IDs and logs to prove concurrent interleaving
8. Widen windows by adding server load or slow backend dependencies
9. Validate on production-like latency; some races only appear under real load
10. Document minimal, repeatable request sets that demonstrate durable impact

## Summary

Concurrency safety is a property of every path that mutates state. If any path lacks atomicity, proper isolation, or idempotency, parallel requests will eventually break invariants.
