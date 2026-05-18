---
name: cloudflare-workers
description: Cloudflare Workers + Pages + Pages Functions — KV / D1 / R2 bindings, Service Bindings, Durable Objects, Email Workers
triggers: [cloudflare workers, cloudflare pages, wrangler, kv namespace, d1, r2, durable objects, service binding, email worker, queue]
---

# Cloudflare Workers Security

Cloudflare Workers is a V8-isolate-based serverless runtime; Pages is the static + Pages-Functions hosting layer. Both share the same security model: **bindings** (KV, D1, R2, Service, Queue, Durable Object, AI, Vectorize) wired at deploy time via `wrangler.toml`. Bugs cluster around (1) **binding-secret exposure** via Worker code, (2) **public-Workers calling private services**, (3) **Pages Functions auth gaps**, (4) **`env` object leakage** in error handling, and (5) **Service Bindings circumventing external rate limits / WAF**.

## Attack Surface

### Bindings (the core security boundary)
| Binding | Surface |
|---|---|
| KV (key-value store) | `env.MY_KV.get/put/delete` — full namespace access |
| D1 (SQLite) | `env.DB.prepare('...').bind(...).first/all/run` — SQL access |
| R2 (S3-compatible) | `env.MY_BUCKET.get/put/delete/list` |
| Service Binding | `env.OTHER_WORKER.fetch(...)` — direct Worker-to-Worker call bypassing public network |
| Queue | `env.MY_QUEUE.send(...)` |
| Durable Object | `env.MY_DO.get(id).fetch(...)` — stateful storage |
| AI | `env.AI.run('model', ...)` |
| Vectorize | `env.VECTORIZE.query(...)` |
| Email | `env.EMAIL.send(...)` |
| Hyperdrive | DB pooling for postgres / mysql |
| Browser Rendering | `env.BROWSER.launch(...)` — headless Chromium |

Every binding is identity-less — Workers don't have a `userIdentity`; capability flows entirely from the binding configuration in `wrangler.toml`.

### `env` exposure
- `env` object contains every binding + every secret (set via `wrangler secret put`)
- Bug: error handler returns `JSON.stringify(env)` → all bindings + secrets leaked
- Bug: `console.log(env)` in error path → leaked to logs

### Pages Functions
- `functions/api/hello.ts` auto-mounts as `/api/hello`
- Same surface as Workers; identical bug classes
- Pages-specific: `_middleware.ts` for path-prefix middleware; misconfig → middleware skipped on certain methods

### Service Bindings + auth bypass
- `env.AUTH_SERVICE.fetch(request)` calls another Worker in the same account
- No public network hop → no edge WAF, no Cloudflare bot protection, no rate-limit
- Bug: developer relies on external WAF for auth; Service-Binding calls bypass entirely

### Durable Objects + isolated execution
- DOs provide single-instance state per object ID
- Bug: DO's `fetch()` handler trusts caller; relying on Worker's auth check
- Compromise of the Worker → arbitrary DO access

### KV / R2 default visibility
- KV value reads are READ COMMITTED with eventual consistency (60s)
- Bug: cache-poisoning via TTL-bound writes when the writer's auth is compromised
- R2 public-access flag at the bucket level: `public-r2-bucket.your-account.r2.cloudflarestorage.com`

## Detection Channels

### Fingerprint Cloudflare Workers
```bash
curl -sI 'https://<TARGET>/' | grep -iE 'cf-ray|cf-cache-status|server: cloudflare'

# Pages-specific
curl -sI 'https://<TARGET>/' | grep -iE 'cf-edge-cache|cf-mitigated'
```

### Pages Functions discovery
```bash
# functions/ directory auto-mounts; common patterns
for path in /api/hello /api/auth /api/user /api/admin /api/_health; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://<TARGET>${path}")
  echo "${path}: ${STATUS}"
done
```

### Error-page env-leak probe
```bash
# Trigger uncaught exception
curl -X POST 'https://<TARGET>/api/known-endpoint' \
  -H 'Content-Type: application/json' \
  -d '{malformed json'

# Look for response containing env-shaped data
# Pages/Workers default error page is opaque; custom error handlers leak more
```

### KV / R2 enumeration (when source is available)
```bash
# Wrangler.toml or _config.ts reveals binding names
grep -rE 'binding\s*=|\[\[kv_namespaces\]\]|\[\[r2_buckets\]\]' .

# Each binding name corresponds to env.<NAME>
```

## Operational Runbook

### Step 1 — fingerprint
```bash
curl -sI 'https://<TARGET>/' | grep -iE 'cf-|server'

# X-Frame-Options / X-Robots-Tag set by Workers when configured
curl -sI 'https://<TARGET>/' | grep -iE 'cf-worker'
```

### Step 2 — Pages Functions sweep
```bash
# Walk common API paths + functions/_middleware
for path in /api/auth/login /api/auth/register /api/user/me /api/admin /api/_internal; do
  curl -i "https://<TARGET>${path}"
done
```

### Step 3 — env / secret exfil via error path
```bash
# Many Workers have a fallback "return new Response(JSON.stringify({error: e.message}))"
# If e is the Error object, sometimes the message includes stack with env values

curl -i 'https://<TARGET>/api/protected' -H 'Authorization: malformed' | head -30
```

### Step 4 — Service Binding bypass
```bash
# Identify the "public" Worker entry point + the "internal" service
# Internal services often:
# - Don't apply rate-limit
# - Skip auth (assumes calling Worker has authed)

# Test: invoke the public Worker with payloads that traditionally trigger WAF/rate-limit
# If the public Worker forwards via Service Binding without those checks → bypass
```

### Step 5 — KV / R2 enum (post-compromise)
```bash
# When you have code execution in the Worker (e.g., via SSTI / RCE in handler):
# env.MY_KV.list() returns all keys in the namespace
# env.MY_R2.list() returns all R2 object keys

# Without code execution but with predictable key patterns:
# KV doesn't expose enumeration publicly; R2 may if bucket is public
```

### Step 6 — Pages Function `_middleware.ts` audit
```bash
# Pages middleware: functions/_middleware.ts applies to all functions
# functions/api/_middleware.ts applies to /api/*

grep -rn 'onRequest' functions/ | head
```

Bug pattern: middleware checks `context.request.method == 'POST'` and skips GET → GET-mediated state-change

## Specific Vulnerability Classes

### Wrangler dev → wrangler.toml exposure
- `wrangler dev` exposes the dev preview on a `*.workers.dev` subdomain
- Bug: production code deployed to `*.workers.dev` (no custom domain) — sometimes accidentally with prod secrets

### KV TTL race
- KV writes are NOT atomic; multiple writes within ~60s can race
- Bug: rate-limit counter stored in KV; concurrent writes lose increments → rate-limit bypass

### Durable Object instance hijack
- DO IDs are unguessable when generated via `idFromName()` with strong inputs
- Bug: DO IDs derived from user-controlled email / username → DO instance hijack by claiming the same name

### R2 + S3 SDK compatibility quirks
- R2 supports S3 API; S3 clients connect to `<bucket>.<account>.r2.cloudflarestorage.com`
- Bug: bucket made public via `wrangler r2 bucket public-access` enables anonymous access; same as public S3

### Email Workers + spoofing
- Email Workers can send outbound; spoof source via `from` field
- Bug: sender authentication not enforced; combined with weak SPF/DMARC on the sending domain = phishing platform

## Bypass Techniques

- **WAF bypass via Service Binding**: public Worker proxies through internal Worker; internal Worker calls don't traverse edge WAF
- **Bot management bypass via Worker → internal Worker**: same as above
- **KV cache exfil**: KV reads are global; once an attacker writes a known key, they can read it from any geographic edge
- **Durable Object script-name confusion**: DO classes accessed by name; renaming the class on deploy but keeping old DO IDs → state confusion

## Validation

1. Pages function 200 without auth.
2. Error path leaks env contents.
3. Service Binding bypass: payload that triggers WAF on public path succeeds via internal binding.
4. KV TTL race: rate-limit counter race-condition exploitable.
5. R2 bucket public-read: anonymous GET returns objects.

## False Positives

- 200 responses on `*.workers.dev` from intentionally-public test deployments.
- Pages middleware that allows-list method-based skip for legitimate reasons (CORS preflight).
- `cf-ray` header on a non-Cloudflare backend that happens to be fronted by Cloudflare CDN — confirm the actual origin server.

## Impact

- Direct binding-secret exfil → KV / D1 / R2 / Service access.
- WAF / rate-limit / bot-management bypass via Service Bindings.
- Mass data exfil from KV namespaces / R2 buckets / D1 databases.
- Email-spoofing platform when Email Worker is misconfigured.

## Remediation

1. **Never `JSON.stringify(env)`** — env contains every secret + binding.
2. **`wrangler secret put`** for secrets; never `vars` in `wrangler.toml` (committed to git).
3. **Service Bindings still enforce auth**: internal Worker re-validates incoming request even though it came from another Worker.
4. **Pages middleware on `_middleware.ts`** for blanket auth; never skip by method.
5. **R2 buckets default-private**; `wrangler r2 bucket public-access` only when explicitly needed.
6. **Durable Object IDs from cryptographically-strong sources** (`idFromName(crypto.randomUUID())`), never from user-controlled strings.
7. **KV writes for rate-limit are not safe** — use Durable Objects (atomic) instead.

## Pro Tips

1. The single most-common Worker finding: error handler that returns `env` contents to the client.
2. `wrangler.toml` lists every binding by name — read it to enumerate the binding surface before testing.
3. Service Bindings are invisible in HTTP captures (no network hop) — audit `wrangler.toml`, not traffic.
4. `*.workers.dev` subdomains are PUBLIC by default — even production Workers without custom domains.
5. Cloudflare Pages Functions ship rapidly; `functions/` directory often grows without security review per addition.

## Summary

Cloudflare Workers + Pages security is binding-centric. Audit `wrangler.toml`, `env` exposure paths, Service Binding boundaries, Pages middleware coverage. The serverless V8 isolate runtime is fast; the bugs are in the operator's wiring.
