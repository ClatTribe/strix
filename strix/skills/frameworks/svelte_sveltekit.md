---
name: svelte-sveltekit
description: Svelte + SvelteKit — load() server context, +page.server.ts vs +page.ts, form actions CSRF, hooks.server permissions
triggers: [svelte, sveltekit, kit, +page.server, load function, form actions, hooks.server, vite]
---

# Svelte + SvelteKit Security

SvelteKit's data-flow distinction (`+page.server.ts` runs server-only; `+page.ts` runs in both) is the central security boundary. Bugs cluster around (1) **server data leaking to client** via `+page.server.ts` returning sensitive fields, (2) **form actions CSRF** when explicit origin checks are skipped, (3) **`hooks.server.ts` auth middleware** that doesn't cover every route, (4) **API route auto-mounting** without explicit auth, and (5) **adapter-specific surfaces** (Cloudflare Workers / Vercel / Node) with different security defaults.

## Attack Surface

### `+page.server.ts` data leakage
- `+page.server.ts` `load()` runs server-only; returns data passed to the page
- Return value serialises to JSON, embeds in the page's `<script>` tag for hydration
- Bug: returning a full user object including `password_hash` / `api_token` leaks to client
- Compare to Next.js's `getServerSideProps` — same pattern, same bug class

### Form actions
- `<form method="POST" action="?/createUser">` invokes the matching `actions.createUser` in `+page.server.ts`
- Built-in CSRF check requires `Origin` header match
- Bug: `kit.csrf.checkOrigin = false` in `svelte.config.js` disables it

### `+server.ts` API routes
- `+server.ts` files auto-mount as API endpoints
- Bug: no built-in auth; developer must add per-route
- `event.locals.user` is the conventional auth state; only populated when `hooks.server.ts` sets it

### `hooks.server.ts` auth middleware
- `handle()` runs on every request before route handlers
- Auth typically: read session cookie, look up user, set `event.locals.user`
- Bug: route handler doesn't check `event.locals.user` → effectively unauthenticated

### Adapter-specific
- `@sveltejs/adapter-node` — Node server; full process access
- `@sveltejs/adapter-cloudflare` — Workers; different runtime constraints (see cloudflare_workers.md)
- `@sveltejs/adapter-vercel` — Vercel edge / serverless
- Bug: adapter-specific env-var handling differs; secrets sometimes leak via adapter-specific debug endpoints

### Vite source maps
- Same as Vue/Nuxt: production builds with `build.sourcemap: true` expose `.map` files

## Detection Channels

### Fingerprint SvelteKit
```bash
curl -s 'https://<TARGET>/' | grep -oE 'kit-route|<div id="svelte"|/_app/|sveltekit'

# Common asset path
curl -s 'https://<TARGET>/' | grep -oE '/_app/immutable/[a-z0-9/]+\.js'
```

### Hydration payload introspection
```bash
# SvelteKit embeds JSON state in the page
curl -s 'https://<TARGET>/some-page' | grep -oE '<script[^>]+type="application/json"[^>]*>[^<]+</script>'

# Server data lands here; look for sensitive fields
```

### `+server.ts` API discovery
```bash
# Walk common API paths
for path in /api/user /api/auth/session /api/admin /api/users; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://<TARGET>${path}")
  echo "${path}: ${STATUS}"
done
```

### Form action probe
```bash
# Check whether CSRF origin-check is on
curl -X POST "https://<TARGET>/some-page?/action" \
  -H 'Origin: https://attacker.com' \
  -d 'field=value'

# 403 with "Cross-site POST form submissions are forbidden" → CSRF protection on
# 200 / 4xx other → CSRF not checked at the SvelteKit layer
```

## Operational Runbook

### Step 1 — fingerprint + hydration introspection
```bash
HTML=$(curl -s 'https://<TARGET>/private-page')

# Find the page's serialised state
echo "$HTML" | grep -oE '<script[^>]+type="application/json"[^>]+>[^<]+</script>' > /tmp/state.html

# Parse the JSON
sed 's/<[^>]*>//g' /tmp/state.html | head -c 5000 | jq -R 'fromjson?'
```

Look for:
- Server-side-only fields that shouldn't be in the client (password_hash, api_token, internal_id)
- Other users' data leaking into the current user's payload
- Environment-variable values

### Step 2 — load() data audit
```bash
# When source is available
grep -rn 'export.*load' --include='+page.server.ts' --include='+page.server.js' .

# Look for return shapes that include sensitive fields
# return { user: dbUser }  ← if dbUser has password_hash, it leaks
```

### Step 3 — form action CSRF
```bash
# Build a CSRF PoC HTML page
cat <<'EOF' > /tmp/csrf.html
<form action="https://<TARGET>/page?/dangerous" method="POST">
  <input name="data" value="attacker_value">
</form>
<script>document.forms[0].submit();</script>
EOF

# Serve via local HTTP, navigate browser to it with target session active
python3 -m http.server 8080 --directory /tmp &
# Visit http://localhost:8080/csrf.html
```

If submission succeeds without origin-mismatch error → CSRF protection off.

### Step 4 — `+server.ts` auth audit
```bash
# Walk API endpoints; check auth state
for endpoint in /api/me /api/users /api/admin /api/users/1; do
  RESP=$(curl -s -i "https://<TARGET>${endpoint}")
  STATUS=$(echo "$RESP" | head -1)
  BODY=$(echo "$RESP" | tail -1 | head -c 300)
  echo "${endpoint}: ${STATUS} | ${BODY}"
done
```

### Step 5 — `hooks.server.ts` route coverage
```bash
# When source is available
grep -rn 'export const handle' --include='hooks.server.*' .

# Look for: bypass paths, route exclusions, conditional auth
# Common bug: if (event.url.pathname.startsWith('/api')) { skip auth }
```

### Step 6 — adapter-specific surfaces
```bash
# Cloudflare adapter
curl -sI 'https://<TARGET>/' | grep -i 'cf-ray\|cf-cache-status\|server.*cloudflare'

# Vercel adapter
curl -sI 'https://<TARGET>/' | grep -i 'x-vercel-id\|server.*vercel'

# Node adapter (custom Node server)
# Often X-Powered-By: SvelteKit
```

## Specific Vulnerability Classes

### `cookies.set` without secure flags
- `event.cookies.set('session', token, { path: '/' })` — missing `secure: true` + `httpOnly: true` + `sameSite: 'lax'`
- Default in older SvelteKit: HTTP-only cookies but not secure

### Streamed response context
- SvelteKit supports streamed responses (`return new Response(stream)`)
- Bug: stream doesn't run through hooks.server.ts auth → unauth read

### `$env/static/private` vs `$env/dynamic/private`
- Static: baked at build; can't leak to client because tree-shaken
- Dynamic: read at runtime; can be templated into responses
- Bug: dynamic private env-var concatenated into client-visible response

### CSRF + form action across origin
- SvelteKit's built-in check is on Origin header
- Bug: `event.request.headers.get('origin')` reflected as ACAO with `*` → CSRF + permissive CORS

### Adapter-cloudflare KV / D1 leakage
- KV namespace / D1 database bindings accessible via `platform.env`
- Bug: error handler exposes platform.env keys + binding names

## Bypass Techniques

- **Form actions accept GET** if `<form method="GET">` — CSRF via image src for state-change
- **Origin header spoofable via XHR**: `fetch('/page?/action', { method: 'POST', headers: { 'Origin': 'https://target.com' }})` — fails in browser, succeeds in raw HTTP
- **Hydration payload tampering**: client can modify the JSON state before Svelte hydrates — exploit relies on the app trusting client-side store state
- **Source-map walk for source-only routes**: dev-only routes excluded from `+page` files may still appear in source maps

## Validation

1. `+page.server.ts` returns leak: sensitive fields in hydration payload.
2. CSRF: cross-origin POST succeeds against a state-change action.
3. `+server.ts` API: 200 without auth on a protected route.
4. Cookie flags: missing `secure` / `httpOnly` / `sameSite`.
5. Document: route, sensitive fields, exact `load()` source location.

## False Positives

- `+page.server.ts` returns intentionally-public data — confirm scope.
- CSRF check disabled in dev (`mode === 'dev'` conditional) — confirm prod build.
- API routes that are intentionally public (status, health, public-content).

## Impact

- Server-side data leak → user PII / credentials in client-visible page source.
- CSRF state-change → unauthorized actions via cross-origin form posts.
- API route auth gap → bulk data access without authentication.

## Remediation

1. **`load()` returns explicit field allow-lists**: never return full DB records.
2. **CSRF origin check enabled** (default): `kit.csrf.checkOrigin: true` in `svelte.config.js`.
3. **`hooks.server.ts` blanket auth**: all routes auth-required by default; explicit allow-list for public routes.
4. **`+server.ts` checks `event.locals.user`** before any data access.
5. **Cookies**: `secure: true, httpOnly: true, sameSite: 'lax'` for sessions.
6. **`$env/static/private`** for secrets, never `dynamic/private` concatenated into responses.
7. **Vite source maps off** in production OR served only via internal IPs.

## Pro Tips

1. The most-common SvelteKit finding: `+page.server.ts` returning DB records with sensitive fields. Always check the hydration payload.
2. `hooks.server.ts` is the chokepoint — audit its handle() function carefully.
3. `+server.ts` files in routes/ auto-mount — don't forget to grep `find . -name '+server.*'`.
4. Adapter-cloudflare has different security characteristics than adapter-node — audit per adapter.
5. SvelteKit's CSRF default is on; defenders sometimes turn it off for dev tooling and forget to re-enable.

## Summary

SvelteKit security is the `+page.server.ts` / `+page.ts` boundary. Audit load() returns, form-action origin checks, +server.ts auth, hooks.server.ts coverage. The hydration payload is the canonical leak surface.
