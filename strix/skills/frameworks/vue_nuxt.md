---
name: vue-nuxt
description: Vue 3 + Nuxt 3 — v-html XSS, SSR-side issues, useFetch context leak, runtime-config exposure, store hydration
triggers: [vue, nuxt, vue3, nuxt3, ssr, useFetch, useState, runtime config, hydration mismatch, vite, vuex pinia]
---

# Vue 3 + Nuxt 3 Security

Vue 3 + Nuxt 3 form the modern SPA + SSR stack. Bugs cluster around (1) **`v-html` directives** that disable Vue's auto-escape, (2) **SSR-context leakage** when `useFetch` / `useAsyncData` runs server-side and leaks server-only secrets to the hydrated client, (3) **runtime config exposure** when `runtimeConfig` (private) is accessed as `publicRuntimeConfig`, (4) **store hydration mismatches** that leak server state into client localStorage, and (5) **Nuxt server routes** with permissive defaults.

## Attack Surface

### v-html XSS
- `<div v-html="user_input">` → no escape → instant XSS
- Vue's documentation explicitly warns against this; still pervasive
- v-bind:href with user input → `javascript:` URI attacks unless validated

### SSR-context leakage
- `useFetch('/api/admin/secret', {server: true})` runs server-side
- Result hydrated into client → `window.__NUXT__` contains the full response
- Bug: server-fetched private data ends up in HTML payload, visible in page source

### `runtimeConfig` vs `publicRuntimeConfig`
- Nuxt 3 splits config: `runtimeConfig` (server-only) and `runtimeConfig.public` (client-visible)
- Bug: a secret put in `runtimeConfig` accessed via `useRuntimeConfig().<key>` returns undefined on client BUT the SECRET is still in nuxt's process memory; SSR-rendered pages may include it accidentally
- Bug: developer puts secret in `runtimeConfig.public` thinking it's "private" — it's not

### Store hydration (Pinia / Vuex)
- Server-side store initialised with sensitive data
- Hydration serialises store state into client → bug similar to useFetch leak
- Pinia: `useUserStore()` populated server-side with full user record (incl. password hash) → leaked to client

### Server routes (`server/api/*`)
- Nuxt's `server/api/<endpoint>.ts` autoloads as routes
- Bug: no built-in auth; developer must add per-route
- Common in tutorials: routes that read DB without auth

### Vite dev server
- `pnpm dev` / `npm run dev` exposes Vite's HMR WebSocket
- Bug: dev server exposed to internet (binding to 0.0.0.0 in CI) → source code disclosure via `/__vite_*` endpoints

## Detection Channels

### Vue / Nuxt fingerprint
```bash
# Nuxt 3 sets window.__NUXT__
curl -s 'https://<TARGET>/' | grep -oE 'window\.__NUXT__|nuxt-loading|<div id="__nuxt"'

# Vite asset paths
curl -s 'https://<TARGET>/' | grep -oE '/_nuxt/[^"]+\.js'
```

### __NUXT__ payload introspection
```bash
# Pull the hydration payload
curl -s 'https://<TARGET>/some-page' | \
  grep -oE 'window\.__NUXT__=[^<]+' | \
  sed 's/window\.__NUXT__=//' | head -c 5000 | \
  jq -R 'fromjson?'

# Look for: API tokens, user IDs, secrets that shouldn't be client-visible
```

### Server routes discovery
```bash
# Nuxt's server routes auto-mount under /api/*
curl -s 'https://<TARGET>/api/' -i

# Common patterns
for path in /api/auth/me /api/users /api/admin /api/internal /api/_secret; do
  curl -s -o /dev/null -w "${path}: %{http_code}\n" "https://<TARGET>${path}"
done
```

### Public runtime config sniff
```bash
# runtimeConfig.public is serialised into the client payload
curl -s 'https://<TARGET>/' | grep -oE '"public":\s*\{[^}]+\}'

# Check for: API keys, OAuth client IDs (sometimes secret), service URLs
```

## Operational Runbook

### Step 1 — fingerprint
```bash
curl -sI 'https://<TARGET>/' | grep -iE 'server'
curl -s 'https://<TARGET>/' | head -20

# Vite chunk paths reveal Vue/Nuxt 3
curl -s 'https://<TARGET>/' | grep -oE '/_nuxt/[a-zA-Z0-9-]+\.js' | head -5
```

### Step 2 — pull + parse __NUXT__ payload
```bash
HTML=$(curl -s 'https://<TARGET>/some-page')

# Extract __NUXT__ assignment (the JS-serialised state)
echo "$HTML" | grep -oE '<script>[^<]*window\.__NUXT__=[^<]*</script>' > /tmp/nuxt_payload.txt

# Look for sensitive-shaped data
grep -oE '"[A-Z_]+_KEY"|"[a-z_]*secret[a-z_]*"|"api[A-Z_]*"' /tmp/nuxt_payload.txt
```

### Step 3 — v-html XSS hunt
```bash
# Probe every reflected-input field
PAYLOAD='<svg onload=alert(1)>'
curl -G "https://<TARGET>/page" --data-urlencode "search=${PAYLOAD}" | \
  grep -oE 'v-html|innerHTML|\${[^}]+}'

# v-html in source → check whether the input is in that context
```

### Step 4 — server route audit
```bash
# Walk every /api/* path; check auth
ENDPOINTS=(
  /api/auth/me /api/auth/session /api/users /api/users/me
  /api/admin /api/internal /api/config /api/secret
  /api/health /api/_internal
)

for endpoint in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://<TARGET>${endpoint}")
  RESP=$(curl -s "https://<TARGET>${endpoint}" | head -c 500)
  echo "${endpoint}: ${STATUS}"
  [[ "$STATUS" == "200" ]] && echo "  body: ${RESP}"
done
```

### Step 5 — SSR-context exfil
```bash
# Force SSR by sending a clean User-Agent (no JS) — Nuxt SSR-renders
curl -s -A 'curl/Strix' 'https://<TARGET>/private-dashboard' > /tmp/ssr.html

# Look for server-only secrets in the SSR output
grep -E 'session|token|api_?key|secret' /tmp/ssr.html
```

### Step 6 — Nitro server (Nuxt 3's server engine) introspection
```bash
# Nitro routes
curl -s 'https://<TARGET>/_nitro' -i
curl -s 'https://<TARGET>/_routes' -i
curl -s 'https://<TARGET>/.nuxt/routes' -i  # rarely exposed but check
```

## Specific Vulnerability Classes

### `v-html` in markdown rendering
- `<div v-html="markdownToHtml(comment)">` — `markdownToHtml` returns rendered HTML
- If the markdown renderer doesn't sanitise: stored XSS via comment

### `useState` shared across users
- Nuxt 3's `useState('shared-key', ...)` shares across requests when SSR
- Bug: server-side `useState` persists across requests if not properly scoped — cross-user data leak

### `definePageMeta({ middleware: ['auth'] })` typo
- Misspelled middleware names silently skip the middleware
- Page renders without auth check

### Vite source map exposure
- Production builds with source maps included (`build.sourcemap: true`)
- `*.js.map` files accessible → full source code recovery
- Strix's `source_map_probe` (#49) catches this

### CSRF via state-changing GET routes
- Nuxt server routes accept GET / POST; developer uses GET for state-change "for simplicity"
- Cross-origin GET triggered via image / iframe → CSRF

## Bypass Techniques

- **CSP `script-src 'self'` + v-html with user input**: v-html bypasses CSP because the script is inserted via document.innerHTML, treated as inline
- **Encoded payloads in v-html**: HTML entity encoding bypasses some Vue sanitisers
- **`router-link` with user-controlled `to`**: `:to="user_input"` can be `javascript:`
- **`v-on` with user-controlled handler**: `:on-click="user_input"` → arbitrary JS evaluation

## Validation

1. v-html XSS: payload renders + executes (alert / dom-change confirmation).
2. __NUXT__ payload contains server-only data.
3. Server route 200 without auth.
4. SSR output contains plaintext secrets.
5. Source map .map file accessible at production URL.

## False Positives

- v-html with input from a TRUSTED source (CMS content the operator controls) — confirm threat model.
- __NUXT__ payload contains user's own session data (expected; only sensitive if it includes OTHER users' data).
- Public API endpoints are intentional — confirm with operator.

## Impact

- Stored XSS via v-html → session theft + persistent compromise.
- SSR-context leak → bulk user-data exfil from page source.
- Server route exposure → unauthorised CRUD on backend resources.
- Source map exposure → full TypeScript / JS source code recovery.

## Remediation

1. **Avoid `v-html`**: use plain `{{ }}` interpolation; sanitise with `DOMPurify` if HTML is unavoidable.
2. **`useFetch({server: false})`** for sensitive data — fetch client-side after auth.
3. **`runtimeConfig` (private) for secrets**; never `runtimeConfig.public`.
4. **Server routes**: `defineEventHandler` with explicit auth middleware on every route.
5. **`build.sourcemap: false`** in production builds; or restrict via web-server to specific IPs.
6. **CSP** with `script-src 'self' 'sha256-...'` per inline script — no `unsafe-inline`.
7. **Pinia stores**: explicit `$reset` server-side; avoid persistence of sensitive state.

## Pro Tips

1. `window.__NUXT__` is gold for recon — pull every page, parse the payload, hunt for user IDs / tokens.
2. Nuxt 3's server routes (`server/api/*.ts`) auto-mount with NO auth — read the operator's middleware setup carefully.
3. Vite source maps (`*.js.map`) are the single fastest path to full source code recovery for Vue / Nuxt apps.
4. The `useState` Nuxt composable has a "key" arg — same-key across users in SSR = cross-user leak.
5. v-html in production is more common than developers admit; `git grep "v-html"` reveals every usage.

## Summary

Vue / Nuxt bugs cluster at v-html, SSR-context, server routes, source maps. The framework's strength (auto-binding + SSR) becomes the surface. Audit v-html usage + server route auth + the __NUXT__ payload contents.
