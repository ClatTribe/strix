---
name: aws-s3-attack-surface
description: S3 misconfigurations — public buckets, signed-URL abuse, cross-account share, object-lock evasion
triggers: [s3, bucket, public bucket, signed url, presigned, object acl, cross account, bucket policy]
---

# AWS S3 Attack Surface

S3 is the most prolific data-leak surface in AWS. The bugs cluster in three regions: **bucket-level access controls** (public buckets, BPA disabled), **object-level access controls** (per-object ACLs, presigned URLs, multipart uploads), and **bucket policies** (cross-account share with weak conditions). Strix's `cloud_attack_paths/patterns.py` covers the canonical patterns; the active `live_probes.py` verifies exploitability by attempting anonymous reads.

## Attack Surface

### Public bucket signals
- `BlockPublicAcls=false` + any object with `public-read` ACL
- `IgnorePublicAcls=false` + bucket ACL with `AllUsers` grant
- `BlockPublicPolicy=false` + bucket policy with `"Principal": "*"`
- `RestrictPublicBuckets=false` + any of the above

The full **Block Public Access (BPA)** configuration is the gate. AWS turns it on by default for new buckets since 2023, but legacy buckets, IaC-created buckets, and cross-account-created buckets often have it off.

### Static-website hosting
- Bucket with `WebsiteConfiguration` + S3 endpoint URL = public-by-design
- Often forgotten when the site decommissions (dangling-content + CloudFront origin = stale-content takeover)

### Presigned URLs
- Short-lived but **transferable**: any party with the URL has read/write within TTL
- Default TTL is **7 days max** (configurable via signature version + bucket policy)
- Signed by the *creator's* credentials → revoking the user doesn't invalidate active URLs

### Cross-account share
- Bucket policy `Principal: arn:aws:iam::OTHER_ACCT:root` shares with the entire other account
- Without `aws:SourceArn` / `aws:SourceAccount` conditions = confused-deputy

### Server-side encryption
- Bucket configured for SSE-S3 → AWS-managed keys; encrypted at rest but no key boundary
- SSE-KMS with bucket-key disabled → per-object KMS API call (cost + revocation channel)
- SSE-C (customer-managed) → key in every request → if leaked, all objects readable

### Multipart upload abandonment
- Incomplete multipart uploads aren't deleted by default → cost + sometimes leak partial content

## Detection Channels

### Bucket discovery

```bash
# All buckets the account owns
aws s3api list-buckets

# Per-bucket: public-access-block
aws s3api get-public-access-block --bucket <BUCKET>

# Per-bucket: ACL
aws s3api get-bucket-acl --bucket <BUCKET>

# Per-bucket: policy
aws s3api get-bucket-policy --bucket <BUCKET>

# Bucket policy status — AWS's "is it public" auto-classifier
aws s3api get-bucket-policy-status --bucket <BUCKET>
```

### Cross-account discovery

```bash
# When you have access to the consumer account, see what's shared in
aws s3 ls s3://<bucket-in-other-account>/ --profile other_account

# Often the consumer doesn't know which buckets it has read on — enumerate via SCPs / org-level access advisor
```

### Anonymous probe

```bash
# Anonymous LIST + GET
curl -s "https://<BUCKET>.s3.amazonaws.com/"
curl -s "https://<BUCKET>.s3.amazonaws.com/?list-type=2"

# If returns XML with `<ListBucketResult>` → publicly listable
# If 403 but specific object key works → object-level public via ACL
curl -s "https://<BUCKET>.s3.amazonaws.com/sensitive-file.json"
```

### Presigned URL replay

```bash
# Test whether captured presigned URLs are still valid
PRESIGNED='https://bucket.s3.amazonaws.com/file?X-Amz-Algorithm=...&X-Amz-Expires=...&X-Amz-Signature=...'
curl -s -o /dev/null -w '%{http_code}\n' "$PRESIGNED"
```

## Operational Runbook

### Step 1 — full bucket audit

```bash
# Strix's discovery.py does this end-to-end; manual variant:
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  echo "=== $bucket ==="
  aws s3api get-public-access-block --bucket "$bucket" 2>&1 | head -10
  aws s3api get-bucket-policy-status --bucket "$bucket" 2>&1 | head -5
done
```

### Step 2 — anonymous probe (live verification)

```bash
# Use unauthenticated AWS calls to probe every bucket found
for bucket in $(...); do
  # LIST
  LIST_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://${bucket}.s3.amazonaws.com/?list-type=2")
  echo "${bucket} list: ${LIST_STATUS}"
  # If 200, fetch the first 10 keys
  if [[ "$LIST_STATUS" == "200" ]]; then
    curl -s "https://${bucket}.s3.amazonaws.com/?list-type=2&max-keys=10"
  fi
done
```

200 OK = public-listable. The XML payload reveals object keys, sizes, last-modified.

### Step 3 — sensitive-data sweep

```bash
# When listing works, look for high-value files
for key in $(curl -s "https://${bucket}.s3.amazonaws.com/?list-type=2" | xmllint --xpath '//*[local-name()="Key"]/text()' -); do
  # Filename heuristics
  case "$key" in
    *.env*|*credentials*|*config.json|backup*|*.sql|*.bak|*.dump)
      echo "HIGH-VALUE: ${bucket}/${key}"
      curl -s "https://${bucket}.s3.amazonaws.com/${key}" | head
      ;;
  esac
done
```

### Step 4 — bucket-policy abuse

```bash
# Pull bucket policy
aws s3api get-bucket-policy --bucket <BUCKET> --output text | jq .

# Common abuses (audit the JSON):
# - "Principal": "*" without IP / VPC condition
# - "Principal": "arn:aws:iam::OTHER:root" without aws:SourceArn condition
# - "Action": "s3:*" — too broad
# - "Resource": "arn:aws:s3:::bucket/*" with prefix wildcard you'd expect to be tighter
# - Missing "aws:SecureTransport" condition (HTTP allowed)
```

### Step 5 — write-side abuse (if writable)

```bash
# If anonymous put-object works:
echo "strix-test-content" | curl -s -X PUT -d @- "https://${bucket}.s3.amazonaws.com/strix-write-test.txt"

# Verify and clean up
curl -s "https://${bucket}.s3.amazonaws.com/strix-write-test.txt"
curl -s -X DELETE "https://${bucket}.s3.amazonaws.com/strix-write-test.txt"
```

Anonymous PUT = critical. Often paves the way to:
- Stored XSS (when the bucket fronts a website)
- Supply-chain poisoning (when the bucket holds JS bundles / Docker layers)
- Persistence via attacker-uploaded static assets

### Step 6 — cross-account confused deputy

```bash
# When you control the trusted-other account, test the shared bucket
aws s3 ls s3://<TARGET_BUCKET>/ --profile other_account

# Without aws:SourceArn / aws:SourceAccount, ANY principal in your account can access — including roles you don't operate.
```

## Specific Vulnerability Classes

### CloudFront-fronted bucket with origin access misconfig
- Old: `OriginAccessIdentity` (OAI) — bucket policy whitelists the OAI principal
- New: `OriginAccessControl` (OAC) — uses SigV4, supports SSE-KMS
- Bug: bucket has BOTH a CloudFront origin AND a permissive bucket policy → bypass CloudFront by hitting S3 directly

### S3 object-level ACL drift
- Bucket BPA blocks bucket-level public; but individual objects can carry ACLs from before BPA was enabled.
- `IgnorePublicAcls=true` saves you; otherwise: `aws s3api list-objects` + per-object `get-object-acl` enumeration.

### Pre-shared signed URL leak in client-side JS
- Some apps embed presigned PUT URLs in HTML for direct browser-to-S3 uploads
- The URL signs ONE specific key — but if `Key` is user-controlled in the request (rare misconfig), attacker writes arbitrary keys

### S3 transfer-acceleration endpoint
- `<bucket>.s3-accelerate.amazonaws.com` uses CloudFront-style edge
- Old buckets had different security posture on this endpoint vs the regional one — test both

## Bypass Techniques

- **`Authorization: AWS4-HMAC-SHA256` malformed**: some buckets accept GET with malformed auth headers as "anonymous"
- **Encoded path traversal**: `bucket/../../../different-bucket/key` — rare but seen against custom S3-compatible APIs
- **Bucket alias enumeration**: `bucket.s3.amazonaws.com` vs `s3-region.amazonaws.com/bucket/...` — different code paths in older buckets
- **CORS preflight info leak**: `OPTIONS` on a bucket with permissive CORS reveals AllowedOrigins / AllowedMethods

## Validation

1. Public-list: anonymous GET on `?list-type=2` returns XML with `<Key>` entries.
2. Public-read: anonymous GET on a specific object returns the content.
3. Public-write: anonymous PUT writes a strix-marker file; follow-up GET retrieves it.
4. Cross-account abuse: assume-role / boto3 with the other-account creds successfully reads the target.
5. Document: bucket name, region, BPA status, exact ACL / policy clause that enabled access, the file(s) leaked.

## False Positives

- Bucket is intentionally a CDN origin for public static assets (logos, CSS). Confirm with the operator before reporting.
- Bucket BPA = "all on" but policy is wide — BPA wins; not exploitable.
- Bucket in a different region returns 301 redirect to its region's endpoint — not a finding.
- Bucket is a "requester pays" bucket — public but caller pays for transfer; rare but valid configuration.

## Impact

- **Data exfil**: customer data, secrets, source code, backups, logs.
- **Stored XSS / persistence**: writable bucket → upload `index.html` with attacker JS; victim browsers run it.
- **Supply-chain**: bucket fronts a JS bundle URL → poison the bundle.
- **Bucket-snipe / takeover**: bucket name DNS-referenced in someone else's content; if the bucket is deleted, attacker creates it; content silently swapped.

## Remediation

1. **Block Public Access at the account level**: AWS Console → S3 → Account-level BPA settings. Overrides per-bucket misconfigs.
2. **Per-bucket BPA on**: 4 sub-settings, all true.
3. **Bucket policies with `aws:SecureTransport: true`**: deny HTTP entirely.
4. **`aws:SourceArn` / `aws:SourceAccount` conditions** on cross-account shares.
5. **CloudFront via OAC** (not OAI) — newer, supports SSE-KMS, signs SigV4.
6. **S3 inventory + access analyzer**: weekly `s3:GetBucketAcl` audit; Access Analyzer flags external-grantee policies.
7. **Object Ownership: BucketOwnerEnforced** — disables ACLs entirely. Strongest defence.

## Pro Tips

1. The single most-leaked S3 file: `.env`. Grep listings for `.env*` aggressively.
2. `s3-bucket-finder` and `bucket-flaws` are open-source enumerators; they hit the global S3 namespace for bucket-name guesses (org-pattern + permutation).
3. Cross-region buckets respond differently — `bucket.s3.amazonaws.com` redirects to `bucket.s3.us-east-1.amazonaws.com`; cache the redirect target.
4. Static-website-hosting buckets serve content via `<bucket>.s3-website-<region>.amazonaws.com` — slightly different endpoint, often missed in scans.
5. Most "public bucket" findings turn out to be intentional CDN origins. Always validate with the operator before scoring.

## Summary

S3 leaks are about identity boundaries. Public-by-default vs default-private; per-object vs per-bucket; account-level vs bucket-level. Strix's patterns catch the structures; live probes confirm exploitability anonymously without credentials.
