---
name: aws-secrets-manager
description: AWS Secrets Manager + Parameter Store — over-broad resource policies, KMS-key chains, env-leak pivots
triggers: [secrets manager, parameter store, ssm, secret rotation, kms decrypt, secret policy]
---

# AWS Secrets Manager + SSM Parameter Store

Secrets in modern AWS sit in three places: **Secrets Manager** (rotation + cross-account share), **SSM Parameter Store** (cheap, simpler), and **Lambda/ECS env vars** (worst, but pervasive). Compromise of any path of `kms:Decrypt → secretsmanager:GetSecretValue → resource access` collapses to "attacker reads every secret in the account."

Strix's `cloud_attack_paths/patterns.py` includes `_pattern_overpermissive_secrets_manager_resource_policy` and `_pattern_public_secrets_store`. Companion to `aws_iam_chains.md` for the IAM side.

## Attack Surface

### Secrets Manager
- Per-secret resource policy attached via `aws secretsmanager put-resource-policy`
- Cross-account share via `Principal: "arn:aws:iam::OTHER:root"` in the policy
- KMS-encrypted with either AWS-managed key (`aws/secretsmanager`) or CMK
- Rotation Lambda has its own IAM role — often over-privileged
- Replication to other regions can leak across-region-policy gaps

### SSM Parameter Store
- Three tiers: Standard (free, 4 KB), Advanced (paid, 8 KB + policies), Intelligent-Tiering
- `String`, `StringList`, `SecureString` (KMS-encrypted)
- Path-prefix-based access: `/app/prod/db-pass` vs `/app/dev/db-pass`
- Bug: IAM allows on `ssm:GetParameter` with `Resource: arn:aws:ssm:*:*:parameter/*` (any param)

### Env vars (the leak point)
- Lambda env vars are plaintext-by-default; KMS-encrypted opt-in
- ECS task definitions can pull from Secrets Manager / SSM at runtime — but task-definition history retains old plaintext values
- CodeBuild env vars exposed in build logs unless `noEcho: true`

### KMS key chains
- A secret is only as private as its KMS key
- `kms:Decrypt` on the key + `secretsmanager:GetSecretValue` on the secret = read
- Cross-account `kms:Decrypt` via key policy + `Resource: "*"` = anyone in the trusted accounts reads

## Detection Channels

### Enumerate

```bash
# Secrets Manager
aws secretsmanager list-secrets --query 'SecretList[].[Name,ARN,KmsKeyId,LastRotatedDate]'

# Per-secret resource policy
aws secretsmanager get-resource-policy --secret-id <SECRET_ARN>

# SSM Parameter Store — list all
aws ssm describe-parameters --query 'Parameters[].[Name,Type,KeyId,LastModifiedDate]'

# Per-parameter (SecureString) — needs Decrypt permission
aws ssm get-parameter --name '/app/prod/api-key' --with-decryption
```

### Lambda env-var sweep

```bash
# Across all functions, dump env vars (requires lambda:GetFunctionConfiguration)
for fn in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do
  echo "=== $fn ==="
  aws lambda get-function-configuration --function-name "$fn" \
    --query 'Environment.Variables' --output json
done | jq -r '.[] | select(. != null) | to_entries[] | "\(.key)=\(.value)"' | \
  grep -iE 'KEY|SECRET|TOKEN|PASSWORD|DB_'
```

### ECS task-definition history

```bash
# Old revisions retain leaked plaintext secrets
aws ecs list-task-definitions --query 'taskDefinitionArns' --output text | tr '\t' '\n' | \
  while read td; do
    aws ecs describe-task-definition --task-definition "$td" \
      --query 'taskDefinition.containerDefinitions[].environment'
  done
```

## Operational Runbook

### Step 1 — enumerate accessible secrets

```bash
# What can the current principal read?
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text

# Per-secret resource policy — look for cross-account / wildcard
for s in $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text); do
  echo "=== $s ==="
  aws secretsmanager get-resource-policy --secret-id "$s" 2>&1 | jq -r '.ResourcePolicy' 2>/dev/null
done
```

### Step 2 — pull secrets

```bash
# Plain read
aws secretsmanager get-secret-value --secret-id <SECRET_ARN>

# JSON-shaped secret with multiple keys
aws secretsmanager get-secret-value --secret-id <SECRET_ARN> \
  --query 'SecretString' --output text | jq

# Versioned secret history
aws secretsmanager list-secret-version-ids --secret-id <SECRET_ARN>
aws secretsmanager get-secret-value --secret-id <SECRET_ARN> --version-id <V>
```

### Step 3 — SSM parameter dump

```bash
# All decryptable SecureString params
aws ssm describe-parameters --query 'Parameters[?Type==`SecureString`].Name' --output text | \
  tr '\t' '\n' | while read p; do
    echo "=== $p ==="
    aws ssm get-parameter --name "$p" --with-decryption \
      --query 'Parameter.Value' --output text 2>&1 | head -3
  done
```

### Step 4 — KMS key audit

```bash
# Per-CMK: who can decrypt?
for key in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  echo "=== $key ==="
  aws kms get-key-policy --key-id "$key" --policy-name default
done

# Cross-account decrypt via key policy
# Look for: "Principal": {"AWS": "arn:aws:iam::OTHER:root"}
# Without aws:SourceArn / aws:SourceAccount conditions
```

### Step 5 — chain to broader compromise

```bash
# A common chain:
# 1. Read secret containing DB master password
# 2. Connect to RDS (master cred bypasses IAM-auth)
# 3. Dump tables

# Another chain:
# 1. Read secret containing AWS access keys (yes — some orgs store sub-account keys here)
# 2. aws configure --profile pivoted
# 3. Pivot to the sub-account

# Yet another:
# 1. Read GitHub PAT from secret
# 2. Clone private repos
# 3. Pivot to source code
```

## Specific Vulnerability Classes

### Resource policy with `"Principal": "*"`
- Cross-account share gone wrong: meant to share with `OTHER:root` but `*` got typed
- Anyone with the secret ARN can read

### Rotation Lambda over-privileged
- Lambda role grants `secretsmanager:GetSecretValue` on `*` and `kms:Decrypt` on `*`
- Compromise of the rotation Lambda → compromise of every secret in the account

### Replicated secrets — region drift
- Secret replicated to another region for DR
- Replica region has *its own* policy → drift from primary; primary tight, replica loose

### Env-var shadow copies
- Function code reads secret into env at init, then references env
- Compromise of the function → env dump → leak

### Cross-account `kms:Decrypt` confused-deputy
- Key policy allows another account's `Principal: "arn:aws:iam::OTHER:root"` to decrypt
- Without `aws:SourceArn` condition, ANY service in OTHER (Lambda, EC2 anywhere) can decrypt
- Bug: meant for a specific Lambda; allowed everywhere in OTHER

## Validation

1. Confirm read access with `aws secretsmanager get-secret-value` returning the plaintext.
2. Demonstrate the secret's downstream use (DB connect, API call, etc.) — context proves impact.
3. For resource-policy / KMS-policy bugs, demonstrate access from an unrelated principal.
4. Document: secret ARN, principal that shouldn't have read, the chain to broader compromise.

## False Positives

- Secret intentionally cross-account-shared with a vendor / trusted partner — verify with operator.
- KMS key policy `Principal: "AWS": "*"` with restrictive `Condition` blocks (matching only specific accounts via `aws:PrincipalAccount`) — confirm by attempting access from an unauthorised account.
- Rotation Lambda over-broad permissions are sometimes intentional for rotating all secrets — flag with medium severity.
- Dev / test secrets in dev accounts — confirm scope.

## Impact

- Direct credential theft → broad cloud pivot.
- DB master password → full data access.
- Third-party API keys (Stripe, Twilio, SendGrid) → upstream service compromise.
- Source-repo PATs / SSH keys → supply-chain access.

## Remediation

1. **Tight resource policies** on every secret: explicit principal allow-list, no `*`.
2. **No env-var secrets**: load from Secrets Manager / Parameter Store at runtime; never bake into task definitions or function configs.
3. **Per-secret KMS CMKs**: separate key per service, scoped policies.
4. **`aws:SourceArn` / `aws:SourceAccount` conditions** on cross-account decrypt grants.
5. **Rotation Lambda least-privilege**: scope to the specific secret it rotates, not `*`.
6. **CloudTrail rule for `secretsmanager:GetSecretValue`** with unusual principals → alert.
7. **AWS Config rule for unencrypted Lambda env vars** + `secrets-store-not-public`.

## Pro Tips

1. `aws secretsmanager list-secrets --include-planned-deletion` — secrets queued for deletion still readable during the 30-day window. Often forgotten.
2. SSM parameter names are often guessable: `/app/prod/db-pass`, `/api/stripe/secret`. Try common patterns even when listing is blocked.
3. ECS task-definition revisions are immutable history — old versions with leaked plaintext stay forever. Audit + redact.
4. CodeBuild env vars marked `noEcho: false` (the default) get logged to S3 / CloudWatch on every build.
5. KMS key aliases are public; principal-listing isn't. Look for predictable aliases (`alias/prod-db`) as a pivot signal.

## Summary

Secrets Manager is only as private as its IAM + KMS chain. Audit per-secret resource policies, KMS key policies, and rotation Lambda permissions. The pivots are short: secret → DB → data, or secret → upstream API → tenant data.
