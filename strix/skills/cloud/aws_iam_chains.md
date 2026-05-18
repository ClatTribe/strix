---
name: aws-iam-chains
description: AWS IAM privilege-escalation chains — assume-role, pass-role, confused-deputy, external trust, wildcard policies
triggers: [aws iam, sts assume role, pass role, confused deputy, role chain, wildcard policy, privilege escalation, identity]
---

# AWS IAM Chains

AWS IAM is the most subtle and most exploited surface in AWS. The bugs aren't in any single role — they're in **how roles chain**. The classic compromise sequence is "stolen credential → assume an over-privileged role → assume something more privileged → admin." Strix's `cloud_attack_paths/patterns.py` (PRs #293, #300, #307) catches the canonical chains; this skill explains the reasoning so the agent can verbalise, extend, and reproduce them.

Companion to: `cloud_attack_paths/patterns.py` (27 patterns, 12 AWS-specific) + `cloud_attack_paths/live_probes.py` + `cspm/prowler.py`.

## Attack Tree

```
1. Initial credential
   ├── Public S3 bucket leaks .aws/credentials
   ├── SSRF on EC2 → IMDSv1/v2 → instance role
   ├── ECS task with assumable role + exposed endpoint
   ├── Lambda function URL with role attached
   ├── GitHub Actions OIDC + over-broad trust policy
   ├── Compromised dev laptop with long-lived keys
   └── Public repo with hardcoded keys

2. Privilege expansion (the heart of IAM exploitation)
   ├── sts:AssumeRole on a more privileged role
   ├── iam:PassRole + lambda:CreateFunction (run arbitrary code as the passed role)
   ├── iam:UpdateAssumeRolePolicy (rewrite a role's trust policy)
   ├── iam:AttachRolePolicy + AdministratorAccess
   ├── iam:CreateAccessKey on another user
   └── iam:CreateLoginProfile on a service account

3. Cross-account lateral movement
   ├── sts:AssumeRole to a role in a peer account (external trust)
   ├── Compromised role with cross-account read on S3 / Secrets Manager
   └── Lambda function URL no-auth crossing account boundaries

4. Persistence / impact
   ├── iam:CreateAccessKey for a backdoor user
   ├── lambda:CreateFunction + EventBridge cron rule
   ├── CloudTrail logging disabled (`StopLogging` event)
   └── KMS key policy modified to allow attacker decrypt
```

## Detection Channels

### Static (audit IAM data)

Strix's `cloud_attack_paths/discovery.py` (PR #301) walks IAM via boto3. The CloudGraph then queries:

```python
# Pseudo-Python — the actual patterns live in patterns.py
def find_assume_role_to_admin(graph: CloudGraph) -> list[AttackPath]:
    """Walk can_assume edges; flag any path reaching a wildcard-admin role."""
    for src in graph.nodes(kind="CloudIdentity"):
        for dst in graph.bfs_along("can_assume", src, max_hops=4):
            if dst.attrs.get("has_wildcard_admin"):
                yield AttackPath(start=src, end=dst, ...)
```

The 12 AWS-specific patterns shipped in `patterns.py`:

| Pattern | What it catches |
|---|---|
| `_pattern_can_assume_chain_to_admin` | Multi-hop assume-role ending in AdministratorAccess |
| `_pattern_pass_role_present` | `iam:PassRole` allows + downstream Lambda/EC2 abuse |
| `_pattern_admin_policy_attached_to_iam_user` | IAM user (not role) with AdministratorAccess — should always be roles |
| `_pattern_wildcard_admin_attached` | Any principal with `"*":"*"` policy |
| `_pattern_world_assumable_role` | `Principal: "*"` in trust policy |
| `_pattern_external_trust_without_external_id` | Cross-account role without sts:ExternalId mitigation |
| `_pattern_internet_exposed_compute_with_iam` | EC2/ECS with public IP + attached role |
| `_pattern_admin_attached_to_compute_with_internet` | Above + admin policy = pre-pwned |
| `_pattern_cross_account_s3_share` | S3 shared cross-account without strict conditions |
| `_pattern_iam_user_active_keys_no_mfa` | Programmatic access without MFA enforcement |
| `_pattern_unused_iam_role_high_priv` | High-priv role unused in 90 days (perfect dormant takeover target) |
| `_pattern_secrets_via_environment` | Lambda env vars containing API keys / passwords |

### Active probes (`cloud_attack_paths/live_probes.py`)

```bash
# Verify each detected pattern by actually exercising it
strix cloud_attack_paths.live_probes --pattern can_assume_chain_to_admin --account 123456789012
```

The probe attempts `sts:AssumeRole` with the discovered chain and reports `verified` or `not_exploitable_in_practice` (e.g., MFA enforced, SCPs blocking).

## Operational Runbook

### Step 1 — full enumeration

```bash
# Strix's discovery.py walks IAM via boto3
strix --target aws://123456789012 \
      --target-type cloud_account \
      --scan-mode standard
```

Output: `cloud_attack_paths/graph.py` populated with `CloudIdentity` + `CloudPolicy` nodes + `can_assume` / `attached_to` / `has_policy` edges.

### Step 2 — query the graph

```bash
# Lead-facing tools (in orchestrator mode)
kg_query_nodes --type CloudIdentity --filters '{"has_wildcard_admin": true}'

kg_query_paths --start arn:aws:iam::123:user/dev_user \
               --end arn:aws:iam::123:role/AdminRole \
               --edge-types can_assume
```

### Step 3 — manual deep-dive on high-value identities

```bash
# Pull a role's full effective policy via boto3
aws iam list-attached-role-policies --role-name SuspectRole
aws iam list-role-policies --role-name SuspectRole
aws iam simulate-principal-policy --policy-source-arn <ROLE_ARN> \
  --action-names 'iam:PassRole' 'lambda:CreateFunction' 's3:GetObject' \
  --resource-arns '*'
```

`iam:PassRole` on `*` + `lambda:CreateFunction` = unauthorised role escalation in one step.

### Step 4 — verify exploitability

```bash
# When you have credentials for the upstream principal
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/SuspectRole \
                    --role-session-name strix-probe \
                    --duration-seconds 900
# Returns AccessKeyId + SecretAccessKey + SessionToken on success.
```

For sensitive engagements, use `--external-id` if the trust policy requires it; otherwise the missing ExternalId IS the finding.

### Step 5 — escalate

```bash
# Chain: PassRole + Lambda
aws lambda create-function \
  --function-name strix-pivot \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT:role/HigherPrivRole \
  --code S3Bucket=...,S3Key=... \
  --handler index.handler

aws lambda invoke --function-name strix-pivot output.json
# Lambda now runs with HigherPrivRole's credentials accessible via metadata service
```

## Canonical Privilege-Escalation Primitives

Memorise these — they're the ones Strix's patterns key on:

| Action | What it enables |
|---|---|
| `iam:CreateAccessKey` | Mint API keys for any user |
| `iam:CreateLoginProfile` | Add console password to any user |
| `iam:UpdateAccessKey` | Re-enable disabled keys |
| `iam:AttachUserPolicy` / `iam:PutUserPolicy` | Self-promote |
| `iam:AttachRolePolicy` | Attach AdministratorAccess to a controlled role |
| `iam:UpdateAssumeRolePolicy` | Rewrite a role's trust to include the attacker |
| `iam:PassRole` + `lambda:CreateFunction` | Run code as the passed role |
| `iam:PassRole` + `ec2:RunInstances` + UserData | Same, longer-lived |
| `iam:PassRole` + `ecs:RunTask` / `glue:CreateJob` / `sagemaker:CreateNotebookInstance` | Same idea, different runtime |
| `sts:AssumeRole` + permissive trust | Direct elevation |
| `kms:Decrypt` on a CMK that encrypts secrets | Read all secrets the CMK protects |
| `secretsmanager:GetSecretValue` | Read secrets directly |
| `ssm:GetParameter` (with `--with-decryption`) | Read parameter-store secrets |

## Cross-Account Specifics

```bash
# Look for trust policies that allow external accounts
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument]'

# Parse the trust JSON; flag any:
#  - "Principal": "*"  (world-assumable)
#  - "Principal": {"AWS": "arn:aws:iam::NOT_OWN_ACCOUNT:..."}  (cross-account)
#  - Cross-account WITHOUT "sts:ExternalId" condition
```

`sts:ExternalId` is the canonical defence against confused-deputy across AWS accounts. Missing it on a cross-account role = high-severity even if the trusted account looks legitimate.

## Bypass Techniques

- **`iam:UpdateAssumeRolePolicy` race**: when you have temp rights to rewrite a trust policy, write your principal in, assume, then rewrite back. Audit trail captures both rewrites.
- **Service-linked role abuse**: SLRs (e.g., `AWSServiceRoleForAutoScaling`) often have implicit trust + over-broad permissions; check if any are abusable.
- **`*` resource scoping**: `Resource: "*"` on policies that should be scoped to specific account / prefix.
- **Policy boundary leaks**: principals with `iam:PutRolePolicy` and no permissions boundary = unbounded escalation.

## Validation

1. Static finding: the `cloud_attack_paths` pattern reports a path with all required edges.
2. Active finding: `aws sts assume-role` succeeds against the suspect role using the upstream principal's creds.
3. Chain verification: when escalation requires multiple hops, demonstrate each hop with a separate `assume-role` + `aws sts get-caller-identity` step.
4. Document: source identity, target role, intermediate hops, ExternalId presence, MFA status, blocked-by-SCP yes/no.

## False Positives

- SCP at the org level blocks the action — chain is theoretical but not exploitable. Validate via `simulate-principal-policy` with the SCP context.
- MFA enforced on the assume-role trust → without MFA token, AssumeRole fails. Confirm by reading the trust's `Condition`.
- Role exists but is *unused* and key in question is *disabled* — old finding; check `LastUsedDate` on access keys + roles.
- Service-linked role with implicit trust that AWS-managed services use — flag with low severity unless you can demonstrate user-controllable invocation.

## Impact

- Account-wide admin compromise (the canonical "AdministratorAccess" reached via 2-4 hop chain).
- Cross-account lateral movement when trust policies are loose.
- Persistence via backdoor users, Lambda + EventBridge cron, CloudTrail disable.
- Data exfil from S3, RDS, Secrets Manager, KMS-encrypted stores.

## Remediation

1. **No long-lived IAM users**: use SSO + assume-role with short-lived credentials.
2. **Least privilege via permissions boundaries**: prevent any role from granting itself more permissions than its boundary allows.
3. **MFA on every console + programmatic-access role**: `aws:MultiFactorAuthPresent` condition in trust policies.
4. **ExternalId on every cross-account role**: defeats confused-deputy.
5. **No `iam:PassRole` on `*` resource**: scope to specific roles.
6. **No `iam:CreateAccessKey` on `*` user**: scope to self.
7. **SCPs as the org-wide safety net**: deny dangerous actions even when account-level policies grant them.
8. **Detect via CloudTrail**: `cloudtrail_detection.py` (PR #306) rules already cover `AssumeRole`-from-unknown-account, `iam:UpdateAssumeRolePolicy`, etc.

## Pro Tips

1. The single most useful IAM diagnostic: `aws iam get-account-authorization-details` — dumps every role + policy + trust. Strix's discovery.py uses this.
2. PMapper (open-source) builds an IAM graph + answers "who can become root?" — useful prior art for the patterns we've shipped.
3. PassRole + service-X is the most common chain; PassRole audits should always check every `iam:PassRole` allow against the downstream service catalog.
4. Service-linked roles + the SLR's auto-attached managed policy is an under-audited surface — managed policies sometimes have CVE-2022-X-style scope creep.
5. AWS adds new services constantly; the chain catalog needs refreshing — track AWS IAM Actions Reference quarterly.

## Summary

AWS IAM exploitation is graph traversal. The bugs are in the chains, not the leaves. Static analysis catches the structure; live probes confirm exploitability; the remediations are unsexy but effective.
