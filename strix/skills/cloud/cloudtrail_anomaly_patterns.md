---
name: cloudtrail-anomaly-patterns
description: CloudTrail-based CDR — rule reasoning, baseline anomalies, attacker behaviour patterns, hunting
triggers: [cloudtrail, cdr, cloud detection, lookup events, console login, assume role, anomaly, threat hunting]
---

# CloudTrail Anomaly Patterns (CDR)

CloudTrail records every AWS API call. The interesting bits aren't individual events — they're **patterns**: which principal does what, from where, at what time, in what sequence. Strix's `cloud_attack_paths/cloudtrail_detection.py` (PR #306) ships deterministic rules covering the canonical compromise patterns. This skill explains the *reasoning* so the agent can extend rules, tune false positives, and reconstruct attack timelines.

Companion to `aws_iam_chains.md` (the privilege-escalation primitives) and `aws_s3_attack_surface.md` (data-exfil endpoints).

## Threat Model

Attacker journey through CloudTrail:

```
1. Initial access
   ├── ConsoleLogin (with / without MFA)
   ├── AssumeRole from outside the trusted geo
   ├── GetCallerIdentity (the "where am I?" probe)
   └── ListAccountAliases (the "what's this org?" probe)

2. Discovery
   ├── ListBuckets, ListUsers, ListRoles, ListPolicies
   ├── Get* on Secrets Manager / SSM / KMS keys
   ├── Describe* on EC2 / RDS / Lambda
   └── GetAccountAuthorizationDetails (IAM-graph dump)

3. Privilege escalation
   ├── UpdateAssumeRolePolicy (trust-policy rewrite)
   ├── AttachUserPolicy / AttachRolePolicy (self-promotion)
   ├── PutUserPolicy / PutRolePolicy (inline self-promotion)
   ├── CreateAccessKey on another user
   ├── CreateLoginProfile on a service account
   └── PassRole + CreateFunction / RunInstances

4. Persistence
   ├── CreateUser (backdoor account)
   ├── CreateAccessKey for own user
   ├── CreateRole with permissive trust + AttachPolicy
   ├── CreateFunction + PutEventBridgeRule (cron backdoor)
   └── UpdateLoginProfile (password reset)

5. Exfil
   ├── Bulk s3:GetObject from a single principal in short window
   ├── CreateDBSnapshot + ModifyDBSnapshotAttribute (share to attacker account)
   ├── CopyImage / CreateImage (AMI share)
   ├── ExportTable (DynamoDB export)
   └── PutBucketPolicy (open bucket up for exfil)

6. Defense evasion
   ├── StopLogging (CloudTrail itself)
   ├── DeleteTrail
   ├── PutBucketPolicy on CloudTrail's S3 bucket (block writes)
   ├── PutMetricFilter on CloudWatch (suppress alerts)
   ├── DisableSecurityHub / DisableGuardDuty
   └── CreateTrail with logging to attacker-controlled bucket
```

## Detection Rule Reasoning

Strix's `cloudtrail_detection.py` ships these rules. Each maps to a canonical attacker move.

| Rule | What it catches | Why high-fidelity |
|---|---|---|
| `root_account_used` | `userIdentity.type == "Root"` for any event | Root should never be used post-setup; even a single event is suspicious |
| `console_login_without_mfa` | `ConsoleLogin` + `additionalEventData.MFAUsed == "No"` | CIS AWS 1.5; either misconfig or compromise |
| `iam_policy_change_after_hours` | IAM mutation events outside business hours | Attackers don't keep office hours |
| `bulk_s3_get_in_window` | > N `GetObject` events from same principal in M minutes | Exfil signature; threshold-tuneable |
| `assume_role_from_unknown_account` | `sts:AssumeRole` with `userIdentity.accountId` not in trust-list | Cross-account compromise marker |
| `cloudtrail_logging_stopped` | `StopLogging` event | Attacker's first move post-compromise; almost always malicious |
| `guardduty_disabled` | `DisableGuardDuty` | Same as above; defence-evasion |
| `mass_security_group_open` | `AuthorizeSecurityGroupIngress` with `0.0.0.0/0` | Often legitimate config change BUT high-fidelity in production |
| `iam_user_created_off_hours` | `CreateUser` outside business hours | Backdoor account creation pattern |
| `kms_key_disabled` | `DisableKey` on a CMK | Often combined with snapshot-share-to-attacker-account |

## Operational Runbook

### Step 1 — pull recent events

```bash
# Using AWS CLI directly (CloudTrail's LookupEvents has rate limits)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false \
  --start-time "$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')" \
  --max-results 1000 \
  --output json > /tmp/ct_recent.json
```

For bulk analysis, prefer Athena over the LookupEvents API (the trail's S3 destination + Athena partitioning is much faster).

### Step 2 — fire Strix's rule engine

```bash
strix cloudtrail_detection \
  --trail-source s3://strix-cloudtrail-logs/ \
  --start "$(date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
```

Outputs `cloudtrail_findings.jsonl` with per-rule matches.

### Step 3 — hunt for known-bad patterns

```bash
# Manual hunt: combine multiple rule-shapes for higher confidence

# Compromise indicator: AssumeRole from unknown account + WHO is dialing in
jq -c 'select(.eventName == "AssumeRole" and .sourceIPAddress | not contains("amazonaws.com"))' /tmp/ct_recent.json | \
  jq -c '{
    time: .eventTime,
    role: .requestParameters.roleArn,
    src_ip: .sourceIPAddress,
    src_account: .userIdentity.accountId,
    src_principal: .userIdentity.arn
  }'

# Exfil indicator: bulk GetObject from one principal
jq -c 'select(.eventName == "GetObject") | .userIdentity.arn' /tmp/ct_recent.json | \
  sort | uniq -c | sort -rn | head -10
```

### Step 4 — timeline reconstruction

```bash
# For a single suspicious principal, build a full timeline
PRINCIPAL='arn:aws:sts::ACCOUNT:assumed-role/Admin/suspicious-session'
jq -c "select(.userIdentity.arn == \"$PRINCIPAL\")" /tmp/ct_recent.json | \
  jq -r '. | "\(.eventTime) \(.eventName) \(.eventSource) \(.requestParameters // {} | tostring | .[:200])"' | \
  sort
```

### Step 5 — pivot to defence-evasion check

```bash
# Did the principal try to stop logging?
jq -c "select(.userIdentity.arn == \"$PRINCIPAL\" and (.eventName == \"StopLogging\" or .eventName == \"DeleteTrail\" or .eventName == \"DisableGuardDuty\"))" /tmp/ct_recent.json
```

A `StopLogging` event from a compromised principal is high-confidence active intrusion.

## Specific Hunt Patterns

### "Living off the IAM" — privilege expansion timeline

A compromised low-priv principal often:
1. `ListUsers` / `ListRoles` / `GetAccountAuthorizationDetails` (discovery)
2. `PutUserPolicy` or `AttachUserPolicy` (self-promote)
3. `CreateAccessKey` (persistence)
4. `AssumeRole` to a more privileged role (lateral)
5. `GetSecretValue` / bulk `GetObject` (exfil)

Detecting any 2-3 of these from the same principal within 30 minutes = high-confidence.

### "AssumeRole from same principal, multiple targets, short window"

Normal: a principal assumes one role per workflow.
Attack: a compromised principal walks the IAM graph, assuming every role they can.

```bash
jq -c 'select(.eventName == "AssumeRole") | {principal: .userIdentity.arn, target: .requestParameters.roleArn, time: .eventTime}' /tmp/ct_recent.json | \
  awk -F'"target":' '{print $0}' | sort | uniq -c | sort -rn | head
```

### Cross-region API call pattern

Many APIs are region-specific. A compromised principal often probes multiple regions to find resources:

```bash
jq -c '.awsRegion' /tmp/ct_recent.json | sort | uniq -c | sort -rn
# Normal: heavy in one or two regions
# Compromise: equal distribution across many regions = probing
```

### "Sleeper" backdoor — long-dormant role activated

A role that hasn't been used in 90 days suddenly fires:

```bash
# Compare CloudTrail's last-used timestamp on a role vs current activity
aws iam get-role --role-name <ROLE> --query 'Role.RoleLastUsed.LastUsedDate'
```

If LastUsedDate is months old but the role appeared in CloudTrail today → reactivation event.

## False Positive Tuning

CloudTrail noise sources:
- Auto-scaling event-fired actions (`assumed-role/AmazonSSMRoleForAutomationAssumeQuickSetupType*`)
- Service-linked role activity (background AWS services)
- CodeBuild / CodePipeline / Lambda execution-role activity at high volume
- Automated tools (Terraform / Pulumi runs) that look like burst-rate IAM changes

Strix's rules ship with reasonable defaults for the volume thresholds; tune via:
```bash
STRIX_CDR_BULK_S3_THRESHOLD=100      # default 50
STRIX_CDR_BULK_WINDOW_MINUTES=15     # default 30
STRIX_CDR_OFF_HOURS_START=22         # default 20 (10pm)
STRIX_CDR_OFF_HOURS_END=6            # default 8 (8am)
```

## Validation

1. Rule fired: events match the rule's criteria.
2. Principal context: pull the principal's last 24h activity for timeline.
3. Source IP: geo-lookup; compare against known-good IP ranges.
4. Cross-rule corroboration: did the same principal trigger 2+ rules in a short window?
5. Document: principal, action, time, source IP, geo, related events from the same principal.

## False Positives

- Service-linked role activity (`AWSServiceRoleFor*`) — normal AWS-side automation.
- IaC runs (Terraform apply) producing burst-rate IAM changes from one principal.
- After-hours CI / batch jobs from automation principals.
- Geo-mobile workforce with VPN exit-nodes in unusual regions.

## Impact

CDR isn't a control — it's an oracle. Its value is **time-to-detect**:
- Mature SOC: 24-48h to noticing an active compromise via SIEM.
- Mature SOC + Strix CDR: minutes to hours, since deterministic rules fire on signal patterns.

## Remediation

1. **CloudTrail enabled on all trails + Organization Trail** for centralised collection.
2. **Multi-region trail** capturing all API events (read + write).
3. **CloudTrail S3 bucket with bucket policy denying delete** to anyone except the trail-management role.
4. **Athena partitioning** on the trail's S3 bucket for fast querying.
5. **Subscribe to `cloudtrail_findings.jsonl`** in the wrapper for alerting + ticketing.
6. **GuardDuty + Security Hub** as the AWS-native layer alongside CDR rules.
7. **Quarterly red-team exercise**: validate the rules fire on canonical attacker actions.

## Pro Tips

1. CloudTrail logs are best stored in a *separate, locked-down* AWS account (the "log archive" pattern in AWS Control Tower).
2. CloudTrail Insights is AWS's ML-baseline anomaly detector — useful complement to deterministic rules.
3. The `userIdentity.invokedBy` field reveals when an event was triggered by another AWS service (e.g., `cloudformation.amazonaws.com`) — useful for de-noising automation events.
4. Bulk-export via Athena partitioned by `dt` is 10-100× faster than `LookupEvents` for week+ ranges.
5. The CDR ML-baseline upgrade (replacing deterministic rules with learned baselines) is masterroadmap §5 P3 — track for future iteration.

## Summary

CloudTrail-based CDR converts API-call streams into compromise signals. Strix's rules cover the canonical attacker patterns; tuning thresholds + rule-stacking + timeline reconstruction is how you go from "alert" to "incident response."
