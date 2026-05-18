---
name: aws-lambda-attack-surface
description: Lambda function-URL no-auth, env-var secret leak, execution-role escalation, layer poisoning
triggers: [lambda, function url, execution role, env secret, lambda env, layer poisoning, faas, serverless]
---

# AWS Lambda Attack Surface

Lambda combines two distinct security boundaries: the **invocation interface** (who can call the function) and the **execution role** (what the function can do). Misconfigurations in either pivot quickly. Add Function URLs (introduced 2022) and the surface grows: a misconfigured Function URL is a public endpoint with the function's execution role attached.

Strix's `cloud_attack_paths/patterns.py` includes `_pattern_lambda_function_url_no_auth` and `_pattern_secrets_via_environment`. Companion to `agentless_scan.py` for the function code itself.

## Attack Surface

### Function URLs
- Per-function HTTPS endpoint at `https://<id>.lambda-url.<region>.on.aws/`
- `AuthType: NONE` → publicly callable
- `AuthType: AWS_IAM` → requires SigV4 (still callable by anyone with IAM credentials in the same account)
- CORS often left wide open (`AllowOrigins=["*"]`)

### Execution role abuse
- Every Lambda runs with a role attached — `arn:aws:iam::ACCOUNT:role/<FunctionName>-role`
- If the function ingests user input and reflects role-context creds: SSRF-like exposure
- The role often has more permissions than the function needs (over-provisioned by default)

### Env-var secrets
- Lambda env vars are visible in the AWS Console + IAM-controlled API
- Plaintext storage is common; KMS-encrypted is opt-in via `KMSKeyArn`
- A leaked function context (via stack trace, logs, or misconfigured error path) reveals env vars

### Lambda layers
- Shared dependencies in `/opt/` of the runtime
- Cross-account-shared layers can be poisoned: if the publisher's IAM is compromised, every consumer's Lambda runs the poisoned code

### Resource-based policies
- `aws lambda add-permission` grants invocation rights
- `Principal: "*"` without `Condition` = world-invokable function (often happens by accident via SDK examples)

### Triggers
- API Gateway / ALB integrations — each is a separate invocation surface
- S3 ObjectCreated triggers — when the source bucket is writable by an attacker
- EventBridge cron + over-broad permissions on the rule

## Detection Channels

### Enumerate Functions + URLs

```bash
# Strix's cloud_attack_paths/discovery.py walks Lambda
aws lambda list-functions --query 'Functions[].FunctionName' --output text

# Per-function URL config
for fn in $(...); do
  echo "=== $fn ==="
  aws lambda get-function-url-config --function-name "$fn" 2>&1 | head -10
  aws lambda get-policy --function-name "$fn" 2>&1 | head -10
done
```

### Public-callable Function URLs

```bash
# Anonymous GET — should be 200 if AuthType=NONE
URL='https://<id>.lambda-url.<region>.on.aws/'
curl -s -o /tmp/lambda_probe.json -w '%{http_code}\n' "$URL"

# If 200/4xx with response body, the function fired with no auth.
```

### Resource-policy probe

```bash
# Pull the function's resource-policy
aws lambda get-policy --function-name <FN_NAME>
# Look for:
# - "Principal": "*" without Condition
# - "Principal": {"Service": "..."}  + missing aws:SourceArn (confused deputy)
# - "Principal": {"AWS": "arn:aws:iam::OTHER:root"} — cross-account invoke
```

### Env-var leak

```bash
# Direct read (requires GetFunctionConfiguration permission)
aws lambda get-function-configuration --function-name <FN_NAME> \
  --query 'Environment.Variables'

# Indirect: trigger an error that returns env in stack trace
# (depends on the function's error-handling)
```

## Operational Runbook

### Step 1 — full enumeration

```bash
strix --target aws://<ACCOUNT> --target-type cloud_account
# Output: cloud_attack_paths/graph.py populated with Lambda nodes
```

### Step 2 — public Function URL sweep

```bash
# Walk every function; test Function URL invocability
for fn in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do
  CFG=$(aws lambda get-function-url-config --function-name "$fn" 2>/dev/null)
  AUTH=$(echo "$CFG" | jq -r '.AuthType // empty')
  URL=$(echo "$CFG" | jq -r '.FunctionUrl // empty')
  if [[ "$AUTH" == "NONE" && -n "$URL" ]]; then
    echo "PUBLIC: $fn → $URL"
    curl -s -o /tmp/probe -w '%{http_code} %{size_download}\n' "$URL"
  fi
done
```

### Step 3 — env-var enumeration

```bash
# Pull env vars across all functions; grep for secrets
for fn in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text); do
  ENV=$(aws lambda get-function-configuration --function-name "$fn" \
        --query 'Environment.Variables' 2>/dev/null)
  if echo "$ENV" | grep -iE 'KEY|SECRET|TOKEN|PASSWORD|DB_PASS|API_'; then
    echo "$fn — env contains potential secret"
    echo "$ENV"
  fi
done
```

### Step 4 — invoke + exfil via the Function URL

```bash
# For a publicly-invokable function, attempt to exfil context
# If the function reflects request data:
curl -s "$URL?cmd=env"   # observe response

# If function accepts user-controlled paths:
curl -s "$URL/proc/self/environ"   # rarely works but cheap to try
```

### Step 5 — execution-role escalation

```bash
# When you have direct invoke access, payload the function to leak role creds
# Requires the function code to do something exfil-friendly with env or context

# Example: function returns os.environ
curl -s -X POST "$URL" -d '{"cmd": "leak_env"}'

# Role-creds via metadata service inside the Lambda runtime are at:
# http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# The function code must be coerced into fetching this.
```

### Step 6 — Lambda layer audit

```bash
# Per-function: layer ARNs
aws lambda list-layer-versions --layer-name <LAYER_NAME>

# Cross-account layer-share check
aws lambda get-layer-version-policy --layer-name <LAYER_NAME> --version-number <N>

# Look for:
# - Layer published from an unfamiliar account
# - Outdated layer version (re-publish drift)
```

## Specific Vulnerability Classes

### Function URL + permissive CORS
- `AuthType: NONE` + `CORS.AllowOrigins=["*"]` + `CORS.AllowCredentials=true` — same as classic CORS misconfig
- Any web origin can call the function with the victim's cookies (when the function accepts cookies)

### Confused-deputy via S3 trigger
- Function fires on `s3:ObjectCreated` from bucket X
- If bucket X is writable by an attacker (cross-account, anonymous PUT, etc.), attacker triggers the function with attacker-controlled inputs
- Function runs with its execution role — pivot

### Cross-account invoke via SDK example
- `aws lambda add-permission --principal "*" ...` is a common SDK demo
- Devs copy-paste; principal "*" remains in production

### Snapstart re-init bugs
- Lambda Snapstart caches runtime init; secrets fetched during init are baked into the cache
- If a Snapstart-enabled function rotates its secret, old invocations may serve cached creds

## Bypass Techniques

- **Path-prefix differentials**: Function URLs strip the path; `/admin` and `/` both invoke the same function. Some apps assume `/admin` is auth-gated; not at the Lambda layer.
- **CORS preflight no-auth**: `OPTIONS` to a Function URL with `AuthType: AWS_IAM` succeeds without IAM (CORS preflight bypasses auth in AWS's implementation).
- **Cold-start info leak**: a freshly-invoked Lambda may have init logging that includes env vars; trigger cold-start by waiting + invoking.

## Validation

1. Public URL: anonymous request to the Function URL returns a 2xx/4xx (not 403 from auth).
2. Env-var leak: env contents readable via API or via function response.
3. Resource-policy abuse: invocation succeeds from outside the expected principal set.
4. Cross-account pivot: assume target's role via the leaked function context.
5. Document: function ARN, URL, AuthType, CORS config, env contents (redacted), execution-role ARN.

## False Positives

- Function URL set to `AuthType: NONE` but the function code enforces auth itself (signed JWT in body, HMAC header). Verify the function rejects unauthed inputs.
- Env vars contain expired tokens / dummy values — confirm liveness before flagging.
- Resource-policy `Principal: "apigateway.amazonaws.com"` is normal for API Gateway integrations — not a finding unless `aws:SourceArn` is missing.
- Test functions in dev accounts — confirm scope before reporting.

## Impact

- Direct invocation of authenticated-by-default business logic.
- Execution-role credential theft → broader cloud pivot (S3, DynamoDB, Secrets Manager).
- Env-var secret leak → API keys, DB passwords, third-party tokens.
- Layer poisoning → supply-chain compromise across every consuming function.

## Remediation

1. **`AuthType: AWS_IAM`** on Function URLs by default; only use `NONE` when the function explicitly enforces auth.
2. **CORS restrictions**: explicit allow-list of origins; never `*` with `AllowCredentials: true`.
3. **Least-privilege execution role**: deny `iam:PassRole`, deny `lambda:*` on the role itself, scope S3/DynamoDB resources tightly.
4. **Secrets in Secrets Manager / Parameter Store**, not env vars. Fetched at runtime + cached in memory; never visible to API listings.
5. **`aws:SourceArn` / `aws:SourceAccount` on every resource-based policy**: defeats confused-deputy.
6. **Per-account Lambda layer publish gating**: SCPs blocking cross-account layer sharing.
7. **CloudTrail rule for `lambda:UpdateFunctionConfiguration`** — env changes are high-fidelity compromise signal.

## Pro Tips

1. Function URLs without auth are surprisingly common — they're easier than API Gateway, and `AuthType: NONE` is the default in some Terraform modules.
2. Lambda + S3 trigger + attacker-writable bucket = unauth RCE pathway. Audit S3 trigger sources alongside Lambda permissions.
3. Cold-start logs go to CloudWatch — if you have CloudWatch read, you sometimes see the function's startup environment serialised.
4. AWS's official "Lambda Function URLs blog post" example uses `AuthType: NONE` in the snippet — many copy-pasted productions inherit this.
5. Snapstart-enabled Java functions are a research area: secret rotation + snapshot caching = expired-creds bugs.

## Summary

Lambda's security splits across invoke + execution boundaries. Public Function URLs, env-var secrets, and over-privileged execution roles are the three patterns that show up in most engagements. Audit all three; the cross-product is where real compromise lives.
