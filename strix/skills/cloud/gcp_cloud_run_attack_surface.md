---
name: gcp-cloud-run-attack-surface
description: GCP Cloud Run + Cloud Functions — public services, SA over-privilege, custom-domain DNS abuse, IAM Invoker bypass
triggers: [cloud run, cloud function, faas, gcp serverless, service account binding, invoker role, custom domain, eventarc]
---

# GCP Cloud Run + Cloud Functions Attack Surface

Cloud Run is GCP's container-based serverless platform; Cloud Functions is the FaaS predecessor (still actively used). Both have similar bug classes: **public invocation when it should be private** (`roles/run.invoker` granted to `allUsers`), **execution-SA over-privilege** (the Compute Engine default SA with Editor), and **environment-variable secret leak** (no native secrets-manager integration; env baked into deploy time).

## Attack Surface

### Cloud Run service IAM
- `roles/run.invoker` controls who can call the service
- Granted to `allUsers` → publicly invokable
- Granted to `allAuthenticatedUsers` → any Google account can invoke
- Granted to `serviceAccount:<some-sa>` → only that SA

### Cloud Run execution service account
- Service runs as `--service-account=` if specified
- Defaults to project's Compute Engine default SA (Editor role!)
- Bug: dev deploys with no explicit SA → service inherits Editor on the project

### Custom-domain DNS
- Cloud Run service mapped to custom domain (`api.example.com`) via DNS verification
- Bug: dangling DNS record (CNAME pointing at Cloud Run mapping that was deleted) → subdomain takeover candidate
- Bug 2: domain mapping deleted but customer's DNS still points at the Cloud Run URL → freed-up

### Environment variables
- Deploy-time env vars are baked into the revision config
- Visible via `gcloud run services describe` → `containers.env[]`
- Persisted in revision history; old revisions retain leaked plaintext

### Eventarc triggers
- Fires Cloud Run / Functions on Pub/Sub / Cloud Storage / Audit Logs events
- Bug: trigger created from `cloudaudit.googleapis.com` event source can fire on attacker-controlled actions in linked services

### Cloud Functions HTTP triggers
- Similar to Cloud Run service IAM
- Function URL: `https://<region>-<project>.cloudfunctions.net/<name>`
- Bug: `--allow-unauthenticated` flag exposed during deploy → public callable

## Detection Channels

### Public-invokable services

```bash
# Cloud Run
for region in us-central1 us-east1 europe-west1 asia-east1; do
  for svc in $(gcloud run services list --region="$region" --format='value(metadata.name)' 2>/dev/null); do
    POLICY=$(gcloud run services get-iam-policy "$svc" --region="$region" --format=json 2>/dev/null)
    if echo "$POLICY" | jq -r '.bindings[]?.members[]?' | grep -qE 'allUsers|allAuthenticatedUsers'; then
      echo "PUBLIC Cloud Run: ${region}/${svc}"
    fi
  done
done

# Cloud Functions
for fn in $(gcloud functions list --format='value(name)'); do
  POLICY=$(gcloud functions get-iam-policy "$fn" --format=json 2>/dev/null)
  echo "$POLICY" | jq -r '.bindings[]?.members[]?' | grep -qE 'allUsers' && echo "PUBLIC Function: $fn"
done
```

### Execution SA enumeration

```bash
# Cloud Run services + their SAs
gcloud run services list --format='value(metadata.name,spec.template.spec.serviceAccountName)'

# Services with no explicit SA (== default Compute SA == Editor)
gcloud run services list \
  --filter='-spec.template.spec.serviceAccountName:*' \
  --format='value(metadata.name)'
```

### Env-var sweep

```bash
for svc in $(gcloud run services list --format='value(metadata.name)'); do
  echo "=== $svc ==="
  gcloud run services describe "$svc" --format=json | \
    jq '.spec.template.spec.containers[].env[]? | "\(.name)=\(.value // .valueFrom // "?")"'
done | grep -iE 'KEY=|SECRET=|TOKEN=|PASSWORD='
```

## Operational Runbook

### Step 1 — full enumeration

```bash
strix --target gcp://target-project --target-type cloud_account
# cloud_attack_paths/discovery.py covers Cloud Run + Functions
```

### Step 2 — anonymous probe

```bash
# Walk each public service; verify it actually serves
for svc_url in $(gcloud run services list --filter='-spec.template.metadata.annotations:run.googleapis.com/launch-stage=BETA' --format='value(status.url)'); do
  STATUS=$(curl -s -o /tmp/probe -w '%{http_code} %{size_download}' "$svc_url")
  echo "${svc_url} → ${STATUS}"
done
```

### Step 3 — execution-SA privilege check

```bash
# For each service, get the SA + its roles
gcloud run services list --format='value(metadata.name,spec.template.spec.serviceAccountName)' | \
  while read svc sa; do
    [[ -z "$sa" ]] && sa='<default Compute SA>'
    echo "=== Service: $svc | SA: $sa ==="
    if [[ "$sa" != '<default Compute SA>' ]]; then
      gcloud projects get-iam-policy "$PROJECT" \
        --flatten='bindings[].members' \
        --filter="bindings.members:serviceAccount:${sa}" \
        --format='value(bindings.role)'
    fi
  done
```

### Step 4 — env-var enumeration

```bash
# Across all services
for svc in $(gcloud run services list --format='value(metadata.name)'); do
  ENV_VARS=$(gcloud run services describe "$svc" --format=json | \
    jq -r '.spec.template.spec.containers[].env[]? | select(.value != null) | "\(.name)=\(.value)"')
  if echo "$ENV_VARS" | grep -iqE 'KEY|SECRET|TOKEN|PASSWORD|API_'; then
    echo "=== $svc ==="
    echo "$ENV_VARS"
  fi
done
```

### Step 5 — exploit public service + execution SA

```bash
# Public Cloud Run service running with high-priv SA = direct compromise pathway
URL='https://public-svc-xxxx-uc.a.run.app/'

# Probe for SSRF / template injection / arbitrary command paths
curl -s "$URL/?cmd=env"

# If the service code reflects env / spawns subprocesses, you can pivot to the SA token
# (via metadata server inside the Cloud Run container)
```

### Step 6 — custom-domain takeover

```bash
# Find domain mappings
gcloud beta run domain-mappings list --region=$REGION

# For each, check if the underlying DNS is still pointing
DOMAIN='api.example.com'
dig +short "$DOMAIN"
# Should point at ghs.googlehosted.com or the service URL

# If the domain mapping was deleted but DNS still points → attacker creates a new
# mapping under their own project + same DNS = subdomain takeover
```

### Step 7 — revision-history env-leak

```bash
# Old revisions retain leaked plaintext
for svc in $(gcloud run services list --format='value(metadata.name)'); do
  for rev in $(gcloud run revisions list --service="$svc" --format='value(metadata.name)'); do
    echo "=== ${svc}/${rev} ==="
    gcloud run revisions describe "$rev" --format=json | \
      jq '.spec.containers[].env[]? | select(.value != null)'
  done
done
```

## Specific Vulnerability Classes

### Cloud Run + IAM Invoker `allUsers`
- Many tutorials/blogs use `--allow-unauthenticated` for demos
- Production deploys inherit this; service is public + runs with full SA
- Frequently combined with no input validation → cloud SSRF pathway

### Cloud Functions + HTTP trigger no auth
- Same issue, older platform; `--allow-unauthenticated` flag
- `gcloud functions describe` shows `httpsTrigger` → no auth listed

### Eventarc trigger SA misconfiguration
- Trigger SA needs `roles/eventarc.eventReceiver`
- Common: SA also given `roles/storage.objectAdmin` "because the function writes to GCS"
- The function can be invoked by attacker-controlled events → it acts with the over-broad SA

### Mtls / Cloud Armor bypass
- Cloud Run can be fronted by HTTPS Load Balancer with Cloud Armor
- Bug: direct service URL (`*.run.app`) bypasses the LB + Cloud Armor entirely
- Defence requires `Ingress: internal-and-cloud-load-balancing` on the service

### Cross-region service replica drift
- Service deployed in multiple regions for HA
- Each region has its own IAM policy → drift between regions; primary tight, replica loose

## Validation

1. Public service: anonymous HTTP to the service URL returns 2xx with application content.
2. SA enumeration: confirm the execution SA's roles (Editor or higher = critical).
3. Env-var leak: list env vars with sensitive-looking keys + values.
4. Custom-domain takeover: DNS resolves to GCP infra but no mapping exists in the target project.
5. Document: service, region, SA roles, env contents (redacted), exact public-callable URL.

## False Positives

- Public landing page intentionally hosted on Cloud Run (a deliberate marketing site).
- `allow-unauthenticated` on a function that itself enforces auth via JWT (verify by sending unauth request and checking response).
- `<region>.run.app` URLs sometimes resolve to a holding-page even when service deleted — confirm via `gcloud run services list`.
- Old revisions retained for audit; old env vars are intentional.

## Impact

- Direct compromise via public-callable service running with project Editor SA.
- Lateral movement via execution-SA token theft.
- Persistent backdoor via attacker-deployed revision with permanent env-set creds.
- Subdomain takeover via dangling Cloud Run domain mappings.

## Remediation

1. **`Ingress: internal-and-cloud-load-balancing`** on every Cloud Run service unless explicitly public-by-design.
2. **No `allow-unauthenticated`** — require `roles/run.invoker` granted to specific principals.
3. **Dedicated execution SA** per service, scoped to its exact resources.
4. **Org policy: `iam.disableAutomaticIAMGrantsForDefaultServiceAccounts`** — block Editor on default Compute SA.
5. **Secrets via Secret Manager**: bind via `--update-secrets=API_KEY=secret_name:latest` instead of `--update-env-vars=`.
6. **VPC-SC** around sensitive services to prevent egress to attacker-controlled targets.
7. **Cloud Audit Logs** + alerts on `services.setIamPolicy` events.

## Pro Tips

1. `gcloud run services list --filter='-spec.template.spec.serviceAccountName:*'` is the fastest "find services using the default SA" query.
2. Cloud Run's status.url is the canonical "is it publicly reachable" indicator — even if Ingress is internal, the URL is published for the Load Balancer.
3. Cloud Functions Gen 1 vs Gen 2 differ structurally — Gen 2 runs on Cloud Run under the hood; audit both.
4. Custom-domain takeover is harder on GCP than AWS because domain mapping requires DNS verification, but the dangling-DNS variant still applies when mappings are deleted.
5. Eventarc triggers with attacker-controlled event sources (e.g., a public bucket emitting `ObjectCreated`) are a 2-hop pivot to "your function ran my code with your SA".

## Summary

Cloud Run + Functions bugs: public invocation, default-SA over-privilege, env-var leaks, custom-domain takeover. Audit IAM Invoker bindings first; tighten execution SAs; migrate env-vars to Secret Manager bindings.
