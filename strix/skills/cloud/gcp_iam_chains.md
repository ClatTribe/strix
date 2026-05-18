---
name: gcp-iam-chains
description: GCP IAM chains — service accounts, primitive roles, IAM Conditions, Domain Restricted Sharing, Workload Identity Federation
triggers: [gcp iam, service account, primitive role, owner role, iam conditions, workload identity federation, gcp impersonate]
---

# GCP IAM Chains

GCP's IAM model differs from AWS in important ways: **service accounts are themselves resources** that can be impersonated, **primitive roles** (Owner/Editor/Viewer) still exist with project-wide scope, and **IAM Conditions** + **Domain Restricted Sharing** add policy guards that defenders use and attackers test for gaps. Strix's `cloud_attack_paths/patterns.py` includes `_pattern_gcp_default_compute_sa_with_internet` and `_pattern_gcp_service_account_owner_role`.

## Attack Surface

### Primitive roles (the legacy danger)
- `Owner`, `Editor`, `Viewer` — project-wide scope; can't be restricted
- `Owner` includes the ability to grant/revoke IAM = self-promotion
- Bug: granted at project-level "for the rollout" and never tightened

### Predefined roles
| Role | What it grants |
|---|---|
| `roles/iam.serviceAccountUser` | Run an instance / Cloud Run service as the SA — same as AWS PassRole |
| `roles/iam.serviceAccountTokenCreator` | Generate short-lived tokens for the SA = direct impersonation |
| `roles/iam.serviceAccountKeyAdmin` | Create/delete SA keys (persistent creds) |
| `roles/resourcemanager.projectIamAdmin` | Manage IAM on the project (= can self-promote) |
| `roles/iam.organizationRoleAdmin` | Manage org-level custom roles |

### Service accounts as principals AND as resources
- A SA is a principal (it has identity) AND a resource (others can have permissions ON it)
- `roles/iam.serviceAccountUser` on SA-X allows the grantee to act as SA-X
- Bug: dev SA granted `serviceAccountUser` on prod SA → trivial elevation

### Default Compute Engine SA
- Every project gets a default SA at `<PROJECT_NUMBER>-compute@developer.gserviceaccount.com`
- Has `Editor` role by default (huge)
- Bug: every VM in the project that doesn't explicitly set a custom SA runs as this — Editor on the project

### Workload Identity Federation (WIF)
- AWS ↔ GCP cross-cloud federation: GitHub Actions / AWS / Azure principal → GCP token
- Bug: WIF pool with overly-broad `attributeCondition` → any GitHub repo can impersonate the SA
- Common pattern: `attribute.repository == "org/*"` instead of `"org/specific-repo"`

### IAM Conditions
- Time-bound, request-attribute-based, resource-attribute-based predicates on IAM grants
- Bug: condition uses `resource.name.startsWith("projects/_/buckets/dev")` — but the principal can also read prod-named buckets because the condition only filters the bound action

## Detection Channels

### Project-level IAM dump

```bash
# Per-project, list all bindings
PROJECT='target-project'
gcloud projects get-iam-policy "$PROJECT" --format=json > /tmp/iam.json

# All Owner/Editor bindings
jq '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor") | .members' /tmp/iam.json
```

### Service-account-as-resource bindings

```bash
# For each SA, get its IAM policy (who can act AS this SA)
for sa in $(gcloud iam service-accounts list --project "$PROJECT" --format='value(email)'); do
  echo "=== $sa ==="
  gcloud iam service-accounts get-iam-policy "$sa" --project "$PROJECT" --format=json
done | jq -c '. | select(.bindings != null) | .bindings[]?'
```

### Default SA in use

```bash
# Find VMs running as the default Compute SA (Editor everywhere)
gcloud compute instances list --filter='serviceAccounts.email~"compute@developer.gserviceaccount.com"'

# Find Cloud Run services with the default SA
gcloud run services list --filter='spec.template.spec.serviceAccountName=""'
```

### Workload Identity Federation pools

```bash
gcloud iam workload-identity-pools list --location=global --project="$PROJECT"

# Per-pool: providers + their attribute conditions
for pool in $(gcloud iam workload-identity-pools list --location=global --format='value(name)'); do
  echo "=== $pool ==="
  gcloud iam workload-identity-pools providers list --workload-identity-pool="$pool" --location=global
done
```

## Operational Runbook

### Step 1 — full enumeration

```bash
# Strix's gcp_discovery.py (PR #311) walks IAM + WIF
strix --target gcp://target-project --target-type cloud_account
```

### Step 2 — find Owner/Editor on humans

```bash
jq -r '.bindings[] | select(.role == "roles/owner" or .role == "roles/editor") | .members[]' /tmp/iam.json
# 'user:alice@org.com' → human Owner is risky
# 'serviceAccount:xxx@project.iam.gserviceaccount.com' → SA Owner is worse
```

### Step 3 — chain via serviceAccountUser

```bash
# Who can act AS the high-priv SA?
TARGET_SA='prod-admin@target-project.iam.gserviceaccount.com'
gcloud iam service-accounts get-iam-policy "$TARGET_SA" --format=json | \
  jq '.bindings[] | select(.role == "roles/iam.serviceAccountUser" or .role == "roles/iam.serviceAccountTokenCreator") | .members'
```

Each member of those bindings can impersonate the SA.

### Step 4 — impersonate (when you have permission)

```bash
# Generate a short-lived token for the target SA
gcloud auth print-access-token --impersonate-service-account="$TARGET_SA"

# Or for a deeper chain
gcloud iam service-accounts get-access-token "$TARGET_SA" \
  --impersonate-service-account="$INTERMEDIATE_SA"
```

### Step 5 — escalate via Cloud Function / Cloud Run

```bash
# Deploy a Cloud Function running as the high-priv SA
gcloud functions deploy strix-pivot \
  --runtime python311 \
  --trigger-http \
  --service-account="$TARGET_SA" \
  --entry-point=main \
  --source=. \
  --allow-unauthenticated

# Invoke and read the SA's bearer token via the metadata server (inside the function)
curl -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
```

### Step 6 — WIF abuse

```bash
# For an over-broad WIF pool (e.g., GitHub Actions trusting org/*)
# Attacker who controls ANY repo in the org can mint a GCP token:

# Spin up a GitHub Actions workflow:
cat <<EOF > .github/workflows/strix-wif.yml
name: WIF-probe
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: '<PROVIDER_NAME>'
          service_account: '<TARGET_SA>'
      - run: gcloud auth list && gcloud projects list
EOF
```

## Specific Vulnerability Classes

### Service-account key creation
- `roles/iam.serviceAccountKeyAdmin` lets the principal create persistent keys
- Persistent keys are LONG-LIVED bearer credentials
- Once exfiltrated, can't be IP-restricted; only revocable by key delete + rotation

### Cross-project SA impersonation
- SA in project A can be granted `serviceAccountUser` from project B
- Principal in B uses A's SA, accesses A's resources → cross-project pivot

### Org-level Owner via inheritance
- Org-level bindings inherit to all projects
- `Org-level Owner` is rarer than `Project Owner` but devastating

### Domain Restricted Sharing
- Org policy that prevents sharing with non-org domains
- Bug: policy in `audit-only` mode → doesn't enforce

### Default network with default rules
- New GCP projects come with a `default` network with `default-allow-ssh` (22) + `default-allow-rdp` (3389) firewall rules
- Combined with default Compute SA = trivial post-compromise SSH

## Bypass Techniques

- **IAM Condition gaps**: `request.time` conditions only apply to that specific request; principals can still query metadata about other resources.
- **Service-agent SAs**: managed-service SAs (e.g., `service-<PROJECT_NUMBER>@gcp-sa-<SVC>.iam.gserviceaccount.com`) have implicit broad roles; if any role binding chains through one, audit carefully.
- **Resource-Manager API quirks**: `projects.setIamPolicy` is atomic; `projects.getIamPolicy` + edit + setIamPolicy can race with concurrent edits, losing audit entries.

## Validation

1. Static finding: IAM dump shows the over-broad binding.
2. Impersonation confirmed: `gcloud auth print-access-token --impersonate-service-account=<SA>` succeeds.
3. Resource access: `gcloud <service> <action> --impersonate-service-account=<SA>` reads/modifies expected resource.
4. WIF abuse: workflow in an unauthorized repo successfully exchanges for a GCP token.
5. Document: principal, role, target SA / project, chain length, presence of org policy guards.

## False Positives

- `serviceAccount:cloudfunctions-build@system.gserviceaccount.com` and similar service-agent SAs — required for the service to function.
- `roles/owner` on a project-creator account — sometimes deliberate for break-glass.
- WIF pool intentionally trusting a wide audience (e.g., all GitHub org repos) when the resulting SA is locked-down — verify the SA's actual permissions before scoring high.

## Impact

- Project-wide admin via Owner self-promotion or SA chain.
- Cross-project pivot via cross-project serviceAccountUser bindings.
- Persistent compromise via long-lived SA keys.
- External-source compromise via over-broad WIF pools (GitHub Actions / AWS principals minting GCP tokens).

## Remediation

1. **No primitive roles in production**: replace `Owner`/`Editor`/`Viewer` with predefined roles.
2. **No default Compute SA**: every VM / Cloud Run service should have an explicit, scoped SA.
3. **Org policy: `iam.disableServiceAccountKeyCreation`** — block long-lived SA keys outright; use WIF or impersonation instead.
4. **Org policy: `iam.allowedPolicyMemberDomains`** — Domain Restricted Sharing to limit external grants.
5. **WIF `attributeCondition` strict**: exact-match `repository`, `ref`, `workflow` fields — never wildcards.
6. **IAM Conditions on sensitive grants**: `resource.name.startsWith(...)` to scope by name; `request.time < ...` for time-bound access.
7. **Cloud Asset Inventory + Policy Analyzer** for finding the "who has what" across the org.

## Pro Tips

1. The default Compute Engine SA has Editor by default. Disable that auto-grant in org policy: `iam.automaticIamGrantsForDefaultServiceAccounts`.
2. `gcloud asset analyze-iam-policy` answers "who can do X on Y?" — useful for "find every principal who can read this secret".
3. WIF GitHub Actions example in GCP docs uses `attribute.repository_owner == "owner"` — overly broad. Always also condition on `attribute.repository`.
4. SA key creation is the gateway to persistent compromise; CIS Benchmark recommends disabling outright.
5. Project deletion in GCP retains the project for 30 days — IAM bindings stay valid. Inactive-project audit is its own surface.

## Summary

GCP IAM exploitation is service-account impersonation, primitive-role over-grant, and WIF condition gaps. Audit `serviceAccountUser` and `serviceAccountTokenCreator` bindings specifically; replace primitive roles; tighten WIF attribute conditions.
