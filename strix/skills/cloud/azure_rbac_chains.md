---
name: azure-rbac-chains
description: Azure RBAC privilege chains — Owner / Contributor / Custom roles, management-group inheritance, AAD pivots
triggers: [azure rbac, role assignment, owner role, contributor role, management group, azure ad, entra, conditional access, service principal]
---

# Azure RBAC Chains

Azure RBAC sits on three layers — **management groups → subscriptions → resource groups → resources** — with role assignments cascading down. The bugs cluster at three levels: (1) overly-broad role assignments (`Owner` on a subscription); (2) ill-defined custom roles that grant `*/write` actions; (3) Azure AD / Entra service principals with implicit-trust SDKs (managed identities). Strix's `cloud_attack_paths/patterns.py` includes `_pattern_azure_owner_role_user` and related patterns.

## Attack Surface

### Built-in roles (the big ones)
| Role | Powers |
|---|---|
| `Owner` | Full control + manage role assignments (= can self-promote) |
| `Contributor` | Manage everything **except** role assignments |
| `User Access Administrator` | Manage role assignments only (= can grant self Owner) |
| `Reader` | Read everything; sometimes leaks secrets via list-secret-properties |
| `Network Contributor` | Manage network; can re-route traffic |
| `Storage Account Contributor` | Read/write storage account properties (incl. keys) |

### Custom roles
- Definition: `Actions`, `NotActions`, `DataActions`, `NotDataActions`, `AssignableScopes`
- Bug pattern: `Actions: ["*/write", "*/delete"]` with broad scope = de-facto Owner
- `*/role*` actions on custom role = self-promotion path

### Management-group inheritance
- Assignment at MG level inherits to every child subscription
- Bug: vendor / consultant added at MG level "temporarily" — never removed
- `Tenant Root Group` assignment = god-mode across the whole tenant

### Service principals + managed identities
- SP types: Application, ManagedIdentity (System-Assigned vs User-Assigned), Legacy
- Bug: SP with high-priv role + permissive Conditional Access (no MFA, no geo restriction) = bearer-token-only auth
- System-Assigned MI on a VM with `Owner` role on the subscription = catastrophic

### Cross-tenant guest users
- B2B guests: invited from another tenant; can be assigned RBAC roles
- Bug: guest user with `Contributor` on a production resource group; the home tenant is breached → spillover

## Detection Channels

### Enumerate role assignments

```bash
# Top-level assignments (subscription + management group level)
az role assignment list --include-inherited --output table

# Owner / UAA assignments specifically (the dangerous ones)
az role assignment list --role 'Owner' --output table
az role assignment list --role 'User Access Administrator' --output table

# Custom roles with broad scopes
az role definition list --custom-role-only true \
  --query '[?contains(to_string(permissions[0].actions), `"*/write"`)].roleName' --output table
```

### Service principal audit

```bash
# All SPs in the tenant
az ad sp list --query '[].{appId:appId, displayName:displayName, servicePrincipalType:servicePrincipalType}'

# SP role assignments
az role assignment list --assignee <APP_ID>

# Look for: managed identities on VMs with subscription-level Owner
```

### Conditional Access policy audit

```bash
# Requires Microsoft Graph permissions
az rest --method get --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
# Look for: gaps in MFA enforcement, missing geo/IP filters, broken-glass accounts excluded
```

## Operational Runbook

### Step 1 — full RBAC dump

```bash
# Strix's azure_discovery.py (PR #310) walks RBAC; manual variant:
SUBS=$(az account list --query '[].id' --output tsv)
for sub in $SUBS; do
  az account set --subscription "$sub"
  echo "=== SUB $sub ==="
  az role assignment list --all --output json > "/tmp/rbac_${sub}.json"
done
```

### Step 2 — find Owner assignments to users / SPs

```bash
jq -r '.[] | select(.roleDefinitionName == "Owner") | "\(.principalName // .principalId)\t\(.scope)"' /tmp/rbac_*.json | sort -u
```

Each line is a (principal × scope) where the principal can do anything within the scope.

### Step 3 — chain via User Access Administrator

```bash
# UAA can assign Owner to themselves
jq -r '.[] | select(.roleDefinitionName == "User Access Administrator") | "\(.principalName)\t\(.scope)"' /tmp/rbac_*.json

# Each UAA principal is effectively Owner-equivalent (they can self-promote)
```

### Step 4 — custom-role audit

```bash
# List custom roles with dangerous actions
az role definition list --custom-role-only true --output json | \
  jq -r '.[] | select(.permissions[0].actions[]? | test("\\*/write|\\*/delete|.+/roleAssignments/write")) | .roleName'
```

### Step 5 — managed-identity discovery

```bash
# System-Assigned MIs on VMs
az vm list --query '[?identity.type==`SystemAssigned`].{name:name, mi:identity.principalId}'

# What roles do those MIs have?
for principal in $(az vm list --query '[?identity.type==`SystemAssigned`].identity.principalId' --output tsv); do
  echo "=== $principal ==="
  az role assignment list --assignee "$principal"
done
```

A VM with an MI assigned `Owner` on the subscription = compromise of that VM = subscription-wide compromise.

### Step 6 — escalate

```bash
# When you have UAA or similar
# Self-promote to Owner
az role assignment create \
  --assignee <YOUR_PRINCIPAL> \
  --role 'Owner' \
  --scope /subscriptions/<SUB_ID>

# When you have an MI that can assume identities
# (rare — MIs typically can't assume other identities, but check)
```

### Step 7 — cross-tenant abuse (guest principals)

```bash
# All guest users
az ad user list --filter 'userType eq "Guest"' --query '[].{upn:userPrincipalName, externalId:externalUserState}'

# Guests with role assignments
for upn in $(az ad user list --filter 'userType eq "Guest"' --query '[].userPrincipalName' --output tsv); do
  az role assignment list --assignee "$upn" 2>/dev/null
done
```

When a guest's home tenant is compromised, the spillover into your tenant follows the role assignments. Audit and prune aggressively.

## Specific Vulnerability Classes

### Management-group sprawl
- Vendor added at root MG "for the rollout" — left there for years
- Audit `Tenant Root Group` assignments specifically; anyone there has god-mode

### Custom role with `Actions: ["*"]`
- Should be `NotActions` for least privilege; `*` with no NotActions = Owner-equivalent
- Custom role names often misleading (`ReadOnlyAuditor` with `*` actions seen IRL)

### Subscription-level Reader leaking secrets
- `Reader` includes `Microsoft.KeyVault/vaults/secrets/read` (metadata only, not value)
- But: `Reader` on a Storage account exposes connection strings via `Microsoft.Storage/storageAccounts/listKeys` if the role definition is custom

### Azure Hybrid Connect / Azure Arc
- On-prem servers registered to Azure inherit the MI + RBAC model
- Bug: on-prem compromise → MI extract → cloud pivot via the Arc identity

### Service Principal with secret-not-key
- SP with a password (`client_secret`) instead of a certificate
- Secret rotation often skipped; old secrets stay valid
- Discover via `az ad sp credential list`

## Bypass Techniques

- **`Just-In-Time` (JIT) gap**: Privileged Identity Management activates roles on request, but the activation window is wide. Compromised account → request JIT activation → use during window.
- **Cross-tenant App Registration**: an Application's `signInAudience: AzureADMultipleOrgs` allows guest users from other tenants to sign in. Misconfig → cross-tenant authn.
- **PIM eligible-but-not-active**: `eligible` assignment is "can activate"; audit it as if it were `active`.
- **Conditional Access "Report-Only" mode**: a policy in report-only doesn't enforce. Confirm it's `Enabled`.

## Validation

1. Static finding: the RBAC dump shows the over-broad assignment.
2. Active confirmation: actually exercise the permission (`az role assignment create` for UAA-as-self-promote).
3. Cross-account: when guest users have assignments, demonstrate the home-tenant compromise → cross-tenant pivot.
4. Document: principal, role, scope, the upstream credential / SP that has the role.

## False Positives

- Role assigned to a built-in service principal (`Azure Backup`, `Azure Site Recovery`) — these are AWS-managed and required for the service to function.
- `Reader` at subscription level for the SOC team — broad but read-only; flag with low severity.
- Custom role with `*/read` and tight `NotActions` for secrets — broad but effectively limited; verify with `az role definition show`.

## Impact

- Subscription-wide admin via Owner self-promotion.
- Cross-resource-group lateral movement via Contributor on the parent RG.
- Data exfil via Storage Account Contributor → connection strings → unauthenticated blob access.
- Cross-tenant compromise via guest-principal spillover.

## Remediation

1. **No Owner at MG / Tenant Root Group** — restrict to a break-glass account with hardware MFA.
2. **PIM for high-priv roles**: Privileged Identity Management requires activation, logs, and time-boxing.
3. **Conditional Access enforcing MFA + geo + device compliance** on every privileged account.
4. **Custom roles use NotActions**: explicit deny on `*/roleAssignments/*`, `*/secrets/*`, etc.
5. **Audit guest users**: prune quarterly; never assign privileged roles to guests.
6. **MI scope minimisation**: an MI's role should match the resource's purpose, not subscription-wide.
7. **Defender for Cloud** + Azure Activity Log alerts on `Microsoft.Authorization/roleAssignments/write` events.

## Pro Tips

1. The "User Access Administrator" role is the under-rated assassin — it doesn't say "Owner" but it's functionally equivalent. Audit it specifically.
2. Management group hierarchy is often opaque; `az account management-group list` reveals the inheritance.
3. SP passwords vs certificates: passwords are short strings in `client_secret`; certs are cryptographically rotatable. Migrate to certs.
4. Azure AD's "Application Administrator" role can manage SPs — chain it to "create SP with high-priv assignment" for self-elevation.
5. Microsoft's `ScubaGear` open-source tool audits Azure AD CIS-benchmark gaps — useful prior art.

## Summary

Azure RBAC bugs are scope + role. Owner, UAA, and broad custom roles are the canonical findings. PIM, Conditional Access, and tight custom-role definitions are the defences. The MI + Conditional Access gap is where most real compromises happen.
