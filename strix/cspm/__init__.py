"""Cloud Security Posture Management (CSPM) — live-cloud scanning.

IaC parsers (`strix/iac/`) attest the *intent* declared in
Terraform / K8s YAML. CSPM attests the *actual* state of a
live cloud account — catches drift from IaC, manual console
changes, and resources that pre-date IaC adoption.

Mid-size orgs always have at least one of:
  * `terraform apply` drift (someone clicked in the console)
  * Resources created before IaC was adopted
  * Resources outside IaC entirely (CloudFormation, hand-rolled
    boto3 scripts, Pulumi, Crossplane)

IaC scanning catches none of these. CSPM does.

Cloud coverage (v1 — AWS only):
  * `strix.cspm.aws` — read-only scan against an AWS account
    using the caller's credential chain (env, profile, role).

GCP + Azure follow in separate modules / PRs. Each cloud has
its own SDK + auth model; mashing them into one abstraction
layer is the wrong call for v1.

## Output shape

Each check emits zero or more `CspmFinding` records that mirror
`IacFinding` so the existing compliance enrichment pipeline
(`strix.compliance.mappings.RULE_ID_TO_CONTROLS`) picks up the
CIS AWS Foundations control mappings automatically.

## Safety contract

ZERO mutating API calls. CSPM is `Describe*` / `Get*` / `List*`
only. No tag updates, no policy patches, no "auto-remediation"
in v1 — too many failure modes (locked-out admins, billing
surprises). The wrapper surfaces remediation steps; humans apply
them.
"""

from __future__ import annotations
