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

Engine strategy:

  * **Prowler** (primary) — Apache 2.0, multi-cloud (AWS / Azure
    / GCP / K8s), 500+ checks, CIS / SOC 2 / PCI / NIST mappings
    built in. Wrapped via `strix.cspm.prowler`. This is the
    default when `prowler` is on $PATH.

  * **Built-in boto3 fallback** (`strix.cspm.aws`) — pure-Python,
    AWS-only, 14 checks. Used when Prowler isn't installed
    (air-gapped envs, minimal-install CI). Same `CspmFinding`
    shape and same compliance-mapping pipeline; the
    `scan_cloud_account` dispatcher selects automatically.

The unified specialist `scan_cloud_account` (in `strix.cspm.tools`)
is the public entry point. The legacy `scan_aws_account_tool` in
`strix.cspm.aws.tools` is retained as the explicit boto3-only
path — useful when you want the hermetic-testable check set
regardless of Prowler availability.

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

# Side-effect imports — register specialist tools so the agent
# tool registry picks them up by `import strix.cspm`. The unified
# `scan_cloud_account` is the primary entry point; the AWS-only
# `scan_aws_account_tool` stays available as the explicit
# boto3-direct path.
from strix.cspm import tools as _tools_unified  # noqa: E402, F401
from strix.cspm.aws import tools as _tools_aws  # noqa: E402, F401
