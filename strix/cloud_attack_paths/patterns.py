"""Attack-path patterns — graph queries that chain individual
findings into red-team scenarios.

A pattern is a function `(graph) -> list[AttackPath]`. Each
returned `AttackPath` describes a multi-hop subgraph that
constitutes an actionable threat narrative — the kind of thing
a red-teamer would write up in a report and a CISO would prioritise
over the underlying single findings.

Why this matters: Wiz's enterprise differentiation isn't its 1500
checks, it's the graph traversal that turns "S3 public" + "RDS
public" + "IAM wildcard" into ONE finding called "attacker chains
public bucket → terraform state → IAM keys → admin." The price
floor on that capability is ~$50k/yr today. This module gives the
same shape at SMB scale.

## Naming convention

Pattern IDs follow `cap_*` (Cloud Attack Path). Each gets a stable
ID, severity, MITRE technique mapping, and human-readable
narrative.

## Adding a pattern

  1. Add a `_pattern_<name>` function returning `list[AttackPath]`.
  2. Register it in `BUILTIN_PATTERNS` with a stable `pattern_id`.
  3. Add tests in `tests/cloud_attack_paths/test_patterns.py`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_ATTACHED_TO,
    EDGE_CAN_ASSUME,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_GRANTS_ACCESS_TO,
    EDGE_HAS_POLICY,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AttackPath shape
# ---------------------------------------------------------------------------


@dataclass
class AttackPath:
    """A multi-hop attack scenario derived from the graph.

    `hops` is the ordered list of node-keys an attacker traverses;
    `evidence_edges` is the edge-type list that connects them.
    `narrative` is the human-readable description rendered in
    auditor / wrapper output.
    """
    pattern_id: str
    title: str
    severity: str            # critical | high | medium | low
    narrative: str
    hops: list[str]
    evidence_edges: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    remediation: str = ""
    confidence: float = 0.85
    # Reachability score [0.0, 1.0] populated by
    # `apply_reachability_to_paths` after pattern detection. 0.0
    # is the no-reachability-computed default; the value is also
    # mirrored on `metadata.reachability_score` for JSON-safe
    # consumption by wrappers.
    reachability_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "title": self.title,
            "severity": self.severity,
            "narrative": self.narrative,
            "hops": list(self.hops),
            "evidence_edges": list(self.evidence_edges),
            "mitre_techniques": list(self.mitre_techniques),
            "remediation": self.remediation,
            "confidence": self.confidence,
            "reachability_score": self.reachability_score,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# Built-in patterns
# ---------------------------------------------------------------------------


# Service kinds whose name conventionally signals secret material.
_CREDENTIALY_NAME_HINTS = (
    "tfstate", "terraform", "state", "secret", "credentials",
    "creds", "config", "env", ".env", "backup", "private",
)


def _resource_likely_holds_secrets(resource: CloudResource) -> bool:
    """Heuristic: does the resource's name / kind suggest sensitive
    content beyond the kind-based `is_data_store` classification?"""
    if resource.is_data_store:
        return True
    name = (resource.attributes.get("name") or resource.arn).lower()
    return any(hint in name for hint in _CREDENTIALY_NAME_HINTS)


# --------- Pattern 1: public storage potentially containing creds ---------


def _pattern_public_storage_credentials_risk(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Public S3 / Azure storage / GCS bucket that's also a data
    store — high probability of containing tfstate, creds, configs.
    Even without verifying contents, the combination justifies a
    critical finding.
    """
    storage_kinds = {
        "s3_bucket", "azure_storage_account", "gcp_storage_bucket",
    }
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind not in storage_kinds:
            continue
        if not _resource_likely_holds_secrets(r):
            continue
        out.append(AttackPath(
            pattern_id="cap_public_storage_credentials_risk",
            title=(
                f"Public storage resource may contain credentials: "
                f"`{r.arn}`"
            ),
            severity="critical",
            narrative=(
                f"Storage resource `{r.arn}` is exposed to the public "
                f"internet AND is classified as a data store / has a "
                f"sensitive-shaped name. Public storage buckets are "
                f"the #1 source of cloud credential leaks — they "
                f"commonly contain `terraform.tfstate` (raw IAM "
                f"keys), `.env` files, config dumps, or DB backups. "
                f"Once an attacker reads them, every credential "
                f"inside grants the access it was originally given."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1530", "T1552.001"],
            remediation=(
                "1. Block public access at the account + bucket "
                "level.\n"
                "2. Audit bucket contents for state files, env "
                "files, and credentials.\n"
                "3. Rotate any credential found inside as if it "
                "were leaked publicly — assume it was."
            ),
            confidence=0.9,
        ))
    return out


# --------- Pattern 2: internet-exposed compute with IAM role ---------


def _pattern_internet_exposed_compute_with_iam(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Compute resource reachable from the internet (open SG'd EC2,
    public Lambda URL, public Azure VM, public GCE) that ALSO has
    an IAM identity attached — an RCE on the compute resource
    becomes credential theft.
    """
    compute_kinds = {
        "ec2_instance", "lambda_function", "azure_vm",
        "gcp_compute_instance", "ecs_task", "eks_pod",
    }
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind not in compute_kinds:
            continue
        # Who's attached?
        attached_identities = graph.incoming(r.arn, EDGE_ATTACHED_TO)
        if not attached_identities:
            continue
        for ident_key in attached_identities:
            ident_node = graph.get_node(ident_key)
            if not isinstance(ident_node, CloudIdentity):
                continue
            severity = "high"
            # If the attached identity has a wildcard-admin policy,
            # bump to critical.
            policies = graph.outgoing(ident_key, EDGE_HAS_POLICY)
            wildcard = False
            for p_key in policies:
                p_node = graph.get_node(p_key) if p_key else None
                if isinstance(p_node, CloudPolicy) and p_node.has_wildcard_admin():
                    wildcard = True
                    break
            if wildcard:
                severity = "critical"
            out.append(AttackPath(
                pattern_id="cap_internet_exposed_compute_with_iam",
                title=(
                    f"Internet-exposed compute `{r.arn}` runs as IAM "
                    f"identity `{ident_node.arn}`"
                ),
                severity=severity,
                narrative=(
                    f"`{r.arn}` is reachable from the public internet "
                    f"AND has IAM identity `{ident_node.arn}` "
                    f"attached. An attacker who lands code execution "
                    f"on this resource (RCE in the app, SSRF to the "
                    f"metadata service, public-Lambda-URL exec) "
                    f"inherits every permission the IAM identity has. "
                    + (
                        f"That identity has a wildcard admin policy — "
                        f"this is a one-step path to full account "
                        f"compromise."
                        if wildcard else
                        f"Audit the identity's permission scope."
                    )
                ),
                hops=[r.arn, ident_node.arn],
                evidence_edges=[
                    EDGE_EXPOSED_TO_INTERNET, EDGE_ATTACHED_TO,
                ],
                mitre_techniques=["T1190", "T1078.004", "T1552.005"],
                remediation=(
                    "1. Restrict public exposure (remove world "
                    "ingress, disable Lambda function URL or add "
                    "auth, move RDS to private subnet).\n"
                    "2. Apply least-privilege to the attached IAM "
                    "identity — list every action the resource "
                    "actually needs, replace `*` with that set.\n"
                    "3. Add IMDSv2-required + hop-limit=1 for EC2 "
                    "so SSRF can't reach the metadata service."
                ),
                confidence=0.85,
                metadata={
                    "compute_kind": r.kind,
                    "identity_kind": ident_node.kind,
                    "wildcard_admin": wildcard,
                },
            ))
    return out


# --------- Pattern 3: wildcard admin attached to runtime ---------


def _pattern_wildcard_admin_attached(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Customer-managed IAM policy granting `Action:* + Resource:*`
    attached to ANY identity that runs in a compute context. The
    finding alone is bad; the path-with-attachment makes it
    critical because the blast radius is concrete.
    """
    out: list[AttackPath] = []
    for p in graph.nodes_by_type(CloudPolicy):
        if not isinstance(p, CloudPolicy) or not p.has_wildcard_admin():
            continue
        # Find identities that have this policy.
        identities = graph.incoming(p.arn, EDGE_HAS_POLICY)
        for ident_key in identities:
            ident = graph.get_node(ident_key)
            if not isinstance(ident, CloudIdentity):
                continue
            # Find compute resources where this identity is attached.
            attached_to = graph.outgoing(ident_key, EDGE_ATTACHED_TO)
            for compute_key in attached_to:
                if compute_key is None:
                    continue
                compute = graph.get_node(compute_key)
                if not isinstance(compute, CloudResource):
                    continue
                out.append(AttackPath(
                    pattern_id="cap_wildcard_admin_attached",
                    title=(
                        f"Wildcard admin policy `{p.arn}` attached "
                        f"to running compute `{compute.arn}`"
                    ),
                    severity="critical",
                    narrative=(
                        f"Policy `{p.arn}` grants `Action:* + "
                        f"Resource:*` (admin-equivalent) and is "
                        f"attached to identity `{ident.arn}` which "
                        f"is in turn attached to compute resource "
                        f"`{compute.arn}`. Any code execution path "
                        f"into the compute resource — application "
                        f"RCE, dependency compromise, hostile pull "
                        f"request — yields full account access."
                    ),
                    hops=[p.arn, ident.arn, compute.arn],
                    evidence_edges=[
                        EDGE_HAS_POLICY, EDGE_ATTACHED_TO,
                    ],
                    mitre_techniques=["T1078.004", "T1098.003"],
                    remediation=(
                        "Replace the wildcard policy with scoped "
                        "permissions. List the actual API calls the "
                        "workload makes and grant only those. Run "
                        "with the new policy in a non-prod account "
                        "first; if anything breaks the missing "
                        "permission tells you what to add — strictly "
                        "more secure than starting from `*` and "
                        "trimming."
                    ),
                    confidence=0.95,
                ))
    return out


# --------- Pattern 4: root account access keys + any public exposure ---------


def _pattern_root_unsafe(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Root account has access keys exist (CIS AWS 1.4) — at the
    account level this is a critical finding regardless of any
    other state. Returns ONE attack path per affected account."""
    out: list[AttackPath] = []
    for ident in graph.nodes_by_type(CloudIdentity):
        if not isinstance(ident, CloudIdentity):
            continue
        if ident.kind != "aws_root":
            continue
        if not ident.attributes.get("root_unsafe"):
            continue
        out.append(AttackPath(
            pattern_id="cap_root_unsafe",
            title=f"Root account with active credentials: `{ident.arn}`",
            severity="critical",
            narrative=(
                f"The AWS root account `{ident.arn}` has live access "
                f"keys (CIS AWS 1.4 violation). The root account "
                f"cannot be restricted by IAM policy — its credential "
                f"unlocks every action including billing + account-"
                f"closure. Leaked root keys = full account "
                f"compromise with no recovery path short of contacting "
                f"AWS support."
            ),
            hops=[ident.arn],
            evidence_edges=[],
            mitre_techniques=["T1078.004"],
            remediation=(
                "1. Delete root account access keys immediately.\n"
                "2. Enable hardware MFA on the root account.\n"
                "3. Stop using root for programmatic access — create "
                "a dedicated IAM user / role for whatever was using "
                "the root key."
            ),
            confidence=1.0,
        ))
    return out


# --------- Pattern 5: world-assumable role ---------


def _pattern_world_assumable_role(
    graph: CloudGraph,
) -> list[AttackPath]:
    """IAM role with `Principal: *` in its trust policy — anyone
    on the internet with a valid AWS account can assume it.
    Combined with any attached permission this is a critical
    misconfig.
    """
    out: list[AttackPath] = []
    for ident in graph.nodes_by_type(CloudIdentity):
        if not isinstance(ident, CloudIdentity):
            continue
        if not ident.is_world_assumable:
            continue
        # Get attached policies (if any) for blast-radius context.
        policies = graph.outgoing(ident.arn, EDGE_HAS_POLICY)
        admin = False
        for p_key in policies:
            p = graph.get_node(p_key) if p_key else None
            if isinstance(p, CloudPolicy) and p.has_wildcard_admin():
                admin = True
                break
        severity = "critical" if admin else "high"
        out.append(AttackPath(
            pattern_id="cap_world_assumable_role",
            title=f"Role `{ident.arn}` can be assumed by anyone",
            severity=severity,
            narrative=(
                f"IAM role `{ident.arn}` has a trust policy listing "
                f"`Principal: *` — any AWS account can call "
                f"`sts:AssumeRole` and obtain its permissions. "
                + (
                    f"The role has a wildcard-admin policy attached, "
                    f"so this is a one-step path to full account "
                    f"compromise from any external AWS account."
                    if admin else
                    f"Audit attached permissions; any of them are "
                    f"accessible to every AWS principal in the "
                    f"world."
                )
            ),
            hops=[ident.arn],
            evidence_edges=[],
            mitre_techniques=["T1078.004"],
            remediation=(
                "Restrict the trust policy: replace `Principal: *` "
                "with a specific account ID, federated provider, or "
                "AWS service principal. If external access is "
                "intentional, also require `sts:ExternalId` to make "
                "the confused-deputy attack infeasible."
            ),
            confidence=1.0,
            metadata={"has_admin_policy_attached": admin},
        ))
    return out


# ---------------------------------------------------------------------------
# Expanded pattern set (masterroadmap §5 P0 — 5 → 20+)
# ---------------------------------------------------------------------------


# Data-resource kinds: dedicated patterns for "public + data-bearing"
# beyond the storage-credential-risk pattern (which is storage-only).
_DATA_RESOURCE_KINDS = {
    "rds_db_instance", "rds_cluster",
    "dynamodb_table",
    "secrets_manager_secret",
    "azure_sql_server",
    "gcp_bigquery_dataset",
}


def _pattern_public_database(graph: CloudGraph) -> list[AttackPath]:
    """Public RDS / DynamoDB / Cloud SQL / BigQuery — direct data
    exposure. Critical regardless of attached IAM identities; the
    data itself is the asset.
    """
    db_kinds = {
        "rds_db_instance", "rds_cluster",
        "dynamodb_table", "azure_sql_server",
    }
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind not in db_kinds:
            continue
        out.append(AttackPath(
            pattern_id="cap_public_database",
            title=f"Database `{r.arn}` is publicly accessible",
            severity="critical",
            narrative=(
                f"{r.kind.replace('_', ' ').title()} `{r.arn}` is "
                f"reachable from the public internet. Any auth "
                f"weakness (weak password, default creds, "
                f"unpatched CVE in the DB engine) → direct data "
                f"theft. The internet is the largest brute-force "
                f"audience available; expect the resource to be "
                f"scanned within hours of going public."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1190", "T1530"],
            remediation=(
                "1. Move the database to a private subnet; expose "
                "only via VPC endpoints / bastion / VPN.\n"
                "2. If a public DB is intentional (rare), restrict "
                "the security group / firewall to known operator "
                "CIDRs only.\n"
                "3. Confirm encryption at rest is enabled; rotate "
                "any password that may have been brute-forced "
                "while public."
            ),
            confidence=0.95,
            metadata={"resource_kind": r.kind},
        ))
    return out


def _pattern_public_secrets_store(graph: CloudGraph) -> list[AttackPath]:
    """Public Secrets Manager secret / KMS key — by definition holds
    credentials or encryption keys. Public access here is end-game:
    the attacker reads secrets directly.
    """
    secret_kinds = {"secrets_manager_secret", "kms_key"}
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind not in secret_kinds:
            continue
        out.append(AttackPath(
            pattern_id="cap_public_secrets_store",
            title=f"Secrets / KMS resource `{r.arn}` is publicly accessible",
            severity="critical",
            narrative=(
                f"`{r.arn}` ({r.kind}) holds credentials or "
                f"encryption keys AND is exposed to the public "
                f"internet. Resource policies that grant "
                f"`Principal: *` on AWS Secrets Manager / KMS "
                f"are catastrophic — anonymous callers can read "
                f"the secret material or use the key to decrypt "
                f"any ciphertext encrypted to it."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1552", "T1555.006"],
            remediation=(
                "Replace the resource policy with explicit "
                "account-scoped principals only. Secrets / KMS "
                "policies should never include `Principal: *` "
                "(even with conditions, the residual risk of "
                "condition-bypass classes makes wildcard "
                "indefensible)."
            ),
            confidence=1.0,
            metadata={"resource_kind": r.kind},
        ))
    return out


def _pattern_public_ecr_repository(graph: CloudGraph) -> list[AttackPath]:
    """Public ECR repository — supply-chain risk class. If your
    organisation publishes images to a public ECR repo, an attacker
    can:
      * Read the image to find embedded secrets / vulnerable
        dependencies.
      * Detect the image-pull endpoint for your private workloads.
    """
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind != "ecr_repository":
            continue
        out.append(AttackPath(
            pattern_id="cap_public_ecr_repository",
            title=f"ECR repository `{r.arn}` is publicly readable",
            severity="high",
            narrative=(
                f"ECR repository `{r.arn}` allows anonymous pull. "
                f"Production container images frequently leak: "
                f"hard-coded credentials in layer history, "
                f"private build URLs, dependency lockfiles, "
                f"internal hostnames. Treat any image that's been "
                f"public as if its credentials are leaked — "
                f"audit + rotate."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1213.003", "T1525"],
            remediation=(
                "1. Set repository policy to restrict pull to "
                "specific account IDs / cross-account roles.\n"
                "2. Scan all images that have been public for "
                "credentials with `trivy fs` + secrets-scan.\n"
                "3. Rotate any credential found inside as if it "
                "were leaked publicly — assume it was."
            ),
            confidence=0.9,
        ))
    return out


def _pattern_admin_policy_attached_to_iam_user(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Wildcard admin policy attached directly to an IAM USER
    (not a role). Users are typically humans with long-lived
    credentials — attaching admin to a user creates a single
    credential whose compromise is full account takeover, with
    no time-bound STS rotation in the way.
    """
    out: list[AttackPath] = []
    for p in graph.nodes_by_type(CloudPolicy):
        if not isinstance(p, CloudPolicy) or not p.has_wildcard_admin():
            continue
        # Identities that have this policy.
        for ident_key in graph.incoming(p.arn, EDGE_HAS_POLICY):
            ident = graph.get_node(ident_key)
            if not isinstance(ident, CloudIdentity):
                continue
            if ident.kind != "iam_user":
                continue
            out.append(AttackPath(
                pattern_id="cap_admin_policy_attached_to_iam_user",
                title=(
                    f"Wildcard admin policy `{p.arn}` attached to "
                    f"IAM user `{ident.arn}`"
                ),
                severity="critical",
                narrative=(
                    f"IAM user `{ident.arn}` has `{p.arn}` "
                    f"attached, which grants `Action:* + Resource:*` "
                    f"(admin-equivalent). Compromise of this single "
                    f"long-lived credential is full-account "
                    f"takeover. Users should never be granted "
                    f"admin directly — assign through a role with "
                    f"required MFA + session duration."
                ),
                hops=[p.arn, ident.arn],
                evidence_edges=[EDGE_HAS_POLICY],
                mitre_techniques=["T1078.004", "T1098.003"],
                remediation=(
                    "1. Detach the wildcard policy from the user.\n"
                    "2. Create a scoped role with only the "
                    "permissions the user actually needs.\n"
                    "3. If admin access is genuinely required, "
                    "create a separate `Admin` role with MFA-"
                    "required trust policy + short session "
                    "duration; have the user assume it on demand."
                ),
                confidence=1.0,
            ))
    return out


def _pattern_external_trust_without_external_id(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Role trust policy allows assumption from an external AWS
    account WITHOUT requiring `sts:ExternalId` — classic confused-
    deputy primitive. Anyone with the role ARN AND in that
    external account can assume the role.

    Detection: identity has `trust_principals` containing an
    external account ARN AND `attributes.external_trust_no_external_id`
    is set (ingester signal). Falls back to flagging based on
    trust_principals + missing external_id_required hint.
    """
    out: list[AttackPath] = []
    for ident in graph.nodes_by_type(CloudIdentity):
        if not isinstance(ident, CloudIdentity):
            continue
        if ident.kind != "iam_role":
            continue
        # World-assumable handled by the existing pattern.
        if ident.is_world_assumable:
            continue
        # Look for external-account principal (different account
        # ARN), absent ExternalId hint.
        has_external_account = False
        for tp in ident.trust_principals:
            tp_s = str(tp).strip()
            if tp_s.startswith("arn:aws:iam::"):
                # Extract account from the principal ARN.
                parts = tp_s.split(":")
                if len(parts) >= 5 and parts[4] and parts[4] != "":
                    # Compare against the role's own account.
                    role_parts = (ident.arn or "").split(":")
                    role_account = (
                        role_parts[4] if len(role_parts) >= 5 else ""
                    )
                    if parts[4] != role_account:
                        has_external_account = True
                        break
        if not has_external_account:
            continue
        # Ingester / asset enrichment flags `external_id_required`
        # when the trust policy includes a `sts:ExternalId`
        # condition. Absence is the confused-deputy primitive.
        if ident.attributes.get("external_id_required"):
            continue
        out.append(AttackPath(
            pattern_id="cap_external_trust_without_external_id",
            title=(
                f"Role `{ident.arn}` trusts external account "
                f"without ExternalId"
            ),
            severity="high",
            narrative=(
                f"Role `{ident.arn}` allows assumption from an "
                f"external AWS account AND does NOT require "
                f"`sts:ExternalId` in the assume-role call. This "
                f"is the canonical confused-deputy primitive — "
                f"any IAM principal in the trusted external "
                f"account can assume the role, even ones the "
                f"target account doesn't intend to grant access "
                f"to. If the external account is ever "
                f"compromised, or runs an untrusted workload, "
                f"that workload inherits this role."
            ),
            hops=[ident.arn],
            mitre_techniques=["T1078.004"],
            remediation=(
                "Add a `sts:ExternalId` condition to the trust "
                "policy: only the operator who knows the "
                "ExternalId can assume the role. AWS documents "
                "this as a hard requirement for third-party "
                "vendor cross-account roles."
            ),
            confidence=0.95,
        ))
    return out


def _pattern_pass_role_present(graph: CloudGraph) -> list[AttackPath]:
    """Any IAM policy that grants `iam:PassRole` is a privilege-
    escalation primitive when combined with `iam:CreateInstance`-
    style actions. We flag every identity that has the action
    granted; the agent's MOAK follow-up checks whether a
    higher-privilege role is also passable.
    """
    out: list[AttackPath] = []
    for p in graph.nodes_by_type(CloudPolicy):
        if not isinstance(p, CloudPolicy):
            continue
        has_pass_role = False
        for stmt in p.statements:
            if (stmt.get("effect") or "").lower() != "allow":
                continue
            actions = stmt.get("actions") or []
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                a_s = str(a).strip().lower()
                if a_s == "iam:passrole" or a_s == "*" or a_s == "iam:*":
                    has_pass_role = True
                    break
            if has_pass_role:
                break
        if not has_pass_role:
            continue
        for ident_key in graph.incoming(p.arn, EDGE_HAS_POLICY):
            ident = graph.get_node(ident_key)
            if not isinstance(ident, CloudIdentity):
                continue
            out.append(AttackPath(
                pattern_id="cap_pass_role_present",
                title=(
                    f"Identity `{ident.arn}` has `iam:PassRole` "
                    f"via `{p.arn}` — privilege-escalation primitive"
                ),
                severity="high",
                narrative=(
                    f"`{ident.arn}` can call `iam:PassRole`. "
                    f"Paired with any of the EC2 / Lambda / ECS / "
                    f"Glue / SageMaker create-resource APIs, the "
                    f"identity can attach a HIGHER-privileged "
                    f"role to a resource they control — "
                    f"effectively assuming that role. Real-world "
                    f"escalation chain: PassRole + RunInstances "
                    f"(attach Admin role to a new EC2) → SSH in "
                    f"→ pull credentials from IMDS → admin."
                ),
                hops=[p.arn, ident.arn],
                evidence_edges=[EDGE_HAS_POLICY],
                mitre_techniques=["T1078.004", "T1098.003"],
                remediation=(
                    "Restrict `iam:PassRole` to specific role "
                    "ARNs only via the `Resource` field. Never "
                    "grant `iam:PassRole` with `Resource: *`. If "
                    "the identity legitimately needs to pass "
                    "multiple roles, enumerate them — wildcard "
                    "passing is a frequent escalation vector."
                ),
                confidence=0.85,
            ))
    return out


def _pattern_can_assume_chain_to_admin(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Multi-hop role-assumption chain: identity → can_assume →
    role → can_assume → admin role. Each hop is a legitimate
    cross-team role pattern; the chain is the escalation
    primitive.

    Depth-2 chains only in v1 (A → B → admin). Deeper traversals
    are a follow-up.
    """
    out: list[AttackPath] = []
    # Identify "admin" identities — those with a wildcard-admin
    # policy attached.
    admin_idents: set[str] = set()
    for p in graph.nodes_by_type(CloudPolicy):
        if not isinstance(p, CloudPolicy) or not p.has_wildcard_admin():
            continue
        for ident_key in graph.incoming(p.arn, EDGE_HAS_POLICY):
            admin_idents.add(ident_key)

    # For each identity, BFS along can_assume edges (depth 2).
    for ident in graph.nodes_by_type(CloudIdentity):
        if not isinstance(ident, CloudIdentity):
            continue
        if ident.arn in admin_idents:
            continue  # already admin; chain to self isn't a finding
        # Depth-1 hops.
        d1_targets = graph.outgoing(ident.arn, EDGE_CAN_ASSUME)
        for d1 in d1_targets:
            if d1 is None:
                continue
            if d1 in admin_idents:
                out.append(AttackPath(
                    pattern_id="cap_can_assume_chain_to_admin",
                    title=(
                        f"`{ident.arn}` can assume admin via `{d1}` "
                        f"(1-hop)"
                    ),
                    severity="critical",
                    narrative=(
                        f"Identity `{ident.arn}` has assume-role "
                        f"permission on `{d1}`, which itself has "
                        f"a wildcard-admin policy. Compromise of "
                        f"`{ident.arn}` → AssumeRole → full account."
                    ),
                    hops=[ident.arn, d1],
                    evidence_edges=[EDGE_CAN_ASSUME],
                    mitre_techniques=["T1078.004"],
                    remediation=(
                        "Either revoke the assume-role permission "
                        "or remove the wildcard admin on the "
                        "destination role. Use scoped permissions "
                        "+ require MFA on the role-assumption."
                    ),
                    confidence=0.95,
                ))
                continue
            # Depth-2: d1 → d2 → admin
            for d2 in graph.outgoing(d1, EDGE_CAN_ASSUME):
                if d2 is None or d2 in (ident.arn, d1):
                    continue
                if d2 in admin_idents:
                    out.append(AttackPath(
                        pattern_id="cap_can_assume_chain_to_admin",
                        title=(
                            f"`{ident.arn}` can assume admin via "
                            f"`{d1}` → `{d2}` (2-hop)"
                        ),
                        severity="critical",
                        narrative=(
                            f"Identity `{ident.arn}` can chain "
                            f"assume-role through `{d1}` to `{d2}`, "
                            f"which has wildcard-admin. The chain "
                            f"obscures the escalation path from "
                            f"casual audit; the impact is the same "
                            f"as direct admin access."
                        ),
                        hops=[ident.arn, d1, d2],
                        evidence_edges=[
                            EDGE_CAN_ASSUME, EDGE_CAN_ASSUME,
                        ],
                        mitre_techniques=["T1078.004"],
                        remediation=(
                            "Audit the role chain. At least one "
                            "of the hops should either (a) require "
                            "MFA + short session duration, or "
                            "(b) not exist at all. Document the "
                            "chain in your IAM-graph review."
                        ),
                        confidence=0.95,
                    ))
    return out


def _pattern_admin_attached_to_compute_with_internet(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Refinement of `cap_wildcard_admin_attached`: SAME chain
    but the compute resource also has `exposed_to_internet`. This
    is the strongest 4-hop attack-path narrative — the path is
    reachable from the outside without any auth bypass needed.
    """
    out: list[AttackPath] = []
    for p in graph.nodes_by_type(CloudPolicy):
        if not isinstance(p, CloudPolicy) or not p.has_wildcard_admin():
            continue
        for ident_key in graph.incoming(p.arn, EDGE_HAS_POLICY):
            ident = graph.get_node(ident_key)
            if not isinstance(ident, CloudIdentity):
                continue
            for compute_key in graph.outgoing(ident_key, EDGE_ATTACHED_TO):
                if compute_key is None:
                    continue
                compute = graph.get_node(compute_key)
                if not isinstance(compute, CloudResource):
                    continue
                if not graph.is_internet_exposed(compute_key):
                    continue
                out.append(AttackPath(
                    pattern_id="cap_admin_attached_to_compute_with_internet",
                    title=(
                        f"Internet-exposed compute `{compute.arn}` "
                        f"runs as admin-equivalent identity"
                    ),
                    severity="critical",
                    narrative=(
                        f"Compute resource `{compute.arn}` is "
                        f"reachable from the public internet AND "
                        f"has IAM identity `{ident.arn}` attached "
                        f"AND that identity carries wildcard-admin "
                        f"policy `{p.arn}`. This is the canonical "
                        f"4-hop full-compromise path: any code-"
                        f"execution primitive on the public-facing "
                        f"compute (RCE in the app, SSRF to metadata "
                        f"service, public Lambda URL exec, "
                        f"dependency compromise) directly yields "
                        f"account-wide admin. Fix priority: "
                        f"absolute highest."
                    ),
                    hops=[
                        compute.arn, ident.arn, p.arn,
                    ],
                    evidence_edges=[
                        EDGE_EXPOSED_TO_INTERNET,
                        EDGE_ATTACHED_TO,
                        EDGE_HAS_POLICY,
                    ],
                    mitre_techniques=[
                        "T1190", "T1078.004",
                        "T1552.005", "T1098.003",
                    ],
                    remediation=(
                        "Multiple fixes; do all three:\n"
                        "1. Restrict public exposure (remove world "
                        "ingress / disable Lambda function URL / "
                        "move to private subnet).\n"
                        "2. Strip the wildcard admin policy — "
                        "enumerate the actual permissions needed.\n"
                        "3. For EC2, require IMDSv2 + hop-limit=1 "
                        "to defang SSRF-to-IMDS chains."
                    ),
                    confidence=0.99,
                    metadata={
                        "compute_kind": compute.kind,
                    },
                ))
    return out


# ---------------------------------------------------------------------------
# Multi-cloud patterns (GCP + Azure) — masterroadmap §5 P1
# ---------------------------------------------------------------------------


def _pattern_gcp_default_compute_sa_with_internet(
    graph: CloudGraph,
) -> list[AttackPath]:
    """GCE VM running as the Compute Engine **default service
    account** with the `cloud-platform` scope, exposed to the
    public internet. Privilege-escalation primitive specific to
    GCP: the default SA has `Editor` role across the project by
    default, and `cloud-platform` scope grants it access to
    every Cloud API.

    Detection: `kind=gcp_compute_instance` + `is_public=True` +
    `attributes['default_service_account']=True` (caller-supplied
    via `cloud_assets`).
    """
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind != "gcp_compute_instance":
            continue
        if not r.attributes.get("default_service_account"):
            continue
        scopes = r.attributes.get("scopes") or []
        has_full_scope = any(
            "cloud-platform" in str(s) for s in scopes
        )
        if not has_full_scope:
            # Default SA is still a problem but `cloud-platform`
            # scope is the escalation primitive that makes this
            # critical. Without it, severity stays high.
            severity = "high"
        else:
            severity = "critical"
        out.append(AttackPath(
            pattern_id="cap_gcp_default_compute_sa_with_internet",
            title=(
                f"Public GCE VM `{r.arn}` runs as default Compute "
                f"Engine SA"
                + (" with cloud-platform scope" if has_full_scope else "")
            ),
            severity=severity,
            narrative=(
                f"`{r.arn}` is reachable from the public internet "
                f"AND runs under the Compute Engine **default** "
                f"service account "
                + (
                    f"with the `cloud-platform` access scope. The "
                    f"default SA has `Editor` at the project "
                    f"level by default; combined with `cloud-"
                    f"platform`, RCE on the VM yields full "
                    f"project access via the metadata service "
                    f"(`http://metadata.google.internal/computeMetadata"
                    f"/v1/instance/service-accounts/default/token`)."
                    if has_full_scope else
                    f". The default SA has `Editor` role at the "
                    f"project level — RCE on the VM yields wide "
                    f"project access via the metadata service."
                )
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1190", "T1078.004", "T1552.005"],
            remediation=(
                "1. Attach a dedicated service account to the VM "
                "with only the permissions it actually needs.\n"
                "2. Restrict scopes — for most workloads, the "
                "`cloud-platform` scope is far too broad.\n"
                "3. Disable the default SA at the project level "
                "via `gcloud iam service-accounts disable "
                "<default-sa-email>` once no VM uses it.\n"
                "4. Block metadata-service access from inside the "
                "VM for non-system processes (kernel-level "
                "iptables rule on 169.254.169.254)."
            ),
            confidence=0.95,
            metadata={
                "compute_kind": r.kind,
                "has_cloud_platform_scope": has_full_scope,
            },
        ))
    return out


def _pattern_gcp_public_bigquery_dataset(
    graph: CloudGraph,
) -> list[AttackPath]:
    """BigQuery dataset with `allUsers` / `allAuthenticatedUsers`
    IAM binding. Critical: BigQuery datasets routinely store
    analytics data with PII / customer records.

    Distinct from `cap_public_database` (which fires on the kind
    alone) because BigQuery's public binding semantics are
    IAM-binding-based, not subnet / firewall-based — calling it
    out separately gives the operator the right remediation."""
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind != "gcp_bigquery_dataset":
            continue
        out.append(AttackPath(
            pattern_id="cap_gcp_public_bigquery_dataset",
            title=(
                f"BigQuery dataset `{r.arn}` allows anonymous "
                f"access"
            ),
            severity="critical",
            narrative=(
                f"BigQuery dataset `{r.arn}` has an IAM binding "
                f"with `allUsers` or `allAuthenticatedUsers` — "
                f"any Google account holder (or any anonymous "
                f"requester, in the `allUsers` case) can run "
                f"queries against the dataset. BigQuery datasets "
                f"are routinely populated by analytics pipelines "
                f"with PII, customer records, and aggregated "
                f"behavioural data."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1530", "T1213"],
            remediation=(
                "1. Remove the `allUsers` / "
                "`allAuthenticatedUsers` binding via:\n"
                "   `bq update --source <iam-json> "
                "<project>:<dataset>`\n"
                "2. Use explicit IAM bindings per group / user; "
                "BigQuery supports table-level + row-level "
                "policies for fine-grained sharing.\n"
                "3. Enable Cloud Audit Logs > Data Access for "
                "BigQuery so future public reads are auditable."
            ),
            confidence=1.0,
        ))
    return out


def _pattern_azure_storage_public_blob(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Azure storage account with `allowBlobPublicAccess=true`
    AND at least one container with public access level. The
    Azure-specific narrative — different remediation from AWS
    S3 (storage-account-level toggle vs. bucket-level ACL).
    """
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind != "azure_storage_account":
            continue
        out.append(AttackPath(
            pattern_id="cap_azure_storage_public_blob",
            title=(
                f"Azure storage account `{r.arn}` allows "
                f"public blob access"
            ),
            severity="critical",
            narrative=(
                f"Azure storage account `{r.arn}` has "
                f"`allowBlobPublicAccess=true` AND at least one "
                f"container is configured with public access. "
                f"Anonymous callers can list / read blobs in the "
                f"affected containers — the canonical Azure data-"
                f"leak primitive (parallel to S3 public ACL). "
                f"Common contents: backup files, log exports, "
                f"build artifacts, terraform state."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1530", "T1213"],
            remediation=(
                "1. Disable account-level public blob access: "
                "`az storage account update --name <name> "
                "--resource-group <rg> --allow-blob-public-access "
                "false`.\n"
                "2. Audit every container and set "
                "`--public-access off` on any that don't need "
                "anonymous reads (most don't).\n"
                "3. For containers that legitimately need public "
                "access (CDN-fronted static assets), use a CDN "
                "with token-based auth instead of raw container "
                "public access."
            ),
            confidence=0.95,
        ))
    return out


def _pattern_azure_owner_role_user(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Azure user / service principal with the `Owner` role
    assigned at a wide scope (subscription or above). Azure RBAC
    equivalent of attaching wildcard admin to an IAM user —
    long-lived credential whose compromise is full-subscription
    takeover.

    Detection: identity kind contains `azure_` AND
    `attributes['azure_roles']` contains 'Owner' AND
    `attributes['azure_scope']` is subscription-level or
    management-group-level (not narrowly resource-scoped).
    """
    out: list[AttackPath] = []
    for ident in graph.nodes_by_type(CloudIdentity):
        if not isinstance(ident, CloudIdentity):
            continue
        kind = (ident.kind or "").lower()
        if not kind.startswith("azure_") and kind != "azure_user":
            continue
        roles = ident.attributes.get("azure_roles") or []
        if not any(
            str(r).lower() == "owner" for r in roles
        ):
            continue
        scope = (ident.attributes.get("azure_scope") or "").lower()
        # Wide scope = empty (assume worst case) OR subscription-
        # only OR management-group-only. Resource-group or
        # resource-specific scope is NARROW — those are fine.
        # Management group check FIRST because that path also
        # contains `/providers/Microsoft.Management/...`.
        if not scope:
            is_wide_scope = True
        elif "/managementgroups/" in scope:
            is_wide_scope = True
        elif "/resourcegroups/" in scope or "/providers/" in scope:
            # Anything below subscription is narrow (except
            # managementGroups handled above).
            is_wide_scope = False
        elif "/subscriptions/" in scope:
            # Pure subscription scope.
            is_wide_scope = True
        else:
            is_wide_scope = False
        if not is_wide_scope:
            continue
        out.append(AttackPath(
            pattern_id="cap_azure_owner_role_user",
            title=(
                f"Azure identity `{ident.arn}` has Owner role "
                f"at subscription scope"
            ),
            severity="critical",
            narrative=(
                f"`{ident.arn}` ({ident.kind}) has the **Owner** "
                f"role assigned at subscription scope. Owner is "
                f"the highest Azure RBAC role — full control "
                f"over every resource in scope, plus the ability "
                f"to delegate access to others. Compromise of "
                f"this principal = full subscription takeover. "
                f"Long-lived credentials (especially service "
                f"principals with non-rotating secrets) are the "
                f"primary risk."
            ),
            hops=[ident.arn],
            mitre_techniques=["T1078.004", "T1098.003"],
            remediation=(
                "1. Replace Owner with the narrowest role that "
                "fits the principal's actual job — Contributor + "
                "User Access Administrator separately when both "
                "are needed.\n"
                "2. Scope role assignments at the resource-group "
                "level instead of subscription level wherever "
                "possible.\n"
                "3. For service principals, rotate the client "
                "secret quarterly + require Federated Credentials "
                "(workload identity) where the workload supports "
                "it."
            ),
            confidence=0.95,
            metadata={
                "identity_kind": ident.kind,
                "scope": scope or "(unknown — assumed wide)",
            },
        ))
    return out


def _pattern_gcp_service_account_owner_role(
    graph: CloudGraph,
) -> list[AttackPath]:
    """GCP service account granted `roles/owner` at the project
    level. The GCP equivalent of Azure Owner role / AWS wildcard
    admin on a user — service accounts are long-lived
    credentials AND grant unlimited project access.

    Detection: identity kind contains `gcp_` AND
    `attributes['gcp_roles']` contains `roles/owner` or
    `roles/editor`.
    """
    out: list[AttackPath] = []
    for ident in graph.nodes_by_type(CloudIdentity):
        if not isinstance(ident, CloudIdentity):
            continue
        kind = (ident.kind or "").lower()
        if not kind.startswith("gcp_"):
            continue
        roles = ident.attributes.get("gcp_roles") or []
        has_owner = any(
            str(r).lower() in ("roles/owner", "roles/editor")
            for r in roles
        )
        if not has_owner:
            continue
        out.append(AttackPath(
            pattern_id="cap_gcp_service_account_owner_role",
            title=(
                f"GCP service account `{ident.arn}` has "
                f"roles/owner or roles/editor"
            ),
            severity="critical",
            narrative=(
                f"GCP service account `{ident.arn}` is granted "
                f"`roles/owner` or `roles/editor` at the project "
                f"level. Both roles grant unlimited project "
                f"access. Service accounts attached to GCE VMs / "
                f"Cloud Run / GKE workloads inherit this access; "
                f"any compromise of those workloads = full "
                f"project takeover. The GCP IAM model conflates "
                f"resource owner with platform-level operator — "
                f"basic roles should never be used in production."
            ),
            hops=[ident.arn],
            mitre_techniques=["T1078.004"],
            remediation=(
                "1. Replace basic role (`roles/owner` / "
                "`roles/editor`) with the predefined / custom "
                "roles the workload actually needs. GCP's "
                "predefined roles are surgical; basic roles "
                "are deliberately broad.\n"
                "2. For workload SAs, prefer **Workload Identity "
                "Federation** over long-lived JSON keys — "
                "ephemeral credentials drastically reduce blast "
                "radius.\n"
                "3. Audit `gcloud projects get-iam-policy` "
                "regularly; alert on any basic-role binding."
            ),
            confidence=0.95,
            metadata={"identity_kind": ident.kind, "roles": list(roles)},
        ))
    return out


def _pattern_internet_resource_unencrypted(
    graph: CloudGraph,
) -> list[AttackPath]:
    """Public resource that also lacks encryption-at-rest. Each
    finding is its own CSPM hit but the combination is the actual
    breach narrative — data is reachable AND clear-text on disk
    means any snapshot/backup leak is a direct data leak too.
    """
    data_kinds = _DATA_RESOURCE_KINDS
    out: list[AttackPath] = []
    for r in graph.public_resources():
        if r.kind not in data_kinds:
            continue
        # `unencrypted` attribute is set by the ingester when a
        # `*_NO_ENCRYPTION` rule fires for the resource. We don't
        # yet propagate that flag; this pattern lights up when the
        # caller's `cloud_assets` enriches with `is_unencrypted`.
        if not r.attributes.get("is_unencrypted"):
            continue
        out.append(AttackPath(
            pattern_id="cap_internet_resource_unencrypted",
            title=(
                f"Public + unencrypted data resource `{r.arn}`"
            ),
            severity="critical",
            narrative=(
                f"`{r.arn}` ({r.kind}) is BOTH publicly reachable "
                f"AND lacks encryption at rest. Any auth weakness "
                f"yields plaintext data; any snapshot exfil yields "
                f"plaintext data; any DR backup that ends up in "
                f"the wrong S3 bucket yields plaintext data. Fix "
                f"both controls — they're independent defences."
            ),
            hops=[r.arn],
            evidence_edges=[EDGE_EXPOSED_TO_INTERNET],
            mitre_techniques=["T1190", "T1530", "T1486"],
            remediation=(
                "1. Restrict public exposure (private subnet / "
                "firewall to operator CIDRs).\n"
                "2. Enable encryption at rest (snapshot the "
                "current data, restore into an encrypted copy, "
                "switch endpoints, delete the unencrypted "
                "original)."
            ),
            confidence=0.95,
        ))
    return out


# ---------------------------------------------------------------------------
# Registry + entry point
# ---------------------------------------------------------------------------


PatternFn = Callable[[CloudGraph], list[AttackPath]]


# Registered patterns. Order doesn't matter — output is just
# unioned. Counts: 13 patterns in v2 (was 5 in v1 — masterroadmap
# §5 P0 expansion).
BUILTIN_PATTERNS: dict[str, PatternFn] = {
    # v1 patterns (PR #293).
    "cap_public_storage_credentials_risk": _pattern_public_storage_credentials_risk,
    "cap_internet_exposed_compute_with_iam": _pattern_internet_exposed_compute_with_iam,
    "cap_wildcard_admin_attached": _pattern_wildcard_admin_attached,
    "cap_root_unsafe": _pattern_root_unsafe,
    "cap_world_assumable_role": _pattern_world_assumable_role,
    # v2 expansion (this PR).
    "cap_public_database": _pattern_public_database,
    "cap_public_secrets_store": _pattern_public_secrets_store,
    "cap_public_ecr_repository": _pattern_public_ecr_repository,
    "cap_admin_policy_attached_to_iam_user":
        _pattern_admin_policy_attached_to_iam_user,
    "cap_external_trust_without_external_id":
        _pattern_external_trust_without_external_id,
    "cap_pass_role_present": _pattern_pass_role_present,
    "cap_can_assume_chain_to_admin":
        _pattern_can_assume_chain_to_admin,
    "cap_admin_attached_to_compute_with_internet":
        _pattern_admin_attached_to_compute_with_internet,
    "cap_internet_resource_unencrypted":
        _pattern_internet_resource_unencrypted,
    # v3 expansion — multi-cloud (GCP + Azure) patterns.
    "cap_gcp_default_compute_sa_with_internet":
        _pattern_gcp_default_compute_sa_with_internet,
    "cap_gcp_public_bigquery_dataset":
        _pattern_gcp_public_bigquery_dataset,
    "cap_gcp_service_account_owner_role":
        _pattern_gcp_service_account_owner_role,
    "cap_azure_storage_public_blob":
        _pattern_azure_storage_public_blob,
    "cap_azure_owner_role_user":
        _pattern_azure_owner_role_user,
}


def find_attack_paths(
    graph: CloudGraph,
    *,
    patterns: list[str] | None = None,
    custom_patterns: dict[str, PatternFn] | None = None,
) -> list[AttackPath]:
    """Run pattern matchers against a graph + return the union.

    Args:
        graph: ingested `CloudGraph`.
        patterns: optional allow-list of pattern IDs to run; None
            runs every registered pattern.
        custom_patterns: extra pattern functions to evaluate
            alongside the built-ins. Wrapper integrations can
            register org-specific patterns without forking strix.

    Returns:
        List of AttackPath, sorted critical-first.
    """
    active: dict[str, PatternFn] = {**BUILTIN_PATTERNS}
    if custom_patterns:
        active.update(custom_patterns)
    if patterns:
        allowed = set(patterns)
        active = {k: v for k, v in active.items() if k in allowed}

    out: list[AttackPath] = []
    for pid, fn in active.items():
        try:
            paths = fn(graph)
            if paths:
                out.extend(paths)
        except Exception as e:  # noqa: BLE001
            logger.warning("attack-path pattern %s failed: %s",
                           pid, e, exc_info=True)

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out.sort(
        key=lambda p: -sev_rank.get((p.severity or "").lower(), 0),
    )
    return out
