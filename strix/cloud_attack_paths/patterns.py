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
# Registry + entry point
# ---------------------------------------------------------------------------


PatternFn = Callable[[CloudGraph], list[AttackPath]]


# Registered patterns. Order doesn't matter — output is just
# unioned.
BUILTIN_PATTERNS: dict[str, PatternFn] = {
    "cap_public_storage_credentials_risk": _pattern_public_storage_credentials_risk,
    "cap_internet_exposed_compute_with_iam": _pattern_internet_exposed_compute_with_iam,
    "cap_wildcard_admin_attached": _pattern_wildcard_admin_attached,
    "cap_root_unsafe": _pattern_root_unsafe,
    "cap_world_assumable_role": _pattern_world_assumable_role,
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
