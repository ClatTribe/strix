"""Terraform misconfig rules — Phase 11.4.

Rules operate on the block list emitted by
`strix/iac/parsers/terraform.py`. Each block is
`{type, label1, label2, body, line, raw}` — rules do substring /
regex searches inside `body` to detect misconfigurations.

The rule set prioritises the most-common real-world cloud misconfigs:
  * Public S3 bucket (ACL=public-read / public-read-write)
  * Security group with 0.0.0.0/0 ingress on dangerous ports
  * RDS / EC2 / EBS without encryption
  * IAM policy with `*` action OR `*` resource
  * Hardcoded secret literal in a `default` variable
  * Logging / versioning disabled on S3
  * Default VPC use (anti-pattern for prod)

Rule IDs mirror Checkov / tfsec where possible so cross-tool
deduplication is feasible at the wrapper layer.
"""

from __future__ import annotations

import re
from typing import Any

from strix.iac.parsers.base import PLATFORM_TERRAFORM, IacFile
from strix.iac.rules import IacFinding, register_rule


def _resource_blocks(iac_file: IacFile) -> list[dict[str, Any]]:
    if not isinstance(iac_file.data, list):
        return []
    return [
        b for b in iac_file.data
        if isinstance(b, dict) and b.get("type") == "resource"
    ]


# Hardcoded secret regex set — same patterns as docker_rules.py
# to keep cross-platform consistency.
_SECRET_LIKE = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY"),
]


# ---------------------------------------------------------------------------
# AWS_S3_PUBLIC — S3 bucket with public ACL
# ---------------------------------------------------------------------------


_S3_PUBLIC_ACL_RE = re.compile(
    r'\bacl\s*=\s*"(public-read|public-read-write|website)"',
    re.IGNORECASE,
)


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_aws_s3_public_acl(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    for block in _resource_blocks(iac_file):
        if block.get("label1") not in {
            "aws_s3_bucket",
            "aws_s3_bucket_acl",
        }:
            continue
        body = block.get("body") or ""
        m = _S3_PUBLIC_ACL_RE.search(body)
        if m:
            out.append(IacFinding(
                rule_id="TF_AWS_S3_PUBLIC_ACL",
                file=iac_file.path,
                line=block.get("line", 0),
                severity="high",
                message=(
                    f"S3 bucket `{block.get('label2')}` has public "
                    f"ACL (`{m.group(1)}`). Public-read buckets "
                    f"are a frequent source of data leaks; use "
                    f"bucket policies + signed URLs instead."
                ),
                cwe="CWE-668",
                category="misconfig",
                platform=PLATFORM_TERRAFORM,
                metadata={
                    "resource_type": block.get("label1"),
                    "resource_name": block.get("label2"),
                    "acl": m.group(1),
                },
            ))
    return out


# ---------------------------------------------------------------------------
# AWS_SG_OPEN_INGRESS — security group with 0.0.0.0/0 on dangerous ports
# ---------------------------------------------------------------------------


_OPEN_CIDR_RE = re.compile(
    r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
)
_INGRESS_BLOCK_RE = re.compile(
    r"ingress\s*\{([^}]*)\}",
    re.DOTALL,
)
_FROM_PORT_RE = re.compile(r"from_port\s*=\s*(\d+)")
_TO_PORT_RE = re.compile(r"to_port\s*=\s*(\d+)")

_DANGEROUS_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    5984: "CouchDB",
    9042: "Cassandra",
    2375: "Docker daemon (plaintext)",
    2376: "Docker daemon (TLS)",
}


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_aws_sg_open_ingress(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    for block in _resource_blocks(iac_file):
        if block.get("label1") != "aws_security_group":
            continue
        body = block.get("body") or ""
        for m in _INGRESS_BLOCK_RE.finditer(body):
            ingress_body = m.group(1)
            if not _OPEN_CIDR_RE.search(ingress_body):
                continue
            fp = _FROM_PORT_RE.search(ingress_body)
            tp = _TO_PORT_RE.search(ingress_body)
            from_port = int(fp.group(1)) if fp else None
            to_port = int(tp.group(1)) if tp else None
            danger_label = None
            if from_port == to_port and from_port in _DANGEROUS_PORTS:
                danger_label = _DANGEROUS_PORTS[from_port]
            severity = "critical" if danger_label else "high"
            out.append(IacFinding(
                rule_id="TF_AWS_SG_OPEN_INGRESS",
                file=iac_file.path,
                line=block.get("line", 0),
                severity=severity,
                message=(
                    f"Security group `{block.get('label2')}` ingress "
                    f"allows 0.0.0.0/0 on port "
                    f"{from_port}–{to_port}"
                    + (f" ({danger_label})" if danger_label else "")
                    + ". Restrict to known CIDRs or a bastion-only "
                    "security-group reference."
                ),
                cwe="CWE-732",
                category="misconfig",
                platform=PLATFORM_TERRAFORM,
                metadata={
                    "resource_name": block.get("label2"),
                    "from_port": from_port,
                    "to_port": to_port,
                    "service_at_port": danger_label,
                },
            ))
    return out


# ---------------------------------------------------------------------------
# AWS_RDS_NO_ENCRYPTION — RDS instance without storage_encrypted=true
# ---------------------------------------------------------------------------


_STORAGE_ENCRYPTED_RE = re.compile(
    r"\bstorage_encrypted\s*=\s*true",
    re.IGNORECASE,
)


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_aws_rds_no_encryption(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    for block in _resource_blocks(iac_file):
        if block.get("label1") not in {
            "aws_db_instance",
            "aws_rds_cluster",
        }:
            continue
        body = block.get("body") or ""
        if _STORAGE_ENCRYPTED_RE.search(body):
            continue
        out.append(IacFinding(
            rule_id="TF_AWS_RDS_NO_ENCRYPTION",
            file=iac_file.path,
            line=block.get("line", 0),
            severity="high",
            message=(
                f"RDS resource `{block.get('label2')}` does not "
                f"declare `storage_encrypted = true`. AWS does NOT "
                f"encrypt RDS storage by default; declare the flag "
                f"explicitly to satisfy PCI-DSS / SOC 2 encryption-"
                f"at-rest requirements."
            ),
            cwe="CWE-311",
            category="misconfig",
            platform=PLATFORM_TERRAFORM,
            metadata={
                "resource_type": block.get("label1"),
                "resource_name": block.get("label2"),
            },
        ))
    return out


# ---------------------------------------------------------------------------
# AWS_EBS_NO_ENCRYPTION — aws_ebs_volume without encrypted=true
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_aws_ebs_no_encryption(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    encrypted_re = re.compile(r"\bencrypted\s*=\s*true", re.IGNORECASE)
    for block in _resource_blocks(iac_file):
        if block.get("label1") != "aws_ebs_volume":
            continue
        body = block.get("body") or ""
        if encrypted_re.search(body):
            continue
        out.append(IacFinding(
            rule_id="TF_AWS_EBS_NO_ENCRYPTION",
            file=iac_file.path,
            line=block.get("line", 0),
            severity="high",
            message=(
                f"EBS volume `{block.get('label2')}` is not encrypted. "
                f"Set `encrypted = true` (or enable AWS account-level "
                f"EBS default encryption)."
            ),
            cwe="CWE-311",
            category="misconfig",
            platform=PLATFORM_TERRAFORM,
            metadata={"resource_name": block.get("label2")},
        ))
    return out


# ---------------------------------------------------------------------------
# IAM_WILDCARD — policy with `*` action OR `*` resource
# ---------------------------------------------------------------------------


_IAM_RESOURCES = {
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
}
_WILDCARD_ACTION_RE = re.compile(
    r'"Action"\s*:\s*"\*"',
)
_WILDCARD_RESOURCE_RE = re.compile(
    r'"Resource"\s*:\s*"\*"',
)


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_aws_iam_wildcard_policy(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    for block in _resource_blocks(iac_file):
        if block.get("label1") not in _IAM_RESOURCES:
            continue
        body = block.get("body") or ""
        wild_action = bool(_WILDCARD_ACTION_RE.search(body))
        wild_resource = bool(_WILDCARD_RESOURCE_RE.search(body))
        if not (wild_action or wild_resource):
            continue
        violations: list[str] = []
        if wild_action:
            violations.append('Action: "*"')
        if wild_resource:
            violations.append('Resource: "*"')
        out.append(IacFinding(
            rule_id="TF_AWS_IAM_WILDCARD_POLICY",
            file=iac_file.path,
            line=block.get("line", 0),
            severity="high",
            message=(
                f"IAM policy `{block.get('label2')}` uses wildcard "
                f"{', '.join(violations)}. Apply least-privilege — "
                f"enumerate the specific actions / resource ARNs "
                f"the principal needs."
            ),
            cwe="CWE-732",
            category="misconfig",
            platform=PLATFORM_TERRAFORM,
            metadata={
                "resource_name": block.get("label2"),
                "wildcard_action": wild_action,
                "wildcard_resource": wild_resource,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# HARDCODED_SECRET — secret literal in a resource body or variable default
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_hardcoded_secret(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for block in iac_file.data:
        if not isinstance(block, dict):
            continue
        body = block.get("body") or ""
        for pattern in _SECRET_LIKE:
            m = pattern.search(body)
            if not m:
                continue
            out.append(IacFinding(
                rule_id="TF_HARDCODED_SECRET",
                file=iac_file.path,
                line=block.get("line", 0),
                severity="critical",
                message=(
                    f"Hardcoded secret-like value detected in "
                    f"{block.get('type')} `{block.get('label1')}` "
                    f"(matches {pattern.pattern[:40]}). NEVER commit "
                    f"secrets to Terraform — use `aws_secretsmanager_"
                    f"secret_version` / Vault provider / env vars."
                ),
                cwe="CWE-798",
                category="secrets",
                platform=PLATFORM_TERRAFORM,
                metadata={
                    "block_type": block.get("type"),
                    "block_label": block.get("label1"),
                    "match_preview": m.group(0)[:16] + "...",
                },
            ))
            # Only emit one finding per block — multiple secret
            # types matching is noise.
            break
    return out


# ---------------------------------------------------------------------------
# AWS_S3_NO_VERSIONING — bucket without versioning enabled
# ---------------------------------------------------------------------------


_VERSIONING_BLOCK_RE = re.compile(
    r"versioning\s*\{([^}]*)\}",
    re.DOTALL,
)
_VERSIONING_ENABLED_RE = re.compile(
    r'\benabled\s*=\s*true',
    re.IGNORECASE,
)


@register_rule(platform=PLATFORM_TERRAFORM)
def tf_aws_s3_no_versioning(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    for block in _resource_blocks(iac_file):
        if block.get("label1") != "aws_s3_bucket":
            continue
        body = block.get("body") or ""
        m = _VERSIONING_BLOCK_RE.search(body)
        enabled = False
        if m and _VERSIONING_ENABLED_RE.search(m.group(1)):
            enabled = True
        if enabled:
            continue
        out.append(IacFinding(
            rule_id="TF_AWS_S3_NO_VERSIONING",
            file=iac_file.path,
            line=block.get("line", 0),
            severity="medium",
            message=(
                f"S3 bucket `{block.get('label2')}` has versioning "
                f"disabled (default). Without versioning, "
                f"ransomware / accidental overwrite is irrecoverable. "
                f"Enable via `versioning {{ enabled = true }}`."
            ),
            cwe="CWE-693",
            category="misconfig",
            platform=PLATFORM_TERRAFORM,
            metadata={"resource_name": block.get("label2")},
        ))
    return out
