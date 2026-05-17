"""Drift correlation core — pure data transformation.

The correlator takes lists of `IacFinding` + `CspmFinding` and
returns a classified `DriftReport`. No I/O, no tracer side effects
— those happen in `strix.drift.tools`. Keeps this module trivially
testable without monkeypatching subprocess / boto3 / tracers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from strix.cspm.aws import CspmFinding
from strix.iac.rules import IacFinding


# ---------------------------------------------------------------------------
# Rule-class normalisation
# ---------------------------------------------------------------------------

# IaC + CSPM use distinct rule-ID namespaces. To correlate "the same
# thing seen from two sides" we normalise both into shared
# rule-CLASS keys. A rule class is a short string identifying what
# the rule looks for — e.g. `s3_public_access`.
#
# Coverage rule: only entries that have BOTH an IaC analog AND a
# CSPM analog appear here. Single-sided rules (e.g. IAM root MFA —
# Terraform doesn't manage the root account) fall through to the
# `uncorrelated_cspm` bucket, which is the correct behaviour: they
# attest a control that has no IaC equivalent to cross-reference
# against.
RULE_CLASS_MAP: dict[str, str] = {
    # ---- S3 ----
    "TF_AWS_S3_PUBLIC_ACL": "s3_public_access",
    "AWS_S3_PUBLIC_ACL": "s3_public_access",
    "prowler:s3_bucket_public_access": "s3_public_access",
    "prowler:s3_bucket_acl_prohibited": "s3_public_access",

    "TF_AWS_S3_NO_VERSIONING": "s3_versioning_disabled",
    "AWS_S3_VERSIONING_DISABLED": "s3_versioning_disabled",
    "prowler:s3_bucket_object_versioning": "s3_versioning_disabled",
    "prowler:s3_bucket_no_mfa_delete": "s3_versioning_disabled",

    # `s3_encryption_disabled`: CSPM-side only. Strix's IaC rule
    # corpus doesn't have a Terraform analog for bucket default
    # encryption today, so these findings land in uncorrelated_cspm
    # (right behaviour — we can't tell drift from "no IaC rule").
    # Add the entries here once the IaC side ships.

    # ---- RDS ----
    "TF_AWS_RDS_NO_ENCRYPTION": "rds_encryption_disabled",
    "AWS_RDS_NO_ENCRYPTION": "rds_encryption_disabled",
    "prowler:rds_instance_storage_encrypted": "rds_encryption_disabled",

    # `rds_public_access`: CSPM-only — IaC rule corpus doesn't have
    # a `publicly_accessible` check yet.

    # ---- EBS ----
    "TF_AWS_EBS_NO_ENCRYPTION": "ebs_encryption_disabled",
    "AWS_EBS_ENCRYPTION_BY_DEFAULT_DISABLED": "ebs_encryption_disabled",
    "prowler:ec2_ebs_default_encryption": "ebs_encryption_disabled",
    "prowler:ec2_ebs_volume_encryption": "ebs_encryption_disabled",

    # ---- Security Groups ----
    "TF_AWS_SG_OPEN_INGRESS": "sg_open_admin_ingress",
    "AWS_SG_OPEN_INGRESS_ADMIN": "sg_open_admin_ingress",
    "prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_22": "sg_open_admin_ingress",
    "prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_3389": "sg_open_admin_ingress",
    "prowler:ec2_securitygroup_allow_ingress_from_internet_to_any_port": "sg_open_admin_ingress",

    # `sg_open_world_ingress`: CSPM-side distinguishes "world open
    # on non-admin port" from admin. IaC scanner today reports all
    # 0.0.0.0/0 ingress under one rule (TF_AWS_SG_OPEN_INGRESS),
    # which the correlator already maps to sg_open_admin_ingress.
    # World-ingress-on-non-admin findings show up as uncorrelated_cspm.

    # ---- IAM ----
    "TF_AWS_IAM_WILDCARD_POLICY": "iam_wildcard_admin",
    "AWS_IAM_POLICY_WILDCARD_ADMIN": "iam_wildcard_admin",
    "prowler:iam_policy_no_full_access_to_cloudtrail": "iam_wildcard_admin",
    "prowler:iam_policy_no_administrative_privileges": "iam_wildcard_admin",
    "prowler:iam_inline_policy_no_administrative_privileges": "iam_wildcard_admin",

    # ---- Hardcoded secrets ----
    # IaC variant detects hardcoded creds in *.tf; CSPM has no
    # direct analog (live secrets are caught by secrets_scan, not
    # CSPM). Included so the rule_class is still recognised on the
    # IaC side and shows up in iac_unfollowed if no CSPM peer.
    "TF_HARDCODED_SECRET": "hardcoded_secret_iac",
}


# Resource types where IaC + CSPM both expose a stable identifier
# we can cross-reference by string. Used by `_resource_key` to do
# precise matching when possible.
#
# The key is the rule_class. The value is a tuple of regex
# patterns: (iac_extractor, cspm_extractor). Each extractor pulls a
# normalised resource id (typically lowercase, no quotes).
_RESOURCE_KEY_EXTRACTORS: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    "s3_public_access": (
        # IaC metadata.resource_name is the TF local name — useful
        # secondary signal. We also accept `bucket = "..."`
        # attribute when present in metadata.
        re.compile(r"(?P<id>[\w\-.]+)"),
        # CSPM: ARN `arn:aws:s3:::bucket-name` → bucket-name.
        re.compile(r"arn:aws:s3:::(?P<id>[\w\-.]+)"),
    ),
    "s3_versioning_disabled": (
        re.compile(r"(?P<id>[\w\-.]+)"),
        re.compile(r"arn:aws:s3:::(?P<id>[\w\-.]+)"),
    ),
    "rds_encryption_disabled": (
        re.compile(r"(?P<id>[\w\-]+)"),
        re.compile(r"arn:aws:rds:[^:]*:[^:]*:db:(?P<id>[\w\-]+)"),
    ),
    "iam_wildcard_admin": (
        re.compile(r"(?P<id>[\w\-]+)"),
        re.compile(r"arn:aws:iam::[^:]*:policy/(?P<id>[\w\-/]+)"),
    ),
}


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE = "iac_root_cause"
DRIFT_CLASSIFICATION_DRIFT = "drift"
DRIFT_CLASSIFICATION_IAC_UNFOLLOWED = "iac_unfollowed"


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _worst_severity(*sevs: str | None) -> str:
    """Pick the highest-rank severity from any provided strings.
    Defaults to medium when none are recognisable — safer to
    over-elevate than under."""
    rank = -1
    pick = "medium"
    for s in sevs:
        if not s:
            continue
        r = _SEV_RANK.get(s.lower(), -1)
        if r > rank:
            rank = r
            pick = s.lower()
    return pick


@dataclass
class DriftFinding:
    """One classified pairing of IaC + CSPM findings.

    Exactly one of `iac_finding` / `cspm_finding` is None for
    one-sided classifications (`iac_unfollowed` / `drift`); both
    are populated for `iac_root_cause`.
    """
    classification: str
    rule_class: str
    severity: str
    iac_finding: IacFinding | None = None
    cspm_finding: CspmFinding | None = None
    resource_hint: str | None = None
    iac_rule_id: str | None = None
    cspm_rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "rule_class": self.rule_class,
            "severity": self.severity,
            "resource_hint": self.resource_hint,
            "iac_rule_id": self.iac_rule_id,
            "cspm_rule_id": self.cspm_rule_id,
            "iac_finding": (
                self.iac_finding.to_dict() if self.iac_finding else None
            ),
            "cspm_finding": (
                self.cspm_finding.to_dict() if self.cspm_finding else None
            ),
        }


@dataclass
class DriftReport:
    """Bundle of classified drift findings + the uncorrelated
    CSPM residual (live-only rules with no IaC analog)."""
    iac_root_cause: list[DriftFinding] = field(default_factory=list)
    drift: list[DriftFinding] = field(default_factory=list)
    iac_unfollowed: list[DriftFinding] = field(default_factory=list)
    uncorrelated_cspm: list[CspmFinding] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            "iac_root_cause": len(self.iac_root_cause),
            "drift": len(self.drift),
            "iac_unfollowed": len(self.iac_unfollowed),
            "uncorrelated_cspm": len(self.uncorrelated_cspm),
            "total": (
                len(self.iac_root_cause) + len(self.drift)
                + len(self.iac_unfollowed)
            ),
        }

    @property
    def total_drift_signal(self) -> int:
        """Findings that indicate IaC ≠ live state — the number an
        ops / SRE lead cares about."""
        return len(self.drift) + len(self.iac_unfollowed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "iac_root_cause": [f.to_dict() for f in self.iac_root_cause],
            "drift": [f.to_dict() for f in self.drift],
            "iac_unfollowed": [f.to_dict() for f in self.iac_unfollowed],
            "uncorrelated_cspm": [f.to_dict() for f in self.uncorrelated_cspm],
        }


# ---------------------------------------------------------------------------
# Resource-id extraction
# ---------------------------------------------------------------------------


def _iac_resource_id(f: IacFinding, rule_class: str) -> str | None:
    """Pull a comparable resource identifier from an IaC finding.

    Strategy:
      1. Prefer `metadata['bucket']` / `metadata['identifier']` /
         `metadata['name']` — explicit attribute the rule may have
         captured.
      2. Fall back to `metadata['resource_name']` (Terraform local
         name like "data" / "prod_db") — useful when the rule
         didn't surface the actual cloud-side name.

    None means "no usable identifier" → coarse rule-class matching.
    """
    if not isinstance(f.metadata, dict):
        return None
    for key in ("bucket", "identifier", "name", "policy_name"):
        v = f.metadata.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    name = f.metadata.get("resource_name")
    if isinstance(name, str) and name.strip():
        return name.strip().lower()
    return None


def _cspm_resource_id(f: CspmFinding, rule_class: str) -> str | None:
    """Pull a comparable resource identifier from a CSPM finding —
    typically the last segment of the ARN."""
    arn = f.resource_arn or ""
    extractor = _RESOURCE_KEY_EXTRACTORS.get(rule_class)
    if extractor is not None:
        _, cspm_re = extractor
        m = cspm_re.search(arn)
        if m:
            return m.group("id").lower()

    # Fallback — last `:`-delimited or `/`-delimited segment.
    # Catches `arn:aws:ec2:us-east-1:*:security-group/sg-aaa`.
    tail = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
    return tail.lower() if tail else None


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def _rule_class(rule_id: str, custom_map: dict[str, str] | None) -> str | None:
    """Resolve a rule_id to its rule_class. Returns None when the
    rule_id has no class mapping (single-sided rule)."""
    if custom_map and rule_id in custom_map:
        return custom_map[rule_id]
    return RULE_CLASS_MAP.get(rule_id)


def correlate(
    iac_findings: list[IacFinding],
    cspm_findings: list[CspmFinding],
    *,
    rule_class_map: dict[str, str] | None = None,
) -> DriftReport:
    """Cross-reference IaC + CSPM findings into a `DriftReport`.

    Algorithm:

      1. Bucket each finding by rule_class. Unknown rule_classes
         (single-sided) go to `uncorrelated_cspm` on the CSPM side
         and are dropped on the IaC side (IaC-only rules with no
         CSPM peer don't represent drift — they're just IaC
         findings, surfaced separately).

      2. Inside each rule_class bucket, try to pair findings by
         resource id (`_iac_resource_id` / `_cspm_resource_id`).
         Exact id matches → `iac_root_cause` pair.

      3. Remaining IaC findings (id had no CSPM peer) become
         `iac_unfollowed`. Remaining CSPM findings (id had no IaC
         peer) become `drift`.

      4. When neither side has a usable resource id, fall back to
         coarse class-matching: `min(N_iac, N_cspm)` paired into
         `iac_root_cause`, residual on either side classified
         accordingly. Coarse matches are flagged in `resource_hint`
         so consumers know the pairing isn't precise.
    """
    report = DriftReport()

    # --------- Bucket by rule_class ---------
    iac_by_class: dict[str, list[IacFinding]] = {}
    cspm_by_class: dict[str, list[CspmFinding]] = {}

    for f in iac_findings:
        cls = _rule_class(f.rule_id, rule_class_map)
        if cls:
            iac_by_class.setdefault(cls, []).append(f)
        # IaC-only with no CSPM analog: dropped here — those findings
        # are already surfaced by the IaC scan path. The drift module
        # is specifically about cross-comparison.

    for f in cspm_findings:
        cls = _rule_class(f.rule_id, rule_class_map)
        if cls is None:
            report.uncorrelated_cspm.append(f)
        else:
            cspm_by_class.setdefault(cls, []).append(f)

    all_classes = set(iac_by_class.keys()) | set(cspm_by_class.keys())

    # --------- Pair within each class ---------
    for rule_class in sorted(all_classes):
        iac_list = list(iac_by_class.get(rule_class, []))
        cspm_list = list(cspm_by_class.get(rule_class, []))

        # Build resource-id index for the CSPM side so we can pop
        # exact matches as we walk IaC.
        cspm_by_id: dict[str, list[CspmFinding]] = {}
        cspm_unindexed: list[CspmFinding] = []
        for cf in cspm_list:
            rid = _cspm_resource_id(cf, rule_class)
            if rid:
                cspm_by_id.setdefault(rid, []).append(cf)
            else:
                cspm_unindexed.append(cf)

        # Split IaC residuals into two buckets:
        #   * `iac_id_known` — had a usable id but no CSPM match
        #     → confirmed iac_unfollowed (no coarse pairing).
        #   * `iac_id_unknown` — no usable id at all → eligible for
        #     coarse pairing against same-class CSPM unknowns.
        iac_id_known: list[IacFinding] = []
        iac_id_unknown: list[IacFinding] = []
        for inf in iac_list:
            iac_id = _iac_resource_id(inf, rule_class)
            if iac_id and iac_id in cspm_by_id and cspm_by_id[iac_id]:
                cf = cspm_by_id[iac_id].pop(0)
                if not cspm_by_id[iac_id]:
                    del cspm_by_id[iac_id]
                report.iac_root_cause.append(DriftFinding(
                    classification=DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE,
                    rule_class=rule_class,
                    severity=_worst_severity(inf.severity, cf.severity),
                    iac_finding=inf,
                    cspm_finding=cf,
                    resource_hint=iac_id,
                    iac_rule_id=inf.rule_id,
                    cspm_rule_id=cf.rule_id,
                ))
            elif iac_id:
                iac_id_known.append(inf)
            else:
                iac_id_unknown.append(inf)

        # Residual CSPM findings — same split. Anything in
        # `cspm_by_id` after the IaC walk is "had an id, no peer";
        # `cspm_unindexed` is "had no usable id" (coarse-pair pool).
        cspm_id_known: list[CspmFinding] = []
        for entries in cspm_by_id.values():
            cspm_id_known.extend(entries)
        cspm_id_unknown = list(cspm_unindexed)

        # Coarse pair ONLY the id-less residuals — those are the
        # only candidates where we can't say with confidence that
        # the resources differ. ID-bearing residuals on either
        # side are confirmed drift / iac_unfollowed.
        paired = min(len(iac_id_unknown), len(cspm_id_unknown))
        for i in range(paired):
            inf = iac_id_unknown[i]
            cf = cspm_id_unknown[i]
            report.iac_root_cause.append(DriftFinding(
                classification=DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE,
                rule_class=rule_class,
                severity=_worst_severity(inf.severity, cf.severity),
                iac_finding=inf,
                cspm_finding=cf,
                resource_hint=f"coarse:{rule_class}",
                iac_rule_id=inf.rule_id,
                cspm_rule_id=cf.rule_id,
            ))

        # Everything else is genuine drift / iac_unfollowed.
        for inf in iac_id_known + iac_id_unknown[paired:]:
            report.iac_unfollowed.append(DriftFinding(
                classification=DRIFT_CLASSIFICATION_IAC_UNFOLLOWED,
                rule_class=rule_class,
                severity=inf.severity or "medium",
                iac_finding=inf,
                resource_hint=_iac_resource_id(inf, rule_class),
                iac_rule_id=inf.rule_id,
            ))
        for cf in cspm_id_known + cspm_id_unknown[paired:]:
            report.drift.append(DriftFinding(
                classification=DRIFT_CLASSIFICATION_DRIFT,
                rule_class=rule_class,
                severity=cf.severity or "medium",
                cspm_finding=cf,
                resource_hint=_cspm_resource_id(cf, rule_class),
                cspm_rule_id=cf.rule_id,
            ))

    return report
