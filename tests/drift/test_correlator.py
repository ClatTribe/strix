"""Pure-data tests for the drift correlator.

No subprocess / boto3 / tracer dependencies — exercises only the
classification + matching logic against constructed finding
objects."""

from __future__ import annotations

import pytest

from strix.cspm.aws import CspmFinding
from strix.drift.correlator import (
    DRIFT_CLASSIFICATION_DRIFT,
    DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE,
    DRIFT_CLASSIFICATION_IAC_UNFOLLOWED,
    RULE_CLASS_MAP,
    correlate,
)
from strix.iac.rules import IacFinding


def _tf(rule_id: str, *, name: str | None = None, sev: str = "high",
        extra_meta: dict | None = None) -> IacFinding:
    md = {"resource_type": "aws_s3_bucket"}
    if name:
        md["resource_name"] = name
    if extra_meta:
        md.update(extra_meta)
    return IacFinding(
        rule_id=rule_id,
        file=f"terraform/main.tf",
        line=1,
        severity=sev,
        message=f"{rule_id} on {name or '?'}",
        cwe="CWE-732",
        category="misconfig",
        platform="terraform",
        metadata=md,
    )


def _cspm(rule_id: str, *, arn: str, sev: str = "high",
          service: str = "s3", region: str | None = "us-east-1") -> CspmFinding:
    return CspmFinding(
        rule_id=rule_id,
        severity=sev,
        message=f"{rule_id} on {arn}",
        service=service,
        region=region,
        resource_arn=arn,
        account_id="111122223333",
        cwe="CWE-732",
        category="misconfig",
    )


# ---------------------------------------------------------------------------
# Rule-class map hygiene
# ---------------------------------------------------------------------------


def test_rule_class_map_pairs_iac_and_cspm() -> None:
    """Every rule_class should have at least one IaC-side rule AND
    at least one CSPM-side rule. A class with only one side is
    pointless (no cross-comparison possible)."""
    by_class: dict[str, list[str]] = {}
    for rid, cls in RULE_CLASS_MAP.items():
        by_class.setdefault(cls, []).append(rid)
    for cls, rule_ids in by_class.items():
        has_iac = any(
            rid.startswith("TF_") or rid.startswith("K8S_")
            or rid.startswith("HELM_") or rid.startswith("docker")
            or rid.startswith("compose")
            for rid in rule_ids
        )
        has_cspm = any(
            rid.startswith("AWS_") or rid.startswith("prowler:")
            for rid in rule_ids
        )
        # Allow IaC-only buckets (`*_iac` suffix) — they're flagged
        # explicitly as one-sided.
        if cls.endswith("_iac"):
            assert has_iac, f"iac-only class {cls} has no IaC rule"
            continue
        assert has_iac, f"class {cls} has no IaC rule: {rule_ids}"
        assert has_cspm, f"class {cls} has no CSPM rule: {rule_ids}"


# ---------------------------------------------------------------------------
# Resource-id name matching
# ---------------------------------------------------------------------------


def test_s3_iac_root_cause_matched_by_resource_name() -> None:
    """IaC's `metadata.resource_name` matches the last segment of
    the CSPM ARN — `arn:aws:s3:::data` matches `resource_name=data`."""
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="data")]
    cspm = [_cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::data")]

    report = correlate(iac, cspm)

    assert len(report.iac_root_cause) == 1
    df = report.iac_root_cause[0]
    assert df.rule_class == "s3_public_access"
    assert df.resource_hint == "data"
    assert report.summary["iac_root_cause"] == 1
    assert report.summary["drift"] == 0


def test_s3_drift_when_cspm_resource_unknown_to_iac() -> None:
    """CSPM finds `arn:aws:s3:::orphan-bucket` but no IaC rule
    declares it → classified as drift (probably created in console)."""
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="known")]
    cspm = [
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::known"),
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::orphan-bucket"),
    ]

    report = correlate(iac, cspm)

    assert len(report.iac_root_cause) == 1
    assert report.iac_root_cause[0].resource_hint == "known"
    assert len(report.drift) == 1
    assert report.drift[0].resource_hint == "orphan-bucket"
    assert report.drift[0].classification == DRIFT_CLASSIFICATION_DRIFT


def test_s3_iac_unfollowed_when_no_cspm_peer() -> None:
    """IaC declares a public bucket but CSPM doesn't see it — IaC
    hasn't been applied yet (or someone hand-fixed live)."""
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="pending")]
    cspm: list[CspmFinding] = []

    report = correlate(iac, cspm)

    assert report.iac_unfollowed
    assert report.iac_unfollowed[0].classification == (
        DRIFT_CLASSIFICATION_IAC_UNFOLLOWED
    )
    assert report.iac_unfollowed[0].resource_hint == "pending"


def test_prowler_rule_class_matched_alongside_boto3() -> None:
    """Prowler-namespaced rule_id (`prowler:s3_bucket_public_access`)
    + boto3 rule_id (`AWS_S3_PUBLIC_ACL`) both map to the same
    rule_class — correlation works regardless of which CSPM engine
    produced the finding."""
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="prodbucket")]
    cspm = [_cspm(
        "prowler:s3_bucket_public_access",
        arn="arn:aws:s3:::prodbucket",
    )]
    report = correlate(iac, cspm)
    assert len(report.iac_root_cause) == 1
    assert report.iac_root_cause[0].cspm_rule_id == "prowler:s3_bucket_public_access"


# ---------------------------------------------------------------------------
# Multi-finding accounting
# ---------------------------------------------------------------------------


def test_multiple_resources_paired_independently() -> None:
    iac = [
        _tf("TF_AWS_S3_PUBLIC_ACL", name="data"),
        _tf("TF_AWS_S3_PUBLIC_ACL", name="backups"),
    ]
    cspm = [
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::data"),
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::backups"),
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::extra"),
    ]
    report = correlate(iac, cspm)
    assert len(report.iac_root_cause) == 2
    paired_hints = {df.resource_hint for df in report.iac_root_cause}
    assert paired_hints == {"data", "backups"}
    assert len(report.drift) == 1
    assert report.drift[0].resource_hint == "extra"


def test_severity_promoted_to_worst_when_both_sides_flag() -> None:
    """`iac_root_cause` inherits the worst severity from either
    side — drift between high (CSPM) and medium (IaC) gets high."""
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="x", sev="medium")]
    cspm = [_cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::x", sev="critical")]
    report = correlate(iac, cspm)
    assert len(report.iac_root_cause) == 1
    assert report.iac_root_cause[0].severity == "critical"


# ---------------------------------------------------------------------------
# Uncorrelated CSPM (rules with no IaC analog)
# ---------------------------------------------------------------------------


def test_iam_root_mfa_in_uncorrelated_bucket() -> None:
    """Terraform doesn't model the root account — CSPM finding
    for `AWS_IAM_USER_NO_MFA` on root has no IaC peer. Must NOT
    be classified as drift (would imply IaC should attest it)."""
    iac: list[IacFinding] = []
    cspm = [_cspm(
        "AWS_IAM_USER_NO_MFA",
        arn="arn:aws:iam::*:user/alice",
        service="iam", region=None,
    )]
    report = correlate(iac, cspm)
    assert report.summary["drift"] == 0
    assert len(report.uncorrelated_cspm) == 1
    assert report.uncorrelated_cspm[0].rule_id == "AWS_IAM_USER_NO_MFA"


def test_prowler_unknown_check_id_in_uncorrelated_bucket() -> None:
    """A Prowler check we don't have in RULE_CLASS_MAP (newer than
    the strix release) gracefully lands in uncorrelated rather
    than crashing or mis-classifying."""
    cspm = [_cspm(
        "prowler:s3_brand_new_check_2026",
        arn="arn:aws:s3:::x",
    )]
    report = correlate([], cspm)
    assert len(report.uncorrelated_cspm) == 1
    assert report.summary["drift"] == 0


# ---------------------------------------------------------------------------
# Coarse-pairing fallback
# ---------------------------------------------------------------------------


def test_mismatched_resource_ids_classified_as_drift() -> None:
    """Both sides have usable resource IDs and the IDs don't match —
    this is confirmed drift on both sides (the CSPM resource isn't
    declared in IaC; the IaC resource isn't visible live). The old
    coarse-pair behaviour would hide this as iac_root_cause; the
    auditor wants the genuine drift signal."""
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="tf-local-name")]
    cspm = [_cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::completely-different")]
    report = correlate(iac, cspm)
    assert report.summary["iac_root_cause"] == 0
    assert report.summary["iac_unfollowed"] == 1
    assert report.summary["drift"] == 1


def test_coarse_pair_only_when_neither_side_has_ids(monkeypatch) -> None:
    """Coarse pairing fires only when BOTH residuals are id-less.
    Construct findings with no resource_name metadata so the
    extractor returns None on the IaC side; ARN-less on CSPM."""
    iac = [
        IacFinding(
            rule_id="TF_AWS_S3_PUBLIC_ACL",
            file="x.tf", line=1, severity="high",
            message="public", cwe="CWE-732",
            category="misconfig", platform="terraform",
            metadata={},  # no resource_name
        ),
    ]
    cspm = [
        CspmFinding(
            rule_id="AWS_S3_PUBLIC_ACL",
            severity="high", message="public",
            service="s3", region=None,
            resource_arn="",   # no ARN → no extractable id
            cwe="CWE-732", category="misconfig",
        ),
    ]
    report = correlate(iac, cspm)
    # Both id-less → coarse-pair eligible → 1 iac_root_cause.
    assert len(report.iac_root_cause) == 1
    assert report.iac_root_cause[0].resource_hint == "coarse:s3_public_access"


def test_residual_split_with_mismatched_ids() -> None:
    """3 IaC findings + 5 CSPM findings, IDs on both sides, no
    overlap → 0 paired, 3 iac_unfollowed, 5 drift. Confirmed
    drift on every entry."""
    iac = [
        _tf("TF_AWS_S3_PUBLIC_ACL", name=f"iac-{i}")
        for i in range(3)
    ]
    cspm = [
        _cspm("AWS_S3_PUBLIC_ACL", arn=f"arn:aws:s3:::cspm-{i}")
        for i in range(5)
    ]
    report = correlate(iac, cspm)
    assert report.summary["iac_root_cause"] == 0
    assert report.summary["iac_unfollowed"] == 3
    assert report.summary["drift"] == 5


# ---------------------------------------------------------------------------
# Custom rule_class_map override
# ---------------------------------------------------------------------------


def test_custom_rule_class_map_overrides_default() -> None:
    """Callers should be able to teach the correlator about
    third-party rule IDs (e.g. Checkov check_ids) without
    forking."""
    custom = {
        "CKV_AWS_53": "s3_public_access",     # Checkov-side
        "AWS_S3_PUBLIC_ACL": "s3_public_access",
    }
    iac = [IacFinding(
        rule_id="CKV_AWS_53",
        file="x.tf", line=1, severity="high",
        message="checkov: public ACL", cwe="CWE-732",
        category="misconfig", platform="terraform",
        metadata={"resource_name": "data"},
    )]
    cspm = [_cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::data")]

    report = correlate(iac, cspm, rule_class_map=custom)
    assert len(report.iac_root_cause) == 1
    assert report.iac_root_cause[0].iac_rule_id == "CKV_AWS_53"


# ---------------------------------------------------------------------------
# Report dict shape (for wrapper consumption)
# ---------------------------------------------------------------------------


def test_to_dict_is_json_safe() -> None:
    """`DriftReport.to_dict()` should be JSON-serialisable end to
    end so the wrapper can write it to disk / send over the wire."""
    import json
    iac = [_tf("TF_AWS_S3_PUBLIC_ACL", name="x")]
    cspm = [
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::x"),
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::y"),
    ]
    report = correlate(iac, cspm)
    payload = json.dumps(report.to_dict())  # must not raise
    assert "iac_root_cause" in payload
    assert "drift" in payload


def test_total_drift_signal_excludes_iac_root_cause() -> None:
    """The `total_drift_signal` count is what an SRE leader cares
    about — "how many findings indicate live ≠ IaC". Excludes
    iac_root_cause because those are agreement, not drift."""
    iac = [
        _tf("TF_AWS_S3_PUBLIC_ACL", name="agreed"),
        _tf("TF_AWS_S3_PUBLIC_ACL", name="pending-apply"),
    ]
    cspm = [
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::agreed"),
        _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::orphan"),
    ]
    report = correlate(iac, cspm)
    assert report.summary["iac_root_cause"] == 1
    assert report.summary["drift"] == 1
    assert report.summary["iac_unfollowed"] == 1
    # drift + iac_unfollowed (NOT iac_root_cause).
    assert report.total_drift_signal == 2
