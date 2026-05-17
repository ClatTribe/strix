"""Wrapper-facing API contract tests.

These pin the public surface webappsec/ imports. Any change here
is a breaking change to the wrapper contract — bump the import
shape only via deliberate migration.
"""

from __future__ import annotations

import json

import pytest

from strix.cloud_attack_paths import (
    AttackPath,
    AttackPathReport,
    analyze_cloud_attack_paths,
)
from strix.cspm.aws import CspmFinding


def _f(rule_id: str, *, arn: str, sev="high") -> CspmFinding:
    return CspmFinding(
        rule_id=rule_id, severity=sev,
        message=f"{rule_id} on {arn}",
        service="s3", region=None, resource_arn=arn,
        account_id="1", cwe=None, category="misconfig",
    )


# ---------------------------------------------------------------------------
# Stable public exports
# ---------------------------------------------------------------------------


def test_public_exports_present() -> None:
    """The wrapper imports THESE names. Removing any is a breaking
    change."""
    import strix.cloud_attack_paths as cap
    for name in (
        "analyze_cloud_attack_paths",
        "AttackPathReport",
        "AttackPath",
        "CloudGraph",
        "CloudResource",
        "CloudIdentity",
        "CloudPolicy",
        "build_graph_from_cspm",
        "find_attack_paths",
        "BUILTIN_PATTERNS",
    ):
        assert hasattr(cap, name), f"missing public export: {name}"


# ---------------------------------------------------------------------------
# analyze_cloud_attack_paths
# ---------------------------------------------------------------------------


def test_analyze_with_findings_only_produces_report() -> None:
    """Minimal contract: pass a list of CspmFindings, get an
    AttackPathReport back."""
    findings = [
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::tfstate-prod"),
        _f("AWS_IAM_ROOT_ACCESS_KEY",
           arn="arn:aws:iam::1:root", sev="critical"),
    ]
    report = analyze_cloud_attack_paths(cspm_findings=findings)
    assert isinstance(report, AttackPathReport)
    assert report.findings_consumed == 2
    assert len(report.paths) >= 2
    # Critical paths surface (root unsafe, public storage with
    # credential-shaped name).
    assert any(p.severity == "critical" for p in report.paths)


def test_analyze_empty_input_returns_empty_report() -> None:
    report = analyze_cloud_attack_paths(cspm_findings=[])
    assert report.paths == []
    assert report.findings_consumed == 0
    assert report.summary["total"] == 0


def test_analyze_includes_graph_only_when_requested() -> None:
    findings = [_f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::x")]
    without = analyze_cloud_attack_paths(cspm_findings=findings)
    with_graph = analyze_cloud_attack_paths(
        cspm_findings=findings, include_graph=True,
    )
    assert without.graph is None
    assert with_graph.graph is not None
    assert with_graph.graph_summary is not None


def test_analyze_with_assets_enriches_graph() -> None:
    """Asset inventory adds nodes findings alone didn't surface —
    e.g. a Lambda with attached IAM role that wasn't itself
    flagged by any CSPM check."""
    report = analyze_cloud_attack_paths(
        cspm_findings=[],
        cloud_assets=[
            {
                "arn": "arn:aws:lambda:us-east-1:1:function:api",
                "kind": "lambda_function",
                "is_public": True,
                "attached_role_arn": "arn:aws:iam::1:role/api",
            },
            {
                "arn": "arn:aws:iam::1:role/api",
                "kind": "iam_role",
            },
        ],
        include_graph=True,
    )
    assert report.assets_consumed == 2
    # The internet_exposed_compute_with_iam pattern should fire.
    assert any(
        p.pattern_id == "cap_internet_exposed_compute_with_iam"
        for p in report.paths
    )


# ---------------------------------------------------------------------------
# Output shape — must be JSON-serialisable for the wrapper to
# persist + render
# ---------------------------------------------------------------------------


def test_report_to_dict_is_json_safe() -> None:
    findings = [
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::tfstate"),
    ]
    report = analyze_cloud_attack_paths(
        cspm_findings=findings, include_graph=True,
    )
    payload = json.dumps(report.to_dict())  # must not raise
    parsed = json.loads(payload)
    assert "summary" in parsed
    assert "paths" in parsed
    assert "graph_summary" in parsed


def test_report_summary_carries_per_severity_counts() -> None:
    report = analyze_cloud_attack_paths(cspm_findings=[
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::tfstate-prod"),
        _f("AWS_IAM_ROOT_ACCESS_KEY",
           arn="arn:aws:iam::1:root", sev="critical"),
    ])
    s = report.summary
    assert "total" in s
    assert "critical" in s
    assert "high" in s
    assert s["total"] == s["critical"] + s["high"] + s.get("medium", 0) \
        + s.get("low", 0) + s.get("info", 0)


def test_report_summary_carries_per_pattern_counts() -> None:
    report = analyze_cloud_attack_paths(cspm_findings=[
        _f("AWS_IAM_ROOT_ACCESS_KEY", arn="arn:aws:iam::1:root"),
    ])
    s = report.summary
    # At least one `pattern:cap_*` key must be present in summary.
    pattern_keys = [k for k in s if k.startswith("pattern:cap_")]
    assert pattern_keys


def test_critical_paths_method_returns_only_critical() -> None:
    report = analyze_cloud_attack_paths(cspm_findings=[
        _f("AWS_IAM_ROOT_ACCESS_KEY", arn="arn:aws:iam::1:root"),
    ])
    crit = report.critical_paths()
    assert all(p.severity == "critical" for p in crit)


# ---------------------------------------------------------------------------
# Pattern allowlist passthrough
# ---------------------------------------------------------------------------


def test_pattern_allowlist_restricts_to_subset() -> None:
    """Wrappers can run a pattern subset for fast / focused scans."""
    findings = [
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::tfstate"),
        _f("AWS_IAM_ROOT_ACCESS_KEY", arn="arn:aws:iam::1:root"),
    ]
    report = analyze_cloud_attack_paths(
        cspm_findings=findings,
        patterns=["cap_root_unsafe"],
    )
    assert all(p.pattern_id == "cap_root_unsafe" for p in report.paths)


def test_custom_patterns_passthrough_works() -> None:
    """Wrapper-provided custom pattern functions are honoured."""
    findings = [_f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::x")]

    def _custom(graph):
        return [AttackPath(
            pattern_id="wrapper_custom_audit",
            title="custom check",
            severity="medium",
            narrative="custom",
            hops=[],
        )]

    report = analyze_cloud_attack_paths(
        cspm_findings=findings,
        patterns=["wrapper_custom_audit"],
        custom_patterns={"wrapper_custom_audit": _custom},
    )
    assert any(p.pattern_id == "wrapper_custom_audit" for p in report.paths)
