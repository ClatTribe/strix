"""Tests for multi-account AWS scanner (`strix.cloud_attack_paths.multi_account`).

Hermetic — all four DI'd dependencies (`_make_factory`,
`_scan_aws_account`, `_discover_aws_assets`,
`_get_caller_account_id`) are stubbed. No real boto3 calls.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.multi_account import (
    AccountScanResult,
    scan_multi_account,
    summarise,
    union_assets,
    union_findings,
)
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths
from strix.cspm.aws import CspmFinding


def _f(rule_id: str, *, arn: str, sev="high") -> CspmFinding:
    return CspmFinding(
        rule_id=rule_id, severity=sev,
        message=f"{rule_id} on {arn}",
        service="s3", region=None, resource_arn=arn,
        account_id="1", cwe="CWE-732", category="misconfig",
    )


class _StubAwsReport:
    """Mirror of `AwsCspmReport` — only the fields multi-account
    reads."""

    def __init__(self, findings, errors=None):
        self.findings = list(findings)
        self.errors = list(errors or [])
        self.account_id = "stub"
        self.regions_scanned = ["us-east-1"]


# ---------------------------------------------------------------------------
# scan_multi_account — happy paths
# ---------------------------------------------------------------------------


def test_scan_multi_account_returns_per_role_result() -> None:
    """One AccountScanResult per input role_arn, in order."""
    arns = [
        "arn:aws:iam::111111111111:role/audit",
        "arn:aws:iam::222222222222:role/audit",
    ]

    def fake_make_factory(*, profile_name=None, role_arn=None):
        return f"factory-for-{role_arn}"

    def fake_scan_aws_account(*, regions=None, client_factory=None):
        # Each per-account scan returns a 1-finding report.
        return _StubAwsReport([
            _f("AWS_S3_PUBLIC_ACL",
               arn=f"arn:aws:s3:::bucket-{client_factory}"),
        ])

    def fake_discover(_factory, *, regions=None, services=None):
        return [{"arn": f"arn:aws:s3:::asset-{_factory}",
                 "kind": "s3_bucket"}]

    def fake_get_account(_factory):
        # Pull account from the fake factory string.
        if "111111111111" in str(_factory):
            return "111111111111"
        if "222222222222" in str(_factory):
            return "222222222222"
        return None

    results = scan_multi_account(
        arns,
        _make_factory=fake_make_factory,
        _scan_aws_account=fake_scan_aws_account,
        _discover_aws_assets=fake_discover,
        _get_caller_account_id=fake_get_account,
    )
    assert len(results) == 2
    assert results[0].role_arn == arns[0]
    assert results[0].account_id == "111111111111"
    assert results[0].findings
    assert results[0].assets
    assert results[1].account_id == "222222222222"


def test_assume_role_failure_does_not_stop_other_accounts() -> None:
    """If one role fails assume-role, the rest still scan."""
    arns = [
        "arn:aws:iam::111111111111:role/audit",  # fails
        "arn:aws:iam::222222222222:role/audit",  # succeeds
    ]

    def fake_make_factory(*, profile_name=None, role_arn=None):
        if "111111111111" in role_arn:
            raise PermissionError("AccessDenied: AssumeRole")
        return f"factory-for-{role_arn}"

    def fake_scan_aws_account(*, regions=None, client_factory=None):
        return _StubAwsReport([
            _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::ok"),
        ])

    results = scan_multi_account(
        arns,
        _make_factory=fake_make_factory,
        _scan_aws_account=fake_scan_aws_account,
        _discover_aws_assets=lambda *a, **kw: [],
        _get_caller_account_id=lambda _f: "222222222222",
    )
    assert len(results) == 2
    # First failed; second succeeded.
    assert any(e.get("stage") == "assume_role"
               for e in results[0].errors)
    assert results[0].findings == []
    assert results[1].findings  # second role scanned cleanly


def test_per_stage_errors_isolated() -> None:
    """If CSPM scan succeeds but discovery fails, findings still
    accumulate; discovery failure recorded as soft error."""
    arns = ["arn:aws:iam::111:role/r"]

    def fake_scan(*, regions=None, client_factory=None):
        return _StubAwsReport([
            _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::ok"),
        ])

    def boom_discover(*a, **kw):
        raise RuntimeError("discovery broke")

    results = scan_multi_account(
        arns,
        _make_factory=lambda **_: "factory",
        _scan_aws_account=fake_scan,
        _discover_aws_assets=boom_discover,
        _get_caller_account_id=lambda _f: "111",
    )
    assert len(results) == 1
    r = results[0]
    assert r.findings  # CSPM ran fine
    assert any(e.get("stage") == "discovery" for e in r.errors)


def test_cspm_failure_recorded_but_does_not_break_pipeline() -> None:
    arns = ["arn:aws:iam::111:role/r"]

    def boom_scan(**_kwargs):
        raise RuntimeError("cspm broke")

    results = scan_multi_account(
        arns,
        _make_factory=lambda **_: "factory",
        _scan_aws_account=boom_scan,
        _discover_aws_assets=lambda *a, **kw: [
            {"arn": "arn:aws:s3:::discovered", "kind": "s3_bucket"},
        ],
        _get_caller_account_id=lambda _f: "111",
    )
    r = results[0]
    assert any(e.get("stage") == "cspm" for e in r.errors)
    # Discovery still ran.
    assert r.assets


def test_empty_role_arns_returns_empty() -> None:
    assert scan_multi_account([]) == []


def test_get_caller_account_id_failure_silent() -> None:
    """Missing account_id is non-fatal — the result still emits
    with `account_id=None`."""

    def fake_get_account(_factory):
        raise RuntimeError("sts call denied")

    results = scan_multi_account(
        ["arn:aws:iam::111:role/r"],
        _make_factory=lambda **_: "factory",
        _scan_aws_account=lambda **_: _StubAwsReport([]),
        _discover_aws_assets=lambda *a, **kw: [],
        _get_caller_account_id=fake_get_account,
    )
    assert results[0].account_id is None


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------


def test_union_findings_concats_per_account() -> None:
    r1 = AccountScanResult(role_arn="a", findings=[
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::b1"),
    ])
    r2 = AccountScanResult(role_arn="b", findings=[
        _f("AWS_IAM_ROOT_ACCESS_KEY", arn="arn:aws:iam::*:root"),
    ])
    out = union_findings([r1, r2])
    assert len(out) == 2


def test_union_assets_concats_per_account() -> None:
    r1 = AccountScanResult(role_arn="a", assets=[
        {"arn": "arn:aws:s3:::b1", "kind": "s3_bucket"},
    ])
    r2 = AccountScanResult(role_arn="b", assets=[
        {"arn": "arn:aws:s3:::b2", "kind": "s3_bucket"},
    ])
    out = union_assets([r1, r2])
    assert len(out) == 2


def test_summarise_counts_succeeded_vs_failed() -> None:
    succeeded = AccountScanResult(role_arn="a")
    failed = AccountScanResult(
        role_arn="b",
        errors=[{"stage": "assume_role", "error": "AccessDenied"}],
    )
    s = summarise([succeeded, failed])
    assert s["accounts_scanned"] == 2
    assert s["accounts_succeeded"] == 1
    assert s["accounts_failed_assume_role"] == 1


def test_summarise_per_account_breakdown() -> None:
    r = AccountScanResult(
        role_arn="arn:aws:iam::1:role/r",
        account_id="1",
        findings=[_f("X", arn="arn:aws:s3:::x")],
        assets=[{"arn": "arn:aws:s3:::y", "kind": "s3_bucket"}],
    )
    s = summarise([r])
    per = s["per_account"][0]
    assert per["role_arn"] == "arn:aws:iam::1:role/r"
    assert per["account_id"] == "1"
    assert per["findings_count"] == 1
    assert per["assets_count"] == 1


# ---------------------------------------------------------------------------
# Specialist integration — additional_role_arns threads through
# ---------------------------------------------------------------------------


def test_specialist_fans_out_to_additional_role_arns(monkeypatch) -> None:
    """`scan_cloud_attack_paths(additional_role_arns=[...])`
    invokes scan_multi_account and unions the findings into the
    main analysis."""
    # Primary CSPM stub.
    class _PrimaryReport:
        findings = [_f("AWS_S3_PUBLIC_ACL",
                        arn="arn:aws:s3:::primary-bucket",
                        sev="critical")]
        errors = []
        account_id = "primary"
        regions_scanned = ["us-east-1"]
        findings_by_service = {"s3": 1}

    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _PrimaryReport())

    # Multi-account stub.
    from strix.cloud_attack_paths import multi_account as ma_module

    def stub_scan_multi(arns, **_):
        return [
            AccountScanResult(
                role_arn=arns[0],
                account_id="secondary",
                findings=[_f("AWS_IAM_ROOT_ACCESS_KEY",
                              arn="arn:aws:iam::secondary:root",
                              sev="critical")],
                assets=[],
            ),
        ]

    monkeypatch.setattr(ma_module, "scan_multi_account",
                        stub_scan_multi)

    result = scan_cloud_attack_paths(
        provider="aws",
        additional_role_arns=["arn:aws:iam::secondary:role/audit"],
        # Disable downstream pipelines for test focus.
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    assert "multi_account_summary" in result["tool_metadata"]
    summary = result["tool_metadata"]["multi_account_summary"]
    assert summary["accounts_scanned"] == 1
    assert summary["total_findings"] == 1
    # Both primary + secondary patterns should fire.
    pattern_keys = [
        k for k in result["tool_metadata"]["attack_paths_summary"]
        if k.startswith("pattern:")
    ]
    # At least cap_public_storage_credentials_risk (from primary
    # bucket) AND cap_root_unsafe (from secondary account).
    found_patterns = "\n".join(pattern_keys)
    assert "cap_public_storage_credentials_risk" in found_patterns
    assert "cap_root_unsafe" in found_patterns


def test_specialist_no_additional_role_arns_keeps_legacy_shape(
    monkeypatch,
) -> None:
    """Default behaviour (no `additional_role_arns`) — no
    multi_account_summary in tool_metadata."""

    class _Report:
        findings = [_f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::x")]
        errors = []
        account_id = "1"
        regions_scanned = ["us-east-1"]
        findings_by_service = {"s3": 1}

    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _Report())

    result = scan_cloud_attack_paths(
        provider="aws", auto_discover_assets=False,
    )
    assert "multi_account_summary" not in result["tool_metadata"]


def test_specialist_multi_account_only_runs_on_aws(monkeypatch) -> None:
    """`additional_role_arns` is ignored for non-AWS providers."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: True)
    # Prowler stub.
    from strix.cspm.prowler import ProwlerScanResult
    monkeypatch.setattr(
        tools_module, "run_prowler",
        lambda **_: ProwlerScanResult(provider="azure", findings=[]),
    )
    # Multi-account scan must NOT be called.
    from strix.cloud_attack_paths import multi_account as ma_module
    monkeypatch.setattr(
        ma_module, "scan_multi_account",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("multi-account should not run on Azure"),
        ),
    )

    result = scan_cloud_attack_paths(
        provider="azure",
        additional_role_arns=["arn:aws:iam::1:role/r"],
        auto_discover_assets=False,
    )
    # No multi_account_summary recorded.
    assert "multi_account_summary" not in result["tool_metadata"]
