"""Tests for AWS Organizations auto-enumeration
(`enumerate_org_accounts` + specialist integration).

Hermetic — all boto3 dependencies DI'd."""

from __future__ import annotations

from typing import Any

import pytest

from strix.cloud_attack_paths import multi_account as ma_module
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.multi_account import enumerate_org_accounts
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _FakeClient:
    def __init__(self, paginators=None):
        self._paginators = paginators or {}

    def get_paginator(self, name):
        if name not in self._paginators:
            raise AttributeError(f"no paginator `{name}`")
        return _Paginator(self._paginators[name])


def _make_factory_returning(organizations_client) -> Any:
    """Build a fake factory that returns the given organizations
    client when called with service='organizations'."""
    def _factory(service, region=None):
        if service == "organizations":
            return organizations_client
        raise KeyError(f"unexpected service: {service}")
    return _factory


# ---------------------------------------------------------------------------
# enumerate_org_accounts — happy path
# ---------------------------------------------------------------------------


def test_enumerate_returns_role_arns_for_active_accounts() -> None:
    org = _FakeClient(paginators={
        "list_accounts": [{
            "Accounts": [
                {"Id": "111111111111", "Status": "ACTIVE"},
                {"Id": "222222222222", "Status": "ACTIVE"},
                {"Id": "333333333333", "Status": "SUSPENDED"},
            ],
        }],
    })
    arns = enumerate_org_accounts(
        _make_factory=lambda **_: _make_factory_returning(org),
    )
    # Only active accounts in the output; suspended skipped.
    assert arns == [
        "arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
        "arn:aws:iam::222222222222:role/OrganizationAccountAccessRole",
    ]


def test_enumerate_honours_custom_role_name() -> None:
    org = _FakeClient(paginators={
        "list_accounts": [{
            "Accounts": [
                {"Id": "111", "Status": "ACTIVE"},
            ],
        }],
    })
    arns = enumerate_org_accounts(
        role_name_template="strix-readonly-audit",
        _make_factory=lambda **_: _make_factory_returning(org),
    )
    assert arns == [
        "arn:aws:iam::111:role/strix-readonly-audit",
    ]


def test_enumerate_handles_multiple_pages() -> None:
    org = _FakeClient(paginators={
        "list_accounts": [
            {"Accounts": [{"Id": "111", "Status": "ACTIVE"}]},
            {"Accounts": [{"Id": "222", "Status": "ACTIVE"}]},
        ],
    })
    arns = enumerate_org_accounts(
        _make_factory=lambda **_: _make_factory_returning(org),
    )
    assert len(arns) == 2


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_enumerate_returns_empty_on_factory_failure() -> None:
    def boom(**_):
        raise PermissionError("AccessDenied: AssumeRole")
    arns = enumerate_org_accounts(_make_factory=boom)
    assert arns == []


def test_enumerate_returns_empty_when_organizations_unavailable() -> None:
    """If `organizations:ListAccounts` paginator is missing
    (e.g. not management account), return empty — caller falls
    back to explicit role-arn list."""
    def fake_factory(**_):
        def _f(service, region=None):
            class _NoOrg:
                def get_paginator(self, name):
                    raise AttributeError("organizations not enabled")
            return _NoOrg()
        return _f
    arns = enumerate_org_accounts(_make_factory=fake_factory)
    assert arns == []


def test_enumerate_returns_empty_when_paginator_raises() -> None:
    class _Boom:
        def paginate(self, **_):
            raise PermissionError("ListAccounts denied")

    class _Client:
        def get_paginator(self, _name):
            return _Boom()

    arns = enumerate_org_accounts(
        _make_factory=lambda **_: lambda *a, **k: _Client(),
    )
    assert arns == []


def test_enumerate_skips_accounts_without_id() -> None:
    org = _FakeClient(paginators={
        "list_accounts": [{
            "Accounts": [
                {"Id": "111", "Status": "ACTIVE"},
                {"Status": "ACTIVE"},  # no Id
            ],
        }],
    })
    arns = enumerate_org_accounts(
        _make_factory=lambda **_: _make_factory_returning(org),
    )
    assert len(arns) == 1


# ---------------------------------------------------------------------------
# Specialist integration
# ---------------------------------------------------------------------------


class _StubAwsReport:
    findings: list = []
    errors: list = []
    account_id = "1"
    regions_scanned = ["us-east-1"]
    findings_by_service = {}


def test_specialist_enumerate_org_accounts_flag(monkeypatch) -> None:
    """Setting `enumerate_org_accounts=True` triggers
    `enumerate_org_accounts()` and feeds the result into the
    multi-account fan-out."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    monkeypatch.setattr(
        ma_module, "enumerate_org_accounts",
        lambda **_: [
            "arn:aws:iam::111:role/OrganizationAccountAccessRole",
            "arn:aws:iam::222:role/OrganizationAccountAccessRole",
        ],
    )
    # Stub the actual per-account scan so the multi-account
    # fan-out runs without further boto3.
    monkeypatch.setattr(
        ma_module, "scan_multi_account",
        lambda arns, **_: [
            ma_module.AccountScanResult(role_arn=a) for a in arns
        ],
    )

    result = scan_cloud_attack_paths(
        provider="aws",
        enumerate_org_accounts=True,
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["org_enumerated_accounts"] == 2
    summary = result["tool_metadata"]["multi_account_summary"]
    assert summary["accounts_scanned"] == 2


def test_specialist_combines_org_enum_and_explicit_arns(monkeypatch) -> None:
    """When BOTH `enumerate_org_accounts=True` AND
    `additional_role_arns=[...]` are set, the combined list is
    deduped + scanned."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())
    monkeypatch.setattr(
        ma_module, "enumerate_org_accounts",
        lambda **_: [
            "arn:aws:iam::111:role/OrganizationAccountAccessRole",
            "arn:aws:iam::222:role/OrganizationAccountAccessRole",
        ],
    )
    captured: dict[str, Any] = {}

    def fake_scan_multi(arns, **_):
        captured["arns"] = arns
        return [ma_module.AccountScanResult(role_arn=a) for a in arns]

    monkeypatch.setattr(ma_module, "scan_multi_account", fake_scan_multi)

    result = scan_cloud_attack_paths(
        provider="aws",
        enumerate_org_accounts=True,
        additional_role_arns=[
            # Duplicate of one org-enumerated account.
            "arn:aws:iam::111:role/OrganizationAccountAccessRole",
            "arn:aws:iam::999:role/custom-audit",
        ],
        auto_discover_assets=False,
    )
    # Dedup: 111 + 222 (from org) + 999 (explicit) = 3 unique.
    assert len(captured["arns"]) == 3
    assert "arn:aws:iam::999:role/custom-audit" in captured["arns"]


def test_specialist_enumerate_org_failure_does_not_crash(
    monkeypatch,
) -> None:
    """If org enumeration fails (denied, not management account),
    the rest of the scan still runs — error surfaces in
    cspm_errors."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    def _boom(**_):
        raise RuntimeError("synthetic org-enum failure")

    monkeypatch.setattr(ma_module, "enumerate_org_accounts", _boom)

    result = scan_cloud_attack_paths(
        provider="aws",
        enumerate_org_accounts=True,
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    errors = result["tool_metadata"]["cspm_errors"]
    assert any(e.get("source") == "org_enumeration" for e in errors)


def test_specialist_enumerate_org_default_off(monkeypatch) -> None:
    """Default (no kwarg) doesn't call enumeration."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    def _refuse(**_):
        raise AssertionError(
            "enumerate_org_accounts called without opt-in"
        )

    monkeypatch.setattr(ma_module, "enumerate_org_accounts", _refuse)

    result = scan_cloud_attack_paths(
        provider="aws", auto_discover_assets=False,
    )
    assert "org_enumerated_accounts" not in result["tool_metadata"]
