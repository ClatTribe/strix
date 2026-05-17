"""Tests for Azure asset discovery
(`strix.cloud_attack_paths.azure_discovery`).

Hermetic — Azure SDK is fully DI'd through the `client_factory`
parameter; no real Azure calls."""

from __future__ import annotations

from typing import Any

import pytest

from strix.cloud_attack_paths import azure_discovery as az_module
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.azure_discovery import (
    _is_open_to_internet,
    discover_azure_assets,
)
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths


# ---------------------------------------------------------------------------
# Fake Azure SDK client shapes
# ---------------------------------------------------------------------------


class _AsDict:
    """Fake Azure SDK model — supports `.as_dict()` like the
    real `azure.mgmt.*` models do."""

    def __init__(self, payload: dict):
        self._p = payload

    def as_dict(self) -> dict:
        return dict(self._p)


class _ListOp:
    """Mimics `client.<resource>.list()` / `.list_all()` /
    `.list_for_scope()` returning an iterable of model objects."""

    def __init__(self, items: list[dict]):
        self._items = items

    def __call__(self, *_args, **_kwargs):
        return iter([_AsDict(i) for i in self._items])


class _Subclient:
    """Generic Azure-SDK-shape subclient. Each attribute is a
    `_ListOp` callable."""

    def __init__(self, **ops):
        for k, v in ops.items():
            setattr(self, k, v)


def _build_factory(clients_by_service: dict[str, Any]):
    """Build an Azure client_factory that returns the given fake
    client when called with `service=<key>`."""
    def _factory(service, subscription_id=None):
        if service not in clients_by_service:
            raise KeyError(f"unexpected service: {service}")
        return clients_by_service[service]
    return _factory


# ---------------------------------------------------------------------------
# NSG rule open-to-internet classification
# ---------------------------------------------------------------------------


def test_inbound_allow_any_is_open() -> None:
    assert _is_open_to_internet({
        "direction": "Inbound", "access": "Allow",
        "source_address_prefix": "*",
    })


def test_inbound_allow_0_0_0_0_slash_0_is_open() -> None:
    assert _is_open_to_internet({
        "direction": "Inbound", "access": "Allow",
        "source_address_prefix": "0.0.0.0/0",
    })


def test_inbound_allow_internet_keyword_is_open() -> None:
    assert _is_open_to_internet({
        "direction": "Inbound", "access": "Allow",
        "source_address_prefix": "Internet",
    })


def test_outbound_allow_is_not_open() -> None:
    assert not _is_open_to_internet({
        "direction": "Outbound", "access": "Allow",
        "source_address_prefix": "*",
    })


def test_inbound_deny_is_not_open() -> None:
    assert not _is_open_to_internet({
        "direction": "Inbound", "access": "Deny",
        "source_address_prefix": "*",
    })


def test_inbound_allow_internal_subnet_is_not_open() -> None:
    assert not _is_open_to_internet({
        "direction": "Inbound", "access": "Allow",
        "source_address_prefix": "10.0.0.0/8",
    })


# ---------------------------------------------------------------------------
# Storage account discovery
# ---------------------------------------------------------------------------


def test_storage_discovery_emits_account_assets() -> None:
    storage_client = _Subclient(
        storage_accounts=_Subclient(
            list=_ListOp([
                {
                    "id": "/subscriptions/sub-x/storage/sa1",
                    "name": "sa1",
                    "location": "eastus",
                    "allow_blob_public_access": True,
                    "enable_https_traffic_only": True,
                    "minimum_tls_version": "TLS1_2",
                },
                {
                    "id": "/subscriptions/sub-x/storage/sa2",
                    "name": "sa2",
                    "location": "westus",
                    "allow_blob_public_access": False,
                },
            ]),
        ),
    )
    factory = _build_factory({"storage": storage_client})
    out = discover_azure_assets(
        factory, "sub-x", services=["storage"],
    )
    assert len(out) == 2
    sa1 = next(a for a in out if a["name"] == "sa1")
    assert sa1["is_public"] is True
    assert sa1["kind"] == "azure_storage_account"
    sa2 = next(a for a in out if a["name"] == "sa2")
    assert sa2["is_public"] is False


# ---------------------------------------------------------------------------
# VM discovery
# ---------------------------------------------------------------------------


def test_compute_discovery_propagates_managed_identity() -> None:
    compute_client = _Subclient(
        virtual_machines=_Subclient(
            list_all=_ListOp([
                {
                    "id": "/subscriptions/sub-x/vm/vm-1",
                    "name": "vm-1",
                    "location": "eastus",
                    "identity": {"principal_id": "pid-1"},
                },
                {
                    "id": "/subscriptions/sub-x/vm/vm-2",
                    "name": "vm-2",
                    "identity": None,
                },
            ]),
        ),
    )
    out = discover_azure_assets(
        _build_factory({"compute": compute_client}),
        "sub-x", services=["compute"],
    )
    vm1 = next(a for a in out if a["name"] == "vm-1")
    assert vm1["managed_identity_principal_id"] == "pid-1"
    assert vm1["attached_identity_arn"].endswith("pid-1")
    vm2 = next(a for a in out if a["name"] == "vm-2")
    assert vm2["managed_identity_principal_id"] is None


# ---------------------------------------------------------------------------
# Network discovery (NSGs + public IPs)
# ---------------------------------------------------------------------------


def test_network_discovery_flags_internet_open_nsg() -> None:
    network_client = _Subclient(
        network_security_groups=_Subclient(
            list_all=_ListOp([
                {
                    "id": "/subscriptions/sub-x/nsg/nsg-open",
                    "name": "nsg-open",
                    "security_rules": [
                        {
                            "name": "AllowSSH",
                            "direction": "Inbound",
                            "access": "Allow",
                            "source_address_prefix": "*",
                            "destination_port_range": "22",
                            "protocol": "Tcp",
                        },
                    ],
                },
                {
                    "id": "/subscriptions/sub-x/nsg/nsg-closed",
                    "name": "nsg-closed",
                    "security_rules": [
                        {
                            "direction": "Inbound",
                            "access": "Allow",
                            "source_address_prefix": "10.0.0.0/8",
                        },
                    ],
                },
            ]),
        ),
        public_ip_addresses=_Subclient(
            list_all=_ListOp([
                {
                    "id": "/subscriptions/sub-x/ip/ip-1",
                    "name": "ip-1",
                    "ip_address": "1.2.3.4",
                },
                # Empty ip_address — skipped.
                {"id": "x", "name": "y", "ip_address": ""},
            ]),
        ),
    )
    out = discover_azure_assets(
        _build_factory({"network": network_client}),
        "sub-x", services=["network"],
    )
    nsgs = [a for a in out if a["kind"] == "azure_nsg"]
    assert {n["name"] for n in nsgs} == {"nsg-open", "nsg-closed"}
    open_nsg = next(n for n in nsgs if n["name"] == "nsg-open")
    closed_nsg = next(n for n in nsgs if n["name"] == "nsg-closed")
    assert open_nsg["is_public"] is True
    assert open_nsg["open_rules"][0]["ports"] == "22"
    assert closed_nsg["is_public"] is False

    ips = [a for a in out if a["kind"] == "azure_public_ip"]
    assert len(ips) == 1
    assert ips[0]["ip_address"] == "1.2.3.4"
    assert ips[0]["is_public"] is True


# ---------------------------------------------------------------------------
# RBAC discovery (role definitions + assignments)
# ---------------------------------------------------------------------------


def test_rbac_discovery_inlines_role_def_statements_on_principal() -> None:
    """The whole point of RBAC enumeration: each role assignment
    surfaces a principal asset whose `statements` field carries
    the role definition's actions. This is what feeds the
    has_policy edge in ingest."""
    auth_client = _Subclient(
        role_definitions=_Subclient(
            list=_ListOp([
                {
                    "id": "/role-def/owner",
                    "role_name": "Owner",
                    "permissions": [
                        {"actions": ["*"], "not_actions": []},
                    ],
                },
                {
                    "id": "/role-def/reader",
                    "role_name": "Reader",
                    "permissions": [
                        {"actions": ["*/read"], "not_actions": []},
                    ],
                },
            ]),
        ),
        role_assignments=_Subclient(
            list_for_scope=_ListOp([
                {
                    "principal_id": "user-1",
                    "principal_type": "User",
                    "role_definition_id": "/role-def/owner",
                    "scope": "/subscriptions/sub-x",
                },
                # Missing principal_id → skipped.
                {"role_definition_id": "/role-def/reader"},
            ]),
        ),
    )
    out = discover_azure_assets(
        _build_factory({"authorization": auth_client}),
        "sub-x", services=["authorization"],
    )
    # Role definitions emitted as their own asset kind.
    rds = [a for a in out if a["kind"] == "azure_role_definition"]
    assert len(rds) == 2

    # Principal emitted with inlined Owner statements.
    principals = [a for a in out if a["kind"] == "azure_identity"]
    assert len(principals) == 1
    p = principals[0]
    assert p["principal_id"] == "user-1"
    assert p["principal_type"] == "User"
    # Statements were inlined from the Owner role definition.
    assert p["statements"][0]["Action"] == ["*"]


# ---------------------------------------------------------------------------
# Key Vault discovery
# ---------------------------------------------------------------------------


def test_keyvault_discovery_flags_public_default_allow() -> None:
    kv_client = _Subclient(
        vaults=_Subclient(
            list=_ListOp([
                {
                    "id": "/subscriptions/sub-x/kv/kv-public",
                    "name": "kv-public",
                    "properties": {
                        "network_acls": {
                            "default_action": "Allow",
                            "ip_rules": [],
                        },
                        "enable_rbac_authorization": True,
                    },
                },
                {
                    "id": "/subscriptions/sub-x/kv/kv-private",
                    "name": "kv-private",
                    "properties": {
                        "network_acls": {
                            "default_action": "Deny",
                            "ip_rules": [{"value": "1.2.3.4"}],
                        },
                    },
                },
            ]),
        ),
    )
    out = discover_azure_assets(
        _build_factory({"keyvault": kv_client}),
        "sub-x", services=["keyvault"],
    )
    pub = next(a for a in out if a["name"] == "kv-public")
    priv = next(a for a in out if a["name"] == "kv-private")
    assert pub["is_public"] is True
    assert priv["is_public"] is False


# ---------------------------------------------------------------------------
# Web app discovery
# ---------------------------------------------------------------------------


def test_web_discovery_distinguishes_functions_vs_app_service() -> None:
    web_client = _Subclient(
        web_apps=_Subclient(
            list=_ListOp([
                {
                    "id": "/subscriptions/sub-x/sites/api-prod",
                    "name": "api-prod",
                    "kind": "app,linux",
                    "host_names": ["api.example.com"],
                    "https_only": True,
                    "identity": {"principal_id": "site-pid"},
                },
                {
                    "id": "/subscriptions/sub-x/sites/fn-prod",
                    "name": "fn-prod",
                    "kind": "functionapp,linux",
                    "host_names": ["fn.example.com"],
                    "https_only": False,
                },
            ]),
        ),
    )
    out = discover_azure_assets(
        _build_factory({"web": web_client}),
        "sub-x", services=["web"],
    )
    api = next(a for a in out if a["name"] == "api-prod")
    fn = next(a for a in out if a["name"] == "fn-prod")
    assert api["kind"] == "azure_app_service"
    assert fn["kind"] == "azure_function_app"
    assert api["managed_identity_principal_id"] == "site-pid"
    assert api["is_public"] is True


# ---------------------------------------------------------------------------
# ACR discovery
# ---------------------------------------------------------------------------


def test_acr_discovery_flags_anonymous_pull() -> None:
    acr_client = _Subclient(
        registries=_Subclient(
            list=_ListOp([
                {
                    "id": "/subscriptions/sub-x/acr/dangerous",
                    "name": "dangerous",
                    "admin_user_enabled": True,
                    "anonymous_pull_enabled": True,
                    "public_network_access": "Enabled",
                },
                {
                    "id": "/subscriptions/sub-x/acr/locked-down",
                    "name": "locked-down",
                    "admin_user_enabled": False,
                    "anonymous_pull_enabled": False,
                    "public_network_access": "Disabled",
                },
            ]),
        ),
    )
    out = discover_azure_assets(
        _build_factory({"containerregistry": acr_client}),
        "sub-x", services=["containerregistry"],
    )
    danger = next(a for a in out if a["name"] == "dangerous")
    safe = next(a for a in out if a["name"] == "locked-down")
    assert danger["anonymous_pull_enabled"] is True
    assert danger["is_public"] is True
    assert safe["is_public"] is False


# ---------------------------------------------------------------------------
# Resilience: per-service failure isolation
# ---------------------------------------------------------------------------


def test_per_service_failure_isolated() -> None:
    """If one service's client build fails, the others still
    return their assets — partial discovery is the contract."""
    def _factory(service, subscription_id=None):
        if service == "storage":
            raise PermissionError("denied")
        if service == "compute":
            return _Subclient(virtual_machines=_Subclient(
                list_all=_ListOp([
                    {"id": "/vm-1", "name": "vm-1", "identity": None},
                ]),
            ))
        raise KeyError(service)
    out = discover_azure_assets(
        _factory, "sub-x",
        services=["storage", "compute"],
    )
    # Storage failed → no storage assets. Compute succeeded → VM
    # surfaces.
    assert len(out) == 1
    assert out[0]["kind"] == "azure_vm"


def test_unknown_service_filtered_out() -> None:
    """`services=['nope']` returns empty without crashing."""
    out = discover_azure_assets(
        lambda *a, **k: (_ for _ in ()).throw(KeyError("x")),
        "sub-x", services=["nope-not-real"],
    )
    assert out == []


# ---------------------------------------------------------------------------
# max_items_per_service cap
# ---------------------------------------------------------------------------


def test_per_service_cap_bounds_enumeration() -> None:
    big = [
        {"id": f"/sa-{n}", "name": f"sa-{n}"}
        for n in range(100)
    ]
    storage_client = _Subclient(
        storage_accounts=_Subclient(list=_ListOp(big)),
    )
    out = discover_azure_assets(
        _build_factory({"storage": storage_client}),
        "sub-x",
        services=["storage"],
        max_items_per_service=10,
    )
    assert len(out) == 10


# ---------------------------------------------------------------------------
# Specialist integration
# ---------------------------------------------------------------------------


class _StubProwlerEngine:
    """Stub matching `cspm/prowler.py`'s `is_prowler_available`
    + the Prowler shim invoked for non-AWS providers."""


def test_specialist_azure_discovery_runs_when_flag_set(
    monkeypatch,
) -> None:
    """Setting `provider="azure"` + `azure_subscription_id` +
    `_azure_client_factory=<stub>` calls `discover_azure_assets`
    and the count surfaces in `tool_metadata`."""
    # Stub the CSPM-collection step so we don't need real Azure
    # Prowler. Returns one Azure-shaped finding to satisfy the
    # "engine != none" branch.
    from strix.cspm.aws import CspmFinding

    def fake_collect(**_):
        finding = CspmFinding(
            rule_id="azure_storage_public",
            severity="high",
            message="public storage",
            service="azure_storage",
            region="eastus",
            resource_arn="/subscriptions/sub-x/sa/sa1",
            cwe="CWE-200",
            category="cspm_misconfig",
            metadata={},
        )
        return [finding], "azure-stub", [], {}

    monkeypatch.setattr(
        tools_module, "_collect_cspm_findings", fake_collect,
    )

    storage_client = _Subclient(
        storage_accounts=_Subclient(
            list=_ListOp([
                {"id": "/sa-1", "name": "sa-1",
                 "allow_blob_public_access": True},
            ]),
        ),
    )
    az_factory = _build_factory({"storage": storage_client})

    result = scan_cloud_attack_paths(
        provider="azure",
        azure_subscription_id="sub-x",
        azure_services=["storage"],
        _azure_client_factory=az_factory,
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["azure_assets_discovered"] == 1


def test_specialist_azure_discovery_skipped_without_subscription_id(
    monkeypatch,
) -> None:
    """No `azure_subscription_id` → discovery is skipped silently;
    the rest of the scan runs."""
    from strix.cspm.aws import CspmFinding

    def fake_collect(**_):
        return [CspmFinding(
            rule_id="x", severity="low", message="x",
            service="azure", region="eastus", resource_arn="x",
            cwe=None, category="cspm_misconfig", metadata={},
        )], "azure-stub", [], {}

    monkeypatch.setattr(
        tools_module, "_collect_cspm_findings", fake_collect,
    )

    def _refuse(*a, **kw):
        raise AssertionError("discover_azure_assets should not run")

    monkeypatch.setattr(
        az_module, "discover_azure_assets", _refuse,
    )

    result = scan_cloud_attack_paths(
        provider="azure", auto_discover_assets=False,
    )
    assert "azure_assets_discovered" not in result["tool_metadata"]


def test_specialist_azure_discovery_failure_does_not_crash(
    monkeypatch,
) -> None:
    """Discovery crash surfaces in cspm_errors; scan continues."""
    from strix.cspm.aws import CspmFinding

    def fake_collect(**_):
        return [CspmFinding(
            rule_id="x", severity="low", message="x",
            service="azure", region="eastus", resource_arn="x",
            cwe=None, category="cspm_misconfig", metadata={},
        )], "azure-stub", [], {}

    monkeypatch.setattr(
        tools_module, "_collect_cspm_findings", fake_collect,
    )

    def _boom(*a, **kw):
        raise RuntimeError("synthetic discovery crash")

    monkeypatch.setattr(
        "strix.cloud_attack_paths.azure_discovery.discover_azure_assets",
        _boom,
    )

    result = scan_cloud_attack_paths(
        provider="azure",
        azure_subscription_id="sub-x",
        _azure_client_factory=lambda *a, **k: object(),
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    errors = result["tool_metadata"]["cspm_errors"]
    assert any(
        e.get("source") == "azure_discovery" for e in errors
    )
