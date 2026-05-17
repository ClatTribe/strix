"""Tests for GCP asset discovery
(`strix.cloud_attack_paths.gcp_discovery`).

Hermetic — google-cloud-* SDK is fully DI'd through the
`client_factory` parameter; no real GCP calls."""

from __future__ import annotations

from typing import Any

import pytest

from strix.cloud_attack_paths import gcp_discovery as gcp_module
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.gcp_discovery import (
    _bindings_to_statements,
    _firewall_is_internet_open,
    _vm_is_public,
    discover_gcp_assets,
)
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths


# ---------------------------------------------------------------------------
# Fake google-cloud SDK shapes
# ---------------------------------------------------------------------------


class _ToDict:
    """Fake google-cloud proto object — supports `.to_dict()`."""

    def __init__(self, payload: dict):
        self._p = payload

    def to_dict(self) -> dict:
        return dict(self._p)


class _ListOp:
    def __init__(self, items: list[dict]):
        self._items = items

    def __call__(self, *_args, **_kwargs):
        return iter([_ToDict(i) for i in self._items])


class _Returning:
    def __init__(self, value):
        self._v = value

    def __call__(self, *_args, **_kwargs):
        return _ToDict(self._v) if isinstance(self._v, dict) else self._v


class _Client:
    def __init__(self, **ops):
        for k, v in ops.items():
            setattr(self, k, v)


def _factory(clients: dict[str, Any]):
    def _f(service, project_id=None):
        if service not in clients:
            raise KeyError(f"unexpected service: {service}")
        return clients[service]
    return _f


# ---------------------------------------------------------------------------
# _bindings_to_statements helper
# ---------------------------------------------------------------------------


def test_owner_role_maps_to_wildcard_action() -> None:
    statements, is_public = _bindings_to_statements([
        {"role": "roles/owner", "members": ["user:alice@x.com"]},
    ])
    assert statements[0]["Action"] == ["*"]
    assert is_public is False


def test_non_admin_role_keeps_specific_action() -> None:
    statements, _ = _bindings_to_statements([
        {"role": "roles/storage.objectViewer",
         "members": ["user:bob@x.com"]},
    ])
    assert statements[0]["Action"] == ["roles/storage.objectViewer"]


def test_all_users_member_flags_public() -> None:
    _, is_public = _bindings_to_statements([
        {"role": "roles/storage.objectViewer",
         "members": ["allUsers"]},
    ])
    assert is_public is True


def test_all_authenticated_users_flags_public() -> None:
    _, is_public = _bindings_to_statements([
        {"role": "roles/run.invoker",
         "members": ["allAuthenticatedUsers"]},
    ])
    assert is_public is True


def test_internal_member_not_flagged_public() -> None:
    _, is_public = _bindings_to_statements([
        {"role": "roles/owner",
         "members": ["serviceAccount:foo@proj.iam"]},
    ])
    assert is_public is False


# ---------------------------------------------------------------------------
# _vm_is_public helper
# ---------------------------------------------------------------------------


def test_vm_with_access_configs_is_public() -> None:
    assert _vm_is_public({
        "network_interfaces": [
            {"access_configs": [{"nat_ip": "1.2.3.4"}]},
        ],
    })


def test_vm_with_camel_case_access_configs_is_public() -> None:
    """GCP SDK sometimes returns camelCase keys."""
    assert _vm_is_public({
        "network_interfaces": [
            {"accessConfigs": [{"natIP": "1.2.3.4"}]},
        ],
    })


def test_vm_without_external_ip_is_private() -> None:
    assert not _vm_is_public({
        "network_interfaces": [
            {"network_ip": "10.0.0.5"},
        ],
    })


# ---------------------------------------------------------------------------
# _firewall_is_internet_open helper
# ---------------------------------------------------------------------------


def test_ingress_allow_0_0_0_0_is_open() -> None:
    assert _firewall_is_internet_open({
        "direction": "INGRESS",
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        "source_ranges": ["0.0.0.0/0"],
    })


def test_egress_is_never_open() -> None:
    assert not _firewall_is_internet_open({
        "direction": "EGRESS",
        "allowed": [{"IPProtocol": "tcp"}],
        "source_ranges": ["0.0.0.0/0"],
    })


def test_internal_source_is_not_open() -> None:
    assert not _firewall_is_internet_open({
        "direction": "INGRESS",
        "allowed": [{"IPProtocol": "tcp"}],
        "source_ranges": ["10.0.0.0/8"],
    })


# ---------------------------------------------------------------------------
# Storage discovery
# ---------------------------------------------------------------------------


def test_storage_discovery_extracts_bucket_iam_publicness() -> None:
    """Per-bucket IAM policy with `allUsers` → is_public=True."""

    class _Bucket(_ToDict):
        def get_iam_policy(self):
            return _ToDict({
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"],
                    },
                ],
            })

    storage_client = _Client(
        list_buckets=lambda: iter([
            _Bucket({
                "name": "public-bucket",
                "location": "US",
            }),
        ]),
    )
    out = discover_gcp_assets(
        _factory({"storage": storage_client}),
        "proj-x", services=["storage"],
    )
    assert len(out) == 1
    assert out[0]["is_public"] is True
    assert out[0]["kind"] == "gcs_bucket"


# ---------------------------------------------------------------------------
# Compute discovery
# ---------------------------------------------------------------------------


def test_compute_discovery_extracts_service_account_and_public_ip() -> None:
    compute_client = _Client(
        list_instances_aggregated=_ListOp([
            {
                "self_link": "//compute/proj-x/instance/web-1",
                "name": "web-1",
                "zone": "us-central1-a",
                "machine_type": "e2-medium",
                "status": "RUNNING",
                "network_interfaces": [
                    {"access_configs": [{"nat_ip": "34.x.x.x"}]},
                ],
                "service_accounts": [
                    {"email": "sa-prod@proj-x.iam.gserviceaccount.com"},
                ],
                "tags": {"items": ["web", "prod"]},
            },
        ]),
    )
    out = discover_gcp_assets(
        _factory({"compute": compute_client}),
        "proj-x", services=["compute"],
    )
    assert len(out) == 1
    vm = out[0]
    assert vm["kind"] == "gcp_compute_instance"
    assert vm["is_public"] is True
    assert vm["service_account_email"].startswith("sa-prod@")
    assert vm["attached_identity_arn"].endswith(
        "sa-prod@proj-x.iam.gserviceaccount.com",
    )
    assert vm["tags"] == ["web", "prod"]


# ---------------------------------------------------------------------------
# Firewall discovery
# ---------------------------------------------------------------------------


def test_firewalls_discovery_flags_internet_open() -> None:
    fw_client = _Client(
        list_firewalls=_ListOp([
            {
                "self_link": "//fw/allow-ssh-from-world",
                "name": "allow-ssh-from-world",
                "direction": "INGRESS",
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "source_ranges": ["0.0.0.0/0"],
                "target_tags": ["web"],
            },
            {
                "self_link": "//fw/internal-only",
                "name": "internal-only",
                "direction": "INGRESS",
                "allowed": [{"IPProtocol": "tcp"}],
                "source_ranges": ["10.0.0.0/8"],
            },
        ]),
    )
    out = discover_gcp_assets(
        _factory({"compute_firewalls": fw_client}),
        "proj-x", services=["firewalls"],
    )
    public = next(a for a in out if a["name"] == "allow-ssh-from-world")
    private = next(a for a in out if a["name"] == "internal-only")
    assert public["is_public"] is True
    assert private["is_public"] is False


# ---------------------------------------------------------------------------
# IAM discovery (service accounts + project bindings)
# ---------------------------------------------------------------------------


def test_iam_discovery_emits_sa_and_inlines_member_bindings() -> None:
    iam_client = _Client(
        list_service_accounts=_ListOp([
            {
                "email": "compute-sa@proj-x.iam.gserviceaccount.com",
                "display_name": "Compute SA",
            },
        ]),
    )
    crm_client = _Client(
        get_iam_policy=_Returning({
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [
                        "user:alice@example.com",
                        "serviceAccount:compute-sa@proj-x.iam.gserviceaccount.com",
                    ],
                },
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"],  # should be skipped
                },
            ],
        }),
    )
    out = discover_gcp_assets(
        _factory({"iam": iam_client, "resourcemanager": crm_client}),
        "proj-x", services=["iam"],
    )
    # Service-account asset.
    sas = [a for a in out if a["kind"] == "gcp_service_account"]
    assert len(sas) == 1
    assert sas[0]["name"] == "compute-sa@proj-x.iam.gserviceaccount.com"

    # Identity assets for the project-bound members.
    identities = [a for a in out if a["kind"] == "gcp_identity"]
    # allUsers binding skipped → only alice + the SA principal.
    assert len(identities) == 2
    by_principal = {i["principal"]: i for i in identities}
    assert "alice@example.com" in by_principal
    # Owner role mapped to wildcard action.
    assert by_principal["alice@example.com"]["statements"][0]["Action"] == ["*"]
    assert by_principal["alice@example.com"]["principal_type"] == "user"


# ---------------------------------------------------------------------------
# Serverless (Cloud Functions + Cloud Run)
# ---------------------------------------------------------------------------


def test_serverless_discovery_flags_allow_all_ingress() -> None:
    cf_client = _Client(
        list_functions=_ListOp([
            {
                "name": "projects/proj-x/locations/us/functions/fn-1",
                "ingress_settings": "ALLOW_ALL",
                "service_account_email": "fn-sa@proj-x.iam.gserviceaccount.com",
            },
            {
                "name": "projects/proj-x/locations/us/functions/fn-2",
                "ingress_settings": "ALLOW_INTERNAL_ONLY",
                "service_account_email": "fn-sa@proj-x.iam.gserviceaccount.com",
            },
        ]),
    )
    run_client = _Client(
        list_services=_ListOp([
            {
                "name": "projects/proj-x/services/run-1",
                "ingress": "INGRESS_TRAFFIC_ALL",
                "service_account": "run-sa@proj-x.iam.gserviceaccount.com",
            },
        ]),
    )
    out = discover_gcp_assets(
        _factory({"cloudfunctions": cf_client, "run": run_client}),
        "proj-x", services=["serverless"],
    )
    fn1 = next(a for a in out if a["name"].endswith("fn-1"))
    fn2 = next(a for a in out if a["name"].endswith("fn-2"))
    run1 = next(a for a in out if a["name"].endswith("run-1"))
    assert fn1["is_public"] is True
    assert fn2["is_public"] is False
    assert run1["is_public"] is True
    assert run1["kind"] == "gcp_cloud_run_service"
    assert run1["attached_identity_arn"].endswith("run-sa@proj-x.iam.gserviceaccount.com")


# ---------------------------------------------------------------------------
# Cloud SQL
# ---------------------------------------------------------------------------


def test_cloudsql_discovery_flags_public_ip_with_open_network() -> None:
    sql_client = _Client(
        list_instances=_ListOp([
            {
                "self_link": "//cloudsql/proj-x/db-public",
                "name": "db-public",
                "database_version": "POSTGRES_14",
                "settings": {
                    "ip_configuration": {
                        "ipv4_enabled": True,
                        "authorized_networks": [
                            {"value": "0.0.0.0/0", "name": "world"},
                        ],
                    },
                },
            },
            {
                "self_link": "//cloudsql/proj-x/db-private",
                "name": "db-private",
                "settings": {
                    "ip_configuration": {
                        "ipv4_enabled": False,
                    },
                },
            },
        ]),
    )
    out = discover_gcp_assets(
        _factory({"cloudsql": sql_client}),
        "proj-x", services=["cloudsql"],
    )
    pub = next(a for a in out if a["name"] == "db-public")
    priv = next(a for a in out if a["name"] == "db-private")
    assert pub["is_public"] is True
    assert pub["has_public_ip"] is True
    assert priv["is_public"] is False
    assert priv["has_public_ip"] is False


# ---------------------------------------------------------------------------
# Secret Manager
# ---------------------------------------------------------------------------


def test_secret_discovery_emits_metadata_only() -> None:
    sm_client = _Client(
        list_secrets=_ListOp([
            {
                "name": "projects/proj-x/secrets/api-key",
                "labels": {"env": "prod"},
            },
        ]),
    )
    out = discover_gcp_assets(
        _factory({"secretmanager": sm_client}),
        "proj-x", services=["secretmanager"],
    )
    assert len(out) == 1
    assert out[0]["kind"] == "gcp_secret"
    assert out[0]["labels"] == {"env": "prod"}


# ---------------------------------------------------------------------------
# Artifact Registry
# ---------------------------------------------------------------------------


def test_artifact_registry_flags_public_repos() -> None:
    """Per-repo IAM policy with `allUsers` → is_public=True."""

    class _ARClient:
        def list_repositories(self, **_):
            return iter([
                _ToDict({
                    "name": "projects/proj-x/locations/us/repositories/dangerous",
                    "format": "DOCKER",
                }),
            ])

        def get_iam_policy(self, **_):
            return _ToDict({
                "bindings": [
                    {
                        "role": "roles/artifactregistry.reader",
                        "members": ["allUsers"],
                    },
                ],
            })

    out = discover_gcp_assets(
        _factory({"artifactregistry": _ARClient()}),
        "proj-x", services=["artifactregistry"],
    )
    assert len(out) == 1
    assert out[0]["is_public"] is True
    assert out[0]["kind"] == "gcp_artifact_repository"


# ---------------------------------------------------------------------------
# Resilience: per-service failure isolation
# ---------------------------------------------------------------------------


def test_per_service_failure_isolated() -> None:
    """If one service's client build fails, others still return
    their assets — partial discovery is the contract."""
    def _f(service, project_id=None):
        if service == "storage":
            raise PermissionError("denied")
        if service == "compute":
            return _Client(
                list_instances_aggregated=_ListOp([
                    {"self_link": "//vm-1", "name": "vm-1"},
                ]),
            )
        raise KeyError(service)
    out = discover_gcp_assets(
        _f, "proj-x", services=["storage", "compute"],
    )
    assert len(out) == 1
    assert out[0]["kind"] == "gcp_compute_instance"


# ---------------------------------------------------------------------------
# max_items cap
# ---------------------------------------------------------------------------


def test_per_service_cap_bounds_enumeration() -> None:
    fw_client = _Client(
        list_firewalls=_ListOp([
            {"self_link": f"//fw-{n}", "name": f"fw-{n}"}
            for n in range(100)
        ]),
    )
    out = discover_gcp_assets(
        _factory({"compute_firewalls": fw_client}),
        "proj-x", services=["firewalls"],
        max_items_per_service=5,
    )
    assert len(out) == 5


# ---------------------------------------------------------------------------
# Specialist integration
# ---------------------------------------------------------------------------


def test_specialist_gcp_discovery_runs_when_flag_set(monkeypatch) -> None:
    from strix.cspm.aws import CspmFinding

    def fake_collect(**_):
        return [CspmFinding(
            rule_id="x", severity="low", message="x",
            service="gcp", region="us", resource_arn="x",
            cwe=None, category="cspm_misconfig", metadata={},
        )], "gcp-stub", [], {}

    monkeypatch.setattr(
        tools_module, "_collect_cspm_findings", fake_collect,
    )

    storage_client = _Client(
        list_buckets=lambda: iter([
            _ToDict({"name": "test-bucket", "location": "US"}),
        ]),
    )
    # _Bucket without get_iam_policy → fallback to client.get_iam_policy.
    storage_client.get_iam_policy = lambda **_: _ToDict({"bindings": []})

    result = scan_cloud_attack_paths(
        provider="gcp",
        gcp_project_id="proj-x",
        gcp_services=["storage"],
        _gcp_client_factory=_factory({"storage": storage_client}),
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["gcp_assets_discovered"] == 1


def test_specialist_gcp_discovery_default_off(monkeypatch) -> None:
    """No `gcp_project_id` → discovery skipped silently."""
    from strix.cspm.aws import CspmFinding

    def fake_collect(**_):
        return [CspmFinding(
            rule_id="x", severity="low", message="x",
            service="gcp", region="us", resource_arn="x",
            cwe=None, category="cspm_misconfig", metadata={},
        )], "gcp-stub", [], {}

    monkeypatch.setattr(
        tools_module, "_collect_cspm_findings", fake_collect,
    )

    def _refuse(*a, **kw):
        raise AssertionError("discover_gcp_assets should not run")

    monkeypatch.setattr(
        gcp_module, "discover_gcp_assets", _refuse,
    )

    result = scan_cloud_attack_paths(
        provider="gcp", auto_discover_assets=False,
    )
    assert "gcp_assets_discovered" not in result["tool_metadata"]


def test_specialist_gcp_discovery_failure_does_not_crash(
    monkeypatch,
) -> None:
    """Discovery crash surfaces in cspm_errors; scan continues."""
    from strix.cspm.aws import CspmFinding

    def fake_collect(**_):
        return [CspmFinding(
            rule_id="x", severity="low", message="x",
            service="gcp", region="us", resource_arn="x",
            cwe=None, category="cspm_misconfig", metadata={},
        )], "gcp-stub", [], {}

    monkeypatch.setattr(
        tools_module, "_collect_cspm_findings", fake_collect,
    )
    monkeypatch.setattr(
        "strix.cloud_attack_paths.gcp_discovery.discover_gcp_assets",
        lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("synthetic crash")
        ),
    )

    result = scan_cloud_attack_paths(
        provider="gcp",
        gcp_project_id="proj-x",
        _gcp_client_factory=lambda *a, **k: object(),
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    errors = result["tool_metadata"]["cspm_errors"]
    assert any(
        e.get("source") == "gcp_discovery" for e in errors
    )
