"""Azure asset discovery — enumerate cloud resources beyond what
CSPM findings alone surface, so the cloud-attack-path graph is
populated even for resources that didn't trigger any CSPM check.

masterroadmap §5 v2 deepening — parallel to
`discovery.py` (AWS) for the Azure side of multi-cloud.

## What this discovers

Per-service enumerators using read-only Azure SDK calls:

  * `StorageManagement.storage_accounts.list`              → storage accounts
  * `Storage.blob_containers.list`                         → containers (public_access)
  * `ComputeManagement.virtual_machines.list_all`          → VMs (+ identities)
  * `NetworkManagement.network_security_groups.list_all`   → NSGs (+ rules)
  * `NetworkManagement.public_ip_addresses.list_all`       → public IPs
  * `AuthorizationManagement.role_assignments.list`        → RBAC bindings
  * `AuthorizationManagement.role_definitions.list`        → role permissions
  * `KeyVaultManagement.vaults.list`                       → key vaults (+ access policies)
  * `Web.web_apps.list`                                    → App Service / Functions
  * `ContainerRegistry.registries.list`                    → ACR repos (+ anon access)

Each enumerator returns asset dicts in the same shape
`build_graph_from_cspm(assets=[...])` already accepts. The
`can_assume` / `has_policy` / `exposed_to_internet` edges
materialise automatically because RBAC role-assignments end up
as policy statements on the principal.

## What this does NOT do

  * **Azure AD identity enumeration** (users, groups, app
    registrations beyond managed identities) — requires Graph
    API permissions out of scope for v1. Managed identities
    (which are the closest to AWS IAM roles for attack-path
    reasoning) are covered.
  * **Mutating APIs** — strictly read-only `list / get`. Same
    safety contract as AWS discovery + the CSPM scanner.

## Safety contract

Read-only. Per-service errors don't stop the whole discovery
(a denied `Storage.list` shouldn't blank the Compute graph).
Each service's enumerator wraps in try/except and returns the
partial result.

## DI shape

`client_factory(service, subscription_id) -> client` — the
caller (typically `strix.cspm.azure.client` once it exists,
which is post-v1) is responsible for binding credentials +
subscription. Tests stub the factory entirely.

## Performance bound

Per-service cap on items enumerated (default 500) to keep
accidental enumeration of a 100k-asset tenant from blowing
the run.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable


logger = logging.getLogger(__name__)


_DEFAULT_PER_SERVICE_CAP = 500


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _take(iterable: Iterable[Any], n: int) -> list[Any]:
    """Bounded list materialisation — Azure SDK pagers are lazy."""
    out: list[Any] = []
    for item in iterable:
        if len(out) >= n:
            break
        out.append(item)
    return out


def _as_dict(obj: Any) -> dict[str, Any]:
    """Azure SDK models support `as_dict()`; fall back to vars()."""
    if obj is None:
        return {}
    if hasattr(obj, "as_dict") and callable(obj.as_dict):
        try:
            return obj.as_dict()
        except Exception:  # noqa: BLE001
            pass
    if isinstance(obj, dict):
        return obj
    try:
        return dict(vars(obj))
    except TypeError:
        return {}


# ---------------------------------------------------------------------------
# Storage accounts + containers
# ---------------------------------------------------------------------------


def _discover_storage(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate storage accounts in the subscription. Public-
    blob-access flag carries the exposed_to_internet signal."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("storage", subscription_id=subscription_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: storage client failed: %s", e)
        return out
    try:
        accounts = _take(
            client.storage_accounts.list(),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: storage list failed: %s", e)
        return out
    for acct in accounts:
        d = _as_dict(acct)
        # Azure exposes "allow_blob_public_access" + the per-
        # container "public_access" setting. The account-level
        # flag matters most: if False, no container can be
        # public regardless.
        out.append({
            "arn": d.get("id") or "",
            "kind": "azure_storage_account",
            "name": d.get("name"),
            "location": d.get("location"),
            "is_public": bool(d.get("allow_blob_public_access")),
            "https_only": d.get("enable_https_traffic_only"),
            "minimum_tls_version": d.get("minimum_tls_version"),
            "discovered_via": "azure:storage_accounts.list",
        })
    return out


# ---------------------------------------------------------------------------
# Virtual machines
# ---------------------------------------------------------------------------


def _discover_compute(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate VMs. Each VM's managed-identity ARN (if any)
    feeds the attached_to / can_assume edge derivation."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("compute", subscription_id=subscription_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: compute client failed: %s", e)
        return out
    try:
        vms = _take(client.virtual_machines.list_all(), max_items)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: vm list failed: %s", e)
        return out
    for vm in vms:
        d = _as_dict(vm)
        identity = d.get("identity") or {}
        principal_id = (
            identity.get("principal_id")
            if isinstance(identity, dict) else None
        )
        out.append({
            "arn": d.get("id") or "",
            "kind": "azure_vm",
            "name": d.get("name"),
            "location": d.get("location"),
            "managed_identity_principal_id": principal_id,
            "attached_identity_arn": (
                f"/subscriptions/{subscription_id}/managed-identity/"
                f"{principal_id}" if principal_id else None
            ),
            "discovered_via": "azure:virtual_machines.list_all",
        })
    return out


# ---------------------------------------------------------------------------
# Network security groups (firewall rules)
# ---------------------------------------------------------------------------


def _is_open_to_internet(rule: dict[str, Any]) -> bool:
    """An NSG rule is internet-open when:
      * direction == Inbound
      * access == Allow
      * source_address_prefix is `*` / `0.0.0.0/0` / `Internet`
    """
    if (rule.get("direction") or "").lower() != "inbound":
        return False
    if (rule.get("access") or "").lower() != "allow":
        return False
    src = rule.get("source_address_prefix") or ""
    if isinstance(src, list):
        srcs = [str(s).lower() for s in src]
    else:
        srcs = [str(src).lower()]
    open_srcs = {"*", "0.0.0.0/0", "internet", "any"}
    return any(s in open_srcs for s in srcs)


def _discover_network(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate NSGs and emit per-NSG asset dicts that carry the
    is_public + open_ports rollup. Public IPs also surface as
    discrete assets for reachability scoring."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("network", subscription_id=subscription_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: network client failed: %s", e)
        return out
    try:
        nsgs = _take(
            client.network_security_groups.list_all(), max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: nsg list failed: %s", e)
        nsgs = []
    for nsg in nsgs:
        d = _as_dict(nsg)
        rules = d.get("security_rules") or []
        open_rules = [r for r in rules if _is_open_to_internet(r)]
        out.append({
            "arn": d.get("id") or "",
            "kind": "azure_nsg",
            "name": d.get("name"),
            "location": d.get("location"),
            "is_public": bool(open_rules),
            "open_rules": [
                {
                    "name": r.get("name"),
                    "ports": r.get("destination_port_range"),
                    "protocol": r.get("protocol"),
                }
                for r in open_rules
            ],
            "discovered_via": "azure:network_security_groups.list_all",
        })
    # Public IP assets — first-class so reachability scoring can
    # treat them as internet entry points.
    try:
        ips = _take(client.public_ip_addresses.list_all(), max_items)
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "azure_discovery: public_ip list failed: %s", e,
        )
        ips = []
    for ip in ips:
        d = _as_dict(ip)
        addr = d.get("ip_address")
        if not addr:
            continue
        out.append({
            "arn": d.get("id") or "",
            "kind": "azure_public_ip",
            "name": d.get("name"),
            "ip_address": addr,
            "is_public": True,
            "discovered_via": "azure:public_ip_addresses.list_all",
        })
    return out


# ---------------------------------------------------------------------------
# RBAC role assignments + role definitions
# ---------------------------------------------------------------------------


def _discover_rbac(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate role assignments + role definitions in the
    subscription. Each role assignment ends up as a policy
    attachment edge (principal → role definition statements)
    so `cap_can_assume_chain_to_admin` traverses Azure principals
    the same way it traverses AWS IAM users / roles."""
    out: list[dict[str, Any]] = []
    try:
        client = factory(
            "authorization", subscription_id=subscription_id,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "azure_discovery: authorization client failed: %s", e,
        )
        return out

    # Index role definitions by ID → statements (actions / not-
    # actions / data-actions). Default scope = subscription root.
    role_def_statements: dict[str, list[dict[str, Any]]] = {}
    try:
        scope = f"/subscriptions/{subscription_id}"
        defs = _take(
            client.role_definitions.list(scope=scope), max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: role_definitions failed: %s", e)
        defs = []
    for rd in defs:
        d = _as_dict(rd)
        rdid = d.get("id") or ""
        statements: list[dict[str, Any]] = []
        for perm in (d.get("permissions") or []):
            if not isinstance(perm, dict):
                perm = _as_dict(perm)
            statements.append({
                "Effect": "Allow",
                "Action": perm.get("actions") or [],
                "NotAction": perm.get("not_actions") or [],
                "DataAction": perm.get("data_actions") or [],
                "Resource": "*",
            })
        role_def_statements[rdid] = statements
        # Also emit the role definition as a `azure_role_definition`
        # asset so the graph has a node for it.
        out.append({
            "arn": rdid,
            "kind": "azure_role_definition",
            "name": d.get("role_name") or d.get("name"),
            "statements": statements,
            "discovered_via": "azure:role_definitions.list",
        })

    # Role assignments — these are the edges between principals
    # and role definitions.
    try:
        scope = f"/subscriptions/{subscription_id}"
        assignments = _take(
            client.role_assignments.list_for_scope(scope=scope),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "azure_discovery: role_assignments failed: %s", e,
        )
        assignments = []
    for ra in assignments:
        d = _as_dict(ra)
        principal_id = d.get("principal_id")
        role_def_id = d.get("role_definition_id")
        if not principal_id or not role_def_id:
            continue
        # Emit the principal as an azure_identity asset with the
        # role-definition statements inlined → ingest builds the
        # has_policy edge automatically.
        out.append({
            "arn": (
                f"/subscriptions/{subscription_id}/principal/"
                f"{principal_id}"
            ),
            "kind": "azure_identity",
            "principal_id": principal_id,
            "principal_type": d.get("principal_type"),
            "statements": role_def_statements.get(role_def_id, []),
            "role_definition_id": role_def_id,
            "scope": d.get("scope"),
            "discovered_via": "azure:role_assignments.list_for_scope",
        })
    return out


# ---------------------------------------------------------------------------
# Key vaults
# ---------------------------------------------------------------------------


def _discover_keyvault(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate Key Vaults and surface access-policy bindings
    + network ACLs. Vaults are the Azure analog of AWS Secrets
    Manager — surfacing them lets `cap_secrets_via_environment`
    + the secrets-resource-policy patterns fire."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("keyvault", subscription_id=subscription_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: keyvault client failed: %s", e)
        return out
    try:
        vaults = _take(client.vaults.list(), max_items)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: vaults list failed: %s", e)
        return out
    for v in vaults:
        d = _as_dict(v)
        props = d.get("properties") or {}
        if not isinstance(props, dict):
            props = _as_dict(props)
        network_acls = props.get("network_acls") or {}
        if not isinstance(network_acls, dict):
            network_acls = _as_dict(network_acls)
        default_action = (
            (network_acls.get("default_action") or "")
            if network_acls else ""
        )
        # Default Allow with no IP rules = public-from-anywhere.
        is_public = (
            (default_action or "").lower() == "allow"
            and not network_acls.get("ip_rules")
        )
        out.append({
            "arn": d.get("id") or "",
            "kind": "azure_key_vault",
            "name": d.get("name"),
            "location": d.get("location"),
            "is_public": bool(is_public),
            "rbac_authorization": props.get(
                "enable_rbac_authorization"
            ),
            "soft_delete_enabled": props.get("enable_soft_delete"),
            "purge_protection": props.get(
                "enable_purge_protection"
            ),
            "discovered_via": "azure:vaults.list",
        })
    return out


# ---------------------------------------------------------------------------
# Web apps / Function apps
# ---------------------------------------------------------------------------


def _discover_web(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate App Services + Function Apps. Public hostnames
    + managed identities feed exposed_to_internet + attached_to
    edges."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("web", subscription_id=subscription_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: web client failed: %s", e)
        return out
    try:
        sites = _take(client.web_apps.list(), max_items)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: web_apps list failed: %s", e)
        return out
    for s in sites:
        d = _as_dict(s)
        kind = (d.get("kind") or "").lower()
        # Function apps have kind containing "functionapp"; web
        # apps are "app" / "linux".
        asset_kind = (
            "azure_function_app" if "functionapp" in kind
            else "azure_app_service"
        )
        identity = d.get("identity") or {}
        principal_id = (
            identity.get("principal_id")
            if isinstance(identity, dict) else None
        )
        # App Services are public-by-default; private access
        # requires a VNet integration / private endpoint flag.
        host_names = d.get("host_names") or []
        out.append({
            "arn": d.get("id") or "",
            "kind": asset_kind,
            "name": d.get("name"),
            "location": d.get("location"),
            "host_names": list(host_names),
            "https_only": d.get("https_only"),
            "is_public": bool(host_names),
            "managed_identity_principal_id": principal_id,
            "attached_identity_arn": (
                f"/subscriptions/{subscription_id}/managed-identity/"
                f"{principal_id}" if principal_id else None
            ),
            "discovered_via": "azure:web_apps.list",
        })
    return out


# ---------------------------------------------------------------------------
# Container Registry (ACR)
# ---------------------------------------------------------------------------


def _discover_acr(
    factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate Azure Container Registries. `admin_user_enabled`
    + `anonymous_pull_enabled` are the dangerous-config flags."""
    out: list[dict[str, Any]] = []
    try:
        client = factory(
            "containerregistry", subscription_id=subscription_id,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: acr client failed: %s", e)
        return out
    try:
        registries = _take(client.registries.list(), max_items)
    except Exception as e:  # noqa: BLE001
        logger.debug("azure_discovery: registries list failed: %s", e)
        return out
    for r in registries:
        d = _as_dict(r)
        out.append({
            "arn": d.get("id") or "",
            "kind": "azure_container_registry",
            "name": d.get("name"),
            "location": d.get("location"),
            "admin_user_enabled": d.get("admin_user_enabled"),
            "anonymous_pull_enabled": d.get(
                "anonymous_pull_enabled"
            ),
            "public_network_access": d.get(
                "public_network_access"
            ),
            "is_public": (
                (d.get("public_network_access") or "").lower()
                == "enabled"
            ),
            "discovered_via": "azure:registries.list",
        })
    return out


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------


def discover_azure_assets(
    client_factory: Callable[..., Any],
    subscription_id: str,
    *,
    max_items_per_service: int = _DEFAULT_PER_SERVICE_CAP,
    services: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate Azure assets via the Azure SDK for a given
    subscription.

    Args:
        client_factory: `(service, subscription_id) -> client`
            callable. Caller binds credentials + subscription;
            tests inject a stub.
        subscription_id: Azure subscription GUID.
        max_items_per_service: hard cap on items enumerated per
            service to keep huge tenants bounded.
        services: optional allow-list of services to discover.
            Recognised: `storage`, `compute`, `network`,
            `authorization`, `keyvault`, `web`,
            `containerregistry`. None = all of them.

    Returns:
        A list of asset dicts compatible with
        `build_graph_from_cspm(assets=...)`. Each dict has at
        least `arn` + `kind`; additional keys depend on the
        service (e.g. `is_public`, `attached_identity_arn`,
        `statements`).
    """
    allowed = set(services) if services else None

    def _allowed(svc: str) -> bool:
        return allowed is None or svc in allowed

    out: list[dict[str, Any]] = []
    if _allowed("storage"):
        out.extend(_discover_storage(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    if _allowed("compute"):
        out.extend(_discover_compute(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    if _allowed("network"):
        out.extend(_discover_network(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    if _allowed("authorization"):
        out.extend(_discover_rbac(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    if _allowed("keyvault"):
        out.extend(_discover_keyvault(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    if _allowed("web"):
        out.extend(_discover_web(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    if _allowed("containerregistry"):
        out.extend(_discover_acr(
            client_factory, subscription_id,
            max_items=max_items_per_service,
        ))
    return out
