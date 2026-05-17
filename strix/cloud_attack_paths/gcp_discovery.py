"""GCP asset discovery — enumerate cloud resources beyond what
CSPM findings alone surface, so the cloud-attack-path graph is
populated even for resources that didn't trigger any CSPM check.

masterroadmap §5 v2 deepening — parallel to `discovery.py` (AWS)
and `azure_discovery.py` (Azure) for the GCP side of multi-cloud.

## What this discovers

Per-service enumerators using read-only google-cloud-* SDK calls:

  * `storage.list_buckets + get_iam_policy`            → buckets (+ IAM bindings, public flag)
  * `compute.instances.list`                            → VMs (+ service account, public IPs, tags)
  * `compute.firewalls.list`                            → firewall rules (+ allow-from-internet)
  * `iam.service_accounts.list`                         → service accounts
  * `crm.projects.get_iam_policy`                       → project-level IAM bindings
  * `cloudfunctions.list_functions`                     → Cloud Functions (+ ingress, public)
  * `run.services.list`                                 → Cloud Run services (+ ingress)
  * `sqladmin.instances.list`                           → Cloud SQL instances (+ public IP)
  * `secretmanager.list_secrets`                        → secrets (metadata only)
  * `artifactregistry.list_repositories + get_iam_policy` → AR repos (+ public flag)

Each enumerator returns an asset dict compatible with
`build_graph_from_cspm(assets=[...])`.

## GCP IAM model — critical for attack-path graph

GCP IAM is **resource-level**: every resource has its own IAM
policy with `bindings: [{role, members}]`. A `member` is a
principal string like:

  * `user:alice@example.com`
  * `serviceAccount:foo@proj.iam.gserviceaccount.com`
  * `group:devs@example.com`
  * `allAuthenticatedUsers` / `allUsers`  ← these = internet-public

The discoverers extract these bindings + emit them as policy
statements on the resource. `allUsers` / `allAuthenticatedUsers`
in any binding → `is_public=True` (the public-from-internet
signal).

Each service-account principal also surfaces as a `gcp_identity`
asset with the bindings' roles inlined, so the `has_policy` edge
materialises automatically.

## What this does NOT do

  * **Org policy enumeration** — Org-level IAM bindings and
    deny-policy reasoning are out of scope for v1.
  * **GKE workload identity** — out of scope; covered by the
    Kubernetes target type once a workload-identity edge
    derivation lands.
  * **Mutating APIs** — strictly read-only `list / get`. Same
    safety contract as AWS + Azure.

## DI shape

`client_factory(service, project_id) -> client` — caller binds
credentials + project; tests stub the factory entirely.

## Performance bound

Per-service hard cap (default 500) keeps huge projects from
blowing the run.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Iterable


logger = logging.getLogger(__name__)


_DEFAULT_PER_SERVICE_CAP = 500


# Members that grant the binding to the public internet.
_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}

# Highly-privileged GCP IAM roles. Mapped onto the same
# `Action: "*"` policy-statement shape AWS uses so the
# `cap_can_assume_chain_to_admin` pattern's wildcard-action
# detection traverses GCP principals uniformly.
_GCP_ADMIN_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderAdmin",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _take(iterable: Iterable[Any], n: int) -> list[Any]:
    out: list[Any] = []
    for item in iterable:
        if len(out) >= n:
            break
        out.append(item)
    return out


def _as_dict(obj: Any) -> dict[str, Any]:
    """google-cloud-* protos support `Message.to_dict`. Falls
    back to vars() / dict() for plain objects."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        try:
            return obj.to_dict()
        except Exception:  # noqa: BLE001
            pass
    # Some legacy GCP SDKs expose protobuf Message; pb2_dict.
    try:
        return dict(vars(obj))
    except TypeError:
        return {}


def _bindings_to_statements(
    bindings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool]:
    """Convert a list of GCP IAM bindings into the
    AWS-shaped statement list `[{Effect, Action, Resource}]`
    expected by `build_graph_from_cspm`, plus a boolean for
    whether any binding includes a public member."""
    statements: list[dict[str, Any]] = []
    is_public = False
    for b in (bindings or []):
        if not isinstance(b, dict):
            b = _as_dict(b)
        role = b.get("role") or ""
        members = b.get("members") or []
        # Public flag: any member is allUsers / allAuthenticatedUsers.
        for m in members:
            ml = str(m).split(":", 1)[-1].lower()
            if ml in _PUBLIC_MEMBERS:
                is_public = True
                break
        actions = ["*"] if role in _GCP_ADMIN_ROLES else [role]
        statements.append({
            "Effect": "Allow",
            "Action": actions,
            "Resource": "*",
            "Members": list(members),
            "Role": role,
        })
    return statements, is_public


# ---------------------------------------------------------------------------
# Cloud Storage buckets
# ---------------------------------------------------------------------------


def _discover_storage(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate GCS buckets + their IAM bindings. allUsers /
    allAuthenticatedUsers in any binding → public flag."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("storage", project_id=project_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("gcp_discovery: storage client failed: %s", e)
        return out
    try:
        buckets = _take(client.list_buckets(), max_items)
    except Exception as e:  # noqa: BLE001
        logger.debug("gcp_discovery: list_buckets failed: %s", e)
        return out
    for b in buckets:
        d = _as_dict(b)
        name = d.get("name")
        if not name:
            continue
        # Per-bucket IAM policy.
        try:
            policy = b.get_iam_policy() if hasattr(b, "get_iam_policy") \
                else client.get_iam_policy(bucket=name)
            policy_d = _as_dict(policy)
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "gcp_discovery: get_iam_policy(%s) failed: %s",
                name, e,
            )
            policy_d = {}
        statements, is_public = _bindings_to_statements(
            policy_d.get("bindings") or [],
        )
        out.append({
            "arn": f"//storage.googleapis.com/projects/_/buckets/{name}",
            "kind": "gcs_bucket",
            "name": name,
            "location": d.get("location"),
            "is_public": is_public,
            "uniform_bucket_level_access": d.get(
                "iam_configuration", {},
            ).get("uniform_bucket_level_access", {}).get("enabled"),
            "statements": statements,
            "discovered_via": "gcp:storage.list_buckets",
        })
    return out


# ---------------------------------------------------------------------------
# Compute Engine instances + firewalls
# ---------------------------------------------------------------------------


def _vm_is_public(d: dict[str, Any]) -> bool:
    """True if any NIC has an access_config (=external IP)."""
    for nic in (d.get("network_interfaces") or []):
        if not isinstance(nic, dict):
            nic = _as_dict(nic)
        if nic.get("access_configs") or nic.get("accessConfigs"):
            return True
    return False


def _discover_compute(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate GCE instances. Service-account email on each
    instance feeds the attached_to edge derivation."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("compute", project_id=project_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("gcp_discovery: compute client failed: %s", e)
        return out
    try:
        # `aggregated_list` returns per-zone scoped results.
        instances = _take(
            client.list_instances_aggregated(project_id=project_id),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: list_instances_aggregated failed: %s", e,
        )
        return out
    for inst in instances:
        d = _as_dict(inst)
        sa_emails = [
            s.get("email") if isinstance(s, dict) else _as_dict(s).get("email")
            for s in (d.get("service_accounts") or [])
        ]
        sa_emails = [e for e in sa_emails if e]
        primary_sa = sa_emails[0] if sa_emails else None
        out.append({
            "arn": d.get("self_link") or f"//compute/instance/{d.get('name')}",
            "kind": "gcp_compute_instance",
            "name": d.get("name"),
            "zone": d.get("zone"),
            "machine_type": d.get("machine_type"),
            "status": d.get("status"),
            "is_public": _vm_is_public(d),
            "service_account_email": primary_sa,
            "attached_identity_arn": (
                f"//iam.googleapis.com/projects/{project_id}/"
                f"serviceAccounts/{primary_sa}"
                if primary_sa else None
            ),
            "tags": (d.get("tags") or {}).get("items") or [],
            "discovered_via": "gcp:compute.list_instances_aggregated",
        })
    return out


def _firewall_is_internet_open(d: dict[str, Any]) -> bool:
    """True if direction=INGRESS + allowed[] + source_ranges
    contains 0.0.0.0/0."""
    if (d.get("direction") or "").upper() != "INGRESS":
        return False
    if not d.get("allowed"):
        return False
    sources = d.get("source_ranges") or []
    return "0.0.0.0/0" in sources


def _discover_firewalls(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate firewall rules. Internet-open INGRESS rules
    feed the exposed_to_internet pattern."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("compute_firewalls", project_id=project_id)
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: firewalls client failed: %s", e,
        )
        return out
    try:
        fws = _take(
            client.list_firewalls(project_id=project_id), max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("gcp_discovery: list_firewalls failed: %s", e)
        return out
    for fw in fws:
        d = _as_dict(fw)
        open_to_internet = _firewall_is_internet_open(d)
        out.append({
            "arn": d.get("self_link") or f"//compute/firewall/{d.get('name')}",
            "kind": "gcp_firewall_rule",
            "name": d.get("name"),
            "direction": d.get("direction"),
            "is_public": open_to_internet,
            "source_ranges": d.get("source_ranges") or [],
            "target_tags": d.get("target_tags") or [],
            "allowed": d.get("allowed") or [],
            "discovered_via": "gcp:compute.list_firewalls",
        })
    return out


# ---------------------------------------------------------------------------
# IAM service accounts + project-level bindings
# ---------------------------------------------------------------------------


def _discover_iam(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Enumerate service accounts in the project + the
    project-level IAM policy. Each project binding emits a
    `gcp_identity` asset for the member with the role
    statements inlined."""
    out: list[dict[str, Any]] = []
    # Service accounts themselves.
    try:
        client = factory("iam", project_id=project_id)
        sas = _take(
            client.list_service_accounts(project_id=project_id),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("gcp_discovery: iam list_sas failed: %s", e)
        sas = []
    for sa in sas:
        d = _as_dict(sa)
        email = d.get("email")
        if not email:
            continue
        out.append({
            "arn": (
                f"//iam.googleapis.com/projects/{project_id}/"
                f"serviceAccounts/{email}"
            ),
            "kind": "gcp_service_account",
            "name": email,
            "display_name": d.get("display_name"),
            "disabled": d.get("disabled"),
            "discovered_via": "gcp:iam.list_service_accounts",
        })

    # Project-level IAM policy → per-member identity asset.
    try:
        crm_client = factory(
            "resourcemanager", project_id=project_id,
        )
        policy = crm_client.get_iam_policy(project_id=project_id)
        policy_d = _as_dict(policy)
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: project iam policy failed: %s", e,
        )
        policy_d = {}

    # Group bindings by member so each principal gets a single
    # identity asset with all its roles.
    by_member: dict[str, list[dict[str, Any]]] = {}
    for b in (policy_d.get("bindings") or []):
        if not isinstance(b, dict):
            b = _as_dict(b)
        for m in (b.get("members") or []):
            by_member.setdefault(m, []).append({
                "role": b.get("role"),
                "members": [m],
            })

    for member, member_bindings in by_member.items():
        statements, is_public = _bindings_to_statements(member_bindings)
        # Skip the special public-member rows; they show up via
        # the resource-level `is_public` flag on the bucket /
        # bucket-equivalent.
        ml = str(member).split(":", 1)[-1].lower()
        if ml in _PUBLIC_MEMBERS:
            continue
        # Member ARN: `serviceAccount:foo@...` → strip prefix.
        principal = member.split(":", 1)[-1] if ":" in member else member
        out.append({
            "arn": (
                f"//iam.googleapis.com/projects/{project_id}/"
                f"principal/{principal}"
            ),
            "kind": "gcp_identity",
            "principal": principal,
            "principal_type": (
                member.split(":", 1)[0] if ":" in member else "unknown"
            ),
            "is_public": is_public,
            "statements": statements,
            "discovered_via": "gcp:crm.get_iam_policy",
        })
    return out


# ---------------------------------------------------------------------------
# Cloud Functions + Cloud Run
# ---------------------------------------------------------------------------


def _discover_serverless(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Cloud Functions + Cloud Run services. Both surface the
    ingress setting (`ALLOW_ALL` = public) and the runtime
    service-account email."""
    out: list[dict[str, Any]] = []
    # Cloud Functions
    try:
        cf_client = factory("cloudfunctions", project_id=project_id)
        funcs = _take(
            cf_client.list_functions(project_id=project_id),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: cloud_functions list failed: %s", e,
        )
        funcs = []
    for f in funcs:
        d = _as_dict(f)
        ingress = (d.get("ingress_settings") or "").upper()
        sa = d.get("service_account_email")
        out.append({
            "arn": d.get("name") or "//cloudfunctions/unknown",
            "kind": "gcp_cloud_function",
            "name": d.get("name"),
            "ingress_settings": ingress,
            "is_public": ingress in ("", "ALLOW_ALL"),
            "service_account_email": sa,
            "attached_identity_arn": (
                f"//iam.googleapis.com/projects/{project_id}/"
                f"serviceAccounts/{sa}" if sa else None
            ),
            "discovered_via": "gcp:cloudfunctions.list_functions",
        })

    # Cloud Run services
    try:
        run_client = factory("run", project_id=project_id)
        services = _take(
            run_client.list_services(project_id=project_id),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: cloud_run list failed: %s", e,
        )
        services = []
    for s in services:
        d = _as_dict(s)
        ingress = (d.get("ingress") or "").upper()
        sa = d.get("service_account") or d.get("service_account_email")
        out.append({
            "arn": d.get("name") or "//run/unknown",
            "kind": "gcp_cloud_run_service",
            "name": d.get("name"),
            "ingress": ingress,
            "is_public": ingress in ("", "INGRESS_TRAFFIC_ALL"),
            "service_account_email": sa,
            "attached_identity_arn": (
                f"//iam.googleapis.com/projects/{project_id}/"
                f"serviceAccounts/{sa}" if sa else None
            ),
            "discovered_via": "gcp:run.list_services",
        })
    return out


# ---------------------------------------------------------------------------
# Cloud SQL
# ---------------------------------------------------------------------------


def _discover_cloudsql(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Cloud SQL instances. Public-IP flag + authorized-network
    `0.0.0.0/0` = directly internet-reachable database."""
    out: list[dict[str, Any]] = []
    try:
        client = factory("cloudsql", project_id=project_id)
        instances = _take(
            client.list_instances(project_id=project_id),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("gcp_discovery: cloudsql list failed: %s", e)
        return out
    for inst in instances:
        d = _as_dict(inst)
        settings = d.get("settings") or {}
        ip_config = settings.get("ip_configuration") or {}
        if not isinstance(ip_config, dict):
            ip_config = _as_dict(ip_config)
        has_public_ip = bool(ip_config.get("ipv4_enabled"))
        nets = ip_config.get("authorized_networks") or []
        open_to_internet = any(
            (
                (n.get("value") if isinstance(n, dict)
                 else _as_dict(n).get("value")) == "0.0.0.0/0"
            )
            for n in nets
        )
        out.append({
            "arn": d.get("self_link") or d.get("name") or "//cloudsql/unknown",
            "kind": "gcp_cloud_sql_instance",
            "name": d.get("name"),
            "database_version": d.get("database_version"),
            "is_public": has_public_ip and open_to_internet,
            "has_public_ip": has_public_ip,
            "authorized_networks_internet": open_to_internet,
            "discovered_via": "gcp:cloudsql.list_instances",
        })
    return out


# ---------------------------------------------------------------------------
# Secret Manager
# ---------------------------------------------------------------------------


def _discover_secrets(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        client = factory("secretmanager", project_id=project_id)
        secrets = _take(
            client.list_secrets(project_id=project_id), max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: secret_manager list failed: %s", e,
        )
        return out
    for s in secrets:
        d = _as_dict(s)
        name = d.get("name") or ""
        out.append({
            "arn": name,
            "kind": "gcp_secret",
            "name": name,
            "labels": d.get("labels") or {},
            "discovered_via": "gcp:secretmanager.list_secrets",
        })
    return out


# ---------------------------------------------------------------------------
# Artifact Registry
# ---------------------------------------------------------------------------


def _discover_artifactregistry(
    factory: Callable[..., Any],
    project_id: str,
    *,
    max_items: int,
) -> list[dict[str, Any]]:
    """Artifact Registry repositories. Per-repo IAM policy with
    `allUsers` = anonymous pull (the GCP equivalent of ACR's
    `anonymous_pull_enabled`)."""
    out: list[dict[str, Any]] = []
    try:
        client = factory(
            "artifactregistry", project_id=project_id,
        )
        repos = _take(
            client.list_repositories(project_id=project_id),
            max_items,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "gcp_discovery: artifactregistry list failed: %s", e,
        )
        return out
    for r in repos:
        d = _as_dict(r)
        repo_name = d.get("name")
        # Per-repo IAM bindings.
        try:
            policy = client.get_iam_policy(resource=repo_name)
            policy_d = _as_dict(policy)
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "gcp_discovery: ar get_iam_policy(%s) failed: %s",
                repo_name, e,
            )
            policy_d = {}
        statements, is_public = _bindings_to_statements(
            policy_d.get("bindings") or [],
        )
        out.append({
            "arn": repo_name or "//artifactregistry/unknown",
            "kind": "gcp_artifact_repository",
            "name": repo_name,
            "format": d.get("format"),
            "is_public": is_public,
            "statements": statements,
            "discovered_via": "gcp:artifactregistry.list_repositories",
        })
    return out


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------


def discover_gcp_assets(
    client_factory: Callable[..., Any],
    project_id: str,
    *,
    max_items_per_service: int = _DEFAULT_PER_SERVICE_CAP,
    services: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate GCP assets via google-cloud-* SDK for a project.

    Args:
        client_factory: `(service, project_id) -> client`
            callable. Caller binds credentials + project; tests
            inject a stub.
        project_id: GCP project ID.
        max_items_per_service: hard cap on items enumerated per
            service.
        services: optional allow-list. Recognised: `storage`,
            `compute`, `firewalls`, `iam`, `serverless`,
            `cloudsql`, `secretmanager`, `artifactregistry`.
            None = all of them.

    Returns:
        A list of asset dicts compatible with
        `build_graph_from_cspm(assets=...)`.
    """
    allowed = set(services) if services else None

    def _allowed(svc: str) -> bool:
        return allowed is None or svc in allowed

    out: list[dict[str, Any]] = []
    if _allowed("storage"):
        out.extend(_discover_storage(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("compute"):
        out.extend(_discover_compute(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("firewalls"):
        out.extend(_discover_firewalls(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("iam"):
        out.extend(_discover_iam(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("serverless"):
        out.extend(_discover_serverless(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("cloudsql"):
        out.extend(_discover_cloudsql(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("secretmanager"):
        out.extend(_discover_secrets(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    if _allowed("artifactregistry"):
        out.extend(_discover_artifactregistry(
            client_factory, project_id,
            max_items=max_items_per_service,
        ))
    return out
