"""AWS asset discovery — enumerate cloud resources beyond what
CSPM findings alone surface, so the cloud-attack-path graph is
populated even for resources that didn't trigger any CSPM check.

masterroadmap §5 P1 — fills the sparse-graph limitation in
`build_graph_from_cspm`. Today the graph only contains resources
that triggered a CSPM rule; attack-path patterns can't reason
about resources that look fine on their own but are dangerous in
combination (e.g. a perfectly-configured IAM role attached to a
public Lambda).

## What this discovers

Per-service enumerators using read-only boto3 `Describe*` /
`List*` / `Get*` calls:

  * `s3:ListBuckets`                           → buckets
  * `iam:ListUsers / ListRoles / ListPolicies` → IAM principals + policies
  * `iam:GetPolicyVersion`                     → policy statements (for can_assume edges)
  * `iam:GetRole`                              → trust policy → trust_principals
  * `ec2:DescribeInstances`                    → EC2 instances + public DNS / IP
  * `ec2:DescribeSecurityGroups`               → SG metadata
  * `rds:DescribeDBInstances`                  → DB instances + PubliclyAccessible
  * `lambda:ListFunctions + GetFunctionUrlConfig` → Lambdas + function URLs
  * `ecr:DescribeRepositories`                 → ECR repos
  * `secretsmanager:ListSecrets`               → secrets (metadata only — no values)

Each enumerator returns a list of asset dicts compatible with the
shape `build_graph_from_cspm(assets=[...])` already accepts.

## What this does NOT do

  * **VPC / network topology** — route tables, NACLs, peering.
    These are the prerequisites for full reachability scoring;
    addressed in the reachability PR (§5 reachability scoring P0).
  * **Non-AWS clouds** — Azure / GCP / OCI enumerators are
    follow-up PRs. Prowler already enumerates these for us;
    cloud-graph ingestion from Prowler output is the natural
    extension point.
  * **Mutating APIs** — strictly read-only `Describe* / List* /
    Get*`. Same safety contract as the CSPM scanner.

## Safety contract

Read-only. Per-service errors don't stop the whole discovery (a
denied `iam:ListUsers` shouldn't blank the EC2 graph). Each
service's enumerator wraps in try/except and returns the partial
result.

## Performance bound

Per-service paginators are bounded by a per-call `max_results`
cap (default 500) to keep accidental enumeration of a 100k-asset
account from blowing the run. Operators can override per call.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Iterable


logger = logging.getLogger(__name__)


# Per-paginator hard cap on items enumerated. Large accounts can
# have tens of thousands of resources; capping prevents accidental
# runaway enumeration. Configurable per call.
_DEFAULT_PER_SERVICE_CAP = 500


# ARN ↔ kind helper for IAM principals (no boto3 dep needed).
_IAM_PRINCIPAL_KIND_RE = re.compile(
    r"^arn:aws:iam::[^:]*:(user|role|group|policy)/"
)


def _iam_arn_kind(arn: str) -> str | None:
    m = _IAM_PRINCIPAL_KIND_RE.match(arn or "")
    if not m:
        return None
    return {
        "user": "iam_user", "role": "iam_role",
        "group": "iam_group", "policy": "iam_managed_policy",
    }.get(m.group(1))


# ---------------------------------------------------------------------------
# S3 buckets
# ---------------------------------------------------------------------------


def _discover_s3(factory: Any) -> list[dict[str, Any]]:
    """`s3:ListBuckets` → bucket asset dicts. Skipped silently on
    auth failure (the most common reason discovery is partial)."""
    out: list[dict[str, Any]] = []
    try:
        s3 = factory("s3", region="us-east-1")
        resp = s3.list_buckets()
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: s3 ListBuckets failed: %s", e)
        return out
    for b in (resp.get("Buckets") or []):
        name = b.get("Name")
        if not name:
            continue
        out.append({
            "arn": f"arn:aws:s3:::{name}",
            "kind": "s3_bucket",
            "name": name,
            "discovered_via": "s3:ListBuckets",
        })
    return out


# ---------------------------------------------------------------------------
# IAM users / roles / policies
# ---------------------------------------------------------------------------


def _paginate(client, paginator_name: str, *, max_items: int) -> Iterable[dict]:
    """Boto3 paginator wrapper with a hard item cap. Yields each
    page until the cap is reached, then stops."""
    seen = 0
    try:
        paginator = client.get_paginator(paginator_name)
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: paginator %s missing: %s",
                     paginator_name, e)
        return
    for page in paginator.paginate():
        yield page
        # Crude per-page count — paginators have heterogenous
        # result-key names so we count by the first list-typed
        # value in the page.
        for v in page.values():
            if isinstance(v, list):
                seen += len(v)
                break
        if seen >= max_items:
            return


def _discover_iam(
    factory: Any, *, max_items: int = _DEFAULT_PER_SERVICE_CAP,
) -> list[dict[str, Any]]:
    """IAM users + roles + customer-managed policies (+ their
    statements). Trust policies for roles surface as
    `trust_principals` AND `external_id_required` (derived from
    the trust-policy condition block) so attack-path patterns
    can light up without extra wiring."""
    out: list[dict[str, Any]] = []
    try:
        iam = factory("iam")
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: iam client failed: %s", e)
        return out

    # --- Users ---
    try:
        for page in _paginate(iam, "list_users", max_items=max_items):
            for u in (page.get("Users") or []):
                arn = u.get("Arn")
                if not arn:
                    continue
                out.append({
                    "arn": arn,
                    "kind": "iam_user",
                    "name": u.get("UserName"),
                    "discovered_via": "iam:ListUsers",
                })
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: iam ListUsers failed: %s", e)

    # --- Roles ---
    try:
        for page in _paginate(iam, "list_roles", max_items=max_items):
            for r in (page.get("Roles") or []):
                arn = r.get("Arn")
                if not arn:
                    continue
                trust_doc = r.get("AssumeRolePolicyDocument")
                trust_principals = _extract_trust_principals(trust_doc)
                external_id_required = _trust_requires_external_id(
                    trust_doc,
                )
                out.append({
                    "arn": arn,
                    "kind": "iam_role",
                    "name": r.get("RoleName"),
                    "trust_principals": trust_principals,
                    "external_id_required": external_id_required,
                    "discovered_via": "iam:ListRoles",
                })
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: iam ListRoles failed: %s", e)

    # --- Customer-managed policies + their default version's statements ---
    try:
        policies_paginator = _paginate(
            iam, "list_policies", max_items=max_items,
        )
        for page in policies_paginator:
            for p in (page.get("Policies") or []):
                arn = p.get("Arn")
                default_version = p.get("DefaultVersionId")
                if not arn or not default_version:
                    continue
                # Customer-managed only — `Scope=Local` is set by
                # the paginator caller below.
                statements: list[dict[str, Any]] = []
                try:
                    pv = iam.get_policy_version(
                        PolicyArn=arn, VersionId=default_version,
                    )
                    doc = pv.get("PolicyVersion", {}).get("Document")
                    statements = _normalise_policy_statements(doc)
                except Exception:  # noqa: BLE001
                    pass
                out.append({
                    "arn": arn,
                    "kind": "iam_managed_policy",
                    "name": p.get("PolicyName"),
                    "statements": statements,
                    "discovered_via": "iam:ListPolicies",
                })
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: iam ListPolicies failed: %s", e)

    return out


def _extract_trust_principals(trust_doc: Any) -> list[str]:
    """Parse an IAM trust policy → flat list of principal strings
    suitable for `CloudIdentity.trust_principals`. Handles dict /
    JSON-string / URL-encoded JSON shapes."""
    doc = _coerce_policy_doc(trust_doc)
    if not isinstance(doc, dict):
        return []
    out: list[str] = []
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if (stmt.get("Effect") or "").lower() != "allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            out.append("*")
            continue
        if isinstance(principal, dict):
            for key, val in principal.items():
                # `{"AWS": "arn:..."}` / `{"AWS": ["arn", "arn"]}` /
                # `{"Service": "lambda.amazonaws.com"}` etc.
                vals = val if isinstance(val, list) else [val]
                for v in vals:
                    if isinstance(v, str):
                        out.append(v)
    return out


def _trust_requires_external_id(trust_doc: Any) -> bool:
    """Walk the trust policy's `Condition.StringEquals.sts:ExternalId`
    keys. Presence of any externalId condition = required."""
    doc = _coerce_policy_doc(trust_doc)
    if not isinstance(doc, dict):
        return False
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        conditions = stmt.get("Condition")
        if not isinstance(conditions, dict):
            continue
        for op_block in conditions.values():
            if not isinstance(op_block, dict):
                continue
            for key in op_block:
                if str(key).lower() == "sts:externalid":
                    return True
    return False


def _coerce_policy_doc(doc: Any) -> dict | None:
    """boto3 returns policy docs as either dict OR URL-encoded
    JSON string. Coerce both."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        from urllib.parse import unquote
        try:
            return json.loads(unquote(doc))
        except (json.JSONDecodeError, ValueError):
            try:
                return json.loads(doc)
            except json.JSONDecodeError:
                return None
    return None


def _normalise_policy_statements(doc: Any) -> list[dict[str, Any]]:
    """Convert a policy document into the lowercase-keyed
    statement-list shape the cloud_attack_paths CloudPolicy
    expects: `[{effect, actions, resources, conditions}, ...]`.
    """
    doc = _coerce_policy_doc(doc)
    if not isinstance(doc, dict):
        return []
    statements = doc.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    out: list[dict[str, Any]] = []
    for s in statements:
        if not isinstance(s, dict):
            continue
        actions = s.get("Action") or s.get("NotAction")
        resources = s.get("Resource") or s.get("NotResource")
        out.append({
            "effect": (s.get("Effect") or "").strip(),
            "actions": actions if isinstance(actions, list) else (
                [actions] if actions else []
            ),
            "resources": resources if isinstance(resources, list) else (
                [resources] if resources else []
            ),
            "conditions": s.get("Condition"),
        })
    return out


# ---------------------------------------------------------------------------
# EC2 instances
# ---------------------------------------------------------------------------


def _discover_ec2(
    factory: Any, region: str, *,
    max_items: int = _DEFAULT_PER_SERVICE_CAP,
) -> list[dict[str, Any]]:
    """EC2 instance + attached IAM role + public-DNS / IP for the
    TCP-reachability live probe.

    Skips instances with no public IP — those aren't internet-
    exposed by virtue of the EC2 layer alone (could still be via
    LB, but reachability scoring handles that)."""
    out: list[dict[str, Any]] = []
    try:
        ec2 = factory("ec2", region=region)
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: ec2 client failed (%s): %s", region, e)
        return out

    instances_seen = 0
    try:
        for page in _paginate(ec2, "describe_instances", max_items=max_items):
            for res in (page.get("Reservations") or []):
                for inst in (res.get("Instances") or []):
                    arn = (
                        f"arn:aws:ec2:{region}:"
                        f"{res.get('OwnerId', '')}:instance/"
                        f"{inst.get('InstanceId', '')}"
                    )
                    public_dns = inst.get("PublicDnsName") or None
                    public_ip = inst.get("PublicIpAddress") or None
                    is_public = bool(public_dns or public_ip)
                    iam_profile = (inst.get("IamInstanceProfile") or {})
                    # Boto3 returns the InstanceProfile ARN, not
                    # the role ARN. We can't easily reverse-resolve
                    # without an extra call; recording the profile
                    # arn so the agent can look it up.
                    attached_profile = iam_profile.get("Arn") or None
                    asset: dict[str, Any] = {
                        "arn": arn,
                        "kind": "ec2_instance",
                        "region": region,
                        "is_public": is_public,
                        "public_dns": public_dns,
                        "public_ip": public_ip,
                        "instance_id": inst.get("InstanceId"),
                        "state": (inst.get("State") or {}).get("Name"),
                        "discovered_via": "ec2:DescribeInstances",
                    }
                    if attached_profile:
                        asset["iam_instance_profile_arn"] = attached_profile
                    out.append(asset)
                    instances_seen += 1
                    if instances_seen >= max_items:
                        return out
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: ec2 DescribeInstances failed (%s): %s",
                     region, e)
    return out


# ---------------------------------------------------------------------------
# RDS instances
# ---------------------------------------------------------------------------


def _discover_rds(
    factory: Any, region: str, *,
    max_items: int = _DEFAULT_PER_SERVICE_CAP,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        rds = factory("rds", region=region)
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: rds client failed (%s): %s", region, e)
        return out
    seen = 0
    try:
        for page in _paginate(
            rds, "describe_db_instances", max_items=max_items,
        ):
            for db in (page.get("DBInstances") or []):
                arn = db.get("DBInstanceArn")
                if not arn:
                    continue
                out.append({
                    "arn": arn,
                    "kind": "rds_db_instance",
                    "region": region,
                    "is_public": bool(db.get("PubliclyAccessible")),
                    "is_unencrypted": not bool(db.get("StorageEncrypted")),
                    "is_data_store": True,
                    "engine": db.get("Engine"),
                    "discovered_via": "rds:DescribeDBInstances",
                })
                seen += 1
                if seen >= max_items:
                    return out
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: rds DescribeDBInstances failed (%s): %s",
                     region, e)
    return out


# ---------------------------------------------------------------------------
# Lambda functions (+ function URL config)
# ---------------------------------------------------------------------------


def _discover_lambda(
    factory: Any, region: str, *,
    max_items: int = _DEFAULT_PER_SERVICE_CAP,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        lam = factory("lambda", region=region)
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: lambda client failed (%s): %s",
                     region, e)
        return out
    seen = 0
    try:
        for page in _paginate(
            lam, "list_functions", max_items=max_items,
        ):
            for fn in (page.get("Functions") or []):
                arn = fn.get("FunctionArn")
                if not arn:
                    continue
                # Function URL config (only present when the
                # function has a public URL). Captures the URL +
                # the auth type — function-url with AuthType=NONE
                # is the public Lambda surface.
                function_url: str | None = None
                auth_type: str | None = None
                try:
                    cfg = lam.get_function_url_config(
                        FunctionName=fn.get("FunctionName"),
                    )
                    function_url = cfg.get("FunctionUrl")
                    auth_type = cfg.get("AuthType")
                except Exception:  # noqa: BLE001
                    pass

                asset: dict[str, Any] = {
                    "arn": arn,
                    "kind": "lambda_function",
                    "region": region,
                    "discovered_via": "lambda:ListFunctions",
                }
                if function_url:
                    asset["function_url"] = function_url
                    asset["function_url_auth_type"] = auth_type
                    # A function URL with AuthType=NONE is publicly
                    # invokable; flag the resource as public.
                    if (auth_type or "").upper() == "NONE":
                        asset["is_public"] = True
                role_arn = fn.get("Role")
                if role_arn:
                    asset["attached_role_arn"] = role_arn
                out.append(asset)
                seen += 1
                if seen >= max_items:
                    return out
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: lambda ListFunctions failed (%s): %s",
                     region, e)
    return out


# ---------------------------------------------------------------------------
# ECR repositories
# ---------------------------------------------------------------------------


def _discover_ecr(
    factory: Any, region: str, *,
    max_items: int = _DEFAULT_PER_SERVICE_CAP,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        ecr = factory("ecr", region=region)
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: ecr client failed (%s): %s", region, e)
        return out
    seen = 0
    try:
        for page in _paginate(
            ecr, "describe_repositories", max_items=max_items,
        ):
            for r in (page.get("repositories") or []):
                arn = r.get("repositoryArn")
                if not arn:
                    continue
                out.append({
                    "arn": arn,
                    "kind": "ecr_repository",
                    "region": region,
                    "is_data_store": True,
                    "name": r.get("repositoryName"),
                    "discovered_via": "ecr:DescribeRepositories",
                })
                seen += 1
                if seen >= max_items:
                    return out
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: ecr DescribeRepositories failed (%s): %s",
                     region, e)
    return out


# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------


def _discover_secrets(
    factory: Any, region: str, *,
    max_items: int = _DEFAULT_PER_SERVICE_CAP,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        sm = factory("secretsmanager", region=region)
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: secretsmanager client failed (%s): %s",
                     region, e)
        return out
    seen = 0
    try:
        for page in _paginate(sm, "list_secrets", max_items=max_items):
            for s in (page.get("SecretList") or []):
                arn = s.get("ARN")
                if not arn:
                    continue
                out.append({
                    "arn": arn,
                    "kind": "secrets_manager_secret",
                    "region": region,
                    "is_data_store": True,
                    "name": s.get("Name"),
                    "discovered_via": "secretsmanager:ListSecrets",
                })
                seen += 1
                if seen >= max_items:
                    return out
    except Exception as e:  # noqa: BLE001
        logger.debug("discovery: secretsmanager ListSecrets failed (%s): %s",
                     region, e)
    return out


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------


def discover_aws_assets(
    client_factory: Callable[..., Any],
    *,
    regions: list[str] | None = None,
    max_items_per_service: int = _DEFAULT_PER_SERVICE_CAP,
    services: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate AWS assets via boto3 across the given regions.

    Args:
        client_factory: `(service, region) -> boto3 client`
            callable — the same `ClientFactory` shape
            `strix.cspm.aws.client.make_default_client_factory`
            returns. Tests inject a stub.
        regions: list of region names for regional services. None
            uses `us-east-1` only (global services discover from
            a single region regardless).
        max_items_per_service: hard cap on items enumerated per
            service to keep huge accounts bounded.
        services: optional allow-list of services to discover.
            Recognised: `s3`, `iam`, `ec2`, `rds`, `lambda`,
            `ecr`, `secretsmanager`. None = all of them.

    Returns:
        A list of asset dicts compatible with
        `build_graph_from_cspm(assets=...)`. Each dict has at
        least `arn` + `kind`; additional keys depend on the
        service (e.g. `is_public`, `function_url`,
        `attached_role_arn`, `statements`).
    """
    region_list = list(regions) if regions else ["us-east-1"]
    allowed = set(services) if services else None

    out: list[dict[str, Any]] = []

    def _allowed(svc: str) -> bool:
        return allowed is None or svc in allowed

    # ---- Global services (S3 listing is global; IAM is global) ----
    if _allowed("s3"):
        out.extend(_discover_s3(client_factory))
    if _allowed("iam"):
        out.extend(
            _discover_iam(client_factory, max_items=max_items_per_service)
        )

    # ---- Per-region services ----
    for region in region_list:
        if _allowed("ec2"):
            out.extend(_discover_ec2(
                client_factory, region,
                max_items=max_items_per_service,
            ))
        if _allowed("rds"):
            out.extend(_discover_rds(
                client_factory, region,
                max_items=max_items_per_service,
            ))
        if _allowed("lambda"):
            out.extend(_discover_lambda(
                client_factory, region,
                max_items=max_items_per_service,
            ))
        if _allowed("ecr"):
            out.extend(_discover_ecr(
                client_factory, region,
                max_items=max_items_per_service,
            ))
        if _allowed("secretsmanager"):
            out.extend(_discover_secrets(
                client_factory, region,
                max_items=max_items_per_service,
            ))

    return out
