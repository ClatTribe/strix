"""IAM posture checks — all `scope=global`.

IAM is a global service so all these checks run once per scan
(`region=None`). The factory should accept `region=None` for
global services — boto3 handles this fine for `iam` (always
routes to `iam.amazonaws.com`).
"""

from __future__ import annotations

import json
from typing import Any

from strix.cspm.aws import CspmFinding, register_check


# CIS-recommended password policy minimums.
_MIN_PASSWORD_LENGTH = 14
_REQUIRED_PASSWORD_POLICY_KEYS = {
    "MinimumPasswordLength",
    "RequireSymbols",
    "RequireNumbers",
    "RequireUppercaseCharacters",
    "RequireLowercaseCharacters",
}


def _iter_users(iam) -> list[dict[str, Any]]:
    out = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        out.extend(page.get("Users", []))
    return out


@register_check(service="iam", scope="global")
def iam_root_access_key_exists(client_factory, region: str | None):
    """CIS AWS Foundations 1.4 — root account access keys must
    not exist."""
    iam = client_factory("iam")
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
    except Exception:  # noqa: BLE001
        return []
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        return [CspmFinding(
            rule_id="AWS_IAM_ROOT_ACCESS_KEY",
            severity="critical",
            message=(
                "Root account has access key(s) — these should "
                "never exist. Delete them and rely on IAM users / "
                "roles for programmatic access."
            ),
            service="iam",
            region=None,
            resource_arn="arn:aws:iam::*:root",
            cwe="CWE-269",
            category="misconfig",
        )]
    return []


@register_check(service="iam", scope="global")
def iam_user_no_mfa(client_factory, region: str | None):
    """CIS AWS Foundations 1.5 — every IAM user with console
    access (login profile) must have MFA enabled."""
    iam = client_factory("iam")
    out: list[CspmFinding] = []
    for user in _iter_users(iam):
        username = user.get("UserName", "")
        # Has console access?
        try:
            iam.get_login_profile(UserName=username)
        except Exception:  # noqa: BLE001
            # NoSuchEntity → no console access; skip.
            continue
        # Any MFA devices?
        try:
            mfa = iam.list_mfa_devices(UserName=username)
            if mfa.get("MFADevices"):
                continue
        except Exception:  # noqa: BLE001
            continue
        out.append(CspmFinding(
            rule_id="AWS_IAM_USER_NO_MFA",
            severity="high",
            message=(
                f"IAM user `{username}` has console access "
                f"but no MFA device configured."
            ),
            service="iam",
            region=None,
            resource_arn=f"arn:aws:iam::*:user/{username}",
            cwe="CWE-308",
            category="misconfig",
            metadata={"username": username},
        ))
    return out


@register_check(service="iam", scope="global")
def iam_password_policy_weak(client_factory, region: str | None):
    """CIS AWS Foundations 1.8 — account password policy must
    meet the recommended baseline (length ≥ 14, requires symbols
    + numbers + upper + lower)."""
    iam = client_factory("iam")
    try:
        policy = iam.get_account_password_policy().get(
            "PasswordPolicy", {},
        )
    except Exception as e:  # noqa: BLE001
        # NoSuchEntity → no policy at all. That's a finding.
        if "NoSuchEntity" in str(e):
            return [CspmFinding(
                rule_id="AWS_IAM_PASSWORD_POLICY_MISSING",
                severity="high",
                message=(
                    "Account has no IAM password policy "
                    "configured. CIS recommends length ≥ 14 + "
                    "symbol + number + upper + lower requirements."
                ),
                service="iam",
                region=None,
                resource_arn="arn:aws:iam::*:account-password-policy",
                cwe="CWE-521",
                category="misconfig",
            )]
        return []

    issues: list[str] = []
    if policy.get("MinimumPasswordLength", 0) < _MIN_PASSWORD_LENGTH:
        issues.append(
            f"MinimumPasswordLength={policy.get('MinimumPasswordLength')}"
            f" (< {_MIN_PASSWORD_LENGTH})"
        )
    for key in (
        "RequireSymbols", "RequireNumbers",
        "RequireUppercaseCharacters", "RequireLowercaseCharacters",
    ):
        if not policy.get(key, False):
            issues.append(f"{key}=False")
    if not issues:
        return []
    return [CspmFinding(
        rule_id="AWS_IAM_PASSWORD_POLICY_WEAK",
        severity="medium",
        message=(
            f"IAM password policy weaker than CIS baseline. "
            f"Issues: {', '.join(issues)}."
        ),
        service="iam",
        region=None,
        resource_arn="arn:aws:iam::*:account-password-policy",
        cwe="CWE-521",
        category="misconfig",
        metadata={"issues": issues},
    )]


def _policy_doc_has_full_wildcard(doc: dict[str, Any]) -> bool:
    """Detect `Action:* AND Resource:*` in any non-Deny Statement —
    the canonical "admin-equivalent" anti-pattern."""
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        if not isinstance(s, dict):
            continue
        if (s.get("Effect") or "").lower() != "allow":
            continue
        action = s.get("Action", [])
        resource = s.get("Resource", [])
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        if "*" in action and "*" in resource:
            return True
    return False


@register_check(service="iam", scope="global")
def iam_policy_wildcard_admin(client_factory, region: str | None):
    """CIS AWS Foundations 1.16 (live) — customer-managed IAM
    policy with `Action: * AND Resource: *` (admin-equivalent).
    AWS-managed policies (e.g. `AdministratorAccess`) are skipped
    — listing them is misleading because customers can't fix them."""
    iam = client_factory("iam")
    out: list[CspmFinding] = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):  # customer-managed only
        for p in page.get("Policies", []):
            arn = p.get("Arn", "")
            name = p.get("PolicyName", "")
            ver = p.get("DefaultVersionId")
            if not ver:
                continue
            try:
                pv = iam.get_policy_version(PolicyArn=arn, VersionId=ver)
                doc = pv["PolicyVersion"]["Document"]
            except Exception:  # noqa: BLE001
                continue
            # Boto can return doc as dict or URL-encoded JSON string
            if isinstance(doc, str):
                try:
                    doc = json.loads(doc)
                except json.JSONDecodeError:
                    continue
            if _policy_doc_has_full_wildcard(doc):
                out.append(CspmFinding(
                    rule_id="AWS_IAM_POLICY_WILDCARD_ADMIN",
                    severity="critical",
                    message=(
                        f"Customer-managed IAM policy `{name}` "
                        f"grants `Action:* + Resource:*` — admin-"
                        f"equivalent. Audit attachments + replace "
                        f"with scoped permissions."
                    ),
                    service="iam",
                    region=None,
                    resource_arn=arn,
                    cwe="CWE-269",
                    category="misconfig",
                    metadata={"policy_name": name},
                ))
    return out
