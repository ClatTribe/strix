"""CloudTrail posture checks.

CloudTrail is technically regional but multi-region trails are
the recommended configuration. We dispatch from `us-east-1` and
let the result speak for the whole account — running per-region
would produce N copies of the same global truth.
"""

from __future__ import annotations

from strix.cspm.aws import CspmFinding, register_check


@register_check(service="cloudtrail", scope="regional")
def cloudtrail_no_multi_region_trail(client_factory, region: str | None):
    """CIS AWS Foundations 3.1 (live) — at least one
    `IsMultiRegionTrail=True` + `IsLogging=True` trail must exist
    in the account."""
    if region != "us-east-1":
        return []
    ct = client_factory("cloudtrail", region=region)
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get(
            "trailList", [],
        )
    except Exception:  # noqa: BLE001
        return []
    has_multi_region = False
    for t in trails:
        if not t.get("IsMultiRegionTrail"):
            continue
        # Is it actually logging?
        try:
            status = ct.get_trail_status(Name=t.get("TrailARN"))
            if status.get("IsLogging"):
                has_multi_region = True
                break
        except Exception:  # noqa: BLE001
            continue
    if has_multi_region:
        return []
    return [CspmFinding(
        rule_id="AWS_CLOUDTRAIL_NOT_MULTI_REGION",
        severity="high",
        message=(
            "No multi-region CloudTrail trail is active in this "
            "account. Audit history is incomplete; incident "
            "response can't reconstruct API activity outside the "
            "specific regions with single-region trails."
        ),
        service="cloudtrail",
        region=None,
        resource_arn="arn:aws:cloudtrail:*:*:account",
        cwe="CWE-778",
        category="misconfig",
    )]


@register_check(service="cloudtrail", scope="regional")
def cloudtrail_log_file_validation_disabled(client_factory, region: str | None):
    """CIS AWS Foundations 3.2 (live) — every trail should have
    `LogFileValidationEnabled=True`. Without it, an attacker who
    gains write access to the log bucket can tamper with audit
    history undetectably."""
    if region != "us-east-1":
        return []
    ct = client_factory("cloudtrail", region=region)
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get(
            "trailList", [],
        )
    except Exception:  # noqa: BLE001
        return []
    out: list[CspmFinding] = []
    for t in trails:
        if t.get("LogFileValidationEnabled"):
            continue
        out.append(CspmFinding(
            rule_id="AWS_CLOUDTRAIL_LOG_VALIDATION_DISABLED",
            severity="medium",
            message=(
                f"CloudTrail trail `{t.get('Name')}` has log "
                f"file validation disabled. Tampering with the "
                f"log bucket goes undetected."
            ),
            service="cloudtrail",
            region=t.get("HomeRegion"),
            resource_arn=t.get("TrailARN", ""),
            cwe="CWE-345",
            category="misconfig",
            metadata={"trail_name": t.get("Name")},
        ))
    return out
