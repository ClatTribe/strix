"""engine-wishlist §4 — `assets.discovered.jsonl` emission.

When the engine enumerates resources (CSPM scanner, cloud attack-
path discovery, recon agents) the asset list lives in scan-
internal state and dies with the run. The wrapper has to
re-walk every cloud SDK to populate its own `discovered_assets`
table — same enumeration twice, double the cloud-API spend, drift
between the engine's view and the wrapper's.

§4 fixes this: the engine emits a `assets.discovered.jsonl`
artefact alongside `events.jsonl` / `findings.jsonl` /
`run_meta.json`. One JSON object per line in the wrapper's
`DiscoveredAsset` shape (see
`webappsec/webapp/frontend/lib/asset-discoverers/types.ts`).

## Wrapper-compatible row shape

```jsonl
{
  "type": "web_application",
  "canonical_id": "aws:123456789012/elbv2/payments-alb",
  "display_name": "payments-alb (us-east-1)",
  "attributes": {"value": "https://...elb.amazonaws.com", "tags": ["prod"], "is_public": true},
  "suggested_config": {"scan_mode": "standard", "scan_frequency": "weekly"},
  "confidence": "high",
  "discovered_by": "cspm.aws.elbv2"
}
```

Three fields are load-bearing for the wrapper's bulk-approve
flow:

  * `canonical_id` — globally unique stable identifier; used for
    dedup across multiple scans of the same project / org.
  * `confidence` ∈ {high, medium, low} — drives default
    scan_frequency tier wrapper-side (high → daily; medium →
    weekly; low → monthly).
  * `discovered_by` — provenance string; wrapper renders it on
    each row + uses it to attribute discovered-asset count to
    the right discoverer.

## Conversion from engine-internal asset dicts

The cloud-attack-paths discovery modules
(`discovery.py` / `azure_discovery.py` / `gcp_discovery.py`)
already emit asset dicts in a near-compatible shape. `from_cloud_asset()`
converts. Other emit paths (researcher recon, future GitHub /
domain enumeration) can call the constructor directly.

## Safety contract

Read-only. The artefact is *additive emission* — no behaviour
change to existing scans. Scans that don't discover any assets
emit nothing (no empty file forced).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# The wrapper's eight target types (from
# webappsec/lib/asset-discoverers/types.ts). Engine-emitted
# `type` must be one of these.
_ALLOWED_TYPES = frozenset({
    "repository",
    "web_application",
    "api",
    "container_image",
    "cloud_account",
    "domain",
    "ip_address",
    "container_registry",
})


# Heuristic kind → target_type mapping. Cloud-attack-paths
# discovery emits resources tagged with `kind=s3_bucket` /
# `kind=iam_role` / etc; these map to the wrapper's target-type
# enum so the wrapper knows which scanner to dispatch.
_KIND_TO_TARGET_TYPE: dict[str, str] = {
    # AWS
    "ec2_instance": "ip_address",
    "ec2_security_group": "cloud_account",
    "elbv2": "web_application",
    "elbv2_loadbalancer": "web_application",
    "alb": "web_application",
    "nlb": "web_application",
    "api_gateway": "api",
    "api_gateway_v2": "api",
    "lambda_function": "api",
    "lambda_function_url": "api",
    "cloudfront_distribution": "web_application",
    "s3_bucket": "cloud_account",
    "rds_instance": "cloud_account",
    "iam_user": "cloud_account",
    "iam_role": "cloud_account",
    "iam_group": "cloud_account",
    "iam_managed_policy": "cloud_account",
    "secret": "cloud_account",
    "ecr_repository": "container_registry",
    # Azure
    "azure_storage_account": "cloud_account",
    "azure_vm": "ip_address",
    "azure_nsg": "cloud_account",
    "azure_public_ip": "ip_address",
    "azure_identity": "cloud_account",
    "azure_role_definition": "cloud_account",
    "azure_key_vault": "cloud_account",
    "azure_app_service": "web_application",
    "azure_function_app": "api",
    "azure_container_registry": "container_registry",
    # GCP
    "gcs_bucket": "cloud_account",
    "gcp_compute_instance": "ip_address",
    "gcp_firewall_rule": "cloud_account",
    "gcp_service_account": "cloud_account",
    "gcp_identity": "cloud_account",
    "gcp_cloud_function": "api",
    "gcp_cloud_run_service": "api",
    "gcp_cloud_sql_instance": "cloud_account",
    "gcp_secret": "cloud_account",
    "gcp_artifact_repository": "container_registry",
}


@dataclass
class DiscoveredAsset:
    """One asset row in the `assets.discovered.jsonl` artefact.

    Shape matches `DiscoveredAsset` in
    `webappsec/lib/asset-discoverers/types.ts`. Any new fields
    here MUST be additive — the wrapper's reader ignores
    unknown keys, so additions don't break shape, but renames /
    removes do.
    """

    type: str
    canonical_id: str
    display_name: str
    discovered_by: str
    attributes: dict[str, Any] = field(default_factory=dict)
    suggested_config: dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"

    def __post_init__(self) -> None:
        # Hard fail loudly in dev; emit-time we fall back to
        # `cloud_account` so a single weird row doesn't blank
        # the whole artefact (see `emit_discovered_assets`).
        if self.type not in _ALLOWED_TYPES:
            raise ValueError(
                f"DiscoveredAsset.type={self.type!r} not in "
                f"_ALLOWED_TYPES; map it in _KIND_TO_TARGET_TYPE",
            )
        if self.confidence not in ("high", "medium", "low"):
            raise ValueError(
                f"DiscoveredAsset.confidence={self.confidence!r} "
                "must be one of high/medium/low",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "canonical_id": self.canonical_id,
            "display_name": self.display_name,
            "attributes": dict(self.attributes),
            "suggested_config": dict(self.suggested_config),
            "confidence": self.confidence,
            "discovered_by": self.discovered_by,
        }


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------


_AWS_ARN_RE = re.compile(
    r"^arn:aws:(?P<svc>[^:]+):(?P<region>[^:]*):(?P<account>[^:]*):(?P<rest>.*)$",
)


def _confidence_for_asset(d: dict[str, Any]) -> str:
    """Heuristic confidence ladder for cloud-attack-paths assets.

      * Internet-public resource (`is_public=True`) → high
      * Has a name + non-empty attribute set → medium
      * Bare ARN only → low
    """
    if d.get("is_public"):
        return "high"
    if d.get("name") and (
        d.get("location") or d.get("region") or d.get("tags")
    ):
        return "medium"
    return "low"


def _canonical_id_from_arn(arn: str, kind: str) -> str:
    """Pick a stable cross-scan id from the asset's ARN. AWS ARNs
    encode account+region+name; for Azure / GCP we use the full
    resource path.
    """
    if not arn:
        return f"unknown:{kind}"
    m = _AWS_ARN_RE.match(arn)
    if m:
        return (
            f"aws:{m.group('account') or 'unknown'}/"
            f"{m.group('svc')}/{m.group('rest').replace('/', '_')}"
        )
    if arn.startswith("//"):
        # GCP self_link / similar — gcp:<rest>
        return f"gcp:{arn.lstrip('/')}"
    if arn.startswith("/subscriptions/"):
        return f"azure:{arn}"
    return arn


def _display_name_for(d: dict[str, Any], target_type: str) -> str:
    """Pick a human label: name [+ region]."""
    name = (
        d.get("name") or d.get("display_name") or d.get("arn") or "unknown"
    )
    region = d.get("region") or d.get("location") or d.get("zone")
    if region:
        return f"{name} ({region})"
    return str(name)


def _suggested_config_for(
    target_type: str, confidence: str, attrs: dict[str, Any],
) -> dict[str, Any]:
    """Default scan_mode + scan_frequency for the bulk-approve
    flow. Same confidence-to-frequency ladder the wrapper uses
    in `lib/asset-discoverers/github.ts`."""
    freq = {"high": "daily", "medium": "weekly", "low": "monthly"}[confidence]
    cfg: dict[str, Any] = {
        "scan_mode": "standard",
        "scan_frequency": freq,
    }
    if attrs.get("is_public"):
        cfg["live_probes_enabled"] = False  # default off; wrapper opts in
    return cfg


def from_cloud_asset(
    asset: dict[str, Any], *, discovered_by: str,
) -> DiscoveredAsset | None:
    """Convert a cloud-attack-paths asset dict (the output shape
    of `discover_aws_assets` / `discover_azure_assets` /
    `discover_gcp_assets`) into a `DiscoveredAsset`.

    Returns None when the dict doesn't carry enough state to
    emit a meaningful row (no kind / no arn).
    """
    kind = asset.get("kind") or ""
    arn = asset.get("arn") or ""
    if not kind and not arn:
        return None

    target_type = _KIND_TO_TARGET_TYPE.get(kind, "cloud_account")
    confidence = _confidence_for_asset(asset)
    canonical = _canonical_id_from_arn(arn, kind)
    display = _display_name_for(asset, target_type)

    # Re-package the asset attributes: keep `is_public`, `tags`,
    # `region` / `location`, `name`, and any extra service-
    # specific keys the discoverer emitted. Drop the engine-
    # internal `kind` (the wrapper uses `type` instead) and `arn`
    # (canonical_id supersedes).
    attrs: dict[str, Any] = {}
    for k, v in asset.items():
        if k in ("kind", "arn", "discovered_via"):
            continue
        if v is None:
            continue
        attrs[k] = v
    # Stash provenance from the discoverer for debugging.
    if asset.get("discovered_via"):
        attrs["_engine_discovered_via"] = asset["discovered_via"]

    suggested = _suggested_config_for(target_type, confidence, attrs)

    try:
        return DiscoveredAsset(
            type=target_type,
            canonical_id=canonical,
            display_name=display,
            attributes=attrs,
            suggested_config=suggested,
            confidence=confidence,
            discovered_by=discovered_by,
        )
    except ValueError:
        logger.debug(
            "discovered_assets: rejected asset (kind=%s, arn=%s)",
            kind, arn,
        )
        return None


def from_cloud_assets(
    assets: list[dict[str, Any]],
    *,
    discovered_by: str,
) -> list[DiscoveredAsset]:
    """Bulk converter. Drops None results silently."""
    out: list[DiscoveredAsset] = []
    for a in assets:
        rec = from_cloud_asset(a, discovered_by=discovered_by)
        if rec is not None:
            out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def emit_discovered_assets(
    run_dir: Path,
    assets: list[DiscoveredAsset],
) -> Path | None:
    """Write `assets.discovered.jsonl` to `run_dir`. Returns the
    path or None when there's nothing to emit (per the wishlist
    contract: "Engine runs that don't produce discoveries emit
    an empty file or omit it entirely.")
    """
    if not assets:
        return None
    out_path = run_dir / "assets.discovered.jsonl"
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for a in assets:
                f.write(json.dumps(a.to_dict(), ensure_ascii=False))
                f.write("\n")
    except OSError as e:
        logger.warning(
            "emit_discovered_assets: write failed (%s): %s",
            out_path, e,
        )
        return None
    return out_path
