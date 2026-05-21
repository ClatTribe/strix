"""iter-21.6 — deterministic cloud-exposure audits.

Two tools sit in this package:

  * `scan_public_bucket_exposure` — bucket-name guessing from the
    target's hostname labels; probes AWS S3 / GCP GCS / Azure Blob
    for listable or publicly-readable buckets.

  * `scan_cloud_imds_passthrough` — direct GET on a known list of
    IMDS-proxy paths (the application accidentally proxies to
    `169.254.169.254` from an unauthenticated route). Complements
    `scan_ssrf` (which needs an SSRF-shaped param) for the
    parameter-less case.

Both are L1, deterministic, recall-safe — they return `partial`
when the target isn't a cloud-shaped surface so non-cloud
fixtures don't take a false-positive load.
"""

from __future__ import annotations

from strix.tools.cloud_exposure_audit.scan_cloud_imds_passthrough import (  # noqa: F401
    scan_cloud_imds_passthrough,
)
from strix.tools.cloud_exposure_audit.scan_public_bucket_exposure import (  # noqa: F401
    scan_public_bucket_exposure,
)


__all__ = [
    "scan_cloud_imds_passthrough",
    "scan_public_bucket_exposure",
]
