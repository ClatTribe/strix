"""iter-21.6.2 — deterministic cloud-exposure audits.

Currently ships ONE tool: `scan_cloud_imds_passthrough` — direct
GET on a known list of IMDS-proxy paths (the application
accidentally proxies to `169.254.169.254` from an unauthenticated
route). Complements `scan_ssrf` (which needs an SSRF-shaped
param) for the parameter-less case.

A companion `scan_public_bucket_exposure` was previously bundled
here in iter-21.6 (PR #400, reverted via PR #401). That work was
avoidable reinvention of CloudEnum / bbot's bucket modules —
iter-21.6.1 brings back bucket discovery by wrapping bbot (matching
the strix convention of WRAPPING OSS tools rather than rebuilding
them, like the trivy / semgrep / gitleaks / nuclei wrappers).

The IMDS-passthrough probe is GENUINELY uncovered by OSS tools —
SSRFmap / SSRFking / smuggler all need an SSRF parameter; nuclei's
`http/misconfiguration/cloud-metadata.yaml` only covers the base
URL leaking JSON. So this in-house probe stays.
"""

from __future__ import annotations

from strix.tools.cloud_exposure_audit.scan_cloud_imds_passthrough import (  # noqa: F401
    scan_cloud_imds_passthrough,
)


__all__ = [
    "scan_cloud_imds_passthrough",
]
