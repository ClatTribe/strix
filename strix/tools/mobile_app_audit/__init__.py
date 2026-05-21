"""iter-21.5 — deterministic mobile-app (APK / IPA) static
analysis. Closes the `asset_type=mobile_app` gap.

Mobile static analysis is genuinely uncovered by generalist
strix competitors: Veracode / Checkmarx / Snyk Mobile / NowSecure
each charge separately for it; OSS mobsf is solid but heavy
(~3GB container, ships its own DAST). This module does the
deterministic L1 layer in pure Python (no docker dep), reading
the binary as a zip archive and applying rules against the
manifest / Info.plist / asset strings.

Future iters can add a `mobsf_runner` for the dynamic side; this
PR establishes the asset_type + the deterministic static
ruleset.
"""

from __future__ import annotations

from strix.tools.mobile_app_audit.scan_mobile_app import (  # noqa: F401
    scan_mobile_app,
)


__all__ = ["scan_mobile_app"]
