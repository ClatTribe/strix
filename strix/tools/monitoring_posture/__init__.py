"""Logging and monitoring posture detection (roadmap §16).

Probes a `web_application` target for telemetry-surface signals
the auditor needs to see:

  * Are response headers redacted (no `Server` / `X-Powered-By`)?
  * Does the app rate-limit (suggesting WAF / abuse-detection)?
  * Does it emit security headers indicating monitoring (`Report-To`,
    `Reporting-Endpoints`, `Content-Security-Policy-Report-Only`)?

Emits a `monitoring_posture` finding per target — ALWAYS emitted,
severity reflects state. SOC 2 CC7.2 / ISO 27001 A.12.4 / PCI-DSS
10.6 want positive evidence the customer is operating logging
infrastructure.
"""

from .monitoring_posture import monitoring_posture_check


__all__ = ["monitoring_posture_check"]
