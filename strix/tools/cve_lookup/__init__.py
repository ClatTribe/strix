"""CVE / OSV lookup at fingerprint time.

Roadmap §10 threat-intelligence enrichment. Queries OSV.dev (the
Open Source Vulnerability database) for known CVEs affecting a
detected (package, version, ecosystem) triple — typically called
right after `fingerprint_tech_stack` resolves a technology version.
Each known-vulnerable, unpatched dependency emits a finding with
the CVE ID; the tracer's existing KEV enrichment auto-decorates
those findings with `is_kev`, `kev_due_date`, and ransomware-use
flags via `strix.telemetry.threat_intel`.
"""

from .cve_lookup import cve_lookup


__all__ = ["cve_lookup"]
