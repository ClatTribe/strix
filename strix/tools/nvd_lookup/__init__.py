"""NIST NVD CVSS / CWE / CPE depth.

Roadmap §10 expert-pentester gap audit (🔴 critical). Augments
`cve_lookup` (#61, OSV-backed) with NIST NVD's authoritative CVSS
scoring + CWE assignments + CPE matching. NVD often has cleaner
CVSS data than GHSA-derived scores (which OSV returns).
"""

from .nvd_lookup import nvd_lookup


__all__ = ["nvd_lookup"]
