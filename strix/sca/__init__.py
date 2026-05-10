"""Software Composition Analysis (SCA) — Phase 6 of the AI Security
Engineer roadmap.

Closes the dependency-CVE gap: ~70% of disclosed bugs in modern web
apps come from third-party packages. Vibe-coded apps especially —
average ~600 transitive npm deps.

Architecture
------------

  strix/sca/
    parsers/    — per-ecosystem lockfile parsers (npm, pip, cargo,
                  ruby, composer, go, ...). Each returns a list of
                  (ecosystem, name, version, dev_only) tuples.
    match.py    — pipeline: (ecosystem, name, version) → CVE list.
                  Backed by the threat-intel cache (PR #217) plus
                  the new GHSA feed.
    scanner.py  — walk a repo path, find lockfiles, parse, match,
                  emit findings.
    reachability.py — Phase 6.4. Per-package import-level
                  reachability scoring; demotes severity for
                  unused / transitive-only packages, never demotes
                  KEV-listed CVEs.
    malicious.py — Phase 6.6. Typosquat / install-script /
                  no-license heuristics for unknown-malicious
                  packages (no CVE feed yet).
    licenses.py — Phase 6.7. SPDX license classification +
                  copyleft / commercial-restricted flagging for
                  SOC 2 OPS-3 license inventory.
    tools.py    — `scan_sca_lockfiles` LLM-facing specialist.

GHSA feed lives in `strix/threat_intel/feeds/ghsa.py`.

Public API
----------

  * `parse_lockfile(path)` — auto-detect format, return list of
    `Package` records.
  * `find_vulnerabilities(packages)` — match a Package list against
    the threat-intel cache, return `[(Package, [CVERecord])]`.
  * `scan_repo_lockfiles(repo_path)` — walk + parse + match, return
    aggregate report.
  * `scan_sca_lockfiles(...)` — LLM-facing specialist (registered).
"""

from strix.sca.match import find_vulnerabilities  # noqa: F401
from strix.sca.parsers.base import Package, parse_lockfile  # noqa: F401
from strix.sca.licenses import (  # noqa: F401
    FAMILY_COMMERCIAL_RESTRICTED,
    FAMILY_COPYLEFT,
    FAMILY_PERMISSIVE,
    FAMILY_UNKNOWN,
    FAMILY_WEAK_COPYLEFT,
    LicenseViolation,
    classify_license,
    find_license_violations,
)
from strix.sca.malicious import (  # noqa: F401
    INDICATOR_INSTALL_SCRIPT,
    INDICATOR_NO_LICENSE,
    INDICATOR_TYPOSQUAT,
    MaliciousIndicator,
    PackageMaliciousReport,
    analyse_package as analyse_malicious_package,
    analyse_packages as analyse_malicious_packages,
)
from strix.sca.reachability import (  # noqa: F401
    PackageReachability,
    REACH_DIRECT,
    REACH_TRANSITIVE_ONLY,
    REACH_UNKNOWN,
    REACH_UNUSED,
    annotate_matches as annotate_reachability,
    classify_package,
    collect_repo_imports,
)
from strix.sca.scanner import scan_repo_lockfiles  # noqa: F401
from strix.sca.tools import scan_sca_lockfiles  # noqa: F401
