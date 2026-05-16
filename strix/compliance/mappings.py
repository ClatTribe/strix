"""CWE → compliance-control mappings.

Auto-derives control IDs from a finding's CWE (or its category
when CWE is absent). The wrapper's compliance dashboard reads
the auto-derived set; if a finding wants to assert additional
controls, the SAST/IaC/SCA emit path can include
`metadata.compliance.{framework}: [control_ids]` and those
get unioned with the auto-derived set.

CWE → control mapping is the careful work. Each row is sourced
from:
  * Public framework documentation (AICPA TSP for SOC 2; ISO
    27001:2022 Annex A; PCI DSS 4.0 Requirements; OWASP ASVS
    4.0).
  * Industry consensus on which controls a given CWE class
    addresses (NIST CWE→ASVS mapping, OWASP cheatsheets,
    Datadog/Snyk/Veracode public mappings).
  * A conservative bias: when there's ambiguity, we map to
    fewer + more-specific controls rather than fewer + broader
    ones. False mappings here mislead auditors; missed
    mappings show up as "untested" coverage gaps the wrapper
    can flag.

Adding a new CWE: append to `CWE_TO_CONTROLS` with all
applicable framework / control-id pairs. Cross-reference the
chosen controls in `frameworks.py` — every control_id MUST
exist in the catalog (the test suite validates this).
"""

from __future__ import annotations

from typing import Iterable

from strix.compliance.frameworks import (
    FRAMEWORK_HIPAA,
    FRAMEWORK_ISO27001,
    FRAMEWORK_OWASP_ASVS,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    get_control,
)


# CWE → list of (framework, control_id) tuples.
# Same CWE can map to multiple controls in the same framework
# (e.g. CWE-89 hits both PCI 6.5.1 + ASVS V5.3.4).
CWE_TO_CONTROLS: dict[str, list[tuple[str, str]]] = {
    # CWE-22 — Path Traversal
    "CWE-22": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.8"),
        (FRAMEWORK_OWASP_ASVS, "V12.3.1"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
    ],
    # CWE-78 — OS Command Injection
    "CWE-78": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.8"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
    ],
    # CWE-79 — Cross-Site Scripting (XSS)
    "CWE-79": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.5.7"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.3"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
    ],
    # CWE-89 — SQL Injection
    "CWE-89": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
    ],
    # CWE-90 — LDAP Injection
    "CWE-90": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
    ],
    # CWE-94 — Code Injection (eval / new Function)
    "CWE-94": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.7"),
    ],
    # CWE-200 — Information Disclosure
    "CWE-200": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "C1.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V8.1"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_HIPAA, "164.312(e)(1)"),
    ],
    # CWE-208 — Observable Timing Discrepancy
    "CWE-208": [
        (FRAMEWORK_SOC2, "CC7.2"),
        (FRAMEWORK_ISO27001, "A.8.27"),
        (FRAMEWORK_OWASP_ASVS, "V11.1"),
    ],
    # CWE-209 — Information Exposure via Error Message
    "CWE-209": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.27"),
        (FRAMEWORK_PCI_DSS, "6.5.5"),
        (FRAMEWORK_OWASP_ASVS, "V7.1.1"),
    ],
    # CWE-269 — Improper Privilege Management
    "CWE-269": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.2"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
    ],
    # CWE-285 — Improper Authorization
    "CWE-285": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
    ],
    # CWE-287 — Improper Authentication
    "CWE-287": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_PCI_DSS, "8.2"),
        (FRAMEWORK_OWASP_ASVS, "V2"),
        (FRAMEWORK_HIPAA, "164.312(d)"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(i)"),
    ],
    # CWE-295 — Improper Certificate Validation
    "CWE-295": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.2"),
        (FRAMEWORK_PCI_DSS, "6.5.4"),
        (FRAMEWORK_OWASP_ASVS, "V9.2"),
        (FRAMEWORK_HIPAA, "164.312(e)(1)"),
    ],
    # CWE-306 — Missing Authentication for Critical Function
    "CWE-306": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.312(d)"),
    ],
    # CWE-326 — Inadequate Encryption Strength
    "CWE-326": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V6.2"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(iv)"),
        (FRAMEWORK_HIPAA, "164.312(e)(2)(ii)"),
    ],
    # CWE-327 — Use of a Broken / Risky Crypto Algorithm
    "CWE-327": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V6.2"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(iv)"),
        (FRAMEWORK_HIPAA, "164.312(e)(2)(ii)"),
    ],
    # CWE-338 — Use of Cryptographically Weak PRNG
    "CWE-338": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V6.3"),
    ],
    # CWE-345 — Insufficient Verification of Data Authenticity
    "CWE-345": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.20"),
        (FRAMEWORK_OWASP_ASVS, "V13.2.6"),
    ],
    # CWE-347 — Improper Verification of Cryptographic Signature
    "CWE-347": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "8.2"),
        (FRAMEWORK_OWASP_ASVS, "V3.5"),
    ],
    # CWE-352 — Cross-Site Request Forgery (CSRF)
    "CWE-352": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.9"),
        (FRAMEWORK_OWASP_ASVS, "V4.2.2"),
    ],
    # CWE-400 — Uncontrolled Resource Consumption
    "CWE-400": [
        (FRAMEWORK_SOC2, "A1.2"),
        (FRAMEWORK_ISO27001, "A.8.6"),
        (FRAMEWORK_OWASP_ASVS, "V11.1.4"),
    ],
    # CWE-434 — Unrestricted Upload of File with Dangerous Type
    "CWE-434": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.4.1"),
        (FRAMEWORK_OWASP_ASVS, "V12.1"),
    ],
    # CWE-489 — Active Debug Code
    "CWE-489": [
        (FRAMEWORK_SOC2, "CC8.1"),
        (FRAMEWORK_ISO27001, "A.8.32"),
        (FRAMEWORK_PCI_DSS, "6.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2"),
    ],
    # CWE-494 — Download of Code without Integrity Check
    "CWE-494": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2.4"),
    ],
    # CWE-502 — Deserialization of Untrusted Data
    "CWE-502": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.10"),
        (FRAMEWORK_OWASP_ASVS, "V5.5.3"),
    ],
    # CWE-601 — URL Redirection to Untrusted Site (Open Redirect)
    "CWE-601": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_OWASP_ASVS, "V5.1.5"),
    ],
    # CWE-611 — XXE
    "CWE-611": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_OWASP_ASVS, "V5.5.2"),
    ],
    # CWE-614 — Sensitive Cookie without Secure Flag
    "CWE-614": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V3.4"),
    ],
    # CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-639": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
    ],
    # CWE-643 — XPath Injection
    "CWE-643": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
    ],
    # CWE-732 — Incorrect Permission Assignment for Critical Resource
    "CWE-732": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
    ],
    # CWE-798 — Use of Hardcoded Credentials
    "CWE-798": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "8.2.1"),
        (FRAMEWORK_OWASP_ASVS, "V2.10"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(D)"),
    ],
    # CWE-862 — Missing Authorization
    "CWE-862": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
    ],
    # CWE-915 — Improperly Controlled Modification of Object Attributes
    # (Mass Assignment)
    "CWE-915": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.10"),
        (FRAMEWORK_OWASP_ASVS, "V5.1.2"),
    ],
    # CWE-916 — Use of Password Hash With Insufficient Computational Effort
    "CWE-916": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "8.2.1"),
        (FRAMEWORK_OWASP_ASVS, "V2.4"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(D)"),
    ],
    # CWE-918 — SSRF
    "CWE-918": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.20"),
        (FRAMEWORK_OWASP_ASVS, "V13.2.6"),
    ],
    # CWE-922 — Insecure Storage of Sensitive Information
    "CWE-922": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.10"),
        (FRAMEWORK_PCI_DSS, "8.2.1"),
        (FRAMEWORK_OWASP_ASVS, "V2.10"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(iv)"),
        (FRAMEWORK_HIPAA, "164.310(d)(1)"),
    ],
    # CWE-943 — Improper Neutralization of Special Elements (NoSQL injection)
    "CWE-943": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
    ],
    # CWE-1004 — Sensitive Cookie Without HttpOnly
    "CWE-1004": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_OWASP_ASVS, "V3.4"),
    ],
    # CWE-1321 — Prototype Pollution
    "CWE-1321": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_OWASP_ASVS, "V5.5.3"),
    ],
    # CWE-1333 — Inefficient Regular Expression Complexity (ReDoS)
    "CWE-1333": [
        (FRAMEWORK_SOC2, "A1.2"),
        (FRAMEWORK_ISO27001, "A.8.6"),
        (FRAMEWORK_OWASP_ASVS, "V11.1"),
    ],
    # CWE-1336 — Improper Neutralization of Special Elements Used in
    # a Template Engine (Server-Side Template Injection)
    "CWE-1336": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.7"),
    ],
    # CWE-1357 — Reliance on Insufficiently Trustworthy Component
    # (Docker :latest tag, deps without integrity)
    "CWE-1357": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_SOC2, "CC8.1"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2.4"),
    ],
}


# Category → controls (fallback for findings without CWE).
# SCA's `vulnerable_dependency` is the most common case —
# emits without CWE because the package may have multiple
# CWEs across its CVEs.
CATEGORY_TO_CONTROLS: dict[str, list[tuple[str, str]]] = {
    "vulnerable_dependency": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_ISO27001, "A.8.7"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2.4"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(B)"),
    ],
    "malicious_dependency": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_ISO27001, "A.8.7"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2.4"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(B)"),
    ],
    "license_violation": [
        (FRAMEWORK_SOC2, "CC9.2"),
        (FRAMEWORK_ISO27001, "A.5.32"),
    ],
    "anomaly": [
        (FRAMEWORK_SOC2, "CC7.1"),
        (FRAMEWORK_SOC2, "CC7.2"),
        (FRAMEWORK_ISO27001, "A.8.27"),
    ],
    "finding_chain": [
        # Chains are correlation-only — controls already
        # accrue on the constituent findings.
    ],
    # SAST + IaC catch-alls. Most findings have CWE, but
    # `category=sast` / `category=misconfig` need a fallback
    # for the rare CWE-less SAST hit.
    "sast": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.2"),
    ],
    "misconfig": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC8.1"),
        (FRAMEWORK_ISO27001, "A.8.32"),
        (FRAMEWORK_OWASP_ASVS, "V14.2"),
    ],
}


def controls_for(
    cwe: str | None = None,
    category: str | None = None,
) -> list[tuple[str, str]]:
    """Return the union of (framework, control_id) tuples for
    a finding with the given CWE / category.

    Resolution: CWE first (more specific), then category. We
    union when BOTH map to controls — a finding with both
    `cwe=CWE-89` AND `category=sast` gets ALL of CWE-89's
    controls + SAST's catch-all controls.
    """
    out: set[tuple[str, str]] = set()
    if cwe and isinstance(cwe, str):
        cwe_norm = cwe.strip().upper()
        if cwe_norm in CWE_TO_CONTROLS:
            out.update(CWE_TO_CONTROLS[cwe_norm])
    if category and isinstance(category, str):
        cat_norm = category.strip().lower()
        if cat_norm in CATEGORY_TO_CONTROLS:
            out.update(CATEGORY_TO_CONTROLS[cat_norm])
    return sorted(out)


def covered_controls(
    frameworks: Iterable[str] | None = None,
) -> set[tuple[str, str]]:
    """Return every (framework, control_id) tuple that some
    CWE OR category in our corpus maps to. The complement
    (against `all_controls()`) is the "untested" set — controls
    in the framework catalog that no rule in our corpus would
    surface."""
    out: set[tuple[str, str]] = set()
    for v in CWE_TO_CONTROLS.values():
        out.update(v)
    for v in CATEGORY_TO_CONTROLS.values():
        out.update(v)
    if frameworks is not None:
        fws = {f.lower() for f in frameworks}
        out = {(f, c) for f, c in out if f in fws}
    return out


def untested_controls(
    frameworks: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    """Controls in the framework catalog(s) that NO rule in our
    corpus maps to. Wrappers can render these as "coverage
    gaps" — e.g. SOC 2 CC6.3 (access removal) isn't in our
    coverage; the customer needs other tooling for it."""
    from strix.compliance.frameworks import all_controls

    catalog = {(c.framework, c.id) for c in all_controls(frameworks)}
    covered = covered_controls(frameworks)
    return sorted(catalog - covered)
