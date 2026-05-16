"""CWE → compliance-control mappings.

Auto-derives control IDs from a finding's CWE (or its category
when CWE is absent). The wrapper's compliance dashboard reads
the auto-derived set; if a finding wants to assert additional
controls, the SAST/IaC/SCA emit path can include
`metadata.compliance.{framework}: [control_ids]` and those
get unioned with the auto-derived set.

This module is the SINGLE source of truth for CWE→control
mappings. Both the run-level evidence report
(`strix.compliance.evidence.build_evidence_report`) and the
per-finding decorator
(`strix.telemetry.compliance.enrich_finding_with_compliance`)
read from here.

CWE → control mapping is the careful work. Each row is sourced
from:
  * Public framework documentation (AICPA TSP for SOC 2; ISO
    27001:2022 Annex A; PCI DSS 4.0 Requirements; OWASP ASVS
    4.0; HHS Security Rule 45 CFR §164; OWASP Top 10 2021;
    NIST SP 800-53 Rev.5; CIS Controls v8; EU GDPR 2016/679).
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
    FRAMEWORK_CIS,
    FRAMEWORK_GDPR,
    FRAMEWORK_HIPAA,
    FRAMEWORK_ISO27001,
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_OWASP_ASVS,
    FRAMEWORK_OWASP_TOP10,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    get_control,
)


# CWE → list of (framework, control_id) tuples.
# Same CWE can map to multiple controls in the same framework
# (e.g. CWE-89 hits both PCI 6.5.1 + ASVS V5.3.4).
CWE_TO_CONTROLS: dict[str, list[tuple[str, str]]] = {
    # CWE-20 — Improper Input Validation (catch-all)
    "CWE-20": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
    ],
    # CWE-22 — Path Traversal
    "CWE-22": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.8"),
        (FRAMEWORK_OWASP_ASVS, "V12.3.1"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-77 — Command Injection
    "CWE-77": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.8"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
        (FRAMEWORK_CIS, "16.10"),
    ],
    # CWE-78 — OS Command Injection
    "CWE-78": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.8"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-79 — Cross-Site Scripting (XSS)
    "CWE-79": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.5.7"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.3"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-89 — SQL Injection
    "CWE-89": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_ISO27001, "A.8.28"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
        (FRAMEWORK_HIPAA, "164.312(c)(1)"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
        (FRAMEWORK_CIS, "16.10"),
    ],
    # CWE-90 — LDAP Injection
    "CWE-90": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-94 — Code Injection (eval / new Function)
    "CWE-94": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.7"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-200 — Information Disclosure
    "CWE-200": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_SOC2, "C1.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V8.1"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_HIPAA, "164.312(e)(1)"),
        (FRAMEWORK_GDPR, "Art.32"),
        (FRAMEWORK_NIST_800_53, "SC-28"),
        (FRAMEWORK_OWASP_TOP10, "A04:2021"),
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
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.27"),
        (FRAMEWORK_PCI_DSS, "6.5.5"),
        (FRAMEWORK_OWASP_ASVS, "V7.1.1"),
        (FRAMEWORK_NIST_800_53, "SI-11"),
    ],
    # CWE-269 — Improper Privilege Management
    "CWE-269": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.2"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_NIST_800_53, "AC-6"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-285 — Improper Authorization
    "CWE-285": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_NIST_800_53, "AC-3"),
        (FRAMEWORK_NIST_800_53, "AC-6"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-287 — Improper Authentication
    "CWE-287": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_PCI_DSS, "8.2"),
        (FRAMEWORK_OWASP_ASVS, "V2"),
        (FRAMEWORK_HIPAA, "164.312(d)"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(i)"),
        (FRAMEWORK_NIST_800_53, "IA-2"),
        (FRAMEWORK_OWASP_TOP10, "A07:2021"),
    ],
    # CWE-295 — Improper Certificate Validation
    "CWE-295": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.2"),
        (FRAMEWORK_PCI_DSS, "6.5.4"),
        (FRAMEWORK_OWASP_ASVS, "V9.2"),
        (FRAMEWORK_HIPAA, "164.312(e)(1)"),
        (FRAMEWORK_OWASP_TOP10, "A02:2021"),
    ],
    # CWE-306 — Missing Authentication for Critical Function
    "CWE-306": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.312(d)"),
        (FRAMEWORK_NIST_800_53, "IA-2"),
        (FRAMEWORK_OWASP_TOP10, "A07:2021"),
    ],
    # CWE-326 — Inadequate Encryption Strength
    "CWE-326": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V6.2"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(iv)"),
        (FRAMEWORK_HIPAA, "164.312(e)(2)(ii)"),
        (FRAMEWORK_GDPR, "Art.32"),
        (FRAMEWORK_NIST_800_53, "SC-13"),
        (FRAMEWORK_OWASP_TOP10, "A02:2021"),
    ],
    # CWE-327 — Use of a Broken / Risky Crypto Algorithm
    "CWE-327": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V6.2"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(iv)"),
        (FRAMEWORK_HIPAA, "164.312(e)(2)(ii)"),
        (FRAMEWORK_NIST_800_53, "SC-13"),
        (FRAMEWORK_OWASP_TOP10, "A02:2021"),
    ],
    # CWE-330 — Use of Insufficiently Random Values
    "CWE-330": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_PCI_DSS, "8.2"),
        (FRAMEWORK_OWASP_ASVS, "V6.3"),
        (FRAMEWORK_NIST_800_53, "SC-13"),
        (FRAMEWORK_OWASP_TOP10, "A02:2021"),
    ],
    # CWE-338 — Use of Cryptographically Weak PRNG
    "CWE-338": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "4.1"),
        (FRAMEWORK_OWASP_ASVS, "V6.3"),
        (FRAMEWORK_NIST_800_53, "SC-13"),
        (FRAMEWORK_OWASP_TOP10, "A02:2021"),
    ],
    # CWE-345 — Insufficient Verification of Data Authenticity
    "CWE-345": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.20"),
        (FRAMEWORK_OWASP_ASVS, "V13.2.6"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
    ],
    # CWE-347 — Improper Verification of Cryptographic Signature
    "CWE-347": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "8.2"),
        (FRAMEWORK_OWASP_ASVS, "V3.5"),
        (FRAMEWORK_NIST_800_53, "SC-13"),
        (FRAMEWORK_OWASP_TOP10, "A02:2021"),
    ],
    # CWE-353 — Missing Support for Integrity Check (Subresource
    # Integrity, supply-chain integrity verification)
    "CWE-353": [
        (FRAMEWORK_SOC2, "CC8.1"),
        (FRAMEWORK_ISO27001, "A.8.30"),
        (FRAMEWORK_NIST_800_53, "SI-7"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
    ],
    # CWE-352 — Cross-Site Request Forgery (CSRF)
    "CWE-352": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.9"),
        (FRAMEWORK_OWASP_ASVS, "V4.2.2"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-362 — Race Condition
    "CWE-362": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
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
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.4.1"),
        (FRAMEWORK_OWASP_ASVS, "V12.1"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A05:2021"),
    ],
    # CWE-444 — HTTP Request Smuggling
    "CWE-444": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.20"),
        (FRAMEWORK_NIST_800_53, "SC-7"),
    ],
    # CWE-453 — Insecure Default Variable Initialization
    "CWE-453": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_NIST_800_53, "CM-6"),
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
        (FRAMEWORK_NIST_800_53, "SI-7"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
    ],
    # CWE-502 — Deserialization of Untrusted Data
    "CWE-502": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.10"),
        (FRAMEWORK_OWASP_ASVS, "V5.5.3"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
    ],
    # CWE-525 — Use of Web Browser Cache Containing Sensitive Info
    "CWE-525": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
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
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_OWASP_ASVS, "V5.5.2"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_OWASP_TOP10, "A05:2021"),
    ],
    # CWE-613 — Insufficient Session Expiration
    "CWE-613": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_NIST_800_53, "IA-11"),
        (FRAMEWORK_OWASP_TOP10, "A07:2021"),
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
        (FRAMEWORK_NIST_800_53, "AC-3"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-643 — XPath Injection
    "CWE-643": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-693 — Protection Mechanism Failure (general)
    "CWE-693": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
    ],
    # CWE-732 — Incorrect Permission Assignment for Critical Resource
    "CWE-732": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_NIST_800_53, "AC-6"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-798 — Use of Hardcoded Credentials
    "CWE-798": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.5"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "8.2.1"),
        (FRAMEWORK_OWASP_ASVS, "V2.10"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(D)"),
        (FRAMEWORK_OWASP_TOP10, "A07:2021"),
    ],
    # CWE-862 — Missing Authorization
    "CWE-862": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.3"),
        (FRAMEWORK_PCI_DSS, "7.1"),
        (FRAMEWORK_OWASP_ASVS, "V4.1"),
        (FRAMEWORK_HIPAA, "164.308(a)(4)(ii)(B)"),
        (FRAMEWORK_HIPAA, "164.312(a)(1)"),
        (FRAMEWORK_NIST_800_53, "AC-3"),
        (FRAMEWORK_OWASP_TOP10, "A01:2021"),
    ],
    # CWE-915 — Improperly Controlled Modification of Object Attributes
    # (Mass Assignment)
    "CWE-915": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.10"),
        (FRAMEWORK_OWASP_ASVS, "V5.1.2"),
        (FRAMEWORK_OWASP_TOP10, "API6:2023"),
    ],
    # CWE-916 — Use of Password Hash With Insufficient Computational Effort
    "CWE-916": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_PCI_DSS, "8.2.1"),
        (FRAMEWORK_OWASP_ASVS, "V2.4"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(D)"),
        (FRAMEWORK_OWASP_TOP10, "A07:2021"),
    ],
    # CWE-918 — SSRF
    "CWE-918": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.20"),
        (FRAMEWORK_OWASP_ASVS, "V13.2.6"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
        (FRAMEWORK_NIST_800_53, "SC-7"),
        (FRAMEWORK_OWASP_TOP10, "A10:2021"),
    ],
    # CWE-922 — Insecure Storage of Sensitive Information
    "CWE-922": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.10"),
        (FRAMEWORK_PCI_DSS, "8.2.1"),
        (FRAMEWORK_OWASP_ASVS, "V2.10"),
        (FRAMEWORK_HIPAA, "164.312(a)(2)(iv)"),
        (FRAMEWORK_HIPAA, "164.310(d)(1)"),
        (FRAMEWORK_NIST_800_53, "SC-28"),
    ],
    # CWE-942 — Permissive Cross-domain Policy (CORS misconfig)
    "CWE-942": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_NIST_800_53, "AC-4"),
        (FRAMEWORK_OWASP_TOP10, "A05:2021"),
    ],
    # CWE-943 — Improper Neutralization of Special Elements (NoSQL injection)
    "CWE-943": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-1004 — Sensitive Cookie Without HttpOnly
    "CWE-1004": [
        (FRAMEWORK_SOC2, "CC6.7"),
        (FRAMEWORK_ISO27001, "A.8.24"),
        (FRAMEWORK_OWASP_ASVS, "V3.4"),
    ],
    # CWE-1104 — Use of Unmaintained Third-Party Components
    "CWE-1104": [
        (FRAMEWORK_SOC2, "CC9.2"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_NIST_800_53, "SI-2"),
        (FRAMEWORK_OWASP_TOP10, "A06:2021"),
    ],
    # CWE-1236 — Improper Neutralization of Formula Elements
    # (CSV / spreadsheet formula injection)
    "CWE-1236": [
        (FRAMEWORK_SOC2, "CC6.6"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_NIST_800_53, "SI-10"),
    ],
    # CWE-1321 — Prototype Pollution
    "CWE-1321": [
        (FRAMEWORK_SOC2, "CC6.1"),
        (FRAMEWORK_ISO27001, "A.8.26"),
        (FRAMEWORK_OWASP_ASVS, "V5.5.3"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
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
        (FRAMEWORK_OWASP_TOP10, "A03:2021"),
    ],
    # CWE-1357 — Reliance on Insufficiently Trustworthy Component
    # (Docker :latest tag, deps without integrity)
    "CWE-1357": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_SOC2, "CC8.1"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2.4"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
    ],
    # CWE-1395 — Vulnerable Software (KEV-flagged + CVE-known)
    "CWE-1395": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_SOC2, "CC9.2"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_PCI_DSS, "6.2"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_NIST_800_53, "SI-2"),
        (FRAMEWORK_OWASP_TOP10, "A06:2021"),
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
        (FRAMEWORK_NIST_800_53, "SI-2"),
        (FRAMEWORK_OWASP_TOP10, "A06:2021"),
        (FRAMEWORK_CIS, "16.11"),
    ],
    "malicious_dependency": [
        (FRAMEWORK_SOC2, "CC6.8"),
        (FRAMEWORK_ISO27001, "A.5.21"),
        (FRAMEWORK_ISO27001, "A.8.7"),
        (FRAMEWORK_PCI_DSS, "6.3.2"),
        (FRAMEWORK_OWASP_ASVS, "V14.2.4"),
        (FRAMEWORK_HIPAA, "164.308(a)(5)(ii)(B)"),
        (FRAMEWORK_NIST_800_53, "SI-2"),
        (FRAMEWORK_OWASP_TOP10, "A08:2021"),
        (FRAMEWORK_CIS, "16.11"),
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
        (FRAMEWORK_NIST_800_53, "CM-6"),
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


def controls_for_by_framework(
    cwe: str | None = None,
    category: str | None = None,
) -> dict[str, list[str]]:
    """Same as `controls_for` but returns
    `{framework: [control_id, ...]}` shape — what the per-finding
    decorator emits as `compliance_controls` on each finding."""
    out: dict[str, list[str]] = {}
    for fw, cid in controls_for(cwe=cwe, category=category):
        out.setdefault(fw, []).append(cid)
    for fw in out:
        out[fw].sort()
    return out


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


def rules_for_control(framework: str, control_id: str) -> set[str]:
    """Inverse of `controls_for` — for a given (framework,
    control_id), return the set of rule-keys (CWE IDs +
    category labels) in our corpus that map to it.

    The set size is the "rule-corpus depth" for that control:
    how many distinct rules strix would surface against it. An
    auditor reading the evidence can use this to judge "how
    aggressively did strix probe this control" — a control
    with 12 mapped rules where 12 ran is well-covered; one with
    1 mapped rule is thin.

    Returns an empty set when the control isn't covered.
    """
    target = (framework, control_id)
    out: set[str] = set()
    for cwe, controls in CWE_TO_CONTROLS.items():
        if target in controls:
            out.add(cwe)
    for category, controls in CATEGORY_TO_CONTROLS.items():
        if target in controls:
            out.add(f"category:{category}")
    return out


def corpus_size_for_control(framework: str, control_id: str) -> int:
    """Count of distinct rules in our corpus mapping to this
    control. Convenience wrapper around `rules_for_control`."""
    return len(rules_for_control(framework, control_id))


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
