"""Compliance framework control catalogs.

Each framework is a dict mapping `control_id` → `Control` with
title + brief description. Catalogs are deliberately narrow:
we only carry controls that strix's rule corpus can plausibly
test against. Auditors who need broader coverage get it from
their compliance platform; we provide the application-security
slice.

Frameworks shipped in v1:

  * **SOC 2** Trust Service Criteria — `CC*` (Common Criteria)
    + `A1.x` (Availability) + `C1.x` (Confidentiality).
    Focus on CC6 (logical access) and CC7 (system operations)
    since that's where application-security findings land.
  * **ISO 27001:2022** Annex A — A.5 / A.8 (organizational +
    technological). Mostly A.8 controls for AppSec.
  * **PCI DSS 4.0** — Requirements 6, 7, 8, 11. The bulk of
    AppSec findings map to Req 6 (secure development).
  * **OWASP ASVS 4.0** — V2 / V3 / V4 / V5 / V8 / V9 / V13.
    Most AppSec frameworks reference ASVS sections; we keep
    the verifiable subset.

Out of v1 (deferred):
  * HIPAA Security Rule, GDPR Art. 32, EU AI Act, CIS
    Benchmarks. All add complexity (HIPAA needs legal review;
    CIS is infrastructure-class).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


FRAMEWORK_SOC2 = "soc2"
FRAMEWORK_ISO27001 = "iso27001"
FRAMEWORK_PCI_DSS = "pci_dss"
FRAMEWORK_OWASP_ASVS = "owasp_asvs"

ALL_FRAMEWORKS = [
    FRAMEWORK_SOC2,
    FRAMEWORK_ISO27001,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_OWASP_ASVS,
]


@dataclass(frozen=True)
class Control:
    """One named control / criterion within a framework."""
    framework: str
    id: str
    title: str
    description: str = ""

    @property
    def fqid(self) -> str:
        """Fully-qualified ID — `<framework>:<id>`."""
        return f"{self.framework}:{self.id}"

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "fqid": self.fqid,
        }


# ---------------------------------------------------------------------------
# SOC 2 Trust Service Criteria
# ---------------------------------------------------------------------------

# The CC (Common Criteria) numbering aligns with the AICPA TSP
# Section 100 (2017). We carry the criteria that AppSec findings
# typically map to. CC1–CC5 are governance / risk-management
# controls (organizational), not directly testable by AppSec
# tools — omitted.

_SOC2_CONTROLS: dict[str, Control] = {
    "CC6.1": Control(
        FRAMEWORK_SOC2, "CC6.1",
        "Logical access security software, infrastructure, and architectures",
        "Identifies, authenticates, and authorises users to "
        "protect information assets from unauthorised access.",
    ),
    "CC6.2": Control(
        FRAMEWORK_SOC2, "CC6.2",
        "Identity assertion and authentication credentials",
        "Registers and authorises users; revokes when users no "
        "longer require access.",
    ),
    "CC6.3": Control(
        FRAMEWORK_SOC2, "CC6.3",
        "Access removal, role changes",
        "Removes / modifies access when no longer required, "
        "based on role or employment status.",
    ),
    "CC6.6": Control(
        FRAMEWORK_SOC2, "CC6.6",
        "Logical access security measures (network / application)",
        "Protects against external threats. Includes firewall "
        "rules, CORS / CSP enforcement, network segmentation.",
    ),
    "CC6.7": Control(
        FRAMEWORK_SOC2, "CC6.7",
        "Restricts transmission of information",
        "Encrypts data in transit (TLS), uses authenticated "
        "channels, prevents disclosure during transmission.",
    ),
    "CC6.8": Control(
        FRAMEWORK_SOC2, "CC6.8",
        "Detects malicious software",
        "Implements controls to prevent / detect malicious "
        "software (vulnerable + malicious dependencies).",
    ),
    "CC7.1": Control(
        FRAMEWORK_SOC2, "CC7.1",
        "Detection of vulnerabilities and security events",
        "Monitors system components and operations for "
        "anomalies indicative of malicious / vulnerable behaviour.",
    ),
    "CC7.2": Control(
        FRAMEWORK_SOC2, "CC7.2",
        "Anomaly detection",
        "Monitors for behavioural anomalies in systems / "
        "applications; investigates suspected events.",
    ),
    "CC8.1": Control(
        FRAMEWORK_SOC2, "CC8.1",
        "Change management",
        "Manages changes to infrastructure, data, software, "
        "and procedures to support security objectives.",
    ),
    "CC9.2": Control(
        FRAMEWORK_SOC2, "CC9.2",
        "Vendor / third-party risk management",
        "Assesses + monitors third-party vendors. Maps to "
        "license-compliance + supply-chain controls.",
    ),
    "A1.2": Control(
        FRAMEWORK_SOC2, "A1.2",
        "Resilience and availability",
        "System availability protection from unauthorised / "
        "DoS-class threats. Resource-exhaustion class controls.",
    ),
    "C1.1": Control(
        FRAMEWORK_SOC2, "C1.1",
        "Confidentiality of information",
        "Information designated as confidential is protected "
        "during collection, use, retention, and disposal.",
    ),
}


# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A
# ---------------------------------------------------------------------------

# 2022 revision collapsed the previous 14 domains into 4
# themes. We carry A.5 (Organizational), A.8 (Technological).

_ISO27001_CONTROLS: dict[str, Control] = {
    "A.5.21": Control(
        FRAMEWORK_ISO27001, "A.5.21",
        "Managing information security in the ICT supply chain",
        "Define + manage information-security risks throughout "
        "the supplier / dependency chain.",
    ),
    "A.5.32": Control(
        FRAMEWORK_ISO27001, "A.5.32",
        "Intellectual property rights",
        "Procedures to ensure compliance with legislative + "
        "contractual requirements (license compliance lives here).",
    ),
    "A.8.2": Control(
        FRAMEWORK_ISO27001, "A.8.2",
        "Privileged access rights",
        "Allocation + use of privileged access rights "
        "(USER-root containers, privileged compose services).",
    ),
    "A.8.3": Control(
        FRAMEWORK_ISO27001, "A.8.3",
        "Information access restriction",
        "Restrict access to information per access policy.",
    ),
    "A.8.5": Control(
        FRAMEWORK_ISO27001, "A.8.5",
        "Secure authentication",
        "Authentication procedures shall be in place to "
        "control access (JWT, OAuth, session management).",
    ),
    "A.8.6": Control(
        FRAMEWORK_ISO27001, "A.8.6",
        "Capacity management",
        "Resource use shall be monitored + tuned to ensure "
        "required capacity (DoS class controls).",
    ),
    "A.8.7": Control(
        FRAMEWORK_ISO27001, "A.8.7",
        "Protection against malware",
        "Detection / prevention controls (vulnerable + "
        "malicious dependency detection).",
    ),
    "A.8.10": Control(
        FRAMEWORK_ISO27001, "A.8.10",
        "Information deletion",
        "Information stored in information systems / devices / "
        "removable media shall be deleted when no longer needed.",
    ),
    "A.8.20": Control(
        FRAMEWORK_ISO27001, "A.8.20",
        "Network security",
        "Networks + network devices shall be secured / managed "
        "(SSRF allow-lists, network policies).",
    ),
    "A.8.22": Control(
        FRAMEWORK_ISO27001, "A.8.22",
        "Segregation of networks",
        "Groups of information services / users / systems "
        "shall be segregated in networks.",
    ),
    "A.8.24": Control(
        FRAMEWORK_ISO27001, "A.8.24",
        "Use of cryptography",
        "Rules for effective use of cryptography (TLS, hashing, "
        "key management).",
    ),
    "A.8.26": Control(
        FRAMEWORK_ISO27001, "A.8.26",
        "Application security requirements",
        "Information-security requirements shall be identified, "
        "specified + approved when developing / acquiring "
        "applications.",
    ),
    "A.8.27": Control(
        FRAMEWORK_ISO27001, "A.8.27",
        "Secure system architecture and engineering principles",
        "Engineering practices for secure systems "
        "(error handling, defense in depth).",
    ),
    "A.8.28": Control(
        FRAMEWORK_ISO27001, "A.8.28",
        "Secure coding",
        "Secure-coding principles applied to software "
        "development.",
    ),
    "A.8.29": Control(
        FRAMEWORK_ISO27001, "A.8.29",
        "Security testing in development and acceptance",
        "Security testing processes shall be defined + "
        "implemented in the development lifecycle.",
    ),
    "A.8.30": Control(
        FRAMEWORK_ISO27001, "A.8.30",
        "Outsourced development",
        "Org shall direct + monitor outsourced development "
        "(supply-chain checkpoints).",
    ),
    "A.8.32": Control(
        FRAMEWORK_ISO27001, "A.8.32",
        "Change management",
        "Changes to information-processing facilities + "
        "information systems shall follow change-management "
        "procedures.",
    ),
}


# ---------------------------------------------------------------------------
# PCI DSS 4.0
# ---------------------------------------------------------------------------

# PCI DSS = Payment Card Industry Data Security Standard.
# Req 6 (secure development) is where most AppSec findings land.
# We carry the requirements specifically referenced by our
# CWE-class mappings.

_PCI_DSS_CONTROLS: dict[str, Control] = {
    "4.1": Control(
        FRAMEWORK_PCI_DSS, "4.1",
        "Strong cryptography for transmission of cardholder data",
        "Use strong cryptography + security protocols when "
        "transmitting cardholder data over open public networks.",
    ),
    "4.2": Control(
        FRAMEWORK_PCI_DSS, "4.2",
        "Cardholder data is never sent unencrypted",
        "Encrypt cardholder data using TLS / strong crypto; "
        "validate certificates.",
    ),
    "6.2": Control(
        FRAMEWORK_PCI_DSS, "6.2",
        "Bespoke + custom software developed securely",
        "SDLC shall include security at design / development / "
        "test / deployment stages.",
    ),
    "6.3.2": Control(
        FRAMEWORK_PCI_DSS, "6.3.2",
        "Inventory of bespoke + custom software components and TPSCs",
        "Maintain inventory of third-party software "
        "components (SCA territory).",
    ),
    "6.4.1": Control(
        FRAMEWORK_PCI_DSS, "6.4.1",
        "Public-facing web applications protection",
        "Protect from known attacks. Periodic application-layer "
        "review + automated technical solution (WAF / SAST / DAST).",
    ),
    "6.5.1": Control(
        FRAMEWORK_PCI_DSS, "6.5.1",
        "Injection flaws (SQL, NoSQL, OS command, LDAP)",
        "Address injection flaws via parameterised queries / "
        "input validation.",
    ),
    "6.5.4": Control(
        FRAMEWORK_PCI_DSS, "6.5.4",
        "Insecure communications",
        "Address insecure communications channels (TLS, "
        "certificate validation).",
    ),
    "6.5.5": Control(
        FRAMEWORK_PCI_DSS, "6.5.5",
        "Improper error handling",
        "Address improper error handling (stack traces in "
        "responses, verbose errors).",
    ),
    "6.5.7": Control(
        FRAMEWORK_PCI_DSS, "6.5.7",
        "Cross-site scripting (XSS)",
        "Address XSS class flaws via output encoding + CSP.",
    ),
    "6.5.8": Control(
        FRAMEWORK_PCI_DSS, "6.5.8",
        "Improper access control",
        "Address improper access controls (path traversal, "
        "missing authz, IDOR).",
    ),
    "6.5.9": Control(
        FRAMEWORK_PCI_DSS, "6.5.9",
        "Cross-site request forgery (CSRF)",
        "Address CSRF via tokens or origin / sameSite cookies.",
    ),
    "6.5.10": Control(
        FRAMEWORK_PCI_DSS, "6.5.10",
        "Broken authentication and session management",
        "Address broken auth + session management (mass "
        "assignment, deserialization, weak passwords).",
    ),
    "7.1": Control(
        FRAMEWORK_PCI_DSS, "7.1",
        "Restrict access to system components by need-to-know",
        "Limit access to those whose job requires it. Default "
        "= deny.",
    ),
    "8.2": Control(
        FRAMEWORK_PCI_DSS, "8.2",
        "User authentication",
        "Strong cryptography for authentication credentials "
        "(no hardcoded creds; rotate JWT keys; use bcrypt + "
        "high cost factor).",
    ),
    "8.2.1": Control(
        FRAMEWORK_PCI_DSS, "8.2.1",
        "User authentication credentials never stored in clear",
        "Render credentials unreadable during storage + "
        "transmission (no hardcoded secrets in source / env).",
    ),
    "11.3": Control(
        FRAMEWORK_PCI_DSS, "11.3",
        "External + internal penetration testing",
        "Annual + after significant change. AppSec scanning "
        "supports the technical-controls slice of this.",
    ),
}


# ---------------------------------------------------------------------------
# OWASP ASVS 4.0
# ---------------------------------------------------------------------------

# Application Security Verification Standard. We carry the
# requirements that align with our CWE corpus.

_OWASP_ASVS_CONTROLS: dict[str, Control] = {
    "V2": Control(
        FRAMEWORK_OWASP_ASVS, "V2",
        "Authentication",
        "Authentication is the act of establishing identity.",
    ),
    "V2.4": Control(
        FRAMEWORK_OWASP_ASVS, "V2.4",
        "Credential storage",
        "Use of strong adaptive hashing (bcrypt / argon2 / "
        "scrypt) for credentials.",
    ),
    "V2.10": Control(
        FRAMEWORK_OWASP_ASVS, "V2.10",
        "Service authentication",
        "API keys / secrets stored securely (not hardcoded; "
        "use vault / env vars).",
    ),
    "V3.4": Control(
        FRAMEWORK_OWASP_ASVS, "V3.4",
        "Cookie-based session bindings",
        "Cookies have Secure / HttpOnly / SameSite attributes.",
    ),
    "V3.5": Control(
        FRAMEWORK_OWASP_ASVS, "V3.5",
        "Token-based session management",
        "JWTs / sessions are signed + verified with strong algorithms.",
    ),
    "V4.1": Control(
        FRAMEWORK_OWASP_ASVS, "V4.1",
        "General access control design",
        "Access control enforced at every endpoint; deny by default.",
    ),
    "V4.2.2": Control(
        FRAMEWORK_OWASP_ASVS, "V4.2.2",
        "Operation level access control (CSRF)",
        "State-changing operations require CSRF tokens or "
        "equivalent (origin checks).",
    ),
    "V5.1.2": Control(
        FRAMEWORK_OWASP_ASVS, "V5.1.2",
        "Mass parameter assignment guards",
        "Allow-list parameters that can be set per endpoint.",
    ),
    "V5.1.5": Control(
        FRAMEWORK_OWASP_ASVS, "V5.1.5",
        "URL redirects + forwards validation",
        "Untrusted redirect destinations validated (open-"
        "redirect prevention).",
    ),
    "V5.3.3": Control(
        FRAMEWORK_OWASP_ASVS, "V5.3.3",
        "Output encoding for XSS prevention",
        "Output is encoded for the consuming context (HTML, "
        "JS, attribute, URL).",
    ),
    "V5.3.4": Control(
        FRAMEWORK_OWASP_ASVS, "V5.3.4",
        "Parameterised queries (SQL / NoSQL)",
        "Prevent injection by parameterised queries / ORM.",
    ),
    "V5.3.7": Control(
        FRAMEWORK_OWASP_ASVS, "V5.3.7",
        "Server-side template injection prevention",
        "Validate templates do not include user-controlled "
        "values as the template body.",
    ),
    "V5.3.8": Control(
        FRAMEWORK_OWASP_ASVS, "V5.3.8",
        "OS command injection prevention",
        "Avoid shell + exec on user input. Use argv list form.",
    ),
    "V5.5.2": Control(
        FRAMEWORK_OWASP_ASVS, "V5.5.2",
        "XML external entities (XXE) prevention",
        "XML parsers configured to disallow external entities.",
    ),
    "V5.5.3": Control(
        FRAMEWORK_OWASP_ASVS, "V5.5.3",
        "Untrusted-data deserialization prevention",
        "Avoid pickle / Java-binary / fastjson on untrusted "
        "input. Includes prototype pollution variants.",
    ),
    "V6.2": Control(
        FRAMEWORK_OWASP_ASVS, "V6.2",
        "Algorithms",
        "Approved algorithms (no MD5/SHA-1 for security; "
        "AES-GCM not ECB; no DES).",
    ),
    "V6.3": Control(
        FRAMEWORK_OWASP_ASVS, "V6.3",
        "Random values",
        "Cryptographically-strong RNG for tokens, keys, IVs.",
    ),
    "V7.1.1": Control(
        FRAMEWORK_OWASP_ASVS, "V7.1.1",
        "Log + error handling — sensitive data exposure",
        "Errors do not leak stack traces / internal state to "
        "users.",
    ),
    "V8.1": Control(
        FRAMEWORK_OWASP_ASVS, "V8.1",
        "General data protection",
        "Sensitive data is identified + protected.",
    ),
    "V9.2": Control(
        FRAMEWORK_OWASP_ASVS, "V9.2",
        "Server communications",
        "TLS configuration is current + verified (no `verify=False`).",
    ),
    "V11.1": Control(
        FRAMEWORK_OWASP_ASVS, "V11.1",
        "Business-logic security",
        "Logic flaws + DoS (ReDoS, large-body) treated as "
        "security risks.",
    ),
    "V11.1.4": Control(
        FRAMEWORK_OWASP_ASVS, "V11.1.4",
        "Resource-exhaustion / DoS limits",
        "Rate-limit / size-limit controls on endpoints + "
        "body parsing.",
    ),
    "V12.1": Control(
        FRAMEWORK_OWASP_ASVS, "V12.1",
        "File upload validation",
        "Validate uploaded file type + size + content.",
    ),
    "V12.3.1": Control(
        FRAMEWORK_OWASP_ASVS, "V12.3.1",
        "File path validation",
        "User-controlled paths validated against an allow-list "
        "or normalised before file ops.",
    ),
    "V13.2.1": Control(
        FRAMEWORK_OWASP_ASVS, "V13.2.1",
        "API security — server / client auth",
        "REST / GraphQL endpoints enforce auth.",
    ),
    "V13.2.6": Control(
        FRAMEWORK_OWASP_ASVS, "V13.2.6",
        "API security — SSRF / network egress",
        "Egress URLs validated against an allow-list.",
    ),
    "V14.2": Control(
        FRAMEWORK_OWASP_ASVS, "V14.2",
        "Build configuration",
        "Production builds disable debug, profilers, dev tools.",
    ),
    "V14.2.4": Control(
        FRAMEWORK_OWASP_ASVS, "V14.2.4",
        "Third-party + open-source components",
        "Inventory + monitor 3rd-party components for "
        "vulnerabilities.",
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_FRAMEWORK_CATALOGS: dict[str, dict[str, Control]] = {
    FRAMEWORK_SOC2: _SOC2_CONTROLS,
    FRAMEWORK_ISO27001: _ISO27001_CONTROLS,
    FRAMEWORK_PCI_DSS: _PCI_DSS_CONTROLS,
    FRAMEWORK_OWASP_ASVS: _OWASP_ASVS_CONTROLS,
}


def get_control(framework: str, control_id: str) -> Control | None:
    """Look up a single control. Returns None when unknown."""
    catalog = _FRAMEWORK_CATALOGS.get(framework.lower())
    if catalog is None:
        return None
    return catalog.get(control_id)


def get_framework_controls(
    framework: str,
) -> list[Control]:
    """Return all controls in a framework (sorted by ID)."""
    catalog = _FRAMEWORK_CATALOGS.get(framework.lower())
    if not catalog:
        return []
    return [catalog[cid] for cid in sorted(catalog.keys())]


def all_controls(
    frameworks: Iterable[str] | None = None,
) -> list[Control]:
    """All controls across the requested frameworks (default: all)."""
    fws = list(frameworks) if frameworks else ALL_FRAMEWORKS
    out: list[Control] = []
    for fw in fws:
        out.extend(get_framework_controls(fw))
    return out
