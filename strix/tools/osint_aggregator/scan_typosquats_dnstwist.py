"""iter-22.6 — `scan_typosquats_dnstwist` subprocess wrapper.

dnstwist (https://github.com/elceef/dnstwist) generates a corpus
of typosquat / homograph domain candidates from a target apex
domain and checks which ones are registered + active. The
brand-monitoring commercial tier (Cyble, ZeroFOX, Constella)
sells this as a recurring SaaS feature; dnstwist is the OSS
equivalent.

Findings emitted per ACTIVE typosquat (DNS A record exists):

  * Severity: medium (CWE-1023 — improper-restriction-of-recipients)
  * Discovered domain + variant type (homograph, addition,
    transposition, etc.) + IP-A record observed
  * Optional banner fingerprint when the squat resolves to an HTTP
    service that returns a phishing-pattern page (dnstwist's
    `--whois` / `--banners` flags emit this — surface as
    `description_plain` augmentation when present).

Recall safety: returns `status=partial` when the binary isn't on
PATH (mirrors bbot / cosign / jwt_tool patterns).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_DNSTWIST_BIN = "dnstwist"
_DEFAULT_TIMEOUT_SECONDS = 120


def _dnstwist_disabled() -> bool:
    return os.environ.get(
        "STRIX_DNSTWIST_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


def _dnstwist_available() -> bool:
    if _dnstwist_disabled():
        return False
    return shutil.which(_DNSTWIST_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1583.001"],  # Acquire Infrastructure: Domains
)
def scan_typosquats_dnstwist(
    domain: str,
    max_variants: int = 200,
) -> dict[str, Any]:
    """Generate + probe typosquat candidates for a domain.

    Args:
        domain: apex (e.g. `example.com`).
        max_variants: cap returned variants (default 200).

    Returns:
        `{success, status, domain, total_findings, findings, reason?}`
    """
    if not domain or not domain.strip():
        return {
            "success": False, "status": "error", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": "domain required",
        }
    if not _dnstwist_available():
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": (
                "dnstwist binary not on PATH (or STRIX_DNSTWIST_DISABLED"
                "=1). Install: `pipx install dnstwist`."
            ),
        }

    cmd = [
        _DNSTWIST_BIN,
        "--registered",   # only show domains that actually resolve
        "--format", "json",
        domain.strip().lower(),
    ]
    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": f"dnstwist invocation failed: {type(e).__name__}: {e}",
        }

    try:
        records = json.loads(result.stdout or "[]")
    except (ValueError, TypeError):
        records = []
    if not isinstance(records, list):
        records = []

    findings: list[dict[str, Any]] = []
    for r in records[:max_variants]:
        if not isinstance(r, dict):
            continue
        squat_domain = r.get("domain") or r.get("fuzzer-domain") or ""
        if not squat_domain or squat_domain == domain.strip().lower():
            # Skip the apex itself; dnstwist sometimes includes it
            # in the registered list.
            continue
        fuzzer = r.get("fuzzer") or "(unknown)"
        dns_a = r.get("dns_a") or r.get("dns-a") or []
        if isinstance(dns_a, str):
            dns_a = [dns_a]
        findings.append({
            "rule_id": "typosquat-domain-registered",
            "title": (
                f"Typosquat domain registered for `{domain}`: "
                f"`{squat_domain}` (variant: {fuzzer})"
            ),
            "severity": "medium",
            "cwe": "CWE-1023",
            "squat_domain": squat_domain,
            "variant_type": fuzzer,
            "resolved_ips": list(dns_a) if isinstance(dns_a, list) else [],
            "description": (
                f"dnstwist found a registered typosquat candidate "
                f"`{squat_domain}` (variant type: `{fuzzer}`) "
                f"targeting `{domain}`. Resolved IPs: "
                f"{dns_a or '(none)'}. Phishing infrastructure may "
                "be staged here even if the domain currently "
                "returns no content — register-then-stage is the "
                "common attacker pattern."
            ),
            "remediation": (
                f"Investigate `{squat_domain}` for active phishing "
                "content. Submit to Google Safe Browsing / "
                "PhishTank if confirmed malicious. Consider "
                "defensively registering high-value typosquats."
            ),
        })

    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=domain,
                    endpoint=f["squat_domain"],
                    category="brand_monitoring",
                    verification_status="verified",
                    confidence=0.95,
                    description=f["description"],
                    impact=(
                        "Phishing / brand-impersonation domain "
                        f"registered against `{domain}` apex."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Tool: dnstwist\nVariant: {f['variant_type']}"
                        f"\nResolved IPs: {f['resolved_ips']}\n"
                        f"Target apex: {domain}\n"
                        f"Squat: {f['squat_domain']}"
                    ),
                    reasoning_trace=[
                        f"dnstwist generated variants for `{domain}`.",
                        f"`{f['squat_domain']}` is registered + "
                        "resolves.",
                    ],
                    poc_description=(
                        f"Reproduce: `dnstwist --registered {domain}`"
                    ),
                    poc_script_code=f"dnstwist --registered {domain}",
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("dnstwist tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "domain": domain,
        "total_findings": len(findings),
        "findings": findings,
    }
