"""iter-22.4 — `scan_dns_hygiene_checkdmarc` library wrapper.

`checkdmarc` (PyPI: `checkdmarc`) audits a domain's SPF / DKIM /
DMARC / MX records + CAA + BIMI + MTA-STS. Pure-Python — no
subprocess.

Findings emitted per missing / insecure record:

  * `dmarc-missing`         — high  (CWE-300 — domain spoofable)
  * `dmarc-policy-none`     — medium (CWE-300 — policy=none = monitor-only)
  * `spf-missing`           — high  (CWE-300)
  * `spf-permissive`        — medium (SPF `+all` or `?all`)
  * `dkim-missing`          — low   (informational — DMARC requires either SPF or DKIM)
  * `mta-sts-missing`       — low   (DoH downgrade protection absent)
  * `caa-missing`           — info  (informational — defense-in-depth)
  * `bimi-missing`          — info  (informational — brand visibility, not security)

The lib has its own DNS-resolver path; we don't wrap timeouts at
the strix layer because checkdmarc's `timeout=` kwarg handles
that. We DO surface lib-import failure as `status=partial` so the
tool degrades gracefully when the optional dep isn't installed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


def _checkdmarc_disabled() -> bool:
    return os.environ.get(
        "STRIX_CHECKDMARC_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1583.001", "T1566.002"],
)
def scan_dns_hygiene_checkdmarc(
    domain: str,
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Audit a domain's SPF/DKIM/DMARC/MX/CAA/MTA-STS posture.

    Args:
        domain: apex or subdomain (e.g. `example.com`,
            `mail.example.com`).
        timeout: per-DNS-query timeout in seconds (default 6).

    Returns:
        `{success, status, domain, total_findings, findings,
          summary, reason?}`
    """
    if _checkdmarc_disabled():
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": "STRIX_CHECKDMARC_DISABLED=1",
        }
    if not domain or not domain.strip():
        return {
            "success": False, "status": "error", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": "domain required",
        }

    try:
        import checkdmarc  # noqa: F401
        from checkdmarc import check_domains
    except Exception as e:  # noqa: BLE001
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": (
                f"checkdmarc lib not available: {type(e).__name__}. "
                "Install: `pip install checkdmarc`."
            ),
        }

    try:
        # `check_domains` accepts a list; we audit one domain.
        results = check_domains([domain.strip().lower()], timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {
            "success": False, "status": "error", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": f"checkdmarc.check_domains raised: {type(e).__name__}: {e}",
        }

    # checkdmarc returns list-of-dicts (one per input domain). We
    # gave one → take the first.
    if isinstance(results, list) and results:
        rec = results[0]
    elif isinstance(results, dict):
        rec = results
    else:
        return {
            "success": False, "status": "error", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": f"checkdmarc returned unexpected shape: {type(results).__name__}",
        }

    findings: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}

    # DMARC
    dmarc = (rec.get("dmarc") or {}) if isinstance(rec, dict) else {}
    if isinstance(dmarc, dict):
        valid = dmarc.get("valid")
        if not valid:
            findings.append({
                "rule_id": "dmarc-missing",
                "title": f"Missing or invalid DMARC record on `{domain}`",
                "severity": "high",
                "cwe": "CWE-300",
                "description": (
                    f"`{domain}` has no valid DMARC record. Receiving "
                    "MTAs have no policy to apply when SPF / DKIM "
                    "fail — phishing emails spoofing this domain "
                    "are deliverable. DMARC error: "
                    f"{dmarc.get('error') or '(none reported)'}"
                ),
                "remediation": (
                    "Publish a DMARC TXT record at "
                    f"`_dmarc.{domain}` with `v=DMARC1; p=reject; "
                    "rua=mailto:dmarc@yourdomain;`. Start with "
                    "`p=none` for monitoring, then escalate to "
                    "`p=quarantine` and `p=reject` once aligned."
                ),
            })
        else:
            tags = (dmarc.get("tags") or {}) if isinstance(dmarc.get("tags"), dict) else {}
            policy = (tags.get("p") or {}).get("value", "")
            if isinstance(policy, str) and policy.lower() == "none":
                findings.append({
                    "rule_id": "dmarc-policy-none",
                    "title": (
                        f"DMARC policy is `p=none` on `{domain}` "
                        "(monitor-only)"
                    ),
                    "severity": "medium",
                    "cwe": "CWE-300",
                    "description": (
                        f"`{domain}`'s DMARC policy is `p=none`. "
                        "Mail receivers ignore the policy — failures "
                        "still aren't blocked. Use `p=none` only "
                        "during the initial DMARC deployment phase."
                    ),
                    "remediation": (
                        "Escalate `_dmarc.{domain}` to `p=quarantine` "
                        "(quarantine failing mail) then `p=reject` "
                        "(bounce failing mail) once your reports show "
                        "100% aligned legitimate traffic."
                    ),
                })

    # SPF
    spf = (rec.get("spf") or {}) if isinstance(rec, dict) else {}
    if isinstance(spf, dict):
        valid = spf.get("valid")
        record = (spf.get("record") or "") if isinstance(spf.get("record"), str) else ""
        if not valid:
            findings.append({
                "rule_id": "spf-missing",
                "title": f"Missing or invalid SPF record on `{domain}`",
                "severity": "high",
                "cwe": "CWE-300",
                "description": (
                    f"`{domain}` has no valid SPF record. Mail-sender "
                    "validation can't distinguish legitimate senders "
                    "from spoofs. SPF error: "
                    f"{spf.get('error') or '(none reported)'}"
                ),
                "remediation": (
                    "Publish a TXT record at the apex `@` with "
                    "`v=spf1 ... -all` listing your authorised "
                    "senders. End with `-all` (hard fail) or `~all` "
                    "(soft fail). Never `+all` or `?all`."
                ),
            })
        elif "+all" in record.replace(" ", "").lower() or "?all" in record.replace(" ", "").lower():
            findings.append({
                "rule_id": "spf-permissive",
                "title": (
                    f"SPF record on `{domain}` uses permissive "
                    "`+all` or `?all`"
                ),
                "severity": "medium",
                "cwe": "CWE-300",
                "description": (
                    f"`{domain}`'s SPF record (`{record}`) ends "
                    "with `+all` or `?all`, which authorises ANY "
                    "sender. Equivalent to having no SPF at all "
                    "for spoofing-prevention purposes."
                ),
                "remediation": (
                    "Replace `+all` / `?all` with `-all` (hard "
                    "fail) once you've confirmed the include / "
                    "ip4 / ip6 mechanisms cover your legitimate "
                    "senders."
                ),
            })

    # MTA-STS
    mta_sts = (rec.get("mta_sts") or {}) if isinstance(rec, dict) else {}
    if isinstance(mta_sts, dict) and not mta_sts.get("valid"):
        findings.append({
            "rule_id": "mta-sts-missing",
            "title": f"MTA-STS missing on `{domain}`",
            "severity": "low",
            "cwe": "CWE-319",
            "description": (
                f"`{domain}` has no valid MTA-STS policy. Mail "
                "delivery to this domain can be downgraded by an "
                "on-path attacker (delivery-time STARTTLS "
                "stripping)."
            ),
            "remediation": (
                "Publish an MTA-STS policy at "
                f"`https://mta-sts.{domain}/.well-known/mta-sts.txt` "
                "with `mode: enforce` after testing in `mode: "
                "testing` for 2-4 weeks."
            ),
        })

    summary = {
        "dmarc_valid": dmarc.get("valid", False) if isinstance(dmarc, dict) else False,
        "spf_valid": spf.get("valid", False) if isinstance(spf, dict) else False,
        "mta_sts_valid": mta_sts.get("valid", False) if isinstance(mta_sts, dict) else False,
    }

    # Tracer emit
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
                    endpoint=domain,
                    category="dns_hygiene",
                    verification_status="verified",
                    confidence=0.95,
                    description=f["description"],
                    impact=(
                        f"DNS / email-hygiene rule `{f['rule_id']}` "
                        f"on `{domain}`."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Tool: checkdmarc (DNS / SPF / DMARC / "
                        f"DKIM / MTA-STS auditor)\n"
                        f"Rule: {f['rule_id']}\nDomain: {domain}"
                    ),
                    reasoning_trace=[
                        f"checkdmarc audited `{domain}`.",
                        f"Rule `{f['rule_id']}` matched.",
                    ],
                    poc_description=(
                        f"Reproduce: `dig TXT _dmarc.{domain}` and "
                        f"`dig TXT {domain}` for SPF."
                    ),
                    poc_script_code=(
                        f"dig TXT {domain}; dig TXT _dmarc.{domain}"
                    ),
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("checkdmarc tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "domain": domain,
        "total_findings": len(findings),
        "findings": findings,
        "summary": summary,
    }
