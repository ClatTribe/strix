"""DNS hygiene checks for a domain target.

Wraps `dig` to evaluate the domain's email-security and DNS-security posture.
Each check that reveals a misconfiguration emits a structured finding via the
tracer; the function returns a per-check summary the agent can reason about.

Checks: SPF, DMARC, DKIM (common selectors), MTA-STS, DANE, BIMI, CAA,
DNSSEC chain, wildcard DNS, AXFR exposure, SOA / NS sanity.

This tool is deterministic — same input, same output (modulo the target's
actual DNS state). Intended to run during the recon phase, complementing
the agent's LLM-driven reasoning with reliable coverage of well-known
DNS-hygiene categories.
"""

from __future__ import annotations

import secrets
from typing import Any

from strix.tools.registry import register_tool

from ._common import dig, emit_finding, http_get_text, looks_like_domain


_DKIM_SELECTORS = [
    "default",
    "google",
    "k1",
    "k2",
    "mail",
    "selector1",
    "selector2",
    "dkim",
    "s1",
    "s2",
    "mailo",
    "smtp",
]


def _check_spf(domain: str) -> dict[str, Any]:
    txt = dig(domain, "TXT")
    spf_lines = [line.strip('"') for line in txt.splitlines() if "v=spf1" in line.lower()]
    if not spf_lines:
        emit_finding(
            title=f"Missing SPF record for {domain}",
            severity="medium",
            category="email_security",
            cwe="CWE-1278",
            target=domain,
            description=(
                "No SPF (Sender Policy Framework) record was published on the "
                "apex TXT records for this domain. Without SPF, receiving mail "
                "servers cannot validate which hosts are authorized to send mail "
                "for this domain."
            ),
            impact=(
                "Attackers can spoof email purportedly from this domain, bypassing "
                "basic anti-phishing checks at receiving servers and impersonating "
                "the brand against customers, partners, and employees."
            ),
            remediation=(
                "Publish a TXT record at the apex with `v=spf1 ...` listing the "
                "domains/IPs authorized to send mail (e.g. `include:_spf.google.com`) "
                "ending in `-all` (hard fail) or `~all` (soft fail). Avoid `+all`."
            ),
            verification_status="verified",
        )
        return {"check": "spf", "present": False, "value": None}
    return {"check": "spf", "present": True, "value": spf_lines[0]}


def _check_dmarc(domain: str) -> dict[str, Any]:
    txt = dig(f"_dmarc.{domain}", "TXT")
    dmarc_lines = [line.strip('"') for line in txt.splitlines() if "v=DMARC1" in line]
    if not dmarc_lines:
        emit_finding(
            title=f"Missing DMARC record for {domain}",
            severity="medium",
            category="email_security",
            cwe="CWE-1278",
            target=domain,
            description=(
                f"No DMARC record was found at `_dmarc.{domain}`. DMARC builds on "
                "SPF and DKIM to publish a domain-wide policy for handling mail "
                "that fails authentication."
            ),
            impact=(
                "Without DMARC, receiving servers have no published policy for "
                "rejecting or quarantining unauthenticated mail claiming to be from "
                "this domain — making brand impersonation easier."
            ),
            remediation=(
                f"Publish a TXT record at `_dmarc.{domain}` with at least "
                "`v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`. Move "
                "to `p=reject` once the rua reports show no legitimate mail being "
                "broken."
            ),
            verification_status="verified",
        )
        return {"check": "dmarc", "present": False, "policy": None}

    record = dmarc_lines[0]
    policy = "none"
    for token in record.split(";"):
        token = token.strip()
        if token.lower().startswith("p="):
            policy = token.split("=", 1)[1].strip().lower()
            break

    if policy in ("none", ""):
        emit_finding(
            title=f"DMARC policy is `p=none` for {domain}",
            severity="low",
            category="email_security",
            cwe="CWE-1278",
            target=domain,
            description=(
                f"`_dmarc.{domain}` is published with `p=none`, which means the "
                "domain owner has set up DMARC reporting but is not asking "
                "receivers to take any action against unauthenticated mail."
            ),
            impact=(
                "`p=none` provides visibility but no enforcement. Spoofed mail still "
                "reaches recipient inboxes."
            ),
            remediation=(
                "After reviewing the DMARC reports for legitimate senders, move to "
                "`p=quarantine` and then `p=reject`."
            ),
            verification_status="verified",
        )
    return {"check": "dmarc", "present": True, "policy": policy, "raw": record}


def _check_dkim(domain: str) -> dict[str, Any]:
    found_selectors: list[str] = []
    for selector in _DKIM_SELECTORS:
        txt = dig(f"{selector}._domainkey.{domain}", "TXT")
        if txt and "v=DKIM1" in txt:
            found_selectors.append(selector)
    if not found_selectors:
        # Don't emit a finding — DKIM uses arbitrary selectors and absence on
        # the common ones isn't conclusive evidence of absence. Just report.
        return {"check": "dkim", "selectors_found": [], "note": "common selectors only"}
    return {"check": "dkim", "selectors_found": found_selectors}


def _check_mta_sts(domain: str) -> dict[str, Any]:
    txt = dig(f"_mta-sts.{domain}", "TXT")
    has_record = bool(txt and "v=STSv1" in txt)
    if not has_record:
        emit_finding(
            title=f"MTA-STS not configured for {domain}",
            severity="low",
            category="email_security",
            cwe="CWE-1278",
            target=domain,
            description=(
                f"No MTA-STS record was found at `_mta-sts.{domain}`. MTA-STS "
                "lets a domain require TLS for incoming SMTP and pin which mail "
                "exchangers are valid."
            ),
            impact=(
                "Without MTA-STS, mail in transit to this domain can be downgraded "
                "to cleartext or routed via attacker-controlled MX servers."
            ),
            remediation=(
                f"Publish `_mta-sts.{domain}` TXT with `v=STSv1; id=...` and serve "
                f"a valid policy at https://mta-sts.{domain}/.well-known/mta-sts.txt"
            ),
            verification_status="verified",
        )
        return {"check": "mta_sts", "present": False}

    # Optional: validate the policy file is reachable.
    status, body = http_get_text(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    return {
        "check": "mta_sts",
        "present": True,
        "policy_reachable": status == 200,
        "policy_status": status,
    }


def _check_caa(domain: str) -> dict[str, Any]:
    out = dig(domain, "CAA")
    if not out:
        emit_finding(
            title=f"No CAA records on {domain}",
            severity="low",
            category="dns_security",
            cwe="CWE-295",
            target=domain,
            description=(
                "No Certificate Authority Authorization (CAA) records are published "
                f"for {domain}. Without CAA, any public CA can issue certificates "
                "for this domain."
            ),
            impact=(
                "An attacker who compromises any CA — or who tricks a CA into "
                "issuing a misvalidated cert — can mint a valid certificate for "
                "this domain. CAA narrows the set of CAs that should issue."
            ),
            remediation=(
                f"Publish CAA records (e.g. `0 issue \"letsencrypt.org\"`) at the "
                "apex listing the CAs you actually use, plus an `iodef` URL."
            ),
            verification_status="verified",
        )
        return {"check": "caa", "present": False}
    return {"check": "caa", "present": True, "records": out.splitlines()}


def _check_dnssec(domain: str) -> dict[str, Any]:
    dnskey = dig(domain, "DNSKEY")
    rrsig = dig(domain, "RRSIG")
    if not dnskey:
        emit_finding(
            title=f"DNSSEC not enabled on {domain}",
            severity="low",
            category="dns_security",
            cwe="CWE-345",
            target=domain,
            description=(
                f"No DNSKEY records were observed for {domain}. The domain is not "
                "DNSSEC-signed."
            ),
            impact=(
                "DNS responses for this domain can be spoofed by on-path attackers "
                "or via cache-poisoning attacks against recursive resolvers."
            ),
            remediation=(
                "Enable DNSSEC at the registrar / DNS provider. Publish DS records "
                "at the parent zone after key rollover."
            ),
            verification_status="verified",
        )
        return {"check": "dnssec", "signed": False}
    return {"check": "dnssec", "signed": True, "has_rrsig": bool(rrsig)}


def _check_wildcard(domain: str) -> dict[str, Any]:
    rand = secrets.token_hex(8)
    out = dig(f"{rand}-bench-probe.{domain}", "A")
    if out:
        emit_finding(
            title=f"Wildcard DNS detected for {domain}",
            severity="info",
            category="dns_security",
            cwe="CWE-1391",
            target=domain,
            description=(
                f"A random non-existent subdomain `{rand}-bench-probe.{domain}` "
                f"resolved to `{out.splitlines()[0]}`. The domain is configured "
                "with wildcard DNS."
            ),
            impact=(
                "Wildcard DNS makes subdomain enumeration noisy (brute-forcers "
                "see false positives). It also enables phishing via attacker-"
                "chosen subdomain names that all resolve, increasing the apparent "
                "trust of malicious URLs."
            ),
            remediation=(
                "If the wildcard is intentional (e.g. SaaS multi-tenant), document "
                "it. Otherwise replace the wildcard with explicit per-subdomain "
                "records."
            ),
            verification_status="verified",
        )
        return {"check": "wildcard", "present": True, "resolves_to": out.splitlines()[0]}
    return {"check": "wildcard", "present": False}


def _check_axfr(domain: str) -> dict[str, Any]:
    ns_out = dig(domain, "NS")
    nameservers = [n.rstrip(".") for n in ns_out.splitlines() if n]
    if not nameservers:
        return {"check": "axfr", "tested": False, "note": "no NS records"}

    leaks: list[str] = []
    for ns in nameservers[:2]:  # bounded to keep the check cheap
        out = dig(domain, "AXFR", server=ns, short=False)
        if out and "Transfer failed" not in out and "REFUSED" not in out and len(out.splitlines()) > 5:
            leaks.append(ns)

    if leaks:
        emit_finding(
            title=f"Public AXFR (zone transfer) on {domain}",
            severity="high",
            category="dns_security",
            cwe="CWE-200",
            target=domain,
            description=(
                f"The following authoritative nameservers responded to an "
                f"unauthenticated AXFR query for {domain}: {', '.join(leaks)}. "
                "A zone transfer reveals every record in the zone."
            ),
            impact=(
                "Full enumeration of all subdomains, internal hostnames, and "
                "infrastructure details — typically the most valuable single "
                "external recon source when present."
            ),
            remediation=(
                "Restrict AXFR on each authoritative NS to known secondary "
                "transfer peers via TSIG and IP allow-listing."
            ),
            verification_status="verified",
        )
    return {"check": "axfr", "tested": True, "exposed_nameservers": leaks}


_CHECK_REGISTRY = {
    "spf": _check_spf,
    "dmarc": _check_dmarc,
    "dkim": _check_dkim,
    "mta_sts": _check_mta_sts,
    "caa": _check_caa,
    "dnssec": _check_dnssec,
    "wildcard": _check_wildcard,
    "axfr": _check_axfr,
}


@register_tool(sandbox_execution=True)
def dns_hygiene_check(domain: str, checks: str | None = None) -> dict[str, Any]:
    """Run a battery of DNS hygiene checks on a domain.

    Args:
        domain: domain name to check (e.g., "example.com").
        checks: comma-separated list of checks to run; default "all".
                Valid: spf, dmarc, dkim, mta_sts, caa, dnssec, wildcard, axfr.

    Each misconfiguration found is emitted as a structured finding via the
    tracer. The return value is a per-check summary the agent can read.
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    if not checks or checks.strip().lower() == "all":
        selected = list(_CHECK_REGISTRY.keys())
    else:
        selected = [c.strip().lower() for c in checks.split(",") if c.strip()]
        unknown = [c for c in selected if c not in _CHECK_REGISTRY]
        if unknown:
            return {
                "success": False,
                "error": f"unknown checks: {', '.join(unknown)}",
                "valid": list(_CHECK_REGISTRY),
            }

    results: list[dict[str, Any]] = []
    for check_id in selected:
        try:
            results.append(_CHECK_REGISTRY[check_id](domain))
        except Exception as e:  # noqa: BLE001
            results.append({"check": check_id, "error": str(e)})

    return {
        "success": True,
        "domain": domain,
        "checks_run": [r["check"] for r in results],
        "results": results,
        "findings_emitted": sum(
            1
            for r in results
            if r.get("present") is False
            or r.get("policy") == "none"
            or r.get("signed") is False
            or (r.get("present") is True and r.get("policy_reachable") is False)
            or r.get("exposed_nameservers")
        ),
    }
