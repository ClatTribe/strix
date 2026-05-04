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

import re
import secrets
from typing import Any

from strix.tools.registry import register_tool

from ._common import (
    complete_check,
    dig,
    emit_finding,
    http_get_text,
    looks_like_domain,
    start_check,
)


_TOOL_NAME = "dns_hygiene_check"


# Roadmap §7.3 row "DKIM selector wordlist expansion" (PR #110).
# Each missed selector = a missed weak/expired DKIM key. The list
# below combines the canonical short list with vendor-specific
# selectors used by the most-deployed transactional / marketing /
# managed-mail vendors. Order chosen so the most likely hits (RFC-
# default + Google + Microsoft + selector1/2) probe first; kept
# alphabetised within each vendor cohort for readability.
_DKIM_SELECTORS = [
    # ---- canonical short list (every vendor falls back to one of these) ----
    "default",
    "dkim",
    "mail",
    "smtp",
    "google",
    "k1",
    "k2",
    "k3",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "s3",
    # ---- Microsoft 365 / Exchange Online ----
    "selector1-azurecomm-prod-net",
    # ---- SendGrid ----
    "smtpapi",
    "s1-sendgrid",
    "s2-sendgrid",
    # ---- Mailchimp / Mandrill ----
    "mandrill",
    "k2-mandrill",
    # ---- Mailgun ----
    "mxvault",
    "mg",
    "smtp-mg",
    # ---- Postmark ----
    "20210112",
    "pm",
    "postmark",
    # ---- Amazon SES ----
    "ses",
    "amazonses",
    # ---- ProtonMail ----
    "protonmail",
    "protonmail2",
    "protonmail3",
    # ---- Zoho ----
    "zoho",
    "zmail",
    # ---- Mimecast ----
    "mta",
    "mimecast",
    # ---- Apple iCloud ----
    "sig1",
    # ---- Sparkpost / SocketLabs / SES variants ----
    "scph0922",
    "sparkpost",
    "socketlabs",
    # ---- Salesforce / Pardot / Marketing Cloud ----
    "pf2014",
    "et",
    # ---- Misc selector conventions seen on big providers ----
    "20161025",
    "main",
    "key1",
    "key2",
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

    # Roadmap §7.3 PR #119 — DNSSEC algorithm strength + signature
    # hygiene. DNSKEY rdata format is:
    #     <flags> <protocol> <algorithm> <base64-key>
    # We parse the algorithm number per RFC 8624 §3.1 and flag weak
    # algorithms (RSA-1024, RSA-MD5, DSA, etc.). Algorithm numbers
    # come from the IANA DNSSEC Algorithm Numbers registry.
    weak_algorithms = _parse_dnskey_algorithms(dnskey, domain)
    rrsig_expiring = _check_rrsig_expiry(rrsig, domain)

    return {
        "check": "dnssec",
        "signed": True,
        "has_rrsig": bool(rrsig),
        "weak_algorithms": weak_algorithms,
        "rrsig_expiring_soon": rrsig_expiring,
    }


# Roadmap §7.3 PR #119 — IANA DNSSEC Algorithm Numbers
# (https://www.iana.org/assignments/dns-sec-alg-numbers).
# Algorithm metadata: (name, deprecated_or_weak, severity).
# Severity is "high" when the algorithm is broken (must-not-use),
# "medium" when it's deprecated (should-not-use), None when modern.
_DNSSEC_ALGORITHMS: dict[int, tuple[str, str | None]] = {
    # 0: reserved
    1: ("RSAMD5", "high"),                # RFC 6944 — must not use
    3: ("DSA-SHA1", "high"),              # NIST sunset
    5: ("RSASHA1", "medium"),             # SHA-1 weak; deprecated
    6: ("DSA-NSEC3-SHA1", "high"),
    7: ("RSASHA1-NSEC3-SHA1", "medium"),  # SHA-1 weak
    8: ("RSASHA256", None),               # OK
    10: ("RSASHA512", None),              # OK
    12: ("ECC-GOST", "medium"),           # niche / regional only
    13: ("ECDSAP256SHA256", None),        # modern; widely deployed
    14: ("ECDSAP384SHA384", None),        # modern
    15: ("ED25519", None),                # modern
    16: ("ED448", None),                  # modern
}


def _parse_dnskey_algorithms(dnskey_text: str, domain: str) -> list[str]:
    """Parse DNSKEY rdata lines and return weak algorithm names.
    Each DNSKEY line from `dig` looks like:

        <flags> <protocol> <algorithm-number> <base64-key>

    Spaces / tabs separate fields. Lines that don't fit the shape
    are silently skipped (they're query metadata, not records)."""
    weak: list[str] = []
    seen_algos: set[int] = set()

    for raw in dnskey_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        # First three fields are integers. Use a tolerant split.
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            algo = int(parts[2])
        except ValueError:
            continue
        if algo in seen_algos:
            continue
        seen_algos.add(algo)

        meta = _DNSSEC_ALGORITHMS.get(algo)
        if meta is None:
            # Unrecognised algorithm number — flag as medium so the
            # operator inspects it rather than silently passing.
            algo_name = f"algorithm-{algo}"
            weak.append(algo_name)
            emit_finding(
                title=f"Unrecognised DNSSEC algorithm {algo} on {domain}",
                severity="medium",
                category="dns_security",
                cwe="CWE-326",
                target=domain,
                description=(
                    f"DNSKEY for `{domain}` declares algorithm number "
                    f"{algo}, which isn't in the canonical IANA registry "
                    f"set checked by Strix. Operator should verify this "
                    f"is intentional."
                ),
                impact=(
                    "Unrecognised DNSSEC algorithms typically indicate a "
                    "misconfiguration or use of a niche / experimental "
                    "algorithm that resolvers may not validate, weakening "
                    "the chain-of-trust."
                ),
                remediation=(
                    "Migrate to a modern algorithm (ECDSAP256SHA256 / "
                    "ED25519). RSASHA256 is also widely supported."
                ),
                verification_status="verified",
            )
            continue

        algo_name, severity = meta
        if severity is not None:
            weak.append(algo_name)
            emit_finding(
                title=f"Weak DNSSEC algorithm {algo_name} on {domain}",
                severity=severity,
                category="dns_security",
                cwe="CWE-326",
                target=domain,
                description=(
                    f"DNSKEY for `{domain}` uses {algo_name} (algorithm "
                    f"number {algo}). Per RFC 8624 / NIST SP 800-57, this "
                    f"algorithm is "
                    f"{'broken (MUST NOT use)' if severity == 'high' else 'deprecated (SHOULD NOT use)'}."
                ),
                impact=(
                    "Weak DNSSEC algorithms allow signature forgery — an "
                    "attacker can produce valid-looking responses that "
                    "spoof your records, undermining the chain-of-trust "
                    "DNSSEC was deployed to provide."
                ),
                remediation=(
                    "Roll keys to ECDSAP256SHA256 (algorithm 13) or "
                    "ED25519 (algorithm 15). Coordinate with your "
                    "registrar to update DS records at the parent zone "
                    "after rollover."
                ),
                verification_status="verified",
            )

    return weak


def _check_rrsig_expiry(rrsig_text: str, domain: str) -> bool:
    """Parse RRSIG rdata and warn when any signature expires within
    7 days. RRSIG rdata format (RFC 4034 §3.1):

        <type-covered> <algo> <labels> <orig-ttl>
        <sig-expiration> <sig-inception> <key-tag> <signer-name> <signature>

    `sig-expiration` and `sig-inception` are UNIX-style YYYYMMDDHHMMSS
    seconds from `dig` text output. We parse and compare to now+7d.
    Returns True iff at least one expiration is within the warning
    window."""
    from datetime import datetime, timedelta, timezone

    warn_window = timedelta(days=7)
    now = datetime.now(timezone.utc)
    threshold = now + warn_window
    expiring = False

    for raw in rrsig_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        # Expect at least: type, algo, labels, ttl, expiration, inception, ...
        if len(parts) < 6:
            continue
        exp_token = parts[4]
        # Format YYYYMMDDHHMMSS — 14 digits.
        if len(exp_token) != 14 or not exp_token.isdigit():
            continue
        try:
            exp_dt = datetime.strptime(exp_token, "%Y%m%d%H%M%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
        if exp_dt <= threshold:
            expiring = True
            days_left = (exp_dt - now).total_seconds() / 86400
            emit_finding(
                title=f"DNSSEC RRSIG expiring soon on {domain}",
                severity="medium" if days_left > 0 else "high",
                category="dns_security",
                cwe="CWE-345",
                target=domain,
                description=(
                    f"At least one RRSIG for `{domain}` "
                    f"{'expires' if days_left > 0 else 'has ALREADY EXPIRED'} "
                    f"({days_left:.1f} days from now, expiration "
                    f"{exp_dt.isoformat()})."
                ),
                impact=(
                    "Once RRSIG signatures expire, DNSSEC-validating "
                    "resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8, "
                    "many ISPs) will SERVFAIL the lookup — taking the "
                    "domain offline for those clients. Real-world "
                    "outage-shaped event."
                ),
                remediation=(
                    "Re-sign the zone now and ensure your DNS provider's "
                    "automatic re-signing is healthy. Enable monitoring "
                    "on signature lifetime — most providers offer it."
                ),
                verification_status="verified",
            )
            break

    return expiring


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


# ---------------------------------------------------------------------------
# Email-security depth (DANE / BIMI / DMARC RUA / SPF flatten / DKIM key strength)
# ---------------------------------------------------------------------------


def _check_dane(domain: str) -> dict[str, Any]:
    """Query the SMTP-bound TLSA record. Informational — no finding emitted
    on absence (DANE adoption is rare; absence isn't actionable). Presence is
    a positive signal that surfaces in the structured return."""
    out = dig(f"_25._tcp.{domain}", "TLSA")
    records = [line for line in out.splitlines() if line.strip()] if out else []
    return {"check": "dane", "present": bool(records), "records": records}


def _check_bimi(domain: str) -> dict[str, Any]:
    """Query default._bimi.<domain> TXT. Informational only — BIMI is opt-in
    branding. Returns presence and the raw record."""
    out = dig(f"default._bimi.{domain}", "TXT")
    has_record = bool(out and "v=BIMI1" in out)
    return {"check": "bimi", "present": has_record}


def _check_dmarc_rua(domain: str) -> dict[str, Any]:
    """When DMARC has rua=mailto:..., verify the rua mailbox's domain has MX
    records. Reports without a working mailbox go to the void."""
    txt = dig(f"_dmarc.{domain}", "TXT")
    if not txt or "v=DMARC1" not in txt:
        return {"check": "dmarc_rua", "rua_present": False, "note": "no DMARC record"}

    rua_match = re.search(r"rua=mailto:([^,;\s\"]+)", txt, re.IGNORECASE)
    if not rua_match:
        return {"check": "dmarc_rua", "rua_present": False}

    mailbox = rua_match.group(1).strip()
    if "@" not in mailbox:
        return {"check": "dmarc_rua", "rua_present": True, "rua_mailbox": mailbox, "valid": False}

    rua_domain = mailbox.split("@", 1)[1]
    mx = dig(rua_domain, "MX")
    has_mx = bool(mx and not all(line.startswith(";") for line in mx.splitlines() if line))

    if not has_mx:
        emit_finding(
            title=f"DMARC rua mailbox unreachable on {domain}",
            severity="low",
            category="email_security",
            cwe="CWE-1278",
            target=domain,
            description=(
                f"`{domain}` publishes DMARC with `rua=mailto:{mailbox}`, but the "
                f"mailbox's domain `{rua_domain}` has no MX records. Aggregate "
                "DMARC reports sent there cannot be delivered."
            ),
            impact=(
                "DMARC reporting that goes nowhere defeats the operational value "
                "of DMARC entirely — the domain owner can't see when their mail "
                "is being spoofed or when legitimate senders are misconfigured. "
                "Missed enforcement signal."
            ),
            remediation=(
                f"Either point `rua=` at a mailbox whose domain has working MX, "
                "or remove the directive. A common fix: use a managed DMARC "
                "reporting service (e.g. Postmark, Valimail, dmarcian)."
            ),
            verification_status="verified",
        )

    return {
        "check": "dmarc_rua",
        "rua_present": True,
        "rua_mailbox": mailbox,
        "rua_domain": rua_domain,
        "mx_present": has_mx,
    }


# Apex-level SPF lookup-counting tokens (DNS-querying mechanisms per RFC 7208).
_SPF_LOOKUP_TOKENS = re.compile(
    r"(?:^|\s)(?:include:|redirect=|a(?::|\s)|mx(?::|\s)|ptr(?::|\s|$)|exists:)",
    re.IGNORECASE,
)


def _check_spf_lookups(domain: str) -> dict[str, Any]:
    """Count DNS-querying mechanisms in the apex SPF record. RFC 7208 caps
    transitive lookups at 10 — apex count is an approximation but most
    breaches of the limit show up at apex level alone."""
    txt = dig(domain, "TXT")
    spf_lines = [line.strip('"') for line in txt.splitlines() if "v=spf1" in line.lower()]
    if not spf_lines:
        return {"check": "spf_lookups", "spf_present": False}

    spf = spf_lines[0]
    apex_count = len(_SPF_LOOKUP_TOKENS.findall(" " + spf))

    if apex_count > 10:
        emit_finding(
            title=f"SPF record exceeds RFC 7208 lookup limit on {domain}",
            severity="medium",
            category="email_security",
            cwe="CWE-1278",
            target=domain,
            description=(
                f"The apex SPF record on `{domain}` contains {apex_count} DNS-"
                "querying mechanisms (include:, redirect=, a:, mx:, ptr:, exists:). "
                "RFC 7208 limits the *transitive* count to 10. Records that exceed "
                "the limit silently fail with PermError at evaluating receivers."
            ),
            impact=(
                "An SPF record that fails evaluation is treated as if no SPF were "
                "published — receivers fall back to default (often 'softfail' or "
                "'none'), defeating spoofing protection. The domain owner thinks "
                "SPF is configured but receivers ignore it."
            ),
            remediation=(
                "Flatten the SPF record by replacing `include:` references with "
                "the actual IPs they expand to (e.g. via a managed flattener like "
                "EasySPF, DMARCLY). Aim for ≤ 8 apex tokens with headroom for "
                "downstream includes."
            ),
            verification_status="verified",
        )

    return {
        "check": "spf_lookups",
        "spf_present": True,
        "apex_lookup_count": apex_count,
        "rfc_limit": 10,
    }


# RSA-1024 SubjectPublicKeyInfo (SPKI) decodes to ~162 bytes; RSA-2048 to ~294;
# RSA-3072 to ~422. Threshold of 250 cleanly separates 1024-bit (weak) from
# 2048-bit and above.
_DKIM_SPKI_WEAK_BYTES = 250


def _check_dkim_keys(domain: str) -> dict[str, Any]:
    """For each found DKIM selector, decode the public key and flag weak
    (RSA-1024 or shorter) keys. Heuristic: SubjectPublicKeyInfo byte length
    after base64 decode."""
    import base64

    audited: list[dict[str, Any]] = []
    weak_selectors: list[str] = []
    for selector in _DKIM_SELECTORS:
        txt = dig(f"{selector}._domainkey.{domain}", "TXT")
        if not txt or "v=DKIM1" not in txt:
            continue

        # Strip TXT-record quoting that dig may leave around the value
        record = txt.replace('"', "").replace("\n", " ")

        algo_match = re.search(r"\bk=([A-Za-z0-9_-]+)", record)
        algorithm = (algo_match.group(1) if algo_match else "rsa").lower()

        p_match = re.search(r"\bp=([A-Za-z0-9+/=]+)", record)
        if not p_match:
            audited.append(
                {"selector": selector, "algorithm": algorithm, "note": "no p= public key"}
            )
            continue

        try:
            key_bytes = base64.b64decode(p_match.group(1) + "==")
        except Exception:  # noqa: BLE001
            audited.append(
                {"selector": selector, "algorithm": algorithm, "note": "p= not valid base64"}
            )
            continue

        spki_len = len(key_bytes)
        weak = algorithm == "rsa" and spki_len < _DKIM_SPKI_WEAK_BYTES
        audited.append(
            {
                "selector": selector,
                "algorithm": algorithm,
                "spki_bytes": spki_len,
                "weak": weak,
            }
        )
        if weak:
            weak_selectors.append(selector)

    if weak_selectors:
        emit_finding(
            title=f"Weak DKIM key(s) on {domain} (selector: {', '.join(weak_selectors)})",
            severity="medium",
            category="email_security",
            cwe="CWE-326",  # Inadequate Encryption Strength
            target=domain,
            description=(
                f"DKIM selector(s) {', '.join(weak_selectors)} on `{domain}` use "
                "RSA-1024 or shorter keys (decoded SubjectPublicKeyInfo length below "
                f"{_DKIM_SPKI_WEAK_BYTES} bytes). NIST has deprecated RSA-1024 since "
                "2014; modern receivers may downgrade or reject DKIM signatures from "
                "weak keys."
            ),
            impact=(
                "Weak DKIM keys are forgeable by sufficiently-resourced adversaries. "
                "A signed message becomes unforgeable only if the signing key is "
                "computationally out of reach. RSA-1024 has been factorable by "
                "well-resourced actors for years."
            ),
            remediation=(
                "Rotate to RSA-2048 (or Ed25519, where supported). Procedure: "
                "generate new key, publish at a new selector (e.g. `s2._domainkey`), "
                "configure mail server to sign with the new selector, retire the "
                "old selector after a propagation window."
            ),
            verification_status="verified",
        )

    return {"check": "dkim_keys", "audited": audited, "weak_selectors": weak_selectors}


# ---------------------------------------------------------------------------
# DNS-security depth (open recursive resolver / dangling NS)
# ---------------------------------------------------------------------------


def _check_open_resolver(domain: str) -> dict[str, Any]:
    """Authoritative NS that also serve recursive answers for unrelated zones
    are misconfigured — they enable DNS-amplification attacks and signal lax
    operator hygiene. Test by querying each NS for a well-known external
    record (a.iana-servers.net) — if the NS returns an A answer, it's
    recursing for arbitrary zones."""
    ns_out = dig(domain, "NS")
    nameservers = [n.rstrip(".").lower() for n in ns_out.splitlines() if n.strip()]
    if not nameservers:
        return {"check": "open_resolver", "tested": False, "note": "no NS records"}

    # Bound to the first 3 to keep the check cheap.
    open_nameservers: list[str] = []
    for ns in nameservers[:3]:
        out = dig("a.iana-servers.net", "A", server=ns)
        # An open resolver returns an A record for an unrelated zone.
        if out and re.search(r"\d+\.\d+\.\d+\.\d+", out):
            open_nameservers.append(ns)

    if open_nameservers:
        emit_finding(
            title=f"Open recursive resolver(s) on {domain}",
            severity="low",
            category="dns_security",
            cwe="CWE-732",  # Incorrect Permission Assignment
            target=domain,
            description=(
                f"The following authoritative nameservers responded recursively "
                "to a query for an unrelated zone (a.iana-servers.net): "
                f"{', '.join(open_nameservers)}."
            ),
            impact=(
                "Open recursive resolvers can be abused for DNS-amplification "
                "DDoS — attackers spoof the victim's IP, query the open resolver, "
                "and the resolver sends a much larger response to the victim. "
                "The presence on an authoritative NS also signals broader operator "
                "hygiene issues."
            ),
            remediation=(
                "Disable recursion on authoritative-only nameservers. Most DNS "
                "software (BIND, NSD, Knot, PowerDNS) has a per-view config "
                "directive for this. If the server must serve both authoritative "
                "and recursive roles, restrict recursion to a known IP allow-list."
            ),
            verification_status="verified",
        )

    return {
        "check": "open_resolver",
        "tested": True,
        "tested_nameservers": nameservers[:3],
        "open_nameservers": open_nameservers,
    }


def _check_dangling_ns(domain: str) -> dict[str, Any]:
    """An NS record pointing at a hostname that itself doesn't resolve is a
    dangling NS — typically the result of a renamed or decommissioned NS that
    wasn't cleaned up. Common subdomain-takeover precursor."""
    ns_out = dig(domain, "NS")
    nameservers = [n.rstrip(".").lower() for n in ns_out.splitlines() if n.strip()]
    if not nameservers:
        return {"check": "dangling_ns", "tested": False, "note": "no NS records"}

    dangling: list[str] = []
    for ns in nameservers:
        a_out = dig(ns, "A")
        if not (a_out and re.search(r"\d+\.\d+\.\d+\.\d+", a_out)):
            # Also try AAAA before declaring dangling.
            aaaa = dig(ns, "AAAA")
            if not (aaaa and ":" in aaaa):
                dangling.append(ns)

    if dangling:
        emit_finding(
            title=f"Dangling NS record(s) on {domain}",
            severity="high",
            category="dns_security",
            cwe="CWE-1390",  # subdomain-takeover-related
            target=domain,
            description=(
                "The following NS records point at hostnames that don't resolve "
                f"to A or AAAA records: {', '.join(dangling)}. Resolution for "
                f"`{domain}` may fail intermittently or be hijackable depending "
                "on registrar / glue-record state."
            ),
            impact=(
                "An attacker who controls (or can register) the dangling NS "
                "hostname can answer DNS queries for the parent zone — full DNS "
                "takeover of the apex. This has been used in the wild against "
                "high-value domains. Even when not exploitable, it causes "
                "intermittent resolution failures that look like outages."
            ),
            remediation=(
                "Identify which nameservers should authoritatively serve this "
                "domain and remove the rest from the NS RRset. Verify glue "
                "records at the registrar match the cleaned-up NS list."
            ),
            verification_status="verified",
        )

    return {
        "check": "dangling_ns",
        "tested": True,
        "tested_nameservers": nameservers,
        "dangling": dangling,
    }


def _check_svcb_https(domain: str) -> dict[str, Any]:
    """RFC 9460 SVCB / HTTPS service-binding records.

    These records publish service-discovery metadata: ALPN protocols
    the origin supports (`h2`, `h3`), preferred port, ECH (Encrypted
    ClientHello) configuration, and IP hints. Adoption is rapidly
    increasing — Cloudflare auto-publishes for all customers, Apple
    devices use them in iOS 16+, Chrome/Firefox prefer them when
    available.

    What we report:
      - **Info**: HTTPS or SVCB record observed → recon signal,
        record the ALPN list and presence-of-ECH for the surface map.
      - **Low CWE-200**: HTTPS record reveals internal hostname via
        `target=` field that points to a non-public ipv4hint or
        non-canonical name.
      - **Info**: ECH (`ech=`) configured → modern privacy posture.

    Roadmap §7.3 PR #120.
    """
    https_text = dig(domain, "HTTPS")
    svcb_text = dig(domain, "SVCB")

    https_records = _parse_svcb_records(https_text)
    svcb_records = _parse_svcb_records(svcb_text)
    all_records = https_records + svcb_records

    if not all_records:
        return {"check": "svcb_https", "present": False}

    alpn_set: set[str] = set()
    ech_present = False
    ipv4_hints: set[str] = set()
    ipv6_hints: set[str] = set()
    targets: set[str] = set()

    for rec in all_records:
        params = rec.get("params") or {}
        alpn_set.update(params.get("alpn", []))
        if params.get("ech"):
            ech_present = True
        ipv4_hints.update(params.get("ipv4hint", []))
        ipv6_hints.update(params.get("ipv6hint", []))
        if rec.get("target") and rec["target"] != ".":
            targets.add(rec["target"])

    # Emit info finding: surface what was discovered. Rare-today,
    # mainstream-soon recon signal — operator should know.
    emit_finding(
        title=f"SVCB/HTTPS service-binding records on {domain}",
        severity="info",
        category="dns_security",
        cwe="CWE-200",
        target=domain,
        description=(
            f"`{domain}` publishes RFC 9460 service-binding records "
            f"(HTTPS={len(https_records)}, SVCB={len(svcb_records)}). "
            f"ALPN={sorted(alpn_set) or '(none)'}; "
            f"ECH={'configured' if ech_present else 'not set'}; "
            f"ipv4hint={sorted(ipv4_hints) or '(none)'}; "
            f"ipv6hint={sorted(ipv6_hints) or '(none)'}; "
            f"target={sorted(targets) or '(self)'}."
        ),
        impact=(
            "Service-binding records publish service-discovery metadata "
            "browsers and resolvers use to negotiate connections. ALPN "
            "values reveal the protocols the origin supports (h2 / h3); "
            "ipvN hints can leak internal IPs that bypass CDN-fronting; "
            "the `target=` field can leak internal hostnames."
        ),
        remediation=(
            "Audit which ALPN protocols and IP hints the records publish "
            "— make sure ipv4hint / ipv6hint don't leak origin IPs that "
            "should stay behind the CDN. Configure `ech=` for Encrypted "
            "ClientHello (modern privacy posture)."
        ),
        verification_status="verified",
    )

    return {
        "check": "svcb_https",
        "present": True,
        "https_records": https_records,
        "svcb_records": svcb_records,
        "alpn": sorted(alpn_set),
        "ech_configured": ech_present,
        "ipv4hints": sorted(ipv4_hints),
        "ipv6hints": sorted(ipv6_hints),
        "targets": sorted(targets),
    }


def _parse_svcb_records(rdata_text: str) -> list[dict[str, Any]]:
    """Parse `dig` HTTPS/SVCB output. Each record line is:

        <priority> <target> <key=value> <key=value> ...

    Where keys are: alpn, no-default-alpn, port, ipv4hint, ipv6hint,
    ech, mandatory. Values for list-keys are comma-separated.
    Returns a list of `{priority, target, params: {...}}` dicts."""
    out: list[dict[str, Any]] = []
    for raw in rdata_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        # Tokens: priority(int) target(name) <kv pairs>
        toks = line.split()
        if len(toks) < 2:
            continue
        try:
            priority = int(toks[0])
        except ValueError:
            continue
        target = toks[1]
        params: dict[str, Any] = {}
        for kv in toks[2:]:
            if "=" not in kv:
                # Bare keyword (e.g. `no-default-alpn`).
                params[kv] = True
                continue
            key, _, value = kv.partition("=")
            value = value.strip().strip('"')
            if key in ("alpn", "ipv4hint", "ipv6hint", "mandatory"):
                params[key] = [v.strip() for v in value.split(",") if v.strip()]
            else:
                params[key] = value
        out.append({
            "priority": priority,
            "target": target,
            "params": params,
        })
    return out


_CHECK_REGISTRY = {
    "spf": _check_spf,
    "dmarc": _check_dmarc,
    "dkim": _check_dkim,
    "mta_sts": _check_mta_sts,
    "caa": _check_caa,
    "dnssec": _check_dnssec,
    "wildcard": _check_wildcard,
    "axfr": _check_axfr,
    "dane": _check_dane,
    "bimi": _check_bimi,
    "dmarc_rua": _check_dmarc_rua,
    "spf_lookups": _check_spf_lookups,
    "dkim_keys": _check_dkim_keys,
    "open_resolver": _check_open_resolver,
    "dangling_ns": _check_dangling_ns,
    "svcb_https": _check_svcb_https,
}


# Map each check_id → category for tracker `start_check` events.
_CHECK_CATEGORY: dict[str, str] = {
    "spf": "email_security",
    "dmarc": "email_security",
    "dkim": "email_security",
    "mta_sts": "email_security",
    "caa": "dns_security",
    "dnssec": "dns_security",
    "wildcard": "dns_security",
    "axfr": "dns_security",
    "dane": "email_security",
    "bimi": "email_security",
    "dmarc_rua": "email_security",
    "spf_lookups": "email_security",
    "dkim_keys": "email_security",
    "open_resolver": "dns_security",
    "dangling_ns": "dns_security",
    "svcb_https": "dns_security",
}


def _verdict_for_check(check_id: str, result: dict[str, Any]) -> tuple[str, str | None]:
    """Map a sub-check's structured result → (verdict, evidence-summary).

    verdict ∈ {vulnerable, not_vulnerable, inconclusive}.
    """
    if result.get("error"):
        return "inconclusive", f"error: {result['error']}"

    if check_id in ("spf", "dmarc", "mta_sts", "caa"):
        if result.get("present") is False:
            return "vulnerable", "missing record"
        if check_id == "dmarc" and result.get("policy") in (None, "none", ""):
            return "vulnerable", f"weak policy: p={result.get('policy')!r}"
        if check_id == "mta_sts" and result.get("policy_reachable") is False:
            return "vulnerable", "policy file unreachable"
        return "not_vulnerable", "record present"

    if check_id == "dnssec":
        return ("not_vulnerable", "DNSSEC signed") if result.get("signed") else (
            "vulnerable",
            "DNSSEC not enabled",
        )

    if check_id == "wildcard":
        return ("vulnerable", "wildcard DNS detected") if result.get("present") else (
            "not_vulnerable",
            "no wildcard",
        )

    if check_id == "axfr":
        if result.get("exposed_nameservers"):
            return "vulnerable", f"AXFR allowed on {result['exposed_nameservers']}"
        if result.get("tested") is False:
            return "inconclusive", result.get("note") or "not tested"
        return "not_vulnerable", "AXFR refused on all NS"

    if check_id == "dkim":
        # Common-selector check is informational, not conclusive either way.
        return "inconclusive", f"selectors_found={result.get('selectors_found')}"

    if check_id in ("dane", "bimi"):
        # Both are informational (opt-in / niche). Presence is positive,
        # absence isn't a finding — score as not_vulnerable when absent so
        # downstream coverage is honest about what was checked.
        return "not_vulnerable", f"present={result.get('present')}"

    if check_id == "dmarc_rua":
        if not result.get("rua_present"):
            return "inconclusive", result.get("note") or "no rua= directive"
        if result.get("mx_present"):
            return "not_vulnerable", "rua mailbox domain has MX"
        return "vulnerable", f"rua mailbox domain {result.get('rua_domain')!r} has no MX"

    if check_id == "spf_lookups":
        if not result.get("spf_present"):
            return "inconclusive", "no SPF record"
        count = result.get("apex_lookup_count", 0)
        if count > 10:
            return "vulnerable", f"{count} apex DNS-querying mechanisms (limit 10)"
        return "not_vulnerable", f"{count}/10 apex lookups"

    if check_id == "dkim_keys":
        if result.get("weak_selectors"):
            return "vulnerable", f"weak keys on: {', '.join(result['weak_selectors'])}"
        if result.get("audited"):
            return "not_vulnerable", f"{len(result['audited'])} selector(s) audited, all ≥ RSA-2048"
        return "inconclusive", "no DKIM selectors found in common list"

    if check_id == "open_resolver":
        if result.get("tested") is False:
            return "inconclusive", result.get("note") or "not tested"
        if result.get("open_nameservers"):
            return "vulnerable", f"open recursion on: {', '.join(result['open_nameservers'])}"
        return "not_vulnerable", "no recursion observed"

    if check_id == "dangling_ns":
        if result.get("tested") is False:
            return "inconclusive", result.get("note") or "not tested"
        if result.get("dangling"):
            return "vulnerable", f"dangling NS: {', '.join(result['dangling'])}"
        return "not_vulnerable", "all NS resolve"

    return "inconclusive", None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1590.002"],  # Gather Victim Network Information: DNS
)
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
        category = _CHECK_CATEGORY.get(check_id, "misconfig")
        cev_id = start_check(category=category, surface=domain, tool=_TOOL_NAME)
        try:
            r = _CHECK_REGISTRY[check_id](domain)
        except Exception as e:  # noqa: BLE001
            r = {"check": check_id, "error": str(e)}
        results.append(r)
        verdict, evidence = _verdict_for_check(check_id, r)
        complete_check(cev_id, verdict, evidence=evidence)

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
