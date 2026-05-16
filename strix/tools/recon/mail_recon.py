"""MX server fingerprint + sample-mail header analysis.

Roadmap §7.3. Two complementary checks for the email-recon story:

1. **MX banner fingerprint.** Resolve the apex's MX records, then for
   each MX host, open a TCP connection to port 25 and read the SMTP
   greeting banner. Optionally issue EHLO and capture the response.
   Surfaces the MTA software + version when disclosed (often is).
   Pairs with `dns_hygiene_check`'s record-presence checks: that tool
   tells you the records exist; this tool tells you what's actually
   serving them.

2. **Sample-mail header analysis.** When a saved `.eml` file is
   provided (e.g. an email the user received from the target's domain),
   parse `Authentication-Results` to extract real-world SPF / DKIM /
   DMARC pass/fail behaviour against actual mail flow. This validates
   that *published* policy and *enforced* policy match — a record set
   to `p=reject` that's actually being delivered with `dmarc=none` is
   evidence of a misconfigured mail receiver.

Findings:
- **Info** (CWE-200) — version disclosure in banner.
- **Medium** (CWE-1104, third-party-component-vuln) — known-old MTA
  major version (Sendmail any, Exim < 4.95, Postfix 2.x).
- **Medium** (CWE-345, insufficient-verification) — sample mail's
  `Authentication-Results` show `spf=fail` / `dkim=fail` / `dmarc=fail`
  for legitimate-looking source — broken authentication chain.
"""

from __future__ import annotations

import logging
import re
import socket
from email import message_from_bytes
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool

from ._common import (
    complete_check,
    dig,
    emit_finding,
    looks_like_domain,
    start_check,
)


logger = logging.getLogger(__name__)
_TOOL_NAME = "mx_fingerprint"

_DEFAULT_SMTP_TIMEOUT = 5.0
_BANNER_MAX_BYTES = 4096
_MAX_MX_HOSTS = 5

# Known-stale MTA fingerprints. These are heuristics for the agent —
# emit medium-severity hint findings; the agent decides whether to
# dig deeper via threat-intel.
#
# (regex on banner-or-software-tag, severity, label)
_VERSION_FLAGS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"\bSendmail\b", re.IGNORECASE),
        "medium",
        "Sendmail is generally regarded as legacy / EOL — review for known CVEs and consider migrating.",
    ),
    (
        re.compile(r"\bExim\s+([34])\.(\d{1,2})", re.IGNORECASE),
        "medium",
        "Exim version disclosed; versions earlier than 4.95 are vulnerable to multiple CVEs from the 21Nails set (CVE-2021-31959 family).",
    ),
    (
        re.compile(r"\bPostfix\b.*?(?:\s|version[\s/])([12])\.", re.IGNORECASE),
        "medium",
        "Postfix major version 1.x or 2.x is end-of-life.",
    ),
    (
        re.compile(r"\bMicrosoft ESMTP MAIL Service.*Version: 6\.", re.IGNORECASE),
        "medium",
        "Exchange 6.x corresponds to Exchange 2003 / 2007 — long EOL.",
    ),
)


# Match e.g. "Postfix" "Sendmail 8.15" "Exim 4.94" "Microsoft ESMTP MAIL Service" "OpenSMTPD 6.6.4"
_SOFTWARE_RE = re.compile(
    r"\b(Postfix|Exim|Sendmail|OpenSMTPD|Microsoft ESMTP|Exchange|Halon|Mailgun|"
    r"SparkPost|Mailchimp|Amazon SES|Mailjet|SendGrid|Zoho|"
    r"ProtonMail|PowerMTA|Smtpd)\b",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


# ---------------------------------------------------------------------------
# MX resolution
# ---------------------------------------------------------------------------


def _resolve_mx_records(domain: str) -> list[tuple[int, str]]:
    """Returns [(preference, host), ...] sorted by preference. Empty list on failure."""
    out = dig(domain, "MX")
    records: list[tuple[int, str]] = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        try:
            pref = int(parts[0])
        except ValueError:
            continue
        host = parts[1].rstrip(".")
        if host:
            records.append((pref, host))
    records.sort(key=lambda r: r[0])
    return records[:_MAX_MX_HOSTS]


# ---------------------------------------------------------------------------
# SMTP banner grab
# ---------------------------------------------------------------------------


def _smtp_banner(
    host: str, port: int = 25, *, timeout: float = _DEFAULT_SMTP_TIMEOUT
) -> dict[str, Any]:
    """Open TCP to host:port, read SMTP greeting + optionally EHLO response.

    No STARTTLS, no auth, no message body. Single connect + read + EHLO + read.

    Returns:
        {success, host, port, banner, ehlo_response, error?}
    """
    result: dict[str, Any] = {
        "success": False,
        "host": host,
        "port": port,
        "banner": "",
        "ehlo_response": "",
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(_BANNER_MAX_BYTES)
            banner = data.decode("ascii", errors="replace").strip()
            result["banner"] = banner
            # Issue EHLO to coax fuller software identification on
            # multi-line response. Use a benign hostname.
            try:
                sock.sendall(b"EHLO recon.example.org\r\n")
                ehlo_data = sock.recv(_BANNER_MAX_BYTES)
                result["ehlo_response"] = ehlo_data.decode(
                    "ascii", errors="replace"
                ).strip()
            except (OSError, socket.timeout) as e:
                logger.debug("EHLO failed for %s:%d: %s", host, port, e)
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            result["success"] = True
    except socket.timeout:
        result["error"] = "timeout"
    except (socket.gaierror, OSError) as e:
        result["error"] = str(e)
    return result


def _parse_software(banner: str, ehlo_response: str) -> dict[str, str | None]:
    """Pull software name + version out of the banner / EHLO response."""
    text = f"{banner}\n{ehlo_response}"
    name_match = _SOFTWARE_RE.search(text)
    version_match = _VERSION_RE.search(text)
    return {
        "software": name_match.group(1) if name_match else None,
        "version": version_match.group(1) if version_match else None,
    }


def _flag_known_stale(text: str) -> list[tuple[str, str]]:
    """Return [(severity, label), ...] for any known-stale-software flags hit."""
    flags: list[tuple[str, str]] = []
    for pattern, severity, label in _VERSION_FLAGS:
        if pattern.search(text):
            flags.append((severity, label))
    return flags


# ---------------------------------------------------------------------------
# Sample-mail header analysis
# ---------------------------------------------------------------------------


# Authentication-Results: example.com;
#   spf=pass smtp.mailfrom=foo@example.com;
#   dkim=pass header.d=example.com;
#   dmarc=pass action=none header.from=example.com
_AR_TOKEN_RE = re.compile(
    r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE
)


def _parse_authentication_results(eml_path: str) -> dict[str, Any]:
    """Parse `Authentication-Results` from a saved email.

    Returns:
        {
          success, path,
          headers_present: bool,
          spf, dkim, dmarc,           # 'pass'/'fail'/'none'/'softfail'/...
          from_domain, return_path,
          raw_authentication_results,
          error?,
        }
    """
    path = Path(eml_path)
    out: dict[str, Any] = {
        "success": False,
        "path": str(path),
        "headers_present": False,
    }
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        out["error"] = "file_not_found"
        return out
    except OSError as e:
        out["error"] = f"read_error: {e}"
        return out
    try:
        msg = message_from_bytes(raw)
    except Exception as e:  # noqa: BLE001
        out["error"] = f"parse_error: {e}"
        return out

    ar_headers = msg.get_all("Authentication-Results") or []
    out["raw_authentication_results"] = ar_headers
    out["from_domain"] = _extract_from_domain(msg.get("From", "") or "")
    out["return_path"] = (msg.get("Return-Path", "") or "").strip("<>")
    if not ar_headers:
        out["success"] = True  # parse succeeded; just no AR headers
        return out
    out["headers_present"] = True
    combined = "\n".join(ar_headers)
    for token, value in _AR_TOKEN_RE.findall(combined):
        out[token.lower()] = value.lower()
    out["success"] = True
    return out


def _extract_from_domain(from_header: str) -> str | None:
    """Best-effort `user@domain` extraction from an RFC 5322 From header."""
    m = re.search(r"<?([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+)>?", from_header)
    return m.group(2).lower() if m else None


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1590", "T1592.002"],  # Network info + Software fingerprint
)
def mx_fingerprint(
    domain: str,
    sample_email_path: str | None = None,
    timeout: float = _DEFAULT_SMTP_TIMEOUT,
) -> dict[str, Any]:
    """Fingerprint the target's MTAs and (optionally) analyse a sample email.

    Args:
        domain: apex domain to query MX for.
        sample_email_path: optional path to a saved `.eml` file from the
                           target's domain. When provided, the file's
                           `Authentication-Results` header is parsed for
                           real-world SPF / DKIM / DMARC pass/fail
                           behaviour against actual mail flow.
        timeout: per-connect SMTP timeout in seconds (default 5).

    Behaviour:
        - Resolves up to 5 MX hosts (lowest-preference first).
        - For each MX host, single TCP connect to port 25, reads the
          SMTP greeting, sends EHLO, reads the response, sends QUIT.
        - Emits info-severity finding for any banner that discloses
          software + version (CWE-200).
        - Emits medium-severity finding for known-stale MTA fingerprints
          (Sendmail, Exim < 4.95, Postfix 1.x/2.x, Exchange 6.x —
          CWE-1104).
        - When sample-mail provided and `Authentication-Results` shows
          `spf=fail` / `dkim=fail` / `dmarc=fail`, emits medium-severity
          finding (CWE-345). When `dmarc=none` against a published
          policy of `p=reject` / `p=quarantine`, emits info-severity
          finding (the policy/enforcement mismatch).

    Returns:
        {
          success, domain,
          mx_records: [{preference, host}, ...],
          mx_results: [{host, port, success, banner, ehlo_response,
                        software, version, flags: [{severity, label}]}, ...],
          sample_mail: {success, headers_present, spf, dkim, dmarc, ...} | None
        }
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    cev_id = start_check(category="mx_recon", surface=domain, tool=_TOOL_NAME)

    mx_records = _resolve_mx_records(domain)
    mx_results: list[dict[str, Any]] = []

    for pref, host in mx_records:
        banner_info = _smtp_banner(host, timeout=timeout)
        software_info = _parse_software(
            banner_info.get("banner", ""), banner_info.get("ehlo_response", "")
        )
        text_for_flags = (
            banner_info.get("banner", "") + "\n" + banner_info.get("ehlo_response", "")
        )
        stale_flags = _flag_known_stale(text_for_flags)
        record_block: dict[str, Any] = {
            "preference": pref,
            "host": host,
            "port": banner_info.get("port"),
            "success": banner_info.get("success", False),
            "banner": banner_info.get("banner", ""),
            "ehlo_response": banner_info.get("ehlo_response", ""),
            "software": software_info["software"],
            "version": software_info["version"],
            "flags": [{"severity": s, "label": l} for s, l in stale_flags],
        }
        if "error" in banner_info:
            record_block["error"] = banner_info["error"]
        mx_results.append(record_block)

        if record_block["success"] and software_info["software"]:
            label = f"{software_info['software']}"
            if software_info["version"]:
                label += f" {software_info['version']}"
            emit_finding(
                title=f"MX banner discloses MTA software: {label} on {host}",
                severity="info",
                category="info_disclosure",
                cwe="CWE-200",
                target=domain,
                endpoint=f"smtp://{host}:25",
                description=(
                    f"SMTP greeting from {host} discloses software identifier "
                    f"`{label}`. Banner: {record_block['banner'][:300]}"
                ),
                impact=(
                    "Banner version disclosure simplifies attacker reconnaissance: "
                    "the disclosed version is enough to look up CVEs and tailor "
                    "exploits without needing further fingerprinting."
                ),
                remediation=(
                    "Configure the MTA to suppress version information from the "
                    "SMTP greeting. For Postfix: `smtpd_banner = $myhostname ESMTP`. "
                    "For Exim: `smtp_banner = $primary_hostname ESMTP`."
                ),
                verification_status="verified",
            )

        for severity, label in stale_flags:
            emit_finding(
                title=f"Stale or vulnerable MTA on {host}",
                severity=severity,
                category="vulnerable_dependency",
                cwe="CWE-1104",
                target=domain,
                endpoint=f"smtp://{host}:25",
                description=(
                    f"MX host {host} runs MTA software flagged as known-stale "
                    f"or known-vulnerable.\n{label}\n\nBanner: "
                    f"{record_block['banner'][:300]}"
                ),
                impact=(
                    "Old / EOL MTA versions accumulate unpatched CVEs across "
                    "areas including memory-corruption, DoS, and authentication "
                    "bypass. Mail-system compromise typically grants the attacker "
                    "the ability to send authoritative-from-the-domain email "
                    "(business email compromise) and read inbound mail."
                ),
                remediation=(
                    "Upgrade to a current supported release. Subscribe to the "
                    "MTA's security advisories. Validate the change in a "
                    "staging environment because MTA upgrades sometimes change "
                    "queue/format semantics."
                ),
                verification_status="verified",
            )

    sample_mail_block: dict[str, Any] | None = None
    if sample_email_path:
        sample_mail_block = _parse_authentication_results(sample_email_path)
        if sample_mail_block.get("success") and sample_mail_block.get("headers_present"):
            spf_v = sample_mail_block.get("spf")
            dkim_v = sample_mail_block.get("dkim")
            dmarc_v = sample_mail_block.get("dmarc")
            failed = [
                (k, v)
                for k, v in (("spf", spf_v), ("dkim", dkim_v), ("dmarc", dmarc_v))
                if v in ("fail", "softfail")
            ]
            if failed:
                fail_list = ", ".join(f"{k}={v}" for k, v in failed)
                emit_finding(
                    title=f"Sample mail from {domain} fails authentication: {fail_list}",
                    severity="medium",
                    category="authentication_bypass",
                    cwe="CWE-345",
                    target=domain,
                    description=(
                        f"The provided sample email's `Authentication-Results` "
                        f"shows authentication failures: {fail_list}.\n"
                        f"Headers: {sample_mail_block.get('raw_authentication_results')}"
                    ),
                    impact=(
                        "An authentication failure on a real-world email from "
                        "the target's domain means the receiver's mail flow does "
                        "not enforce the published policy. This is the gap "
                        "phishing campaigns exploit: the receiver lets through "
                        "spoofed mail despite the org publishing SPF / DKIM / "
                        "DMARC records."
                    ),
                    remediation=(
                        "Audit the path the sample email travelled: was it sent "
                        "via a third-party service (transactional mail / "
                        "marketing platform) that hasn't been included in the "
                        "SPF record or aligned for DKIM? If so, either include "
                        "the service, or stop sending mail through it. "
                        "Revisit DMARC alignment requirements."
                    ),
                    verification_status="verified",
                )

    complete_check(
        cev_id,
        result=("not_vulnerable" if mx_records else "inconclusive"),
        evidence=f"{len(mx_records)} MX host(s) probed, "
        f"{sum(1 for r in mx_results if r['success'])} reachable",
    )

    # KG: emit an Asset per MX host so threat-intel / vuln-
    # correlation on mail infrastructure joins on the shared node.
    try:
        from strix.agents.kg_emit import record_asset_in_kg

        for pref, host in mx_records:
            record_asset_in_kg(
                asset_type="mx_record",
                value=host,
                source="mail_recon",
                parent_value=domain,
                properties={"preference": pref},
            )
    except Exception:  # noqa: BLE001
        pass

    return {
        "success": True,
        "domain": domain,
        "mx_records": [{"preference": p, "host": h} for p, h in mx_records],
        "mx_results": mx_results,
        "sample_mail": sample_mail_block,
    }
