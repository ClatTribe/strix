"""Subdomain takeover candidate detection.

For each given subdomain (or auto-derived list), follow CNAMEs and match the
final target against a known third-party-service fingerprint table. When a
CNAME points at a service whose response indicates the project / bucket /
app is unclaimed, emit a structured finding.

This tool is conservative — it flags *candidates*. Active verification (claim
the project, confirm exploitability) is a separate step that requires
authorization and is intentionally out of scope here.
"""

from __future__ import annotations

import logging
import re
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


logger = logging.getLogger(__name__)
_TOOL_NAME = "subdomain_takeover_check"


# Provider matrix: each entry maps a provider name to:
#   - cname_pattern: regex matching CNAME targets associated with the provider
#   - fingerprint:   substring/regex that indicates an *unclaimed* response
#                    when the subdomain is fetched. None = "always-candidate"
#                    (CNAMEs to this provider are inherently risky to verify).
#   - severity:      base severity for a confirmed candidate
#
# Source informally cross-referenced with `can-i-take-over-xyz` provider
# knowledge. Signatures are conservative — false positives are acceptable;
# the agent verifies via reasoning and the security team verifies in the
# real environment.
_PROVIDERS: list[dict[str, Any]] = [
    {
        "name": "github_pages",
        "cname_pattern": re.compile(r"\.github\.io\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"There isn't a GitHub Pages site here", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "heroku",
        "cname_pattern": re.compile(r"\.herokuapp\.com\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"No such app", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "shopify",
        "cname_pattern": re.compile(r"\.myshopify\.com\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Sorry, this shop is currently unavailable", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "tumblr",
        "cname_pattern": re.compile(r"\.tumblr\.com\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Whatever you were looking for doesn't currently exist", re.IGNORECASE),
        "severity": "medium",
    },
    {
        "name": "wordpress",
        "cname_pattern": re.compile(r"\.wordpress\.com\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Do you want to register .*?\?", re.IGNORECASE),
        "severity": "medium",
    },
    {
        "name": "fastly",
        "cname_pattern": re.compile(r"\.fastly\.net\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Fastly error: unknown domain", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "aws_s3_website",
        "cname_pattern": re.compile(r"s3-website[.-].*\.amazonaws\.com\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"NoSuchBucket", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "azure_cloudapp",
        "cname_pattern": re.compile(r"\.cloudapp\.(?:net|azure\.com)\.?$", re.IGNORECASE),
        "fingerprint": None,  # always-candidate; manual verification required
        "severity": "medium",
    },
    {
        "name": "vercel",
        "cname_pattern": re.compile(r"\.vercel\.app\.?$|\.vercel-dns(?:-\d+)?\.com\.?$", re.IGNORECASE),
        # Vercel returns 404 for unclaimed projects; fingerprint is a "404: NOT_FOUND" page.
        "fingerprint": re.compile(r"404: NOT_FOUND|This deployment can not be found", re.IGNORECASE),
        "severity": "medium",
    },
    {
        "name": "netlify",
        "cname_pattern": re.compile(r"\.netlify\.(?:app|com)\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Not Found - Request ID:", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "bitbucket",
        "cname_pattern": re.compile(r"\.bitbucket\.io\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Repository not found", re.IGNORECASE),
        "severity": "high",
    },
    {
        "name": "ghost",
        "cname_pattern": re.compile(r"\.ghost\.io\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"The thing you were looking for is no longer here", re.IGNORECASE),
        "severity": "medium",
    },
    {
        "name": "readme",
        "cname_pattern": re.compile(r"\.readme\.io\.?$", re.IGNORECASE),
        "fingerprint": re.compile(r"Project doesnt exist", re.IGNORECASE),
        "severity": "medium",
    },
]


def _resolve_cname(host: str) -> str | None:
    """Return the final CNAME target (without trailing dot), or None."""
    out = dig(host, "CNAME")
    if not out:
        return None
    target = out.splitlines()[0].strip()
    return target.rstrip(".") or None


def _classify(cname_target: str) -> dict[str, Any] | None:
    for entry in _PROVIDERS:
        if entry["cname_pattern"].search(cname_target):
            return entry
    return None


def _check_one(host: str) -> dict[str, Any]:
    check_id = start_check(category="subdomain_takeover", surface=host, tool=_TOOL_NAME)
    cname = _resolve_cname(host)
    if not cname:
        complete_check(check_id, "not_vulnerable", evidence="no CNAME")
        return {"host": host, "cname": None, "candidate": False}

    provider = _classify(cname)
    if not provider:
        complete_check(check_id, "not_vulnerable", evidence=f"CNAME → {cname} (no known provider)")
        return {"host": host, "cname": cname, "candidate": False}

    # Provider matched. Try to verify by HTTP fetching the host and matching
    # the unclaimed-fingerprint. If no fingerprint defined for this provider,
    # we still emit a finding but mark verification_status as "pattern_match".
    body = ""
    fingerprint = provider.get("fingerprint")
    is_unclaimed = False
    if fingerprint is not None:
        for scheme in ("https", "http"):
            status, body = http_get_text(f"{scheme}://{host}/", max_bytes=8192)
            if status:
                break
        if body and fingerprint.search(body):
            is_unclaimed = True

    severity = provider["severity"] if (is_unclaimed or fingerprint is None) else "info"
    verification = "verified" if is_unclaimed else "pattern_match"
    summary = (
        f"{host} CNAMEs to {cname} ({provider['name']}). "
        + ("Unclaimed signature confirmed via HTTP fetch." if is_unclaimed
           else "No fingerprint match — manual verification required.")
    )

    if is_unclaimed or fingerprint is None:
        emit_finding(
            title=f"Subdomain takeover candidate: {host}",
            severity=severity,
            category="subdomain_takeover",
            cwe="CWE-1390",
            target=host,
            endpoint=f"https://{host}/",
            description=summary,
            impact=(
                "An attacker who claims the unclaimed third-party project / "
                "bucket / app can serve arbitrary content under this subdomain, "
                "abusing the trust associated with the parent domain (cookies "
                "scoped to the apex, brand reputation, link-trust)."
            ),
            remediation=(
                f"Either claim the {provider['name']} project tied to this "
                "CNAME, repoint the CNAME to a host you control, or delete "
                "the subdomain record."
            ),
            verification_status=verification,
        )

    # Emit completed-check verdict: vulnerable if unclaimed-fingerprint matched
    # or provider has fingerprint=None (always-candidate); otherwise the
    # CNAME-only match is treated as inconclusive — confirmation requires
    # active verification (out of scope here).
    if is_unclaimed or fingerprint is None:
        complete_check(
            check_id,
            "vulnerable",
            confidence=0.95 if is_unclaimed else 0.6,
            evidence=summary,
        )
    else:
        complete_check(
            check_id,
            "inconclusive",
            confidence=0.4,
            evidence=summary,
        )

    return {
        "host": host,
        "cname": cname,
        "candidate": True,
        "provider": provider["name"],
        "verification_status": verification,
        "severity": severity,
    }


@register_tool(sandbox_execution=True)
def subdomain_takeover_check(
    domain: str, subdomains: str | None = None
) -> dict[str, Any]:
    """Check a list of subdomains (or the apex) for takeover candidates.

    Args:
        domain: apex domain (used as fallback when `subdomains` not given).
        subdomains: comma-separated list of fully-qualified subdomains to check
                    (e.g. "blog.example.com,api.example.com"). When omitted,
                    only the apex `domain` is checked — practical use-case is
                    to first run subfinder, then pass the result here.

    Each candidate is emitted as a structured finding. Returns a per-subdomain
    summary the agent can iterate.
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    if subdomains:
        hosts = [h.strip() for h in subdomains.split(",") if h.strip()]
        invalid = [h for h in hosts if not looks_like_domain(h)]
        if invalid:
            return {"success": False, "error": f"invalid subdomains: {invalid}"}
    else:
        hosts = [domain]

    results = [_check_one(h) for h in hosts]
    candidates = [r for r in results if r.get("candidate")]
    return {
        "success": True,
        "domain": domain,
        "checked": len(hosts),
        "candidates": len(candidates),
        "results": results,
    }
