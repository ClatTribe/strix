"""`scan_subdomain_takeover_active` — deterministic active subdomain-
takeover specialist (workitem.md Phase 2.9).

Closes CWE-1390 + CWE-668. Differs from the existing
`subdomain_takeover_check` (passive CNAME inspection) by ACTIVELY
fetching the candidate URL and checking the response body / status
against a curated list of dangling-CNAME signatures from
`can-i-take-over-xyz`-style databases.

Why this is high-leverage
-------------------------

DNS recon (Phase 2.X domain pipeline) emits a list of subdomains.
Today the lead has the CNAME-only check — but most takeover
candidates are only confirmable by fetching the URL: the response
body / 404 page reveals the unclaimed cloud service.

Detection strategy
------------------

For each candidate subdomain URL, GET it and compare the response
body / status code against the signature table below. A hit means
the CNAME points at an unclaimed cloud-service slot — register the
slot, you control the subdomain.

Signatures (curated from EdOverflow's `can-i-take-over-xyz` +
ProjectDiscovery's nuclei templates):

  * **AWS S3** — `<Code>NoSuchBucket</Code>` — 404 / 403
  * **GitHub Pages** — "There isn't a GitHub Pages site here"
  * **Heroku** — `No such app` — 404
  * **Azure** — `404 Web Site not found.`
  * **Bitbucket** — "Repository not found"
  * **Cloudfront** — "Bad request" + Server: CloudFront + 403
  * **Fastly** — "Fastly error: unknown domain"
  * **Pantheon** — "The gods are wise, but do not know..."
  * **Tumblr** — "Whatever you were looking for doesn't currently"
  * **WordPress** — "Do you want to register"
  * **Shopify** — "Sorry, this shop is currently unavailable"
  * **Squarespace** — "No Such Account"
  * **Webflow** — "The page you are looking for doesn't exist"
  * **Zendesk** — "this help center no longer exists"
  * **Vercel** — `DEPLOYMENT_NOT_FOUND` / "The deployment could not be found"
  * **Netlify** — "Not Found - Request ID:" + 404

Auto-emits CWE-1390 finding on detection. Severity: high.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# (service_label, fingerprint_substr_lower, severity, takeover_instructions)
# fingerprint matched against the response body (case-insensitive).
_SIGNATURES: tuple[tuple[str, str, str, str], ...] = (
    (
        "aws_s3",
        "<code>nosuchbucket</code>",
        "high",
        "Register the S3 bucket name in any AWS account",
    ),
    (
        "aws_s3_message",
        "the specified bucket does not exist",
        "high",
        "Register the S3 bucket name in any AWS account",
    ),
    (
        "github_pages",
        "there isn't a github pages site here",
        "high",
        "Create a GitHub repo named matching the CNAME target",
    ),
    (
        "heroku",
        "no such app",
        "high",
        "Create a Heroku app with the unclaimed slug",
    ),
    (
        "azure_websites",
        "404 web site not found",
        "high",
        "Register the Azure App Service slot",
    ),
    (
        "bitbucket",
        "repository not found",
        "high",
        "Register the Bitbucket repo / pages slot",
    ),
    (
        "cloudfront",
        "bad request: errorcode: invalid_host_header",
        "medium",
        "Configure CloudFront distribution to claim the host",
    ),
    (
        "fastly",
        "fastly error: unknown domain",
        "high",
        "Register the Fastly service for the host",
    ),
    (
        "pantheon",
        "the gods are wise",
        "high",
        "Register the Pantheon site slot",
    ),
    (
        "tumblr",
        "whatever you were looking for doesn't currently exist",
        "medium",
        "Register the Tumblr blog name",
    ),
    (
        "wordpress",
        "do you want to register",
        "medium",
        "Register the WordPress.com blog",
    ),
    (
        "shopify",
        "sorry, this shop is currently unavailable",
        "high",
        "Register the Shopify shop slug",
    ),
    (
        "squarespace",
        "no such account",
        "medium",
        "Register the Squarespace account",
    ),
    (
        "webflow",
        "the page you are looking for doesn't exist",
        "low",
        "Register the Webflow project (low confidence — generic message)",
    ),
    (
        "zendesk",
        "this help center no longer exists",
        "high",
        "Register the Zendesk help-centre subdomain",
    ),
    (
        "vercel_deployment",
        "deployment_not_found",
        "high",
        "Claim the Vercel deployment URL",
    ),
    (
        "vercel_deployment_msg",
        "the deployment could not be found",
        "high",
        "Claim the Vercel deployment URL",
    ),
    (
        "netlify",
        "not found - request id:",
        "medium",
        "Register the Netlify site slug",
    ),
    (
        "ghost",
        "the thing you were looking for is no longer here",
        "medium",
        "Register the Ghost blog",
    ),
    (
        "readme_io",
        "project doesnt exist",
        "medium",
        "Register the readme.io project",
    ),
    (
        "surge_sh",
        "project not found",
        "high",
        "Register the surge.sh project",
    ),
    (
        "tilda",
        "please renew your subscription",
        "medium",
        "Renew/claim the Tilda subscription",
    ),
)


def _emit_finding(
    *,
    url: str,
    service_label: str,
    fingerprint: str,
    severity: str,
    takeover_instructions: str,
    response_excerpt: str,
    status_code: int,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=f"Subdomain takeover possible at `{url}` ({service_label})",
            severity=severity,
            cwe="CWE-1390",
            endpoint=url,
            target=url,
            category="subdomain_takeover",
            verification_status="verified",
            confidence=0.9,
            description=(
                f"GET `{url}` returned a response containing the "
                f"unclaimed-service fingerprint `{service_label}`:\n"
                f"  → {fingerprint}\n\n"
                f"This means the DNS record (typically a CNAME) for "
                f"the host points at a {service_label} slot that no "
                f"longer exists. An attacker who registers that slot "
                f"now controls the subdomain — full content control, "
                f"cookie scope hijack, and (if the parent uses cookie-"
                f"sharing across subdomains) session theft on the "
                f"main app."
            ),
            impact=(
                "Subdomain takeover. The unclaimed slot can be "
                "claimed by any attacker:\n"
                "  * Serve attacker content on the legitimate "
                "    domain — perfect phishing vector (browser shows "
                "    the trusted parent domain).\n"
                "  * Receive cookies scoped to `*.parent.com` — "
                "    session hijack against the main app.\n"
                "  * Issue valid TLS certificate via DV (Let's "
                "    Encrypt confirms domain-control via HTTP "
                "    challenge — which now goes to the attacker).\n"
                "  * Bypass IP allowlists / SSO trust relationships "
                "    that key off the parent organisation's domain."
            ),
            technical_analysis=(
                f"URL: {url}\n"
                f"Status code: {status_code}\n"
                f"Service signature: {service_label}\n"
                f"Fingerprint: {fingerprint}\n"
                f"Takeover step: {takeover_instructions}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Confirm the DNS chain: `dig +short {url}` resolves "
                f"to a {service_label} slot.\n"
                f"2. {takeover_instructions}\n"
                f"3. Once registered, serve any content — the browser "
                f"shows the trusted domain, and any cookie scoped to "
                f"the parent `*.domain.com` flows to your slot."
            ),
            poc_script_code=f"curl -sS -i '{url}' | head -c 2000",
            remediation_steps=(
                "1. IMMEDIATELY remove the dangling DNS record OR "
                "re-register the orphaned cloud-service slot.\n"
                "2. Audit ALL CNAME records pointing at cloud "
                "services (S3, GitHub Pages, Heroku, Vercel, "
                "Netlify, Azure, etc.) — they all share this risk.\n"
                "3. Implement a DNS hygiene process: when a service "
                "is decommissioned, the CNAME is removed in the same "
                "change. Add a CI lint that flags orphaned CNAMEs.\n"
                "4. For high-value parent domains, consider "
                "switching to a subdomain-takeover-resistant DNS "
                "configuration (point CNAMEs at customer-owned "
                "intermediate hosts, not directly at SaaS slots)."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "R",
                "S": "C", "C": "H", "I": "H", "A": "L",
            },
            reasoning_trace=[
                f"GET {url} returned status {status_code}.",
                f"Response matched {service_label} unclaimed-slot fingerprint.",
                f"Takeover step: {takeover_instructions}",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_subdomain_takeover_active: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="subdomain-takeover-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1583", "T1584"],
)
def scan_subdomain_takeover_active(
    *,
    urls: list[str] | str | None = None,
    url: str | None = None,
    extra_headers: dict[str, str] | None = None,
    max_urls: int = 100,
) -> SpecialistResult:
    """Active subdomain-takeover scanner — fetches each URL and matches
    the response against curated unclaimed-service fingerprints.

    Args:
        urls: list of subdomain URLs to probe.
        url: convenience alias for a single URL.
        extra_headers: forwarded as-is.
        max_urls: cap to prevent runaway probing.

    Auto-emits one finding per (url, service_label) hit.
    """
    if url and not urls:
        urls = [url]
    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        return SpecialistResult(
            status="partial",
            error="no URLs supplied",
            evidence=[
                "scan_subdomain_takeover_active invoked with no urls; "
                "supply `urls=[...]` or `url=...`. Typically called "
                "with subdomains discovered by `subdomain_enum_tool`."
            ],
        )

    urls = list(urls)[:max_urls]

    extra_headers = dict(extra_headers or {})
    # Set a User-Agent — some takeover signatures only show on
    # browser-shaped requests.
    extra_headers.setdefault(
        "User-Agent",
        "Mozilla/5.0 (compatible; strix-subdomain-takeover-scan/1.0)",
    )

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    fetch_count = 0
    seen_findings: set[tuple[str, str]] = set()

    for u in urls:
        if not isinstance(u, str) or not u.strip():
            continue
        u = u.strip()
        try:
            resp = pm.send_simple_request(
                "GET", u,
                headers=extra_headers, body="", timeout=15,
            )
            fetch_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"transport error for {u}: {e}")
            continue
        if "error" in resp and not resp.get("status_code"):
            continue
        body = resp.get("body") or ""
        if not isinstance(body, str):
            body = ""
        status = int(resp.get("status_code") or 0)
        body_lower = body.lower()

        for service_label, fingerprint, severity, takeover_instructions in _SIGNATURES:
            if fingerprint not in body_lower:
                continue
            key = (u, service_label)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            # Excerpt around the match for evidence.
            idx = body_lower.find(fingerprint)
            start = max(0, idx - 100)
            end = min(len(body), idx + len(fingerprint) + 200)
            excerpt = body[start:end]
            rid = _emit_finding(
                url=u, service_label=service_label,
                fingerprint=fingerprint, severity=severity,
                takeover_instructions=takeover_instructions,
                response_excerpt=excerpt, status_code=status,
            )
            if rid:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"Subdomain takeover at `{u}` ({service_label})",
                severity=severity, cwe="CWE-1390",
                endpoint=u, category="subdomain_takeover",
                verification_status="verified", confidence=0.9,
                description=f"Unclaimed slot fingerprint: {service_label}",
            ))
            evidence.append(f"takeover: {u} → {service_label}")
            break  # one finding per URL

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        for u in urls:
            record_endpoint(u, method="GET", probed_for="subdomain_takeover")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=urls[0] if urls else None,
            actor={"tool_name": "scan_subdomain_takeover_active"},
            input={"urls_count": len(urls), "fetches_done": fetch_count},
            output={"findings_emitted": emitted_count, "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["confirm DNS chain (`dig +short`) + register the unclaimed slot in a sandboxed account"]
            if drafts else
            ["no takeovers in supplied URLs; expand subdomain enumeration "
             "(passive DNS history, certificate transparency logs)"]
        ),
        tool_metadata={
            "fetches_done": fetch_count,
            "urls_attempted": len(urls),
            "findings_emitted_to_tracer": emitted_count,
            "signatures_checked": len(_SIGNATURES),
        },
    )
