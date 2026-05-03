"""Public SaaS leak discovery — find org-named public pages on
known leak-prone SaaS platforms.

Roadmap §7.3. Many orgs accidentally publish internal docs to "the
world" via permalink: a Trello board left on "Public", a Notion page
shared with "Anyone with the link", a Google Doc set to public, a
Pastebin upload. These are real treasure sources during external recon
and are completely invisible to DNS / port-scan / crawl tooling.

Search strategy:

This tool uses **Bing Web Search API** (key-gated on `STRIX_BING_KEY`)
to issue `site:<platform> "<org_name>"` queries against each known
leak-prone SaaS platform. We deliberately do not scrape Google or
DuckDuckGo — those return CAPTCHAs to non-browser clients within
minutes, and a tool that fails 80% of the time is worse than no tool.

When `STRIX_BING_KEY` isn't set, the tool fail-opens with a clear
`error_reason="no api key configured"` so the agent can move on.

Findings:
- **Info** (CWE-200, info_disclosure) for each hit — an org-named page
  on a public-by-default platform is a leak candidate.
- **High** (CWE-200, info_disclosure, `verification_status=needs_review`)
  when the snippet contains secret-indicator tokens (`password`,
  `api_key`, `Bearer`, etc.) — same heuristic as code_search.

The agent is expected to fetch the URL, confirm the leak, and decide
on takedown / rotation if the document is genuinely sensitive.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from strix.tools.registry import register_tool

from ._common import complete_check, emit_finding, start_check


logger = logging.getLogger(__name__)
_TOOL_NAME = "saas_leak_discovery"
_HTTP_TIMEOUT = 12

_BING_API = "https://api.bing.microsoft.com/v7.0/search"

_DEFAULT_MAX_RESULTS = 20
_HARD_MAX_RESULTS = 50

# Reuse the same secret-indicator heuristic as code_search.py — see
# that file for rationale on the no-\b boundary choice.
_SECRET_INDICATOR_RE = re.compile(
    r"("
    r"api[_-]?key|access[_-]?key|secret[_-]?key|secret_access_key|"
    r"client[_-]?secret|auth[_-]?token|bearer\s|password|passwd|"
    r"private[_-]?key|aws_access|aws_secret|stripe_(?:live|test)_|"
    r"sk_(?:live|test)_|xox[abopr]-|ghp_[A-Za-z0-9]|gho_[A-Za-z0-9]|"
    r"glpat-|slack_token|github_token|credential"
    r")",
    re.IGNORECASE,
)


# Provider matrix. Each entry:
#   - search_site: the dork's site: filter
#   - url_match: regex confirming the result URL is actually on this
#                platform's leak-shaped path (Bing site: filters can
#                return tangentially-related pages)
#   - description: one-line rationale shown in the finding's impact
_PROVIDERS: dict[str, dict[str, Any]] = {
    "trello": {
        "search_site": "trello.com",
        "url_match": re.compile(r"^https?://trello\.com/b/", re.IGNORECASE),
        "description": (
            "Trello boards default to private but are commonly switched to public "
            "for sharing. Public boards can leak credentials, internal roadmaps, "
            "support-case PII."
        ),
    },
    "notion": {
        "search_site": "notion.site",
        "url_match": re.compile(r"^https?://[\w-]+\.notion\.site/", re.IGNORECASE),
        "description": (
            "Notion pages shared with 'Anyone with the link' are indexed once "
            "the link is referenced anywhere public. Internal docs / runbooks / "
            "credential rotation guides are common leaks."
        ),
    },
    "google_docs": {
        "search_site": "docs.google.com",
        "url_match": re.compile(
            r"^https?://docs\.google\.com/(?:document|spreadsheets|presentation|forms)/d/",
            re.IGNORECASE,
        ),
        "description": (
            "Google Docs / Sheets / Slides published with 'Anyone on the "
            "internet' permission are search-indexed. Frequently contain "
            "internal data, customer lists, credentials."
        ),
    },
    "google_drive": {
        "search_site": "drive.google.com",
        "url_match": re.compile(
            r"^https?://drive\.google\.com/(?:file|drive)/", re.IGNORECASE
        ),
        "description": (
            "Public Google Drive folders / files. The folder view exposes the "
            "complete directory contents including unredacted filenames."
        ),
    },
    "pastebin": {
        "search_site": "pastebin.com",
        "url_match": re.compile(r"^https?://pastebin\.com/(?:raw/)?[A-Za-z0-9]+", re.IGNORECASE),
        "description": (
            "Pastebin is a classic leak vector for code snippets / config "
            "dumps / database extracts. Org-name references are high-signal."
        ),
    },
    "confluence_cloud": {
        "search_site": "atlassian.net",
        "url_match": re.compile(
            r"^https?://[\w-]+\.atlassian\.net/wiki/", re.IGNORECASE
        ),
        "description": (
            "Atlassian Cloud Confluence pages are private by default, but "
            "anonymous-access pages occasionally surface internal runbooks."
        ),
    },
    "airtable": {
        "search_site": "airtable.com",
        "url_match": re.compile(
            r"^https?://airtable\.com/(?:app|shr)", re.IGNORECASE
        ),
        "description": (
            "Public Airtable bases sometimes contain customer lists, sales "
            "pipelines, support tickets."
        ),
    },
}


def _http_get_json(
    url: str, *, headers: dict[str, str], params: dict[str, str] | None = None
) -> tuple[int, dict[str, Any] | None]:
    """GET returning (status, parsed_json or None)."""
    try:
        import httpx

        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as c:
            r = c.get(url, headers=headers, params=params)
            try:
                return r.status_code, r.json()
            except Exception:  # noqa: BLE001
                return r.status_code, None
    except Exception:  # noqa: BLE001
        try:
            import json as _json
            import urllib.parse
            import urllib.request

            full = url
            if params:
                full = f"{url}?{urllib.parse.urlencode(params)}"
            req = urllib.request.Request(full, headers=headers)
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:  # noqa: S310
                body = r.read()
            try:
                return r.status, _json.loads(body)
            except Exception:  # noqa: BLE001
                return r.status, None
        except Exception:  # noqa: BLE001
            return 0, None


def _bing_search(
    query: str, api_key: str, *, count: int
) -> tuple[int, list[dict[str, str]], str | None]:
    """Run a Bing Web Search and normalize results.

    Returns (status, results, error). `results` is a list of
    {url, name, snippet} dicts.
    """
    headers = {
        "Ocp-Apim-Subscription-Key": api_key,
        "Accept": "application/json",
    }
    params = {"q": query, "count": str(min(count, 50)), "responseFilter": "Webpages"}
    status, data = _http_get_json(_BING_API, headers=headers, params=params)
    if status == 401:
        return status, [], "unauthorized"
    if status == 429:
        return status, [], "rate_limited"
    if status != 200 or not isinstance(data, dict):
        return status, [], f"http_{status}"
    web = data.get("webPages") if isinstance(data.get("webPages"), dict) else {}
    raw = web.get("value") if isinstance(web, dict) else []
    results: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            if not isinstance(url, str):
                continue
            results.append(
                {
                    "url": url,
                    "name": item.get("name") or "",
                    "snippet": item.get("snippet") or "",
                }
            )
    return status, results, None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1593"],  # Search Open Websites/Domains
)
def saas_leak_discovery(
    org_name: str,
    providers: str | None = None,
    max_results_per_provider: int = _DEFAULT_MAX_RESULTS,
) -> dict[str, Any]:
    """Discover org-named public pages on known leak-prone SaaS platforms.

    Args:
        org_name: organization or domain name. Used as the literal-quoted
                  search term (e.g. `site:trello.com "acme"`). For domains,
                  pass the apex (or the leftmost label).
        providers: comma-separated subset of {trello, notion, google_docs,
                   google_drive, pastebin, confluence_cloud, airtable}.
                   Default: all.
        max_results_per_provider: max hits per provider. Default 20, capped 50.

    Required environment:
        - `STRIX_BING_KEY` — Bing Web Search API key.

    Behaviour:
        - Fail-open when no key is configured (success=False with
          error_reason="no api key configured"). The agent should move
          on rather than retrying.
        - For each hit, an info-severity finding is emitted (CWE-200,
          info_disclosure) with the URL + snippet as evidence.
        - When the snippet contains secret-indicator tokens, severity
          escalates to high (CWE-200, `verification_status=needs_review`)
          — the agent must verify by fetching the URL.

    Returns:
        {
          success, org_name,
          providers_queried, per_provider: [{provider, success, hits,
                                              error?}],
          hit_count, secret_leak_count
        }
    """
    if not org_name or not org_name.strip():
        return {"success": False, "error": "org_name required"}
    org_name = org_name.strip()
    # Use the leftmost dotted label as the search term to match how the
    # agent typically receives a domain target.
    search_term = org_name.split(".")[0].lower()

    api_key = os.environ.get("STRIX_BING_KEY")
    if not api_key:
        return {
            "success": False,
            "error_reason": "no api key configured",
            "hint": "Set STRIX_BING_KEY in the worker environment to enable SaaS leak discovery.",
            "org_name": org_name,
        }

    if providers is None or providers.strip().lower() == "all":
        active = list(_PROVIDERS.keys())
    else:
        active = [p.strip().lower() for p in providers.split(",") if p.strip()]
        unknown = [p for p in active if p not in _PROVIDERS]
        if unknown:
            return {"success": False, "error": f"unknown providers: {unknown}"}

    capped_max = max(1, min(max_results_per_provider, _HARD_MAX_RESULTS))
    per_provider_results: list[dict[str, Any]] = []
    total_hits = 0
    secret_leak_count = 0

    for provider in active:
        prov_info = _PROVIDERS[provider]
        cev_id = start_check(
            category="saas_leaks", surface=org_name, tool=_TOOL_NAME
        )
        query = f'site:{prov_info["search_site"]} "{search_term}"'
        status, raw_results, error = _bing_search(query, api_key, count=capped_max)
        # Filter results by the platform's URL pattern — Bing's
        # `site:` filter sometimes returns tangentially-related pages.
        url_match = prov_info["url_match"]
        filtered_hits: list[dict[str, str]] = []
        for r in raw_results:
            if url_match.match(r["url"]):
                filtered_hits.append(r)

        per_provider_results.append(
            {
                "provider": provider,
                "success": error is None,
                "raw_count": len(raw_results),
                "hits": filtered_hits,
                **({"error": error} if error else {}),
            }
        )
        total_hits += len(filtered_hits)

        for hit in filtered_hits:
            snippet = hit.get("snippet") or ""
            has_secret = bool(_SECRET_INDICATOR_RE.search(snippet))
            if has_secret:
                secret_leak_count += 1
            severity = "high" if has_secret else "info"
            verification = "needs_review" if has_secret else "verified"
            title_prefix = (
                "Possible secret leak in" if has_secret else "Public SaaS reference on"
            )
            emit_finding(
                title=f"{title_prefix} {provider}: {hit.get('name') or '(untitled)'}",
                severity=severity,
                category="info_disclosure",
                cwe="CWE-200",
                target=org_name,
                endpoint=hit["url"],
                description=(
                    f"Search hit on {prov_info['search_site']} for '{search_term}'.\n"
                    f"URL: {hit['url']}\n"
                    f"Title: {hit.get('name') or '(untitled)'}\n"
                    f"Snippet: {snippet[:400]}"
                ),
                impact=(
                    "Snippet contains secret-shaped tokens — treat the linked "
                    "page as a credential leak until proven otherwise. The agent "
                    "should fetch the URL, confirm whether secrets are present, "
                    "and trigger immediate rotation if so."
                    if has_secret
                    else prov_info["description"]
                ),
                remediation=(
                    "If the document genuinely contains a credential, rotate "
                    "immediately and audit access logs. Then change the "
                    "document's sharing setting from public to restricted. "
                    "Add a workspace-wide policy preventing 'Anyone with the "
                    "link' sharing for documents tagged sensitive."
                    if has_secret
                    else (
                        "Review whether the document needs to be public. If "
                        "not, change sharing settings to restricted. If it must "
                        "remain public, scrub it of internal data. Establish a "
                        "workspace-wide review process for public documents."
                    )
                ),
                verification_status=verification,
            )

        complete_check(
            cev_id,
            result=("not_vulnerable" if error is None else "inconclusive"),
            evidence=f"{provider}: {len(filtered_hits)} matched hit(s)"
            + (f" (raw: {len(raw_results)})" if filtered_hits != raw_results else ""),
        )

    return {
        "success": any(r.get("success") for r in per_provider_results),
        "org_name": org_name,
        "providers_queried": active,
        "per_provider": per_provider_results,
        "hit_count": total_hits,
        "secret_leak_count": secret_leak_count,
    }
