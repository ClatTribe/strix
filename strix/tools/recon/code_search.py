"""Code-search recon — find references to the org's apex domain in
public source-code hosts.

Roadmap §7.3. Catches subdomains and dev/staging URLs never advertised
externally, plus accidentally-committed secrets adjacent to those URLs.
A staple of real-world external recon: GitHub's index covers tens of
millions of public repos and pulls up dev URLs that DNS enumeration
will never see.

Provider matrix:
- **GitHub Code Search** (`api.github.com/search/code`). Requires
  `STRIX_GITHUB_TOKEN` (free GitHub PAT; unauthenticated requests are
  rate-limited to 10/min and frequently 403).
- **GitLab** (`gitlab.com/api/v4/search?scope=blobs`). Optional
  `STRIX_GITLAB_TOKEN` raises the rate limit; works at low rate
  without one.

Findings:
- For each hit, an info-severity finding is emitted with the repo +
  file + snippet evidence so the agent can drill into the most
  promising leaks.
- When a snippet contains tokens that look like a secret near the
  domain reference (api_key / secret / password / token / bearer
  patterns), severity escalates to **high** with category=secret_leak
  / CWE-798.
- Subdomains extracted from snippets feed into `surface_map.json`
  for the next phase.

Fail-open: if no providers have keys configured, returns
`success=False` with a clear `error_reason` so the agent moves on.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from strix.tools.registry import register_tool

from ._common import complete_check, emit_finding, looks_like_domain, start_check


logger = logging.getLogger(__name__)
_TOOL_NAME = "code_search_for_domain"
_HTTP_TIMEOUT = 15

_GITHUB_API = "https://api.github.com/search/code"
_GITLAB_API = "https://gitlab.com/api/v4/search"

_DEFAULT_MAX_RESULTS = 30
_HARD_MAX_RESULTS = 100

# Secret-indicator regex applied to the matched-line snippet. When any
# of these match in the same snippet that references the domain, we
# escalate severity to high (CWE-798). No \b anchors — `_` is a word
# character, so boundaries fail at typical underscore-separated names
# like AWS_SECRET_KEY. False positives here are acceptable; findings
# are emitted with verification_status="needs_review".
_SECRET_INDICATOR_RE = re.compile(
    r"("
    r"api[_-]?key|access[_-]?key|secret[_-]?key|secret_access_key|"
    r"client[_-]?secret|auth[_-]?token|bearer\s|password|passwd|"
    r"private[_-]?key|aws_access|aws_secret|stripe_(?:live|test)_|"
    r"sk_(?:live|test)_|xox[abopr]-|ghp_[A-Za-z0-9]|gho_[A-Za-z0-9]|"
    r"glpat-|slack_token|github_token"
    r")",
    re.IGNORECASE,
)

# Capture a host token that ends in ".<apex>" to extract leaked
# subdomain references.
def _build_subdomain_re(apex: str) -> re.Pattern[str]:
    escaped = re.escape(apex)
    # Hostname tokens preceding ".<apex>"; allow a-z0-9 and "-".
    return re.compile(rf"\b([a-z0-9][a-z0-9.\-]*\.{escaped})\b", re.IGNORECASE)


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


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


def _github_code_search(
    domain: str, token: str, max_results: int
) -> dict[str, Any]:
    """Query GitHub Code Search for `domain`. Returns normalized hit list."""
    headers = {
        "Accept": "application/vnd.github.text-match+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # GitHub paginates at 100; bound per-call.
    per_page = min(max_results, 100)
    params = {"q": f'"{domain}"', "per_page": str(per_page)}
    status, data = _http_get_json(_GITHUB_API, headers=headers, params=params)
    if status == 401:
        return {
            "provider": "github",
            "success": False,
            "error": "unauthorized (token rejected)",
            "hits": [],
        }
    if status == 403:
        # GitHub returns 403 for rate-limit and for unauthorized
        # repository-content access.
        return {
            "provider": "github",
            "success": False,
            "error": "rate_limited_or_forbidden",
            "hits": [],
        }
    if status != 200 or not isinstance(data, dict):
        return {
            "provider": "github",
            "success": False,
            "error": f"http_{status}",
            "hits": [],
        }
    raw_items = data.get("items") if isinstance(data.get("items"), list) else []
    hits: list[dict[str, Any]] = []
    for item in raw_items[:max_results]:
        if not isinstance(item, dict):
            continue
        repo_obj = item.get("repository") or {}
        repo_name = repo_obj.get("full_name") if isinstance(repo_obj, dict) else None
        path = item.get("path")
        html_url = item.get("html_url")
        snippets: list[str] = []
        for tm in item.get("text_matches", []) or []:
            frag = tm.get("fragment") if isinstance(tm, dict) else None
            if isinstance(frag, str) and frag.strip():
                snippets.append(frag.strip())
        hits.append(
            {
                "provider": "github",
                "repo": repo_name,
                "path": path,
                "url": html_url,
                "snippets": snippets,
            }
        )
    return {
        "provider": "github",
        "success": True,
        "total_count": data.get("total_count"),
        "hits": hits,
    }


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------


def _gitlab_code_search(
    domain: str, token: str | None, max_results: int
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["PRIVATE-TOKEN"] = token
    per_page = min(max_results, 100)
    params = {"scope": "blobs", "search": f'"{domain}"', "per_page": str(per_page)}
    status, data = _http_get_json(_GITLAB_API, headers=headers, params=params)
    if status == 401:
        return {
            "provider": "gitlab",
            "success": False,
            "error": "unauthorized",
            "hits": [],
        }
    if status == 429:
        return {
            "provider": "gitlab",
            "success": False,
            "error": "rate_limited",
            "hits": [],
        }
    if status != 200 or not isinstance(data, list):
        return {
            "provider": "gitlab",
            "success": False,
            "error": f"http_{status}",
            "hits": [],
        }
    hits: list[dict[str, Any]] = []
    for item in data[:max_results]:
        if not isinstance(item, dict):
            continue
        # GitLab blob results: project_id, path, ref, filename, data (snippet).
        snippet = item.get("data")
        path = item.get("path") or item.get("filename")
        project = item.get("project_id")
        ref = item.get("ref")
        url: str | None = None
        if isinstance(project, int) and path and ref:
            url = (
                f"https://gitlab.com/api/v4/projects/{project}/repository/files/"
                f"{path}/raw?ref={ref}"
            )
        snippets: list[str] = []
        if isinstance(snippet, str) and snippet.strip():
            # GitLab snippets are typically multi-line; cap length.
            snippets.append(snippet.strip()[:500])
        hits.append(
            {
                "provider": "gitlab",
                "repo": str(project) if project is not None else None,
                "path": path,
                "url": url,
                "snippets": snippets,
            }
        )
    return {
        "provider": "gitlab",
        "success": True,
        "total_count": len(data),
        "hits": hits,
    }


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


_KNOWN_PROVIDERS = ("github", "gitlab")


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1593.003"],  # Search Open Websites/Domains: Code Repositories
)
def code_search_for_domain(
    domain: str,
    providers: str | None = None,
    max_results: int = _DEFAULT_MAX_RESULTS,
) -> dict[str, Any]:
    """Search public code hosts for references to `domain`.

    Args:
        domain: apex or subdomain. The exact string is queried (quoted).
        providers: comma-separated subset of {github, gitlab}. Default: all
                   (key-gated providers fall back gracefully).
        max_results: max hits per provider (capped at 100).

    Provider keys:
        - `STRIX_GITHUB_TOKEN` — required for GitHub.
        - `STRIX_GITLAB_TOKEN` — optional for GitLab (unauthenticated
          requests work at low rate).

    Behaviour:
        - For each hit, emits an info-severity finding (info_disclosure,
          CWE-200) with the repo + file + snippet as evidence.
        - When a snippet contains secret-indicator tokens (api_key,
          secret, password, bearer, AWS-style key prefixes, etc.) near
          the domain reference, severity escalates to **high** with
          category=secret_leak and CWE-798.
        - Subdomains extracted from snippets are returned in
          `extracted_subdomains` for handoff to the next phase.

    Returns:
        {
          success, domain,
          providers_queried: [...],
          per_provider: [{provider, success, total_count?, hits, error?}],
          extracted_subdomains: [...],
          hit_count, secret_leak_count
        }
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    capped_max = max(1, min(max_results, _HARD_MAX_RESULTS))

    # Resolve provider set.
    if providers is None or providers.strip().lower() == "all":
        active = list(_KNOWN_PROVIDERS)
    else:
        active = [p.strip().lower() for p in providers.split(",") if p.strip()]
        unknown = [p for p in active if p not in _KNOWN_PROVIDERS]
        if unknown:
            return {"success": False, "error": f"unknown providers: {unknown}"}

    gh_token = os.environ.get("STRIX_GITHUB_TOKEN")
    gl_token = os.environ.get("STRIX_GITLAB_TOKEN")

    explicitly_requested = providers is not None and providers.strip().lower() != "all"
    # GitHub silently dropped without a token unless explicitly requested.
    if "github" in active and not gh_token and not explicitly_requested:
        active = [p for p in active if p != "github"]
    if "github" in active and not gh_token and explicitly_requested:
        return {
            "success": False,
            "error_reason": "github requested but STRIX_GITHUB_TOKEN not set",
            "domain": domain,
        }

    if not active:
        return {
            "success": False,
            "error_reason": "no providers available — set STRIX_GITHUB_TOKEN to enable",
            "domain": domain,
        }

    apex = domain.lower()
    sub_re = _build_subdomain_re(apex)
    extracted_subs: set[str] = set()
    per_provider_results: list[dict[str, Any]] = []
    total_hit_count = 0
    secret_leak_count = 0

    for provider in active:
        cev_id = start_check(category="code_search", surface=domain, tool=_TOOL_NAME)
        try:
            if provider == "github":
                assert gh_token  # guarded above
                r = _github_code_search(apex, gh_token, capped_max)
            elif provider == "gitlab":
                r = _gitlab_code_search(apex, gl_token, capped_max)
            else:
                continue
        except Exception as e:  # noqa: BLE001
            logger.exception("code-search provider %s failed", provider)
            r = {"provider": provider, "success": False, "error": str(e), "hits": []}

        per_provider_results.append(r)
        provider_hits = r.get("hits", []) or []
        total_hit_count += len(provider_hits)

        # Per-hit handling: extract subdomains, scan snippets for secrets,
        # emit findings.
        for hit in provider_hits:
            snippets = hit.get("snippets") or []
            joined_snippets = "\n".join(snippets)
            # Subdomain extraction.
            for m in sub_re.finditer(joined_snippets):
                cand = m.group(1).lower()
                if cand != apex:
                    extracted_subs.add(cand)
            # Secret-indicator detection.
            has_secret_indicator = bool(_SECRET_INDICATOR_RE.search(joined_snippets))
            if has_secret_indicator:
                secret_leak_count += 1

            severity = "high" if has_secret_indicator else "info"
            category = "secret_leak" if has_secret_indicator else "info_disclosure"
            cwe = "CWE-798" if has_secret_indicator else "CWE-200"
            evidence_snippet = (joined_snippets[:400] or "(no snippet)").strip()
            repo_label = hit.get("repo") or "(unknown)"
            path_label = hit.get("path") or "(unknown)"
            title = (
                f"Possible secret leak referencing {apex} in "
                f"{provider}:{repo_label}/{path_label}"
                if has_secret_indicator
                else f"Public code reference to {apex} in "
                f"{provider}:{repo_label}/{path_label}"
            )
            description = (
                f"Match in {provider} repo {repo_label}, file {path_label}.\n"
                f"Snippet:\n{evidence_snippet}"
            )
            impact = (
                "A committed secret adjacent to an in-scope domain reference is "
                "high-confidence evidence that the secret authenticates against "
                "real production infrastructure. Treat as exposed and rotate "
                "immediately, then audit downstream access logs."
                if has_secret_indicator
                else (
                    "Public code references frequently surface internal "
                    "subdomains, dev/staging URLs, deprecated endpoints, and "
                    "debug paths that DNS enumeration alone wouldn't see. "
                    "Each hit is a candidate to fingerprint + skill-load against."
                )
            )
            remediation = (
                "Rotate the leaked credential. Audit git history "
                "(`git log -p -S<secret>`) for re-occurrences. Audit access "
                "logs for the credential's lifetime to determine blast radius. "
                "Add a pre-commit secret-scanner (gitleaks / trufflehog) and a "
                "CI gate to prevent regression."
                if has_secret_indicator
                else (
                    "Review the referenced URL/subdomain — if internal, "
                    "either secure access or rename. For dev/staging URLs, "
                    "consider whether they should be on a private network "
                    "rather than committed in public code."
                )
            )
            emit_finding(
                title=title,
                severity=severity,
                category=category,
                cwe=cwe,
                target=domain,
                endpoint=hit.get("url"),
                description=description,
                impact=impact,
                remediation=remediation,
                verification_status=(
                    "needs_review" if has_secret_indicator else "verified"
                ),
            )

        complete_check(
            cev_id,
            result=("not_vulnerable" if r.get("success") else "inconclusive"),
            evidence=f"{provider}: {len(provider_hits)} hit(s)",
        )

    return {
        "success": any(r.get("success") for r in per_provider_results),
        "domain": domain,
        "providers_queried": active,
        "per_provider": per_provider_results,
        "extracted_subdomains": sorted(extracted_subs),
        "hit_count": total_hit_count,
        "secret_leak_count": secret_leak_count,
    }
