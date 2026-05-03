"""Fresh CVE intelligence via Perplexity.

For a `(tech, version)` pair, run a structured CVE-intel query
through Perplexity's Sonar API. Returns extracted CVE IDs + the raw
LLM summary + citation URLs. Display-only — does NOT emit findings;
the agent feeds extracted CVEs into `cve_lookup` (#61) for
authoritative validation before treating them as real.

Why this complements `cve_lookup`:

- OSV.dev (`cve_lookup`'s data source) lags vendor advisories by
  hours-to-days. A 0-day disclosed Tuesday morning shows up in
  Perplexity's web-indexed corpus before OSV picks it up.
- Vendor advisories that aren't formally CVE-numbered (e.g. "GHSA-…",
  "RHSA-…", or vendor security bulletins) appear in Perplexity but
  may not show up in OSV.
- "In the wild" exploitation reports (KEV-adjacent) come up in
  Perplexity even when KEV hasn't yet listed the CVE.

Auth: `PERPLEXITY_API_KEY` env var (the same key gating the existing
`web_search` tool). Without it, the tool returns
`success=False, error="no PERPLEXITY_API_KEY configured"` so the
agent knows to fall back to `cve_lookup` only.

Caching: per-(tech, version) JSON cache under
`~/.strix/cve_intel_cache/`, 12-hour TTL. Stale-cache served on
network failure (fail-open with `error` populated). Disable with
`STRIX_CVE_INTEL_NO_CACHE=1`.

The tool is **display-only**. It does NOT emit findings — Perplexity
output is LLM-generated and may include hallucinated CVE IDs. The
agent's workflow is:

1. `fingerprint_tech_stack` detects `(tech, version)`.
2. `cve_lookup` queries OSV (authoritative) for known CVEs.
3. `cve_intel_search` (this tool) queries Perplexity for FRESH intel.
4. The agent compares the two: any CVE mentioned by Perplexity but
   not OSV gets a follow-up `cve_lookup` query (in case OSV was
   stale) OR is flagged for human review.

Composes with cluster-A safety: rate-limit applies to the Perplexity
request; `--exclude-path` doesn't apply (URL is api.perplexity.ai,
not the customer's domain).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "cve_intel_search"
_DEFAULT_TIMEOUT = 60.0
_DEFAULT_CACHE_TTL_SECONDS = 12 * 3600
_PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions"
_DEFAULT_MODEL = "sonar-pro"
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_CVE_EXTRACT = 50

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CITATION_URL_RE = re.compile(r"https?://[^\s\)\]\"\']+")


_CVE_INTEL_PROMPT_TEMPLATE = (
    "I am a security researcher auditing `{tech} version {version}`. "
    "List ALL publicly-disclosed CVEs affecting this exact version, "
    "as of {today}.\n\n"
    "For each CVE, include:\n"
    "- The CVE ID (e.g. CVE-2024-XXXXX)\n"
    "- CVSS severity (low / medium / high / critical) if known\n"
    "- A one-sentence summary of the vulnerability\n"
    "- Whether a public exploit or PoC exists, and if so a citation URL\n"
    "- Whether the CVE is on the CISA KEV catalog (if known)\n"
    "- The fixed version (if announced)\n\n"
    "Prioritize CVEs disclosed in the last 90 days. Cite official "
    "sources (NVD, vendor advisories, GitHub Security Advisories). "
    "If there are no CVEs for this version, say so explicitly. "
    "Do NOT make up CVE IDs — only list ones with citations."
)


# ---------------------------------------------------------------------------
# HTTP helper (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_post(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """POST via cluster-A safety. Returns {status, headers, body, error?}."""
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                "POST", url, headers=headers, body=body, timeout=int(timeout),
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": r.get("body") or "",
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            throttle_for_rate_limit,
        )

        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=True) as c:
            content = body.encode("utf-8") if body else None
            r = c.post(url, content=content, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_BYTES],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    return Path.home() / ".strix" / "cve_intel_cache"


def _cache_key(tech: str, version: str, model: str) -> str:
    raw = f"{tech.lower()}|{version.lower()}|{model.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _cache_path(tech: str, version: str, model: str) -> Path:
    return _cache_dir() / f"{_cache_key(tech, version, model)}.json"


def _cache_read(
    tech: str, version: str, model: str, *, fresh_only: bool
) -> dict[str, Any] | None:
    if os.environ.get("STRIX_CVE_INTEL_NO_CACHE") == "1":
        return None
    path = _cache_path(tech, version, model)
    if not path.exists():
        return None
    if fresh_only:
        age = time.time() - path.stat().st_mtime
        if age > _DEFAULT_CACHE_TTL_SECONDS:
            return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError) as e:
        logger.debug("cve_intel cache read failed: %s", e)
        return None


def _cache_write(
    tech: str, version: str, model: str, payload: dict[str, Any]
) -> None:
    if os.environ.get("STRIX_CVE_INTEL_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(tech, version, model).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("cve_intel cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Perplexity API call
# ---------------------------------------------------------------------------


def _query_perplexity(
    tech: str,
    version: str,
    api_key: str,
    model: str,
    timeout: float,
) -> dict[str, Any]:
    """POST to Perplexity. Returns
    {success, content, citations, raw, error?}."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    user_prompt = _CVE_INTEL_PROMPT_TEMPLATE.format(
        tech=tech, version=version, today=today,
    )
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a security researcher's CVE-intel assistant. "
                    "Return accurate, citation-backed CVE information for "
                    "the specified software version. Never invent CVE IDs."
                ),
            },
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    response = _http_post(
        _PERPLEXITY_API_URL,
        headers=headers,
        body=json.dumps(payload),
        timeout=timeout,
    )
    if response.get("error"):
        return {"success": False, "error": f"Perplexity request failed: {response['error']}"}
    if response.get("skipped"):
        return {"success": False, "error": "Perplexity URL filtered by --exclude-path (unexpected)"}

    status = response.get("status", 0)
    if status == 401:
        return {"success": False, "error": "Perplexity returned 401 (invalid API key)"}
    if status == 429:
        return {"success": False, "error": "Perplexity returned 429 (rate-limited)"}
    if status != 200:
        return {"success": False, "error": f"Perplexity returned status {status}"}

    try:
        body = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Perplexity invalid JSON: {e}"}
    if not isinstance(body, dict):
        return {"success": False, "error": "Perplexity response is not a dict"}

    content = ""
    try:
        choices = body.get("choices") or []
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message")
                if isinstance(msg, dict):
                    raw_content = msg.get("content")
                    if isinstance(raw_content, str):
                        content = raw_content
    except Exception:  # noqa: BLE001
        logger.debug("Perplexity content extract failed", exc_info=True)

    citations: list[str] = []
    raw_citations = body.get("citations") or []
    if isinstance(raw_citations, list):
        for c in raw_citations:
            if isinstance(c, str):
                citations.append(c)
            elif isinstance(c, dict):
                url = c.get("url")
                if isinstance(url, str):
                    citations.append(url)

    return {
        "success": True,
        "content": content,
        "citations": citations,
    }


# ---------------------------------------------------------------------------
# CVE / citation extraction
# ---------------------------------------------------------------------------


def _extract_cves(content: str) -> list[str]:
    if not content:
        return []
    found = {m.group(0).upper() for m in _CVE_RE.finditer(content)}
    return sorted(found)[:_MAX_CVE_EXTRACT]


def _extract_inline_urls(content: str) -> list[str]:
    if not content:
        return []
    seen: set[str] = set()
    urls: list[str] = []
    for m in _CITATION_URL_RE.finditer(content):
        url = m.group(0).rstrip(".,);]")
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls[:50]


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    requires_web_search_mode=True,
    mitre_techniques=["T1592.002", "T1588.006"],
)
def cve_intel_search(
    tech: str,
    version: str,
    timeout: float = _DEFAULT_TIMEOUT,
    model: str = _DEFAULT_MODEL,
) -> dict[str, Any]:
    """Query Perplexity for fresh CVE intelligence on a specific
    `(tech, version)`.

    Args:
        tech: Software / framework name (e.g. `Apache`, `Log4j`,
            `OpenSSL`). Free-text — Perplexity does its own fuzzy
            matching.
        version: Exact version string (e.g. `2.4.49`, `2.14.1`).
        timeout: Per-request timeout in seconds (default 60). Sonar
            queries can take 10-30s; budget more than typical HTTP.
        model: Perplexity model to use. Default `sonar-pro` (better
            quality + citations); `sonar` is faster + cheaper.

    Returns:
        {
          success, tech, version, model, queried_at, from_cache,
          cves: [CVE-XXXX-XXXX, ...],   # extracted from content
          citations: [url, ...],         # Perplexity-supplied
          inline_urls: [url, ...],       # URLs in content body
          summary: <full LLM response text>,
          error?,
        }

    Findings:
        Display-only — does NOT emit findings. Perplexity output is
        LLM-generated and may include hallucinated CVE IDs. The agent
        feeds extracted CVEs into `cve_lookup` (#61) for authoritative
        validation before treating them as real.

    Notes:
        - Requires `PERPLEXITY_API_KEY` env var (the same key gating
          the existing `web_search` tool). Returns `success=False`
          with a clear error when not set.
        - 12-hour cache under `~/.strix/cve_intel_cache/`. Stale
          cache served on network failure (fail-open with `error`
          populated). Disable with `STRIX_CVE_INTEL_NO_CACHE=1`.
        - Composes with cluster-A safety: rate-limit applies to the
          Perplexity request.
    """
    tech = (tech or "").strip()
    version = (version or "").strip()
    model = (model or _DEFAULT_MODEL).strip()
    if not tech or not version:
        return {
            "success": False,
            "error": "tech and version are required",
        }

    cev = _start_check("cve_intel", f"{tech}@{version}")

    api_key = (os.environ.get("PERPLEXITY_API_KEY") or "").strip()
    if not api_key:
        _complete_check(cev, "inconclusive", "no PERPLEXITY_API_KEY")
        return {
            "success": False,
            "tech": tech,
            "version": version,
            "model": model,
            "error": "no PERPLEXITY_API_KEY configured (the same key as web_search)",
            "cves": [],
            "citations": [],
            "summary": "",
            "from_cache": False,
        }

    # Fresh cache.
    cached = _cache_read(tech, version, model, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        _complete_check(
            cev,
            result="not_vulnerable",
            evidence=f"{len(cached.get('cves', []))} CVE(s) for {tech}@{version} (cached)",
        )
        return cached

    # Live query.
    api_response = _query_perplexity(tech, version, api_key, model, timeout)
    if not api_response.get("success"):
        # Stale cache fallback.
        stale = _cache_read(tech, version, model, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            stale["error"] = (
                f"Perplexity request failed ({api_response.get('error')}); "
                "served stale cache"
            )
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"Perplexity failed; stale cache for {tech}@{version}",
            )
            return stale
        _complete_check(
            cev,
            result="inconclusive",
            evidence=f"Perplexity failed: {api_response.get('error')}",
        )
        return {
            "success": False,
            "tech": tech,
            "version": version,
            "model": model,
            "error": api_response.get("error"),
            "cves": [],
            "citations": [],
            "summary": "",
            "from_cache": False,
        }

    content = api_response.get("content") or ""
    citations = api_response.get("citations") or []
    cves = _extract_cves(content)
    inline_urls = _extract_inline_urls(content)

    result = {
        "success": True,
        "tech": tech,
        "version": version,
        "model": model,
        "queried_at": int(time.time()),
        "from_cache": False,
        "cves": cves,
        "citations": list(citations),
        "inline_urls": inline_urls,
        "summary": content,
    }
    _cache_write(tech, version, model, result)

    _complete_check(
        cev,
        result="not_vulnerable",
        evidence=f"{len(cves)} CVE(s) extracted for {tech}@{version}",
    )
    return result
