"""MITRE ATT&CK → Sigma detection rule mapping.

For a MITRE ATT&CK technique ID, returns Sigma rules from the
SigmaHQ corpus that detect it. Closes the loop on the #66 ATT&CK
tagging: today the agent says "this finding maps to T1190"; with
this tool it says "this finding maps to T1190; here are 12 Sigma
rules across Splunk / Elastic / Sentinel that detect attempts in
your SIEM".

Sigma rules carry MITRE ATT&CK tags like `attack.t1190` /
`attack.t1190.001` in their YAML `tags:` field, so we use GitHub
Code Search with `attack.<technique-lower>` filtered to
`SigmaHQ/sigma`.

Display-only — does NOT emit findings. The agent integrates the
rule list into existing findings via the report's `references` field
or the wrapper's display layer (the same pattern as
`exploit_refs` #62).

Auth: `STRIX_GITHUB_TOKEN` is required because GitHub's Code Search
API needs authentication. Without it the tool returns
`success=False` with a clear error so the agent knows the data
isn't available for this scan.

Cache: per-technique JSON cache under `~/.strix/sigma_cache/`,
24-hour TTL. Stale-cache served on network failure (fail-open with
`error` populated). Disable with `STRIX_SIGMA_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies; `--exclude-path`
doesn't apply (URL is api.github.com / SigmaHQ, not the customer's
domain).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "sigma_rules_for_technique"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 24 * 3600
_GH_CODE_SEARCH = "https://api.github.com/search/code"
_DEFAULT_MAX_RESULTS = 20
_HARD_CAP_RESULTS = 100  # GitHub Code Search per_page max
_MAX_RESPONSE_BYTES = 256 * 1024

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# ---------------------------------------------------------------------------
# Technique normalization
# ---------------------------------------------------------------------------


def _normalize_technique(technique: str) -> str | None:
    if not technique or not isinstance(technique, str):
        return None
    technique = technique.strip().upper()
    return technique if _TECHNIQUE_RE.match(technique) else None


def _technique_lowercase_for_query(technique: str) -> str:
    """Sigma's `tags:` field uses `attack.t1190` (lowercase)."""
    return technique.lower()


# ---------------------------------------------------------------------------
# HTTP helper (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?}."""
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, headers=headers, timeout=int(timeout))
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
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as c:
            r = c.get(url, headers=merged)
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
    return Path.home() / ".strix" / "sigma_cache"


def _cache_path(technique: str, max_results: int) -> Path:
    raw = f"{technique}|{max_results}"
    safe = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{technique}-{safe}.json"


def _cache_read(
    technique: str, max_results: int, *, fresh_only: bool
) -> dict[str, Any] | None:
    if os.environ.get("STRIX_SIGMA_NO_CACHE") == "1":
        return None
    path = _cache_path(technique, max_results)
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
        logger.debug("sigma cache read failed: %s", e)
        return None


def _cache_write(
    technique: str, max_results: int, payload: dict[str, Any]
) -> None:
    if os.environ.get("STRIX_SIGMA_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(technique, max_results).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("sigma cache write failed: %s", e)


# ---------------------------------------------------------------------------
# GitHub Code Search query
# ---------------------------------------------------------------------------


def _query_github(
    technique: str, token: str, max_results: int, timeout: float
) -> tuple[list[dict[str, Any]], str | None]:
    """Returns (rules, error). Each rule:
    {name, path, url, html_url, repo, sha}."""
    if not token:
        return [], "no STRIX_GITHUB_TOKEN — Sigma lookup requires GitHub auth"

    tag = _technique_lowercase_for_query(technique)
    # Note: GitHub Code Search per_page cap is 100; we honour the
    # caller's max_results up to that.
    per_page = min(max_results, _HARD_CAP_RESULTS)
    params = (
        f"q=attack.{tag}+repo:SigmaHQ/sigma+extension:yml"
        f"&per_page={per_page}"
    )
    url = f"{_GH_CODE_SEARCH}?{params}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    response = _http_get(url, headers=headers, timeout=timeout)
    if response.get("error"):
        return [], f"GitHub code search failed: {response['error']}"
    if response.get("skipped"):
        return [], "GitHub code search filtered by --exclude-path (unexpected)"
    if response.get("status", 0) == 401:
        return [], "GitHub code search: 401 (invalid STRIX_GITHUB_TOKEN)"
    if response.get("status", 0) == 403:
        return [], "GitHub code search: 403 (rate-limited or insufficient scope)"
    if response.get("status", 0) == 422:
        return [], "GitHub code search: 422 (invalid query)"
    if response.get("status", 0) != 200:
        return [], f"GitHub code search returned status {response.get('status')}"
    try:
        body = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return [], f"GitHub code search: invalid JSON: {e}"
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return [], None

    rules: list[dict[str, Any]] = []
    for item in items[:max_results]:
        if not isinstance(item, dict):
            continue
        repo_obj = item.get("repository") or {}
        rules.append({
            "name": item.get("name"),
            "path": item.get("path"),
            "html_url": item.get("html_url"),
            "url": item.get("url"),
            "sha": item.get("sha"),
            "repo": (
                repo_obj.get("full_name")
                if isinstance(repo_obj, dict)
                else None
            ),
        })
    return rules, None


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
    mitre_techniques=["T1593.003"],  # Search Open Websites/Domains: Code Repositories
)
def sigma_rules_for_technique(
    technique: str,
    max_results: int = _DEFAULT_MAX_RESULTS,
    timeout: float = _DEFAULT_TIMEOUT,
    github_token: str = "",
) -> dict[str, Any]:
    """Look up Sigma detection rules for a MITRE ATT&CK technique.

    Args:
        technique: ATT&CK technique ID (e.g. `T1190`, `T1190.001`).
            Case-insensitive on input; normalised to upper-case.
        max_results: Hard cap on rules returned (default 20; GitHub
            Code Search per_page max is 100).
        timeout: Per-request timeout in seconds (default 15).
        github_token: Optional override for the GitHub API token.
            Default reads from `STRIX_GITHUB_TOKEN` env. Required —
            GitHub Code Search needs auth.

    Returns:
        {
          success, technique, queried_at, from_cache,
          rules: [{name, path, html_url, url, sha, repo}, ...],
          rule_count, max_results, source_errors,
          error?,
        }

    Findings:
        Display-only — does NOT emit findings. The agent integrates
        the rule list into existing findings via the report's
        `references` field or the wrapper's display layer.

    Notes:
        - Requires `STRIX_GITHUB_TOKEN` (GitHub Code Search needs
          auth). Without it, returns `success=False` with clear
          error.
        - 24-hour cache under `~/.strix/sigma_cache/`. Stale cache
          served on network failure. Disable with
          `STRIX_SIGMA_NO_CACHE=1`.
        - Composes with cluster-A safety: rate-limit applies.
    """
    normalized = _normalize_technique(technique)
    if normalized is None:
        return {
            "success": False,
            "error": (
                f"invalid technique id: {technique!r} (expected "
                "T<digits> or T<digits>.<digits>, e.g. T1190 or "
                "T1190.001)"
            ),
        }

    if not isinstance(max_results, int) or max_results <= 0:
        max_results = _DEFAULT_MAX_RESULTS
    if max_results > _HARD_CAP_RESULTS:
        max_results = _HARD_CAP_RESULTS

    cev = _start_check("sigma_lookup", normalized)
    token = (github_token or os.environ.get("STRIX_GITHUB_TOKEN") or "").strip()

    cached = _cache_read(normalized, max_results, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        _complete_check(
            cev,
            result="not_vulnerable",
            evidence=f"{cached.get('rule_count', 0)} Sigma rule(s) for {normalized} (cached)",
        )
        return cached

    if not token:
        _complete_check(cev, "inconclusive", "no STRIX_GITHUB_TOKEN")
        return {
            "success": False,
            "technique": normalized,
            "error": (
                "no STRIX_GITHUB_TOKEN configured (GitHub Code Search "
                "requires auth — free token at github.com/settings/tokens)"
            ),
            "rules": [],
            "rule_count": 0,
            "from_cache": False,
            "max_results": max_results,
        }

    rules, err = _query_github(normalized, token, max_results, timeout)
    source_errors: dict[str, str] = {}
    if err:
        source_errors["github_code_search"] = err

    # Stale-cache fallback when the live query failed.
    if err and not rules:
        stale = _cache_read(normalized, max_results, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            stale["error"] = f"GitHub query failed ({err}); served stale cache"
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"GitHub failed; stale cache for {normalized}",
            )
            return stale
        _complete_check(cev, "inconclusive", f"GitHub failed: {err}")
        return {
            "success": False,
            "technique": normalized,
            "error": err,
            "rules": [],
            "rule_count": 0,
            "from_cache": False,
            "source_errors": source_errors,
            "max_results": max_results,
        }

    result = {
        "success": True,
        "technique": normalized,
        "queried_at": int(time.time()),
        "from_cache": False,
        "rules": rules,
        "rule_count": len(rules),
        "max_results": max_results,
        "source_errors": source_errors,
    }
    _cache_write(normalized, max_results, result)

    _complete_check(
        cev,
        result="not_vulnerable",
        evidence=f"{len(rules)} Sigma rule(s) for {normalized}",
    )
    return result
