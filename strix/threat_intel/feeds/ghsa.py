"""GitHub Security Advisories (GHSA) feed.

Source: https://github.com/advisories
API:    https://api.github.com/graphql (`securityAdvisories` query)

GHSA covers per-ecosystem advisories that NVD doesn't have first-
party (npm, pip, maven, cargo, composer, rubygems, go, pub, swift,
nuget). Critical for SCA — every Snyk, Socket.dev, Dependabot uses
this feed.

Auth: optional but strongly recommended. Without a token, public
GraphQL is rate-limited to 60 req/h (~insufficient for full sync).
With a fine-grained PAT (read-only `Public repositories`) the limit
is 5,000 req/h — plenty for hourly sync.

Set `GITHUB_TOKEN` env var. Falls back to unauthenticated calls
(slower, gets less data per call) when absent.

Per-record schema mapped into our cache:

  cves(cve_id, description, cvss_score, severity, published, modified)
  cve_components(cve_id, vendor=ecosystem, product=package_name,
                 version_pattern=range_expr_or_*)
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from strix.threat_intel import cache as ti_cache


logger = logging.getLogger(__name__)


GHSA_GRAPHQL = "https://api.github.com/graphql"


_QUERY = """
query($cursor: String, $updated_since: DateTime!, $page_size: Int!) {
  securityAdvisories(
    first: $page_size,
    after: $cursor,
    updatedSince: $updated_since,
    orderBy: { field: UPDATED_AT, direction: ASC }
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      identifiers { type value }
      cvss { score }
      cwes(first: 5) { nodes { cweId } }
      vulnerabilities(first: 30) {
        nodes {
          package {
            ecosystem
            name
          }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""


def _http_post(
    url: str, *, body: bytes, headers: dict[str, str], timeout: float = 60.0,
) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _ecosystem_label(eco: str) -> str:
    """Map GHSA ecosystem → our cache vendor field."""
    m = (eco or "").upper()
    return {
        "NPM": "npm",
        "PIP": "pypi",
        "RUBYGEMS": "rubygems",
        "MAVEN": "maven",
        "COMPOSER": "composer",
        "RUST": "cargo",
        "CARGO": "cargo",
        "GO": "go",
        "NUGET": "nuget",
        "PUB": "pub",
        "SWIFT": "swift",
        "ERLANG": "erlang",
        "ACTIONS": "github-actions",
    }.get(m, m.lower())


def _normalize_range(rng: str) -> str:
    """Translate a GHSA `vulnerableVersionRange` like
    "< 4.17.21" or ">= 1.0.0, < 1.5.0" to our cache's
    version-pattern grammar.

    Our cache understands: `*`, `=X`, `<X`, `>X`, `<=X`, `>=X`,
    comma-separated for AND ranges. GHSA's format is largely
    compatible.
    """
    if not isinstance(rng, str):
        return "*"
    s = rng.strip()
    if not s:
        return "*"
    # Strip whitespace inside operators: "< 4.17.21" → "<4.17.21".
    parts = [p.strip().replace(" ", "") for p in s.split(",")]
    return ",".join(parts) if parts else "*"


def _normalize_record(node: dict[str, Any]) -> dict[str, Any] | None:
    """Translate one GHSA node into our `upsert_cves` shape."""
    ghsa_id = (node.get("ghsaId") or "").strip()
    # Prefer the CVE identifier when available; fall back to GHSA-id.
    cve_id = ghsa_id
    for ident in (node.get("identifiers") or []):
        if (ident or {}).get("type") == "CVE":
            cve_id = ident.get("value") or cve_id
            break
    if not cve_id:
        return None

    cvss = node.get("cvss") or {}
    try:
        cvss_score = float(cvss.get("score")) if cvss.get("score") is not None else None
    except (TypeError, ValueError):
        cvss_score = None

    severity = (node.get("severity") or "").lower()
    if severity == "moderate":
        severity = "medium"

    components: list[dict[str, str]] = []
    vulns = (node.get("vulnerabilities") or {}).get("nodes") or []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        pkg = v.get("package") or {}
        eco = _ecosystem_label(pkg.get("ecosystem") or "")
        name = (pkg.get("name") or "").lower().strip()
        if not name:
            continue
        components.append({
            "vendor": eco,
            "product": name,
            "version_pattern": _normalize_range(v.get("vulnerableVersionRange") or "*"),
        })

    description = (node.get("description") or node.get("summary") or "")[:8000]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity or None,
        "published": node.get("publishedAt"),
        "modified": node.get("updatedAt"),
        "components": components,
    }


def poll_ghsa(
    *,
    days_window: int = 30,
    page_size: int = 100,
    token: str | None = None,
    fetch: callable | None = None,
    max_pages: int = 50,
) -> dict[str, Any]:
    """Pull GHSA advisories updated in the last `days_window` days.

    Args:
        days_window: how far back to look. 30d default keeps weekly
            cron lightweight; 365d on first run for backfill.
        page_size: GraphQL `first:` value (max 100 per GitHub).
        token: GitHub PAT. Falls back to `GITHUB_TOKEN` env.
        fetch: optional `(url, body, headers, timeout) -> bytes` for
            tests.
        max_pages: hard cap on pagination loops.

    Returns:
        {"status": ..., "ingested": N, "pages": N, "error": ...}
    """
    fetch = fetch or _http_post
    token = token or os.environ.get("GITHUB_TOKEN")
    if not token:
        # Public unauth still works but is heavily rate-limited.
        logger.info("GHSA: no GITHUB_TOKEN set; rate-limited to 60 req/h")

    headers = {
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "strix-threat-intel/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    updated_since = (
        datetime.now(timezone.utc) - timedelta(days=days_window)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    cursor = None
    pages = 0
    total = 0
    last_modified: str | None = None

    while pages < max_pages:
        body = json.dumps({
            "query": _QUERY,
            "variables": {
                "cursor": cursor,
                "updated_since": updated_since,
                "page_size": page_size,
            },
        }).encode("utf-8")
        try:
            raw = fetch(GHSA_GRAPHQL, body=body, headers=headers, timeout=60.0)
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504):
                logger.warning("GHSA: transient %s, sleeping 5s", e.code)
                time.sleep(5)
                continue
            msg = f"GHSA HTTP {e.code}: {e.read()[:300]!r}"
            ti_cache.record_feed_status("ghsa", status="error", error=msg)
            return {"status": "error", "ingested": total, "pages": pages,
                    "error": msg}
        except Exception as e:  # noqa: BLE001
            msg = f"GHSA fetch failed: {type(e).__name__}: {e}"
            ti_cache.record_feed_status("ghsa", status="error", error=msg)
            return {"status": "error", "ingested": total, "pages": pages,
                    "error": msg}

        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            msg = f"GHSA JSON parse failed: {e}"
            ti_cache.record_feed_status("ghsa", status="error", error=msg)
            return {"status": "error", "ingested": total, "pages": pages,
                    "error": msg}

        if "errors" in doc:
            msg = f"GHSA GraphQL errors: {doc['errors'][:1]}"
            ti_cache.record_feed_status("ghsa", status="error", error=msg)
            return {"status": "error", "ingested": total, "pages": pages,
                    "error": msg}

        data = ((doc.get("data") or {}).get("securityAdvisories") or {})
        nodes = data.get("nodes") or []
        normalized = [_normalize_record(n) for n in nodes if isinstance(n, dict)]
        normalized = [n for n in normalized if n is not None]
        if normalized:
            try:
                n = ti_cache.upsert_cves(normalized, source="ghsa")
                total += n
                for r in normalized:
                    m = r.get("modified")
                    if m and (last_modified is None or m > last_modified):
                        last_modified = m
            except Exception as e:  # noqa: BLE001
                msg = f"GHSA upsert failed: {type(e).__name__}: {e}"
                ti_cache.record_feed_status("ghsa", status="error", error=msg,
                                            record_count=total)
                return {"status": "error", "ingested": total, "pages": pages,
                        "error": msg}

        pages += 1
        page_info = data.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")

    ti_cache.record_feed_status(
        "ghsa", status="ok",
        record_count=total,
        last_updated_at=last_modified,
    )
    return {
        "status": "ok",
        "ingested": total,
        "pages": pages,
        "days_window": days_window,
        "error": None,
    }
