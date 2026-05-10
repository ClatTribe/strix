"""Popular-package corpus feed (roadmap §6a / Phase 6.6 dynamic).

The Phase 6.6 typosquat detector compares installed package names
against a corpus of "popular" packages — installed names within
edit distance 2 of a popular name are flagged as squat candidates.
v1 baked the corpus into source. This feed makes it dynamic.

Sources (both daily-updated, free, no auth):

  * **npm**: https://github.com/anvaka/common-words/raw/master/data/...
    via Anvaka's npm-rank gist. We resolve to the canonical raw URL.
    Fallback: GitHub package metadata API for top-N by dependents.
  * **pypi**: https://hugovk.github.io/top-pypi-packages/
    `top-pypi-packages-30-days.min.json` — Hugo van Kemenade's
    daily-updated rollup of the public PyPI BigQuery dataset.

Both URLs serve a JSON document with ranked package names. We
take top-N (default 1000), normalise to lowercase, write to
`popular_packages` cache table with `replace_ecosystem=` so the
previous day's snapshot is fully replaced — packages that drop
off the chart don't linger.

The SCA matcher (`malicious.py::_detect_typosquat`) reads from the
cache; when the cache is empty (first-run, refresh failed), it
falls back to the small hardcoded corpus baked in v1. So the
typosquat detector keeps working even if the feed never runs.

Test-injectable via `fetch=` so unit tests don't need network.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

from strix.threat_intel import cache as ti_cache


logger = logging.getLogger(__name__)


# Top-pypi-packages publishes a 30-day rolling rank.
PYPI_TOP_URL = (
    "https://hugovk.github.io/top-pypi-packages/"
    "top-pypi-packages-30-days.min.json"
)

# Anvaka's npm-rank gist — "raw" URL serves the most-recent revision.
# This is a published JSON with `{name, downloads, ...}` per package
# entry, ranked by download count.
NPM_TOP_URL = (
    "https://anvaka.github.io/npmrank/online/npmrank.json"
)


def _http_get(url: str, *, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "strix-threat-intel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_pypi_top(raw: bytes, *, top_n: int) -> list[tuple[str, str, int | None]]:
    """top-pypi-packages format:
        {"last_update": "...", "rows": [{"project": "boto3",
                                          "download_count": 123}]}
    The `rows` are pre-ordered by download_count desc → rank = index+1.
    """
    doc = json.loads(raw)
    rows = doc.get("rows") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[tuple[str, str, int | None]] = []
    for i, r in enumerate(rows[:top_n]):
        if not isinstance(r, dict):
            continue
        name = (r.get("project") or "").strip().lower()
        if not name:
            continue
        out.append(("pypi", name, i + 1))
    return out


def _parse_npm_top(raw: bytes, *, top_n: int) -> list[tuple[str, str, int | None]]:
    """npmrank format (Anvaka's):
        {"package_name": {"name": "...", "rank": N, "downloads": M}, ...}
    OR a list of {name, rank, downloads}. Handle both shapes.
    """
    doc = json.loads(raw)
    out: list[tuple[str, str, int | None]] = []
    if isinstance(doc, dict):
        # Map shape — values are package records.
        items: list[dict] = []
        for v in doc.values():
            if isinstance(v, dict):
                items.append(v)
        # Sort by rank if present, else by downloads desc.
        def _key(d: dict) -> tuple[int, int]:
            rank = d.get("rank")
            if isinstance(rank, int):
                return (0, rank)
            dls = d.get("downloads")
            return (1, -int(dls) if isinstance(dls, int) else 0)
        items.sort(key=_key)
        for i, item in enumerate(items[:top_n]):
            name = (item.get("name") or "").strip().lower()
            if not name:
                continue
            rank = item.get("rank")
            if not isinstance(rank, int):
                rank = i + 1
            out.append(("npm", name, rank))
        return out
    if isinstance(doc, list):
        for i, item in enumerate(doc[:top_n]):
            if not isinstance(item, dict):
                continue
            name = (item.get("name") or item.get("package")
                    or "").strip().lower()
            if not name:
                continue
            rank = item.get("rank")
            if not isinstance(rank, int):
                rank = i + 1
            out.append(("npm", name, rank))
    return out


def poll_popular_packages(
    *,
    top_n: int = 1000,
    ecosystems: list[str] | None = None,
    fetch: Callable[[str], bytes] | None = None,
) -> dict[str, Any]:
    """Pull top-N popular packages for each ecosystem and write
    to the cache.

    Args:
        top_n: how many packages per ecosystem.
        ecosystems: subset to refresh. Default: ["npm", "pypi"].
        fetch: optional `(url) -> bytes` injection for tests.

    Returns:
        {"status": "ok" | "partial" | "error",
         "ingested": {"npm": N, "pypi": M}, "errors": {...}}

    "partial" means at least one ecosystem succeeded but not all
    (e.g. npm fetched fine, pypi 503'd) — the successful ones are
    still committed so the typosquat detector has SOMETHING to
    compare against.
    """
    fetch = fetch or _http_get
    eco_list = ecosystems or ["npm", "pypi"]

    sources: dict[str, str] = {
        "npm": NPM_TOP_URL,
        "pypi": PYPI_TOP_URL,
    }
    parsers: dict[str, Callable[[bytes, int], list]] = {
        "npm": lambda raw, n: _parse_npm_top(raw, top_n=n),
        "pypi": lambda raw, n: _parse_pypi_top(raw, top_n=n),
    }

    ingested: dict[str, int] = {}
    errors: dict[str, str] = {}
    any_ok = False
    any_err = False

    for eco in eco_list:
        url = sources.get(eco)
        if not url:
            errors[eco] = f"no source URL configured for ecosystem {eco}"
            any_err = True
            continue
        try:
            raw = fetch(url)
        except urllib.error.HTTPError as e:
            errors[eco] = f"HTTP {e.code}: {str(e)[:200]}"
            any_err = True
            continue
        except Exception as e:  # noqa: BLE001
            errors[eco] = f"{type(e).__name__}: {str(e)[:200]}"
            any_err = True
            continue
        try:
            records = parsers[eco](raw, top_n)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            errors[eco] = f"parse failed: {type(e).__name__}: {e}"
            any_err = True
            continue
        if not records:
            errors[eco] = "source returned zero records"
            any_err = True
            continue
        try:
            n = ti_cache.upsert_popular_packages(
                records, replace_ecosystem=eco,
            )
            ingested[eco] = n
            any_ok = True
        except Exception as e:  # noqa: BLE001
            errors[eco] = f"upsert failed: {type(e).__name__}: {e}"
            any_err = True

    if any_ok and not any_err:
        status = "ok"
    elif any_ok:
        status = "partial"
    else:
        status = "error"

    last_updated = (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if any_ok else None
    )
    ti_cache.record_feed_status(
        "popular_packages",
        status=status,
        error=("; ".join(f"{k}={v}" for k, v in errors.items())
               if errors else None),
        record_count=sum(ingested.values()),
        last_updated_at=last_updated,
    )
    return {
        "status": status,
        "ingested": ingested,
        "errors": errors,
        "top_n": top_n,
    }
