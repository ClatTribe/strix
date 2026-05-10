"""OSSF malicious-packages feed (roadmap §6a / Phase 6.6 dynamic).

Pulls from OSV.dev's per-ecosystem bulk export. OSV aggregates
the OSSF malicious-packages namespace (`MAL-*` advisory IDs) plus
ecosystem-specific malicious feeds (npm, PyPI, RubyGems...).
Filtering to `MAL-` prefix gives us the curated "this package was
confirmed malicious" set without polluting with regular CVEs.

Source: https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip
  * `npm` → npm/all.zip
  * `PyPI` → PyPI/all.zip
  * `RubyGems` → RubyGems/all.zip

Each ZIP holds one JSON file per advisory in OSV format. We
stream-parse the ZIP, filter to `id` starting with `MAL-`, and
upsert into the `malicious_packages` cache table.

Why this matters: Phase 6.6's `_detect_typosquat` finds
suspicious-looking-name packages. This feed finds packages that
are CONFIRMED malicious — different signal class. A package that
matches a `MAL-*` advisory is a hard "do not install" finding
(severity=critical), not a heuristic.

Test-injectable via `fetch=`. The fake fetch returns a small
in-memory ZIP for unit tests; production calls hit the real
OSV bucket.
"""

from __future__ import annotations

import io
import json
import logging
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable

from strix.threat_intel import cache as ti_cache


logger = logging.getLogger(__name__)


_OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"


# OSV's ecosystem labels are slightly different from ours
# (PyPI vs pypi, RubyGems vs rubygems). Map both ways.
_OSV_ECOSYSTEM_LABELS: dict[str, str] = {
    "npm": "npm",
    "pypi": "PyPI",
    "rubygems": "RubyGems",
    "cargo": "crates.io",
    "go": "Go",
    "composer": "Packagist",
    "maven": "Maven",
    "nuget": "NuGet",
    "pub": "Pub",
    "swift": "SwiftURL",
}


def _osv_url(ecosystem: str) -> str:
    label = _OSV_ECOSYSTEM_LABELS.get(
        ecosystem.strip().lower(), ecosystem,
    )
    return f"{_OSV_BUCKET}/{label}/all.zip"


def _http_get(url: str, *, timeout: float = 120.0) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "strix-threat-intel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _normalise_osv_record(
    osv: dict[str, Any], target_ecosystem: str,
) -> list[dict[str, Any]]:
    """Convert one OSV advisory into 0+ malicious_packages rows.

    OSV records have an `affected[]` array; one advisory can
    cover multiple packages (rare for `MAL-*` but legal).
    `affected[].versions` (list) or `affected[].ranges`
    determine which versions are flagged. For malicious advisories
    we flatten ranges to "all versions" — OSSF doesn't typically
    distinguish "this version" vs "this whole package" for
    malicious; if any version was caught, the package itself is
    typically rugged.
    """
    out: list[dict[str, Any]] = []
    advisory_id = (osv.get("id") or "").strip()
    if not advisory_id:
        return out
    summary = (osv.get("summary") or osv.get("details") or "")[:2048]
    detected = (
        osv.get("modified")
        or osv.get("published")
        or None
    )
    severity_score = osv.get("database_specific", {}).get(
        "severity"
    ) if isinstance(osv.get("database_specific"), dict) else None
    severity = "critical"
    if isinstance(severity_score, str) and severity_score.lower() in {
        "low", "medium", "high", "critical",
    }:
        severity = severity_score.lower()

    affected = osv.get("affected") or []
    if not isinstance(affected, list):
        return out
    for a in affected:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        eco = (pkg.get("ecosystem") or "").strip()
        # OSV uses canonical-cased labels; we store lowercase.
        if eco.lower() != target_ecosystem.strip().lower() and \
           _OSV_ECOSYSTEM_LABELS.get(target_ecosystem.lower(), "").lower() \
           != eco.lower():
            continue
        name = (pkg.get("name") or "").strip().lower()
        if not name:
            continue
        versions: list[str] = []
        if isinstance(a.get("versions"), list):
            versions = [str(v) for v in a["versions"] if v]
        # If `ranges` is present without explicit versions, leave
        # `versions=[]` to mean "all" — see schema docstring.
        out.append({
            "ecosystem": target_ecosystem.strip().lower(),
            "name": name,
            "advisory_id": advisory_id,
            "summary": summary,
            "detected_at": detected,
            "severity": severity,
            "affected_versions": versions,
        })
    return out


def _walk_zip_for_mal_records(
    raw: bytes, ecosystem: str,
) -> list[dict[str, Any]]:
    """Open the ZIP in-memory and pull every `MAL-*` advisory's
    normalised rows. Skips entries that aren't malicious-prefix —
    the OSV bulk includes regular CVEs too."""
    out: list[dict[str, Any]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not info.filename.lower().endswith(".json"):
                continue
            base = info.filename.rsplit("/", 1)[-1]
            # OSV file naming convention: `<ID>.json`. Filter at
            # filename level to skip the JSON parse on irrelevant
            # records.
            if not base.upper().startswith("MAL-"):
                continue
            try:
                with zf.open(info) as f:
                    osv = json.loads(f.read())
            except (json.JSONDecodeError, OSError, KeyError):
                continue
            out.extend(_normalise_osv_record(osv, ecosystem))
    return out


def poll_ossf_malicious(
    *,
    ecosystems: list[str] | None = None,
    fetch: Callable[[str], bytes] | None = None,
    max_per_ecosystem: int | None = None,
) -> dict[str, Any]:
    """Pull MAL-* advisories from OSV.dev's per-ecosystem bulk
    export and write to the `malicious_packages` cache table.

    Args:
        ecosystems: subset to refresh. Default: ["npm", "pypi",
            "rubygems"] (the three with the most malicious-package
            traffic). Can be expanded via the arg.
        fetch: `(url) -> bytes` injection for tests. Tests build a
            small in-memory ZIP containing 1–2 fake `MAL-*.json`
            entries.
        max_per_ecosystem: cap rows ingested per ecosystem.
            Defensive: the npm bulk has thousands of MAL- entries
            and we don't want a runaway cron.

    Returns:
        {"status": ..., "ingested": {eco: N}, "errors": {eco: msg}}.
        "partial" when at least one ecosystem succeeded.
    """
    fetch = fetch or _http_get
    eco_list = ecosystems or ["npm", "pypi", "rubygems"]

    ingested: dict[str, int] = {}
    errors: dict[str, str] = {}
    any_ok = False
    any_err = False

    for eco in eco_list:
        url = _osv_url(eco)
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
            records = _walk_zip_for_mal_records(raw, eco)
        except (zipfile.BadZipFile, OSError) as e:
            errors[eco] = f"zip parse failed: {e}"
            any_err = True
            continue
        if max_per_ecosystem is not None:
            records = records[:max_per_ecosystem]
        if not records:
            # Not an error — empty result is valid (e.g. ecosystem
            # has no MAL- entries yet). Still record a 0-count
            # success.
            try:
                n = ti_cache.upsert_malicious_packages([])
                ingested[eco] = n
                any_ok = True
            except Exception as e:  # noqa: BLE001
                errors[eco] = f"upsert: {e}"
                any_err = True
            continue
        try:
            n = ti_cache.upsert_malicious_packages(records)
            ingested[eco] = n
            any_ok = True
        except Exception as e:  # noqa: BLE001
            errors[eco] = f"upsert failed: {e}"
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
        "ossf_malicious",
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
    }
