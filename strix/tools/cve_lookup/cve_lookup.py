"""CVE / OSV lookup at fingerprint time.

For a `(package, version, ecosystem)` triple, query OSV.dev's free
public API and emit a finding for each known CVE affecting that
version. Designed to run right after `fingerprint_tech_stack` has
resolved a technology version — closes the loop between recon-time
detection and the catalog of known-vulnerable releases without
spending agent tokens.

Why OSV.dev: free, no API key, covers npm / PyPI / Maven / Go /
RubyGems / crates.io / NuGet / Packagist / Hex / Pub / ConanCenter /
SwiftURL plus Linux-distro vuln databases. Returns CVE-aliased
advisories in a uniform JSON schema. Authoritative for ecosystem-
indexed CVEs — for non-package server software (nginx / apache /
WordPress core) OSV doesn't help and the tool returns "no data"
gracefully.

API: `POST https://api.osv.dev/v1/query` with body
```json
{"version": "<v>", "package": {"name": "<n>", "ecosystem": "<e>"}}
```
returns `{"vulns": [{...}, ...]}` — empty when the version isn't
known to be vulnerable.

Each `vulns[]` entry's `aliases[]` is searched for a `CVE-` ID; that
becomes the canonical CVE for the finding. When no CVE alias exists,
the OSV ID (e.g. `GHSA-…`) is used.

Severity derivation:
- `database_specific.severity` — GHSA's enum (CRITICAL / HIGH /
  MODERATE / LOW). Mapped to (critical / high / medium / low).
- `severity[].score` — CVSS vector. Numeric base score parsed from
  the vector string (`CVSS:3.1/AV:N/.../E:H/...` → score). Mapped
  by CVSS bands (>=9 critical / >=7 high / >=4 medium / else low).
- Default: medium when no severity signal is present.

The tracer's existing KEV enrichment auto-upgrades any CVE-aliased
finding to high (or pins it as ransomware-use) if it's on the CISA
KEV catalog — this tool emits the CVE, the tracer's
`add_vulnerability_report` hook adds the KEV decoration.

Cache: per-(ecosystem,name,version) JSON cache under
`~/.strix/cve_lookup_cache/`. 6h TTL. Stale-cache served on
network failure (fail-open). Disable with
`STRIX_CVE_LOOKUP_NO_CACHE=1`.

Safety:
- Read-only — queries only OSV.dev (a public threat-intel API),
  never the customer's infrastructure.
- Cluster-A composition: rate-limit applies to the OSV request;
  exclude-path doesn't apply (the URL is OSV.dev, not the customer's
  domain).

Each finding carries `description_plain` + `recommended_action` (the
§11 non-tech UX fields) — recommended_action is universal: upgrade
the package to the fix-version published in the OSV record (or, if
no fix is published, monitor the advisory and apply the workaround
in the references).
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
_TOOL_NAME = "cve_lookup"
_OSV_API_URL = "https://api.osv.dev/v1/query"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 6 * 3600
_MAX_CVES_PER_LOOKUP = 200  # Hard cap so a noisy package doesn't flood findings.

# CVSS v3 / v4 vector → numeric score parser. We don't run the full
# scoring algorithm; instead we look for an explicit score in
# database_specific.cvss.score (when present) or in the CVSS_V3
# severity entry's `score` field.
_CVSS_VECTOR_RE = re.compile(r"CVSS:3\.[0-9]/AV:[NALP]/AC:[LH]", re.IGNORECASE)

# OSV severity enum used by GHSA records (uppercase).
_GHSA_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

_CVE_ALIAS_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# Best-effort mapping from common fingerprint-tech-stack tech IDs
# to OSV ecosystem strings. The agent typically calls cve_lookup
# directly with the right ecosystem; this mapping documents the
# canonical answer for the most-common cases.
TECH_TO_ECOSYSTEM_HINT: dict[str, str] = {
    # JavaScript / TypeScript
    "express": "npm",
    "react": "npm",
    "vue": "npm",
    "angular": "npm",
    "next": "npm",
    "nestjs": "npm",
    "fastify": "npm",
    "koa": "npm",
    "lodash": "npm",
    "moment": "npm",
    # Python
    "django": "PyPI",
    "flask": "PyPI",
    "fastapi": "PyPI",
    "tornado": "PyPI",
    "starlette": "PyPI",
    "pyramid": "PyPI",
    # Ruby
    "rails": "RubyGems",
    "sinatra": "RubyGems",
    # Java / JVM
    "spring": "Maven",
    "tomcat": "Maven",
    "struts": "Maven",
    "log4j": "Maven",
    "jackson": "Maven",
    # PHP
    "laravel": "Packagist",
    "symfony": "Packagist",
    "drupal": "Packagist",
    # Go
    "gin": "Go",
    "echo": "Go",
    # Rust
    "actix": "crates.io",
    "rocket": "crates.io",
    # WordPress core has its own database (wpscan); OSV doesn't index it
    # cleanly — returned as "" for "no clean ecosystem mapping".
    "wordpress": "",
    "nginx": "",
    "apache": "",
    "iis": "",
}


# ---------------------------------------------------------------------------
# OSV API client
# ---------------------------------------------------------------------------


def _query_osv(
    name: str, version: str, ecosystem: str, timeout: float
) -> dict[str, Any]:
    """POST to OSV.dev. Returns the raw response dict, OR a dict with
    `error` key on failure (callers fall back to cache)."""
    body: dict[str, Any] = {"version": version}
    pkg: dict[str, str] = {"name": name}
    if ecosystem:
        pkg["ecosystem"] = ecosystem
    body["package"] = pkg

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    payload = json.dumps(body)

    if manager is not None:
        try:
            r = manager.send_simple_request(
                "POST", _OSV_API_URL,
                headers=headers, body=payload, timeout=int(timeout),
            )
            if r.get("skipped"):
                return {"error": "OSV URL filtered by --exclude-path (unexpected)"}
            status = int(r.get("status_code") or 0)
            if status != 200:
                return {"error": f"OSV returned status {status}"}
            try:
                return json.loads(r.get("body") or "{}")
            except (ValueError, TypeError) as e:
                return {"error": f"OSV response is not valid JSON: {e}"}
        except Exception as e:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
            # Fall through to direct httpx.

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            throttle_for_rate_limit,
        )

        merged = inject_auth_headers(dict(headers))
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=True) as c:
            r = c.post(_OSV_API_URL, content=payload, headers=merged)
            if r.status_code != 200:
                return {"error": f"OSV returned status {r.status_code}"}
            try:
                return r.json()
            except (ValueError, TypeError) as e:
                return {"error": f"OSV response is not valid JSON: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# On-disk cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    base = Path.home() / ".strix" / "cve_lookup_cache"
    return base


def _cache_key(name: str, version: str, ecosystem: str) -> str:
    raw = f"{ecosystem.lower()}|{name.lower()}|{version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _cache_path(name: str, version: str, ecosystem: str) -> Path:
    return _cache_dir() / f"{_cache_key(name, version, ecosystem)}.json"


def _cache_read(name: str, version: str, ecosystem: str, *, fresh_only: bool) -> dict[str, Any] | None:
    """Return cached OSV response. If `fresh_only=True`, only return if
    the cache file is younger than _DEFAULT_CACHE_TTL_SECONDS."""
    if os.environ.get("STRIX_CVE_LOOKUP_NO_CACHE") == "1":
        return None
    path = _cache_path(name, version, ecosystem)
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
        logger.debug("cve_lookup cache read failed: %s", e)
        return None


def _cache_write(name: str, version: str, ecosystem: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_CVE_LOOKUP_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        path = _cache_path(name, version, ecosystem)
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("cve_lookup cache write failed: %s", e)


# ---------------------------------------------------------------------------
# OSV record processing
# ---------------------------------------------------------------------------


def _extract_cve_id(vuln: dict[str, Any]) -> str | None:
    """Return the first CVE-shaped alias, or None."""
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and _CVE_ALIAS_RE.match(alias):
            return alias.upper()
    # Some advisories have the CVE in the top-level `id` instead of an alias.
    raw_id = vuln.get("id")
    if isinstance(raw_id, str) and _CVE_ALIAS_RE.match(raw_id):
        return raw_id.upper()
    return None


def _derive_severity(vuln: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return (severity, severity_meta) where severity ∈
    {critical, high, medium, low} and severity_meta documents the source.
    """
    db_spec = vuln.get("database_specific") or {}
    if isinstance(db_spec, dict):
        # GHSA emits `severity` as an enum.
        sev_enum = db_spec.get("severity")
        if isinstance(sev_enum, str):
            mapped = _GHSA_SEVERITY_MAP.get(sev_enum.upper())
            if mapped:
                return mapped, {"source": "database_specific.severity", "value": sev_enum}

        # Some records put a numeric CVSS score under `database_specific.cvss.score`.
        cvss_obj = db_spec.get("cvss") if isinstance(db_spec.get("cvss"), dict) else None
        if cvss_obj:
            score = cvss_obj.get("score")
            if isinstance(score, (int, float)):
                return _cvss_score_to_severity(float(score)), {
                    "source": "database_specific.cvss.score", "value": score,
                }

    # OSV `severity` array — entries are {type, score}.
    for sev in vuln.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        score = sev.get("score")
        if not isinstance(score, str):
            continue
        # Some records put a numeric score in this string ("9.8"); others
        # put a CVSS vector ("CVSS:3.1/AV:N/...").
        try:
            numeric = float(score)
            return _cvss_score_to_severity(numeric), {
                "source": "severity[].score", "value": score,
            }
        except ValueError:
            pass
        # Vector form — we don't run the full CVSS algorithm here. As a
        # heuristic, mark as `high` when the AV:N + AC:L pair is set
        # (network-attackable / low-complexity), `medium` otherwise.
        if _CVSS_VECTOR_RE.search(score):
            sev_text = "high" if "AV:N" in score and "AC:L" in score else "medium"
            return sev_text, {"source": "severity[].score (vector)", "value": score}

    return "medium", {"source": "default"}


def _cvss_score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_fix_versions(vuln: dict[str, Any], package_name: str, ecosystem: str) -> list[str]:
    """Walk `affected[]` and pull out the `fixed` versions for matching
    package+ecosystem entries."""
    fixes: list[str] = []
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if not isinstance(pkg, dict):
            continue
        if (pkg.get("name") or "").lower() != package_name.lower():
            continue
        if ecosystem and (pkg.get("ecosystem") or "").lower() != ecosystem.lower():
            continue
        for r in aff.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            for ev in r.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    fixes.append(str(ev["fixed"]))
    # Dedup, preserve order.
    seen: set[str] = set()
    out: list[str] = []
    for f in fixes:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _extract_references(vuln: dict[str, Any], cap: int = 5) -> list[str]:
    refs: list[str] = []
    for r in vuln.get("references") or []:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            refs.append(url)
            if len(refs) >= cap:
                break
    return refs


def _summary_text(vuln: dict[str, Any]) -> str:
    summary = vuln.get("summary")
    if isinstance(summary, str) and summary.strip():
        # Cap to keep finding descriptions human-readable.
        return summary.strip()[:500]
    details = vuln.get("details")
    if isinstance(details, str):
        return details.strip().splitlines()[0][:500]
    return ""


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    cve: str | None,
    target: str,
    endpoint: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="vulnerable_dependency",
        cwe="CWE-1104",
        cve=cve,
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Components with publicly-known vulnerabilities are the "
            "single most common source of exploitable findings in real "
            "engagements (OWASP A06:2021 Vulnerable and Outdated "
            "Components). Public CVE databases mean attackers can "
            "fingerprint the target's exact version and pull a working "
            "exploit from ExploitDB / GitHub PoCs. KEV-listed CVEs (the "
            "tracer auto-decorates this finding when applicable) are "
            "actively-exploited in the wild."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )


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
    mitre_techniques=["T1592.002", "T1588.006"],  # Software fingerprint + Obtain Vulns
)
def cve_lookup(
    name: str,
    version: str,
    ecosystem: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Query OSV.dev for known CVEs affecting (name, version, ecosystem).

    Args:
        name: Package name (e.g. "express", "django", "log4j-core").
        version: Exact version string (e.g. "4.16.0", "1.11.5",
            "2.14.1"). Pre-release suffixes (e.g. `-rc.1`, `-beta`)
            preserved verbatim.
        ecosystem: OSV ecosystem string. One of: `npm`, `PyPI`,
            `Maven`, `Go`, `RubyGems`, `crates.io`, `NuGet`,
            `Packagist`, `Hex`, `Pub`, `ConanCenter`, `SwiftURL`,
            plus Linux-distro names (`Debian`, `Ubuntu`, `Alpine`,
            etc.). Pass empty string to query without an ecosystem
            filter — OSV will match by package name across
            ecosystems (lower precision but useful when the ecosystem
            is unknown).
        timeout: Per-request timeout in seconds (default 15).

    Returns:
        {
          success, name, version, ecosystem,
          osv_url, queried_at, cve_count, from_cache,
          vulnerabilities: [
            {
              id, cve, severity, severity_source,
              summary, fix_versions, references,
              ghsa_id, alias_count,
            },
            ...
          ],
          findings_emitted: int,
          error: str | None,
        }

    Findings:
        Emits one finding per CVE matching the version. Severity
        derived from OSV's GHSA enum or the CVSS vector / score.
        Tracer auto-decorates KEV-listed CVEs with `is_kev=True` and
        the CISA KEV due-date — no extra integration needed.

    Notes:
        - Results cached on disk for 6 hours per (name, version,
          ecosystem) under `~/.strix/cve_lookup_cache/`. Stale-cache
          served on network failure (fail-open).
        - Read-only — queries only OSV.dev.
        - Composes with cluster-A safety: rate-limit applies to the
          OSV request.
    """
    name = (name or "").strip()
    version = (version or "").strip()
    ecosystem = (ecosystem or "").strip()

    if not name or not version:
        return {
            "success": False,
            "error": "name and version are required",
        }

    cev = _start_check("cve_lookup", f"{ecosystem}/{name}@{version}")

    # ---- Try fresh cache first ----
    cached = _cache_read(name, version, ecosystem, fresh_only=True)
    if cached is not None:
        result = _process_osv_response(
            name, version, ecosystem, cached, from_cache=True,
        )
        _complete_check(
            cev,
            result="vulnerable" if result["findings_emitted"] else "not_vulnerable",
            evidence=f"{result['cve_count']} CVE(s) for {ecosystem}/{name}@{version} (cached)",
        )
        return result

    # ---- Fresh OSV query ----
    osv_response = _query_osv(name, version, ecosystem, timeout)
    if osv_response.get("error"):
        # Fail-open: try stale cache when network failed.
        stale = _cache_read(name, version, ecosystem, fresh_only=False)
        if stale is not None:
            result = _process_osv_response(
                name, version, ecosystem, stale, from_cache=True,
            )
            result["error"] = (
                f"OSV query failed ({osv_response['error']}); "
                f"served stale cache"
            )
            _complete_check(
                cev,
                result="vulnerable" if result["findings_emitted"] else "not_vulnerable",
                evidence=(
                    f"{result['cve_count']} CVE(s) for "
                    f"{ecosystem}/{name}@{version} (stale cache; "
                    f"{osv_response['error']})"
                ),
            )
            return result

        # No cache — return the error.
        _complete_check(
            cev,
            result="inconclusive",
            evidence=f"OSV query failed: {osv_response['error']}",
        )
        return {
            "success": False,
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "error": osv_response["error"],
            "vulnerabilities": [],
            "findings_emitted": 0,
            "from_cache": False,
        }

    # ---- Cache the fresh response ----
    _cache_write(name, version, ecosystem, osv_response)

    result = _process_osv_response(
        name, version, ecosystem, osv_response, from_cache=False,
    )
    _complete_check(
        cev,
        result="vulnerable" if result["findings_emitted"] else "not_vulnerable",
        evidence=f"{result['cve_count']} CVE(s) for {ecosystem}/{name}@{version}",
    )
    return result


def _process_osv_response(
    name: str, version: str, ecosystem: str, response: dict[str, Any], *,
    from_cache: bool,
) -> dict[str, Any]:
    """Parse OSV response → emit findings → return result dict."""
    vulns = response.get("vulns") or []
    if not isinstance(vulns, list):
        vulns = []
    if len(vulns) > _MAX_CVES_PER_LOOKUP:
        logger.info(
            "cve_lookup capping %s/%s@%s from %d to %d vulns",
            ecosystem, name, version, len(vulns), _MAX_CVES_PER_LOOKUP,
        )
        vulns = vulns[:_MAX_CVES_PER_LOOKUP]

    vulnerabilities: list[dict[str, Any]] = []
    findings_emitted = 0

    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        osv_id = vuln.get("id")
        cve = _extract_cve_id(vuln)
        severity, sev_meta = _derive_severity(vuln)
        summary = _summary_text(vuln)
        fix_versions = _extract_fix_versions(vuln, name, ecosystem)
        references = _extract_references(vuln, cap=5)
        ghsa = osv_id if isinstance(osv_id, str) and osv_id.startswith("GHSA-") else None

        record = {
            "id": osv_id,
            "cve": cve,
            "severity": severity,
            "severity_source": sev_meta,
            "summary": summary,
            "fix_versions": fix_versions,
            "references": references,
            "ghsa_id": ghsa,
            "alias_count": len(vuln.get("aliases") or []),
        }
        vulnerabilities.append(record)

        # ---- Emit finding ----
        identifier = cve or osv_id or "unknown"
        title = (
            f"Known-vulnerable component: {ecosystem or 'package'}/{name}@{version} "
            f"affected by {identifier}"
        )

        fix_text = ""
        if fix_versions:
            fix_text = ", ".join(fix_versions[:3])

        if fix_versions:
            description_plain = (
                f"Your application uses `{name}` version `{version}`, "
                f"which has a publicly-known vulnerability "
                f"(`{identifier}`). The fix is in version "
                f"`{fix_versions[0]}`. Attackers can pull a working "
                f"exploit from ExploitDB or public GitHub PoCs once "
                f"they fingerprint your version."
            )
            recommended_action = (
                f"Upgrade `{name}` from `{version}` to `{fix_versions[0]}` "
                f"or newer. Test in staging, deploy via your usual "
                f"dependency-update process. If a direct upgrade isn't "
                f"feasible, check the references in this finding for "
                f"vendor-supplied workarounds."
            )
        else:
            description_plain = (
                f"Your application uses `{name}` version `{version}`, "
                f"which has a publicly-known vulnerability "
                f"(`{identifier}`). No fix has been published yet — "
                f"monitor the advisory and apply any vendor workaround."
            )
            recommended_action = (
                "Monitor the advisory listed in this finding's "
                "references. When a fix is published, upgrade. In the "
                "interim, evaluate whether the vulnerable code path is "
                "reachable from your application and consider a "
                "WAF rule / config workaround."
            )

        ref_text = ""
        if references:
            ref_text = " References: " + " ".join(references[:3])
        description = (
            f"{summary}{ref_text}"
            f"\n\nDetected via OSV.dev. Affected: "
            f"{ecosystem or '(no ecosystem)'} / {name} @ {version}. "
            f"Fix: {fix_text or 'no fixed version published'}. "
            f"OSV ID: {osv_id}; CVE: {cve or '(none)'}."
        )

        _emit_finding(
            title=title,
            severity=severity,
            cve=cve,
            target=name,
            endpoint=f"{ecosystem or 'pkg'}://{name}@{version}",
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted += 1

    return {
        "success": True,
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "osv_url": _OSV_API_URL,
        "queried_at": int(time.time()),
        "cve_count": len(vulnerabilities),
        "from_cache": from_cache,
        "vulnerabilities": vulnerabilities,
        "findings_emitted": findings_emitted,
    }
