"""NIST NVD CVSS / CWE / CPE depth.

For a CVE ID, queries NIST's NVD v2 REST API for the authoritative
CVSS scoring + CWE assignments + CPE matching. Augments `cve_lookup`
(#61, OSV-backed) which often returns GHSA-derived heuristic CVSS
scores; NVD is the canonical source for CVE data.

Why this complements `cve_lookup`:

- OSV's `severity` data is heuristic (GHSA enum + CVSS-vector
  parsing). NVD's `cvssMetricV31` / `cvssMetricV30` / `cvssMetricV2`
  carry the **CNA-assigned canonical scores**.
- NVD's `weaknesses[]` carries the canonical CWE assignment(s) —
  useful when OSV's record doesn't have a CWE or has a less-specific
  one.
- NVD's `configurations[].nodes[].cpeMatch[]` carries the affected
  CPE-23 ranges (vendor:product:version), useful for CPE-shaped
  matching against detected tech stacks.

API: `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>`.
Free, no key required (rate-limited to 5 requests/30s anonymously);
`STRIX_NVD_KEY` raises the limit to 50 requests/30s.

Severity tuning:

NVD's `cvssMetricVXX` returns numeric `baseScore` (0-10) and
`baseSeverity` (CRITICAL / HIGH / MEDIUM / LOW). We use the
preferred-version order (v3.1 → v3.0 → v2.0) and emit findings:

- **Critical** — CVSS baseSeverity = CRITICAL OR baseScore ≥ 9.0
- **High** — baseScore 7.0-8.9
- **Medium** — baseScore 4.0-6.9
- **Low** — baseScore 0.1-3.9
- *(no finding)* — score == 0 OR no CVSS data

The tracer's KEV enrichment auto-decorates findings carrying a
`cve` (which we do).

Cache: per-CVE JSON cache under `~/.strix/nvd_cache/`, 24-hour TTL.
Stale cache served on network failure (fail-open with `error`
populated). Disable with `STRIX_NVD_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies; `--exclude-path`
doesn't apply (URL is services.nvd.nist.gov, not the customer's
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
_TOOL_NAME = "nvd_lookup"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 24 * 3600
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_CPE_RANGES = 30
_MAX_REFERENCES = 10

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# CVE normalization
# ---------------------------------------------------------------------------


def _normalize_cve(cve: str) -> str | None:
    if not cve or not isinstance(cve, str):
        return None
    cve = cve.strip().upper()
    return cve if _CVE_RE.match(cve) else None


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
    return Path.home() / ".strix" / "nvd_cache"


def _cache_path(cve: str) -> Path:
    safe = hashlib.sha256(cve.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{cve}-{safe}.json"


def _cache_read(cve: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_NVD_NO_CACHE") == "1":
        return None
    path = _cache_path(cve)
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
        logger.debug("nvd cache read failed: %s", e)
        return None


def _cache_write(cve: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_NVD_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(cve).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("nvd cache write failed: %s", e)


# ---------------------------------------------------------------------------
# NVD parsing
# ---------------------------------------------------------------------------


def _extract_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    """Walk `metrics.cvssMetricV31 / V30 / V2` in preference order
    and return {version, base_score, base_severity, vector_string,
    source}."""
    if not isinstance(metrics, dict):
        return {}
    for version_key, version_label in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(version_key)
        if not isinstance(entries, list) or not entries:
            continue
        # Prefer "Primary" type if present.
        primary = next(
            (e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"),
            None,
        )
        chosen = primary or (entries[0] if isinstance(entries[0], dict) else None)
        if not isinstance(chosen, dict):
            continue
        cvss_data = chosen.get("cvssData")
        if not isinstance(cvss_data, dict):
            continue
        try:
            base_score = float(cvss_data.get("baseScore") or 0.0)
        except (TypeError, ValueError):
            base_score = 0.0
        return {
            "version": cvss_data.get("version") or version_label,
            "base_score": base_score,
            "base_severity": (
                (cvss_data.get("baseSeverity") or chosen.get("baseSeverity") or "")
                .upper()
            ),
            "vector_string": cvss_data.get("vectorString"),
            "source": chosen.get("source"),
            "type": chosen.get("type"),
            "exploitability_score": chosen.get("exploitabilityScore"),
            "impact_score": chosen.get("impactScore"),
        }
    return {}


def _extract_cwes(weaknesses: Any) -> list[str]:
    if not isinstance(weaknesses, list):
        return []
    out: set[str] = set()
    for entry in weaknesses:
        if not isinstance(entry, dict):
            continue
        for desc in entry.get("description") or []:
            if isinstance(desc, dict):
                value = desc.get("value")
                if isinstance(value, str) and value.upper().startswith("CWE-"):
                    out.add(value.upper())
                elif isinstance(value, str) and value.upper() == "NVD-CWE-OTHER":
                    out.add("NVD-CWE-OTHER")
                elif isinstance(value, str) and value.upper() == "NVD-CWE-NOINFO":
                    out.add("NVD-CWE-NOINFO")
    return sorted(out)


def _extract_cpe_matches(configurations: Any) -> list[dict[str, Any]]:
    """Walk configurations.nodes[].cpeMatch[] and return CPE-23 strings
    + version-range fields."""
    out: list[dict[str, Any]] = []
    if not isinstance(configurations, list):
        return out
    seen: set[str] = set()
    for cfg in configurations:
        if not isinstance(cfg, dict):
            continue
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                criteria = match.get("criteria")
                if not isinstance(criteria, str) or criteria in seen:
                    continue
                seen.add(criteria)
                out.append({
                    "criteria": criteria,
                    "vulnerable": bool(match.get("vulnerable", True)),
                    "versionStartIncluding": match.get("versionStartIncluding"),
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding": match.get("versionEndIncluding"),
                    "versionEndExcluding": match.get("versionEndExcluding"),
                })
                if len(out) >= _MAX_CPE_RANGES:
                    return out
    return out


def _extract_description(descriptions: Any) -> str:
    """Pick the English description if present."""
    if not isinstance(descriptions, list):
        return ""
    en = next(
        (d.get("value") for d in descriptions
         if isinstance(d, dict) and d.get("lang") == "en"
         and isinstance(d.get("value"), str)),
        None,
    )
    if isinstance(en, str):
        return en[:1000]
    # Fallback to first description.
    for d in descriptions:
        if isinstance(d, dict) and isinstance(d.get("value"), str):
            return d["value"][:1000]
    return ""


def _extract_references(references: Any) -> list[dict[str, Any]]:
    if not isinstance(references, list):
        return []
    out: list[dict[str, Any]] = []
    for r in references:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        if not isinstance(url, str):
            continue
        out.append({
            "url": url,
            "source": r.get("source"),
            "tags": list(r.get("tags") or []) if isinstance(r.get("tags"), list) else [],
        })
        if len(out) >= _MAX_REFERENCES:
            break
    return out


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def _cvss_to_severity(base_score: float, base_severity: str | None = None) -> str | None:
    """Map CVSS base score → severity tier. Falls back to NVD's
    `baseSeverity` enum when the numeric score is missing."""
    if base_severity:
        upper = base_severity.upper()
        if upper == "CRITICAL":
            return "critical"
        if upper == "HIGH":
            return "high"
        if upper == "MEDIUM":
            return "medium"
        if upper == "LOW":
            return "low"
    if base_score >= 9.0:
        return "critical"
    if base_score >= 7.0:
        return "high"
    if base_score >= 4.0:
        return "medium"
    if base_score > 0.0:
        return "low"
    return None


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    cve: str,
    cwe: str | None,
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
        cwe=cwe or "CWE-1104",
        cve=cve,
        target=cve,
        endpoint=f"cve://{cve}",
        description=description,
        impact=(
            "NIST NVD's authoritative CVSS / CWE / CPE data is the "
            "canonical reference for CVE severity. NVD's CVSS scores "
            "are CNA-assigned and reviewed; OSV's GHSA-derived "
            "scores are heuristic. When a finding's NVD score "
            "differs materially from its OSV score, the NVD value "
            "should win for prioritisation."
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
    provenance="trusted_source",  # NVD (nist.gov) — canonical CVE registry
)
def nvd_lookup(
    cve: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Look up a CVE in NIST NVD for authoritative CVSS / CWE / CPE
    data.

    Args:
        cve: CVE ID (e.g. `CVE-2021-44228`). Case-insensitive on
            input; normalised to upper-case.
        timeout: Per-request timeout in seconds (default 15).

    Returns:
        {
          success, cve, queried_at, from_cache,
          published, last_modified, status, source_identifier,
          description,
          cvss: {version, base_score, base_severity, vector_string,
                 source, type, exploitability_score, impact_score},
          cwes: [CWE-XXX, ...],
          cpe_matches: [{criteria, vulnerable, versionStartIncluding,
                         versionEndExcluding, ...}, ...],
          references: [{url, source, tags}, ...],
          severity: critical|high|medium|low|None,
          findings_emitted, error?,
          no_data?,
        }

    Findings:
        Single finding tagged `category=vulnerable_dependency`,
        `cwe=<NVD CWE>` (defaults to CWE-1104 when NVD has no CWE),
        with the CVE attached so the tracer's KEV enrichment
        auto-decorates. `verification_status=verified` since NVD is
        the authoritative source.

    Notes:
        - Free, no key required. `STRIX_NVD_KEY` raises rate limit
          to 50 requests/30s (anonymous: 5 requests/30s).
        - 24-hour cache under `~/.strix/nvd_cache/`. Stale cache
          served on network failure. Disable with
          `STRIX_NVD_NO_CACHE=1`.
        - NVD 404 / "no vulnerabilities" response treated as success
          with `no_data=True`, NOT failure.
        - Pairs naturally with `cve_lookup` (#61): when OSV-OSV
          severity disagrees with NVD-NVD, NVD wins for
          prioritisation.
    """
    normalized = _normalize_cve(cve)
    if normalized is None:
        return {
            "success": False,
            "error": f"invalid CVE id: {cve!r} (expected CVE-YYYY-NNNN)",
        }

    cev = _start_check("nvd_lookup", normalized)

    cached = _cache_read(normalized, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        emitted = _maybe_emit(cached)
        cached["findings_emitted"] = emitted
        _complete_check(
            cev,
            result="vulnerable" if emitted else "not_vulnerable",
            evidence=f"NVD cached for {normalized}; findings={emitted}",
        )
        return cached

    api_key = (os.environ.get("STRIX_NVD_KEY") or "").strip()
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    url = f"{_NVD_API}?cveId={normalized}"
    response = _http_get(url, headers=headers, timeout=timeout)

    if (
        response.get("error")
        or response.get("status", 0) >= 400
        or response.get("skipped")
    ):
        # Fail-open via stale cache.
        stale = _cache_read(normalized, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            err_text = (
                response.get("error")
                or (
                    "filtered by --exclude-path"
                    if response.get("skipped")
                    else f"HTTP {response.get('status')}"
                )
            )
            stale["error"] = f"NVD request failed ({err_text}); served stale cache"
            emitted = _maybe_emit(stale)
            stale["findings_emitted"] = emitted
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"NVD failed; stale cache for {normalized}",
            )
            return stale
        err_text = (
            response.get("error")
            or (
                "filtered by --exclude-path"
                if response.get("skipped")
                else f"HTTP {response.get('status')}"
            )
        )
        _complete_check(cev, "inconclusive", f"NVD failed: {err_text}")
        return {
            "success": False,
            "cve": normalized,
            "error": err_text,
            "findings_emitted": 0,
            "from_cache": False,
        }

    try:
        body = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        _complete_check(cev, "inconclusive", f"NVD invalid JSON: {e}")
        return {
            "success": False,
            "cve": normalized,
            "error": f"NVD invalid JSON: {e}",
            "findings_emitted": 0,
            "from_cache": False,
        }

    vulns = body.get("vulnerabilities") if isinstance(body, dict) else None
    if not isinstance(vulns, list) or not vulns:
        # NVD returns an empty `vulnerabilities` list when the CVE
        # isn't in their index. Treat as "no data" success.
        result = {
            "success": True,
            "cve": normalized,
            "queried_at": int(time.time()),
            "from_cache": False,
            "no_data": True,
            "description": "",
            "cvss": {},
            "cwes": [],
            "cpe_matches": [],
            "references": [],
            "severity": None,
            "findings_emitted": 0,
        }
        _cache_write(normalized, result)
        _complete_check(cev, "not_vulnerable", f"NVD no data for {normalized}")
        return result

    first_vuln = vulns[0] if isinstance(vulns[0], dict) else {}
    cve_obj = first_vuln.get("cve") if isinstance(first_vuln.get("cve"), dict) else {}

    description = _extract_description(cve_obj.get("descriptions"))
    cvss = _extract_cvss(cve_obj.get("metrics") or {})
    cwes = _extract_cwes(cve_obj.get("weaknesses"))
    cpe_matches = _extract_cpe_matches(cve_obj.get("configurations"))
    references = _extract_references(cve_obj.get("references"))

    base_score = float(cvss.get("base_score") or 0.0)
    severity = _cvss_to_severity(base_score, cvss.get("base_severity"))

    result = {
        "success": True,
        "cve": normalized,
        "queried_at": int(time.time()),
        "from_cache": False,
        "published": cve_obj.get("published"),
        "last_modified": cve_obj.get("lastModified"),
        "status": cve_obj.get("vulnStatus"),
        "source_identifier": cve_obj.get("sourceIdentifier"),
        "description": description,
        "cvss": cvss,
        "cwes": cwes,
        "cpe_matches": cpe_matches,
        "references": references,
        "severity": severity,
        "findings_emitted": 0,
    }
    findings_emitted = _maybe_emit(result)
    result["findings_emitted"] = findings_emitted

    _cache_write(normalized, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=(
            f"NVD: {normalized} → severity={severity} "
            f"(score={base_score})"
        ),
    )
    return result


def _maybe_emit(payload: dict[str, Any]) -> int:
    severity = payload.get("severity")
    if not severity:
        return 0
    cve = payload.get("cve")
    if not isinstance(cve, str):
        return 0
    cvss = payload.get("cvss") or {}
    cwes = payload.get("cwes") or []
    primary_cwe = next(
        (c for c in cwes if isinstance(c, str) and c.startswith("CWE-")),
        None,
    )
    description_summary = (payload.get("description") or "")[:400]
    cvss_text = (
        f"CVSS v{cvss.get('version')} score "
        f"{cvss.get('base_score')} "
        f"({cvss.get('base_severity')})"
    )

    title = (
        f"NVD-confirmed CVE {cve} — {cvss_text}"
        if cvss
        else f"NVD-confirmed CVE {cve}"
    )
    description = (
        f"{description_summary}\n\nNVD authoritative data: {cvss_text}. "
        f"Vector: {cvss.get('vector_string')}. "
        f"CWE(s): {', '.join(cwes) or '(none)'}. "
        f"Affected CPE ranges: {len(payload.get('cpe_matches') or [])} listed."
    )
    description_plain = (
        f"NIST NVD — the authoritative US government CVE database — "
        f"confirms {cve} with CVSS {cvss.get('base_score', '?')} "
        f"({cvss.get('base_severity', 'unknown').lower()}). "
        f"NVD's score is the canonical reference; if other tools "
        f"reported a different severity for this CVE, NVD wins for "
        f"prioritisation."
    )
    recommended_action = (
        f"Use NVD's CVSS score ({cvss.get('base_score', '?')}, "
        f"{cvss.get('base_severity', 'unknown')}) as the canonical "
        f"severity for this finding. The tracer's KEV enrichment "
        f"will auto-decorate this finding if {cve} is on the CISA "
        f"KEV catalog. Cross-reference NVD's `cpe_matches` against "
        f"your detected tech stack to confirm exposure. NVD "
        f"references: {len(payload.get('references') or [])} listed "
        f"in the result."
    )
    _emit_finding(
        title=title,
        severity=severity,
        cve=cve,
        cwe=primary_cwe,
        description=description,
        description_plain=description_plain,
        recommended_action=recommended_action,
    )
    return 1
