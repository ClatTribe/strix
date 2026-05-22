"""iter-22.6 — `scan_iocs_for_target_threatfox` — abuse.ch
ThreatFox IoC lookup.

ThreatFox (https://threatfox.abuse.ch/) is a free, zero-auth
threat-intel API aggregating active-malware IoCs across
researcher submissions. Given a target's domain / IP / file hash,
returns matching IoC records when the artifact is currently
in active malware campaigns.

This is the commercial-feed-equivalent strix capability mentioned
in `docs/L1-optimization.md §6 iter-22.6` (Cyble / Recorded
Future / Mandiant ASM bundle equivalent feeds at $$$$ tiers;
ThreatFox is free).

Severity mapping:

  * Hash match (md5/sha1/sha256)  → critical (CWE-506 malware-on-disk)
  * URL match                     → high     (CWE-829 phishing/C2)
  * Domain match                  → high     (CWE-829 phishing/C2)
  * IP-port match                 → medium   (CWE-829 — IP may be shared)

Recall safety: free API has rate limits; we send ONE lookup per
invocation. Returns `status=partial` on network failure / API
error; never raises.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
_DEFAULT_TIMEOUT_SECONDS = 10


def _threatfox_disabled() -> bool:
    return os.environ.get(
        "STRIX_THREATFOX_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


_IOC_TYPE_SEVERITY = {
    "md5_hash": ("critical", "CWE-506"),
    "sha1_hash": ("critical", "CWE-506"),
    "sha256_hash": ("critical", "CWE-506"),
    "url": ("high", "CWE-829"),
    "domain": ("high", "CWE-829"),
    "ip:port": ("medium", "CWE-829"),
}


def _post_json(url: str, payload: dict, timeout: float) -> tuple[dict | None, str | None]:
    """ThreatFox API expects POST + JSON body. Uses httpx when
    available (already in strix sandbox), falls back to urllib.
    Returns `(parsed_body, error)`."""
    body = json.dumps(payload).encode("utf-8")
    try:
        import httpx
        with httpx.Client(timeout=timeout, trust_env=False) as c:
            resp = c.post(
                url, content=body,
                headers={"Content-Type": "application/json"},
            )
            try:
                return resp.json(), None
            except Exception as e:  # noqa: BLE001
                return None, f"JSON parse failed: {e}"
    except Exception:  # noqa: BLE001
        # urllib fallback
        try:
            import urllib.request
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                return json.loads(r.read().decode("utf-8")), None
        except Exception as e:  # noqa: BLE001
            return None, f"{type(e).__name__}: {e}"


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1583", "T1071"],
)
def scan_iocs_for_target_threatfox(
    target: str,
) -> dict[str, Any]:
    """Query abuse.ch ThreatFox for active-malware IoC matches
    against the supplied target artefact (domain / IP / hash / URL).

    Args:
        target: domain, IP, IP:port, URL, or file hash. ThreatFox's
            API auto-detects the input shape.

    Returns:
        `{success, status, target, total_findings, findings,
          reason?}`
    """
    if not target or not target.strip():
        return {
            "success": False, "status": "error", "target": target,
            "total_findings": 0, "findings": [],
            "reason": "target required",
        }
    if _threatfox_disabled():
        return {
            "success": True, "status": "partial", "target": target,
            "total_findings": 0, "findings": [],
            "reason": "STRIX_THREATFOX_DISABLED=1",
        }

    payload = {"query": "search_ioc", "search_term": target.strip()}
    body, err = _post_json(
        THREATFOX_API_URL, payload, timeout=_DEFAULT_TIMEOUT_SECONDS,
    )
    if err:
        return {
            "success": True, "status": "partial", "target": target,
            "total_findings": 0, "findings": [],
            "reason": f"ThreatFox HTTP failed: {err}",
        }
    if not isinstance(body, dict):
        return {
            "success": True, "status": "partial", "target": target,
            "total_findings": 0, "findings": [],
            "reason": "ThreatFox returned unexpected shape",
        }
    # API response shape: {"query_status": "ok|no_result|...",
    # "data": [{"ioc": ..., "ioc_type": ..., "threat_type": ...,
    # "malware": ..., "confidence_level": ..., "first_seen": ...},
    # ...]}
    query_status = body.get("query_status") or ""
    if query_status == "no_result":
        return {
            "success": True, "status": "ok", "target": target,
            "total_findings": 0, "findings": [],
        }
    if query_status != "ok":
        return {
            "success": True, "status": "partial", "target": target,
            "total_findings": 0, "findings": [],
            "reason": f"ThreatFox query_status={query_status!r}",
        }

    data = body.get("data") or []
    if not isinstance(data, list):
        data = []

    findings: list[dict[str, Any]] = []
    for r in data:
        if not isinstance(r, dict):
            continue
        ioc_type = (r.get("ioc_type") or "").lower()
        severity, cwe = _IOC_TYPE_SEVERITY.get(
            ioc_type, ("medium", "CWE-829"),
        )
        ioc = r.get("ioc") or target
        malware = r.get("malware") or "(unknown family)"
        threat_type = r.get("threat_type") or "(unknown type)"
        confidence = r.get("confidence_level") or 0
        first_seen = r.get("first_seen") or "(unknown)"
        findings.append({
            "rule_id": f"threatfox-{ioc_type or 'unknown'}-match",
            "title": (
                f"ThreatFox IoC match: `{ioc}` linked to "
                f"`{malware}` ({threat_type}, confidence {confidence})"
            ),
            "severity": severity,
            "cwe": cwe,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "malware": malware,
            "threat_type": threat_type,
            "confidence": confidence,
            "first_seen": first_seen,
            "description": (
                f"abuse.ch ThreatFox flags `{ioc}` as an active "
                f"IoC for `{malware}` ({threat_type}). First seen "
                f"{first_seen}; confidence {confidence}/100. The "
                "target artefact appears in active malware "
                "campaigns observed by researchers — treat as "
                "compromised or staged-for-compromise."
            ),
            "remediation": (
                "If this IoC matches a customer-owned artefact, "
                "investigate for compromise (running malware "
                "matching the family signature, beaconing to the "
                "C2 IoC, etc.). If it's an inbound IoC (attacker "
                "infrastructure), block at the perimeter and "
                "alert the SOC."
            ),
        })

    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=target,
                    endpoint=f["ioc"],
                    category="ioc_match",
                    verification_status="verified",
                    confidence=0.92,
                    description=f["description"],
                    impact=(
                        f"Target artefact `{target}` matches an "
                        "active-malware IoC in abuse.ch ThreatFox."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Tool: ThreatFox (abuse.ch)\n"
                        f"IoC type: {f['ioc_type']}\n"
                        f"Malware family: {f['malware']}\n"
                        f"Threat type: {f['threat_type']}\n"
                        f"Confidence: {f['confidence']}/100\n"
                        f"First seen: {f['first_seen']}"
                    ),
                    reasoning_trace=[
                        f"Submitted `{target}` to ThreatFox API.",
                        f"Returned active IoC match for "
                        f"`{f['malware']}`.",
                    ],
                    poc_description=(
                        f"Reproduce: `curl -X POST "
                        "https://threatfox-api.abuse.ch/api/v1/ "
                        f'-d \'{{\"query\":\"search_ioc\",'
                        f'\"search_term\":\"{target}\"}}\'`'
                    ),
                    poc_script_code=(
                        "curl -X POST "
                        "https://threatfox-api.abuse.ch/api/v1/ "
                        f'-d \'{{"query":"search_ioc",'
                        f'"search_term":"{target}"}}\''
                    ),
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("threatfox tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "total_findings": len(findings),
        "findings": findings,
    }
