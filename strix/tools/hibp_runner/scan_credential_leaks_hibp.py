"""iter-22.6 — `scan_credential_leaks_hibp` HTTP wrapper.

HIBP (https://haveibeenpwned.com/API/v3) offers:

  * `/breachedaccount/{email}` — per-email breach list (free, paid
    key required)
  * `/breaches?domain={domain}` — list breaches affecting a
    domain (free, no auth)
  * `/breaches/{name}` — breach detail (free, no auth)

This wrapper uses the `domain` endpoint (no auth required) to
answer: "what data breaches affect this org's domain?" — useful
brand-monitoring / compliance check. The per-email endpoint
requires a paid API key (`HIBP_API_KEY` env var); we degrade
gracefully when not set.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


HIBP_DOMAIN_URL = "https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
HIBP_USER_AGENT = "strix-scanner/1.0"
_DEFAULT_TIMEOUT_SECONDS = 10


def _hibp_disabled() -> bool:
    return os.environ.get(
        "STRIX_HIBP_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


def _http_get_json(url: str, timeout: float) -> tuple[Any, str | None]:
    """GET + parse JSON. Returns `(body, error)`."""
    try:
        import httpx
        with httpx.Client(
            timeout=timeout, trust_env=False,
            headers={"User-Agent": HIBP_USER_AGENT},
        ) as c:
            resp = c.get(url)
            if resp.status_code == 404:
                # HIBP returns 404 for "no breaches for this domain"
                return [], None
            if resp.status_code != 200:
                return None, f"HIBP HTTP {resp.status_code}: {resp.text[:200]}"
            try:
                return resp.json(), None
            except Exception as e:  # noqa: BLE001
                return None, f"JSON parse failed: {e}"
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1589.001"],  # Gather Victim Identity: Credentials
)
def scan_credential_leaks_hibp(
    domain: str,
) -> dict[str, Any]:
    """Query HIBP for breaches affecting a domain.

    Args:
        domain: apex domain (e.g. `example.com`).

    Returns:
        ```
        {success, status, domain, total_findings, findings: [...],
         reason?}
        ```

    Per-breach finding emits:
      * Title: "Org domain `<domain>` data exposed in breach `<name>` (Nm records)"
      * Severity: high (default; downgradeable via env)
      * CWE-200 — information exposure
    """
    if not domain or not domain.strip():
        return {
            "success": False, "status": "error", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": "domain required",
        }
    if _hibp_disabled():
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": "STRIX_HIBP_DISABLED=1",
        }

    url = HIBP_DOMAIN_URL.format(domain=domain.strip().lower())
    body, err = _http_get_json(url, timeout=_DEFAULT_TIMEOUT_SECONDS)
    if err:
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": f"HIBP HTTP failed: {err}",
        }
    if not isinstance(body, list):
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_findings": 0, "findings": [],
            "reason": "HIBP returned unexpected shape",
        }

    findings: list[dict[str, Any]] = []
    for b in body:
        if not isinstance(b, dict):
            continue
        name = b.get("Name") or "(unknown breach)"
        title_breach = b.get("Title") or name
        breach_date = b.get("BreachDate") or "(unknown date)"
        pwn_count = b.get("PwnCount") or 0
        data_classes = b.get("DataClasses") or []
        verified = bool(b.get("IsVerified"))
        if not verified:
            # Unverified entries are submitter-reported — skip to
            # avoid false positives in compliance reports.
            continue
        findings.append({
            "rule_id": f"hibp-breach-{name}",
            "title": (
                f"Org domain `{domain}` records exposed in breach "
                f"`{title_breach}` ({pwn_count:,} records, "
                f"{breach_date})"
            ),
            "severity": "high",
            "cwe": "CWE-200",
            "breach_name": name,
            "breach_title": title_breach,
            "breach_date": breach_date,
            "pwn_count": pwn_count,
            "data_classes": data_classes,
            "description": (
                f"HIBP reports {pwn_count:,} records from `{domain}` "
                f"in breach `{title_breach}` ({breach_date}). Data "
                f"classes exposed: {data_classes}. Credential reuse "
                "+ phishing infrastructure can be staged from this "
                "data."
            ),
            "remediation": (
                "Force password resets for affected accounts. "
                "Cross-reference internal IAM logs for impossible-"
                "travel / credential-stuffing patterns since the "
                f"breach date ({breach_date}). Consider deploying "
                "haveibeenpwned-passwords integration in your "
                "auth flow to block known-compromised credentials."
            ),
        })

    return {
        "success": True,
        "status": "ok",
        "domain": domain,
        "total_findings": len(findings),
        "findings": findings,
    }
