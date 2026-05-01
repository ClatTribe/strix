"""Passive DNS history mining via SecurityTrails / VirusTotal Passive DNS.

Roadmap §7.3. Surfaces stale subdomains and historical resolutions that
the live-DNS query would miss — typically the highest-value finding when
old subdomains still point at defunct or internal infrastructure.

Provider keys:
- `STRIX_SECURITYTRAILS_KEY` — preferred (direct historical-resolutions
  endpoint).
- `STRIX_VIRUSTOTAL_KEY` — fallback (returns less detail per record but is
  free-tier-friendlier).

Fail-open: when neither key is configured, returns `success=False` with a
clear `error_reason` of "no api keys configured" so the agent can move on
to other recon tools without retrying.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from strix.tools.registry import register_tool

from ._common import complete_check, looks_like_domain, start_check


logger = logging.getLogger(__name__)
_TOOL_NAME = "passive_dns_history"
_HTTP_TIMEOUT = 10
_SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"
_VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"


def _http_get_json(url: str, *, headers: dict[str, str]) -> tuple[int, dict[str, Any] | None]:
    """GET returning (status, parsed_json or None)."""
    try:
        import httpx

        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as c:
            r = c.get(url, headers=headers)
            try:
                return r.status_code, r.json()
            except Exception:  # noqa: BLE001
                return r.status_code, None
    except Exception:  # noqa: BLE001
        # Fall back to stdlib JSON fetch.
        try:
            import json as _json
            import urllib.request

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:  # noqa: S310
                body = r.read()
            try:
                return r.status, _json.loads(body)
            except Exception:  # noqa: BLE001
                return r.status, None
        except Exception:  # noqa: BLE001
            return 0, None


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------


def _securitytrails_history(domain: str, api_key: str) -> dict[str, Any]:
    """Returns historical A-record resolutions and known subdomains for `domain`."""
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    history_status, history = _http_get_json(
        f"{_SECURITYTRAILS_BASE}/history/{domain}/dns/a",
        headers=headers,
    )
    subs_status, subs = _http_get_json(
        f"{_SECURITYTRAILS_BASE}/domain/{domain}/subdomains?children_only=false",
        headers=headers,
    )

    resolutions: list[dict[str, Any]] = []
    if history_status == 200 and isinstance(history, dict):
        for record in history.get("records", []) or []:
            for value in record.get("values", []) or []:
                resolutions.append(
                    {
                        "ip": value.get("ip"),
                        "first_seen": record.get("first_seen"),
                        "last_seen": record.get("last_seen"),
                        "type": "A",
                    }
                )

    subdomains: list[str] = []
    if subs_status == 200 and isinstance(subs, dict):
        for sub in subs.get("subdomains", []) or []:
            if isinstance(sub, str) and sub:
                subdomains.append(f"{sub}.{domain}")

    return {
        "provider": "securitytrails",
        "history_status": history_status,
        "subs_status": subs_status,
        "resolutions": resolutions,
        "subdomains": subdomains,
        "success": history_status == 200 or subs_status == 200,
    }


# ---------------------------------------------------------------------------
# VirusTotal Passive DNS
# ---------------------------------------------------------------------------


def _virustotal_history(domain: str, api_key: str) -> dict[str, Any]:
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    res_status, res = _http_get_json(
        f"{_VIRUSTOTAL_BASE}/domains/{domain}/resolutions?limit=40",
        headers=headers,
    )
    subs_status, subs = _http_get_json(
        f"{_VIRUSTOTAL_BASE}/domains/{domain}/subdomains?limit=40",
        headers=headers,
    )

    resolutions: list[dict[str, Any]] = []
    if res_status == 200 and isinstance(res, dict):
        for entry in res.get("data", []) or []:
            attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            ip = attrs.get("ip_address")
            if ip:
                resolutions.append(
                    {
                        "ip": ip,
                        "last_seen": attrs.get("date"),
                        "type": "A",
                    }
                )

    subdomains: list[str] = []
    if subs_status == 200 and isinstance(subs, dict):
        for entry in subs.get("data", []) or []:
            if isinstance(entry, dict) and entry.get("id"):
                subdomains.append(entry["id"])

    return {
        "provider": "virustotal",
        "resolutions_status": res_status,
        "subs_status": subs_status,
        "resolutions": resolutions,
        "subdomains": subdomains,
        "success": res_status == 200 or subs_status == 200,
    }


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=True)
def passive_dns_history(domain: str, prefer: str | None = None) -> dict[str, Any]:
    """Mine passive-DNS history (historical resolutions + known subdomains).

    Args:
        domain: apex or subdomain (e.g. "example.com").
        prefer: "securitytrails" or "virustotal". When set and the key is
                available, that provider is queried alone. When unset or the
                preferred provider's key is missing, falls back to whichever
                key is configured.

    Provider key environment variables:
        - `STRIX_SECURITYTRAILS_KEY`
        - `STRIX_VIRUSTOTAL_KEY`

    Behaviour:
        - Fails open when neither key is configured (returns success=False with
          error_reason="no api keys configured").
        - Emits one `check.started`/`check.completed` per provider queried.
        - Doesn't emit findings on its own — historical resolutions are
          informational. Pair with `subdomain_takeover_check` against the
          discovered subdomains to surface dangling-CNAME findings.

    Returns the structured dict with merged resolutions + subdomains across
    queried providers.
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    st_key = os.environ.get("STRIX_SECURITYTRAILS_KEY")
    vt_key = os.environ.get("STRIX_VIRUSTOTAL_KEY")

    if not st_key and not vt_key:
        return {
            "success": False,
            "error_reason": "no api keys configured",
            "hint": (
                "Set STRIX_SECURITYTRAILS_KEY or STRIX_VIRUSTOTAL_KEY in the "
                "worker environment to enable passive-DNS history mining."
            ),
            "domain": domain,
        }

    providers_to_query: list[str] = []
    if prefer in ("securitytrails", "virustotal"):
        providers_to_query.append(prefer)
    else:
        if st_key:
            providers_to_query.append("securitytrails")
        if vt_key:
            providers_to_query.append("virustotal")

    results: list[dict[str, Any]] = []
    merged_resolutions: list[dict[str, Any]] = []
    merged_subdomains: set[str] = set()

    for provider in providers_to_query:
        cev_id = start_check(category="passive_dns", surface=domain, tool=_TOOL_NAME)
        try:
            if provider == "securitytrails":
                if not st_key:
                    raise RuntimeError("no SecurityTrails key")
                r = _securitytrails_history(domain, st_key)
            elif provider == "virustotal":
                if not vt_key:
                    raise RuntimeError("no VirusTotal key")
                r = _virustotal_history(domain, vt_key)
            else:
                continue
        except Exception as e:  # noqa: BLE001
            r = {"provider": provider, "success": False, "error": str(e)}

        results.append(r)
        merged_resolutions.extend(r.get("resolutions", []))
        for s in r.get("subdomains", []):
            merged_subdomains.add(s)

        complete_check(
            cev_id,
            result=("not_vulnerable" if r.get("success") else "inconclusive"),
            evidence=(
                f"{provider}: {len(r.get('resolutions', []))} resolutions, "
                f"{len(r.get('subdomains', []))} subdomains"
            ),
        )

    return {
        "success": any(r.get("success") for r in results),
        "domain": domain,
        "providers_queried": providers_to_query,
        "results": results,
        "merged_resolutions": merged_resolutions,
        "merged_subdomains": sorted(merged_subdomains),
        "merged_subdomain_count": len(merged_subdomains),
    }
