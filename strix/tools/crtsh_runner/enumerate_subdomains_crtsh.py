"""iter-Q5.46 — `enumerate_subdomains_crtsh` direct-HTTP wrapper.

crt.sh is the canonical free certificate-transparency log search
engine (run by Sectigo / Comodo). Cert issuance is the most reliable
signal that a subdomain has been deployed — once a TLS cert is
issued for `secret-api.example.com`, it lands in the public CT logs
within minutes regardless of whether the host is publicly resolvable.

This catches the long-tail subdomains subfinder + amass miss:
internal CI environments, dev / staging hosts, customer-specific
tenant subdomains, recently-deployed assets the passive DNS sources
haven't picked up yet.

Architecture note: this is a network-side HTTP wrapper rather than a
binary subprocess. The Q5.44 child-asset extractor reads the same
top-level `subdomains[]` field amass uses, so no extractor change is
needed beyond a new tool-name branch.

Recall safety: `status=partial` on any HTTP failure (network down,
crt.sh rate limit, parse error). Never fails-hard.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


logger = logging.getLogger(__name__)


_CRTSH_HOST = "https://crt.sh"
_DEFAULT_TIMEOUT_SECONDS = 60
# crt.sh sometimes 502s under load; honour a single retry by default.
_DEFAULT_RETRIES = 1


def _crtsh_enabled() -> bool:
    """False iff the kill switch is set. No binary to probe — crt.sh
    is reached over HTTP."""
    return os.environ.get(
        "STRIX_CRTSH_DISABLED", "",
    ).strip().lower() not in {"1", "true", "yes", "on"}


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1596.002 Search Open Tech Databases: WHOIS — CT logs are the
    # cert-side equivalent.
    mitre_techniques=["T1596.002"],
)
def enumerate_subdomains_crtsh(
    domain: str,
    max_results: int = 500,
    include_expired: bool = True,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Subdomain enumeration via crt.sh certificate-transparency logs.

    Args:
        domain: apex domain (e.g. ``example.com``). Must not include
            scheme or path.
        max_results: cap on returned subdomains. Default 500.
        include_expired: when True, includes certs that have expired
            (default — historical certs still reveal subdomains that
            may be re-provisioned later). When False, queries with
            `&exclude=expired` to drop them.
        timeout_seconds: HTTP timeout in seconds. crt.sh is sometimes
            slow under load; default 60s.

    Returns:
        ```
        {success, status, domain, total_found: int,
         subdomains: [str, ...], reason?}
        ```

    Side effects: one HTTPS GET to `crt.sh/?q=%25.<domain>&output=json`.
    Result deduped + lower-cased + leading-wildcard-stripped (`*.foo`
    → `foo`). Hosts not under the apex are dropped (crt.sh's
    fuzzy-match sometimes surfaces unrelated certs).
    """
    if not domain or not domain.strip():
        return {
            "success": False, "status": "error", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": "domain required",
        }
    if not _crtsh_enabled():
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": "STRIX_CRTSH_DISABLED set",
        }

    apex = domain.strip().lower().rstrip(".")
    # %25 is URL-encoded `%` — crt.sh's SQL-LIKE wildcard.
    query = f"%25.{apex}"
    params = {"q": query, "output": "json"}
    if not include_expired:
        params["exclude"] = "expired"

    url = f"{_CRTSH_HOST}/?{urllib.parse.urlencode(params)}"

    body = _fetch_with_retries(url, timeout_seconds, _DEFAULT_RETRIES)
    if isinstance(body, dict):  # error sentinel
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": body["reason"],
        }

    try:
        records = json.loads(body)
    except (ValueError, TypeError) as e:
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": f"crt.sh response not JSON: {type(e).__name__}: {e}",
        }
    if not isinstance(records, list):
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": f"crt.sh response not a list (got {type(records).__name__})",
        }

    subdomains: list[str] = []
    seen: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        # crt.sh returns both `common_name` and `name_value`.
        # name_value can be multi-line — one cert covers many SANs.
        candidates: list[str] = []
        cn = rec.get("common_name")
        if isinstance(cn, str):
            candidates.append(cn)
        nv = rec.get("name_value")
        if isinstance(nv, str):
            candidates.extend(nv.splitlines())

        for raw_host in candidates:
            host = raw_host.strip().lower().rstrip(".")
            # Drop wildcard prefix — `*.foo.example.com` → `foo.example.com`.
            if host.startswith("*."):
                host = host[2:]
            if not host or host in seen:
                continue
            # Defensive: drop hosts that don't end with the apex.
            # crt.sh's fuzzy LIKE can return unrelated certs when
            # the apex is short or matches inside other names.
            if not (host == apex or host.endswith("." + apex)):
                continue
            seen.add(host)
            subdomains.append(host)
            if len(subdomains) >= max_results:
                break
        if len(subdomains) >= max_results:
            break

    return {
        "success": True,
        "status": "ok",
        "domain": domain,
        "total_found": len(subdomains),
        "subdomains": subdomains,
    }


def _fetch_with_retries(
    url: str, timeout_seconds: int, retries: int,
) -> str | dict[str, str]:
    """HTTPS GET with up to N retries on transient failures.

    Returns the response body string on success, or a `{"reason": ...}`
    error sentinel for the caller to fold into a partial result.
    """
    last_err: str = ""
    attempts = max(1, retries + 1)
    for _ in range(attempts):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "strix-crtsh/1.0"},
            )
            with urllib.request.urlopen(  # noqa: S310
                req, timeout=timeout_seconds,
            ) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code}: {e.reason}"
            # Retry on 502/503/504 — crt.sh is intermittent.
            if e.code not in (502, 503, 504):
                break
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            last_err = f"{type(e).__name__}: {e}"
        except Exception as e:  # noqa: BLE001 — defensive
            last_err = f"{type(e).__name__}: {e}"
            break
    return {"reason": f"crt.sh fetch failed: {last_err}"}
