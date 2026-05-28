"""iter-Q5.45 — `enumerate_subdomains_amass` subprocess wrapper.

Amass (OWASP) is the gold-standard subdomain enumeration tool —
combines passive sources, ASN/BGP enumeration, and active DNS brute
force. Subfinder is faster on the passive-only path, but amass
catches subdomains subfinder misses (active DNS enum + cert-transparency
deeper crawl).

Both wrappers ship side-by-side in `_ANCHORS_DOMAIN`. Q5.44's
`_extract_child_assets_from_domain_prepass` already dedupes by host
across multiple sources, so the duplication is intentional —
maximises recall.

Mode: passive by default (no active DNS noise against target).
Operator opt-in to active mode via the `active` kwarg.

Recall safety: `status=partial` when the binary is missing — never
fails-hard; matches the subfinder wrapper's contract.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any


logger = logging.getLogger(__name__)


_AMASS_BIN = "amass"
_DEFAULT_TIMEOUT_SECONDS = 300


def _amass_available() -> bool:
    """True iff `amass` is on PATH AND the kill switch isn't set."""
    if os.environ.get(
        "STRIX_AMASS_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_AMASS_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1596.001 Search Open Tech Databases: DNS/Passive (matches subfinder).
    # T1590.002 Gather Victim Network Information: DNS — active mode adds this.
    mitre_techniques=["T1596.001", "T1590.002"],
)
def enumerate_subdomains_amass(
    domain: str,
    max_results: int = 500,
    active: bool = False,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Subdomain enumeration via OWASP amass.

    Args:
        domain: apex domain (e.g. ``example.com``). Must not include
            scheme or path.
        max_results: cap on returned subdomains. Default 500.
        active: when True, runs amass in active mode (DNS brute force
            + zone transfer attempts). Default False — passive-only,
            stays ASM-friendly like subfinder. Env override:
            ``STRIX_AMASS_ACTIVE=1``.
        timeout_seconds: subprocess timeout. Amass is slower than
            subfinder; default 300s (vs subfinder's 180s).

    Returns:
        ```
        {success, status, domain, total_found: int,
         subdomains: [str, ...], reason?}
        ```

    Side effects: invokes `amass enum -d <domain> -json -` and
    streams each JSON line into a deduped `subdomains` list. Lines
    that don't parse as JSON or don't carry a recognised host field
    are silently skipped — amass's JSON shape varies across
    versions and we don't want one bad line to drop the run.
    """
    if not domain or not domain.strip():
        return {
            "success": False, "status": "error", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": "domain required",
        }
    if not _amass_available():
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": (
                "amass binary not on PATH (or STRIX_AMASS_DISABLED=1). "
                "Install via `go install -v github.com/owasp-amass/amass"
                "/v4/...@master` or `brew install amass`."
            ),
        }

    # Env override for active mode — operators can flip it
    # without threading a kwarg through.
    if not active:
        active = os.environ.get(
            "STRIX_AMASS_ACTIVE", "",
        ).strip().lower() in {"1", "true", "yes", "on"}

    cmd = [
        _AMASS_BIN, "enum",
        "-d", domain.strip(),
        "-json", "-",        # stream JSONL to stdout
        "-silent",
        "-nocolor",
    ]
    if active:
        cmd.append("-active")
    else:
        cmd.append("-passive")

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": f"amass invocation failed: {type(e).__name__}: {e}",
        }

    subdomains: list[str] = []
    seen: set[str] = set()
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        # Amass JSON shape carries the host as either `name` (v4) or
        # `domain` (older v3); accept both to stay version-portable.
        host = rec.get("name") or rec.get("domain") or rec.get("host")
        if not host or not isinstance(host, str):
            continue
        host = host.strip().lower().rstrip(".")
        if host in seen:
            continue
        seen.add(host)
        subdomains.append(host)
        if len(subdomains) >= max_results:
            break

    return {
        "success": True,
        "status": "ok",
        "domain": domain,
        "total_found": len(subdomains),
        "subdomains": subdomains,
        "mode": "active" if active else "passive",
    }
