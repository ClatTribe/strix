"""iter-26.8 — posture-aware payload selection guidance for active specialists.

When the target's SecurityPosture indicates WAF detected
(`stealth_mode_required=True`), the conversational active specialists
(sqli / xss / path-traversal / cmd-injection / ssrf / ssti) should
switch to stealth payloads to avoid getting the scanner IP
blacklisted. This module ships a small per-category guidance block
that the specialist dispatch path appends to the system prompt when
the dispatch target is on a posture-flagged host.

Per-category guidance (rendered conditionally):

  * sqli      — `--tamper=space2comment,between` style obfuscation,
                prefer time-based-blind over error-based, longer
                inter-payload sleep, fewer concurrent threads.
  * xss       — prefer `<svg/onload>` / `<details/ontoggle>` over
                `<script>` (keyword WAFs miss the tag-event syntax),
                URL-encode payload markers, no DOM-extraction
                bursts.
  * path_traversal — encode `../` as `%2e%2e%2f` / `..%252f` (double
                encoded), break up sequences with junk bytes.
  * cmd_injection — prefer `${IFS}` / `$@` separators over spaces;
                base64-encode the proof token; avoid common
                wget/curl-to-attacker patterns.
  * ssrf      — skip cloud-metadata IPs on Cloudflare-fronted targets
                (returns 403 cleanly anyway); prefer DNS-rebinding
                probes over direct internal-IP scans.
  * ssti      — fragment template expressions across multiple params
                if possible.

Concurrency guidance applies to ALL categories: respect the
SecurityPosture.rate_limit_rps measurement; default to 1 RPS when
stealth-required.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.l15.posture import get_posture


logger = logging.getLogger(__name__)


_STEALTH_PROMPT_HEADER = (
    "\n\n=== STEALTH MODE — WAF DETECTED ===\n"
    "Target's SecurityPosture indicates a WAF / edge protection "
    "layer is in front. Standard payload sets will get this "
    "scanner's IP blacklisted within 10-20 noisy requests. Switch "
    "to the stealth guidance below.\n\n"
)


_STEALTH_GUIDANCE: dict[str, str] = {
    "sqli": (
        "SQLi STEALTH GUIDANCE:\n"
        "  * Prefer TIME-BASED BLIND payloads over error-based "
        "(the error responses are usually masked).\n"
        "  * Encode payload tokens — `'` as `%27`, spaces as "
        "`/**/` or `%09` (TAB), `=` as `%3d`.\n"
        "  * Add inter-payload sleeps (>= 2s); WAFs throttle "
        "burst-style requests.\n"
        "  * When invoking `scan_sqli` via the deterministic sandbox "
        "  tool: use the lower risk levels (1-2) rather than 3, "
        "  and enable sqlmap's --tamper=space2comment,between."
    ),
    "xss": (
        "XSS STEALTH GUIDANCE:\n"
        "  * Use tag-event payloads (`<svg/onload=...>`, "
        "`<details/ontoggle=...>`) over `<script>` — keyword WAFs "
        "miss these.\n"
        "  * Avoid `alert(1)` proof tokens; use a "
        "domain-correlation proof (`fetch('//<random-subdomain>"
        "<your-collab-host>')`) instead.\n"
        "  * Don't run DOM-extraction bursts; one payload per "
        "endpoint, then move on."
    ),
    "path_traversal": (
        "PATH-TRAVERSAL STEALTH GUIDANCE:\n"
        "  * Encode `../` as `%2e%2e%2f` and try double-encoded "
        "`..%252f` variants; many WAFs decode once but not twice.\n"
        "  * Mix in junk bytes between traversal sequences "
        "(`../foo/../`) — WAFs key off contiguous `../../` "
        "patterns.\n"
        "  * Target known sensitive files first (`/etc/passwd`, "
        "`/proc/self/environ`) — one probe per endpoint."
    ),
    "cmd_injection": (
        "COMMAND-INJECTION STEALTH GUIDANCE:\n"
        "  * Use `${IFS}` or `$@` instead of literal spaces.\n"
        "  * Base64-encode the OOB-DNS proof token to avoid "
        "domain-match WAF rules.\n"
        "  * Skip `wget|curl|nc` patterns — use Bash's "
        "`/dev/tcp/<host>/<port>` instead."
    ),
    "ssrf": (
        "SSRF STEALTH GUIDANCE:\n"
        "  * Skip direct probes of `169.254.169.254` / "
        "`metadata.google.internal` — Cloudflare-fronted targets "
        "return 403 unconditionally on those, no info gained.\n"
        "  * Use DNS-rebinding payloads via your OOB collab.\n"
        "  * Try `gopher://` and `file://` schemes alongside HTTP."
    ),
    "ssti": (
        "SSTI STEALTH GUIDANCE:\n"
        "  * If the endpoint takes multiple params, fragment the "
        "template expression across them. WAFs key off full "
        "`{{...}}` shapes; partial fragments slip through."
    ),
    # Generic fallback for non-listed categories.
    "_default": (
        "GENERIC STEALTH GUIDANCE:\n"
        "  * Throttle to ≤ 1 RPS.\n"
        "  * Rotate User-Agent between requests.\n"
        "  * Avoid bursts; one payload, observe, decide.\n"
        "  * URL-encode payload markers (don't ship raw `<`, `'`, "
        "`{{`, etc.)."
    ),
}


def stealth_addendum_for(
    category: str,
    target: str | None = None,
) -> str:
    """Return the per-category stealth-guidance prompt addendum.

    Args:
        category: specialist category (sqli, xss, etc.).
        target: the dispatch target URL. Used to look up
            `posture.stealth_required` — if False (or target unset),
            we return an empty string (the specialist runs at normal
            payload intensity).

    Returns:
        Multi-line string ready to append to a specialist system
        prompt, OR empty string when stealth not required.
    """
    try:
        if not target:
            return ""
        p = get_posture(target)
        if not p or not p.stealth_mode_required:
            return ""
        cat = (category or "").lower().strip()
        guidance = _STEALTH_GUIDANCE.get(cat, _STEALTH_GUIDANCE["_default"])
        rps = (
            f"  * Rate-limit cap from posture probe: ≤ "
            f"{p.rate_limit_rps} rps observed → throttle to ≤ "
            f"{max(1, (p.rate_limit_rps or 1) // 2)} rps.\n"
            if p.rate_limit_rps else ""
        )
        return _STEALTH_PROMPT_HEADER + guidance + ("\n" + rps if rps else "")
    except Exception as e:  # noqa: BLE001
        logger.debug("stealth_addendum_for failed: %s", e)
        return ""
