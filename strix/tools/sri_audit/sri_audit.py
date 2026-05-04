"""Subresource Integrity (SRI) audit.

Fetches a target URL, parses the HTML response, and emits findings
for every external `<script src="...">` and
`<link rel="stylesheet" href="...">` that loads cross-origin
content WITHOUT an `integrity=` attribute.

Why this is zero-false-positive:
- The HTML response either has the attribute or doesn't. Pure
  binary string-match.
- Cross-origin classification is also binary: parse host from URL,
  compare to target host.

Severity ladder:
- **Medium** CWE-353 (missing data integrity check) when an external
  script lacks `integrity=`. Scripts execute arbitrary code; a
  compromised CDN delivers an attacker-modified JS.
- **Low** CWE-353 when an external stylesheet lacks `integrity=`.
  Stylesheets are less dangerous (CSS-injection has narrower
  impact than JS-execution) but still on the supply-chain risk
  ladder.

Same-origin assets are SKIPPED (they're not a supply-chain risk
the customer controls — if attackers compromise the same-origin
server, integrity hashes don't help anyway).

`<script>` / `<link>` tags missing `crossorigin=` attribute on
external assets get an additional **info** finding noting that
SRI requires `crossorigin="anonymous"` to verify; without it the
browser doesn't enforce the hash. We surface this as a usability
warning paired with the missing-integrity finding.

References:
- W3C SRI spec: https://www.w3.org/TR/SRI/
- polyfill.io 2024 incident: classic example of why SRI matters.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "sri_audit"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 256 * 1024  # SRI scan needs a longer body window than typical probes


# Regex for capturing `<script ...>` and `<link rel="stylesheet" ...>`
# tags. Case-insensitive, multi-line, with attribute capture.
# Note: this is a lenient-tolerant match (regex on HTML is
# imperfect by design; `BeautifulSoup` would be more correct but
# adds a dependency). For SRI specifically — which is about
# attribute presence on `<script>`/`<link>` — regex is sufficient.

_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*?)>", re.IGNORECASE | re.DOTALL,
)
_LINK_TAG_RE = re.compile(
    r"<link\b([^>]*?)/?>", re.IGNORECASE | re.DOTALL,
)


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_RESPONSE_SCAN],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Attribute extraction
# ---------------------------------------------------------------------------


_ATTR_RE = re.compile(
    r"""(\w[\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
)


def _parse_attrs(tag_inner: str) -> dict[str, str]:
    """Parse the attribute portion of a tag (everything inside <X ...>)
    into a dict. Handles double / single / unquoted values."""
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(tag_inner):
        name = m.group(1).lower()
        # Pick whichever group matched.
        value = m.group(2) if m.group(2) is not None else (
            m.group(3) if m.group(3) is not None else m.group(4) or ""
        )
        out[name] = value
    return out


def _is_external(asset_url: str, target_host: str) -> bool:
    """True if asset_url's host is non-empty AND different from target_host."""
    if not asset_url:
        return False
    parsed = urlparse(asset_url)
    if not parsed.netloc:
        return False  # Relative URL — same origin
    return parsed.netloc.lower() != target_host.lower()


def _normalize_target(target: str) -> str | None:
    if not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
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
        category="missing_sri",
        cwe="CWE-353",  # Missing Support for Integrity Check
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Without Subresource Integrity (SRI), the browser executes "
            "whatever the CDN delivers. If the CDN is compromised "
            "(see polyfill.io 2024), every visiting browser runs the "
            "attacker's code. SRI hashes guarantee the asset bytes "
            "match what was deployed; a single-byte modification "
            "fails the check and the browser refuses to execute."
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
    mitre_techniques=["T1592"],
)
def sri_audit(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Audit a page for missing Subresource Integrity (SRI) hashes
    on external `<script>` / `<link>` assets.

    Args:
        target_url: URL to fetch and audit. Auto-prefixed `https://`
            for bare hosts.
        timeout: HTTP timeout (default 10s).

    Returns:
        {
          success, target_url, target_host,
          assets_examined: int,
          external_scripts: [{src, has_integrity, has_crossorigin}, ...],
          external_links: [...],
          findings_emitted, errors?
        }

    Findings:
        - **Medium** CWE-353 — external `<script>` without `integrity=`
        - **Low** CWE-353 — external `<link rel="stylesheet">` without
          `integrity=`
        - **Info** CWE-353 — `<script integrity=...>` without
          `crossorigin="anonymous"` (browser won't enforce)

    Notes:
        - Same-origin assets are skipped (not a supply-chain risk
          the customer controls).
        - Verification status: `verified` (the HTML literally
          contains or omits the attribute — no probabilistic
          signal). This is a zero-FP detector.
        - Composes with cluster-A safety; `--exclude-path` skips.
    """
    target = _normalize_target(target_url)
    if target is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    cev = _start_check("sri_audit", target_host)

    response = _http_get(target, timeout=timeout)
    if response.get("skipped"):
        _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
        return {
            "success": True, "target_url": target, "target_host": target_host,
            "assets_examined": 0, "external_scripts": [], "external_links": [],
            "findings_emitted": 0, "skipped": True,
        }

    status = int(response.get("status") or 0)
    if status not in (200, 301, 302, 303, 307, 308):
        _complete_check(
            cev, "inconclusive",
            f"target returned status {status}; can't audit HTML",
        )
        return {
            "success": True, "target_url": target, "target_host": target_host,
            "assets_examined": 0, "external_scripts": [], "external_links": [],
            "findings_emitted": 0, "status": status,
        }

    body = response.get("body") or ""
    findings_emitted = 0
    external_scripts: list[dict[str, Any]] = []
    external_links: list[dict[str, Any]] = []

    # Per-asset dedup so the same CDN URL referenced N times in HTML
    # emits ONE finding.
    seen_script_srcs: set[str] = set()
    seen_link_hrefs: set[str] = set()

    # ---- <script> tags ----
    for m in _SCRIPT_TAG_RE.finditer(body):
        attrs = _parse_attrs(m.group(1))
        src = attrs.get("src", "").strip()
        if not src:
            continue
        # Resolve relative URLs against the target so we can classify
        # cross-origin correctly.
        absolute_src = urljoin(target, src)
        if not _is_external(absolute_src, target_host):
            continue

        has_integrity = bool(attrs.get("integrity"))
        has_crossorigin = bool(attrs.get("crossorigin"))

        record = {
            "src": absolute_src,
            "has_integrity": has_integrity,
            "has_crossorigin": has_crossorigin,
        }
        external_scripts.append(record)

        if absolute_src in seen_script_srcs:
            continue
        seen_script_srcs.add(absolute_src)

        if not has_integrity:
            _emit_finding(
                title=f"External `<script>` missing SRI integrity hash on {target_host}",
                severity="medium",
                target=target_host,
                endpoint=target,
                description=(
                    f"`<script src=\"{absolute_src}\">` loads from an "
                    f"external host without an `integrity=` attribute. "
                    f"If the CDN is compromised, attacker-modified "
                    f"JavaScript runs in every visitor's browser."
                ),
                description_plain=(
                    "Your page loads JavaScript from an external CDN "
                    "without the integrity hash that proves the file "
                    "wasn't tampered with. If that CDN ever gets "
                    "compromised — see the polyfill.io 2024 incident "
                    "— the attacker can deliver malicious code to "
                    "every user visiting your site."
                ),
                recommended_action=(
                    "Add an `integrity=\"sha384-...\"` attribute and "
                    "`crossorigin=\"anonymous\"` to every external "
                    "`<script>` tag. Generate the hash with "
                    "`openssl dgst -sha384 -binary <file> | openssl base64 -A` "
                    "or copy from sri.web.dev. Pin to a specific "
                    "version of the asset (avoid `latest`-style "
                    "URLs). Better yet: bundle the dependency at "
                    "build time so it's served from your own origin."
                ),
            )
            findings_emitted += 1
        elif not has_crossorigin:
            _emit_finding(
                title=f"External `<script integrity=...>` missing `crossorigin` attribute on {target_host}",
                severity="info",
                target=target_host,
                endpoint=target,
                description=(
                    f"`<script src=\"{absolute_src}\" integrity=\"...\">` "
                    f"has the integrity hash but is missing "
                    f"`crossorigin=\"anonymous\"`. Browsers will not "
                    f"enforce the SRI hash on cross-origin requests "
                    f"without `crossorigin` set."
                ),
                description_plain=(
                    "Your page declares the SRI hash but is missing "
                    "`crossorigin=\"anonymous\"`. Browsers don't "
                    "verify cross-origin SRI hashes without that "
                    "attribute — so the protection effectively "
                    "doesn't apply."
                ),
                recommended_action=(
                    "Add `crossorigin=\"anonymous\"` to the "
                    "`<script>` tag alongside the existing "
                    "`integrity=` attribute. The CDN must respond "
                    "with `Access-Control-Allow-Origin: *` (most "
                    "modern CDNs already do)."
                ),
            )
            findings_emitted += 1

    # ---- <link rel="stylesheet"> tags ----
    for m in _LINK_TAG_RE.finditer(body):
        attrs = _parse_attrs(m.group(1))
        rel = attrs.get("rel", "").lower()
        if rel != "stylesheet":
            continue
        href = attrs.get("href", "").strip()
        if not href:
            continue
        absolute_href = urljoin(target, href)
        if not _is_external(absolute_href, target_host):
            continue

        has_integrity = bool(attrs.get("integrity"))
        has_crossorigin = bool(attrs.get("crossorigin"))

        record = {
            "href": absolute_href,
            "has_integrity": has_integrity,
            "has_crossorigin": has_crossorigin,
        }
        external_links.append(record)

        if absolute_href in seen_link_hrefs:
            continue
        seen_link_hrefs.add(absolute_href)

        if not has_integrity:
            _emit_finding(
                title=f"External stylesheet missing SRI integrity hash on {target_host}",
                severity="low",
                target=target_host,
                endpoint=target,
                description=(
                    f"`<link rel=\"stylesheet\" href=\"{absolute_href}\">` "
                    f"loads from an external host without an "
                    f"`integrity=` attribute. CDN compromise → "
                    f"CSS-injection / data-exfiltration via CSS "
                    f"selectors → narrower than `<script>` but real."
                ),
                description_plain=(
                    "Your page loads CSS from an external CDN without "
                    "an integrity hash. CSS injection is less "
                    "dangerous than JavaScript injection, but a "
                    "compromised stylesheet can still exfiltrate "
                    "sensitive data via attribute-selector tricks "
                    "and reskin the UI to phish credentials."
                ),
                recommended_action=(
                    "Add `integrity=\"sha384-...\"` + "
                    "`crossorigin=\"anonymous\"` to every external "
                    "`<link rel=\"stylesheet\">`. Or, host the "
                    "stylesheet on your own origin."
                ),
            )
            findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=(
            f"audited {len(external_scripts)} external script(s) and "
            f"{len(external_links)} external stylesheet(s); "
            f"emitted {findings_emitted} finding(s)"
        ),
    )

    return {
        "success": True,
        "target_url": target,
        "target_host": target_host,
        "assets_examined": len(external_scripts) + len(external_links),
        "external_scripts": external_scripts,
        "external_links": external_links,
        "findings_emitted": findings_emitted,
    }
