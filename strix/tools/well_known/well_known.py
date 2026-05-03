"""`.well-known/` endpoint harvester.

Roadmap §7.3 expert-pentester gap audit. Probes the IETF-registered
well-known paths (RFC 8615 + RFC 9116 + ad-hoc industry standards) on
a target host; emits one info-severity finding per hit, capturing
the contents (length-capped) so the agent can read it without a
follow-up fetch.

Hits frequently include:
- `security.txt` — security-contact + scope (highest-value: tells you
  the disclosure policy, often credits, sometimes private endpoints)
- `openid-configuration` — tenant ID + every OAuth endpoint + JWKS URL
- `oauth-authorization-server` — OAuth 2.x metadata
- `change-password` — RFC 8615 well-known redirect for password-mgr
- `host-meta` (XRD) — WebFinger metadata
- `assetlinks.json` — Android digital asset link verification
- `apple-app-site-association` — iOS universal-link / app-binding

Composes with cluster-A safety (auth-injection / exclude-path / rate-
limit) automatically — every fetch routes through the proxy or the
direct fallback that uses the same env-driven `http_safety` middleware.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "well_known_harvest"
_HTTP_TIMEOUT = 12

# Body cap per probe — well-known files should be small. Anything bigger
# is suspicious and we still capture only the head.
_BODY_CAP_BYTES = 32 * 1024


# Each entry: (path, label, expected_content_type_hint, parser).
# `parser` returns a small dict of structured fields; None means "no
# parsing, just record presence". The label appears in the finding title.
_WELL_KNOWN_PATHS: tuple[tuple[str, str, str, str], ...] = (
    ("/.well-known/security.txt", "security.txt", "text", "security_txt"),
    ("/.well-known/openid-configuration", "OpenID Connect discovery", "json", "json"),
    ("/.well-known/oauth-authorization-server", "OAuth 2.0 authorization server metadata", "json", "json"),
    ("/.well-known/change-password", "RFC 8615 change-password redirect", "text", "redirect"),
    ("/.well-known/host-meta", "host-meta (XRD)", "xml", "raw"),
    ("/.well-known/host-meta.json", "host-meta (JSON)", "json", "json"),
    ("/.well-known/assetlinks.json", "Android asset links", "json", "json"),
    ("/.well-known/apple-app-site-association", "iOS app-site association", "json", "json"),
    ("/.well-known/gpc.json", "Global Privacy Control", "json", "json"),
    ("/.well-known/dnt-policy.txt", "Do Not Track policy", "text", "raw"),
    ("/.well-known/pki-validation/", "ACME / PKI validation directory", "html", "raw"),
    ("/humans.txt", "humans.txt", "text", "raw"),
    ("/security.txt", "security.txt (legacy root)", "text", "security_txt"),
)

# security.txt key:value lines — case-insensitive on the key.
_SECURITY_TXT_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z\-]*?)\s*:\s*(.+?)\s*$", re.MULTILINE)


def _http_get(url: str) -> dict[str, Any]:
    """GET with cluster-A safety. Returns {status, headers, body, location?}."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=_HTTP_TIMEOUT)
            return {
                "status": int(r.get("status_code") or 0),
                "headers": r.get("headers") or {},
                "body": r.get("body") or "",
                "skipped": bool(r.get("skipped")),
                "error": r.get("error"),
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            excluded_response,
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, glob = is_path_excluded(url)
        if excluded:
            return {**excluded_response(url, glob or ""), "status": 0}
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:_BODY_CAP_BYTES],
                "skipped": False,
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _parse_security_txt(body: str) -> dict[str, Any]:
    """RFC 9116 — extract key:value lines (Contact, Encryption, Acknowledgments,
    Canonical, Expires, Policy, Hiring, Preferred-Languages)."""
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        m = _SECURITY_TXT_LINE_RE.match(line)
        if m:
            key = m.group(1).strip().lower()
            value = m.group(2).strip()
            fields.setdefault(key, []).append(value)
    # Collapse single-value fields for readability.
    return {k: (v[0] if len(v) == 1 else v) for k, v in fields.items()}


def _parse_well_known_json(body: str) -> dict[str, Any] | None:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return {"_raw_top_level_type": type(data).__name__}
    # Capture only the most-useful keys to avoid bloating the finding.
    interesting_keys = (
        "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
        "userinfo_endpoint", "registration_endpoint", "end_session_endpoint",
        "introspection_endpoint", "revocation_endpoint", "device_authorization_endpoint",
        "scopes_supported", "response_types_supported", "grant_types_supported",
        "id_token_signing_alg_values_supported", "subject_types_supported",
        "applinks", "webcredentials", "appclips", "activitycontinuation",  # apple
        "relations", "target",  # assetlinks
        "version", "value",  # gpc
    )
    out: dict[str, Any] = {}
    for k in interesting_keys:
        if k in data:
            v = data[k]
            # Flatten lists of dicts to type-name + count to keep payload small.
            if isinstance(v, list) and v and isinstance(v[0], dict):
                out[k] = f"<{len(v)} entries>"
            elif isinstance(v, str) and len(v) > 200:
                out[k] = v[:200] + "..."
            else:
                out[k] = v
    return out or {"_keys": sorted(data.keys())[:30]}


def _origin_root(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


def _content_type(headers: dict[str, str]) -> str:
    return (
        headers.get("content-type")
        or headers.get("Content-Type")
        or ""
    ).split(";")[0].strip().lower()


def _emit_finding(
    *,
    title: str,
    severity: str,
    category: str,
    cwe: str,
    target: str,
    endpoint: str,
    description: str,
    impact: str,
    remediation: str,
    description_plain: str | None = None,
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
        category=category,
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        description=description,
        impact=impact,
        remediation_steps=remediation,
        description_plain=description_plain,
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


@register_tool(sandbox_execution=True)
def well_known_harvest(
    target: str,
    *,
    include_legacy: bool = True,
) -> dict[str, Any]:
    """Probe the standard `.well-known/` paths on a target host.

    Args:
        target: target URL or hostname (e.g. `https://example.com` or
                `example.com`). The tool builds `<origin>/.well-known/<path>`
                URLs from this.
        include_legacy: when True (default), also probes legacy locations
                        like `/security.txt` (root) and `/humans.txt`.
                        Disable for strict RFC 8615 compliance.

    Returns:
        {
          success, target,
          probed: int,
          hits: [{path, label, status, content_type, parsed: {...} | None,
                  body_excerpt}],
          errors: [{path, error}],
          stats: {hits, errors_count}
        }

    Findings: one info-severity (CWE-200, info_disclosure) per hit
    capturing the parsed metadata. `security.txt` (or `openid-configuration`,
    or `apple-app-site-association`) hits get `description_plain` populated
    automatically with what the field discloses in lay terms.
    """
    if not target or not target.strip():
        return {"success": False, "error": "target required"}
    base = _origin_root(target)
    if not base:
        return {"success": False, "error": f"invalid target URL: {target!r}"}

    paths_to_probe = list(_WELL_KNOWN_PATHS)
    if not include_legacy:
        paths_to_probe = [p for p in paths_to_probe if p[0].startswith("/.well-known/")]

    hits: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    cev = _start_check("well_known_harvest", base)

    for path, label, _ct_hint, parser in paths_to_probe:
        url = urljoin(base, path)
        response = _http_get(url)
        status = response.get("status") or 0
        if response.get("skipped"):
            errors.append({"path": path, "error": "excluded by --exclude-path"})
            continue
        if response.get("error"):
            errors.append({"path": path, "error": str(response["error"])[:200]})
            continue
        if status == 0 or status >= 400:
            # 404 / 403 / 401 — not a hit, nothing to log loudly.
            continue
        # 200 / 3xx — treat as a hit.
        body = response.get("body", "") or ""
        ct = _content_type(response.get("headers") or {})
        excerpt = body[:600] if body else ""
        parsed: dict[str, Any] | None = None
        plain_summary: str | None = None
        if parser == "security_txt":
            parsed = _parse_security_txt(body) if body else {}
            if parsed.get("contact"):
                plain_summary = (
                    f"This site publishes a security contact: "
                    f"{parsed['contact']}. Treat as the official disclosure "
                    "channel — no need to find one through guesswork."
                )
        elif parser == "json":
            parsed = _parse_well_known_json(body)
            if path.endswith("openid-configuration") and parsed and parsed.get("issuer"):
                plain_summary = (
                    f"This site uses OpenID Connect / OAuth 2.0 for sign-in. "
                    f"Issuer: {parsed['issuer']}. The full set of OAuth "
                    "endpoints is published in the metadata."
                )
            elif path.endswith("apple-app-site-association"):
                plain_summary = (
                    "This site has an iOS app paired to it. The association "
                    "file lists the universal-link paths the app handles."
                )
        elif parser == "redirect":
            location = (
                response.get("headers", {}).get("location")
                or response.get("headers", {}).get("Location")
            )
            parsed = {"location": location} if location else None

        hit_record = {
            "path": path,
            "label": label,
            "status": status,
            "content_type": ct,
            "parsed": parsed,
            "body_excerpt": excerpt,
        }
        hits.append(hit_record)

        # Emit per-hit info finding.
        description_lines = [f"{label} disclosed at {url} (status {status})."]
        if parsed:
            description_lines.append(f"Parsed metadata: {json.dumps(parsed, default=str)[:600]}")
        if excerpt:
            description_lines.append(f"Body excerpt: {excerpt[:300]}")

        _emit_finding(
            title=f"{label} discovered at {url}",
            severity="info",
            category="info_disclosure",
            cwe="CWE-200",
            target=base,
            endpoint=url,
            description="\n\n".join(description_lines),
            impact=(
                "Well-known endpoints are publicly designed and not vulns on "
                "their own. They reveal architecture (OAuth endpoints, app "
                "associations, security-contact policies) which accelerates "
                "downstream reconnaissance and exploit chaining. Notable: "
                "`security.txt` confirms the disclosure policy; "
                "`openid-configuration` exposes the JWKS URL and full "
                "OAuth surface; `apple-app-site-association` reveals iOS "
                "app pairings."
            ),
            remediation=(
                "If the endpoint is intentionally published (security.txt, "
                "openid-configuration, etc.), no action needed. If it leaked "
                "by accident (debug toolbar, framework default, dev artifact), "
                "remove or restrict it via WAF / config flag in production."
            ),
            description_plain=plain_summary,
        )

    _complete_check(
        cev,
        result="not_vulnerable" if hits else "inconclusive",
        evidence=f"{len(hits)}/{len(paths_to_probe)} well-known paths responded; {len(errors)} errors",
    )

    return {
        "success": True,
        "target": base,
        "probed": len(paths_to_probe),
        "hits": hits,
        "errors": errors,
        "stats": {
            "hits": len(hits),
            "errors_count": len(errors),
        },
    }
