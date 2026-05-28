"""Open-redirect prober.

Probe a URL for open-redirect vulnerabilities. Standard pentest
deliverable: when the application redirects to a URL it builds from
a request parameter, an attacker who can send a victim a link to
`https://target.com/login?next=https://attacker.com` can have the
victim land on attacker-controlled infrastructure after authentication
— credential phishing, OAuth-token theft, malware delivery.

Methodology:

1. **Discover redirect-shaped parameters** in the target URL.
   - If the URL has a query string, every parameter whose name
     matches the redirect-name lexicon is treated as a candidate.
   - If the URL has no query string, the tool falls back to probing
     a small default-name set (`next`, `redirect`, `url`, `return`,
     `goto`, `dest`) appended to the URL.
2. **Replay each candidate parameter** with the bypass cohort: 11
   payload variants exercising scheme manipulation, protocol-relative
   URLs, backslash interpretation, `@`-userinfo confusion, encoded
   slashes, query-anchored allow-list bypass, javascript: / data:
   schemes, unicode-confusable hosts.
3. **Inspect each response** for the attacker host appearing in:
   - `Location` / `Content-Location` / `Refresh` response headers
     (3xx redirect or refresh) — high CWE-601.
   - Body `<meta http-equiv="refresh" content="0; url=...">` —
     medium CWE-601 (attacker-controlled redirect, but client-side).
   - Body `window.location = "..."` / `window.location.href = "..."`
     / `location.replace("...")` (any of these) — medium CWE-601.
4. **Per-param dedup**: at most one finding per
   `(param_name, severity)` pair.

Bypass cohort:

| Label | Payload (after substitution) | Class |
|---|---|---|
| `direct_https`        | `https://<attacker>`              | direct_scheme |
| `direct_http`         | `http://<attacker>`               | direct_scheme |
| `protocol_relative`   | `//<attacker>`                    | protocol_relative |
| `backslash_relative`  | `\\\\<attacker>`                  | backslash |
| `userinfo_confusion`  | `https://<target>@<attacker>`     | userinfo |
| `userinfo_confusion2` | `//<attacker>%23@<target>/`       | userinfo |
| `subdomain_confusion` | `https://<target>.<attacker>`     | suffix |
| `query_bypass`        | `https://<attacker>?legit=<target>` | query_bypass |
| `encoded_slash`       | `https:%2f%2f<attacker>`          | encoded |
| `js_scheme`           | `javascript:alert(1)`             | js_scheme |
| `data_scheme`         | `data:text/html,<script>alert(1)</script>` | data_scheme |

Severity tuning:

- **High** (CWE-601, open_redirect) — attacker host appears in
  `Location` / `Content-Location` / `Refresh` response header on a
  3xx response.
- **Medium** (CWE-601) — attacker host appears in body
  `<meta http-equiv="refresh">` content URL, or in a body
  `window.location` / `location.href` / `location.replace`
  assignment.
- **Medium** (CWE-601) — `javascript:` or `data:` scheme reflected
  in a 3xx Location header (XSS adjacent; severity capped at medium
  because most browsers block 30x to javascript: now).
- *(no finding)* — server preserves the param value as a literal
  but doesn't redirect; or rejects with 4xx; or strips/sanitizes.

Composes with cluster-A safety (auth-injection / exclude-path /
rate-limit) — every fetch routes through `proxy_manager` /
`http_safety` direct fallback. Read-only: GET only, follow_redirects=
False (so we observe the 30x decision, not the final target).

Each finding carries `description_plain` + `recommended_action` (the
§11 non-tech UX fields). Recommendation is universal: maintain a
server-side allow-list of redirect targets (relative-path-only OR
exact-match scheme+host); reject any client-supplied target that
isn't on the list; never blindly forward `Location:` based on
`?next=` / `?redirect=` user input.

`verification_status=needs_review` since reflected attacker-host in
the response is a strong signal but ahead of the agent confirming
victim-side browser behavior (some intermediate WAFs / browser
mitigations block the actual redirect even when the server emits it).
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import Any
from urllib.parse import (
    parse_qsl,
    quote,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "open_redirect_check"
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_ATTACKER_BASE = "evil.example"
_MAX_BODY_SCAN = 256 * 1024


# Redirect-shaped parameter name lexicon. Matched case-insensitively
# against query parameter names. Heavy bias toward names that appear
# in real-world apps (e.g. OAuth callback param names).
_REDIRECT_PARAM_NAMES: tuple[str, ...] = (
    "next", "return", "returnurl", "return_url", "returnto", "return_to",
    "redirect", "redirect_uri", "redirect_url", "redirecturl", "redir",
    "goto", "continue", "dest", "destination", "target", "to", "url",
    "image_url", "callback", "back", "path", "forward", "link", "out",
    "rd", "r", "u", "ref", "referrer", "successurl", "success_url",
    "failureurl", "failure_url", "loginredirect", "login_redirect",
    "logout_redirect", "checkout_url", "site",
)

# Default fallback param names when the URL has no query string. Small
# set (vs the full lexicon above) so we don't burn rate-limit budget
# probing irrelevant names.
_DEFAULT_FALLBACK_PARAMS: tuple[str, ...] = (
    "next", "redirect", "url", "return", "goto", "dest",
)


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety (no follow-redirects). Returns
    {status, headers, body, error?, skipped?}."""
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
                "body": r.get("body") or "",
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
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_BODY_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Target / parameter handling
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    """Return canonical URL with explicit scheme. Default to https for
    bare hostnames."""
    if not target or not isinstance(target, str):
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


def _discover_redirect_params(target_url: str) -> list[tuple[str, str]]:
    """Return [(param_name, original_value), ...] from the URL's query
    string, filtered to redirect-name-shaped params.

    If the URL has no query string, returns an empty list (the caller
    falls back to default-param probing).
    """
    parsed = urlparse(target_url)
    if not parsed.query:
        return []
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    candidates: list[tuple[str, str]] = []
    for name, value in pairs:
        if name.lower() in _REDIRECT_PARAM_NAMES:
            candidates.append((name, value))
    return candidates


# iter-Q7.4 — page form / href param-name discovery. The fan-out
# dispatches `open_redirect_check(target_url=<bare crawled URL>)` with
# no query string; pre-Q7.4 that fell back to a 6-name default set
# (`next, redirect, url, return, goto, dest`), missing redirect params
# rendered in an on-page <form> or example links (the bare-path
# redirect-endpoint recall gap). Discovery fetches the page and pulls
# candidate param names from <form> input fields + same-origin <a href>
# query keys, ranking redirect-shaped names first.
_HTML_FIELD_NAME_RE = re.compile(
    r"<(?:input|textarea|select)\b[^>]*\bname\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_HTML_HREF_RE = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["']([^"'#>]+)["']""", re.IGNORECASE,
)


def _discover_redirect_param_names(target_url: str, timeout: float) -> list[str]:
    """Fetch the page; return candidate redirect param names from its
    form fields + same-origin href query keys. Redirect-shaped names
    (in `_REDIRECT_PARAM_NAMES`) are ordered first."""
    resp = _http_get(target_url, timeout=timeout)
    body = resp.get("body") or ""
    if not isinstance(body, str) or not body:
        return []
    origin = urlparse(target_url)
    names: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    for m in _HTML_FIELD_NAME_RE.finditer(body):
        _add(m.group(1))
    for hm in _HTML_HREF_RE.finditer(body):
        href = urljoin(target_url, hm.group(1))
        hp = urlparse(href)
        if hp.netloc and origin.netloc and hp.netloc != origin.netloc:
            continue
        for k, _v in parse_qsl(hp.query, keep_blank_values=True):
            _add(k)

    lex = set(_REDIRECT_PARAM_NAMES)
    names.sort(key=lambda n: (n.lower() not in lex, n.lower()))
    return names


def _build_url_with_param(
    base_url: str, param_name: str, payload: str, preserve_others: bool
) -> str:
    """Reconstruct `base_url` with `param_name=payload`.

    `preserve_others=True` retains every other query parameter at its
    existing value. `preserve_others=False` (used in default-fallback
    probing) drops the whole query string and re-emits with just the
    new param.
    """
    parsed = urlparse(base_url)
    if preserve_others and parsed.query:
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        new_pairs: list[tuple[str, str]] = []
        replaced = False
        for n, v in pairs:
            if n == param_name and not replaced:
                new_pairs.append((n, payload))
                replaced = True
            else:
                new_pairs.append((n, v))
        if not replaced:
            new_pairs.append((param_name, payload))
        # quote_via=quote so payload chars like `@`, `:`, `/`, `\\`
        # round-trip into the URL bytes the server actually sees.
        new_query = urlencode(new_pairs, quote_via=quote)
    else:
        new_query = urlencode([(param_name, payload)], quote_via=quote)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, "",
    ))


# ---------------------------------------------------------------------------
# Bypass cohort
# ---------------------------------------------------------------------------


def _build_payloads(target_host: str, attacker_host: str) -> list[dict[str, str]]:
    """Generate the open-redirect bypass cohort. Each entry is
    `{label, payload, class_}`."""
    return [
        {"label": "direct_https",
         "payload": f"https://{attacker_host}",
         "class_": "direct_scheme"},
        {"label": "direct_http",
         "payload": f"http://{attacker_host}",
         "class_": "direct_scheme"},
        {"label": "protocol_relative",
         "payload": f"//{attacker_host}",
         "class_": "protocol_relative"},
        {"label": "backslash_relative",
         "payload": f"\\\\{attacker_host}",
         "class_": "backslash"},
        {"label": "userinfo_confusion",
         "payload": f"https://{target_host}@{attacker_host}",
         "class_": "userinfo"},
        {"label": "userinfo_confusion2",
         "payload": f"//{attacker_host}%23@{target_host}/",
         "class_": "userinfo"},
        {"label": "subdomain_confusion",
         "payload": f"https://{target_host}.{attacker_host}",
         "class_": "suffix"},
        {"label": "query_bypass",
         "payload": f"https://{attacker_host}?legit={target_host}",
         "class_": "query_bypass"},
        {"label": "encoded_slash",
         "payload": f"https:%2f%2f{attacker_host}",
         "class_": "encoded"},
        {"label": "js_scheme",
         "payload": "javascript:alert(1)",
         "class_": "js_scheme"},
        {"label": "data_scheme",
         "payload": "data:text/html,<script>alert(1)</script>",
         "class_": "data_scheme"},
    ]


# ---------------------------------------------------------------------------
# Reflection detection
# ---------------------------------------------------------------------------


_LOCATION_HEADERS = ("location", "content-location", "refresh")
_META_REFRESH_RE = re.compile(
    r"(?i)<meta[^>]+http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*content\s*=\s*[\"']?\s*\d+\s*;?\s*url\s*=\s*([^\"'>\s]+)",
)
_WINDOW_LOCATION_RE = re.compile(
    r"""(?i)(?:window\s*\.\s*)?location\s*(?:\.\s*(?:href|replace))?\s*[\(=]\s*[\"']([^\"']+)[\"']"""
)


def _normalize_for_match(s: str) -> str:
    """Strip whitespace, leading/trailing quotes, common URL-encoding noise."""
    if not s:
        return ""
    s = s.strip().strip('"\'')
    return s


def _location_redirects_to(value: str, attacker_host: str) -> bool:
    """Return True if a `Location:`-like value redirects to attacker_host."""
    if not value or not attacker_host:
        return False
    norm = _normalize_for_match(value).lower()
    needle = attacker_host.lower()
    if not norm:
        return False

    # Direct: `https://attacker`, `http://attacker`, `//attacker`,
    # encoded variants. The scheme prefix MUST be at the start — a
    # path like `/foo-https://x.com/y` is not a redirect, just a
    # path on the same origin.
    candidates: list[str] = []
    if norm.startswith("//"):
        candidates.append(norm[2:])
    elif norm.startswith(("http://", "https://", "ftp://", "javascript:", "data:")):
        # Generic absolute URL.
        if ":" in norm:
            scheme_split = norm.split("://", 1)
            if len(scheme_split) == 2:
                candidates.append(scheme_split[1])
            else:
                # `javascript:` / `data:` — not netloc-shaped, no redirect to host.
                return False
    elif norm.startswith("\\\\"):
        candidates.append(norm[2:])
    elif norm.startswith(("https:%2f%2f", "http:%2f%2f")):
        candidates.append(norm.split("%2f%2f", 1)[1])
    else:
        # Relative path or arbitrary other content; not an open redirect.
        return False

    for cand in candidates:
        # Strip path / query / fragment.
        for delim in ("/", "?", "#"):
            if delim in cand:
                cand = cand.split(delim, 1)[0]
                break
        # Strip userinfo segment if present.
        if "@" in cand:
            cand = cand.rsplit("@", 1)[1]
        # Strip explicit port.
        if ":" in cand:
            cand = cand.split(":", 1)[0]
        if not cand:
            continue
        if cand == needle:
            return True
        # `target.com.attacker.com` — netloc is `attacker.com` if the
        # server interprets the trailing label, but we conservatively
        # only fire if the suffix is exactly attacker_host preceded by
        # `.`.
        if cand.endswith("." + needle):
            return True
    return False


def _scan_response_for_attacker(
    response: dict[str, Any], attacker_host: str
) -> dict[str, Any]:
    """Inspect response for attacker host placement.

    Returns:
        {
          "header_redirect": str | None,   # name of redirect header
          "header_value": str | None,
          "scheme_in_header": str | None,  # 'js' / 'data' / None
          "meta_refresh": str | None,      # body URL
          "window_location": str | None,
        }
    """
    out: dict[str, Any] = {
        "header_redirect": None, "header_value": None,
        "scheme_in_header": None, "meta_refresh": None,
        "window_location": None,
    }
    if not attacker_host:
        return out

    headers = response.get("headers") or {}
    for hname in _LOCATION_HEADERS:
        value = headers.get(hname)
        if not value:
            continue
        norm_value = _normalize_for_match(value)
        # Capture js/data scheme reflections in Location separately —
        # they're treated as a different severity tier than HTTP/HTTPS
        # redirects to the attacker.
        if norm_value.lower().startswith("javascript:"):
            out["header_redirect"] = hname
            out["header_value"] = value
            out["scheme_in_header"] = "js"
            return out
        if norm_value.lower().startswith("data:"):
            out["header_redirect"] = hname
            out["header_value"] = value
            out["scheme_in_header"] = "data"
            return out
        if _location_redirects_to(value, attacker_host):
            out["header_redirect"] = hname
            out["header_value"] = value
            return out

    body = response.get("body") or ""
    if not body:
        return out
    body_scan = body[:_MAX_BODY_SCAN]

    for m in _META_REFRESH_RE.finditer(body_scan):
        url_val = m.group(1)
        if _location_redirects_to(url_val, attacker_host):
            out["meta_refresh"] = url_val
            break

    if not out["window_location"]:
        for m in _WINDOW_LOCATION_RE.finditer(body_scan):
            url_val = m.group(1)
            if _location_redirects_to(url_val, attacker_host):
                out["window_location"] = url_val
                break

    return out


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
    finding_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="open_redirect",
        cwe="CWE-601",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Open redirects let an attacker land a victim on attacker-"
            "controlled infrastructure after the victim has clicked a "
            "trusted-host link. Routine real-world uses: phishing chains "
            "(harvest credentials on a fake login page that looks like "
            "the trusted host), OAuth-token theft (an attacker-supplied "
            "redirect URL pulls the victim's authorization code into "
            "the attacker's server), malware delivery, and CSP / HSTS "
            "bypass for downstream attacks. Browser warnings have not "
            "removed this from the standard pentest deliverable."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )
    # §3 KG side-effect.
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=endpoint, param="redirect_url",
            cwe="CWE-601", severity=severity, category="open_redirect",
            method="GET",
            detection_kind=title[:60],
            confidence=0.9,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "open_redirect: kg record failed: %s", e, exc_info=True,
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
    mitre_techniques=["T1204.001"],  # User Execution: Malicious Link
)
def open_redirect_check(
    target_url: str,
    extra_param_names: list[str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    attacker_host: str | None = None,
) -> dict[str, Any]:
    """Probe a URL for open-redirect vulnerabilities.

    Args:
        target_url: URL to probe. Bare hostnames are auto-prefixed
            with `https://`. If the URL has a query string, the tool
            looks for redirect-shaped param names in it. If the URL
            has no query string, the tool falls back to probing a
            small default-name set (`next`, `redirect`, `url`,
            `return`, `goto`, `dest`) appended to the URL.
        extra_param_names: Additional param names to probe regardless
            of whether the target URL already has them. Useful when
            the agent has discovered a non-standard redirect param
            via crawl analysis.
        timeout: Per-probe timeout in seconds (default 10).
        attacker_host: Override the attacker host used in payloads.
            Default: a unique random `strix-<nonce>.evil.example`
            subdomain so probes are auditable in target logs.

    Returns:
        {
          success, target_url, target_host, attacker_host,
          probed_params: [name, ...],
          probes: [
            {param, label, class_, payload, status, evidence: {...},
             finding_severity},
            ...
          ],
          findings_emitted: int
        }

    Findings:
        - **High** (CWE-601, open_redirect) — attacker host appears
          in `Location` / `Content-Location` / `Refresh` response
          header on a 3xx response.
        - **Medium** (CWE-601) — attacker host appears in body
          `<meta http-equiv="refresh">` content URL or in
          `window.location` / `location.href` / `location.replace`
          assignment.
        - **Medium** (CWE-601) — `javascript:` or `data:` scheme
          reflected in a 3xx Location header.

    Notes:
        - Read-only: GET only, no follow-redirects so the 30x
          decision is observable.
        - Composes with cluster-A safety: `--exclude-path` /
          `--rate-limit` / `--auth-*` apply to every probe.
        - Per-param dedup: at most one finding per
          `(param_name, severity)` pair so an 11-payload cohort
          against a single vulnerable param produces one report.
        - `verification_status=needs_review` since reflected attacker-
          host in the response is a strong signal but the agent should
          confirm victim-side browser behavior (some intermediate WAFs
          / browser mitigations block the actual redirect even when
          the server emits it).
    """
    target_url_norm = _normalize_target(target_url)
    if target_url_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target_url_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    # Pin a unique attacker host per run.
    base_attacker = attacker_host or _DEFAULT_ATTACKER_BASE
    nonce = secrets.token_hex(4)
    attacker = f"strix-{nonce}.{base_attacker}"

    cev = _start_check("open_redirect", target_host)

    # Discover redirect-shaped params on the target.
    discovered = _discover_redirect_params(target_url_norm)
    discovered_names = {n for n, _ in discovered}

    # Extra param names (agent-supplied) get probed too. Default-
    # fallback names probe ONLY when the target had no candidates.
    probe_param_names: list[str] = []
    for n, _ in discovered:
        if n not in probe_param_names:
            probe_param_names.append(n)
    if extra_param_names:
        for n in extra_param_names:
            if n and n not in probe_param_names:
                probe_param_names.append(n)
    if not discovered and not extra_param_names:
        # iter-Q7.4 — bare URL: discover redirect param names from the
        # page (form fields + href query keys) before resorting to the
        # blind default set. Discovered names are GET-probed via the
        # existing machinery; the 6 defaults always ride along (cheap).
        try:
            for n in _discover_redirect_param_names(target_url_norm, timeout)[:15]:
                if n not in probe_param_names:
                    probe_param_names.append(n)
        except Exception:  # noqa: BLE001
            logger.debug("open_redirect: param discovery failed", exc_info=True)
        for n in _DEFAULT_FALLBACK_PARAMS:
            if n not in probe_param_names:
                probe_param_names.append(n)

    payloads = _build_payloads(target_host, attacker)

    findings_emitted = 0
    probe_results: list[dict[str, Any]] = []
    seen_dedup_keys: set[tuple[str, str]] = set()

    for param_name in probe_param_names:
        # Preserve other query params iff this param was actually present
        # in the original URL's query.
        preserve_others = param_name in discovered_names

        for payload in payloads:
            probe_url = _build_url_with_param(
                target_url_norm,
                param_name=param_name,
                payload=payload["payload"],
                preserve_others=preserve_others,
            )
            response = _http_get(probe_url, timeout=timeout)

            if response.get("skipped"):
                probe_results.append({
                    "param": param_name,
                    "label": payload["label"],
                    "class_": payload["class_"],
                    "payload": payload["payload"],
                    "status": 0,
                    "evidence": {"skipped": True},
                    "finding_severity": None,
                    "reason": "skipped by cluster-A path filter",
                })
                continue
            if response.get("error"):
                probe_results.append({
                    "param": param_name,
                    "label": payload["label"],
                    "class_": payload["class_"],
                    "payload": payload["payload"],
                    "status": 0,
                    "evidence": {"error": response["error"]},
                    "finding_severity": None,
                })
                continue

            evidence = _scan_response_for_attacker(response, attacker)

            severity: str | None = None
            scheme_class = evidence.get("scheme_in_header")
            if evidence.get("header_redirect") and scheme_class is None:
                # Plain http(s) attacker host in a redirect header.
                # Confirm the response actually IS a 3xx (Refresh / Content-
                # Location can appear on 200s too — those still count
                # but at the same severity).
                severity = "high"
            elif scheme_class in ("js", "data"):
                # javascript: / data: in Location: medium (capped).
                severity = "medium"
            elif evidence.get("meta_refresh") or evidence.get("window_location"):
                severity = "medium"

            verdict = {
                "param": param_name,
                "label": payload["label"],
                "class_": payload["class_"],
                "payload": payload["payload"],
                "status": response.get("status", 0),
                "evidence": evidence,
                "finding_severity": severity,
            }
            probe_results.append(verdict)

            if severity is None:
                continue

            dedup_key = (param_name, severity)
            if dedup_key in seen_dedup_keys:
                continue
            seen_dedup_keys.add(dedup_key)

            # Build finding text per severity.
            if severity == "high":
                if scheme_class == "js":
                    title = (
                        f"Open redirect via javascript: scheme in `{param_name}` "
                        f"on {target_host}"
                    )
                elif scheme_class == "data":
                    title = (
                        f"Open redirect via data: scheme in `{param_name}` "
                        f"on {target_host}"
                    )
                else:
                    title = (
                        f"Open redirect — attacker host in {evidence['header_redirect']} "
                        f"header via `{param_name}` on {target_host}"
                    )
                description_plain = (
                    "Your application redirects to a URL that an attacker "
                    "can control via a request parameter. An attacker can "
                    "send a victim a link to your site and have the victim "
                    "land on attacker-controlled infrastructure after they "
                    "click — used for credential phishing, OAuth-token "
                    "theft, and malware delivery."
                )
                recommended_action = (
                    "Maintain a server-side allow-list of redirect targets. "
                    "Reject any client-supplied target that isn't on the "
                    "list. Prefer relative paths (`/dashboard`) over full "
                    "URLs in the `?next=` parameter; if absolute URLs are "
                    "required, validate `(scheme, host)` against an exact-"
                    "match allow-list. Treat `//host`, `\\\\host`, and "
                    "user-info forms (`https://target@evil.com`) as absolute "
                    "URLs during validation, not as relative paths."
                )
            else:  # medium — meta refresh, window.location, js/data scheme
                if evidence.get("meta_refresh"):
                    title = (
                        f"Open redirect via `<meta http-equiv=refresh>` "
                        f"on `{param_name}` parameter at {target_host}"
                    )
                elif evidence.get("window_location"):
                    title = (
                        f"Open redirect via `window.location` body "
                        f"redirect on `{param_name}` parameter at {target_host}"
                    )
                else:
                    scheme_label = "javascript" if scheme_class == "js" else "data"
                    title = (
                        f"Open redirect via `{scheme_label}:` scheme on "
                        f"`{param_name}` parameter at {target_host}"
                    )
                description_plain = (
                    "Your application returns a page that contains an "
                    "attacker-controlled redirect target — either a "
                    "`<meta refresh>` tag or a JavaScript `location` "
                    "assignment built from a request parameter. This is "
                    "client-side, but attackers exploit it the same way "
                    "as a server-side redirect."
                )
                recommended_action = (
                    "Same fix as server-side open redirect: maintain an "
                    "allow-list of valid redirect targets server-side. "
                    "Don't render attacker-supplied URLs into "
                    "`<meta refresh>` or JavaScript `location` "
                    "assignments. If you must, escape and re-validate as "
                    "an absolute URL (relative paths only by default)."
                )

            description = (
                f"Probe `{payload['label']}` on parameter `{param_name}` "
                f"(payload=`{payload['payload']}`) → status={response.get('status')}, "
                f"evidence={evidence}. Attacker host: `{attacker}`."
            )
            _emit_finding(
                title=title,
                severity=severity,
                target=target_host,
                endpoint=probe_url,
                description=description,
                description_plain=description_plain,
                recommended_action=recommended_action,
            )
            findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} open-redirect finding(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url_norm,
        "target_host": target_host,
        "attacker_host": attacker,
        "probed_params": probe_param_names,
        "probes": probe_results,
        "findings_emitted": findings_emitted,
    }
