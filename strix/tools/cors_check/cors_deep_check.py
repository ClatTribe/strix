"""CORS deep-probe.

Goes beyond the static reflection check in `http_headers` (#47) and
probes the laxity classes that exploit framework string-matching
bugs:

- **`Origin: null`** — sandboxed iframes, `data:` URIs, and some
  cross-origin redirects send `Origin: null`. Servers that
  reflect `null` plus `Access-Control-Allow-Credentials: true` give
  any sandbox-iframe attacker full credentialed access.
- **Subdomain-suffix bypass** — `evil.com.target.com` (the legit
  netloc as a left-side label) is a real-world hit when the server
  matches `Origin` with `endswith("target.com")`.
- **Subdomain-prefix bypass** — `target.com.evil.com` is a hit when
  the server matches with `startswith("target.com")` or a regex
  that doesn't anchor on `^...$`.
- **Subdomain-substring bypass** — `https://target.com.evil.com`
  reflected catches a substring match.
- **Trailing-slash bypass** — `https://target.com/` (trailing
  slash) matched against an allow-list of bare-host strings.
- **Scheme bypass** — `http://target.com` reflected when the
  intended allow-list is `https`-only.
- **Userinfo confusion** — `https://target.com@evil.com` — some
  CORS validators parse the host segment incorrectly.
- **Backslash bypass** — `https://target.com\\.evil.com` —
  exploits parsers that treat `\\` as a delimiter.
- **Backtick bypass** — `https://target.com\`.evil.com` — Chrome
  accepts backtick in some contexts; servers using regex without
  the right escapes do too.
- **Pre-flight method laxity** — sends `OPTIONS` with
  `Access-Control-Request-Method: TRACE` (or `DELETE`,
  `CONNECT`); flags servers that echo it back into
  `Access-Control-Allow-Methods` (means the server doesn't
  validate which methods are intended for CORS).
- **Pre-flight header laxity** — sends `OPTIONS` with
  `Access-Control-Request-Headers: X-Bogus-Header`; flags
  servers that echo arbitrary header names into
  `Access-Control-Allow-Headers`.

Each probe constructs an attacker-origin variant, sends it as the
`Origin` request header (GET) or the appropriate pre-flight
request, and inspects the response's CORS headers.

Severity — every dispatched probe is judged independently:

- **Critical** (CWE-942) — attacker origin reflected in
  `Access-Control-Allow-Origin` AND `Access-Control-Allow-Credentials:
  true`. Any of the bypass variants here is a credentialed-access
  bypass.
- **High** (CWE-942) — attacker origin reflected without
  credentials, OR `null` reflection with credentials.
- **Medium** (CWE-942) — pre-flight allow-methods / allow-headers
  laxity (server echoes arbitrary method / header names back).

Skip / soft-fail:

- Baseline GET non-2xx → tool exits gracefully with `inconclusive`.
  We can still try the OPTIONS pre-flight probes (those don't
  require a 2xx baseline).
- Cluster-A `--exclude-path` blocks the URL → graceful no-op.

Each finding carries `description_plain` + `recommended_action`
(replace dynamic Origin reflection with an explicit allow-list of
trusted origins; reject `null` Origins; never set
`Access-Control-Allow-Credentials: true` alongside wildcard or
reflected origins; explicitly list intended methods / headers in
the pre-flight response — don't echo arbitrary values).

`verification_status=needs_review` since reflection alone doesn't
always equal exploitable in the customer's threat model.

Composes with cluster-A safety. MITRE T1190.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "cors_deep_check"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 64 * 1024


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Send an HTTP request via cluster-A safety. Returns
    {status, headers, body, error?, skipped?}."""
    headers = dict(headers or {})

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers, timeout=int(timeout)
            )
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
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.request(method, url, headers=merged)
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
# Origin construction
# ---------------------------------------------------------------------------


def _build_origin_probes(
    target_host: str,
    target_scheme: str,
    nonce: str,
) -> list[tuple[str, str]]:
    """Build the (label, origin) probe list for the GET-with-Origin
    cohort. The attacker host is `strix-<nonce>.evil.example`."""
    attacker = f"strix-{nonce}.evil.example"

    probes: list[tuple[str, str]] = [
        ("null_origin", "null"),
        ("baseline_evil", f"https://{attacker}"),
        ("subdomain_suffix", f"https://{attacker}.{target_host}"),
        ("subdomain_prefix", f"https://{target_host}.{attacker}"),
        ("subdomain_substring", f"https://{target_host}-{attacker}"),
        ("trailing_slash", f"https://{target_host}/"),
        ("scheme_swap", f"http://{target_host}" if target_scheme == "https" else f"https://{target_host}"),
        ("userinfo_confusion", f"https://{target_host}@{attacker}"),
        ("backslash_bypass", f"https://{target_host}\\.{attacker}"),
        ("backtick_bypass", f"https://{target_host}`.{attacker}"),
    ]
    return probes


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
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


def _origin_reflected(probe_origin: str, response_aco: str) -> bool:
    """True if the response Access-Control-Allow-Origin equals our
    probe origin (case-insensitive, with optional trailing-slash
    tolerance)."""
    if not response_aco:
        return False
    aco = response_aco.strip().lower()
    probe = probe_origin.strip().lower()
    if aco == probe:
        return True
    # Tolerate the rare case where the server strips a trailing
    # slash before reflecting.
    if probe.endswith("/") and aco == probe.rstrip("/"):
        return True
    if aco.endswith("/") and probe == aco.rstrip("/"):
        return True
    return False


def _classify(
    label: str,
    probe_origin: str,
    response_headers: dict[str, str],
) -> dict[str, Any]:
    """Return verdict dict with severity / evidence for one probe."""
    aco = (response_headers.get("access-control-allow-origin") or "").strip()
    acc = (response_headers.get("access-control-allow-credentials") or "").strip().lower()
    credentialed = acc == "true"

    reflected = _origin_reflected(probe_origin, aco)
    is_wildcard = aco == "*"

    severity: str | None = None
    evidence_lines: list[str] = []
    issue: str | None = None

    if label == "null_origin":
        if reflected and credentialed:
            severity = "high"
            issue = "null_with_credentials"
            evidence_lines.append(
                "Server reflected `Origin: null` and set "
                "`Access-Control-Allow-Credentials: true`."
            )
        elif reflected:
            severity = "medium"
            issue = "null_reflected"
            evidence_lines.append("Server reflected `Origin: null`.")
    elif label == "scheme_swap":
        if reflected:
            severity = "high" if credentialed else "medium"
            issue = "scheme_bypass"
            evidence_lines.append(
                f"Server reflected the scheme-swapped origin "
                f"`{probe_origin}`. Allow-Credentials: {credentialed}."
            )
    elif label == "trailing_slash":
        if reflected:
            severity = "high" if credentialed else "medium"
            issue = "trailing_slash_bypass"
            evidence_lines.append(
                f"Server reflected the trailing-slash variant "
                f"`{probe_origin}`."
            )
    else:
        # All other labels → these all encode the attacker host
        # somewhere in the origin string; reflection means a CORS
        # validator bypass.
        if reflected:
            if credentialed:
                severity = "critical"
                issue = f"{label}_with_credentials"
            else:
                severity = "high"
                issue = label
            evidence_lines.append(
                f"Server reflected attacker-controlled origin "
                f"`{probe_origin}` in Access-Control-Allow-Origin. "
                f"Allow-Credentials: {credentialed}."
            )

    if is_wildcard and credentialed and severity is None:
        severity = "high"
        issue = "wildcard_with_credentials"
        evidence_lines.append(
            "Server returns `Access-Control-Allow-Origin: *` with "
            "`Access-Control-Allow-Credentials: true`. Browsers reject "
            "this combination, but it documents developer intent to "
            "allow any origin — replace with explicit allow-list."
        )

    return {
        "label": label,
        "probe_origin": probe_origin,
        "reflected": reflected,
        "credentialed": credentialed,
        "wildcard": is_wildcard,
        "severity": severity,
        "issue": issue,
        "evidence": " ".join(evidence_lines) if evidence_lines else "",
        "aco_header": aco,
        "acc_header": acc,
    }


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
        category="cors_misconfiguration",
        cwe="CWE-942",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "CORS misconfiguration breaks the browser's same-origin "
            "policy: any web origin the bypass covers can read the "
            "user's authenticated responses (when `Allow-Credentials: "
            "true`) or send arbitrary methods / headers (when the "
            "pre-flight is lax). Real-world impact: account-takeover "
            "primitives, exfiltration of API responses, CSRF-via-CORS "
            "on state-changing endpoints."
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
            finding_id=finding_id, url=endpoint, param="Origin",
            cwe="CWE-942", severity=severity,
            category="cors_misconfiguration",
            method="GET",
            detection_kind=title[:60],
            confidence=0.85,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "cors_check: kg record failed: %s", e, exc_info=True,
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
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def cors_deep_check(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a URL for CORS misconfiguration laxity.

    Goes beyond the static `Origin: <attacker>` reflection check in
    `http_headers` (#47) — probes 10 origin-bypass classes plus
    pre-flight method/header laxity.

    Args:
        target_url: URL to probe. Bare hostnames auto-prefixed
            `https://`.
        timeout: Per-probe timeout in seconds (default 10).

    Returns:
        {
          success, target_url, target_host,
          baseline: {status, body_length, error?, skipped?},
          origin_probes: [{label, probe_origin, reflected,
                           credentialed, wildcard, severity, issue,
                           evidence, aco_header, acc_header}, ...],
          preflight_probes: [{label, request_method, request_header,
                              response_methods, response_headers,
                              echoed, severity, evidence}, ...],
          findings_emitted
        }

    Findings:
        - **Critical** CWE-942 — attacker origin reflected with
          `Allow-Credentials: true`.
        - **High** CWE-942 — attacker origin reflected w/o
          credentials; OR `null` reflection with credentials; OR
          wildcard + credentials.
        - **Medium** CWE-942 — pre-flight method/header laxity.

    Notes:
        - Read-only (GET + OPTIONS only, no follow-redirects).
        - Composes with cluster-A safety; `--exclude-path` skips.
        - `verification_status=needs_review`.
    """
    target_url_norm = _normalize_target(target_url)
    if target_url_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    parsed = urlparse(target_url_norm)
    target_host = (parsed.hostname or "").lower()
    target_scheme = parsed.scheme
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    cev = _start_check("cors_deep", target_host)
    nonce = secrets.token_hex(4)

    # ---- Baseline ----
    baseline = _http_request("GET", target_url_norm, timeout=timeout)
    if baseline.get("skipped"):
        _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
        return {
            "success": True,
            "target_url": target_url_norm,
            "target_host": target_host,
            "baseline": {"skipped": True, "reason": "excluded by --exclude-path"},
            "origin_probes": [],
            "preflight_probes": [],
            "findings_emitted": 0,
        }

    baseline_status = int(baseline.get("status") or 0)
    baseline_summary = {
        "status": baseline_status,
        "body_length": len(baseline.get("body") or ""),
        "error": baseline.get("error"),
        "skipped": False,
    }

    findings_emitted = 0
    origin_results: list[dict[str, Any]] = []
    preflight_results: list[dict[str, Any]] = []

    # Per-(severity, label) dedup so a credentialed reflection doesn't
    # cascade into 5 near-identical findings.
    emitted_keys: set[str] = set()

    # ---- Origin probes (only if baseline returned 2xx/3xx) ----
    can_probe_origins = 200 <= baseline_status < 400
    if can_probe_origins:
        for label, origin in _build_origin_probes(target_host, target_scheme, nonce):
            response = _http_request(
                "GET", target_url_norm,
                headers={"Origin": origin},
                timeout=timeout,
            )
            if response.get("skipped"):
                origin_results.append({
                    "label": label,
                    "probe_origin": origin,
                    "reflected": False,
                    "credentialed": False,
                    "wildcard": False,
                    "severity": None,
                    "issue": None,
                    "evidence": "skipped by --exclude-path",
                    "aco_header": "",
                    "acc_header": "",
                })
                continue

            verdict = _classify(label, origin, response.get("headers") or {})
            origin_results.append(verdict)

            if verdict["severity"] is None:
                continue

            dedup_key = f"{verdict['severity']}::{verdict.get('issue')}"
            if dedup_key in emitted_keys:
                continue
            emitted_keys.add(dedup_key)

            severity = verdict["severity"]
            credentialed_text = (
                "with `Allow-Credentials: true` (full credentialed bypass)"
                if verdict["credentialed"]
                else "without credentials"
            )

            if severity == "critical":
                description_plain = (
                    "Your server reflects an attacker-controlled origin "
                    f"in `Access-Control-Allow-Origin` and sets "
                    f"`Access-Control-Allow-Credentials: true`. "
                    "Any malicious web page using one of the bypass "
                    "patterns this probe sent can read the victim's "
                    "authenticated responses — full account takeover "
                    "primitive."
                )
            elif severity == "high":
                description_plain = (
                    "Your server reflects an attacker-controlled origin "
                    "in `Access-Control-Allow-Origin`. Even without "
                    "credentials, this lets any malicious web page "
                    "read public response bodies and use them as "
                    "stepping stones for further attacks."
                )
            else:  # medium
                description_plain = (
                    "Your server's CORS validator accepts an "
                    "attacker-controlled origin variant. Without "
                    "Allow-Credentials this isn't an immediate "
                    "credentialed-access bypass, but it documents a "
                    "validator-correctness bug — combine with future "
                    "Allow-Credentials misconfig and it becomes one."
                )

            recommended_action = (
                "Replace dynamic Origin reflection with an explicit "
                "allow-list of trusted origins. The validator MUST: "
                "(a) reject `Origin: null` outright; (b) compare the "
                "exact full origin string (scheme + host + port), not "
                "by `endswith` / `startswith` / regex without anchors; "
                "(c) refuse to set `Access-Control-Allow-Credentials: "
                "true` alongside any reflected or wildcard origin. "
                "On unknown origins, omit the Allow-Origin header "
                "entirely (don't return `*`)."
            )

            _emit_finding(
                title=(
                    f"CORS misconfiguration ({verdict['issue']}) on "
                    f"{target_host} — {severity}"
                ),
                severity=severity,
                target=target_host,
                endpoint=target_url_norm,
                description=(
                    f"Probe `{label}` sent `Origin: {origin}` and the "
                    f"server reflected it {credentialed_text}. "
                    f"Allow-Origin: `{verdict['aco_header']}`; "
                    f"Allow-Credentials: `{verdict['acc_header'] or '(absent)'}`."
                ),
                description_plain=description_plain,
                recommended_action=recommended_action,
            )
            findings_emitted += 1

    # ---- Pre-flight method laxity ----
    laxity_method_probes = [
        ("preflight_method_trace", "TRACE"),
        ("preflight_method_delete", "DELETE"),
        ("preflight_method_connect", "CONNECT"),
    ]
    for label, method in laxity_method_probes:
        attacker = f"https://strix-{nonce}.evil.example"
        response = _http_request(
            "OPTIONS", target_url_norm,
            headers={
                "Origin": attacker,
                "Access-Control-Request-Method": method,
            },
            timeout=timeout,
        )
        if response.get("skipped"):
            preflight_results.append({
                "label": label, "request_method": method,
                "request_header": None,
                "response_methods": "",
                "response_headers": "",
                "echoed": False,
                "severity": None,
                "evidence": "skipped by --exclude-path",
            })
            continue

        response_methods = (response.get("headers") or {}).get(
            "access-control-allow-methods", ""
        )
        echoed = method.lower() in response_methods.lower()
        verdict = {
            "label": label,
            "request_method": method,
            "request_header": None,
            "response_methods": response_methods,
            "response_headers": (response.get("headers") or {}).get(
                "access-control-allow-headers", ""
            ),
            "echoed": echoed,
            "severity": None,
            "evidence": (
                f"OPTIONS pre-flight requested {method}; "
                f"Access-Control-Allow-Methods: `{response_methods}`."
            ),
        }
        preflight_results.append(verdict)

        if echoed:
            dedup_key = "medium::preflight_method_laxity"
            if dedup_key not in emitted_keys:
                emitted_keys.add(dedup_key)
                verdict["severity"] = "medium"
                _emit_finding(
                    title=(
                        f"CORS pre-flight method laxity on {target_host}"
                    ),
                    severity="medium",
                    target=target_host,
                    endpoint=target_url_norm,
                    description=(
                        f"OPTIONS pre-flight with `Access-Control-Request-"
                        f"Method: {method}` was echoed back into "
                        f"`Access-Control-Allow-Methods: "
                        f"{response_methods}`. The server doesn't "
                        f"validate which methods are intended for "
                        f"cross-origin calls."
                    ),
                    description_plain=(
                        "Your server echoes any HTTP method an attacker "
                        "asks about in the pre-flight (CORS) check back "
                        "into the response. That tells browsers it's OK "
                        "to send arbitrary methods cross-origin — "
                        "including ones (like TRACE) that should never "
                        "be cross-origin reachable."
                    ),
                    recommended_action=(
                        "In the pre-flight handler, return only the "
                        "explicit list of methods your API actually "
                        "supports cross-origin (typically `GET, POST, "
                        "PUT, DELETE, OPTIONS`). Don't read "
                        "`Access-Control-Request-Method` from the "
                        "request and echo it back."
                    ),
                )
                findings_emitted += 1

    # ---- Pre-flight header laxity ----
    laxity_header_probes = [
        ("preflight_header_bogus", f"X-Strix-Bogus-{nonce}"),
        ("preflight_header_internal", "X-Internal-User-Id"),
    ]
    for label, header_name in laxity_header_probes:
        attacker = f"https://strix-{nonce}.evil.example"
        response = _http_request(
            "OPTIONS", target_url_norm,
            headers={
                "Origin": attacker,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": header_name,
            },
            timeout=timeout,
        )
        if response.get("skipped"):
            preflight_results.append({
                "label": label, "request_method": "GET",
                "request_header": header_name,
                "response_methods": "",
                "response_headers": "",
                "echoed": False,
                "severity": None,
                "evidence": "skipped by --exclude-path",
            })
            continue

        response_headers_str = (response.get("headers") or {}).get(
            "access-control-allow-headers", ""
        )
        echoed = header_name.lower() in response_headers_str.lower()
        verdict = {
            "label": label,
            "request_method": "GET",
            "request_header": header_name,
            "response_methods": (response.get("headers") or {}).get(
                "access-control-allow-methods", ""
            ),
            "response_headers": response_headers_str,
            "echoed": echoed,
            "severity": None,
            "evidence": (
                f"OPTIONS pre-flight requested header `{header_name}`; "
                f"Access-Control-Allow-Headers: `{response_headers_str}`."
            ),
        }
        preflight_results.append(verdict)

        if echoed:
            dedup_key = "medium::preflight_header_laxity"
            if dedup_key not in emitted_keys:
                emitted_keys.add(dedup_key)
                verdict["severity"] = "medium"
                _emit_finding(
                    title=(
                        f"CORS pre-flight header laxity on {target_host}"
                    ),
                    severity="medium",
                    target=target_host,
                    endpoint=target_url_norm,
                    description=(
                        f"OPTIONS pre-flight with `Access-Control-Request-"
                        f"Headers: {header_name}` was echoed back into "
                        f"`Access-Control-Allow-Headers: "
                        f"{response_headers_str}`. The server doesn't "
                        f"validate which request headers are intended "
                        f"for cross-origin calls."
                    ),
                    description_plain=(
                        "Your server echoes any header name an attacker "
                        "asks about in the pre-flight (CORS) check back "
                        "into the response. That lets a malicious web "
                        "page send arbitrary custom headers cross-"
                        "origin — including framework-internal headers "
                        "like `X-Internal-User-Id` that the back-end "
                        "may trust."
                    ),
                    recommended_action=(
                        "In the pre-flight handler, return only the "
                        "explicit list of header names your API "
                        "supports cross-origin (typically "
                        "`Content-Type, Authorization, X-Requested-"
                        "With`). Don't read "
                        "`Access-Control-Request-Headers` from the "
                        "request and echo it back. Strip framework-"
                        "internal headers (`X-Internal-*`, "
                        "`X-Forwarded-User`) at the edge."
                    ),
                )
                findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} CORS finding(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url_norm,
        "target_host": target_host,
        "baseline": baseline_summary,
        "origin_probes": origin_results,
        "preflight_probes": preflight_results,
        "findings_emitted": findings_emitted,
    }
