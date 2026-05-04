"""WebSocket handshake audit.

Tests four classes at the HTTP-upgrade level (no full WebSocket
client needed):

  1. **Baseline upgrade** — does the endpoint accept WS upgrades
     at all? Sets `endpoint_is_websocket` so the rest of the
     suite makes sense.
  2. **Auth-on-upgrade** — when the caller supplied auth headers
     (Cookie / Authorization), retry the upgrade WITHOUT them.
     If unauthed upgrade still returns 101, that's CWE-306
     (Missing Authentication).
  3. **Origin variants** — six distinct attacker-shape Origin
     values: `null`, attacker apex, suffix-injection
     (`<target>.evil.example`), prefix-injection
     (`evil.<target>`), scheme-swap (http on a wss endpoint),
     missing-Origin entirely. If a 101 comes back when the
     baseline-with-no-Origin DOES enforce, that's CWE-942.
  4. **Subprotocol echo** — `Sec-WebSocket-Protocol: <attacker
     value>` reflected verbatim in the 101 response → low
     CWE-79 (sub-XSS surface; many SDKs interpolate the
     subprotocol into client UI).

Why zero-FP-by-construction
---------------------------

* Auth-on-upgrade: 101 vs 401/403 is a binary HTTP status code.
  The probe runs ONLY when the caller supplied auth; the
  "without-auth" run is a comparable counterfactual.
* Origin enforcement: probe with `Origin: <attacker>` → if 101,
  AND the baseline-no-Origin run was rejected, then we know
  the server distinguishes Origin presence — which means the
  attacker-Origin acceptance is a real bypass, not just a
  no-validation server.
* Subprotocol echo: the server ECHOES the value verbatim → byte
  match in the response header.

Scope
-----

This is HANDSHAKE-level only — message-level fuzzing (frame
parsing, opcode injection, masking edge cases) is the §17.1
WebSocket-fuzzer follow-up. A first-pass tool that catches the
big four classes is much higher leverage than a frame fuzzer
that catches obscure parser bugs in unmaintained servers.

References
----------

* RFC 6455 §1.3 (Opening Handshake)
* RFC 6455 §10.2 (Origin considerations)
* CWE-306 / CWE-942
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "websocket_audit"
_DEFAULT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Handshake construction
# ---------------------------------------------------------------------------


def _make_ws_key() -> str:
    """RFC 6455 §4.1: 16 random bytes → base64-encoded; the server
    will compute Sec-WebSocket-Accept from this."""
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def _ws_to_http_url(url: str) -> str:
    """Convert ws://..../ws into http://..../ws so httpx can issue
    the upgrade request. wss → https."""
    if url.startswith("ws://"):
        return "http://" + url[len("ws://"):]
    if url.startswith("wss://"):
        return "https://" + url[len("wss://"):]
    if url.startswith(("http://", "https://")):
        return url
    return f"https://{url}"


def _http_to_origin(url: str, *, scheme: str | None = None) -> str:
    """Build an Origin header value (`<scheme>://<host>:<port>`)
    matching the target — used for legitimate-Origin baseline."""
    parsed = urlparse(_ws_to_http_url(url))
    sch = scheme or parsed.scheme
    if sch == "http":
        sch = "http"
    elif sch == "https":
        sch = "https"
    return f"{sch}://{parsed.netloc}"


def _send_handshake(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Send the WebSocket upgrade request. Returns a dict with
    `{status, response_headers, error?, skipped?}`. Composes with
    cluster-A safety (auth-injection, exclude-path, rate-limit)."""
    http_url = _ws_to_http_url(url)
    base_headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": _make_ws_key(),
    }
    base_headers.update(headers or {})

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None:
        try:
            r = manager.send_simple_request(
                "GET", http_url, headers=base_headers, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {"status": 0, "response_headers": {}, "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "response_headers": _lower_keys(r.get("headers") or {}),
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy upgrade failed; falling back", exc_info=True)

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(http_url)
        if excluded:
            return {"status": 0, "response_headers": {}, "skipped": True}
        merged = inject_auth_headers(dict(base_headers))
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.request("GET", http_url, headers=merged)
            return {
                "status": r.status_code,
                "response_headers": _lower_keys(dict(r.headers)),
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "response_headers": {}, "error": str(e)}


def _lower_keys(d: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in d.items()}


def _is_upgrade_success(resp: dict[str, Any]) -> bool:
    """True iff the response is a successful WebSocket upgrade.
    RFC 6455: 101 Switching Protocols + `Upgrade: websocket` +
    `Connection: Upgrade` (case-insensitive). Some servers send
    the upgrade headers but with status 200 — those don't count."""
    if int(resp.get("status") or 0) != 101:
        return False
    headers = resp.get("response_headers") or {}
    upgrade = (headers.get("upgrade") or "").lower()
    if "websocket" not in upgrade:
        return False
    connection = (headers.get("connection") or "").lower()
    return "upgrade" in connection


# ---------------------------------------------------------------------------
# Probe families
# ---------------------------------------------------------------------------


def _attacker_origin_value(url: str, kind: str) -> str:
    """Build the Origin value for one attack class. `kind` is one
    of `null` / `attacker_apex` / `suffix` / `prefix` / `scheme_swap`."""
    parsed = urlparse(_ws_to_http_url(url))
    target = parsed.netloc
    nonce = secrets.token_hex(4)
    if kind == "null":
        return "null"
    if kind == "attacker_apex":
        return f"https://strix-{nonce}.evil.example"
    if kind == "suffix":
        return f"https://{target}.strix-{nonce}.evil.example"
    if kind == "prefix":
        return f"https://strix-{nonce}-evil.{target}"
    if kind == "scheme_swap":
        # If target is HTTPS, present an HTTP origin (and vice-versa)
        wrong_scheme = "http" if parsed.scheme == "https" else "https"
        return f"{wrong_scheme}://{target}"
    return f"https://strix-{nonce}.evil.example"


def _probe_origin_variants(
    url: str,
    *,
    baseline_no_origin: dict[str, Any],
    timeout: float,
) -> list[dict[str, Any]]:
    """Issue 5 origin-bypass probes. Emit a finding per variant
    that succeeds AS A DEVIATION from the baseline (i.e. when
    baseline-no-Origin succeeded too, the server doesn't enforce
    Origin and we don't double-flag).

    Returns a list of structured records — emission to tracer
    happens later."""
    out: list[dict[str, Any]] = []

    # Track whether the baseline-no-Origin succeeded. If yes, the
    # server doesn't enforce Origin at all → emit ONE info finding
    # noting the server doesn't enforce, instead of 5 "high"
    # findings on different origin variants.
    baseline_no_origin_succeeded = _is_upgrade_success(baseline_no_origin)

    # Always run the variant probes; the dedup is on emission.
    variants = ("null", "attacker_apex", "suffix", "prefix", "scheme_swap")
    succeeded_variants: list[tuple[str, str]] = []

    for v in variants:
        origin = _attacker_origin_value(url, v)
        r = _send_handshake(
            url, headers={"Origin": origin}, timeout=timeout
        )
        if _is_upgrade_success(r):
            succeeded_variants.append((v, origin))

    if baseline_no_origin_succeeded and succeeded_variants:
        # Server doesn't enforce Origin AT ALL — single info finding.
        out.append({
            "kind": "ws_no_origin_enforcement",
            "severity": "info",
            "url": url,
            "evidence": (
                f"Server accepts upgrades with NO Origin header AND with "
                f"all attacker-shape origins ({len(succeeded_variants)} "
                f"variants). Origin enforcement appears disabled — "
                f"if browsers are NOT the only client class for this WS "
                f"endpoint, that's intentional; otherwise it's a CSWSH risk."
            ),
        })
    elif succeeded_variants:
        # Server REJECTS no-Origin but ACCEPTS attacker-Origins —
        # binary bypass.
        for kind, origin in succeeded_variants:
            severity = "high" if kind != "null" else "medium"
            out.append({
                "kind": f"ws_origin_bypass_{kind}",
                "severity": severity,
                "url": url,
                "origin_used": origin,
                "evidence": (
                    f"WebSocket upgrade succeeded with "
                    f"`Origin: {origin}` even though the no-Origin "
                    f"baseline was rejected. Server's Origin validator "
                    f"has a {kind}-class flaw."
                ),
            })

    return out


def _probe_auth_on_upgrade(
    url: str,
    *,
    auth_headers: dict[str, str],
    timeout: float,
) -> list[dict[str, Any]]:
    """Send the upgrade WITHOUT auth. If 101 still comes back,
    auth-on-upgrade is missing."""
    if not auth_headers:
        # Nothing to compare against — skip.
        return []

    unauthed = _send_handshake(
        url,
        headers={"Origin": _http_to_origin(url)},
        timeout=timeout,
    )
    if _is_upgrade_success(unauthed):
        return [{
            "kind": "ws_auth_on_upgrade_missing",
            "severity": "high",
            "url": url,
            "evidence": (
                "WebSocket upgrade succeeded WITHOUT the auth headers "
                "the caller supplied for the baseline. The endpoint "
                "doesn't enforce authentication on upgrade — any "
                "anonymous client can connect to the channel."
            ),
        }]
    return []


def _probe_subprotocol_echo(
    url: str, *, timeout: float
) -> list[dict[str, Any]]:
    """Send `Sec-WebSocket-Protocol: <attacker>` and check whether
    the server echoes it back verbatim. Verbatim echo without
    validation → low XSS-on-subprotocol."""
    nonce = f"strix-{secrets.token_hex(4)}-<script>"
    r = _send_handshake(
        url,
        headers={
            "Origin": _http_to_origin(url),
            "Sec-WebSocket-Protocol": nonce,
        },
        timeout=timeout,
    )
    if not _is_upgrade_success(r):
        return []
    echoed = (r.get("response_headers") or {}).get("sec-websocket-protocol", "")
    # Verbatim echo of attacker-controlled input.
    if echoed and nonce in echoed:
        return [{
            "kind": "ws_subprotocol_echo",
            "severity": "low",
            "url": url,
            "echoed": echoed[:240],
            "evidence": (
                f"Server echoed back attacker-controlled "
                f"`Sec-WebSocket-Protocol` value `{nonce[:40]}…` "
                f"verbatim in the 101 response. SDKs that interpolate "
                f"the subprotocol into client UI inherit a sub-XSS "
                f"surface; servers should validate the subprotocol "
                f"against an allow-list."
            ),
        }]
    return []


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


_DESCRIPTION_BY_KIND = {
    "ws_auth_on_upgrade_missing": (
        "The WebSocket endpoint at `{url}` accepts upgrades WITHOUT "
        "the authentication headers the rest of the application requires. "
        "Anonymous clients can establish a persistent channel and send / "
        "receive messages."
    ),
    "ws_no_origin_enforcement": (
        "The WebSocket endpoint at `{url}` accepts upgrades from any "
        "Origin (including no-Origin and attacker-shape values). When "
        "the endpoint is consumed from browsers, this is Cross-Site "
        "WebSocket Hijacking (CSWSH) — a malicious page can establish "
        "a connection in the user's authenticated context and "
        "exfiltrate / inject messages."
    ),
    "ws_origin_bypass_null": (
        "The WebSocket endpoint at `{url}` accepts upgrades with "
        "`Origin: null` while rejecting no-Origin. `null` is sent by "
        "sandboxed iframes / data: URLs — accepting it lets sandboxed "
        "attackers bypass the Origin validator."
    ),
    "ws_origin_bypass_attacker_apex": (
        "The WebSocket endpoint at `{url}` accepts upgrades from an "
        "arbitrary attacker domain, while rejecting no-Origin. CSWSH risk."
    ),
    "ws_origin_bypass_suffix": (
        "The WebSocket endpoint at `{url}` accepts an Origin where "
        "the target's hostname appears as a SUFFIX inside the attacker's "
        "host (`<target>.evil.example`). Origin validator probably "
        "uses `endsWith(target)` instead of host-equality — a classic "
        "string-prefix bug."
    ),
    "ws_origin_bypass_prefix": (
        "The WebSocket endpoint at `{url}` accepts an Origin where "
        "the target's hostname appears as a PREFIX inside the attacker's "
        "host (`evil.<target>`). Origin validator probably uses "
        "`startsWith(target)` or unanchored regex."
    ),
    "ws_origin_bypass_scheme_swap": (
        "The WebSocket endpoint at `{url}` accepts an Origin with the "
        "wrong scheme (http on a TLS endpoint, or vice versa). Validator "
        "isn't comparing the scheme component."
    ),
    "ws_subprotocol_echo": (
        "The WebSocket endpoint at `{url}` echoes `Sec-WebSocket-Protocol` "
        "attacker-controlled values verbatim in the 101 response. Sub-XSS "
        "surface for SDKs that interpolate the subprotocol into UI."
    ),
}

_RECOMMENDED_BY_KIND = {
    "ws_auth_on_upgrade_missing": (
        "Validate the auth context BEFORE accepting the WebSocket upgrade. "
        "Reject (401/403) when the cookie / token is missing or invalid. "
        "Don't rely on the first message-level auth handshake — by then "
        "the channel is already open and the attacker has consumed "
        "anonymous resources."
    ),
    "ws_no_origin_enforcement": (
        "Add an Origin allow-list to your WebSocket upgrade handler. "
        "Reject upgrades whose `Origin` doesn't match an exact entry. "
        "If this endpoint is intentionally consumed by non-browser "
        "clients (e.g. native apps), document that decision and "
        "compensate with strong message-level auth."
    ),
    "ws_origin_bypass_null": (
        "Reject `Origin: null` outright at the upgrade handler. "
        "Browsers send `null` from sandboxed iframes and `data:` URLs; "
        "no legitimate flow needs it."
    ),
    "ws_origin_bypass_attacker_apex": (
        "Replace the current Origin check with strict host-equality "
        "against an explicit allow-list."
    ),
    "ws_origin_bypass_suffix": (
        "Replace `endsWith` / unanchored matching with strict host "
        "equality. `endsWith('example.com')` matches `attacker.example.com` "
        "AND `attacker-example.com` (nasty edge case)."
    ),
    "ws_origin_bypass_prefix": (
        "Same fix as suffix — switch to strict host equality. "
        "`startsWith` and unanchored regex are both unsafe for "
        "Origin validation."
    ),
    "ws_origin_bypass_scheme_swap": (
        "Compare the FULL Origin (scheme + host + port), not just the host."
    ),
    "ws_subprotocol_echo": (
        "Validate `Sec-WebSocket-Protocol` against the application's "
        "supported subprotocols. Echo back ONLY the negotiated value "
        "from your allow-list, never the raw client value."
    ),
}

_CWE_BY_KIND = {
    "ws_auth_on_upgrade_missing": "CWE-306",
    "ws_no_origin_enforcement": "CWE-942",
    "ws_origin_bypass_null": "CWE-942",
    "ws_origin_bypass_attacker_apex": "CWE-942",
    "ws_origin_bypass_suffix": "CWE-942",
    "ws_origin_bypass_prefix": "CWE-942",
    "ws_origin_bypass_scheme_swap": "CWE-942",
    "ws_subprotocol_echo": "CWE-79",
}


def _emit_finding(rec: dict[str, Any], *, target: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None

    kind = rec["kind"]
    severity = rec["severity"]
    description = _DESCRIPTION_BY_KIND.get(kind, kind).format(**rec)
    recommended = _RECOMMENDED_BY_KIND.get(kind, "Review the WebSocket configuration.")
    cwe = _CWE_BY_KIND.get(kind, "CWE-942")

    return tracer.add_vulnerability_report(
        title=f"WebSocket: {kind.replace('ws_', '').replace('_', ' ')} on {rec['url']}",
        severity=severity,
        category="websocket_misconfiguration",
        cwe=cwe,
        target=target,
        endpoint=rec["url"],
        description=description,
        impact=(
            "WebSocket misconfigurations are routinely missed by HTTP-driven "
            "scanners. An attacker that exploits a missing-auth or "
            "Origin-bypass on a WebSocket can establish persistent "
            "two-way channels in the user's authenticated context — "
            "data exfiltration, command injection, real-time pivoting."
        ),
        remediation_steps=recommended,
        description_plain=description,
        recommended_action=recommended,
        verification_status="verified",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME) if t else None


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is not None:
        t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190", "T1090"],
)
def websocket_audit(
    target_url: str,
    *,
    auth_headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Audit a WebSocket endpoint for the four big handshake-level
    classes: auth-on-upgrade, Origin enforcement, scheme-swap,
    subprotocol echo.

    Args:
        target_url: WebSocket URL (`ws://...` / `wss://...`) or
            HTTP URL of the upgrade endpoint. Accepts bare hosts
            (`api.example.com/ws`) — `wss://` is auto-prefixed.
        auth_headers: optional dict of authentication headers
            (e.g. `{"Cookie": "session=...", "Authorization": "Bearer ..."}`).
            When supplied, the auth-on-upgrade probe runs.
        timeout: per-request HTTP timeout (default 10s).

    Returns:
        ```
        {
          success, target_url,
          baseline_upgrade_succeeded,
          probes_run, findings_emitted,
          records: [...],
          errors?
        }
        ```

    Findings:
        - **High** CWE-306 — auth-on-upgrade missing
        - **High** CWE-942 — Origin bypass (suffix / prefix /
          attacker-apex / scheme-swap)
        - **Medium** CWE-942 — `Origin: null` accepted
        - **Info** CWE-942 — server doesn't enforce Origin at all
        - **Low** CWE-79 — subprotocol echo
    """
    # Normalize URL.
    if not target_url or "://" not in target_url:
        target_url = f"wss://{target_url}" if target_url else ""
    if not target_url:
        return {
            "success": False,
            "error": "empty target_url",
            "findings_emitted": 0,
        }

    parsed = urlparse(_ws_to_http_url(target_url))
    if not parsed.netloc:
        return {
            "success": False,
            "error": f"invalid target_url: {target_url}",
            "findings_emitted": 0,
        }

    target = parsed.netloc
    check_id = _start_check(category="websocket", surface=target)

    errors: list[str] = []

    # 1. Baseline-with-correct-Origin probe — establishes whether
    #    the endpoint is actually a WebSocket (sets the rest of the
    #    suite's expectations). Includes auth headers when supplied.
    legit_origin = _http_to_origin(target_url)
    baseline_authed = _send_handshake(
        target_url,
        headers={"Origin": legit_origin, **(auth_headers or {})},
        timeout=timeout,
    )
    baseline_succeeded = _is_upgrade_success(baseline_authed)

    if baseline_authed.get("error"):
        errors.append(f"baseline: {baseline_authed['error']}")

    if not baseline_succeeded:
        # Endpoint isn't a WebSocket at all (or rejected even the
        # legitimate-origin baseline). The rest of the suite would
        # produce noise — return early.
        _complete_check(
            check_id,
            result="inconclusive",
            evidence=(
                f"baseline upgrade returned {baseline_authed.get('status')}; "
                f"endpoint not exposed as a WebSocket"
            ),
        )
        return {
            "success": True,
            "target_url": target_url,
            "baseline_upgrade_succeeded": False,
            "probes_run": 1,
            "findings_emitted": 0,
            "records": [],
            "errors": errors,
        }

    # 2. Baseline-no-Origin probe — used by the origin-variant
    #    suite to disambiguate "server doesn't enforce Origin"
    #    from "server is bypassable via specific origin shape".
    baseline_no_origin = _send_handshake(target_url, timeout=timeout)

    records: list[dict[str, Any]] = []

    # 3. Auth-on-upgrade probe.
    if auth_headers:
        records.extend(
            _probe_auth_on_upgrade(
                target_url, auth_headers=auth_headers, timeout=timeout
            )
        )

    # 4. Origin-variant probes.
    records.extend(
        _probe_origin_variants(
            target_url,
            baseline_no_origin=baseline_no_origin,
            timeout=timeout,
        )
    )

    # 5. Subprotocol-echo probe.
    records.extend(_probe_subprotocol_echo(target_url, timeout=timeout))

    # Emit findings.
    findings_emitted = 0
    for rec in records:
        if _emit_finding(rec, target=target):
            findings_emitted += 1

    if findings_emitted > 0:
        _complete_check(
            check_id,
            result="vulnerable",
            evidence=f"{findings_emitted} websocket misconfig(s) on {target}",
        )
    else:
        _complete_check(
            check_id,
            result="not_vulnerable",
            evidence=f"baseline ok; {len(records)} probe records; no issues",
        )

    out: dict[str, Any] = {
        "success": True,
        "target_url": target_url,
        "baseline_upgrade_succeeded": baseline_succeeded,
        "probes_run": 4 + (1 if auth_headers else 0),
        "findings_emitted": findings_emitted,
        "records": records,
    }
    if errors:
        out["errors"] = errors
    return out
