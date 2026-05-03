"""HTTP request smuggling / desync prober.

Detects classic CL.TE / TE.CL / TE.TE / H1 desync vulnerabilities by
**differential Transfer-Encoding header probing**. The principle: when
a request's TE / CL headers are obfuscated in different ways, parsers
on the front-end (CDN / load-balancer / WAF) and back-end (origin)
sometimes disagree about how to interpret them. Disagreement = a
desync vector.

This tool catches that disagreement by:

1. Establishing a baseline with a canonical `Transfer-Encoding: chunked`
   request and a chunked-empty body (`0\\r\\n\\r\\n`).
2. Sending the same request shape with each of ~9 obfuscated TE
   variants — `xchunked`, trailing-space, trailing-tab, mixed case,
   dual-value, vertical-tab in header name, duplicate TE headers, and
   simultaneous CL+TE.
3. Diffing each variant's `(status, body_length, body)` against the
   baseline. When a variant returns success where baseline returned
   error (or vice versa) — or returns the same status but a materially
   different body — at least one tier in the chain is interpreting the
   header differently.

The detection is **header-level only** — never sends a payload that
would actually smuggle a second request. The body is `0\\r\\n\\r\\n`
(chunked-empty terminator) on every probe; even if a back-end treated
the body as a smuggled second request, `0\\r\\n` is not a valid HTTP
request line and the back-end would 400 it.

Why raw sockets: standard HTTP libraries (`requests`, `httpx`) auto-
normalize headers and silently strip / merge / refuse conflicting
`Content-Length` + `Transfer-Encoding`. To probe parser disagreement
we need byte-exact control of what goes on the wire, which only raw
sockets give us.

Implementation:

- One TCP connection per probe (TLS-wrapped for `https`).
- Per-probe timeout enforced via `socket.settimeout`. Sockets are
  always closed in a `finally`.
- Reads up to 64 KiB of response (status line + headers + body
  fragment). Enough to make the differential decision; we don't need
  the full body.
- Cluster-A safety integrated manually: `is_path_excluded` check
  before connect; `throttle_for_rate_limit` before connect; auth
  headers from `STRIX_AUTH_*` env via `inject_auth_headers`. We don't
  go through the sandbox Caido proxy because it's a CONNECT-style
  HTTP proxy that can't faithfully forward the byte-exact malformed
  requests we need to send.

Findings:

- **High** (CWE-444, http_request_smuggling) — any obfuscated TE
  variant returns a success-class status (2xx) where baseline returned
  error-class (4xx / 5xx), or vice versa. Direct evidence of parser
  disagreement; this is the smuggling primitive.
- **Medium** (CWE-444) — variant returns the same status class as
  baseline but body length differs by more than 20% with both
  responses being 2xx / 4xx (5xx pairs filtered because both tiers
  may be timing out independently for unrelated reasons).
- *(no finding)* — all variants behave identically to baseline (single
  parser in the chain, or both tiers normalize the same way).

Each finding includes `description_plain` + `recommended_action`. The
fix recommendation is universal: front the application with a single
HTTP parser (or strip ambiguous TE headers at the edge), reject
requests that have both CL and TE, and reject obfuscated TE values.

`verification_status=needs_review` since header-level differential
detection is a strong signal but not equivalent to a confirmed
smuggle. The agent should follow up with PortSwigger's full
methodology (timing-based CL.TE / TE.CL probes, then Burp Repeater
PoC) before treating as a confirmed exploit.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse


from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "request_smuggling_check"
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_PORT_HTTP = 80
_DEFAULT_PORT_HTTPS = 443
_MAX_RESPONSE_BYTES = 64 * 1024
_BODY_LEN_DIVERGENCE_THRESHOLD = 0.20  # 20% length divergence triggers medium

# Same chunked-empty body on every probe — safe by design (decodes to
# zero bytes; even if smuggled, '0\r\n' isn't a valid request line).
_BENIGN_CHUNKED_EMPTY_BODY = b"0\r\n\r\n"


# ---------------------------------------------------------------------------
# Probe cohort
# ---------------------------------------------------------------------------


# Each probe specifies the LITERAL header lines to send (so we can
# exercise obfuscation that a `dict` representation would normalize
# away — duplicate headers, weird whitespace, vertical tabs, etc.).
# An empty / missing CL header tuple means "don't send a CL line".


def _build_probes() -> list[dict[str, Any]]:
    return [
        {
            "label": "te_baseline",
            "te_lines": ["Transfer-Encoding: chunked"],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: chunked (canonical)",
            "is_baseline": True,
        },
        {
            "label": "te_xchunked",
            "te_lines": ["Transfer-Encoding: xchunked"],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: xchunked",
            "is_baseline": False,
        },
        {
            "label": "te_space_after_value",
            "te_lines": ["Transfer-Encoding: chunked "],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: chunked␣ (trailing space)",
            "is_baseline": False,
        },
        {
            "label": "te_tab_after_value",
            "te_lines": ["Transfer-Encoding: chunked\t"],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: chunked\\t (trailing tab)",
            "is_baseline": False,
        },
        {
            "label": "te_chunked_uppercase",
            "te_lines": ["Transfer-Encoding: Chunked"],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: Chunked (mixed case)",
            "is_baseline": False,
        },
        {
            "label": "te_dual_value",
            "te_lines": ["Transfer-Encoding: chunked, identity"],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: chunked, identity",
            "is_baseline": False,
        },
        {
            "label": "te_obscure_separator",
            "te_lines": ["Transfer-Encoding\x0b: chunked"],  # vertical tab in header name
            "send_cl": False,
            "mutation_note": "Transfer-Encoding\\x0b: chunked (vtab in header name)",
            "is_baseline": False,
        },
        {
            "label": "te_dup_header",
            "te_lines": [
                "Transfer-Encoding: chunked",
                "Transfer-Encoding: identity",
            ],
            "send_cl": False,
            "mutation_note": "Transfer-Encoding: chunked + Transfer-Encoding: identity (duplicate header)",
            "is_baseline": False,
        },
        {
            "label": "cl_te_present",
            "te_lines": ["Transfer-Encoding: chunked"],
            "send_cl": True,
            "mutation_note": "Content-Length: 0 + Transfer-Encoding: chunked (both present)",
            "is_baseline": False,
        },
    ]


# ---------------------------------------------------------------------------
# Target handling
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> dict[str, Any] | None:
    """Return {scheme, host, port, path} or None on failure."""
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
    host = parsed.hostname
    if not host:
        return None
    if parsed.port:
        port = int(parsed.port)
    else:
        port = _DEFAULT_PORT_HTTPS if parsed.scheme == "https" else _DEFAULT_PORT_HTTP
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return {"scheme": parsed.scheme, "host": host.lower(), "port": port, "path": path}


# ---------------------------------------------------------------------------
# Raw-socket request / response
# ---------------------------------------------------------------------------


_STATUS_LINE_RE = re.compile(rb"^HTTP/[\d.]+\s+(\d{3})", re.IGNORECASE)


def _build_request_bytes(
    *,
    method: str,
    path: str,
    host_header: str,
    te_lines: list[str],
    send_cl: bool,
    extra_headers: dict[str, str],
    body: bytes,
) -> bytes:
    """Construct the raw HTTP/1.1 request bytes."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
    if send_cl:
        lines.append(f"Content-Length: {len(body)}")
    lines.extend(te_lines)
    for k, v in extra_headers.items():
        if not k:
            continue
        lines.append(f"{k}: {v}")
    lines.append("Connection: close")  # one-shot connection
    lines.append("")  # blank line before body
    lines.append("")  # extra to make sure trailing CRLF
    head = "\r\n".join(lines).encode("ascii", errors="replace")
    return head + body


def _read_response_with_timeout(
    sock: socket.socket, deadline: float
) -> dict[str, Any]:
    """Read until socket close OR deadline OR _MAX_RESPONSE_BYTES."""
    chunks: list[bytes] = []
    total = 0
    while total < _MAX_RESPONSE_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            sock.settimeout(remaining)
            data = sock.recv(8192)
        except (TimeoutError, socket.timeout):
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    raw = b"".join(chunks)
    return _parse_response(raw)


def _parse_response(raw: bytes) -> dict[str, Any]:
    """Parse status line + headers + body from raw HTTP response bytes."""
    if not raw:
        return {"status": 0, "headers": {}, "body": "", "raw_length": 0}
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        # No body separator; treat all as head.
        head, body = raw, b""
    lines = head.split(b"\r\n")
    if not lines:
        return {"status": 0, "headers": {}, "body": "", "raw_length": len(raw)}
    m = _STATUS_LINE_RE.match(lines[0])
    status = int(m.group(1)) if m else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    try:
        body_text = body.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        body_text = ""
    return {
        "status": status,
        "headers": headers,
        "body": body_text,
        "raw_length": len(raw),
    }


def _send_one_probe(
    *,
    scheme: str,
    host: str,
    port: int,
    path: str,
    te_lines: list[str],
    send_cl: bool,
    extra_headers: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    """Send one raw probe and return parsed response.

    Returns {status, headers, body, raw_length, error?}.
    """
    request_bytes = _build_request_bytes(
        method="POST",
        path=path,
        host_header=host,
        te_lines=te_lines,
        send_cl=send_cl,
        extra_headers=extra_headers,
        body=_BENIGN_CHUNKED_EMPTY_BODY,
    )

    sock: socket.socket | None = None
    try:
        deadline = time.monotonic() + timeout
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock
        sock.settimeout(timeout)
        sock.sendall(request_bytes)
        return _read_response_with_timeout(sock, deadline)
    except (socket.gaierror, socket.timeout, TimeoutError, OSError, ssl.SSLError) as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "raw_length": 0,
            "error": f"{type(e).__name__}: {e}",
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Cluster-A composition (manual, since we bypass proxy_manager)
# ---------------------------------------------------------------------------


def _cluster_a_preflight(url: str) -> dict[str, Any] | None:
    """Apply exclude-path + rate-limit before a probe. Returns a skip
    response when the URL is excluded; None otherwise (probe should run).
    """
    try:
        from strix.tools.proxy.http_safety import (
            is_path_excluded,
            throttle_for_rate_limit,
        )
    except Exception:  # noqa: BLE001
        return None
    excluded, matched_glob = is_path_excluded(url)
    if excluded:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "raw_length": 0,
            "skipped": True,
            "skipped_reason": f"excluded by --exclude-path: {matched_glob or ''}",
        }
    throttle_for_rate_limit()
    return None


def _cluster_a_auth_headers() -> dict[str, str]:
    """Return auth headers from `STRIX_AUTH_*` env vars."""
    try:
        from strix.tools.proxy.http_safety import inject_auth_headers
    except Exception:  # noqa: BLE001
        return {}
    return inject_auth_headers({})


# ---------------------------------------------------------------------------
# Differential analysis
# ---------------------------------------------------------------------------


def _status_class(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "unknown"


def _diff_against_baseline(
    baseline: dict[str, Any], probe: dict[str, Any]
) -> dict[str, Any]:
    """Compare probe vs baseline. Returns
    {differs_status_class, body_length_delta_pct, severity, evidence_parts}.
    """
    if probe.get("error"):
        return {
            "differs_status_class": False,
            "body_length_delta_pct": 0.0,
            "severity": None,
            "evidence_parts": [f"probe errored: {probe['error']}"],
        }

    bl_class = _status_class(baseline.get("status", 0))
    pb_class = _status_class(probe.get("status", 0))
    bl_len = len(baseline.get("body") or "")
    pb_len = len(probe.get("body") or "")

    differs_class = (bl_class != pb_class) and bl_class != "unknown" and pb_class != "unknown"

    if bl_len == 0 and pb_len == 0:
        len_delta = 0.0
    else:
        denom = max(bl_len, pb_len, 1)
        len_delta = abs(pb_len - bl_len) / denom

    evidence_parts: list[str] = []
    severity: str | None = None

    if differs_class:
        severity = "high"
        evidence_parts.append(
            f"status class differs: baseline {baseline.get('status')} ({bl_class}) "
            f"vs probe {probe.get('status')} ({pb_class})"
        )
    elif (
        bl_class in ("2xx", "4xx")
        and pb_class in ("2xx", "4xx")
        and len_delta >= _BODY_LEN_DIVERGENCE_THRESHOLD
    ):
        severity = "medium"
        evidence_parts.append(
            f"body length differs >20%: baseline {bl_len}B vs probe {pb_len}B "
            f"(delta={len_delta:.1%})"
        )
    else:
        evidence_parts.append(
            f"matches baseline: status={probe.get('status')}, body_len={pb_len}"
        )

    return {
        "differs_status_class": differs_class,
        "body_length_delta_pct": round(len_delta, 4),
        "severity": severity,
        "evidence_parts": evidence_parts,
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
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="http_request_smuggling",
        cwe="CWE-444",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "HTTP request smuggling lets an attacker prepend bytes to "
            "another user's request, bypassing front-end authorization, "
            "stealing CSRF tokens, poisoning the cache for every "
            "subsequent visitor, or escalating to RCE on vulnerable "
            "back-ends. The class is high-impact, deterministic to "
            "exploit once a desync vector is identified, and "
            "consistently produces critical-severity findings in real-"
            "world engagements (PortSwigger's Top-10 Web Hacking "
            "Techniques 2019, 2020)."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
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
def request_smuggling_check(
    target: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a URL for HTTP request smuggling / desync via differential
    Transfer-Encoding header detection.

    Args:
        target: URL to probe. Bare hostnames are auto-prefixed with
            `https://`. Default ports: 443 (https), 80 (http).
        timeout: Per-probe timeout in seconds (default 10).

    Methodology:
        1. Send a baseline POST with `Transfer-Encoding: chunked` and a
           chunked-empty body (`0\\r\\n\\r\\n`).
        2. Send 8 obfuscated TE variants (same body, mutated TE header):
           `xchunked`, trailing-space, trailing-tab, mixed case,
           dual-value, vtab-in-name, duplicate header, simultaneous
           CL+TE.
        3. Diff each variant's `(status, body_length)` against the
           baseline.

    Returns:
        {
          success, target_url, target_host, target_port,
          baseline: {status, body_length, error?},
          probes: [
            {label, mutation_note, status, body_length, error?,
             differs_status_class, body_length_delta_pct,
             finding_severity, evidence},
            ...
          ],
          findings_emitted: int
        }

    Findings:
        - **High** (CWE-444, http_request_smuggling) — variant returns
          a different status class than baseline. Direct evidence of
          parser disagreement.
        - **Medium** (CWE-444) — same class but body length differs by
          more than 20% (and both responses are 2xx / 4xx).

    Notes:
        - Read-only and safe-by-default. The probe body is `0\\r\\n\\r\\n`
          on every variant; even if a back-end interpreted it as a
          smuggled second request, the bytes don't form a valid HTTP
          request line.
        - Uses raw sockets (HTTP libraries auto-normalize headers).
        - Per-probe deadline enforced via `socket.settimeout`.
        - Composes with cluster-A safety: `--exclude-path` /
          `--rate-limit` / `--auth-*` apply to every probe.
        - `verification_status=needs_review` — header-level differential
          detection is a strong signal but not a confirmed smuggle.
          Follow up with PortSwigger's full timing-based methodology.
    """
    parsed = _normalize_target(target)
    if parsed is None:
        return {"success": False, "error": f"invalid target: {target!r}"}
    scheme, host, port, path = parsed["scheme"], parsed["host"], parsed["port"], parsed["path"]
    target_url = f"{scheme}://{host}:{port}{path}"

    cev = _start_check("http_request_smuggling", host)

    auth_headers = _cluster_a_auth_headers()
    extra_headers = {**auth_headers, "Accept": "*/*", "User-Agent": "strix-smuggle-probe/1"}

    probes = _build_probes()
    baseline_response: dict[str, Any] | None = None
    probe_results: list[dict[str, Any]] = []
    findings_emitted = 0

    for probe in probes:
        skip = _cluster_a_preflight(target_url)
        if skip is not None:
            probe_results.append({
                "label": probe["label"],
                "mutation_note": probe["mutation_note"],
                "status": 0,
                "body_length": 0,
                "skipped": True,
                "evidence": skip.get("skipped_reason", "skipped"),
                "finding_severity": None,
            })
            if probe["is_baseline"]:
                baseline_response = skip
            continue

        response = _send_one_probe(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            te_lines=probe["te_lines"],
            send_cl=probe["send_cl"],
            extra_headers=extra_headers,
            timeout=timeout,
        )
        if probe["is_baseline"]:
            baseline_response = response
            probe_results.append({
                "label": probe["label"],
                "mutation_note": probe["mutation_note"],
                "status": response.get("status", 0),
                "body_length": len(response.get("body") or ""),
                "error": response.get("error"),
                "evidence": "baseline",
                "finding_severity": None,
            })
            continue

        if baseline_response is None or baseline_response.get("error") or baseline_response.get("status", 0) == 0:
            # Baseline failed — record the probe but can't diff usefully.
            probe_results.append({
                "label": probe["label"],
                "mutation_note": probe["mutation_note"],
                "status": response.get("status", 0),
                "body_length": len(response.get("body") or ""),
                "error": response.get("error"),
                "evidence": "baseline failed; differential analysis skipped",
                "finding_severity": None,
            })
            continue

        diff = _diff_against_baseline(baseline_response, response)
        verdict = {
            "label": probe["label"],
            "mutation_note": probe["mutation_note"],
            "status": response.get("status", 0),
            "body_length": len(response.get("body") or ""),
            "error": response.get("error"),
            "differs_status_class": diff["differs_status_class"],
            "body_length_delta_pct": diff["body_length_delta_pct"],
            "evidence": "; ".join(diff["evidence_parts"]),
            "finding_severity": diff["severity"],
        }
        probe_results.append(verdict)

        sev = diff["severity"]
        if sev is None:
            continue

        # Emit finding.
        if sev == "high":
            title = (
                f"HTTP request smuggling — TE-header parser disagreement on "
                f"{host} ({probe['label']})"
            )
            description_plain = (
                "Your CDN / load-balancer and your back-end disagree on how "
                "to parse a `Transfer-Encoding` header. An attacker can craft "
                "a single request that the front-end forwards as one request "
                "but the back-end reads as two — letting the attacker prepend "
                "bytes to the next user's request, bypass authorization, "
                "steal CSRF tokens, or poison the cache for every other "
                "visitor."
            )
            recommended_action = (
                "Front the application with a single HTTP parser end-to-end. "
                "At the edge: reject any request with both `Content-Length` "
                "and `Transfer-Encoding`; reject `Transfer-Encoding` values "
                "other than exact-match `chunked`; strip `Transfer-Encoding` "
                "headers with non-ASCII characters or whitespace anomalies. "
                "Cloudflare / Akamai / AWS CloudFront all expose toggles for "
                "strict HTTP parsing — turn them on."
            )
        else:  # medium
            title = (
                f"HTTP request smuggling (response divergence) — {probe['label']} on {host}"
            )
            description_plain = (
                "When we sent your application the same request with a "
                "slightly-mangled `Transfer-Encoding` header, the response "
                "body changed materially. This is a strong signal that the "
                "front-end and back-end are interpreting the header "
                "differently — the precondition for HTTP request smuggling."
            )
            recommended_action = (
                "Audit your CDN / load-balancer's HTTP parsing strictness. "
                "Reject any request with both `Content-Length` and "
                "`Transfer-Encoding` at the edge; reject `Transfer-Encoding` "
                "values other than exact-match `chunked`. Test by sending "
                "the same probe and confirming both tiers return the same "
                "response."
            )
        description = (
            f"Probe `{probe['label']}` ({probe['mutation_note']}) → "
            f"{verdict['evidence']}. Baseline: status={baseline_response.get('status')}, "
            f"body_length={len(baseline_response.get('body') or '')}. Probe: "
            f"status={verdict['status']}, body_length={verdict['body_length']}."
        )
        _emit_finding(
            title=title,
            severity=sev,
            target=host,
            endpoint=target_url,
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted += 1

    # Check event.
    if baseline_response is None or (baseline_response.get("status", 0) == 0 and not baseline_response.get("skipped")):
        result_label = "inconclusive"
        result_evidence = "baseline could not be established"
    elif baseline_response.get("skipped"):
        result_label = "inconclusive"
        result_evidence = "baseline excluded by --exclude-path"
    else:
        result_label = "vulnerable" if findings_emitted else "not_vulnerable"
        result_evidence = f"{findings_emitted} smuggling indicator(s) on {host}"
    _complete_check(cev, result=result_label, evidence=result_evidence)

    baseline_summary: dict[str, Any] = {}
    if baseline_response is not None:
        baseline_summary = {
            "status": baseline_response.get("status", 0),
            "body_length": len(baseline_response.get("body") or ""),
            "error": baseline_response.get("error"),
            "skipped": baseline_response.get("skipped", False),
        }

    return {
        "success": True,
        "target_url": target_url,
        "target_host": host,
        "target_port": port,
        "baseline": baseline_summary,
        "probes": probe_results,
        "findings_emitted": findings_emitted,
    }
