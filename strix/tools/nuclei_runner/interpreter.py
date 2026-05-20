"""Run a parsed Template against a target URL.

Single-template execution; the runner specialist handles
multi-template iteration. Substitutes `{{BaseURL}}` with the
target's `scheme://host[:port]`, sends the request via the global
proxy_manager, evaluates matchers, and returns a `TemplateResult`.

Multi-step templates (a sequence of HTTP probes) are partially
supported — each step is run independently in order, and we stop
at the first match (the default nuclei behaviour). Variable
extraction across steps is NOT supported in this MVP.

## Raw-HTTP socket sender (iter-16)

The proxy_manager path uses urllib / httpx, which normalize the URL
before sending — they decode percent-encoded path segments that
"shouldn't" be encoded. For most templates that's correct behavior.
But CVE-2021-41773 (and the broader class of path-traversal CVEs
that depend on URL-encoded `..` surviving the wire) require the
raw `%2e` sequence to reach the server INTACT. urllib normalizes
`/icons/.%2e/.%2e/etc/passwd` → `/icons/../../etc/passwd` and
Apache 2.4.49 rejects the normalized form with 400.

For raw-HTTP nuclei probes we send via a raw socket — no URL
normalization, path bytes go to the wire exactly as authored. Cost:
re-implement basic HTTP/1.1 read/write. Benefit: ~56% of CVE
templates that rely on raw-form work end-to-end without the
nuclei binary.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from strix.tools.nuclei_runner.matchers import evaluate_matchers
from strix.tools.nuclei_runner.parser import (
    HttpRequest, Matcher, RawHttpRequest, Template,
)


logger = logging.getLogger(__name__)


@dataclass
class TemplateResult:
    """Outcome of running one template against one target URL."""
    template_id: str
    matched: bool
    matched_request_index: int | None = None
    matched_path: str | None = None
    response_status: int | None = None
    response_body_excerpt: str = ""
    matched_matchers: list[str] = field(default_factory=list)
    error: str | None = None


def _base_url(url: str) -> str:
    """`http://host:port` portion of a URL."""
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return url.rstrip("/")
    return f"{p.scheme}://{p.netloc}"


def _substitute(text: str, *, base_url: str) -> str:
    """Replace `{{BaseURL}}` in path/headers/body. Other nuclei
    variables (e.g. `{{Hostname}}`, `{{Port}}`) are best-effort
    substituted to keep more templates runnable."""
    if not isinstance(text, str):
        return text
    p = urlparse(base_url)
    out = text.replace("{{BaseURL}}", base_url.rstrip("/"))
    out = out.replace("{{Hostname}}", p.netloc)
    if p.hostname:
        out = out.replace("{{Host}}", p.hostname)
    if p.port:
        out = out.replace("{{Port}}", str(p.port))
    if p.scheme:
        out = out.replace("{{Scheme}}", p.scheme)
    return out


def _interpolate_request(
    req: HttpRequest, *, base_url: str, path: str,
) -> tuple[str, dict[str, str], str | None]:
    """Build the (url, headers, body) for one request path."""
    final_url = _substitute(path, base_url=base_url)
    if not final_url.startswith(("http://", "https://")):
        # Path is something like "/admin" — prefix with base.
        final_url = f"{base_url.rstrip('/')}/{final_url.lstrip('/')}"
    headers = {
        k: _substitute(v, base_url=base_url) for k, v in (req.headers or {}).items()
    }
    body = (
        _substitute(req.body, base_url=base_url)
        if isinstance(req.body, str) else None
    )
    return final_url, headers, body


def _send_raw_http(
    method: str, url: str, *,
    headers: dict[str, str], body: str | None, timeout: float,
) -> dict[str, Any]:
    """Raw-socket HTTP/1.1 sender. Bypasses urllib's URL
    normalization so percent-encoded path segments survive the
    wire intact — required for CVE-2021-41773 and similar
    path-traversal-via-encoded-dot exploits.

    Returns dict in the same shape proxy_manager.send_simple_request
    returns: `{status_code, headers, body, error?}`. On error
    returns `{error: <str>}` and the caller continues to the next
    probe.

    Limitations:
      * HTTPS uses unverified TLS (matches nuclei's default).
        Internal benchmark targets are localhost with self-signed
        certs / no cert; we don't want hostname verification to
        block legitimate matches.
      * Body is sent as a single send() — no chunked-transfer
        for now.
      * Response is read until EOF (Connection: close); doesn't
        support keep-alive or HTTP/2.
      * UTF-8 decode of response body uses errors="replace" —
        nuclei templates match on byte patterns inside the body;
        we surface text for the matcher engine.
    """
    p = urlparse(url)
    host = p.hostname
    if not host:
        return {"error": f"no host in URL: {url}"}
    port = p.port or (443 if p.scheme == "https" else 80)
    # Path goes to the wire VERBATIM. p.path is already-extracted
    # from the URL string by urlparse — but urlparse preserves
    # percent-encoding in the path component.
    path = p.path or "/"
    if p.query:
        path += "?" + p.query

    request_line = f"{method} {path} HTTP/1.1\r\n"
    out_headers: list[str] = [f"Host: {host}{':' + str(port) if port not in (80, 443) else ''}"]
    seen_host = True   # we already added our own Host
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            continue
        out_headers.append(f"{k}: {v}")
    body_bytes = b""
    if body:
        body_bytes = body.encode("utf-8", errors="replace")
        # Add Content-Length if caller didn't.
        if not any(h.lower().startswith("content-length:") for h in out_headers):
            out_headers.append(f"Content-Length: {len(body_bytes)}")
    if not any(h.lower().startswith("connection:") for h in out_headers):
        out_headers.append("Connection: close")
    if not any(h.lower().startswith("user-agent:") for h in out_headers):
        out_headers.append("User-Agent: Mozilla/5.0 (compatible; strix-nuclei-runner)")

    request_bytes = (
        request_line.encode("latin-1", errors="replace")
        + ("\r\n".join(out_headers) + "\r\n\r\n").encode("latin-1", errors="replace")
        + body_bytes
    )

    try:
        sock: socket.socket = socket.create_connection(
            (host, port), timeout=timeout,
        )
    except (OSError, socket.gaierror) as e:
        return {"error": f"connect failed: {e}"}

    try:
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(request_bytes)
        chunks: list[bytes] = []
        # Cap response size at 1MB to avoid pathological responses.
        # Matchers don't need more than a body excerpt anyway.
        max_bytes = 1024 * 1024
        total = 0
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        raw_response = b"".join(chunks)
    except (OSError, ssl.SSLError) as e:
        try:
            sock.close()
        except OSError:
            pass
        return {"error": f"transport: {type(e).__name__}: {e}"}
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not raw_response:
        return {"error": "empty response"}

    # Parse: status-line + headers + body
    head, sep, resp_body = raw_response.partition(b"\r\n\r\n")
    if not sep:
        # No header/body separator — treat the whole thing as head
        # so the matchers can still operate on whatever came back.
        head, resp_body = raw_response, b""
    head_lines = head.split(b"\r\n")
    status_code = 0
    if head_lines:
        status_parts = head_lines[0].decode("latin-1", errors="replace").split()
        if len(status_parts) >= 2:
            try:
                status_code = int(status_parts[1])
            except ValueError:
                status_code = 0
    resp_headers: dict[str, str] = {}
    for hl in head_lines[1:]:
        text = hl.decode("latin-1", errors="replace")
        if ":" not in text:
            continue
        k, _, v = text.partition(":")
        # Last-write-wins for duplicate headers — fine for matching.
        resp_headers[k.strip()] = v.strip()

    return {
        "status_code": status_code,
        "headers": resp_headers,
        "body": resp_body.decode("utf-8", errors="replace"),
    }


def _interpolate_raw(
    raw_req: RawHttpRequest, *, base_url: str,
) -> tuple[str, dict[str, str], str | None]:
    """Build the (final_url, headers, body) for a raw-HTTP probe.

    Iter-16. Raw blocks carry their own request-line + headers +
    body; we substitute nuclei interpolation placeholders
    (`{{BaseURL}}`, `{{Hostname}}`, `{{Host}}`, `{{Port}}`,
    `{{Scheme}}`) and stitch path onto base_url when path is
    relative (`/foo/bar`) rather than an absolute URL.
    """
    final_url = _substitute(raw_req.path, base_url=base_url)
    if not final_url.startswith(("http://", "https://")):
        final_url = f"{base_url.rstrip('/')}/{final_url.lstrip('/')}"
    headers = {
        k: _substitute(v, base_url=base_url)
        for k, v in (raw_req.headers or {}).items()
    }
    # The Host header in the raw block is just `{{Hostname}}` — we
    # want the proxy_manager / underlying urllib to set Host from
    # the URL itself, so drop any Host header that came in.
    headers.pop("Host", None)
    headers.pop("host", None)
    body = (
        _substitute(raw_req.body, base_url=base_url)
        if isinstance(raw_req.body, str) and raw_req.body else None
    )
    return final_url, headers, body


def run_template(
    template: Template,
    *,
    target_url: str,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: float = 15.0,
) -> TemplateResult:
    """Execute one parsed template against `target_url`. Returns a
    `TemplateResult`; on success, `matched=True` with metadata."""
    if not template.is_supported:
        return TemplateResult(
            template_id=template.id,
            matched=False,
            error=(
                f"unsupported template kinds: {template.unsupported_kinds}"
            ),
        )

    if not target_url:
        return TemplateResult(
            template_id=template.id,
            matched=False,
            error="empty target_url",
        )

    base = _base_url(target_url)

    # proxy_manager — lazy import so unit tests can monkeypatch.
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return TemplateResult(
            template_id=template.id,
            matched=False,
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    base_extra_headers = dict(extra_headers or {})

    # Iterate HTTP probes; nuclei's default is "stop at first match"
    # — we honour it.
    for ridx, req in enumerate(template.http):
        # ---- iter-16: raw-HTTP probe path ----
        if req.is_raw and req.raw_requests:
            for raw_req in req.raw_requests:
                final_url, raw_headers, raw_body = _interpolate_raw(
                    raw_req, base_url=base,
                )
                merged_headers = {**raw_headers, **base_extra_headers}
                # Use raw-socket sender — urllib normalises percent-
                # encoded path segments BEFORE sending, which breaks
                # exploits that depend on `%2e` reaching the wire
                # intact (CVE-2021-41773 and its sibling LFIs). The
                # proxy_manager goes through urllib; we bypass it
                # here for raw probes.
                try:
                    resp = _send_raw_http(
                        raw_req.method,
                        final_url,
                        headers=merged_headers,
                        body=raw_body,
                        timeout=timeout_seconds,
                    )
                except Exception as e:  # noqa: BLE001
                    logger.debug(
                        "nuclei_runner: raw transport error on %s: %s",
                        final_url, e,
                    )
                    continue
                if "error" in resp and not resp.get("status_code"):
                    continue
                status = int(resp.get("status_code") or 0)
                response_body = resp.get("body") or ""
                if not isinstance(response_body, str):
                    response_body = str(response_body)
                response_headers = resp.get("headers") or {}
                if not isinstance(response_headers, dict):
                    response_headers = {}

                matched, matched_list = evaluate_matchers(
                    req.matchers,
                    condition=req.matchers_condition,
                    body=response_body,
                    headers=response_headers,
                    status=status,
                )
                if matched:
                    return TemplateResult(
                        template_id=template.id,
                        matched=True,
                        matched_request_index=ridx,
                        # Use the substituted final_url, not the
                        # raw `{{BaseURL}}` template path — so
                        # downstream emit_finding has a concrete
                        # endpoint to attach.
                        matched_path=final_url,
                        response_status=status,
                        response_body_excerpt=response_body[:1500],
                        matched_matchers=[m.type for m in matched_list],
                    )
            # Move to next request in template after this raw block.
            continue

        for path in req.paths:
            final_url, req_headers, body = _interpolate_request(
                req, base_url=base, path=path,
            )
            merged_headers = {**req_headers, **base_extra_headers}
            try:
                resp = pm.send_simple_request(
                    req.method,
                    final_url,
                    headers=merged_headers,
                    body=body or "",
                    timeout=timeout_seconds,
                )
            except Exception as e:  # noqa: BLE001
                logger.debug(
                    "nuclei_runner: transport error on %s: %s",
                    final_url, e,
                )
                continue
            if "error" in resp and not resp.get("status_code"):
                continue

            status = int(resp.get("status_code") or 0)
            response_body = resp.get("body") or ""
            if not isinstance(response_body, str):
                response_body = str(response_body)
            response_headers = resp.get("headers") or {}
            if not isinstance(response_headers, dict):
                response_headers = {}

            matched, matched_list = evaluate_matchers(
                req.matchers,
                condition=req.matchers_condition,
                body=response_body,
                headers=response_headers,
                status=status,
            )
            if matched:
                return TemplateResult(
                    template_id=template.id,
                    matched=True,
                    matched_request_index=ridx,
                    # Use the substituted final_url, not the raw
                    # template `{{BaseURL}}` form — same reason as
                    # the raw-HTTP branch above. Downstream emit_finding
                    # binds this to the FindingDraft.endpoint.
                    matched_path=final_url,
                    response_status=status,
                    response_body_excerpt=response_body[:1500],
                    matched_matchers=[m.type for m in matched_list],
                )
            if req.stop_at_first_match:
                # Continue to other paths on this request — but if
                # the template wants to stop early, the next path is
                # still tried within the same request (nuclei's
                # convention). We move on after exhausting paths.
                continue
        # Move to next request only after exhausting paths in this one.

    return TemplateResult(template_id=template.id, matched=False)
