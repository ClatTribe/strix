"""Run a parsed Template against a target URL.

Single-template execution; the runner specialist handles
multi-template iteration. Substitutes `{{BaseURL}}` with the
target's `scheme://host[:port]`, sends the request via the global
proxy_manager, evaluates matchers, and returns a `TemplateResult`.

Multi-step templates (a sequence of HTTP probes) are partially
supported — each step is run independently in order, and we stop
at the first match (the default nuclei behaviour). Variable
extraction across steps is NOT supported in this MVP.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from strix.tools.nuclei_runner.matchers import evaluate_matchers
from strix.tools.nuclei_runner.parser import HttpRequest, Matcher, Template


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
        if req.raw:
            # We don't interpret raw HTTP yet; skip.
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
                    matched_path=path,
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
