"""Request-builder helpers shared across deterministic specialists
(roadmap §8.5 Phase 3c).

The Phase 3b specialists (`scan_xss`, `scan_sqli`) only handled
GET-with-querystring. That's a fatal mismatch for modern APIs where
the high-impact bugs live behind POST + JSON / form bodies (Juice
Shop login, Altoro Mutual transfer, OAuth flows, GraphQL endpoints).
This module factors out the shared work so each specialist can
accept `method=`, `body_template=`, and `body_format=` args without
duplicating the substitution logic.

Supported probe vectors
-----------------------

  * **Query string** — GET (or any method) with `?param=payload`.
    The default; preserves Phase 3b behavior.
  * **JSON body** — POST/PUT/PATCH with `Content-Type: application/json`.
    Caller supplies a `body_template` dict; the builder deep-copies
    and replaces the named param's value with the payload.
  * **Form body** — POST/PUT/PATCH with `application/x-www-form-urlencoded`.
    Caller supplies a `body_template` dict; the builder URL-encodes
    after substitution.
  * **Path param** — URL with a literal `{param_name}` placeholder
    (e.g., `/api/Baskets/{id}`). The builder substitutes the
    payload directly into the path segment.

Detection helpers in scan_xss / scan_sqli are protocol-agnostic —
they only inspect the response body / status / headers. So the
builders are purely the request-side change.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


logger = logging.getLogger(__name__)


def is_path_param_url(url: str, param_name: str) -> bool:
    """True when `url` contains `{param_name}` as a literal path
    placeholder."""
    return f"{{{param_name}}}" in url


def build_request(
    *,
    url: str,
    method: str,
    param_name: str,
    payload: str,
    body_template: dict[str, Any] | str | None = None,
    body_format: str = "auto",
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, str, dict[str, str], str]:
    """Build (method, url, headers, body) for a single probe.

    Args:
        url: target URL. May contain `{param_name}` for path-param
            substitution.
        method: HTTP method.
        param_name: which parameter the probe is targeting.
        payload: payload to substitute into the param's value.
        body_template: when provided, payload is substituted INTO
            the body, not the URL. dict → JSON or form (per
            body_format); str → raw body with `{param_name}`
            placeholder.
        body_format: `"json"` / `"form"` / `"auto"`. `"auto"` infers
            JSON for dict templates.
        other_params: baseline values for OTHER query params.
        extra_headers: forwarded as-is.

    Returns:
        `(method, final_url, headers, body)` ready for
        `proxy_manager.send_simple_request`.
    """
    method = (method or "GET").upper()
    headers: dict[str, str] = dict(extra_headers or {})

    # 1. Path-param substitution — independent of body / query.
    if is_path_param_url(url, param_name):
        url = url.replace(f"{{{param_name}}}", _safe_path_segment(payload))

    # 2. Body-based substitution.
    if body_template is not None:
        body, content_type = _build_body(
            body_template, body_format, param_name, payload,
        )
        if content_type and "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = content_type
        return method, url, headers, body

    # 3. Query-string substitution (default — Phase 3b behavior).
    final_url = _apply_query_param(
        url, param_name=param_name, value=payload,
        other_params=other_params,
    )
    return method, final_url, headers, ""


def _safe_path_segment(value: str) -> str:
    """Encode just enough so the payload doesn't blow apart URL
    parsing. Preserves SQL/XSS payload semantics — a `'` survives,
    a `<` survives, but a literal `/` would break path structure so
    we encode it. Conservative: encode the path-special set,
    leave everything else."""
    from urllib.parse import quote
    return quote(value, safe="'\"<>=")


def _apply_query_param(
    url: str, *,
    param_name: str,
    value: str,
    other_params: dict[str, str] | None = None,
) -> str:
    """Add/replace `param_name=value` in the URL's query string,
    preserving other params. Equivalent to the Phase 3b helpers in
    scan_xss/scan_sqli."""
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat: dict[str, str] = {k: (v[0] if v else "") for k, v in qs.items()}
    if other_params:
        for k, v in other_params.items():
            if k != param_name and k not in flat:
                flat[k] = v
    flat[param_name] = value
    return urlunparse(parts._replace(query=urlencode(flat, doseq=False)))


def _build_body(
    body_template: dict[str, Any] | str,
    body_format: str,
    param_name: str,
    payload: str,
) -> tuple[str, str | None]:
    """Substitute payload into body_template; return (body, content_type).

    For dict templates with a nested structure, only top-level keys
    are substituted in this minimal Phase 3c implementation. Nested
    JSON probes (e.g. `{"user": {"email": "..."}}`) are Phase 3d /
    follow-up.
    """
    fmt = body_format.lower()
    if isinstance(body_template, dict):
        # Auto-detect: dicts default to JSON.
        if fmt == "auto":
            fmt = "json"
        # Deep copy so the caller's template isn't mutated across probes.
        body_dict = copy.deepcopy(body_template)
        if param_name in body_dict:
            body_dict[param_name] = payload
        else:
            # Param name not in template — caller mistake but don't
            # crash. The probe will hit the endpoint with the original
            # template, providing a baseline-equivalent signal.
            logger.debug(
                "build_request: param %r not found in body_template "
                "keys %s; sending unmodified body",
                param_name, list(body_dict.keys()),
            )
        if fmt == "json":
            return json.dumps(body_dict), "application/json"
        if fmt == "form":
            return urlencode(body_dict, doseq=False), "application/x-www-form-urlencoded"
        # Unknown format → JSON fallback.
        return json.dumps(body_dict), "application/json"

    if isinstance(body_template, str):
        # Raw body with `{param_name}` placeholder for substitution.
        body = body_template.replace(f"{{{param_name}}}", payload)
        # Caller-supplied content type via extra_headers takes precedence;
        # we don't add one for raw bodies.
        return body, None

    return "", None
