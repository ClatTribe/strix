from typing import Any, Literal

from strix.tools.registry import register_tool


RequestPart = Literal["request", "response"]


@register_tool
def list_requests(
    httpql_filter: str | None = None,
    start_page: int = 1,
    end_page: int = 1,
    page_size: int = 50,
    sort_by: Literal[
        "timestamp",
        "host",
        "method",
        "path",
        "status_code",
        "response_time",
        "response_size",
        "source",
    ] = "timestamp",
    sort_order: Literal["asc", "desc"] = "desc",
    scope_id: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_requests(
        httpql_filter, start_page, end_page, page_size, sort_by, sort_order, scope_id
    )


@register_tool
def view_request(
    request_id: str,
    part: RequestPart = "request",
    search_pattern: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_request(request_id, part, search_pattern, page, page_size)


@register_tool
def send_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 30,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if headers is None:
        headers = {}
    manager = get_proxy_manager()
    response = manager.send_simple_request(method, url, headers, body, timeout)

    # Roadmap §8.5 Phase 5 — auto-populate SecurityContext so the
    # lead's notebook stays current. Best-effort: never fails the
    # request. Records the endpoint, captures tech-stack hints from
    # response headers, and notes auth-required if 401/403.
    try:
        from strix.agents.security_context import (
            record_endpoint,
            record_partial_signal,
            update_tech_stack,
        )

        if isinstance(response, dict):
            status = response.get("status_code")
            resp_headers = response.get("headers") or {}
            # Normalize header keys to title-case for consistent lookups.
            resp_headers_lc = {k.lower(): v for k, v in resp_headers.items()
                               if isinstance(k, str)}

            # Extract param names from query string + body for ledger.
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params: list[str] = list(parse_qs(parsed.query).keys())
            body_params: list[str] = []
            if isinstance(body, str) and body.strip():
                # Heuristic: try JSON, then form-urlencoded.
                try:
                    import json as _json
                    data = _json.loads(body)
                    if isinstance(data, dict):
                        body_params = list(data.keys())
                except Exception:  # noqa: BLE001
                    if "=" in body and "&" in body or "=" in body:
                        try:
                            body_params = list(parse_qs(body).keys())
                        except Exception:  # noqa: BLE001
                            pass
            params.extend(body_params)

            auth_required: bool | None = None
            if status in (401, 403):
                auth_required = True
            elif status and 200 <= status < 400:
                auth_required = False

            record_endpoint(
                url,
                method=method,
                status=status if isinstance(status, int) else None,
                params=params or None,
                auth_required=auth_required,
                response_headers={k: v for k, v in resp_headers.items()
                                  if isinstance(k, str)
                                  and k.lower() in {
                                      "server", "x-powered-by", "x-aspnet-version",
                                      "x-aspnetmvc-version", "via", "set-cookie",
                                      "location", "content-type", "www-authenticate",
                                  }},
            )

            # Tech stack hints from response headers.
            ts_kwargs: dict[str, Any] = {}
            if "server" in resp_headers_lc:
                ts_kwargs["server"] = resp_headers_lc["server"]
            if "x-powered-by" in resp_headers_lc:
                ts_kwargs["language"] = resp_headers_lc["x-powered-by"]
            if "x-aspnet-version" in resp_headers_lc:
                ts_kwargs["framework"] = "ASP.NET " + resp_headers_lc["x-aspnet-version"]
            if "via" in resp_headers_lc and "varnish" in resp_headers_lc["via"].lower():
                ts_kwargs["framework"] = "Varnish"
            # Version disclosure if server includes a version number
            srv = resp_headers_lc.get("server", "")
            import re as _re
            if isinstance(srv, str) and _re.search(r"\d+\.\d+", srv):
                ts_kwargs["version_disclosed"] = True
            if ts_kwargs or any(h.lower() in resp_headers_lc for h in ("server", "x-powered-by")):
                ts_kwargs["raw_headers"] = {
                    k: v for k, v in resp_headers.items()
                    if isinstance(k, str) and k.lower() in {
                        "server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version", "via",
                    }
                }
                update_tech_stack(**ts_kwargs)

            # Partial signal: URL value reflected in Location header
            # — candidate open-redirect.
            location = resp_headers_lc.get("location", "")
            if isinstance(location, str) and location:
                # Check if any query param value appears verbatim in Location.
                for pv in parse_qs(parsed.query).values():
                    for v in pv:
                        if v and len(v) > 4 and v in location:
                            record_partial_signal(
                                surface=f"{method} {parsed.path} (param value reflected)",
                                signal=f"Query param value '{v}' reflected verbatim in Location header → '{location}'",
                                next_probe="scan_xss / open_redirect_check on this param with absolute external URL (e.g. https://evil.example)",
                                category_hint="open_redirect",
                            )
                            break

            # Phase 1.4 — OpenAPI / Swagger threat-model parser. When
            # the response body looks like an OpenAPI spec, parse it
            # and pre-populate SecurityContext with every documented
            # endpoint + per-endpoint specialist hints (POST = CSRF +
            # auth check; numeric path = IDOR candidate; query string
            # = XSS/SQLi candidate). Massively accelerates discovery
            # — instead of waiting for the lead to crawl, we get the
            # canonical surface map for free.
            try:
                _parse_and_record_openapi_spec(
                    url=url,
                    body_text=response.get("body") or "",
                    content_type=resp_headers_lc.get("content-type", ""),
                )
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        # Never fail the request because of bookkeeping.
        pass

    return response


def _parse_and_record_openapi_spec(
    *, url: str, body_text: str, content_type: str,
) -> None:
    """Detect + parse an OpenAPI / Swagger spec and pre-populate
    SecurityContext with documented endpoints. Called from
    `send_request`'s side-effect block.

    Detection: response body parses as JSON AND has either
    `swagger:` or `openapi:` top-level key (Swagger 2 / OpenAPI 3).
    YAML specs are best-effort — if the body parses as YAML and has
    the markers, we use it.

    Per-endpoint records:
      * `record_endpoint(path, method, params=...)` for every operation
      * `record_partial_signal` with a per-shape next_probe hint:
          - POST/PUT/PATCH = state-change → CSRF + auth check
          - numeric path param = IDOR candidate
          - query string params = XSS / SQLi candidate
    """
    if not body_text or not isinstance(body_text, str):
        return
    # Cheap pre-filter: must look JSON-shaped and small enough that
    # parse cost is bounded.
    if len(body_text) > 5_000_000:  # 5MB cap
        return
    body_stripped = body_text.lstrip()
    if not body_stripped.startswith(("{", "[")):
        return
    if "swagger" not in body_stripped[:2000].lower() and "openapi" not in body_stripped[:2000].lower():
        return

    import json as _json
    try:
        spec = _json.loads(body_text)
    except Exception:  # noqa: BLE001
        return
    if not isinstance(spec, dict):
        return
    if not (spec.get("swagger") or spec.get("openapi")):
        return

    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return

    from urllib.parse import urlparse as _urlparse

    from strix.agents.security_context import (
        record_endpoint,
        record_partial_signal,
    )

    parsed_target = _urlparse(url)
    base = f"{parsed_target.scheme}://{parsed_target.netloc}"
    # OpenAPI 3 has servers[0].url; Swagger 2 has basePath
    if isinstance(spec.get("servers"), list) and spec["servers"]:
        s0 = spec["servers"][0]
        if isinstance(s0, dict) and s0.get("url"):
            su = s0["url"]
            if su.startswith("/"):
                base = base + su
            else:
                base = su.rstrip("/")
    elif spec.get("basePath"):
        base = base + spec["basePath"]

    methods_with_body = {"post", "put", "patch", "delete"}
    state_change_methods = {"post", "put", "patch", "delete"}

    for path_pattern, ops in paths.items():
        if not isinstance(ops, dict) or not isinstance(path_pattern, str):
            continue
        full_path = base + path_pattern
        # Collect param names declared in the path-level + per-op.
        path_level_params = ops.get("parameters", []) if isinstance(ops, dict) else []
        for method, op in ops.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            if not isinstance(op, dict):
                continue
            op_params = op.get("parameters", [])
            all_params = (path_level_params or []) + (op_params or [])
            param_names: list[str] = []
            has_body_param = False
            for p in all_params:
                if not isinstance(p, dict):
                    continue
                pname = p.get("name")
                ploc = (p.get("in") or "").lower()
                if isinstance(pname, str):
                    param_names.append(pname)
                if ploc == "body":
                    has_body_param = True

            record_endpoint(
                full_path,
                method=method.upper(),
                params=param_names or None,
                notes="documented in OpenAPI/Swagger spec",
            )

            # Per-shape probe hints.
            if method.lower() in state_change_methods:
                record_partial_signal(
                    surface=f"{method.upper()} {path_pattern} (state-change endpoint)",
                    signal="OpenAPI declares this as a write endpoint",
                    next_probe="csrf_check; scan_auth_flow re-test with anon → expect 401",
                    category_hint="csrf",
                )
            # Numeric path param → IDOR candidate
            import re as _re
            if _re.search(r"\{[a-zA-Z_]+_?id\}|\{id\}|\{[A-Za-z]+Id\}", path_pattern):
                record_partial_signal(
                    surface=f"{method.upper()} {path_pattern} (numeric path param)",
                    signal="OpenAPI path declares an ID parameter — classic IDOR shape",
                    next_probe="scan_sqli with method+params for SQLi via path; scan_idor with multi-role auth",
                    category_hint="idor",
                )
            # Query/body params → XSS+SQLi candidate
            if param_names and method.lower() in methods_with_body:
                record_partial_signal(
                    surface=f"{method.upper()} {path_pattern} (params: {','.join(param_names[:3])})",
                    signal=f"OpenAPI declares {len(param_names)} param(s) on this endpoint",
                    next_probe="scan_xss / scan_sqli on each param; for body endpoints use body_template={...}",
                    category_hint="injection",
                )


@register_tool
def repeat_request(
    request_id: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    if modifications is None:
        modifications = {}
    manager = get_proxy_manager()
    return manager.repeat_request(request_id, modifications)


@register_tool
def scope_rules(
    action: Literal["get", "list", "create", "update", "delete"],
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
    scope_id: str | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.scope_rules(action, allowlist, denylist, scope_id, scope_name)


@register_tool
def list_sitemap(
    scope_id: str | None = None,
    parent_id: str | None = None,
    depth: Literal["DIRECT", "ALL"] = "DIRECT",
    page: int = 1,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.list_sitemap(scope_id, parent_id, depth, page)


@register_tool
def view_sitemap_entry(
    entry_id: str,
) -> dict[str, Any]:
    from .proxy_manager import get_proxy_manager

    manager = get_proxy_manager()
    return manager.view_sitemap_entry(entry_id)
