"""Authorization-matrix prober.

Roadmap §7.2. For each (role × endpoint) cell, dispatch the same request
as that role and compare outcomes. Detects:

- **Unauthenticated bypass** — an `unauth` role gets the same 2xx response
  as authenticated roles. CWE-862 (Missing Authorization).
- **Vertical privilege escalation** — a lower-privilege role gets the same
  response as a higher-privilege one on an admin-shaped endpoint. CWE-285
  (Improper Authorization). Heuristic: path contains `admin`, `internal`,
  `private`, `manage`, `superuser`, `staff`, or matches a regex set
  configurable via `admin_path_patterns`.

Composes with cluster-A safety (auth-injection / exclude-path / rate-
limit) and cluster-B's endpoint inventory shape — pass the
`endpoints` field from `bfs_crawl`'s output verbatim.

Roles are supplied per-call (not via env) because most engagements need
two or three roles for a full matrix and the values are credential-
shaped — keeping them in the agent's tool-call args (which the wrapper
injects from a credentials vault) is cleaner than a multi-flag CLI.
The values are still NOT logged: this tool short-strings them in event
emission and never echoes the headers to the LLM context.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "authz_matrix_check"

_DEFAULT_TIMEOUT = 12

# Heuristic admin-path patterns. Operators can override with the
# `admin_path_patterns` parameter (comma-separated regex).
_DEFAULT_ADMIN_PATTERNS: tuple[str, ...] = (
    r"/admin\b",
    r"/internal\b",
    r"/private\b",
    r"/manage\b",
    r"/superuser\b",
    r"/staff\b",
    r"/_admin\b",
    r"/sudo\b",
    r"/root\b",
)

# Hard cap on cells (roles × endpoints) to bound the work + protect the
# rate-limit budget. Operators tune via parameters.
_DEFAULT_MAX_CELLS = 200
_HARD_MAX_CELLS = 2000


def _normalize_endpoints(raw: Any) -> list[dict[str, Any]]:
    """Accept either bfs_crawl's endpoint shape or a flat list of strings.

    Output: [{url, method}, ...] de-duplicated.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            # Fall back: comma-separated URL list with implicit GET method.
            raw = [u.strip() for u in raw.split(",") if u.strip()]
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(raw, list):
        return out
    for entry in raw:
        if isinstance(entry, str):
            url, method = entry, "GET"
        elif isinstance(entry, dict):
            url = entry.get("url")
            method = (entry.get("method") or "GET").upper()
        else:
            continue
        if not isinstance(url, str) or not url:
            continue
        key = (url, method)
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": url, "method": method})
    return out


def _normalize_roles(raw: Any) -> list[dict[str, Any]]:
    """Accept the agent's roles list and normalize.

    Each role: {name: str, headers: dict[str, str], privilege?: int}
    `privilege` is optional; default 50 for named roles, 0 for `unauth`.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        headers = entry.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        # Coerce all to string-string.
        headers = {
            str(k): str(v) for k, v in headers.items() if isinstance(k, str) and k.strip()
        }
        privilege = entry.get("privilege")
        if not isinstance(privilege, (int, float)):
            privilege = 0 if name.lower() in ("unauth", "anonymous", "anon") else 50
        out.append({
            "name": name,
            "headers": headers,
            "privilege": int(privilege),
        })
    # Stable ordering: lowest privilege first so cell-comparison
    # heuristics see the unauth/low-priv result before the authenticated.
    out.sort(key=lambda r: (r["privilege"], r["name"]))
    return out


def _looks_admin_path(url: str, patterns: list[re.Pattern[str]]) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    path = parsed.path or "/"
    return any(p.search(path) for p in patterns)


def _send_with_role(
    method: str, url: str, role_headers: dict[str, str], timeout: int
) -> dict[str, Any]:
    """Single role-tagged request. Tries the proxy first (gets cluster-A
    middleware: auth-inject / exclude-path / rate-limit); falls back to
    direct httpx with the same env-driven middleware."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            return manager.send_simple_request(method, url, headers=role_headers, timeout=timeout)
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
            return excluded_response(url, glob or "")
        merged = inject_auth_headers(role_headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.request(method, url, headers=merged)
            return {
                "status_code": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:10000],
            }
    except Exception as e:  # noqa: BLE001
        return {"error": f"request failed: {type(e).__name__}", "details": str(e)}


def _outcome_signature(response: dict[str, Any]) -> tuple[int, int]:
    """A tiny hash of the response that's stable for `same response` checks
    without storing bodies cell-by-cell. (status_code, body_length)."""
    if response.get("error") or response.get("skipped"):
        return (0, 0)
    status = int(response.get("status_code") or 0)
    body = response.get("body") or ""
    return (status, len(body))


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1078", "T1078.004"],  # Valid Accounts + Cloud Accounts (authz)
)
def authz_matrix_check(  # noqa: PLR0913
    endpoints: str,
    roles: str,
    timeout: int = _DEFAULT_TIMEOUT,
    max_cells: int = _DEFAULT_MAX_CELLS,
    admin_path_patterns: str | None = None,
) -> dict[str, Any]:
    """Test authorization across (role × endpoint) cells.

    Args:
        endpoints: JSON-encoded list of `{url, method}` (or flat URL list).
                   Pass `bfs_crawl`'s `endpoints` field verbatim.
        roles: JSON-encoded list of role dicts:
                 [{"name": "unauth", "headers": {}},
                  {"name": "user", "headers": {"Cookie": "session=user-token"},
                   "privilege": 50},
                  {"name": "admin", "headers": {"Cookie": "session=admin-token"},
                   "privilege": 100}]
               `privilege` is optional (default 50, or 0 for `unauth`).
               Headers cross only into the proxy's request — never logged.
        timeout: per-request timeout in seconds.
        max_cells: cap on (role × endpoint) cells probed. Default 200,
                   hard-capped at 2000.
        admin_path_patterns: comma-separated regex list; default is a
                             standard set (admin/internal/private/manage/...).

    Findings:
        - **High** (CWE-862, missing_authorization) when an `unauth` role
          succeeds (2xx) on an endpoint where ANY authenticated role also
          succeeds — anonymous bypass.
        - **High** (CWE-285, improper_authorization) when a lower-privilege
          role gets the same outcome signature as a higher-privilege role
          on an admin-shaped path — vertical priv-esc.

    Returns:
        {
          success, target,
          roles: [...], endpoints_count,
          cells: [{role, url, method, status, body_length, signature}],
          findings: [{type, severity, role, endpoint, evidence}],
          stats: {cells_probed, cells_skipped, ...}
        }
    """
    parsed_endpoints = _normalize_endpoints(endpoints)
    parsed_roles = _normalize_roles(roles)
    if not parsed_endpoints:
        return {"success": False, "error": "no valid endpoints supplied"}
    if not parsed_roles:
        return {
            "success": False,
            "error": "no valid roles supplied (need at least one)",
        }

    # Compile admin patterns.
    if admin_path_patterns:
        raw_patterns = [p.strip() for p in admin_path_patterns.split(",") if p.strip()]
    else:
        raw_patterns = list(_DEFAULT_ADMIN_PATTERNS)
    compiled_patterns: list[re.Pattern[str]] = []
    for p in raw_patterns:
        try:
            compiled_patterns.append(re.compile(p, re.IGNORECASE))
        except re.error:
            logger.debug("skipping invalid admin path pattern: %s", p)

    capped = max(1, min(max_cells, _HARD_MAX_CELLS))
    cells: list[dict[str, Any]] = []
    cells_probed = 0
    cells_skipped = 0

    # Tracer for per-cell check events.
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
    except Exception:  # noqa: BLE001
        tracer = None

    # We probe in row-major order: for each endpoint, try all roles.
    # Lets us compare outcomes per-endpoint cell-by-cell.
    for endpoint in parsed_endpoints:
        url = endpoint["url"]
        method = endpoint["method"]
        per_endpoint_results: dict[str, dict[str, Any]] = {}
        for role in parsed_roles:
            if cells_probed >= capped:
                cells_skipped += 1
                continue
            cells_probed += 1
            check_id = None
            if tracer is not None:
                try:
                    check_id = tracer.start_check(
                        category="authorization", surface=url, tool=_TOOL_NAME
                    )
                except Exception:  # noqa: BLE001
                    check_id = None

            response = _send_with_role(method, url, role["headers"], timeout)
            sig = _outcome_signature(response)
            cell = {
                "role": role["name"],
                "url": url,
                "method": method,
                "status": sig[0],
                "body_length": sig[1],
                "signature": f"{sig[0]}:{sig[1]}",
                "skipped": bool(response.get("skipped")),
            }
            if response.get("error"):
                cell["error"] = response.get("error")
            cells.append(cell)
            per_endpoint_results[role["name"]] = cell

            if tracer is not None and check_id:
                try:
                    if cell.get("skipped") or cell.get("error"):
                        result = "inconclusive"
                    else:
                        result = "not_vulnerable"
                    tracer.complete_check(
                        check_id,
                        result=result,
                        evidence=f"{role['name']}: {sig[0]} ({sig[1]} bytes)",
                    )
                except Exception:  # noqa: BLE001
                    pass

        # Per-endpoint detection passes.
        is_admin_path = _looks_admin_path(url, compiled_patterns)

        # 1. Unauth bypass: a role named unauth/anonymous returned 2xx AND
        #    at least one other role also returned 2xx with a similar sig.
        unauth_cell = next(
            (c for c in per_endpoint_results.values()
             if c["role"].lower() in ("unauth", "anonymous", "anon")),
            None,
        )
        if unauth_cell and 200 <= unauth_cell["status"] < 300:
            # Compare against any authenticated role.
            for role in parsed_roles:
                if role["privilege"] <= 0:
                    continue
                authed_cell = per_endpoint_results.get(role["name"])
                if not authed_cell:
                    continue
                if authed_cell["signature"] == unauth_cell["signature"]:
                    # Same response — anonymous bypass.
                    _emit_authz_finding(
                        finding_type="unauth_bypass",
                        severity="high",
                        category="missing_authorization",
                        cwe="CWE-862",
                        url=url,
                        method=method,
                        roles_involved=[unauth_cell["role"], authed_cell["role"]],
                        evidence=(
                            f"`{unauth_cell['role']}` (no auth) and "
                            f"`{authed_cell['role']}` (privilege "
                            f"{role['privilege']}) both return "
                            f"{unauth_cell['status']} with identical body "
                            f"length ({unauth_cell['body_length']} bytes) on "
                            f"{method} {url}. The endpoint accepts "
                            "unauthenticated access where authentication is "
                            "expected."
                        ),
                    )
                    break

        # 2. Vertical priv-esc: lower-privilege role got identical signature
        #    to a higher-privilege role on an admin-shaped path.
        if is_admin_path and len(parsed_roles) >= 2:
            sorted_roles = sorted(parsed_roles, key=lambda r: r["privilege"])
            for low_idx, low_role in enumerate(sorted_roles):
                low_cell = per_endpoint_results.get(low_role["name"])
                if not low_cell or not (200 <= low_cell["status"] < 300):
                    continue
                if low_role["name"].lower() in ("unauth", "anonymous", "anon"):
                    # Already covered by unauth bypass detection.
                    continue
                for high_role in sorted_roles[low_idx + 1:]:
                    high_cell = per_endpoint_results.get(high_role["name"])
                    if not high_cell:
                        continue
                    if (
                        200 <= high_cell["status"] < 300
                        and high_cell["signature"] == low_cell["signature"]
                    ):
                        _emit_authz_finding(
                            finding_type="vertical_priv_esc",
                            severity="high",
                            category="improper_authorization",
                            cwe="CWE-285",
                            url=url,
                            method=method,
                            roles_involved=[low_cell["role"], high_cell["role"]],
                            evidence=(
                                f"`{low_role['name']}` (privilege "
                                f"{low_role['privilege']}) and "
                                f"`{high_role['name']}` (privilege "
                                f"{high_role['privilege']}) get identical "
                                f"responses on {method} {url} (admin-shaped "
                                f"path). Lower-privilege account can access "
                                "this admin surface."
                            ),
                        )
                        break

    return {
        "success": True,
        "endpoints_count": len(parsed_endpoints),
        "roles": [{"name": r["name"], "privilege": r["privilege"]} for r in parsed_roles],
        "cells": cells,
        "stats": {
            "cells_probed": cells_probed,
            "cells_skipped": cells_skipped,
            "max_cells": capped,
        },
    }


def _emit_authz_finding(  # noqa: PLR0913
    *,
    finding_type: str,
    severity: str,
    category: str,
    cwe: str,
    url: str,
    method: str,
    roles_involved: list[str],
    evidence: str,
) -> None:
    """Centralizes finding emission so the role names can be sanitized
    once. Role headers are NEVER passed to the tracer — only role names
    (which are operator-chosen labels) appear in finding evidence."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    title_prefix = (
        "Unauthenticated access to" if finding_type == "unauth_bypass"
        else "Privilege escalation via authorization gap on"
    )
    impact = (
        "Anyone on the public internet can reach this endpoint without "
        "authentication. Any data returned is fully exposed; any state "
        "change accepted is fully unauthenticated. This is the highest-"
        "impact authorization gap."
        if finding_type == "unauth_bypass"
        else "A lower-privilege account can reach an admin-shaped "
        "endpoint and receive the same response as the privileged "
        "account. The privilege boundary is not enforced server-side."
    )
    remediation = (
        "Add authentication at the route. For session-based auth, ensure "
        "the auth middleware is applied to this path; for JWT, verify the "
        "token signature and required claims. Add a regression test that "
        "calls the endpoint with no credentials and asserts a 401/403."
        if finding_type == "unauth_bypass"
        else "Add a server-side authorization check at the route. Verify "
        "the caller's role/scope before processing the request — "
        "client-side checks alone are not sufficient. Pair with audit "
        "logging on this surface so future bypasses are visible."
    )
    finding_id = tracer.add_vulnerability_report(
        title=f"{title_prefix} {method} {url}",
        severity=severity,
        category=category,
        cwe=cwe,
        target=url,
        endpoint=url,
        method=method,
        description=evidence,
        impact=impact,
        remediation_steps=remediation,
        verification_status="needs_review",
    )
    # §3 KG side-effect — Vuln + Surface + AFFECTS triple. The
    # method discriminates Surface dedup (GET vs POST same path
    # = two surfaces, since authz boundaries are method-specific).
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=url,
            param=",".join(roles_involved[:2]) or "anon",
            cwe=cwe, severity=severity, category=category,
            method=method,
            detection_kind=finding_type,
            confidence=0.9,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "authz_matrix: kg record failed: %s", e, exc_info=True,
        )
