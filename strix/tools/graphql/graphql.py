"""GraphQL specialist — protocol-specific abuse tests.

Roadmap §7.2 cluster C, third item. The other two are already shipped:
- `authz_matrix_check` (#42) covers cross-role access at the HTTP layer
- the API Top 10 skill pack (#43) gives the agent the GraphQL-specific
  checklist to run as guidance

This tool runs the **deterministic** GraphQL-protocol-specific tests:

1. **Introspection probe** — issue the standard `__schema` query. When
   the endpoint returns the schema, emit an info finding (CWE-200) and
   capture the type/field inventory for the agent's downstream
   reasoning.
2. **Depth abuse** — send a recursive depth query (`{ me { friends {
   friends { friends { ... } } } } }`). If the server accepts it without
   error, the depth limit is missing.
3. **Alias overloading** — send N aliased copies of the same query in a
   single request. If the server processes all N, per-operation rate
   limits are bypassed (real DoS vector — N can be 100+).
4. **Batch query** — JSON array of operations in one POST. Same rate-
   limit bypass pattern.

All requests route through `proxy_manager.send_simple_request` so
cluster-A safety (auth-injection / exclude-path / rate-limit) applies
automatically. When the proxy isn't available, the direct fallback
also runs the same env-driven http_safety middleware.

Composes with `authz_matrix_check`: pass the GraphQL endpoint as one of
the URLs in the matrix to test field-level authz across roles.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "graphql_specialist_check"

_DEFAULT_TIMEOUT = 12

# The minimal introspection query — enough to confirm introspection is
# enabled and capture top-level type/field inventory without overwhelming
# the response payload.
_INTROSPECTION_QUERY = """\
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) { name }
      enumValues(includeDeprecated: true) { name }
    }
  }
}
"""

# Depth-abuse probe. Builds a deeply nested query against `__schema` so
# we don't depend on the target's actual type names.
def _build_depth_query(depth: int) -> str:
    """Construct a query with `depth` levels of nesting through the
    introspection schema. Each level wraps the previous in `ofType`."""
    inner = "name"
    for _ in range(max(1, depth)):
        inner = f"ofType {{ {inner} }}"
    return f"query DepthProbe {{ __schema {{ types {{ name kind {inner} }} }} }}"


def _build_alias_query(alias_count: int) -> str:
    """Build a single query body that aliases `__schema` N times. If the
    server processes all N, alias-based rate-limit bypass is confirmed."""
    parts = [f"a{i}: __schema {{ queryType {{ name }} }}" for i in range(alias_count)]
    return "query AliasProbe { " + " ".join(parts) + " }"


def _build_batch_payload(batch_size: int) -> list[dict[str, str]]:
    """Build the JSON-array batch payload."""
    q = "query BatchProbe { __schema { queryType { name } } }"
    return [{"query": q} for _ in range(batch_size)]


def _post_graphql(
    url: str,
    payload: Any,
    *,
    extra_headers: dict[str, str] | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """POST a GraphQL payload (JSON-encoded) to `url`. Routes through the
    sandbox proxy when available so cluster-A safety applies; falls back
    to direct httpx with the same env-driven http_safety middleware.

    Returns: {status_code, headers, body, elapsed_ms} or {error, ...}.
    """
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    body = json.dumps(payload)
    start = time.monotonic()

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None:
        try:
            result = manager.send_simple_request(
                "POST", url, headers=headers, body=body, timeout=timeout
            )
            result["elapsed_ms"] = int((time.monotonic() - start) * 1000)
            return result
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
            return {**excluded_response(url, glob or ""), "elapsed_ms": 0}
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.post(url, headers=merged, content=body)
            return {
                "status_code": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:20000],
                "elapsed_ms": int((time.monotonic() - start) * 1000),
            }
    except Exception as e:  # noqa: BLE001
        return {
            "error": f"request failed: {type(e).__name__}",
            "details": str(e),
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }


def _is_graphql_data_response(response: dict[str, Any]) -> bool:
    """Tells whether the response looks like a GraphQL `data` payload
    (vs. an error / forbidden / non-JSON response)."""
    if response.get("error") or response.get("skipped"):
        return False
    status = response.get("status_code") or 0
    if not (200 <= status < 300):
        return False
    body = response.get("body") or ""
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return False
    return isinstance(parsed, dict) and "data" in parsed and parsed.get("data") is not None


def _emit_finding(
    *,
    title: str,
    severity: str,
    category: str,
    cwe: str,
    target: str,
    description: str,
    impact: str,
    remediation: str,
    verification_status: str = "needs_review",
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
        category=category,
        cwe=cwe,
        target=target,
        endpoint=target,
        description=description,
        impact=impact,
        remediation_steps=remediation,
        verification_status=verification_status,
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None
    return tracer.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def graphql_specialist_check(  # noqa: PLR0912, PLR0915
    target_url: str,
    timeout: int = _DEFAULT_TIMEOUT,
    depth_probe_max: int = 12,
    alias_count: int = 100,
    batch_size: int = 50,
) -> dict[str, Any]:
    """Run the deterministic GraphQL-protocol-specific abuse tests.

    Args:
        target_url: GraphQL endpoint URL (typically `/graphql`,
                    `/api/graphql`, or `/v1/graphql`).
        timeout: per-request timeout in seconds.
        depth_probe_max: max nesting depth for the depth-abuse probe.
                         Default 12 — most servers should reject > 5-7.
        alias_count: how many aliased operations to send in one request.
                     Default 100 — should be rejected by any
                     well-configured server.
        batch_size: how many operations to send in a JSON-array batch.
                    Default 50.

    Tests:
        1. Introspection probe (info finding when enabled)
        2. Depth abuse (high finding when nested query accepted)
        3. Alias overloading (high finding when N aliases all processed)
        4. Batch query (medium finding when array batch accepted)

    Returns the structured result. Always success=True; per-test results
    are in `tests` and findings are emitted via the tracer.
    """
    if not target_url or not target_url.strip():
        return {"success": False, "error": "target_url required"}
    target_url = target_url.strip()
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"success": False, "error": f"invalid target URL: {target_url!r}"}

    results: dict[str, dict[str, Any]] = {}

    # ---- 1. Introspection probe ----
    cev = _start_check("graphql_introspection", target_url)
    introspection_response = _post_graphql(
        target_url, {"query": _INTROSPECTION_QUERY}, timeout=timeout
    )
    introspection_enabled = False
    schema_summary: dict[str, Any] = {}
    if _is_graphql_data_response(introspection_response):
        try:
            data = json.loads(introspection_response["body"])
            schema = data.get("data", {}).get("__schema") or {}
            type_count = len(schema.get("types") or [])
            if type_count > 0:
                introspection_enabled = True
                schema_summary = {
                    "type_count": type_count,
                    "query_type": (schema.get("queryType") or {}).get("name"),
                    "mutation_type": (schema.get("mutationType") or {}).get("name"),
                    "subscription_type": (schema.get("subscriptionType") or {}).get("name"),
                    # Sample of type names for downstream agent reasoning.
                    "sample_types": [
                        t.get("name") for t in (schema.get("types") or [])[:30]
                        if isinstance(t, dict) and t.get("name")
                    ],
                }
        except (ValueError, TypeError, KeyError, AttributeError):
            pass
    results["introspection"] = {
        "enabled": introspection_enabled,
        "status": introspection_response.get("status_code"),
        "schema_summary": schema_summary,
    }
    _complete_check(
        cev,
        result="vulnerable" if introspection_enabled else "not_vulnerable",
        evidence=(
            f"introspection enabled — {schema_summary.get('type_count', 0)} types disclosed"
            if introspection_enabled
            else f"introspection disabled (status {introspection_response.get('status_code')})"
        ),
    )
    if introspection_enabled:
        _emit_finding(
            title=f"GraphQL introspection enabled on {target_url}",
            severity="info",
            category="info_disclosure",
            cwe="CWE-200",
            target=target_url,
            description=(
                f"The GraphQL endpoint at {target_url} responds to the standard "
                f"`__schema` introspection query, disclosing the full type system "
                f"({schema_summary.get('type_count', 0)} types including "
                f"{schema_summary.get('query_type')!r} as the root query). "
                "OWASP API9 and OWASP API8 — production endpoints should disable "
                "introspection unless explicitly required for client tooling."
            ),
            impact=(
                "Schema disclosure removes a layer of obscurity. Attackers can map "
                "every queryable field, every mutation, every input type's required "
                "fields without trial-and-error — accelerating discovery of BOLA / "
                "BOPLA / mass-assignment / authz gaps."
            ),
            remediation=(
                "Disable introspection in production. For Apollo Server: "
                "`introspection: false`. For Hasura: `enable-introspection` flag. "
                "For graphql-yoga: `validationRules: [NoSchemaIntrospectionCustomRule]`. "
                "Keep introspection enabled in non-production tiers for client "
                "code-generation, but block it on the production-facing route."
            ),
        )

    # ---- 2. Depth abuse ----
    cev = _start_check("graphql_depth_abuse", target_url)
    depth_query = _build_depth_query(depth_probe_max)
    depth_response = _post_graphql(target_url, {"query": depth_query}, timeout=timeout)
    depth_accepted = _is_graphql_data_response(depth_response)
    results["depth_abuse"] = {
        "depth_tested": depth_probe_max,
        "accepted": depth_accepted,
        "status": depth_response.get("status_code"),
        "elapsed_ms": depth_response.get("elapsed_ms"),
    }
    _complete_check(
        cev,
        result="vulnerable" if depth_accepted else "not_vulnerable",
        evidence=(
            f"depth-{depth_probe_max} query accepted ({depth_response.get('elapsed_ms')}ms)"
            if depth_accepted
            else f"depth-{depth_probe_max} query rejected (status "
            f"{depth_response.get('status_code')})"
        ),
    )
    if depth_accepted:
        _emit_finding(
            title=f"GraphQL depth limit missing on {target_url}",
            severity="high",
            category="dos",
            cwe="CWE-770",
            target=target_url,
            description=(
                f"The endpoint accepted a query nested {depth_probe_max} levels deep "
                f"({depth_response.get('elapsed_ms')}ms response time). OWASP API4 — "
                "no max-depth enforcement means an attacker can construct queries "
                "with super-linear server cost."
            ),
            impact=(
                "Denial of service via deeply-nested queries. A single attacker "
                "request can pin a CPU core for seconds; a handful of concurrent "
                "attackers can saturate the API."
            ),
            remediation=(
                "Apply a query-depth limit at the GraphQL layer. "
                "graphql-depth-limit npm package: `depthLimit(7)` is a common "
                "ceiling. graphql-cost-analysis is more sophisticated — bounds the "
                "estimated cost rather than just the depth. Reject queries above "
                "the threshold before resolver execution."
            ),
        )

    # ---- 3. Alias overloading ----
    cev = _start_check("graphql_alias_abuse", target_url)
    alias_query = _build_alias_query(alias_count)
    alias_response = _post_graphql(target_url, {"query": alias_query}, timeout=timeout)
    alias_accepted = False
    if _is_graphql_data_response(alias_response):
        try:
            data = json.loads(alias_response["body"])
            data_block = data.get("data") or {}
            # Count how many aliases came back successfully populated.
            alias_keys = [k for k in data_block.keys() if k.startswith("a")]
            alias_accepted = len(alias_keys) >= alias_count
        except (ValueError, TypeError):
            pass
    results["alias_abuse"] = {
        "aliases_sent": alias_count,
        "all_accepted": alias_accepted,
        "status": alias_response.get("status_code"),
        "elapsed_ms": alias_response.get("elapsed_ms"),
    }
    _complete_check(
        cev,
        result="vulnerable" if alias_accepted else "not_vulnerable",
        evidence=(
            f"{alias_count} aliases all processed ({alias_response.get('elapsed_ms')}ms)"
            if alias_accepted
            else f"alias overload rejected (status {alias_response.get('status_code')})"
        ),
    )
    if alias_accepted:
        _emit_finding(
            title=f"GraphQL alias overloading accepted on {target_url}",
            severity="high",
            category="dos",
            cwe="CWE-770",
            target=target_url,
            description=(
                f"The endpoint processed {alias_count} aliased operations in a "
                "single request without enforcing a per-operation rate limit. OWASP "
                "API4 — alias overloading lets one HTTP request consume N times the "
                "server cost of a single query, fully bypassing per-IP / per-account "
                "request-rate limits applied at the HTTP layer."
            ),
            impact=(
                "DoS amplification: one HTTP request triggers N resolver runs. "
                "Often combined with credential-stuffing for password spray that "
                "evades login-attempt rate limits, or with object-by-id queries to "
                "exfiltrate large data sets in one HTTP round trip."
            ),
            remediation=(
                "Enforce per-operation rate limits at the GraphQL layer, not just "
                "the HTTP layer. Count aliased operations against the budget. Cap "
                "the number of root-level operations per request (typically 5-10). "
                "Apollo / graphql-shield / Yoga all expose middleware for this."
            ),
        )

    # ---- 4. Batch query ----
    cev = _start_check("graphql_batch_abuse", target_url)
    batch_payload = _build_batch_payload(batch_size)
    batch_response = _post_graphql(target_url, batch_payload, timeout=timeout)
    batch_accepted = False
    if _is_graphql_data_response(batch_response):
        try:
            data = json.loads(batch_response["body"])
            # Batch responses are a JSON array; if we got an object with `data`,
            # the server may have only processed one or coalesced them.
            batch_accepted = False
        except (ValueError, TypeError):
            pass
    elif batch_response.get("status_code") and 200 <= batch_response["status_code"] < 300:
        # Parse the body — batch responses are arrays.
        try:
            parsed = json.loads(batch_response.get("body") or "[]")
            if isinstance(parsed, list) and len(parsed) >= batch_size:
                # All operations processed.
                batch_accepted = all(
                    isinstance(item, dict) and "data" in item for item in parsed
                )
        except (ValueError, TypeError):
            pass
    results["batch_abuse"] = {
        "batch_size": batch_size,
        "accepted": batch_accepted,
        "status": batch_response.get("status_code"),
        "elapsed_ms": batch_response.get("elapsed_ms"),
    }
    _complete_check(
        cev,
        result="vulnerable" if batch_accepted else "not_vulnerable",
        evidence=(
            f"batch of {batch_size} queries all processed"
            if batch_accepted
            else f"batch query rejected or coalesced (status "
            f"{batch_response.get('status_code')})"
        ),
    )
    if batch_accepted:
        _emit_finding(
            title=f"GraphQL batch query support accepted on {target_url}",
            severity="medium",
            category="dos",
            cwe="CWE-770",
            target=target_url,
            description=(
                f"The endpoint accepted a JSON-array batch of {batch_size} GraphQL "
                "operations in a single HTTP request, processing all of them. "
                "OWASP API4 — like alias overloading, batch operations bypass "
                "per-request rate limits by stuffing multiple operations into one "
                "request."
            ),
            impact=(
                "Same DoS amplification + rate-limit-evasion class as alias "
                "overloading. Attackers prefer batching because some servers harden "
                "alias-counts but leave batch support fully open. Often used for "
                "credential-stuffing where the rate limit applies per HTTP request, "
                "not per login attempt."
            ),
            remediation=(
                "Either disable batch query support entirely (most clients don't "
                "need it) or apply per-operation rate limits inside the batch. For "
                "Apollo Server: set `allowBatchedHttpRequests: false`. For Yoga: "
                "the same flag. If batch must remain enabled, count each operation "
                "against the rate budget."
            ),
        )

    return {
        "success": True,
        "target_url": target_url,
        "tests": results,
    }
