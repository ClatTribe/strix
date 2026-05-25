"""iter-28.5 — GraphQL endpoint discovery + introspection primitive.

The existing `graphql_specialist_check` tool runs depth/alias/batch
abuse + introspection — but only when handed an explicit endpoint URL.
For an unknown SUT, the Lead never knows whether to call it because
the endpoint hasn't been discovered yet. This primitive fills the gap.

**What it does:**

  1. Probes a curated list of well-known GraphQL paths (`/graphql`,
     `/api/graphql`, `/v1/graphql`, ...) on the target.
  2. For each path returning a GraphQL-shaped response (200 or 400
     to the introspection query), captures the introspection schema.
  3. Returns the discovered endpoints + their schemas, so downstream
     specialists can craft per-query / per-mutation probes.

**Why this is generic:**

  * The path list is **industry convention** (Apollo, Hasura, Postgraphile,
    GraphCMS, Strapi GraphQL plugin, Shopify Storefront, GitHub v4).
    NO per-SUT entries.
  * Detection is by response SHAPE (does `__schema` return a valid
    GraphQL schema?) not by header/banner fingerprint.
  * Works against any GraphQL server: Apollo, Hasura, AWS AppSync,
    Hot Chocolate, graphql-java, gqlgen, juniper, async-graphql.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from strix.tools.registry import register_tool


def _rewrite_for_sandbox(url: str) -> str:
    """When running inside the sandbox container, localhost / 127.0.0.1
    refers to the sandbox itself, not the host's docker-compose'd SUT.
    Rewrite to `host.docker.internal` (wired in via `extra_hosts`).
    No-op when not in sandbox mode (host invocation). See seed_auth
    for the canonical comment block."""
    if os.environ.get("STRIX_SANDBOX_MODE", "").lower() != "true":
        return url
    parsed = urlparse(url)
    if parsed.hostname in ("localhost", "127.0.0.1"):
        new_netloc = "host.docker.internal"
        if parsed.port:
            new_netloc += f":{parsed.port}"
        return parsed._replace(netloc=new_netloc).geturl()
    return url


logger = logging.getLogger(__name__)


# Industry-standard GraphQL endpoint paths. Sourced from:
#   - Apollo Server defaults (`/graphql`)
#   - Hasura defaults (`/v1/graphql`, `/v1alpha1/graphql`)
#   - Postgraphile defaults (`/graphql`)
#   - Strapi GraphQL plugin (`/graphql`)
#   - Shopify Storefront (`/api/graphql`, `/api/2024-04/graphql`)
#   - GitHub v4 (`/graphql`)
#   - AppSync convention (`/graphql`)
#   - Generic alternative paths
_GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/v1/graphql",
    "/v1alpha1/graphql",  # hasura
    "/query",
    "/api/query",
    "/gql",
    "/api/gql",
    "/graphql/v1",
    "/api/graphiql",   # GraphiQL UI often exposes the underlying endpoint
    "/playground",     # apollo playground proxies to /graphql
)

# Minimal introspection query — small enough to not exhaust query depth
# limits, large enough to confirm GraphQL semantics.
_INTROSPECTION_QUERY_MINIMAL = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
    }
  }
}
""".strip()

# Full introspection (used after a hit is confirmed) — captures
# field-level detail downstream specialists need.
_INTROSPECTION_QUERY_FULL = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name type { name kind } }
        type { name kind ofType { name kind } }
      }
      inputFields { name type { name kind } }
      enumValues(includeDeprecated: true) { name }
    }
  }
}
""".strip()

_DEFAULT_TIMEOUT = 8


def _looks_like_graphql_response(payload: Any) -> bool:
    """Does this JSON response look like a GraphQL reply?

    GraphQL responses always have either `data` or `errors` at top
    level (per the spec). A response with `data.__schema.queryType`
    confirms a real GraphQL server returning introspection.
    """
    if not isinstance(payload, dict):
        return False
    if "errors" in payload and isinstance(payload["errors"], list):
        return True  # graphql-shaped error envelope
    data = payload.get("data")
    if not isinstance(data, dict):
        return False
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return False
    return "queryType" in schema or "types" in schema


def _probe_endpoint(
    url: str, *, full_introspection: bool, timeout: int,
) -> dict[str, Any] | None:
    """POST an introspection query to `url`. Returns the parsed
    response dict on a graphql-shaped hit; None otherwise.

    Tries POST application/json first (the modern convention), then
    falls back to POST application/graphql (legacy).
    """
    query = (
        _INTROSPECTION_QUERY_FULL if full_introspection
        else _INTROSPECTION_QUERY_MINIMAL
    )
    headers_json = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    try:
        r = requests.post(
            url, json={"query": query},
            headers=headers_json, timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None
    if r.status_code in (200, 400):
        try:
            payload = r.json()
        except (ValueError, TypeError):
            payload = None
        if payload is not None and _looks_like_graphql_response(payload):
            return payload
    return None


def _summarize_schema(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract a compact summary of the introspection result for the
    Lead's downstream planning. Full schema is in `raw_schema` for
    specialists that need details."""
    schema = (payload.get("data") or {}).get("__schema") or {}
    query_name = (schema.get("queryType") or {}).get("name")
    mutation_name = (schema.get("mutationType") or {}).get("name")
    subscription_name = (schema.get("subscriptionType") or {}).get("name")

    types = schema.get("types") or []
    user_defined = [
        t for t in types
        if isinstance(t, dict) and t.get("name")
        and not str(t["name"]).startswith("__")  # skip __Schema, __Type, ...
    ]
    type_names = [t["name"] for t in user_defined]

    # Tally Query / Mutation field counts (≈ how many endpoints the
    # API exposes via GraphQL)
    query_fields: list[str] = []
    mutation_fields: list[str] = []
    for t in user_defined:
        if t.get("name") == query_name:
            for f in t.get("fields") or []:
                if isinstance(f, dict) and f.get("name"):
                    query_fields.append(f["name"])
        if t.get("name") == mutation_name:
            for f in t.get("fields") or []:
                if isinstance(f, dict) and f.get("name"):
                    mutation_fields.append(f["name"])

    return {
        "query_type": query_name,
        "mutation_type": mutation_name,
        "subscription_type": subscription_name,
        "type_count": len(user_defined),
        "type_names_sample": type_names[:30],  # cap noise
        "query_field_count": len(query_fields),
        "mutation_field_count": len(mutation_fields),
        "query_fields": query_fields[:50],
        "mutation_fields": mutation_fields[:50],
        "introspection_enabled": True,
    }


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190", "T1592.002"],
    provenance="target",
)
def discover_graphql_endpoints(
    target_url: str,
    extra_paths: list[str] | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
    full_introspection: bool = True,
) -> dict[str, Any]:
    """Probe a target for GraphQL endpoints; capture introspection
    schemas when found.

    Args:
        target_url: base URL of the target (e.g. `http://app:3000`).
        extra_paths: additional paths to probe beyond the built-in
            list. Useful for SUTs that mount GraphQL at a non-standard
            path the operator has already identified.
        timeout: per-request timeout in seconds.
        full_introspection: when True (default), captures full schema
            including per-field args + types. When False, captures
            only the top-level type names (faster, smaller response).

    Returns:
        ```
        {
          "success": bool,
          "status": "ok" | "partial" | "error",
          "target": "...",
          "endpoints_found": int,
          "endpoints": [
            {
              "url": "...",
              "introspection_enabled": bool,
              "query_type": "Query",
              "mutation_type": "Mutation",
              "type_count": 47,
              "query_field_count": 23,
              "mutation_field_count": 12,
              "query_fields": ["user", "users", "products", ...],
              "mutation_fields": ["createUser", "deleteOrder", ...],
              "type_names_sample": [...],
            },
            ...
          ],
          "raw_schemas": {"<url>": {...full introspection payload...}},
          "paths_probed": int,
        }
        ```

        Findings emitted: one informational `graphql_endpoint_exposed`
        per discovered endpoint with introspection enabled.

    Examples:
        # Discover any GraphQL endpoint on the SUT
        discover_graphql_endpoints(target_url="http://app:3000")

        # Probe non-standard path
        discover_graphql_endpoints(
            target_url="http://app:3000",
            extra_paths=["/secret/graphql"],
        )
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error",
            "reason": "target_url required",
            "endpoints_found": 0, "endpoints": [],
        }

    target_url = _rewrite_for_sandbox(target_url.strip())
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {
            "success": False, "status": "error",
            "reason": (
                f"target_url must be a full http(s) URL with a host; "
                f"got scheme={parsed.scheme!r} netloc={parsed.netloc!r}"
            ),
            "endpoints_found": 0, "endpoints": [],
        }
    base = f"{parsed.scheme}://{parsed.netloc}"

    paths = list(_GRAPHQL_PATHS) + list(extra_paths or [])
    # Dedup while preserving order
    seen_paths: set[str] = set()
    paths = [p for p in paths if not (p in seen_paths or seen_paths.add(p))]

    endpoints: list[dict[str, Any]] = []
    raw_schemas: dict[str, Any] = {}

    for path in paths:
        url = urljoin(base + "/", path.lstrip("/"))
        payload = _probe_endpoint(
            url, full_introspection=full_introspection, timeout=timeout,
        )
        if payload is None:
            continue
        summary = _summarize_schema(payload)
        endpoint_record = {"url": url, **summary}
        endpoints.append(endpoint_record)
        raw_schemas[url] = payload

    status = "ok" if endpoints else "partial"
    return {
        "success": True,
        "status": status,
        "target": target_url,
        "endpoints_found": len(endpoints),
        "endpoints": endpoints,
        "raw_schemas": raw_schemas,
        "paths_probed": len(paths),
        "reason": (
            None if endpoints
            else f"probed {len(paths)} paths — none returned a GraphQL schema"
        ),
    }
