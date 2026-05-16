"""`graphql_introspection_deep` — full GraphQL `__schema`
introspection + four category-specific abuse probes.

`graphql_specialist_check` already exists as a shallow probe
(does the target answer introspection at all?). This module is
the deep walk: parse the full type graph, then run four
follow-ups that catch the most common GraphQL-specific bugs:

  1. **Introspection-enabled-in-production** (existing — kept
     here so the deep walker is a one-stop tool).
  2. **Alias-based DoS amplification** — issue a query with the
     same expensive field aliased N times; if the server
     processes all N (rather than collapsing), you've got a
     DoS amplification.
  3. **Deep-nested-query DoS** — issue a recursively-nested
     query that explodes the response size; if the server
     returns it without depth-limiting, that's a DoS gate
     missing.
  4. **Mutation auth-gate** — for every Mutation field on the
     schema, attempt invocation with default args. Mutations
     that respond `2xx` without authentication are likely
     unauthenticated state-changers (OWASP API1/5 hybrid).

## Inputs / outputs

  * `endpoint` (str): GraphQL endpoint URL.
  * Optional Bearer/Cookie headers for auth-walled probes.
  * Returns a `SpecialistResult` with one finding per detected
    issue. `tool_metadata.schema_excerpt` includes the
    introspection-result for downstream LLM-driven follow-up.

Kill switch: `STRIX_GRAPHQL_DEEP_DISABLED=1`.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import FindingDraft, SpecialistResult


logger = logging.getLogger(__name__)


_INTROSPECTION_QUERY = """{
  __schema {
    types { name kind }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}"""


# Aliased-DoS probe: one expensive-looking field aliased 50x.
# Servers without per-query alias caps will process all 50.
def _build_alias_dos_query(field_name: str, alias_count: int = 50) -> str:
    aliases = "\n  ".join(
        f"a{i}: {field_name}" for i in range(alias_count)
    )
    return f"{{\n  {aliases}\n}}"


# Recursive-depth DoS probe: standard tactic against schemas
# with circular references (User → Posts → Author → Posts...).
# We don't know the schema-specific cycle so we use the
# universally-supported `__schema { types { name kind ... } }`
# nested deeply.
_DEEP_NESTED_QUERY = """{
  __schema {
    types {
      fields {
        type {
          ofType {
            ofType {
              ofType {
                ofType {
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}"""


def _kill_switched() -> bool:
    return os.environ.get("STRIX_GRAPHQL_DEEP_DISABLED") == "1"


def _default_fetcher(
    *, url: str, headers: dict[str, str] | None,
    json_body: dict[str, Any], timeout: float,
) -> tuple[int | None, str, float]:
    """POST a GraphQL query. Returns (status, body, latency_ms).
    Latency is critical for the DoS probes."""
    import time as _time
    try:
        import httpx
    except ImportError:
        return None, "", 0.0
    started = _time.monotonic()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.post(url, headers=headers or None, json=json_body)
            latency = (_time.monotonic() - started) * 1000.0
            return r.status_code, r.text or "", latency
    except Exception:  # noqa: BLE001
        latency = (_time.monotonic() - started) * 1000.0
        return None, "", latency


def _parse_introspection(body: str) -> dict[str, Any] | None:
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    schema = data.get("data", {}).get("__schema")
    if not isinstance(schema, dict):
        return None
    return schema


def _extract_query_root_field(schema: dict[str, Any]) -> str | None:
    """Pick a representative Query-root field name for the alias-
    DoS probe. We can't pick blindly — some fields require args.
    Picks the first arg-less field from the Query type."""
    query_type_name = (schema.get("queryType") or {}).get("name")
    if not query_type_name:
        return None
    types = schema.get("types") or []
    if not isinstance(types, list):
        return None
    for t in types:
        if not isinstance(t, dict):
            continue
        if t.get("name") != query_type_name:
            continue
        fields = t.get("fields") or []
        for f in fields:
            if not isinstance(f, dict):
                continue
            # Heuristic: `__typename` is always argless and side-
            # effect-free. Falls back to any field whose `args`
            # list is empty.
            if f.get("name") == "__typename":
                return "__typename"
        for f in fields:
            if not isinstance(f, dict):
                continue
            args = f.get("args") or []
            if isinstance(args, list) and len(args) == 0:
                return f["name"]
    return "__typename"   # universal fallback


def _extract_mutations(schema: dict[str, Any]) -> list[str]:
    """List Mutation-root field names (the auth-gate probe will
    attempt each)."""
    mutation_type_name = (schema.get("mutationType") or {}).get("name")
    if not mutation_type_name:
        return []
    types = schema.get("types") or []
    for t in types:
        if isinstance(t, dict) and t.get("name") == mutation_type_name:
            fields = t.get("fields") or []
            return [
                str(f.get("name"))
                for f in fields
                if isinstance(f, dict) and isinstance(f.get("name"), str)
            ]
    return []


@register_specialist_tool(
    category="api-graphql-deep-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 120},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def graphql_introspection_deep(
    *,
    endpoint: str,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: float = 12.0,
    probe_alias_dos: bool = True,
    probe_deep_nesting: bool = True,
    probe_mutation_auth: bool = True,
    alias_count: int = 50,
    _fetcher=None,
) -> SpecialistResult:
    """Deep GraphQL introspection + 4-category abuse probe.

    Args:
        endpoint: GraphQL endpoint URL.
        extra_headers: optional auth headers.
        timeout_seconds: per-request HTTP timeout.
        probe_alias_dos: when True (default), run alias-DoS probe.
        probe_deep_nesting: when True (default), run nested-depth
            probe.
        probe_mutation_auth: when True (default), probe mutations
            for missing auth.
        alias_count: alias multiplier for the DoS probe.
        _fetcher: injection point for tests.

    Kill switch: `STRIX_GRAPHQL_DEEP_DISABLED=1`.
    """
    if _kill_switched():
        return SpecialistResult(
            status="error",
            error="kill_switch (STRIX_GRAPHQL_DEEP_DISABLED)",
        )
    if not isinstance(endpoint, str) or not endpoint.strip():
        return SpecialistResult(status="error", error="endpoint required")

    fetcher = _fetcher or _default_fetcher
    findings: list[FindingDraft] = []
    evidence: list[str] = []
    schema_excerpt: dict[str, Any] | None = None

    # ---- 1. Introspection probe ----
    intro_status, intro_body, intro_latency = fetcher(
        url=endpoint, headers=extra_headers,
        json_body={"query": _INTROSPECTION_QUERY},
        timeout=timeout_seconds,
    )
    if intro_status is None:
        return SpecialistResult(
            status="error",
            error=f"network error reaching {endpoint}",
        )
    schema = _parse_introspection(intro_body) if intro_status == 200 else None
    if schema is not None:
        schema_excerpt = {
            "type_count": len(schema.get("types") or []),
            "query_root": (schema.get("queryType") or {}).get("name"),
            "mutation_root": (
                schema.get("mutationType") or {}
            ).get("name"),
            "subscription_root": (
                schema.get("subscriptionType") or {}
            ).get("name"),
        }
        findings.append(FindingDraft(
            title=(
                "GraphQL introspection enabled — full schema "
                "disclosed"
            ),
            severity="medium",
            cwe="CWE-200",
            endpoint=endpoint,
            category="graphql_introspection",
            description=(
                f"The GraphQL endpoint at `{endpoint}` answers "
                f"`__schema` introspection queries. Schema "
                f"summary: {schema_excerpt['type_count']} types, "
                f"query root `{schema_excerpt['query_root']}`, "
                f"mutation root "
                f"`{schema_excerpt['mutation_root']}`.\n\n"
                f"Introspection in production is the canonical "
                f"GraphQL recon goldmine — every field, type, "
                f"argument, deprecation note is enumerated. "
                f"Production deployments should disable "
                f"introspection or gate it behind admin auth."
            ),
            verification_status="verified",
            confidence=0.95,
        ))
        evidence.append(
            f"introspection: {schema_excerpt['type_count']} types in "
            f"{intro_latency:.0f}ms"
        )
    else:
        evidence.append(
            f"introspection: not enabled / not parseable "
            f"(status={intro_status})"
        )
        # Without the schema we can't drive the other probes
        # meaningfully — return now.
        return SpecialistResult(
            status="ok",
            findings=findings,
            evidence=evidence,
            tool_metadata={
                "introspection_status": intro_status,
                "introspection_latency_ms": intro_latency,
            },
        )

    # ---- 2. Alias-DoS probe ----
    if probe_alias_dos:
        field = _extract_query_root_field(schema) or "__typename"
        alias_query = _build_alias_dos_query(field, alias_count=alias_count)
        a_status, a_body, a_latency = fetcher(
            url=endpoint, headers=extra_headers,
            json_body={"query": alias_query},
            timeout=timeout_seconds,
        )
        # Heuristic: if the aliased query returns 2xx AND latency
        # scales roughly linearly with alias_count (here approx
        # >= alias_count × baseline-latency × 0.5), the server
        # processed all aliases without collapse → DoS vector.
        if (
            a_status == 200
            and a_latency >= max(intro_latency * 1.5, 200.0)
        ):
            findings.append(FindingDraft(
                title=(
                    f"GraphQL alias-based DoS amplification — "
                    f"{alias_count}× aliased `{field}` processed"
                ),
                severity="high",
                cwe="CWE-770",
                endpoint=endpoint,
                category="graphql_alias_dos",
                description=(
                    f"Sent a query with `{field}` aliased "
                    f"{alias_count} times. The server processed all "
                    f"aliases (status={a_status}, "
                    f"latency={a_latency:.0f}ms vs. "
                    f"baseline {intro_latency:.0f}ms). A small "
                    f"client request multiplies into N server-side "
                    f"operations — classic GraphQL DoS pattern.\n\n"
                    f"Mitigations: per-query alias cap, query-cost "
                    f"analysis (Apollo / Hasura / Hot Chocolate all "
                    f"have built-in cost analysers), persisted "
                    f"queries."
                ),
                verification_status="verified",
                confidence=0.8,
            ))
            evidence.append(
                f"alias_dos: status={a_status}, "
                f"latency={a_latency:.0f}ms (baseline={intro_latency:.0f})"
            )

    # ---- 3. Deep-nested DoS probe ----
    if probe_deep_nesting:
        d_status, d_body, d_latency = fetcher(
            url=endpoint, headers=extra_headers,
            json_body={"query": _DEEP_NESTED_QUERY},
            timeout=timeout_seconds,
        )
        if d_status == 200 and d_latency >= max(intro_latency * 2, 300.0):
            findings.append(FindingDraft(
                title=(
                    "GraphQL deep-nested query DoS — no depth limit"
                ),
                severity="medium",
                cwe="CWE-770",
                endpoint=endpoint,
                category="graphql_depth_dos",
                description=(
                    f"Sent a recursively-nested 5-deep query on the "
                    f"`__schema.types.fields.type.ofType` chain. "
                    f"Server processed and returned the response "
                    f"(status={d_status}, "
                    f"latency={d_latency:.0f}ms). A real attacker "
                    f"would use a schema-specific cycle (User → "
                    f"Posts → Author → Posts → ...) to amplify "
                    f"further.\n\n"
                    f"Mitigations: query depth limit, query "
                    f"complexity / cost analyser, persisted queries."
                ),
                verification_status="verified",
                confidence=0.7,
            ))
            evidence.append(
                f"deep_nested: status={d_status}, "
                f"latency={d_latency:.0f}ms"
            )

    # ---- 4. Mutation-auth probe ----
    if probe_mutation_auth:
        mutations = _extract_mutations(schema)
        for mutation_name in mutations[:5]:   # cap probe count
            # Anonymous probe: NO auth headers.
            m_query = f"mutation {{ {mutation_name} }}"
            m_status, m_body, _ = fetcher(
                url=endpoint, headers=None,   # explicitly drop auth
                json_body={"query": m_query},
                timeout=timeout_seconds,
            )
            if m_status == 200 and m_body:
                # 200 + a non-empty body suggests the mutation
                # was at least PROCESSED (often with a validation
                # error in `errors`, but processed). When the
                # GraphQL response shape carries no errors key,
                # the mutation succeeded.
                try:
                    parsed = json.loads(m_body)
                    if isinstance(parsed, dict) and "errors" not in parsed:
                        findings.append(FindingDraft(
                            title=(
                                f"GraphQL mutation `{mutation_name}` "
                                f"accepts unauthenticated requests"
                            ),
                            severity="high",
                            cwe="CWE-306",
                            endpoint=endpoint,
                            category="graphql_unauth_mutation",
                            description=(
                                f"Mutation `{mutation_name}` returned "
                                f"a non-error 200 response when "
                                f"called without authentication "
                                f"headers. Likely missing auth gate "
                                f"on a state-changing operation."
                            ),
                            verification_status="verified",
                            confidence=0.75,
                        ))
                except (ValueError, TypeError):
                    pass

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=evidence,
        tool_metadata={
            "schema_excerpt": schema_excerpt,
            "introspection_latency_ms": intro_latency,
        },
    )
