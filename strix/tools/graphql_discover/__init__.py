"""iter-28.5 — GraphQL endpoint discovery + introspection capture.

Complements the existing `graphql_specialist_check` tool (which runs
depth/alias/batch abuse on a known endpoint). This primitive probes
industry-standard GraphQL paths, captures introspection schemas, and
hands the result back so the Lead can dispatch per-query/mutation
specialists.
"""

from .discover_graphql import discover_graphql_endpoints


__all__ = ["discover_graphql_endpoints"]
