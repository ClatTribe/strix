"""GraphQL specialist support.

Roadmap §7.2. Focused tests against a GraphQL endpoint:
- Introspection enabled in prod (CWE-200, info disclosure)
- Schema discovery via introspection (when allowed)
- Depth abuse (max-depth probing — DoS via deeply nested queries)
- Alias overloading (N aliased queries in one request bypassing rate limits)
- Batch query support (JSON array bypassing rate limits)

Distinct from `authz_matrix_check` which handles role × endpoint at the HTTP
layer. This tool tests GraphQL-protocol-specific abuse classes.
"""

from .graphql import graphql_specialist_check


__all__ = ["graphql_specialist_check"]
