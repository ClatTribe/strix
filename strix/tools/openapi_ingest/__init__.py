"""OpenAPI / Swagger spec ingestion — replaces HTML crawling on API targets.

For an `api` target type, the canonical endpoint inventory is the
target's own OpenAPI / Swagger spec. `bfs_crawl` was built for
HTML pages; APIs don't render HTML, and crawling can miss
documented-but-unlinked endpoints. The OpenAPI spec is exact
inventory by design.

`openapi_spec_ingest` fetches the spec, parses paths + methods +
parameters + auth schemes, emits a `Surface` KG node per (path,
method) tuple, and returns a structured inventory the lead can
hand to specialists for parallel probing.
"""

from strix.tools.openapi_ingest.openapi_spec_ingest import (  # noqa: F401
    openapi_spec_ingest,
)
