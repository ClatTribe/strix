"""iter-24.1 — `update_hadolint_config` lazy-refresh tool.

Hadolint ships sensible defaults baked into the binary, but the
canonical "all severity-mapped, all rules enabled" baseline lives in
the project's wiki / example YAML on GitHub. We mirror that into
``~/.strix/cache/rules/hadolint.yaml`` so ``scan_dockerfile_hadolint``
can pass it via ``--config`` for deterministic severity assignment
across binary versions.

Upstream URL: the rendered example config in the hadolint repo.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool
from strix.tools.rule_updates._common import refresh_via_etag


_HADOLINT_URL = (
    "https://raw.githubusercontent.com/hadolint/hadolint/master/"
    ".hadolint.yaml"
)


@register_tool(sandbox_execution=True)
def update_hadolint_config(
    max_age_hours: float = 24.0,
    force: bool = False,
) -> dict[str, Any]:
    """Refresh cached ``hadolint.yaml`` baseline from upstream.

    Args:
        max_age_hours: skip if cached copy is younger than this.
        force: ignore freshness window; always issue an HTTP call.

    Returns:
        ```
        {success, status: fresh|updated|unchanged|partial|error,
         path: str, size_bytes?: int, age_hours?: float, reason?: str}
        ```
    """
    return refresh_via_etag(
        name="hadolint.yaml",
        url=_HADOLINT_URL,
        max_age_hours=max_age_hours,
        force=force,
    )
