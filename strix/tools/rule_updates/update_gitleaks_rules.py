"""iter-24.1 — `update_gitleaks_rules` lazy-refresh tool.

Pulls the upstream gitleaks default rule corpus
(``config/gitleaks.toml`` on the master branch) into
``~/.strix/cache/rules/gitleaks.toml``. ``secrets_scan`` looks here
before falling back to gitleaks' built-in defaults.

The 24h ETag-guarded refresh is implemented in
:func:`strix.tools.rule_updates._common.refresh_via_etag`.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool
from strix.tools.rule_updates._common import refresh_via_etag


_GITLEAKS_URL = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/master/"
    "config/gitleaks.toml"
)


@register_tool(sandbox_execution=True)
def update_gitleaks_rules(
    max_age_hours: float = 24.0,
    force: bool = False,
) -> dict[str, Any]:
    """Refresh the cached ``gitleaks.toml`` from upstream.

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
        name="gitleaks.toml",
        url=_GITLEAKS_URL,
        max_age_hours=max_age_hours,
        force=force,
    )
