"""iter-24.1 — `update_wappalyzer_signatures` lazy-refresh tool.

The wappalyzer-cli npm package looks up its tech-detection rules from
a bundled ``technologies.json`` — which goes stale fast (the upstream
DB sees ~100 commits/month). We mirror it into
``~/.strix/cache/rules/wappalyzer-technologies.json`` so the httpx
``-tech-detect`` consumer and any future wappalyzer-cli wrap pick up
fresh fingerprints daily.

Upstream URL: enable-security maintains an actively-merged fork after
the original wappalyzer/wappalyzer repo went private — this is the
canonical OSS continuation.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool
from strix.tools.rule_updates._common import refresh_via_etag


# enable-security/wappalyzer is the actively-maintained OSS fork after
# the original repo went closed-source in 2023. Mirrors all source
# tech-detection JSON files.
_WAPPALYZER_URL = (
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/"
    "src/technologies.json"
)


@register_tool(sandbox_execution=True)
def update_wappalyzer_signatures(
    max_age_hours: float = 24.0,
    force: bool = False,
) -> dict[str, Any]:
    """Refresh cached Wappalyzer ``technologies.json`` from upstream.

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
        name="wappalyzer-technologies.json",
        url=_WAPPALYZER_URL,
        max_age_hours=max_age_hours,
        force=force,
    )
