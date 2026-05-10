"""Parser for Cloudflare Workers / Pages config (`wrangler.toml`).

Schema: https://developers.cloudflare.com/workers/wrangler/configuration/

Notable fields strix's rules care about:
  * `[[r2_buckets]]` — public R2 bucket bindings
  * `[[kv_namespaces]]` — KV bindings (preview vs prod separation)
  * `[[services]]` — Service binding allowlist
  * `[[routes]]` — wildcard route patterns
  * `[vars]` — hardcoded secrets in vars table (vs `[secrets]`)
  * `[[d1_databases]]` — D1 (SQL) bindings
"""

from __future__ import annotations

import logging
from pathlib import Path

from strix.iac.parsers.base import (
    PLATFORM_CLOUDFLARE,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


@register_parser(filenames=["wrangler.toml"])
def parse_wrangler(path: Path) -> IacFile | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_CLOUDFLARE, path=str(path),
            data={}, raw_text="", parse_error=str(e),
        )
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        with path.open("rb") as f:
            data = tomllib.load(f)
    except Exception as e:  # noqa: BLE001
        return IacFile(
            platform=PLATFORM_CLOUDFLARE, path=str(path),
            data={}, raw_text=text,
            parse_error=f"toml parse failed: {e}",
        )
    return IacFile(
        platform=PLATFORM_CLOUDFLARE, path=str(path),
        data=data, raw_text=text,
    )
