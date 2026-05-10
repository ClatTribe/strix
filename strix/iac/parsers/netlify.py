"""Parser for Netlify project config (`netlify.toml`).

Schema: https://docs.netlify.com/configure-builds/file-based-configuration/

Notable fields strix's rules care about:
  * `[[redirects]]` — wildcard redirects to external hosts (open
    redirect)
  * `[[headers]]` — per-route CORS / CSP config
  * `[build.environment]` — hardcoded secrets in build env
  * `[functions]` / `[edge_functions]` — resource configs
  * `[context.production.environment]` — env-var leaks
"""

from __future__ import annotations

import logging
from pathlib import Path

from strix.iac.parsers.base import (
    PLATFORM_NETLIFY,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


def _load_toml(path: Path) -> tuple[dict, str | None]:
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        with path.open("rb") as f:
            return tomllib.load(f), None
    except Exception as e:  # noqa: BLE001
        return {}, f"toml parse failed: {e}"


@register_parser(filenames=["netlify.toml"])
def parse_netlify(path: Path) -> IacFile | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_NETLIFY, path=str(path),
            data={}, raw_text="", parse_error=str(e),
        )
    data, err = _load_toml(path)
    return IacFile(
        platform=PLATFORM_NETLIFY, path=str(path),
        data=data, raw_text=text, parse_error=err,
    )
