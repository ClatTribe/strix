"""Parser for Vercel project config (`vercel.json`).

Vercel reads `vercel.json` from the repo root. Schema:
https://vercel.com/docs/project-configuration

Notable fields strix's rules care about:
  * `headers[]` — per-route HTTP header config (CORS, CSP, ...)
  * `redirects[]` / `rewrites[]` — open-redirect candidates
  * `crons[]` — auth-less scheduled invocations of routes
  * `functions{}` — per-function `maxDuration`, `memory`,
    `regions`. Resource-exhaustion DoS lives here.
  * `env{}` / `build.env{}` — accidental literal secrets

We don't validate the schema (Vercel's CLI does that). We just
parse JSON and let rules pick over the fields they care about.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from strix.iac.parsers.base import (
    PLATFORM_VERCEL,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


@register_parser(filenames=["vercel.json"])
def parse_vercel(path: Path) -> IacFile | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text) if text.strip() else {}
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("iac/vercel: parse failed for %s: %s", path, e)
        return IacFile(
            platform=PLATFORM_VERCEL, path=str(path),
            data={}, raw_text="", parse_error=str(e),
        )
    if not isinstance(data, dict):
        # Some users ship a list (older Vercel format); treat as
        # parse-error so rules don't false-positive.
        return IacFile(
            platform=PLATFORM_VERCEL, path=str(path),
            data={}, raw_text=text,
            parse_error="vercel.json should be a JSON object",
        )
    return IacFile(
        platform=PLATFORM_VERCEL, path=str(path),
        data=data, raw_text=text,
    )
