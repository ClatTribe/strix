"""Parsers for Dockerfile + docker-compose.yml.

Dockerfiles are line-oriented directive lists (FROM, RUN, COPY,
USER, ...). We parse to a list of `{directive, args, line}`
dicts so rules can iterate and apply line-precise checks.

docker-compose.yml is YAML; we just `yaml.safe_load` and let
rules walk the structure (services / volumes / network mode etc.).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from strix.iac.parsers.base import (
    PLATFORM_DOCKER,
    PLATFORM_DOCKER_COMPOSE,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


# Dockerfile directives we surface. Anything else is preserved
# as `directive=...other...` for completeness.
_DOCKER_DIRECTIVES = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE",
    "ENV", "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER",
    "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK",
    "SHELL",
}


_DIRECTIVE_RE = re.compile(r"^\s*(\#.*|([A-Z]+)\s+(.*))$", re.IGNORECASE)


def _parse_dockerfile_lines(text: str) -> list[dict]:
    """Parse a Dockerfile into structured directives.

    Handles line continuations (trailing `\\`) by joining into
    the originating directive's args. Preserves the start line
    so rules can emit precise hits.
    """
    out: list[dict] = []
    pending: dict | None = None

    lines = text.splitlines()
    for i, raw in enumerate(lines, start=1):
        stripped = raw.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            if pending is not None:
                out.append(pending)
                pending = None
            continue

        # Continuation: the previous directive's args extend.
        if pending is not None:
            pending["args"] += " " + stripped.lstrip().rstrip("\\").rstrip()
            if not stripped.endswith("\\"):
                out.append(pending)
                pending = None
            continue

        m = _DIRECTIVE_RE.match(stripped)
        if not m:
            continue
        directive = (m.group(2) or "").upper()
        args = (m.group(3) or "").rstrip()
        # Skip lines that aren't directives (shouldn't reach here
        # given the regex; defensive).
        if not directive:
            continue
        ends_with_backslash = stripped.endswith("\\")
        if ends_with_backslash:
            args = args.rstrip("\\").rstrip()
        rec = {"directive": directive, "args": args, "line": i}
        if ends_with_backslash:
            pending = rec
        else:
            out.append(rec)
    if pending is not None:
        out.append(pending)
    return out


@register_parser(
    filenames=["dockerfile"],
    patterns=[r"^dockerfile(\..+)?$"],
)
def parse_dockerfile(path: Path) -> IacFile | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_DOCKER, path=str(path),
            data=[], raw_text="", parse_error=str(e),
        )
    directives = _parse_dockerfile_lines(text)
    return IacFile(
        platform=PLATFORM_DOCKER, path=str(path),
        data=directives, raw_text=text,
    )


@register_parser(
    filenames=["docker-compose.yml", "docker-compose.yaml",
               "compose.yml", "compose.yaml"],
)
def parse_docker_compose(path: Path) -> IacFile | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_DOCKER_COMPOSE, path=str(path),
            data={}, raw_text="", parse_error=str(e),
        )
    try:
        import yaml
        data = yaml.safe_load(text) or {}
    except Exception as e:  # noqa: BLE001
        return IacFile(
            platform=PLATFORM_DOCKER_COMPOSE, path=str(path),
            data={}, raw_text=text,
            parse_error=f"yaml parse failed: {e}",
        )
    if not isinstance(data, dict):
        return IacFile(
            platform=PLATFORM_DOCKER_COMPOSE, path=str(path),
            data={}, raw_text=text,
            parse_error="docker-compose.yml should be a mapping",
        )
    return IacFile(
        platform=PLATFORM_DOCKER_COMPOSE, path=str(path),
        data=data, raw_text=text,
    )
