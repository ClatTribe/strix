"""IaC rule registry — Phase 11.

Rules are pure-Python functions taking an `IacFile` and returning
a list of `IacFinding`. Per-platform modules register their rules
via `@register_rule(platform=...)`.

Why pure Python (not YAML / Checkov format) for v1:
  * Each rule has bespoke logic (traverse vercel.json's nested
    headers array, walk Dockerfile's directive list with line-
    precise hits, etc.). YAML rules engines fight us on this.
  * Pure Python = no extra runtime dep + trivial unit tests.
  * Adding a Checkov shell-out (Phase 11.2) is orthogonal —
    it'd dump findings into the same emit pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from strix.iac.parsers.base import IacFile


logger = logging.getLogger(__name__)


@dataclass
class IacFinding:
    """One IaC misconfig finding.

    `cwe` and `category` follow the same conventions as
    `SastFinding` so the wrapper renders these alongside SAST
    findings. The cross-asset routing reads `category` to pivot
    to the matching DAST specialist (e.g. category=misconfig +
    cors-credentials → cross-asset DAST cross-origin probe).
    """
    rule_id: str
    file: str
    line: int                # 0 = whole-file finding (no line)
    severity: str            # info | low | medium | high | critical
    message: str
    cwe: str | None = None
    category: str | None = None
    platform: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "message": self.message,
            "cwe": self.cwe,
            "category": self.category,
            "platform": self.platform,
            "metadata": dict(self.metadata),
        }


# Per-platform rule registry. Functions take an IacFile and
# return list[IacFinding].
RuleFn = Callable[[IacFile], list[IacFinding]]
_RULES: dict[str, list[RuleFn]] = {}


def register_rule(*, platform: str) -> Callable[[RuleFn], RuleFn]:
    """Decorator: register a rule for a given platform. Multiple
    platforms can share rules by registering the same function
    multiple times."""
    def decorator(fn: RuleFn) -> RuleFn:
        _RULES.setdefault(platform, []).append(fn)
        return fn
    return decorator


def run_rules(iac_file: IacFile) -> list[IacFinding]:
    """Run every rule registered for `iac_file.platform` and
    return the union of findings."""
    rules = _RULES.get(iac_file.platform, [])
    out: list[IacFinding] = []
    for rule in rules:
        try:
            findings = rule(iac_file)
            if findings:
                out.extend(findings)
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "iac: rule %s failed for %s: %s",
                rule.__name__, iac_file.path, e, exc_info=True,
            )
    return out


def list_rules(platform: str | None = None) -> list[str]:
    """Return rule function names. Used by tests + status output."""
    if platform:
        return [fn.__name__ for fn in _RULES.get(platform, [])]
    out: list[str] = []
    for rules in _RULES.values():
        out.extend(fn.__name__ for fn in rules)
    return out


# Side-effect imports — register rules per platform.
from strix.iac.rules import cloudflare_rules as _cf  # noqa: E402, F401
from strix.iac.rules import docker_rules as _dr  # noqa: E402, F401
from strix.iac.rules import helm_rules as _hr  # noqa: E402, F401
from strix.iac.rules import kubernetes_rules as _kr  # noqa: E402, F401
from strix.iac.rules import netlify_rules as _nl  # noqa: E402, F401
from strix.iac.rules import terraform_rules as _tr  # noqa: E402, F401
from strix.iac.rules import vercel_rules as _vr  # noqa: E402, F401
