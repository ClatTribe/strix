"""EngagementScope dataclass — the in-memory shape of `strix.scope.yml`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# Target-type tags. Match the values strix's existing target-routing
# code uses (`strix.utils.target_classifier`); kept lowercase + snake
# so the YAML stays readable.
TargetType = Literal[
    "web_application",
    "api",
    "repository",
    "host",
    "mobile",
    "binary",
    "container_image",
]

OpSecLevel = Literal["quiet", "standard", "loud"]
AuthMethod = Literal["bearer", "basic", "cookie", "none"]


@dataclass(frozen=True)
class ScopeTarget:
    """One target listed in the engagement scope."""
    type: TargetType
    value: str


@dataclass(frozen=True)
class AuthConfig:
    """Auth method + how to fetch the credential at runtime.

    `inject_from` is one of:
      env:VAR_NAME    — read from env
      file:/abs/path  — read from file
      literal         — value already present in another field
      (none, default) — no injection (covers `method: none`)
    """
    method: AuthMethod = "none"
    inject_from: str | None = None


@dataclass(frozen=True)
class EngagementScope:
    """Parsed `strix.scope.yml` — what the agent enforces every spawn.

    Built via `strix.scope.loader.load_scope_file()` or
    `parse_scope_yaml()`. The dataclass is frozen so it can be
    safely passed across threads / cached at scan start without
    races.
    """
    targets: tuple[ScopeTarget, ...]
    exclusion_paths: tuple[str, ...] = ()
    exclusion_hosts: tuple[str, ...] = ()
    opsec_level: OpSecLevel = "standard"
    rate_limit_rps: int | None = None
    auth: AuthConfig = field(default_factory=AuthConfig)
    acceptance_criteria: tuple[str, ...] = ()
    escalation_contact: str | None = None

    def has_exclusions(self) -> bool:
        return bool(self.exclusion_paths or self.exclusion_hosts)

    def target_values(self) -> list[str]:
        return [t.value for t in self.targets]
