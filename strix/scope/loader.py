"""Load + validate `strix.scope.yml` into an `EngagementScope`.

Validation is fail-fast: a malformed scope file refuses to load
rather than silently dropping fields. §7 doc explicitly says:
"refuse to spawn specialists if scope.yml is malformed."
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from strix.scope.spec import (
    AuthConfig,
    EngagementScope,
    OpSecLevel,
    ScopeTarget,
    TargetType,
)


logger = logging.getLogger(__name__)


_VALID_TARGET_TYPES = {
    "web_application", "api", "repository",
    "host", "mobile", "binary", "container_image",
}
_VALID_OPSEC = {"quiet", "standard", "loud"}
_VALID_AUTH_METHODS = {"bearer", "basic", "cookie", "none"}


class ScopeValidationError(ValueError):
    """Raised when `strix.scope.yml` is structurally invalid.
    Carries `errors: list[str]` with one entry per failure so the
    CLI can render all problems at once instead of just the first."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(
            "Invalid strix.scope.yml:\n  - " + "\n  - ".join(errors)
        )


def load_scope_file(path: Path | str) -> EngagementScope:
    """Read + parse + validate a scope file. Raises:
      * FileNotFoundError when path doesn't exist
      * ScopeValidationError on schema / value problems
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scope file not found: {p}")
    text = p.read_text(encoding="utf-8")
    return parse_scope_yaml(text)


def parse_scope_yaml(text: str) -> EngagementScope:
    """Parse a YAML string into an `EngagementScope`. Same
    validation rules as `load_scope_file`."""
    import yaml
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ScopeValidationError([f"YAML parse error: {e}"]) from e

    if data is None:
        raise ScopeValidationError(["scope file is empty"])
    if not isinstance(data, dict):
        raise ScopeValidationError([
            f"top level must be a mapping, got {type(data).__name__}",
        ])

    errors: list[str] = []

    # --- targets (required) ---
    raw_targets = data.get("targets")
    targets: list[ScopeTarget] = []
    if not raw_targets:
        errors.append("`targets` is required and must be non-empty")
    elif not isinstance(raw_targets, list):
        errors.append(
            f"`targets` must be a list, got {type(raw_targets).__name__}",
        )
    else:
        for idx, entry in enumerate(raw_targets):
            t = _parse_target(entry, idx, errors)
            if t is not None:
                targets.append(t)

    # --- exclusions (optional) ---
    excl = data.get("exclusions") or {}
    paths: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    if not isinstance(excl, dict):
        errors.append(
            f"`exclusions` must be a mapping, got {type(excl).__name__}",
        )
    else:
        paths = _parse_str_list(excl.get("paths"), "exclusions.paths", errors)
        hosts = _parse_str_list(excl.get("hosts"), "exclusions.hosts", errors)

    # --- opsec_level (optional, default standard) ---
    opsec_raw = data.get("opsec_level", "standard")
    if not isinstance(opsec_raw, str) or opsec_raw not in _VALID_OPSEC:
        errors.append(
            f"`opsec_level` must be one of {sorted(_VALID_OPSEC)}, "
            f"got {opsec_raw!r}",
        )
        opsec_raw = "standard"
    opsec: OpSecLevel = opsec_raw  # type: ignore[assignment]

    # --- rate_limit_rps (optional) ---
    rate = data.get("rate_limit_rps")
    if rate is not None:
        if not isinstance(rate, int) or rate <= 0:
            errors.append(
                f"`rate_limit_rps` must be a positive int, got {rate!r}",
            )
            rate = None

    # --- auth (optional) ---
    auth_raw = data.get("auth") or {}
    auth = AuthConfig()
    if not isinstance(auth_raw, dict):
        errors.append(
            f"`auth` must be a mapping, got {type(auth_raw).__name__}",
        )
    else:
        method = auth_raw.get("method", "none")
        if method not in _VALID_AUTH_METHODS:
            errors.append(
                f"`auth.method` must be one of {sorted(_VALID_AUTH_METHODS)}, "
                f"got {method!r}",
            )
            method = "none"
        inject = auth_raw.get("inject_from")
        if inject is not None and not isinstance(inject, str):
            errors.append(
                f"`auth.inject_from` must be a string, got "
                f"{type(inject).__name__}",
            )
            inject = None
        elif inject and not _is_valid_inject_source(inject):
            errors.append(
                f"`auth.inject_from` must start with `env:`, `file:`, or "
                f"be `literal`; got {inject!r}",
            )
            inject = None
        auth = AuthConfig(method=method, inject_from=inject)  # type: ignore[arg-type]

    # --- acceptance_criteria (optional) ---
    criteria = _parse_str_list(
        data.get("acceptance_criteria"), "acceptance_criteria", errors,
    )

    # --- escalation_contact (optional) ---
    escal = data.get("escalation_contact")
    if escal is not None and not isinstance(escal, str):
        errors.append(
            f"`escalation_contact` must be a string, got "
            f"{type(escal).__name__}",
        )
        escal = None

    if errors:
        raise ScopeValidationError(errors)

    return EngagementScope(
        targets=tuple(targets),
        exclusion_paths=paths,
        exclusion_hosts=hosts,
        opsec_level=opsec,
        rate_limit_rps=rate,
        auth=auth,
        acceptance_criteria=criteria,
        escalation_contact=escal,
    )


def _parse_target(
    entry: Any, idx: int, errors: list[str],
) -> ScopeTarget | None:
    if not isinstance(entry, dict):
        errors.append(
            f"targets[{idx}] must be a mapping, got "
            f"{type(entry).__name__}",
        )
        return None
    t = entry.get("type")
    v = entry.get("value")
    if not isinstance(t, str) or t not in _VALID_TARGET_TYPES:
        errors.append(
            f"targets[{idx}].type must be one of "
            f"{sorted(_VALID_TARGET_TYPES)}, got {t!r}",
        )
        return None
    if not isinstance(v, str) or not v.strip():
        errors.append(
            f"targets[{idx}].value must be a non-empty string, got {v!r}",
        )
        return None
    return ScopeTarget(type=t, value=v.strip())  # type: ignore[arg-type]


def _parse_str_list(
    value: Any, field_name: str, errors: list[str],
) -> tuple[str, ...]:
    """Coerce to tuple[str,...]. None → empty. Non-list / non-string
    entries record a validation error."""
    if value is None:
        return ()
    if not isinstance(value, list):
        errors.append(f"`{field_name}` must be a list, got {type(value).__name__}")
        return ()
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            errors.append(
                f"`{field_name}[{i}]` must be a string, got "
                f"{type(item).__name__}",
            )
            continue
        item = item.strip()
        if item:
            out.append(item)
    return tuple(out)


def _is_valid_inject_source(source: str) -> bool:
    return (
        source.startswith("env:")
        or source.startswith("file:")
        or source == "literal"
    )
