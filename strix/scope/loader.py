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
    CustomDockerfileRules,
    CustomSecretRule,
    CustomSignatures,
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
# iter-24.2 — hadolint maps severities to one of these labels. We
# reject anything else so users get a clear error instead of a silent
# pass-through that hadolint then crashes on.
_VALID_HADOLINT_SEVERITIES = {
    "error", "warning", "info", "style", "ignore",
}


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

    # --- custom_signatures (optional, iter-24.2) ---
    custom_sigs = _parse_custom_signatures(
        data.get("custom_signatures"), errors,
    )

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
        custom_signatures=custom_sigs,
    )


def _parse_custom_signatures(
    raw: Any, errors: list[str],
) -> CustomSignatures:
    """Parse `custom_signatures:` block — user L1 rule extensions.

    Schema:
        custom_signatures:
          secrets:
            - id: <str>
              regex: <str>      # python re-syntax; compiled to validate
              description: <str optional>
          dockerfile:
            exclude_rules: [DL3008, ...]
            severity_overrides:
              DL3000: warning
              DL4006: error
    """
    if raw is None:
        return CustomSignatures()
    if not isinstance(raw, dict):
        errors.append(
            f"`custom_signatures` must be a mapping, got "
            f"{type(raw).__name__}",
        )
        return CustomSignatures()

    # --- secrets ---
    raw_secrets = raw.get("secrets")
    secrets_out: list[CustomSecretRule] = []
    if raw_secrets is not None:
        if not isinstance(raw_secrets, list):
            errors.append(
                f"`custom_signatures.secrets` must be a list, got "
                f"{type(raw_secrets).__name__}",
            )
        else:
            seen_ids: set[str] = set()
            for i, entry in enumerate(raw_secrets):
                rule = _parse_secret_rule(entry, i, errors)
                if rule is None:
                    continue
                if rule.id in seen_ids:
                    errors.append(
                        f"`custom_signatures.secrets[{i}].id` duplicate: "
                        f"{rule.id!r}",
                    )
                    continue
                seen_ids.add(rule.id)
                secrets_out.append(rule)

    # --- dockerfile ---
    raw_df = raw.get("dockerfile") or {}
    excl_rules: tuple[str, ...] = ()
    sev_overrides: list[tuple[str, str]] = []
    if not isinstance(raw_df, dict):
        errors.append(
            f"`custom_signatures.dockerfile` must be a mapping, got "
            f"{type(raw_df).__name__}",
        )
    else:
        excl_rules = _parse_str_list(
            raw_df.get("exclude_rules"),
            "custom_signatures.dockerfile.exclude_rules",
            errors,
        )
        raw_sev = raw_df.get("severity_overrides")
        if raw_sev is not None:
            if not isinstance(raw_sev, dict):
                errors.append(
                    f"`custom_signatures.dockerfile.severity_overrides` "
                    f"must be a mapping, got {type(raw_sev).__name__}",
                )
            else:
                for rule_id, sev in raw_sev.items():
                    if not isinstance(rule_id, str) or not rule_id.strip():
                        errors.append(
                            "`custom_signatures.dockerfile."
                            "severity_overrides` keys must be non-empty "
                            f"strings; got {rule_id!r}",
                        )
                        continue
                    if (
                        not isinstance(sev, str)
                        or sev not in _VALID_HADOLINT_SEVERITIES
                    ):
                        errors.append(
                            f"`custom_signatures.dockerfile."
                            f"severity_overrides[{rule_id}]` must be one "
                            f"of {sorted(_VALID_HADOLINT_SEVERITIES)}, "
                            f"got {sev!r}",
                        )
                        continue
                    sev_overrides.append((rule_id, sev))

    return CustomSignatures(
        secrets=tuple(secrets_out),
        dockerfile=CustomDockerfileRules(
            exclude_rules=excl_rules,
            severity_overrides=tuple(sev_overrides),
        ),
    )


def _parse_secret_rule(
    entry: Any, idx: int, errors: list[str],
) -> CustomSecretRule | None:
    import re
    if not isinstance(entry, dict):
        errors.append(
            f"`custom_signatures.secrets[{idx}]` must be a mapping, "
            f"got {type(entry).__name__}",
        )
        return None
    rid = entry.get("id")
    regex = entry.get("regex")
    desc = entry.get("description", "")
    if not isinstance(rid, str) or not rid.strip():
        errors.append(
            f"`custom_signatures.secrets[{idx}].id` must be a "
            f"non-empty string, got {rid!r}",
        )
        return None
    if not isinstance(regex, str) or not regex.strip():
        errors.append(
            f"`custom_signatures.secrets[{idx}].regex` must be a "
            f"non-empty string, got {regex!r}",
        )
        return None
    # Validate compile so the user gets the error at scope-load time
    # instead of at gitleaks invocation.
    try:
        re.compile(regex)
    except re.error as e:
        errors.append(
            f"`custom_signatures.secrets[{idx}].regex` is invalid: {e}",
        )
        return None
    if not isinstance(desc, str):
        errors.append(
            f"`custom_signatures.secrets[{idx}].description` must be "
            f"a string, got {type(desc).__name__}",
        )
        desc = ""
    return CustomSecretRule(
        id=rid.strip(), regex=regex, description=desc.strip(),
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
