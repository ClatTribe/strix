"""`code_map.json` schema validator (roadmap §8.1 + §8.0).

Recon → Decide handoff for code-target scans. Produced by
`build_code_map`; consumed by `spawn_code_specialist_team` and the
spawned code-target specialists (`secret-agent`, `dependency-agent`,
`sast-agent`, plus future taint / validator agents).

Mirrors the `surface_map.json` (§7.3) and `webapp_surface_map.json`
(§8.2) handoff-schema patterns: pure validator, never raises, never
mutates. Returns a list of `CodeMapViolation` records keyed by
stable codes.

Contract (current `schema_version=1`):

| Field | Type | Required |
|---|---|---|
| `schema_version` | int | yes |
| `repo_path` | str (non-empty) | yes |
| `repo_name` | str | no |
| `generated_at` | str (ISO 8601) | yes |
| `phase_id` | str | no |
| `summary` | dict | yes (counters: files_scanned, routes_discovered, models_discovered, db_queries_discovered, external_http_calls_discovered, auth_boundaries_discovered) |
| `routes` | list[dict] | no |
| `models` | list[dict] | no |
| `db_queries` | list[dict] | no |
| `external_http_calls` | list[dict] | no |
| `auth_boundaries` | list[dict] | no |
| `errors` | list[dict] | no |

Per-record minimum fields (validated when the array is present):
- `routes[]`: `framework`, `path`, `file`, `line`
- `models[]`: `name`, `framework`, `file`, `line`
- `db_queries[]`: `kind`, `file`, `line`
- `external_http_calls[]`: `library`, `file`, `line`
- `auth_boundaries[]`: `kind`, `file`, `line`

Stable violation codes:
- `code_map.missing.{schema_version,repo_path,generated_at,summary}`
- `code_map.{schema_version,repo_path,generated_at}.invalid_*`
- `code_map.summary.missing_counters` (warn)
- `code_map.{routes,models,db_queries,external_http_calls,auth_boundaries}.invalid_shape`
- `code_map.not_dict`
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


SUPPORTED_SCHEMA_VERSIONS: frozenset[int] = frozenset({1})

REQUIRED_SUMMARY_COUNTERS: frozenset[str] = frozenset({
    "files_scanned",
    "routes_discovered",
    "models_discovered",
    "db_queries_discovered",
    "external_http_calls_discovered",
    "auth_boundaries_discovered",
})

# Per-array minimum fields. Each entry in the array must be a dict
# containing all of these keys.
_ROUTES_REQUIRED = frozenset({"framework", "path", "file", "line"})
_MODELS_REQUIRED = frozenset({"name", "framework", "file", "line"})
_QUERIES_REQUIRED = frozenset({"kind", "file", "line"})
_HTTP_REQUIRED = frozenset({"library", "file", "line"})
_AUTH_REQUIRED = frozenset({"kind", "file", "line"})


@dataclass(frozen=True)
class CodeMapViolation:
    """One contract violation against the code_map.json schema."""
    code: str
    field: str
    message: str
    severity: str  # 'error' or 'warn'


def _is_isoformat(value: str) -> bool:
    try:
        datetime.fromisoformat(value.rstrip("Z").replace("Z", ""))
        return True
    except (ValueError, TypeError):
        return False


def _validate_array_records(
    array_value: Any,
    array_name: str,
    required_keys: frozenset[str],
    code_prefix: str,
) -> list[CodeMapViolation]:
    """Validate that array_value is list[dict] with each dict
    containing required_keys."""
    out: list[CodeMapViolation] = []
    if array_value is None:
        return out
    if not isinstance(array_value, list):
        out.append(CodeMapViolation(
            code=f"{code_prefix}.invalid_shape",
            field=array_name,
            message=f"{array_name} must be a list when present",
            severity="error",
        ))
        return out
    for i, entry in enumerate(array_value):
        if not isinstance(entry, dict):
            out.append(CodeMapViolation(
                code=f"{code_prefix}.invalid_shape",
                field=f"{array_name}[{i}]",
                message=f"entry {i} is not a dict",
                severity="error",
            ))
            continue
        missing = required_keys - set(entry.keys())
        if missing:
            out.append(CodeMapViolation(
                code=f"{code_prefix}.invalid_shape",
                field=f"{array_name}[{i}]",
                message=f"entry {i} missing required keys: {sorted(missing)}",
                severity="error",
            ))
    return out


def validate_code_map(data: Any) -> list[CodeMapViolation]:  # noqa: PLR0912
    """Validate `data` against the code_map.json contract.

    Pure function: never raises, never mutates. Returns a list of
    `CodeMapViolation` records. Empty = canonical."""
    if not isinstance(data, dict):
        return [CodeMapViolation(
            code="code_map.not_dict",
            field="(root)",
            message=f"code_map is not a dict: {type(data).__name__}",
            severity="error",
        )]

    violations: list[CodeMapViolation] = []

    # ---- schema_version ----
    sv = data.get("schema_version")
    if sv is None:
        violations.append(CodeMapViolation(
            code="code_map.missing.schema_version",
            field="schema_version",
            message="required field `schema_version` is missing",
            severity="error",
        ))
    elif not isinstance(sv, int):
        violations.append(CodeMapViolation(
            code="code_map.schema_version.invalid",
            field="schema_version",
            message=f"schema_version must be an int; got {type(sv).__name__}",
            severity="error",
        ))
    elif sv not in SUPPORTED_SCHEMA_VERSIONS:
        violations.append(CodeMapViolation(
            code="code_map.schema_version.invalid",
            field="schema_version",
            message=(
                f"schema_version={sv} is not in the supported set "
                f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            ),
            severity="error",
        ))

    # ---- repo_path ----
    repo_path = data.get("repo_path")
    if repo_path is None:
        violations.append(CodeMapViolation(
            code="code_map.missing.repo_path",
            field="repo_path",
            message="required field `repo_path` is missing",
            severity="error",
        ))
    elif not isinstance(repo_path, str) or not repo_path.strip():
        violations.append(CodeMapViolation(
            code="code_map.repo_path.invalid_type",
            field="repo_path",
            message=f"repo_path must be a non-empty string; got {type(repo_path).__name__}",
            severity="error",
        ))

    # ---- generated_at ----
    ts = data.get("generated_at")
    if ts is None:
        violations.append(CodeMapViolation(
            code="code_map.missing.generated_at",
            field="generated_at",
            message="required field `generated_at` is missing",
            severity="error",
        ))
    elif not isinstance(ts, str) or not _is_isoformat(ts):
        violations.append(CodeMapViolation(
            code="code_map.generated_at.invalid_type",
            field="generated_at",
            message=f"generated_at must be ISO-8601; got {ts!r}",
            severity="error",
        ))

    # ---- summary ----
    summary = data.get("summary")
    if summary is None:
        violations.append(CodeMapViolation(
            code="code_map.missing.summary",
            field="summary",
            message="required field `summary` is missing",
            severity="error",
        ))
    elif not isinstance(summary, dict):
        violations.append(CodeMapViolation(
            code="code_map.summary.invalid_type",
            field="summary",
            message=f"summary must be a dict; got {type(summary).__name__}",
            severity="error",
        ))
    else:
        missing_counters = REQUIRED_SUMMARY_COUNTERS - set(summary.keys())
        if missing_counters:
            violations.append(CodeMapViolation(
                code="code_map.summary.missing_counters",
                field="summary",
                message=(
                    f"summary is missing recommended counters: "
                    f"{sorted(missing_counters)}"
                ),
                severity="warn",
            ))

    # ---- per-array shape validation ----
    violations.extend(_validate_array_records(
        data.get("routes"), "routes", _ROUTES_REQUIRED, "code_map.routes",
    ))
    violations.extend(_validate_array_records(
        data.get("models"), "models", _MODELS_REQUIRED, "code_map.models",
    ))
    violations.extend(_validate_array_records(
        data.get("db_queries"), "db_queries", _QUERIES_REQUIRED, "code_map.db_queries",
    ))
    violations.extend(_validate_array_records(
        data.get("external_http_calls"), "external_http_calls",
        _HTTP_REQUIRED, "code_map.external_http_calls",
    ))
    violations.extend(_validate_array_records(
        data.get("auth_boundaries"), "auth_boundaries",
        _AUTH_REQUIRED, "code_map.auth_boundaries",
    ))

    return violations


def has_canonical_errors(violations: list[CodeMapViolation]) -> bool:
    """True if any violation has severity='error'."""
    return any(v.severity == "error" for v in violations)


def violations_to_dict_list(
    violations: list[CodeMapViolation],
) -> list[dict[str, str]]:
    return [
        {"code": v.code, "field": v.field, "message": v.message, "severity": v.severity}
        for v in violations
    ]


def load_code_map(
    path: str | Path,
) -> tuple[dict[str, Any] | None, list[CodeMapViolation]]:
    """Load `code_map.json` from disk, validate, return (data, violations).
    Never raises."""
    p = Path(path)
    if not p.exists():
        return (None, [CodeMapViolation(
            code="code_map.not_dict",
            field="(root)",
            message=f"code_map file not found: {p}",
            severity="error",
        )])
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError) as e:
        return (None, [CodeMapViolation(
            code="code_map.not_dict",
            field="(root)",
            message=f"failed to parse code_map.json: {e}",
            severity="error",
        )])
    violations = validate_code_map(data)
    return (data if isinstance(data, dict) else None, violations)
