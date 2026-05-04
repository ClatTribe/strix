"""`webapp_surface_map.json` schema validator (roadmap §8.2 + §8.0).

Recon → Decide handoff for web-application targets. Produced by
`webapp_recon_pipeline`; consumed by `spawn_webapp_specialist_team`
and the spawned exploit specialists.

Mirrors the §8.0 finding-contract / surface_map.json pattern: pure
validator, never raises, never mutates. Returns a list of
`WebappSurfaceMapViolation` records keyed by stable codes.

Contract (current `schema_version=1`):

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | int | yes | currently 1 |
| `target_url` | str (non-empty) | yes | full URL |
| `target_host` | str (non-empty) | yes | hostname extracted from URL |
| `generated_at` | str (ISO 8601) | yes | UTC timestamp |
| `phase_id` | str | no | links to recon phase event |
| `summary` | dict | yes | counters: endpoints_discovered, javascript_bundles, openapi_specs_found, tech_stack_detections, skills_auto_loaded |
| `fingerprint` | dict | no | output of fingerprint_tech_stack |
| `crawl` | dict | no | output of bfs_crawl |
| `security_headers` | dict | no | output of http_security_headers_audit |
| `tls` | dict | no | output of tls_audit |
| `well_known` | dict | no | output of well_known_harvest |
| `endpoints` | list[str] | no | flat URL list |
| `errors` | list[dict] | no | per-step failure log |

Stable violation codes (public-interface keying for wrapper / GRC):

- `webapp_surface_map.missing.{schema_version,target_url,target_host,generated_at,summary}`
- `webapp_surface_map.{schema_version,target_url,target_host,generated_at}.invalid_*`
- `webapp_surface_map.summary.missing_counters` (warn)
- `webapp_surface_map.endpoints.invalid_shape`
- `webapp_surface_map.not_dict`
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
    "endpoints_discovered",
    "javascript_bundles",
    "openapi_specs_found",
})


@dataclass(frozen=True)
class WebappSurfaceMapViolation:
    """One contract violation against the webapp_surface_map.json
    schema."""
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


def validate_webapp_surface_map(  # noqa: PLR0912
    data: Any,
) -> list[WebappSurfaceMapViolation]:
    """Validate `data` against the webapp_surface_map.json contract.

    Pure function: never raises, never mutates.

    Returns a list of `WebappSurfaceMapViolation` records. Empty =
    canonical."""
    if not isinstance(data, dict):
        return [WebappSurfaceMapViolation(
            code="webapp_surface_map.not_dict",
            field="(root)",
            message=f"webapp_surface_map is not a dict: {type(data).__name__}",
            severity="error",
        )]

    violations: list[WebappSurfaceMapViolation] = []

    # ---- schema_version ----
    sv = data.get("schema_version")
    if sv is None:
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.missing.schema_version",
            field="schema_version",
            message="required field `schema_version` is missing",
            severity="error",
        ))
    elif not isinstance(sv, int):
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.schema_version.invalid",
            field="schema_version",
            message=f"schema_version must be an int; got {type(sv).__name__}",
            severity="error",
        ))
    elif sv not in SUPPORTED_SCHEMA_VERSIONS:
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.schema_version.invalid",
            field="schema_version",
            message=(
                f"schema_version={sv} is not in the supported set "
                f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            ),
            severity="error",
        ))

    # ---- target_url ----
    url = data.get("target_url")
    if url is None:
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.missing.target_url",
            field="target_url",
            message="required field `target_url` is missing",
            severity="error",
        ))
    elif not isinstance(url, str) or not url.strip():
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.target_url.invalid_type",
            field="target_url",
            message=f"target_url must be a non-empty string; got {type(url).__name__}",
            severity="error",
        ))

    # ---- target_host ----
    host = data.get("target_host")
    if host is None:
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.missing.target_host",
            field="target_host",
            message="required field `target_host` is missing",
            severity="error",
        ))
    elif not isinstance(host, str) or not host.strip():
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.target_host.invalid_type",
            field="target_host",
            message=f"target_host must be a non-empty string; got {type(host).__name__}",
            severity="error",
        ))

    # ---- generated_at ----
    ts = data.get("generated_at")
    if ts is None:
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.missing.generated_at",
            field="generated_at",
            message="required field `generated_at` is missing",
            severity="error",
        ))
    elif not isinstance(ts, str) or not _is_isoformat(ts):
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.generated_at.invalid_type",
            field="generated_at",
            message=f"generated_at must be ISO-8601; got {ts!r}",
            severity="error",
        ))

    # ---- summary ----
    summary = data.get("summary")
    if summary is None:
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.missing.summary",
            field="summary",
            message="required field `summary` is missing",
            severity="error",
        ))
    elif not isinstance(summary, dict):
        violations.append(WebappSurfaceMapViolation(
            code="webapp_surface_map.summary.invalid_type",
            field="summary",
            message=f"summary must be a dict; got {type(summary).__name__}",
            severity="error",
        ))
    else:
        missing_counters = REQUIRED_SUMMARY_COUNTERS - set(summary.keys())
        if missing_counters:
            violations.append(WebappSurfaceMapViolation(
                code="webapp_surface_map.summary.missing_counters",
                field="summary",
                message=(
                    f"summary is missing recommended counters: "
                    f"{sorted(missing_counters)}"
                ),
                severity="warn",
            ))

    # ---- endpoints ----
    endpoints = data.get("endpoints")
    if endpoints is not None:
        if not (
            isinstance(endpoints, list)
            and all(isinstance(e, str) for e in endpoints)
        ):
            violations.append(WebappSurfaceMapViolation(
                code="webapp_surface_map.endpoints.invalid_shape",
                field="endpoints",
                message="endpoints must be a list[str] when present",
                severity="error",
            ))

    return violations


def has_canonical_errors(
    violations: list[WebappSurfaceMapViolation],
) -> bool:
    """True if any violation has severity='error'."""
    return any(v.severity == "error" for v in violations)


def violations_to_dict_list(
    violations: list[WebappSurfaceMapViolation],
) -> list[dict[str, str]]:
    return [
        {"code": v.code, "field": v.field, "message": v.message, "severity": v.severity}
        for v in violations
    ]


def load_webapp_surface_map(
    path: str | Path,
) -> tuple[dict[str, Any] | None, list[WebappSurfaceMapViolation]]:
    """Load `webapp_surface_map.json` from disk, validate, return
    (data, violations). Never raises."""
    p = Path(path)
    if not p.exists():
        return (None, [WebappSurfaceMapViolation(
            code="webapp_surface_map.not_dict",
            field="(root)",
            message=f"webapp_surface_map file not found: {p}",
            severity="error",
        )])
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError) as e:
        return (None, [WebappSurfaceMapViolation(
            code="webapp_surface_map.not_dict",
            field="(root)",
            message=f"failed to parse webapp_surface_map.json: {e}",
            severity="error",
        )])
    violations = validate_webapp_surface_map(data)
    return (data if isinstance(data, dict) else None, violations)
