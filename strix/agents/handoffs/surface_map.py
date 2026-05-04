"""`surface_map.json` schema validator.

`surface_map.json` is the Observe → Decide handoff artifact for
domain targets. Produced by `domain_recon_pipeline` (§17 in
recon_pipeline.py); consumed by exploit-stage agents and
`cross_target_correlate` (§17.1).

The schema corresponds to what `domain_recon_pipeline._write_surface_map`
emits today; this module makes the contract explicit so:

1. Consumers can validate before reading (defensive against
   future producer drift).
2. Wrappers / GRC platforms can declare a stable schema_version.
3. New producers (e.g. recon for repo / IP target types) can
   conform to the same shape.

Contract:

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | int | yes | currently 1; bump on breaking changes |
| `domain` | str (non-empty) | yes | the canonical domain target |
| `generated_at` | str (ISO 8601) | yes | UTC timestamp |
| `phase_id` | str | no | links to the recon phase event |
| `dns_only` | bool | no | true if the run is `--dns-only` |
| `summary` | dict | yes | counts: subdomains_discovered, subdomains_live, deep_targets, shallow_targets, takeover_candidates |
| `subdomain_enum` | dict | no | {per_source: dict, all_unique: int, subdomains: list[str]} |
| `subdomain_triage` | list | no | list of {subdomain: str, ips_resolved: list[str]} |
| `deep_targets` / `shallow_targets` | list[str] | no | URL lists |
| `passive_dns` | dict | no | passive-DNS records |
| `org_fingerprint` | dict | no | WHOIS / ASN / GitHub-org metadata |
| `dns_hygiene` | dict | no | SPF / DMARC / DNSSEC posture |
| `cloud_assets` | dict | no | discovered cloud namespaces |
| `takeover` | dict | no | subdomain takeover candidates |

Violation codes (stable public interface):
- `surface_map.missing.{schema_version,domain,generated_at,summary}` — error
- `surface_map.schema_version.invalid` — error (unknown version)
- `surface_map.{domain,generated_at}.invalid_type` — error
- `surface_map.summary.missing_counters` — warn (advisory; wrapper rendering may degrade)
- `surface_map.subdomain_enum.invalid_shape` — error
- `surface_map.subdomain_triage.invalid_entry` — error
- `surface_map.not_dict` — error
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
    "subdomains_discovered",
    "subdomains_live",
    "deep_targets",
    "shallow_targets",
})


@dataclass(frozen=True)
class SurfaceMapViolation:
    """One contract violation against the surface_map.json schema."""
    code: str
    field: str
    message: str
    severity: str  # 'error' or 'warn'


def _is_isoformat(value: str) -> bool:
    try:
        # Python 3.11+ accepts most ISO 8601 strings via fromisoformat
        # (3.10 needs trailing Z stripped). We support either.
        v = value.rstrip("Z").replace("Z", "")
        datetime.fromisoformat(v)
        return True
    except (ValueError, TypeError):
        return False


def validate_surface_map(data: Any) -> list[SurfaceMapViolation]:
    """Validate `data` against the surface_map.json contract.

    Pure function: never raises, never mutates.

    Returns a list of SurfaceMapViolation records. Empty = canonical.
    """
    if not isinstance(data, dict):
        return [SurfaceMapViolation(
            code="surface_map.not_dict",
            field="(root)",
            message=f"surface_map is not a dict: {type(data).__name__}",
            severity="error",
        )]

    violations: list[SurfaceMapViolation] = []

    # ---- schema_version ----
    sv = data.get("schema_version")
    if sv is None:
        violations.append(SurfaceMapViolation(
            code="surface_map.missing.schema_version",
            field="schema_version",
            message="required field `schema_version` is missing",
            severity="error",
        ))
    elif not isinstance(sv, int):
        violations.append(SurfaceMapViolation(
            code="surface_map.schema_version.invalid",
            field="schema_version",
            message=f"schema_version must be an int; got {type(sv).__name__}",
            severity="error",
        ))
    elif sv not in SUPPORTED_SCHEMA_VERSIONS:
        violations.append(SurfaceMapViolation(
            code="surface_map.schema_version.invalid",
            field="schema_version",
            message=(
                f"schema_version={sv} is not in the supported set "
                f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            ),
            severity="error",
        ))

    # ---- domain ----
    domain = data.get("domain")
    if domain is None:
        violations.append(SurfaceMapViolation(
            code="surface_map.missing.domain",
            field="domain",
            message="required field `domain` is missing",
            severity="error",
        ))
    elif not isinstance(domain, str) or not domain.strip():
        violations.append(SurfaceMapViolation(
            code="surface_map.domain.invalid_type",
            field="domain",
            message=f"domain must be a non-empty string; got {type(domain).__name__}",
            severity="error",
        ))

    # ---- generated_at ----
    ts = data.get("generated_at")
    if ts is None:
        violations.append(SurfaceMapViolation(
            code="surface_map.missing.generated_at",
            field="generated_at",
            message="required field `generated_at` is missing",
            severity="error",
        ))
    elif not isinstance(ts, str) or not _is_isoformat(ts):
        violations.append(SurfaceMapViolation(
            code="surface_map.generated_at.invalid_type",
            field="generated_at",
            message=f"generated_at must be an ISO-8601 string; got {ts!r}",
            severity="error",
        ))

    # ---- summary ----
    summary = data.get("summary")
    if summary is None:
        violations.append(SurfaceMapViolation(
            code="surface_map.missing.summary",
            field="summary",
            message="required field `summary` is missing",
            severity="error",
        ))
    elif not isinstance(summary, dict):
        violations.append(SurfaceMapViolation(
            code="surface_map.summary.invalid_type",
            field="summary",
            message=f"summary must be a dict; got {type(summary).__name__}",
            severity="error",
        ))
    else:
        missing_counters = REQUIRED_SUMMARY_COUNTERS - set(summary.keys())
        if missing_counters:
            violations.append(SurfaceMapViolation(
                code="surface_map.summary.missing_counters",
                field="summary",
                message=(
                    f"summary is missing recommended counters: "
                    f"{sorted(missing_counters)}"
                ),
                severity="warn",
            ))

    # ---- subdomain_enum ----
    sub_enum = data.get("subdomain_enum")
    if sub_enum is not None:
        if not isinstance(sub_enum, dict):
            violations.append(SurfaceMapViolation(
                code="surface_map.subdomain_enum.invalid_shape",
                field="subdomain_enum",
                message="subdomain_enum must be a dict when present",
                severity="error",
            ))
        else:
            subs = sub_enum.get("subdomains")
            if subs is not None and not (
                isinstance(subs, list) and all(isinstance(s, str) for s in subs)
            ):
                violations.append(SurfaceMapViolation(
                    code="surface_map.subdomain_enum.invalid_shape",
                    field="subdomain_enum.subdomains",
                    message="subdomain_enum.subdomains must be a list[str]",
                    severity="error",
                ))

    # ---- subdomain_triage ----
    triage = data.get("subdomain_triage")
    if triage is not None:
        if not isinstance(triage, list):
            violations.append(SurfaceMapViolation(
                code="surface_map.subdomain_triage.invalid_entry",
                field="subdomain_triage",
                message="subdomain_triage must be a list when present",
                severity="error",
            ))
        else:
            for i, entry in enumerate(triage):
                if not isinstance(entry, dict):
                    violations.append(SurfaceMapViolation(
                        code="surface_map.subdomain_triage.invalid_entry",
                        field=f"subdomain_triage[{i}]",
                        message=f"entry {i} is not a dict",
                        severity="error",
                    ))
                    continue
                ips = entry.get("ips_resolved") or entry.get("a_records")
                if ips is not None and not (
                    isinstance(ips, list) and all(isinstance(x, str) for x in ips)
                ):
                    violations.append(SurfaceMapViolation(
                        code="surface_map.subdomain_triage.invalid_entry",
                        field=f"subdomain_triage[{i}].ips_resolved",
                        message="ips_resolved/a_records must be list[str]",
                        severity="error",
                    ))

    return violations


def has_canonical_errors(violations: list[SurfaceMapViolation]) -> bool:
    """True if any violation has severity='error'."""
    return any(v.severity == "error" for v in violations)


def violations_to_dict_list(
    violations: list[SurfaceMapViolation],
) -> list[dict[str, str]]:
    """Convert violations into JSON-serialisable dicts."""
    return [
        {
            "code": v.code,
            "field": v.field,
            "message": v.message,
            "severity": v.severity,
        }
        for v in violations
    ]


def load_surface_map(
    path: str | Path,
) -> tuple[dict[str, Any] | None, list[SurfaceMapViolation]]:
    """Load `surface_map.json` from disk, validate, and return
    (data, violations).

    On parse failure: returns (None, [violation describing the
    parse error]).

    Never raises.
    """
    p = Path(path)
    if not p.exists():
        return (None, [SurfaceMapViolation(
            code="surface_map.not_dict",
            field="(root)",
            message=f"surface_map file not found: {p}",
            severity="error",
        )])
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError) as e:
        return (None, [SurfaceMapViolation(
            code="surface_map.not_dict",
            field="(root)",
            message=f"failed to parse surface_map.json: {e}",
            severity="error",
        )])
    violations = validate_surface_map(data)
    return (data if isinstance(data, dict) else None, violations)
