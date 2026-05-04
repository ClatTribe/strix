"""Handoff artifact schemas (roadmap §8.0).

Documented contracts for the data that flows BETWEEN OODA stages:

- `surface_map.json` — Observe → Decide.
  Produced by `domain_recon_pipeline`; consumed by exploit-stage
  agents and `cross_target_correlate`.

(Future: `candidate_findings.json` Decide→Validator;
`verified_findings.json` Validator→Report — both depend on the
Validator agent in §17.1, which isn't built yet. The surface_map
schema is the only one with a current producer + consumer pair.)

Each schema ships:

- A pure-function `validate_<artifact>(data) -> list[Violation]` that
  never raises and never mutates.
- A `load_<artifact>(path)` helper for consumers — loads JSON,
  validates, returns the dict + violations.
- A stable list of violation codes wrapper / GRC consumers can key
  on.

The validators mirror the `finding_contract` pattern from §8.0:
errors mean "this artifact is non-canonical", warns mean "advisory".
"""

from .surface_map import (
    SurfaceMapViolation,
    has_canonical_errors,
    load_surface_map,
    validate_surface_map,
)


__all__ = [
    "SurfaceMapViolation",
    "has_canonical_errors",
    "load_surface_map",
    "validate_surface_map",
]
