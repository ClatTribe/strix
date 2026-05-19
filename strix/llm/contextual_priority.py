"""Contextual priority rollup — MA-S2 P0-CVS-B.

## Why this exists

MA-S2 CVS-0.5 explicitly disqualifies vendors who "apply uniform
SLAs based on CVSS alone, without contextual enrichment." This
module emits a structured `contextual_priority` block on every
finding rolling up the four contextual inputs the standard names:

  1. EPSS / KEV — exploitability intel (from P0-CVS-A + threat_intel)
  2. Reachability — source-level (SAST), dependency-level (SCA),
     runtime-level (DAST) — and a worst-case verdict.
  3. Asset context — criticality, data sensitivity, blast radius
     (from `target_metadata`, plumbed by the wrapper).
  4. Attack-path membership — chain IDs from P0-APM-A's
     `attack_paths.jsonl` + the worst-case chained severity.

Plus a derived `priority_tier` (p0_emergency … p4_suppressible)
the wrapper reads to set SLAs. The engine's tier is a
*recommendation* — the wrapper may override per customer SLA
contract.

## Block shape (always present)

```json
"contextual_priority": {
  "raw_cvss": 9.8,                       // copied from finding
  "raw_severity": "critical",            // copied from finding
  "epss_score": 0.94,                    // from epss block
  "kev_listed": true,
  "reachability": {
    "source_level": null,                // reachable | unreachable | unknown
    "dependency_level": null,            // called | not_called | unknown
    "runtime_level": null,               // observed | not_observed | unknown
    "verdict": "unknown"                 // reachable | unreachable | unknown
  },
  "asset_context": {
    "criticality": "high",               // critical | high | medium | low | unknown
    "data_sensitivity": "pii",           // pii | financial | health | public | unknown
    "blast_radius": "tenant"             // shared | tenant | single | unknown
  },
  "attack_path_membership": [],          // populated by P0-APM-A
  "max_chained_severity": "critical",    // copied from raw_severity until APM-A ships
  "priority_tier": "p0_emergency"
}
```

## Doctrine — preserved across the strix ↔ webappsec boundary

`raw_cvss`, `raw_severity`, and `priority_tier` are immutable
once emitted. The wrapper may store its own override in a
separate field (`findings.wrapper_priority_tier`) but MUST NOT
overwrite the engine's values. This invariant comes from
webappsec/ma-s2-proposal.md §4 (two-signal layering).

## Recall safety

Block always present on every finding. Failures in any
individual section degrade to `unknown` / null / [] for that
section while preserving the rest of the block. The builder
NEVER raises.

## priority_tier derivation (this PR)

Rules-of-thumb, in order (first match wins):
  * KEV-listed → p0_emergency
  * EPSS ≥ 0.7 → p0_emergency
  * raw_severity == critical → p1_urgent
  * raw_severity == high AND EPSS ≥ 0.5 → p1_urgent
  * raw_severity == high → p2_standard
  * raw_severity == medium → p3_deferrable
  * otherwise → p4_suppressible

P0-APM-B's R9 (downgrade unreachable critical) + R10 (upgrade
chain-first-link) refine these rules in a follow-up.

## Kill switch

`STRIX_CONTEXTUAL_PRIORITY_DISABLED=1` returns a minimal block
with `priority_tier="unknown"`. Useful for runs where the
operator wants raw CVSS only.
"""

from __future__ import annotations

import logging
import os
from typing import Any


logger = logging.getLogger(__name__)


# Per-EPSS-score thresholds for tier bumps. FIRST.org recommends
# EPSS ≥ 0.7 as "highly probable exploit in next 30 days"; ≥ 0.5
# is "watch closely." These thresholds match.
_EPSS_EMERGENCY = 0.7
_EPSS_URGENT = 0.5

# Canonical priority tiers (in priority order — p0 is most urgent).
_PRIORITY_TIERS = (
    "p0_emergency",
    "p1_urgent",
    "p2_standard",
    "p3_deferrable",
    "p4_suppressible",
    "unknown",
)


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_CONTEXTUAL_PRIORITY_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _lookup_kev(cve: str | None) -> bool:
    """Best-effort KEV check via the threat_intel cache."""
    if not cve or not isinstance(cve, str):
        return False
    try:
        from strix.threat_intel.lookup import get_cve
        rec = get_cve(cve.strip())
        return bool(getattr(rec, "kev", False)) if rec else False
    except Exception:  # noqa: BLE001
        return False


def _build_reachability(report: dict[str, Any]) -> dict[str, Any]:
    """Build the reachability sub-block from existing per-finding
    evidence. Today we have partial SAST evidence (via the
    sca-reachability tag); SCA + DAST runtime evidence is the
    follow-up scope. Default values are 'unknown' so consumers
    can distinguish "we don't know" from "definitely safe.\""""
    sub: dict[str, Any] = {
        "source_level": "unknown",
        "dependency_level": "unknown",
        "runtime_level": "unknown",
        "verdict": "unknown",
    }
    # Phase 6.4 reachability tag — SCA findings carry a
    # `reachability` tag in their description / metadata. Look
    # for it conservatively.
    desc = (report.get("description") or "")
    if "reachability=direct_import" in desc or "reachability=called" in desc:
        sub["dependency_level"] = "called"
    elif "reachability=transitive_only" in desc:
        sub["dependency_level"] = "transitive_only"
    elif "reachability=unused" in desc:
        sub["dependency_level"] = "unused"

    # SAST taint: findings with a `code_locations` field have
    # source-level evidence — they're verified reachable in
    # source (the taint flow connected user input to sink).
    if report.get("code_locations"):
        sub["source_level"] = "reachable"

    # Verdict: worst-case across the three. If ANY level reports
    # "reachable" / "called" / "observed", the verdict is
    # reachable. If ALL report "unreachable" variants, unreachable.
    # Otherwise unknown (the safe default — recall protected).
    reachable_signals = {"reachable", "called", "observed"}
    unreachable_signals = {"unreachable", "not_called", "unused", "not_observed"}
    levels = {
        sub["source_level"], sub["dependency_level"], sub["runtime_level"],
    }
    if levels & reachable_signals:
        sub["verdict"] = "reachable"
    elif levels.issubset(unreachable_signals | {"unknown"}) and not (levels == {"unknown"}):
        # All known levels say unreachable AND at least one is known
        sub["verdict"] = "unreachable"
    else:
        sub["verdict"] = "unknown"
    return sub


def _build_asset_context(
    scan_config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Pull asset context from `scan_config['target_metadata']` per
    the wrapper-side commitment (webappsec/ma-s2-proposal.md §2
    item 1). When target_metadata is empty / not plumbed, every
    field is 'unknown' — the wrapper can render that explicitly
    as 'untagged asset'."""
    sub = {
        "criticality": "unknown",
        "data_sensitivity": "unknown",
        "blast_radius": "unknown",
    }
    if not isinstance(scan_config, dict):
        return sub
    tm = scan_config.get("target_metadata") or {}
    if not isinstance(tm, dict):
        return sub
    crit = tm.get("criticality")
    if isinstance(crit, str) and crit.strip():
        sub["criticality"] = crit.strip().lower()
    ds = tm.get("data_sensitivity")
    if isinstance(ds, str) and ds.strip():
        sub["data_sensitivity"] = ds.strip().lower()
    br = tm.get("blast_radius")
    if isinstance(br, str) and br.strip():
        sub["blast_radius"] = br.strip().lower()
    return sub


def _derive_priority_tier(
    *,
    raw_severity: str,
    epss_score: float | None,
    kev_listed: bool,
) -> str:
    """Derivation rules-of-thumb in priority order. P0-APM-B's R9
    + R10 contextual rules refine this with reachability + chain
    membership in a follow-up."""
    if kev_listed:
        return "p0_emergency"
    if isinstance(epss_score, (int, float)) and epss_score >= _EPSS_EMERGENCY:
        return "p0_emergency"
    sev = (raw_severity or "").strip().lower()
    if sev == "critical":
        return "p1_urgent"
    if sev == "high":
        if isinstance(epss_score, (int, float)) and epss_score >= _EPSS_URGENT:
            return "p1_urgent"
        return "p2_standard"
    if sev == "medium":
        return "p3_deferrable"
    if sev in ("low", "info", "informational"):
        return "p4_suppressible"
    return "unknown"


def _minimal_block(report: dict[str, Any]) -> dict[str, Any]:
    """Last-resort canonical-shape block when the full builder
    fails — preserves the doctrine that the block is always
    present with all top-level keys."""
    return {
        "raw_cvss": report.get("cvss"),
        "raw_severity": report.get("severity"),
        "epss_score": None,
        "kev_listed": False,
        "reachability": {
            "source_level": "unknown",
            "dependency_level": "unknown",
            "runtime_level": "unknown",
            "verdict": "unknown",
        },
        "asset_context": {
            "criticality": "unknown",
            "data_sensitivity": "unknown",
            "blast_radius": "unknown",
        },
        "attack_path_membership": [],
        "max_chained_severity": report.get("severity"),
        "priority_tier": "unknown",
    }


def build_contextual_priority(
    *,
    report: dict[str, Any],
    scan_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Top-level entry point. Build the contextual_priority block
    from an in-flight report dict (post-EPSS-enrichment) plus the
    scan_config (for target_metadata).

    Args:
      report: the finding dict as built up by
        `tracer.add_vulnerability_report`, including the `epss`
        block. The function reads from it but DOES NOT mutate.
      scan_config: tracer.scan_config; carries target_metadata.

    Returns:
      The full `contextual_priority` dict — always populated with
      the canonical 9 top-level keys.
    """
    if is_disabled():
        return _minimal_block(report)
    try:
        raw_cvss = report.get("cvss")
        raw_severity = (report.get("severity") or "").strip().lower()
        epss_block = report.get("epss") or {}
        epss_score = (
            epss_block.get("score")
            if isinstance(epss_block, dict) else None
        )
        cve = report.get("cve")
        kev_listed = _lookup_kev(cve)
        reachability = _build_reachability(report)
        asset_context = _build_asset_context(scan_config)
        # attack_path_membership stays empty until P0-APM-A
        # writes attack_paths.jsonl + this module reads it.
        path_membership: list[str] = []
        max_chained_severity = raw_severity or None
        priority_tier = _derive_priority_tier(
            raw_severity=raw_severity,
            epss_score=epss_score if isinstance(epss_score, (int, float)) else None,
            kev_listed=kev_listed,
        )
        return {
            "raw_cvss": raw_cvss,
            "raw_severity": report.get("severity"),  # preserve case from report
            "epss_score": (
                float(epss_score) if isinstance(epss_score, (int, float)) else None
            ),
            "kev_listed": bool(kev_listed),
            "reachability": reachability,
            "asset_context": asset_context,
            "attack_path_membership": path_membership,
            "max_chained_severity": max_chained_severity,
            "priority_tier": priority_tier,
        }
    except Exception as e:  # noqa: BLE001
        logger.debug("contextual_priority build failed: %s", e, exc_info=True)
        return _minimal_block(report)
