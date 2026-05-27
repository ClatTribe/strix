"""iter-Q5.8 — `lookup_compliance_mapping(finding_shape, frameworks)`.

Per CLAUDE.md §1.5.7 FETCH EXTERNAL bucket and the consolidated Q5
proposal §4.2. Maps a finding shape (CWE + severity) to current
SOC2 / PCI-DSS / HIPAA / GDPR / FedRAMP control IDs.

## Why a tool, not LLM inline

LLM training cutoff doesn't know which SOC2 revision is current
(2017 vs 2022 vs 2025) or how PCI-DSS 4.0 control IDs map to CWEs.
The mapping changes when frameworks revise; a versioned corpus
refreshed on cron is the right shape.

## Corpus location

`STRIX_COMPLIANCE_CORPUS_DIR` env var → corpus directory. Defaults
to a ship-with-package corpus under
`strix/tools/compliance_lookup/corpus/`. A cron pager (similar to
iter-Q1.3's Vulhub freshness check) flags when the corpus is
>90 days stale.

## Returns

```
{
  finding_shape: {cwe, severity, ...},
  mappings: {
    SOC2:    [{control_id, description, revision}, ...],
    PCI-DSS: [{control_id, description, revision}, ...],
    HIPAA:   [...],
    GDPR:    [...],
    FedRAMP: [...],
  },
  corpus_version: str,
  corpus_age_days: int,
  reason: str | null,  # populated when a framework has no mapping
                       # for the CWE
}
```
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)


# Built-in corpus path (ships with the package).
_DEFAULT_CORPUS_DIR = Path(__file__).parent / "corpus"

# Stale threshold — frameworks revise yearly; corpus older than 90d
# should pager. Surfaced via `corpus_age_days` field.
_STALE_THRESHOLD_DAYS = 90

_SUPPORTED_FRAMEWORKS: frozenset[str] = frozenset({
    "SOC2", "PCI-DSS", "HIPAA", "GDPR", "FedRAMP",
})


def _corpus_dir() -> Path:
    """Return the active corpus directory."""
    custom = os.environ.get("STRIX_COMPLIANCE_CORPUS_DIR")
    if custom:
        return Path(custom)
    return _DEFAULT_CORPUS_DIR


def _load_framework_mappings(framework: str) -> dict[str, Any]:
    """Load one framework's CWE→control mapping. Returns empty dict
    when the corpus file is missing (graceful — the tool still
    returns a structured response with reason=...)."""
    path = _corpus_dir() / f"{framework}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.debug("compliance corpus %s read failed: %s", framework, e)
        return {}


def _corpus_age_days() -> int:
    """Approximate corpus age in days (based on the newest file mtime
    in the corpus dir). Returns -1 when the dir is missing."""
    d = _corpus_dir()
    if not d.exists():
        return -1
    try:
        newest = max(p.stat().st_mtime for p in d.glob("*.json"))
        age_seconds = time.time() - newest
        return int(age_seconds / 86_400)
    except Exception:  # noqa: BLE001
        return -1


def _corpus_version() -> str:
    """Returns the corpus version string read from `corpus/VERSION`,
    or 'unknown' when missing."""
    version_path = _corpus_dir() / "VERSION"
    if version_path.exists():
        try:
            return version_path.read_text(encoding="utf-8").strip()
        except OSError:
            return "unknown"
    return "unknown"


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1597"],  # Search Closed Sources
)
def lookup_compliance_mapping(
    *,
    finding_shape: dict[str, Any],
    frameworks: list[str],
) -> dict[str, Any]:
    """Map a finding to current compliance control IDs.

    Per CLAUDE.md §1.5.7 — FETCH EXTERNAL bucket. The corpus is
    versioned (`corpus/VERSION`) and refreshed on cron; returns
    `corpus_age_days` so the L2-audience artifact can flag stale
    data.

    Args:
        finding_shape: dict with at minimum `cwe` (e.g. "CWE-89").
            Optional: `severity`, `category`. The lookup keys on
            CWE; severity is preserved in the return for downstream
            consumers.
        frameworks: list of framework names to map. Valid:
            ``SOC2``, ``PCI-DSS``, ``HIPAA``, ``GDPR``, ``FedRAMP``.
            Unknown names are rejected with a clear error.

    Returns:
        See module docstring for the structured shape.
    """
    if not isinstance(finding_shape, dict):
        return {
            "success": False, "status": "error",
            "reason": "finding_shape must be a dict (at minimum {cwe: 'CWE-X'})",
        }
    cwe = (finding_shape.get("cwe") or "").strip()
    if not cwe:
        return {
            "success": False, "status": "error",
            "reason": "finding_shape.cwe is required (e.g. 'CWE-89')",
        }

    if not isinstance(frameworks, list) or not frameworks:
        return {
            "success": False, "status": "error",
            "reason": (
                f"frameworks must be a non-empty list of "
                f"{sorted(_SUPPORTED_FRAMEWORKS)!r}"
            ),
        }
    invalid = [f for f in frameworks if f not in _SUPPORTED_FRAMEWORKS]
    if invalid:
        return {
            "success": False, "status": "error",
            "reason": (
                f"unknown framework(s) {invalid!r}; valid: "
                f"{sorted(_SUPPORTED_FRAMEWORKS)!r}"
            ),
        }

    mappings: dict[str, list[dict[str, Any]]] = {}
    missing_frameworks: list[str] = []
    for framework in frameworks:
        corpus = _load_framework_mappings(framework)
        controls = corpus.get(cwe) or []
        if not controls:
            missing_frameworks.append(framework)
            mappings[framework] = []
            continue
        # Always include the framework's revision so the L2 audience
        # sees "SOC2 2022" not "SOC2".
        revision = corpus.get("__revision") or ""
        mappings[framework] = [
            {
                "control_id": c.get("control_id"),
                "description": c.get("description"),
                "revision": revision,
            }
            for c in controls if isinstance(c, dict)
        ]

    reason = None
    if missing_frameworks:
        reason = (
            f"No mappings found for {cwe} in: "
            f"{', '.join(missing_frameworks)}. Either the framework "
            f"genuinely doesn't have a corresponding control, or the "
            f"corpus is missing the {cwe} entry — check "
            f"`{_corpus_dir()}/{missing_frameworks[0]}.json`."
        )

    age = _corpus_age_days()
    return {
        "success": True,
        "status": "ok",
        "finding_shape": dict(finding_shape),
        "mappings": mappings,
        "corpus_version": _corpus_version(),
        "corpus_age_days": age,
        "corpus_stale": age > _STALE_THRESHOLD_DAYS if age >= 0 else False,
        "reason": reason,
    }
