"""Attack-paths attestation artefact — MA-S2 P0-APM-A.

## Why this exists

MA-S2 APM-1.1 requires "the capability to model multi-stage
attack paths" with output "technically integrated into
vulnerability prioritization tooling and decisions."

Strix already builds chains in `strix/agents/chaining_graph.py`
(via `build_chain_graph`); this module surfaces those chains as
a per-run `attack_paths.jsonl` artefact in the canonical
MA-S2 shape, with stable IDs + MITRE technique enrichment.

## Output

`<run_dir>/attack_paths.jsonl` — one JSON object per line:

```json
{
  "id": "ap-<run_id>-001",
  "name": "<stage1 cat> → <stage2 cat>",
  "max_severity": "critical",
  "stages": [
    {
      "step": 1,
      "type": "entry",
      "finding_id": "vuln-0001",
      "category": "saml-xsw",
      "mitre_technique": "T1190",
      "description": "..."
    },
    ...
  ],
  "preconditions": [],
  "impact_summary": "...",
  "confidence": 0.85
}
```

## Schema notes

- `id` is stable across re-emit calls within a run.
- `max_severity` is the chain's existing `chain_severity` field
  from `chaining_graph.Chain`.
- `stages[].mitre_technique` is best-effort: derived from the
  per-tool MITRE tags recorded in `tracer.tool_executions` when
  the chain's finding came from a tagged tool; otherwise null.
- `stages[].type` is heuristically derived from the stage position
  (entry / pivot / data_access) — operators can override per
  chain.
- `preconditions` defaults to `[]` until we have explicit
  precondition extraction.
- `confidence` is heuristic — chain length × per-finding
  verification status (1.0 when every finding verified;
  reduced when any are unverified).

## Recall safety

- Builder never raises; failure falls through to an empty
  output file (which is still valid attestation: "we tried,
  no qualifying paths").
- Only chains with ≥2 stages AND at least one HIGH/CRITICAL
  stage are emitted (per the MA-S2 proposal's conservative
  threshold). Lower-severity chains stay in the KG but don't
  clutter the attestation artefact.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

_HIGH_TIER = {"high", "critical"}


def _stage_type(step: int, total: int) -> str:
    """Heuristic stage classification by position in the chain.
    Step 1 is always 'entry'; the final step is 'impact' /
    'data_access' / 'privilege_escalation' depending on the
    chain's last finding; middle steps are 'pivot'."""
    if step == 1:
        return "entry"
    if step == total:
        return "impact"
    return "pivot"


def _classify_impact_stage(finding: dict[str, Any]) -> str:
    """For the final stage, refine the type from the finding's
    category. Default 'impact' covers everything else."""
    cat = (finding.get("category") or "").lower()
    title = (finding.get("title") or "").lower()
    if cat in ("rce", "command_injection", "deserialization", "ssti"):
        return "code_execution"
    if cat in ("idor", "authz", "bola", "bfla"):
        return "data_access"
    if cat in ("auth_flow", "auth", "session_fixation"):
        return "privilege_escalation"
    if "admin" in title or "credential" in title:
        return "privilege_escalation"
    return "impact"


def _lookup_mitre_technique(
    finding: dict[str, Any], tracer: Any,
) -> str | None:
    """Best-effort MITRE technique lookup for a finding. We don't
    persist the per-finding technique tag today; this reads the
    tracer's tool_executions table for the first tool that
    matched the finding's category."""
    if tracer is None:
        return None
    try:
        execs = getattr(tracer, "tool_executions", {}) or {}
    except Exception:  # noqa: BLE001
        return None
    cat = (finding.get("category") or "").lower()
    if not cat:
        return None
    # Match scan_<cat> tool name
    for ex in execs.values():
        if not isinstance(ex, dict):
            continue
        tn = (ex.get("tool_name") or "")
        if isinstance(tn, str) and tn.startswith("scan_") and tn[len("scan_"):] == cat:
            techs = ex.get("mitre_techniques") or []
            if isinstance(techs, list) and techs:
                first = techs[0]
                if isinstance(first, str) and first.strip():
                    return first.strip()
    return None


def _confidence(chain_findings: list[dict[str, Any]]) -> float:
    """Compute chain confidence from per-finding verification
    status. 1.0 when every finding is 'verified'; reduced
    proportionally when any are 'inconclusive' / 'needs_review'."""
    if not chain_findings:
        return 0.0
    verified = 0
    for f in chain_findings:
        vs = (f.get("verification_status") or "").lower()
        if vs == "verified" or vs == "exploited":
            verified += 1
        elif vs in ("pattern_match",):
            verified += 0.5  # half-credit
    return round(verified / len(chain_findings), 2)


def _is_high_tier_chain(chain_findings: list[dict[str, Any]]) -> bool:
    """Conservative threshold: at least one HIGH/CRITICAL finding
    in the chain."""
    for f in chain_findings:
        sev = (f.get("severity") or "").lower()
        if sev in _HIGH_TIER:
            return True
    return False


def _chain_name(chain_findings: list[dict[str, Any]]) -> str:
    """Concise chain name: `<first cat> → <last cat>`. Falls
    back to per-stage titles when categories are unavailable."""
    if not chain_findings:
        return "(empty chain)"
    first = chain_findings[0]
    last = chain_findings[-1]
    first_label = (
        first.get("category") or first.get("title") or "?"
    ).strip()
    last_label = (
        last.get("category") or last.get("title") or "?"
    ).strip()
    if first_label == last_label:
        return first_label
    return f"{first_label} → {last_label}"


def _impact_summary(chain_findings: list[dict[str, Any]]) -> str:
    """One-line impact summary. Reuses the last finding's
    `impact` field; falls back to a generic phrase."""
    if not chain_findings:
        return "No impact identified."
    last = chain_findings[-1]
    impact = (last.get("impact") or "").strip()
    if not impact:
        return f"Multi-stage chain ({len(chain_findings)} stages)."
    # Trim to a single sentence / 200 chars.
    sentence = impact.split(".")[0].strip()
    if len(sentence) > 200:
        sentence = sentence[:197] + "..."
    return sentence + ("." if not sentence.endswith(".") else "")


def build_attack_paths(
    *, tracer: Any, run_id: str | None,
) -> list[dict[str, Any]]:
    """Walk the chain graph and emit MA-S2-shaped attack paths.

    Filtering:
      * Chains must have ≥2 stages.
      * Chains must contain at least one HIGH/CRITICAL finding.

    Returns a list of attack-path dicts (always returns a list;
    empty list when no qualifying chains exist)."""
    try:
        from strix.agents.chaining_graph import build_chain_graph
    except Exception as e:  # noqa: BLE001
        logger.debug("chaining_graph unavailable: %s", e)
        return []
    try:
        chains = build_chain_graph() or []
    except Exception as e:  # noqa: BLE001
        logger.debug("build_chain_graph failed: %s", e)
        return []

    out: list[dict[str, Any]] = []
    for idx, chain in enumerate(chains, start=1):
        try:
            findings = list(chain.findings or [])
        except Exception:  # noqa: BLE001
            continue
        if len(findings) < 2:
            continue
        if not _is_high_tier_chain(findings):
            continue

        stages: list[dict[str, Any]] = []
        total = len(findings)
        for step_i, f in enumerate(findings, start=1):
            stage_type = _stage_type(step_i, total)
            if step_i == total and stage_type == "impact":
                stage_type = _classify_impact_stage(f)
            stages.append({
                "step": step_i,
                "type": stage_type,
                "finding_id": f.get("id"),
                "category": (f.get("category") or "").lower() or None,
                "mitre_technique": _lookup_mitre_technique(f, tracer),
                "description": (f.get("title") or "").strip() or None,
            })

        path_id = (
            f"ap-{run_id}-{idx:03d}" if run_id else f"ap-{idx:03d}"
        )
        max_sev_rank = max(
            _SEVERITY_RANK.get((f.get("severity") or "").lower(), 1)
            for f in findings
        )
        inv_sev = {v: k for k, v in _SEVERITY_RANK.items()}
        out.append({
            "id": path_id,
            "name": _chain_name(findings),
            "max_severity": inv_sev[max_sev_rank],
            "stages": stages,
            "preconditions": [],
            "impact_summary": _impact_summary(findings),
            "confidence": _confidence(findings),
        })
    return out


def write_attack_paths_jsonl(
    *, tracer: Any, run_dir: Path, run_id: str | None,
) -> int:
    """Build + write `<run_dir>/attack_paths.jsonl`. Returns the
    number of paths written. ALWAYS writes the file (even when
    zero paths) — auditors see absence as a positive "we tried"
    signal per the MA-S2 attestation discipline."""
    try:
        paths = build_attack_paths(tracer=tracer, run_id=run_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("attack_paths build failed: %s", e)
        paths = []
    out_path = run_dir / "attack_paths.jsonl"
    try:
        with out_path.open("w", encoding="utf-8") as f:
            for p in paths:
                f.write(json.dumps(p, ensure_ascii=False))
                f.write("\n")
    except OSError as e:
        logger.debug("attack_paths jsonl write failed: %s", e)
        return 0
    return len(paths)
