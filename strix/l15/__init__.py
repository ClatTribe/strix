"""L1.5 — deterministic enrichment / join / amplify layer.

Sits between L1 finding emission (`tracer.add_vulnerability_report`) and
L2 LLM consumption. Three sub-functions implemented here in Wave 1:

  * `pre_emission_fp_filter` — anti-FP via local context
    (test-file / docstring / getenv-default heuristics)
  * `root_cause_collapse` — coalesce same (rule × file × function) into
    one finding with an occurrences[] list
  * `mid_scan_corroborator` — promote/demote on cross-tool ≥2-signal
    co-occurrence

All functions are deterministic, no-LLM, and fall back to passthrough
semantics on any internal error so L1.5 failure never makes L2 worse off
than no-L1.5 (the "Not in the critical path for crashes" guardrail in
`docs/L2-optimization.md` §7).

Subsequent waves will add:
  Wave 2 — defensive_posture / composite_exploitability / sast_to_dast
  Wave 3 — hygiene_prior / surface_priority / git_blame_enrich
  Wave 4 — finding_triggered_probes + execute_adaptive_probe
"""

from strix.l15.corroborator import (
    CorroboratorLedger,
    corroborator_ledger,
)
from strix.l15.exploitability import (
    ExploitabilityScore,
    apply_exploitability_to_severity,
    score_exploitability,
)
from strix.l15.fp_filter import (
    FpFilterDecision,
    pre_emission_fp_filter,
)
from strix.l15.posture import (
    SecurityPosture,
    get_posture,
    probe_defensive_posture,
    rate_limit_cap,
    set_posture,
    stealth_required,
)
from strix.l15.root_cause import (
    RootCauseLedger,
    root_cause_ledger,
)
from strix.l15.sast_to_dast import (
    ConfirmationRequest,
    plan_dast_confirmation,
)


__all__ = [
    # Wave 1 — prune
    "CorroboratorLedger",
    "FpFilterDecision",
    "RootCauseLedger",
    "corroborator_ledger",
    "pre_emission_fp_filter",
    "root_cause_ledger",
    # Wave 2 — posture / exploitability / sast→dast
    "ConfirmationRequest",
    "ExploitabilityScore",
    "SecurityPosture",
    "apply_exploitability_to_severity",
    "get_posture",
    "plan_dast_confirmation",
    "probe_defensive_posture",
    "rate_limit_cap",
    "score_exploitability",
    "set_posture",
    "stealth_required",
]
