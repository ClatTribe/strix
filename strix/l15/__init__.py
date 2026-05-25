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
from strix.l15.endpoint_classifier import (  # iter-29.1
    EndpointProfile,
    classify_endpoint,
    classify_endpoints_batch,
)
from strix.l15.baseline_diff import (  # iter-29.2
    DiffSignal,
    diff_responses,
    fire_and_diff,
    score_signal,
)
from strix.l15.payload_bins import (  # iter-29.3
    PayloadBin,
    bin_for,
    bin_object_for,
    list_available_combinations,
)
from strix.l15.poc_verifier import (  # iter-29.5
    CONFIDENCE_DISMISSED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_SUSPECTED,
    CONFIDENCE_VERIFIED,
    PocVerification,
    verify_finding,
)
from strix.l15.safety_guards import (  # iter-29.9
    RateLimitGovernor,
    check_destructive,
    destructive_ok,
    get_governor,
    is_destructive_endpoint,
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
from strix.l15.git_blame import (
    GitBlame,
    enrich_finding_with_blame,
    get_blame,
)
from strix.l15.probe_bundles import (
    ProbeStep,
    adaptive_call_log,
    clear_adaptive_log,
    execute_adaptive_probe,
    plan_probe_bundle,
    record_planned_bundle,
)
from strix.l15.stealth_guidance import stealth_addendum_for
from strix.l15.hygiene import (
    HygieneLedger,
    HygieneScore,
    hygiene_ledger,
)
from strix.l15.sast_to_dast import (
    ConfirmationRequest,
    plan_dast_confirmation,
)
from strix.l15.surface_priority import (
    SurfaceClassification,
    SurfaceLabel,
    classify_surface,
    depth_multiplier_for,
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
    # Wave 3 — context / depth / authorship
    "GitBlame",
    "HygieneLedger",
    "HygieneScore",
    "SurfaceClassification",
    "SurfaceLabel",
    "classify_surface",
    "depth_multiplier_for",
    "enrich_finding_with_blame",
    "get_blame",
    "hygiene_ledger",
    # Wave 4 — amplify
    "ProbeStep",
    "adaptive_call_log",
    "clear_adaptive_log",
    "execute_adaptive_probe",
    "plan_probe_bundle",
    "record_planned_bundle",
    # iter-26.8 — stealth payload guidance
    "stealth_addendum_for",
    # iter-29.1 — endpoint classifier (foundation for shape-aware exploitation)
    "EndpointProfile",
    "classify_endpoint",
    "classify_endpoints_batch",
    # iter-29.2 — baseline-and-diff verifier
    "DiffSignal",
    "diff_responses",
    "fire_and_diff",
    "score_signal",
    # iter-29.3 — shape-aware payload bins
    "PayloadBin",
    "bin_for",
    "bin_object_for",
    "list_available_combinations",
    # iter-29.5 — PoC validator
    "CONFIDENCE_DISMISSED",
    "CONFIDENCE_LIKELY",
    "CONFIDENCE_SUSPECTED",
    "CONFIDENCE_VERIFIED",
    "PocVerification",
    "verify_finding",
    # iter-29.9 — safety guards
    "RateLimitGovernor",
    "check_destructive",
    "destructive_ok",
    "get_governor",
    "is_destructive_endpoint",
]
