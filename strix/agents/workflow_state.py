"""Pentesting workflow state machine (Phase 3d / PR-α).

Closes the architectural gap diagnosed from the Altoro Mutual
13%-recall benchmark: the single-lead architecture asks the LLM to
maintain a multi-phase pentesting workflow (recon → auth → re-crawl
→ probe → correlate → report) entirely in its head, via 6000+
characters of system prompt directives. Empirically, Gemini Flash
doesn't follow them; even stronger models tune the directives out
by turn 30 once the conversation history compresses.

The fix is to move workflow structure from prompt-text into
**enforced state**: a 6-phase state machine that

  * pins the current phase as a structured fact in security_context
  * surfaces a `workflow_status()` snapshot the lead can query each turn
  * gates `finish_scan` on phase == REPORT (with `force=True` override)
  * lets `tool_catalog.py` filter the lead's tool surface by phase
    (probe tools hidden during recon, recon tools hidden during probe)
  * records auto-transitions when entry conditions are met (no
    LLM judgment required to advance the workflow)

The state machine is a process-global singleton, like
`security_context` — every tool that wants to record progress
(endpoint discovered, auth captured, finding emitted) calls into
this module. The lead's LLM calls a thin tool wrapper that
reads/writes the same state.

## Phases (canonical order)

```
recon → auth_attempt → post_auth_recon → probe → chain_correlation → report
              |              |
              |              └─ skipped if recon didn't find a login form
              └─ skipped if scan_auth_flow failed (no captured session)
```

## Why a state machine vs. more prompt

The structural argument from `docs/proposals/phase-3d-architecture.md`
(coming):

  * **Prompts are aspirational, code is enforcing.** A directive
    that says "after finding a login form, try defaults" is a hint
    the model may or may not act on. A tool catalog that HIDES the
    probe tools until auth_attempt completes is enforcement.
  * **Smaller models become viable when structure is in the system.**
    Gemini Flash matches Claude on tactical decisions ("which tool
    fits this endpoint shape?") but loses on multi-step protocol
    reasoning. Phase-locked tool subsets reduce the per-turn
    cognitive load to a tactical decision.
  * **Phase boundaries are the senior-pentester model.** A real
    pentester doesn't decide "should I be in recon or probing
    mode?" — their tooling enforces the phase. Burp's Active Scan
    refuses to scan endpoints not in the sitemap.

## Kill switch

`STRIX_WORKFLOW_DISABLED=1` reverts to free-form mode (any tool
at any time, no phase gates). The workflow_state singleton is
still populated for telemetry but no enforcement fires.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Literal


logger = logging.getLogger(__name__)


Phase = Literal[
    "recon",
    "auth_attempt",
    "post_auth_recon",
    "probe",
    "chain_correlation",
    "report",
]

PHASES: tuple[Phase, ...] = (
    "recon",
    "auth_attempt",
    "post_auth_recon",
    "probe",
    "chain_correlation",
    "report",
)


# ---------------------------------------------------------------------------
# Data class — the workflow state itself
# ---------------------------------------------------------------------------


@dataclass
class _PhaseEntry:
    """One row in the phase-history audit log."""
    phase: Phase
    entered_at: float                       # monotonic seconds
    exited_at: float | None = None
    reason: str = ""


@dataclass
class WorkflowState:
    """Process-singleton holding the current workflow state.

    Mutators MUST be called via the module-level helpers below
    (which acquire the lock); fields are accessed directly only
    by `snapshot()` which builds a defensive copy under the lock.
    """

    # Phase tracking
    current_phase: Phase = "recon"
    phase_history: list[_PhaseEntry] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)

    # Recon outputs (drive auth/probe phase gates)
    endpoints_discovered: set[str] = field(default_factory=set)
    login_forms_found: list[str] = field(default_factory=list)
    tech_stack_fingerprinted: bool = False

    # Auth state (drives post_auth_recon → probe gating)
    auth_attempted: bool = False
    auth_state_captured: bool = False
    captured_auth_labels: list[str] = field(default_factory=list)

    # Post-auth recon outputs
    post_auth_endpoints_discovered: set[str] = field(default_factory=set)

    # Probe progress
    endpoints_probed: set[str] = field(default_factory=set)
    findings_emitted: int = 0

    # Chain correlation
    chains_emitted: int = 0

    # Initial seed — the first phase entry is `recon` from time-zero.
    def __post_init__(self) -> None:
        if not self.phase_history:
            self.phase_history.append(
                _PhaseEntry(phase="recon", entered_at=self.started_at)
            )


# ---------------------------------------------------------------------------
# Module-level singleton + lock
# ---------------------------------------------------------------------------


_STATE: WorkflowState | None = None
_LOCK = threading.Lock()


def _get_or_create() -> WorkflowState:
    global _STATE
    if _STATE is None:
        _STATE = WorkflowState()
    return _STATE


def reset_for_testing() -> None:
    """Clear the singleton. Tests call this in fixtures."""
    global _STATE
    with _LOCK:
        _STATE = None


def is_workflow_disabled() -> bool:
    """Kill switch — `STRIX_WORKFLOW_DISABLED=1` opts out of
    workflow enforcement. State is still populated for telemetry
    but no phase gates fire."""
    return os.environ.get(
        "STRIX_WORKFLOW_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Recorders — tools call these to advance the workflow's view of progress
# ---------------------------------------------------------------------------


def record_endpoint_discovered(url: str) -> None:
    """Recon outputs feed this. Idempotent; case-preserving set."""
    if not url or not isinstance(url, str):
        return
    with _LOCK:
        s = _get_or_create()
        if s.current_phase in ("post_auth_recon",):
            s.post_auth_endpoints_discovered.add(url)
        else:
            s.endpoints_discovered.add(url)
    # PR-γ — progress signal. Watchdog import is lazy + best-effort
    # so a missing/broken watchdog never blocks the recorder.
    try:
        from strix.agents.progress_watchdog import record_progress
        record_progress("endpoint.discovered", url[:120])
    except Exception:  # noqa: BLE001
        pass


def record_login_form_found(url: str) -> None:
    """Recon: a login form was discovered. Triggers the
    auth_attempt phase gate."""
    if not url or not isinstance(url, str):
        return
    with _LOCK:
        s = _get_or_create()
        if url not in s.login_forms_found:
            s.login_forms_found.append(url)


def record_tech_stack_fingerprinted() -> None:
    """Recon: the lead has fingerprinted the tech stack. Used as
    a soft signal that recon has produced something useful."""
    with _LOCK:
        _get_or_create().tech_stack_fingerprinted = True


def record_auth_attempt(*, captured: bool, label: str | None = None) -> None:
    """scan_auth_flow / try_default_credentials calls this. When
    `captured` is True, the post_auth_recon phase becomes
    reachable."""
    with _LOCK:
        s = _get_or_create()
        s.auth_attempted = True
        if captured:
            s.auth_state_captured = True
            if label and label not in s.captured_auth_labels:
                s.captured_auth_labels.append(label)
    if captured:
        try:
            from strix.agents.progress_watchdog import record_progress
            record_progress("auth.captured", label or "default")
        except Exception:  # noqa: BLE001
            pass


def record_endpoint_probed(url: str) -> None:
    """Probe phase: a specialist (or composite probe) finished
    against this endpoint. Used to compute probe-phase
    completion percentage."""
    if not url or not isinstance(url, str):
        return
    with _LOCK:
        _get_or_create().endpoints_probed.add(url)
    try:
        from strix.agents.progress_watchdog import record_progress
        record_progress("endpoint.probed", url[:120])
    except Exception:  # noqa: BLE001
        pass


def record_finding_emitted() -> None:
    """Increments the finding counter so workflow_status() shows
    the lead a quick "you've found N things" feedback."""
    with _LOCK:
        _get_or_create().findings_emitted += 1
    try:
        from strix.agents.progress_watchdog import record_progress
        record_progress("finding.created", "")
    except Exception:  # noqa: BLE001
        pass


def record_chain_emitted() -> None:
    """correlate_findings -> chain_correlation phase progress."""
    with _LOCK:
        _get_or_create().chains_emitted += 1


# ---------------------------------------------------------------------------
# Phase transitions
# ---------------------------------------------------------------------------


def _validate_transition(
    current: Phase, target: Phase, state: WorkflowState,
) -> tuple[bool, str]:
    """Phase-transition predicates. Returns `(allowed, reason)`.

    The reason string is informational — used by callers to
    surface why a transition was rejected (so the lead can adjust
    rather than getting an opaque error)."""
    if target == current:
        return True, "already in this phase"
    if target not in PHASES:
        return False, f"unknown phase: {target!r}"

    cur_idx = PHASES.index(current)
    tgt_idx = PHASES.index(target)

    # Backwards transitions are allowed (rare: e.g. discovering a
    # new endpoint during probe-phase triggers a return to recon
    # to crawl it). We don't enforce monotonic forward motion.
    if tgt_idx <= cur_idx:
        return True, "backwards transition (re-entry)"

    # Forward transitions — guard each gate.
    if target == "auth_attempt":
        if not state.login_forms_found:
            return False, (
                "no login form discovered — cannot enter auth_attempt. "
                "Continue recon until a login surface is found, or "
                "skip directly to `probe`."
            )
    elif target == "post_auth_recon":
        if not state.auth_state_captured:
            return False, (
                "no auth state captured — cannot enter post_auth_recon. "
                "Either try more default-cred combinations, or skip "
                "to `probe` for unauth-only coverage."
            )
    elif target == "probe":
        # Probe is always reachable from recon/auth — no gate
        # beyond "at least one endpoint discovered."
        if not state.endpoints_discovered and not state.post_auth_endpoints_discovered:
            return False, (
                "no endpoints discovered — recon hasn't produced "
                "anything probable yet. Continue recon."
            )
    elif target == "chain_correlation":
        # Allow at any probe progress — chains can be useful even
        # with one finding (single-category chains are still
        # informative for the report).
        if state.findings_emitted == 0:
            return False, (
                "no findings emitted — chain_correlation is a no-op "
                "with zero findings. Probe more endpoints, or "
                "advance directly to `report`."
            )
    elif target == "report":
        # Report is the terminal phase. No prerequisites — the
        # lead can always decide it's done. `finish_scan`'s own
        # guards (force=True override) handle the "are you sure"
        # case.
        pass

    return True, "ok"


def advance_phase(
    target: Phase, *, reason: str = "", force: bool = False,
) -> tuple[bool, str]:
    """Move the workflow to `target` phase.

    Returns `(transitioned, message)`. `transitioned=False` means
    the gate refused (look at `message` for why); `force=True`
    bypasses the gate.
    """
    if target not in PHASES:
        return False, f"unknown phase: {target!r}"

    with _LOCK:
        s = _get_or_create()
        current = s.current_phase

        if not force:
            allowed, why = _validate_transition(current, target, s)
            if not allowed:
                return False, why

        if target == current:
            return True, "already in this phase"

        # Close the current entry + open a new one.
        now = time.monotonic()
        if s.phase_history:
            s.phase_history[-1].exited_at = now
        s.phase_history.append(_PhaseEntry(
            phase=target, entered_at=now, reason=reason,
        ))
        s.current_phase = target

    logger.info(
        "workflow phase: %s → %s (%s)",
        current, target, reason or "no reason given",
    )
    try:
        from strix.agents.progress_watchdog import record_progress
        record_progress("phase.transitioned", f"{current}->{target}")
    except Exception:  # noqa: BLE001
        pass
    return True, "ok"


def get_current_phase() -> Phase:
    """Fast accessor for the current phase. Doesn't lock — phase
    reads are racy-but-OK (the worst that happens is a tool gate
    sees a stale phase for one round-trip)."""
    s = _STATE
    return s.current_phase if s is not None else "recon"


# ---------------------------------------------------------------------------
# Snapshot for the lead's `workflow_status()` tool
# ---------------------------------------------------------------------------


def snapshot() -> dict:
    """Build the structured snapshot the lead reads each turn.

    This is the **primary surface** for the lead to know what
    phase it's in and what's left to do. Instead of relying on
    the lead to remember "have I tried auth?", the lead calls
    `workflow_status()` and sees the answer in the response.
    """
    with _LOCK:
        s = _get_or_create()
        all_endpoints = s.endpoints_discovered | s.post_auth_endpoints_discovered
        unprobed = sorted(all_endpoints - s.endpoints_probed)
        probed_pct = (
            len(s.endpoints_probed) / len(all_endpoints)
            if all_endpoints else 0.0
        )
        elapsed = time.monotonic() - s.started_at

        next_actions = _suggest_next_actions(s)

        # Phase-completion gates surfaced explicitly so the lead
        # can see WHICH prerequisite is blocking.
        gates = {
            "recon_has_endpoints": bool(all_endpoints),
            "recon_found_login_form": bool(s.login_forms_found),
            "auth_attempted": s.auth_attempted,
            "auth_state_captured": s.auth_state_captured,
            "probe_coverage_pct": round(probed_pct * 100, 1),
            "findings_emitted": s.findings_emitted,
        }

        return {
            "current_phase": s.current_phase,
            "phase_history": [
                {
                    "phase": e.phase,
                    "entered_at": round(e.entered_at - s.started_at, 2),
                    "exited_at": (
                        round(e.exited_at - s.started_at, 2)
                        if e.exited_at is not None else None
                    ),
                    "duration_s": (
                        round((e.exited_at or time.monotonic()) - e.entered_at, 2)
                    ),
                    "reason": e.reason,
                }
                for e in s.phase_history
            ],
            "elapsed_s": round(elapsed, 2),
            "endpoints_discovered_count": len(s.endpoints_discovered),
            "post_auth_endpoints_discovered_count": len(
                s.post_auth_endpoints_discovered,
            ),
            "endpoints_probed_count": len(s.endpoints_probed),
            "unprobed_endpoints_sample": unprobed[:10],
            "login_forms_found": list(s.login_forms_found),
            "auth_state_captured": s.auth_state_captured,
            "captured_auth_labels": list(s.captured_auth_labels),
            "findings_emitted": s.findings_emitted,
            "chains_emitted": s.chains_emitted,
            "gates": gates,
            "next_recommended_actions": next_actions,
            "workflow_disabled": is_workflow_disabled(),
        }


def _suggest_next_actions(s: WorkflowState) -> list[str]:
    """Compute 1-3 recommended next actions based on the current
    phase and gate state. Surfaces the workflow's expectation of
    what the lead should do next, without relying on the lead to
    infer it from the prompt directives."""
    out: list[str] = []
    phase = s.current_phase
    if phase == "recon":
        if not s.endpoints_discovered:
            out.append(
                "Continue recon — no endpoints discovered yet. Try "
                "`bfs_crawl` / `webapp_recon_pipeline` / `list_sitemap`."
            )
        elif s.login_forms_found and not s.auth_attempted:
            out.append(
                f"A login form was found at {s.login_forms_found[0]!r}. "
                f"`advance_workflow_phase('auth_attempt')` then call "
                f"`scan_auth_flow` with default-cred corpus."
            )
        else:
            out.append(
                f"{len(s.endpoints_discovered)} endpoint(s) discovered. "
                "When recon is reasonably complete, "
                "`advance_workflow_phase('probe')`."
            )
    elif phase == "auth_attempt":
        if not s.auth_attempted:
            out.append(
                "Call `scan_auth_flow` on the discovered login form(s) "
                "with the default-cred corpus."
            )
        elif s.auth_state_captured:
            out.append(
                "Auth captured. `advance_workflow_phase('post_auth_recon')` "
                "and re-crawl with the captured session."
            )
        else:
            out.append(
                "Auth attempted but no session captured. "
                "`advance_workflow_phase('probe')` to continue with "
                "unauth-only coverage."
            )
    elif phase == "post_auth_recon":
        out.append(
            "Re-crawl using `send_request` / `browser_action` / "
            "`webapp_recon_pipeline` WITH the captured session. New "
            "endpoints will populate post_auth_endpoints_discovered."
        )
    elif phase == "probe":
        all_eps = s.endpoints_discovered | s.post_auth_endpoints_discovered
        unprobed = sorted(all_eps - s.endpoints_probed)
        if unprobed:
            out.append(
                f"{len(unprobed)} unprobed endpoint(s) remain. Fan out "
                f"specialists per endpoint shape (scan_sqli + scan_xss + "
                f"csrf_check / scan_idor / etc.)."
            )
        else:
            out.append(
                "All discovered endpoints probed. "
                "`advance_workflow_phase('chain_correlation')` to emit "
                "finding chains, then 'report'."
            )
    elif phase == "chain_correlation":
        out.append(
            "Call `correlate_findings` to emit the cross-category "
            "chains, then `advance_workflow_phase('report')`."
        )
    elif phase == "report":
        out.append("Call `finish_scan` with the executive summary.")

    return out


# ---------------------------------------------------------------------------
# Phase → tool category mapping (for tool_catalog.py phase filtering)
# ---------------------------------------------------------------------------


# Tools that are appropriate in EVERY phase — coordination,
# emission, threat-intel, reasoning, the workflow tools themselves.
_PHASE_AGNOSTIC_TOOLS: frozenset[str] = frozenset({
    # Workflow control (must always be reachable to advance phases)
    "workflow_status", "advance_workflow_phase",
    # PR-β — composite probe fan-out. Lives in the probe phase
    # primarily but also useful in post_auth_recon for quick
    # validation; phase-agnostic to give the lead the lowest
    # cognitive-load path.
    "probe_endpoint",
    # Coordination
    "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
    "list_active_hypotheses", "is_surface_under_investigation",
    "agent_self_audit",
    # Findings (lead can emit at any time once evidence is in hand)
    "create_vulnerability_report", "update_finding", "dismiss_finding",
    "check_budget",
    # Threat intel — always allowed (read-only)
    "cve_lookup", "nvd_lookup", "lookup_known_cves", "lookup_cve_by_id",
    "list_actively_exploited_cves", "threat_intel_status",
    # Reasoning / notes / scratchpad
    "think", "create_note", "list_notes", "get_note",
    "update_note", "delete_note",
    # Cross-category emission (run before finish, but allowed any time)
    "correlate_findings", "emit_compliance_evidence",
})


# Phase-specific tool surface. These are the tools that
# semantically belong to a phase. The lead's catalog is the
# intersection of (target_type tools) ∩ (phase tools ∪ agnostic).
_PHASE_TOOLS: dict[Phase, frozenset[str]] = {
    "recon": frozenset({
        # Crawl + sitemap + tech-stack
        "fingerprint_tech_stack", "bfs_crawl", "well_known_harvest",
        "webapp_recon_pipeline", "extract_dom", "list_sitemap",
        # HTTP primitives (recon makes baseline requests)
        "send_request", "browser_action",
        # HAR / Burp ingestion (alternative recon paths)
        "ingest_har_file", "ingest_burp_file",
        # Domain / IP recon (for non-web targets)
        "domain_recon_pipeline", "subdomain_enum_tool",
        "dns_hygiene_check", "passive_dns_history",
        "org_fingerprint", "discover_cloud_assets",
        "reverse_ip", "mail_recon", "saas_leaks",
        # Source maps + secrets-in-response are recon-y
        "source_maps", "scan_secrets_in_response",
        # Code recon
        "build_code_map", "sbom_extract", "secrets_scan",
        "terminal_execute",
        # SCA / SAST / IaC produce static findings from artefacts —
        # treat as recon-phase outputs.
        "scan_sca_lockfiles", "scan_sast", "scan_iac",
    }),
    "auth_attempt": frozenset({
        # Auth-focused specialists + HTTP primitives to drive them
        "scan_auth_flow", "scan_multi_role_auth",
        "send_request", "browser_action",
        # Cookie / JWT inspection
        "cookie_jwt_scoping_check", "jwt_audit",
        # Session entropy + CSRF (initial auth analysis)
        "session_entropy_check",
    }),
    "post_auth_recon": frozenset({
        # Same recon tools, used with captured session
        "bfs_crawl", "webapp_recon_pipeline", "extract_dom",
        "list_sitemap",
        "send_request", "browser_action",
        # Authed-IDOR precondition probing
        "scan_multi_role_auth",
    }),
    "probe": frozenset({
        # All active specialists fan out here
        "scan_xss", "scan_sqli", "scan_xxe",
        "scan_blind_ssrf", "scan_deserialization",
        "scan_blind_cmd_injection", "scan_oob_xxe",
        "scan_business_logic", "scan_idor",
        "scan_oauth", "scan_request_smuggling_active",
        "scan_ldap_injection", "scan_xpath_injection",
        "scan_cmd_injection", "scan_nosql_injection",
        "scan_ssti", "scan_path_traversal", "scan_ssrf",
        "scan_subdomain_takeover_active",
        "scan_misconfig",
        "scan_nuclei_templates",
        "scan_response_anomaly", "scan_timing_oracle",
        # Deterministic checks
        "http_security_headers_audit", "tls_audit",
        "csrf_check", "cors_deep_check",
        "open_redirect_check", "request_smuggling_check",
        "race_check", "sqli_check", "graphql_specialist_check",
        "websocket_audit", "authz_matrix_check",
        "dom_xss_static_probe",
        # Mutation / replay
        "replay_mutation_on_endpoints",
        "replay_mutation_from_har_file",
        "replay_mutation_from_burp_file",
        # HTTP primitives — needed to follow up specialist hits
        "send_request", "browser_action",
        # Threat-intel lookups (specific to findings)
        "vt_reputation", "greynoise_classify", "domain_rep",
    }),
    "chain_correlation": frozenset({
        # `correlate_findings` is already in the agnostic set —
        # we just keep this phase's surface tight so the lead
        # focuses on chain emission.
        "send_request", "browser_action",
    }),
    "report": frozenset({
        # Only the finishing tool surface
        "finish_scan",
    }),
}


def allowed_tools_for_phase(phase: Phase | None = None) -> set[str]:
    """Return the union of (phase-specific tools, agnostic tools)
    for the given phase. None / unknown phase → return everything
    (phase filtering disabled). Caller intersects with the
    target-type catalog."""
    if phase is None:
        # Disabled — return a sentinel that the caller should treat
        # as "no phase filtering."
        return set()
    if phase not in _PHASE_TOOLS:
        return set()
    return set(_PHASE_AGNOSTIC_TOOLS) | set(_PHASE_TOOLS[phase])


def list_phases() -> list[Phase]:
    """List all canonical phase names."""
    return list(PHASES)
