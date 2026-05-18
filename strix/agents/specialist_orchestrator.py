"""Fresh-context specialist orchestration (§1 of strixredteam.md).

The architectural shift: specialists run in their OWN bounded LLM
loops with fresh conversation history, not in the lead's saturated
context. Lead becomes a pure orchestrator — its catalog is reduced
to `dispatch_specialist`, workflow management, hypothesis tracking,
and finish_scan. The lead never sees raw tool output from probes;
it sees structured `SpecialistResult`-shaped returns.

## What this addresses

The Phase 3d work (PR-α / PR-β) confirmed the single-lead
architecture's primary failure: context saturation. After ~50 tool
calls the lead's conversation is dominated by stale recon output,
verification quality drifts, and the model forgets what it
already tried.

Decepticon's answer (per `strixredteam.md` §1): orchestrator with
`tools=[]`. Every objective dispatched via `task()` to a sub-agent
that boots with a CLEAN context window seeded only with: (a) the
objective, (b) the scope file, (c) relevant prior findings, (d)
its skill bundle.

This module is the MVP of that architecture for strix. Not the
full agents-graph machinery (which carries legacy parent-child
message-passing baggage from incident #147), but a tight
`dispatch_specialist()` that:

  1. Builds a fresh LLM client (NEW conversation, no inheritance)
  2. Seeds it with a category-specific system prompt
  3. Runs an inner agent loop bounded to N iterations (default 50)
  4. Exits when: specialist calls `complete_objective`, max
     iterations hit, or the specialist's budget is exhausted
  5. Returns structured result — findings count, status, summary

## Relationship to Phase 3b

Phase 3b (`strix/tools/specialist/llm_orchestrator.py`) was a
"one adaptive retry" pattern: procedural probe → 0 findings → one
LLM call to suggest adapted args → procedural probe again.

This module (§1) is the multi-round generalisation: procedural
probe is just ONE of the tools the specialist's bounded inner-LLM
can call. The loop continues until the specialist itself decides
it's done (`complete_objective`) or hits the iteration cap.

Phase 3b stays in place for the deterministic specialists; §1's
dispatch wraps the same specialists in a longer-running loop
when the lead's orchestrator decides multi-round depth is
warranted.

## Kill switch

`STRIX_ORCHESTRATOR_MODE` is OPT-IN, not the default. Set to
`true` / `1` / `yes` to enable. When unset (the default), the
lead's catalog is unchanged from PR #229's single-lead behaviour.

## v0 limitations (documented for follow-ups)

* Synchronous dispatch only — no parallel specialist execution.
  v1 could add asyncio.gather for independent specialists.
* Specialist context doesn't include the KG (§3) yet — when §3
  ships, the system-prompt seed should pull relevant prior
  findings from the KG instead of just the workflow snapshot.
* Per-specialist iteration cap is global (default 50). v1 could
  read from the specialist profile's `default_budget`.
* No checkpoint / resume — if the orchestrator's parent process
  dies mid-dispatch, the specialist's partial work is lost.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config + state
# ---------------------------------------------------------------------------


DEFAULT_MAX_ITERATIONS: int = 50
"""Per-specialist iteration cap. Decepticon uses 50-80; we default
to the lower bound since each specialist is bounded to one
objective. Override via `STRIX_SPECIALIST_MAX_ITERATIONS`."""


def get_max_iterations() -> int:
    raw = (os.environ.get("STRIX_SPECIALIST_MAX_ITERATIONS") or "").strip()
    if not raw:
        return DEFAULT_MAX_ITERATIONS
    try:
        return max(1, int(float(raw)))
    except (ValueError, TypeError):
        return DEFAULT_MAX_ITERATIONS


def is_orchestrator_mode_enabled() -> bool:
    """Returns True when STRIX_ORCHESTRATOR_MODE is set to
    a truthy value. Opt-in default-off because this is a real
    architectural change; wrappers should validate per-target
    before flipping."""
    return os.environ.get(
        "STRIX_ORCHESTRATOR_MODE", ""
    ).lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Scan-mode dispatch gate (phase 1 of cost-optimization proposal)
# ---------------------------------------------------------------------------
#
# `--scan-mode quick|standard|deep` used to be a prompt-level nudge only —
# it picked the skill body that landed in the system prompt and bumped
# reasoning_effort. Every other phase (specialist dispatch, recon depth,
# verification) was identical across modes, so a `quick` run cost the
# same order of magnitude as `deep`. The dispatch loop is the single
# largest cost multiplier (~60-70% of total spend on `standard`), so
# capping N at the dispatch boundary is the highest-leverage knob.
#
# See docs/proposals/2026-05-19-scan-mode-cost-optimization.md.

# Per-mode dispatch caps. `None` = unbounded; `0` = no dispatches allowed
# at all (deterministic specialists only — the fresh-context loop is
# skipped entirely).
_SCAN_MODE_DISPATCH_CAP: dict[str, int | None] = {
    "initial": 0,
    "quick": 0,
    "standard": 8,
    "deep": None,
}


def get_scan_mode_dispatch_cap() -> int | None:
    """Return the per-run dispatch_specialist cap derived from the
    active scan mode. `STRIX_DISPATCH_CAP_OVERRIDE` short-circuits
    the mode-derived value when the wrapper needs an explicit budget.

    Returns:
      int — the max number of dispatch_specialist calls that may
        execute this run. After this many, further dispatches
        short-circuit to DENIED_BY_SCAN_MODE.
      None — unbounded (default for `deep`).
    """
    raw_override = (os.environ.get("STRIX_DISPATCH_CAP_OVERRIDE") or "").strip()
    if raw_override:
        try:
            v = int(float(raw_override))
            return max(0, v)
        except (ValueError, TypeError):
            pass
    mode = (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower()
    if mode in _SCAN_MODE_DISPATCH_CAP:
        return _SCAN_MODE_DISPATCH_CAP[mode]
    # Unknown / unset mode — default to `deep` semantics (unbounded)
    # so we never silently throttle a run that didn't opt in.
    return None


# Process-global dispatch counter. Reset between scans via
# `reset_dispatch_counter()` (called from `reset_for_testing` and
# at scan-config boot in cli.py / tui.py).
_DISPATCH_COUNT: int = 0


def reset_dispatch_counter() -> None:
    """Reset the per-run dispatch_specialist counter to zero.
    Called at scan boot and from tests."""
    global _DISPATCH_COUNT
    _DISPATCH_COUNT = 0


def get_dispatch_count() -> int:
    """Read the current dispatch counter — exposed for telemetry
    and tests."""
    return _DISPATCH_COUNT


# ---------------------------------------------------------------------------
# Per-category specialist profiles
# ---------------------------------------------------------------------------


@dataclass
class SpecialistDispatchProfile:
    """Configuration for one specialist category. Used by
    `dispatch_specialist` to scope the fresh-context loop.

    Attributes:
      category: matches a `_TOOLS_BY_TARGET_TYPE` category in
        `tool_catalog.py` or a specialist tool name.
      system_prompt_addendum: scope-specific instructions
        prepended to the specialist's system prompt. Should be
        ~200-400 words — the inner LLM is bounded, so brevity
        matters.
      allowed_tool_subset: tool names the specialist may invoke.
        Heavily filtered vs the full catalog — a SQLi specialist
        doesn't need scan_xss; a Verifier doesn't need recon
        tools. Empty list → use category's full surface.
      max_iterations: per-spawn iteration cap. Defaults to
        `get_max_iterations()` (env-configurable).
      max_cost_usd: per-spawn LLM cost cap. None → inherit from
        run-level `--max-cost`.
      recommended_skills: Phase 1C — skill names from
        `strix/skills/vulnerabilities/` (or other categories) that
        the dispatched specialist should boot with. Loaded via
        `strix.skills.load_skills` and injected into the
        fresh-context system prompt. Empty list → no skill
        injection (the specialist runs on its addendum + scope
        only). The names are filename stems, not display names
        (e.g. `sql_injection`, `saml_xsw`).
    """
    category: str
    system_prompt_addendum: str
    allowed_tool_subset: list[str] = field(default_factory=list)
    max_iterations: int | None = None
    max_cost_usd: float | None = None
    recommended_skills: list[str] = field(default_factory=list)


# Built-in profiles for the common specialist categories. The
# orchestrator's `dispatch_specialist(category=...)` looks up the
# profile by category name; unknown categories fall through to a
# generic profile.
_PROFILES: dict[str, SpecialistDispatchProfile] = {
    "sqli": SpecialistDispatchProfile(
        category="sqli",
        system_prompt_addendum=(
            "You are a bounded SQLi specialist. Your objective is "
            "to determine whether the target endpoint is vulnerable "
            "to SQL injection. Probe systematically — try multiple "
            "payload contexts (string, numeric, boolean, time-based, "
            "OOB), observe responses, adapt your approach. When you "
            "have credible evidence (SQL error / boolean diff / "
            "timing oracle), emit via `create_vulnerability_report` "
            "and call `complete_objective(status='PASSED')`. If you "
            "exhaust productive probes without finding anything, "
            "call `complete_objective(status='BLOCKED', "
            "reason='...')`."
        ),
        allowed_tool_subset=[
            "scan_sqli", "send_request", "think",
            "create_vulnerability_report", "complete_objective",
            "cve_lookup",
        ],
        max_cost_usd=0.30,
        recommended_skills=["sql_injection"],
    ),
    "xss": SpecialistDispatchProfile(
        category="xss",
        system_prompt_addendum=(
            "You are a bounded XSS specialist. Your objective is "
            "to determine reflected / DOM XSS on the target. "
            "Probe systematically — different param contexts (HTML "
            "body, attribute, JS string, URL), different payload "
            "shapes, different content-types. When you observe "
            "unescaped reflection of your payload, emit via "
            "`create_vulnerability_report` and "
            "`complete_objective(status='PASSED')`. If you exhaust "
            "productive probes, call "
            "`complete_objective(status='BLOCKED', reason='...')`."
        ),
        allowed_tool_subset=[
            "scan_xss", "send_request", "browser_action", "think",
            "create_vulnerability_report", "complete_objective",
        ],
        max_cost_usd=0.30,
        recommended_skills=["xss"],
    ),
    "idor": SpecialistDispatchProfile(
        category="idor",
        system_prompt_addendum=(
            "You are a bounded IDOR specialist. You need TWO auth "
            "states to do meaningful cross-session diffs. If only "
            "one auth state is captured, call "
            "`complete_objective(status='BLOCKED', "
            "reason='need_second_session')`. Otherwise probe "
            "ID-bearing endpoints with both sessions, look for "
            "cross-tenant reads, and emit findings via "
            "`create_vulnerability_report`."
        ),
        allowed_tool_subset=[
            "scan_idor", "scan_multi_role_auth", "send_request",
            "think", "create_vulnerability_report",
            "complete_objective",
        ],
        max_cost_usd=0.40,
        recommended_skills=["idor", "broken_function_level_authorization"],
    ),
    "recon": SpecialistDispatchProfile(
        category="recon",
        system_prompt_addendum=(
            "You are a bounded recon specialist. Your objective is "
            "to enumerate the target's attack surface — endpoints, "
            "auth shapes, tech-stack fingerprints. You do NOT "
            "probe for vulnerabilities. Emit each discovered "
            "endpoint as a workflow signal, and call "
            "`complete_objective(status='PASSED')` when you've "
            "exhausted obvious surfaces. Don't crawl forever."
        ),
        allowed_tool_subset=[
            "webapp_recon_pipeline", "bfs_crawl", "list_sitemap",
            "fingerprint_tech_stack", "send_request",
            "browser_action", "extract_dom", "think",
            "complete_objective",
        ],
        max_cost_usd=0.20,
        recommended_skills=[
            "asset_discovery_pipeline",
            "subdomain_strategy",
        ],
    ),
    "auth": SpecialistDispatchProfile(
        category="auth",
        system_prompt_addendum=(
            "You are a bounded auth specialist. Your objective is "
            "to capture a working session via default + tenant-"
            "supplied credentials, OR determine that no valid creds "
            "are obtainable. On success, the captured session is "
            "recorded into security_context for downstream "
            "specialists. Call `complete_objective(status='PASSED')` "
            "on session capture or `'BLOCKED'` after exhausting "
            "the credential corpus."
        ),
        allowed_tool_subset=[
            "scan_auth_flow", "send_request", "think",
            "complete_objective", "create_vulnerability_report",
        ],
        max_cost_usd=0.25,
        recommended_skills=["authentication_jwt", "oauth_oidc"],
    ),
    "generic": SpecialistDispatchProfile(
        category="generic",
        system_prompt_addendum=(
            "You are a bounded specialist working on a focused "
            "objective. Probe systematically, emit findings via "
            "`create_vulnerability_report` when you have credible "
            "evidence, and call `complete_objective(status=...)` "
            "to return control to the orchestrator. Avoid "
            "scope creep — stay on the assigned objective."
        ),
        max_cost_usd=0.30,
    ),
    "patcher": SpecialistDispatchProfile(
        category="patcher",
        system_prompt_addendum=(
            "You are a bounded Patcher specialist. Your objective: "
            "given a verified VULNERABILITY finding, craft a minimal "
            "fix, propose it, optionally apply it, then verify it.\n\n"
            "Mandatory flow:\n"
            "  1. Use `get_objective` / `list_objectives` to read "
            "     the linked objective if one was provided. Use the "
            "     finding's evidence + code_locations to understand "
            "     the bug.\n"
            "  2. For code-bearing findings (SAST / SCA / has "
            "     `code_locations` field): read the file, write a "
            "     unified-diff that fixes the root cause (parameterised "
            "     query, output-escape, allowlist check, etc.). The "
            "     diff must be MINIMAL — no unrelated formatting, "
            "     no new abstractions, no doc changes.\n"
            "  3. For DAST findings (no source available): write the "
            "     diff as the *recommended* shape and pass "
            "     `applied=False`. The fix lands when the customer "
            "     applies it to their codebase.\n"
            "  4. Call `propose_patch(finding_id, diff, "
            "     commit_message, applied=<bool>)`. The patch_id is "
            "     returned in the response.\n"
            "  5. If you applied the diff: call "
            "     `auto_verify_patch(patch_id)`. This re-runs the "
            "     original detector against the (now-patched) target "
            "     and either:\n"
            "       - flips §4 finding to PATCHED (autofix held)\n"
            "       - or marks the patch `regressed` (rethink + new "
            "     proposal)\n"
            "       - or reports `manual_verification_required` "
            "     (fall back to `verify_patch(probe_result_still_fires=...)` "
            "     with your own re-run results)\n"
            "  6. Call `complete_objective(status='PASSED')` on "
            "     verified fix, or `complete_objective(status='BLOCKED', "
            "     reason='...')` if you can't make progress.\n\n"
            "Hard rules:\n"
            "  * Diff must be MINIMAL. No drive-by formatting.\n"
            "  * Commit messages are conventional-commit shape: "
            "    `fix(<scope>): <one-line summary>`.\n"
            "  * Never claim a patch is verified without an "
            "    `auto_verify_patch` or `verify_patch` PASSED result."
        ),
        allowed_tool_subset=[
            "propose_patch", "mark_patch_applied", "verify_patch",
            "auto_verify_patch", "list_patches",
            "verification_status",
            "list_objectives", "get_objective", "update_objective",
            "kg_query_nodes", "kg_query_paths",
            "str_replace_editor",
            "think", "complete_objective",
        ],
        max_cost_usd=0.50,
    ),
}


def get_profile(category: str) -> SpecialistDispatchProfile:
    """Look up a profile by category. Unknown categories fall
    through to the generic profile."""
    norm = (category or "").strip().lower()
    return _PROFILES.get(norm, _PROFILES["generic"])


def list_categories() -> list[str]:
    """Categories the orchestrator can dispatch. Excludes
    'generic' since it's a fallback."""
    return sorted(k for k in _PROFILES if k != "generic")


# ---------------------------------------------------------------------------
# Specialist result shape
# ---------------------------------------------------------------------------


@dataclass
class SpecialistRunResult:
    """Structured return from `dispatch_specialist`.

    Attributes:
      category: the dispatched specialist category
      objective: the objective string the orchestrator passed in
      status: PASSED | BLOCKED | ITERATION_CAP_REACHED |
        BUDGET_EXCEEDED | DENIED_BY_SCAN_MODE | CACHE_HIT_BLOCKED |
        ERROR — the exit reason. DENIED_BY_SCAN_MODE means the
        run-level dispatch cap (derived from --scan-mode) was
        exhausted; the lead should fall back to deterministic
        probes for this objective rather than retrying dispatch.
        CACHE_HIT_BLOCKED means a prior dispatch on a
        structurally-similar endpoint already returned BLOCKED
        with a no-signal reason — re-running would re-confirm
        the same negative; the lead should pivot to a different
        surface or category.
      reason: optional human-readable explanation, especially for
        BLOCKED / ERROR
      iterations_used: how many inner-LLM rounds the specialist ran
      findings_count: number of vulnerability reports the
        specialist emitted (read from tracer's delta)
      duration_s: wall-clock seconds the specialist ran
      summary: short string summary of what the specialist did
    """
    category: str
    objective: str
    status: str
    reason: str | None = None
    iterations_used: int = 0
    findings_count: int = 0
    duration_s: float = 0.0
    summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "objective": self.objective,
            "status": self.status,
            "reason": self.reason,
            "iterations_used": self.iterations_used,
            "findings_count": self.findings_count,
            "duration_s": round(self.duration_s, 2),
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Specialist exit signal
# ---------------------------------------------------------------------------


# Module-level signal — the specialist's `complete_objective` tool
# writes here; dispatch_specialist's inner loop polls it.
#
# This is a process-global like workflow_state. Tests reset it
# via `reset_for_testing`.
_SPECIALIST_EXIT: dict[str, Any] | None = None


def reset_for_testing() -> None:
    global _SPECIALIST_EXIT
    _SPECIALIST_EXIT = None
    reset_dispatch_counter()
    # v2 step 2 — clear the verdict cache between scans.
    try:
        from strix.agents.specialist_verdict_cache import (  # noqa: PLC0415
            reset as _verdict_cache_reset,
        )
        _verdict_cache_reset()
    except Exception:  # noqa: BLE001
        pass


def signal_specialist_complete(*, status: str, reason: str | None = None,
                                summary: str | None = None) -> None:
    """Called by the specialist's `complete_objective` tool to
    declare done. Sets the module-level signal that
    `dispatch_specialist`'s inner loop polls.

    Status values:
      PASSED — objective achieved (finding emitted or surface
        determined safe)
      BLOCKED — couldn't complete (missing prerequisite, scope
        boundary, etc.)
    """
    global _SPECIALIST_EXIT
    _SPECIALIST_EXIT = {
        "status": str(status or "PASSED").upper(),
        "reason": reason,
        "summary": summary,
    }


def get_specialist_exit_signal() -> dict[str, Any] | None:
    """Read + clear the exit signal. Returns None if no signal
    has been raised since the last reset."""
    global _SPECIALIST_EXIT
    sig = _SPECIALIST_EXIT
    _SPECIALIST_EXIT = None
    return sig


# ---------------------------------------------------------------------------
# Inner LLM loop
# ---------------------------------------------------------------------------


def _build_system_prompt(
    *, profile: SpecialistDispatchProfile, scope_context: str | None,
    relevant_findings: list[dict[str, Any]] | None,
    skills_override: list[str] | None = None,
) -> str:
    """Compose the specialist's system prompt — fresh, scope-
    bound, no inherited chat history.

    Four slots:
      1. The category-specific addendum (probe playbook)
      2. Phase 1C — paired skill bodies (auto-attached via
         `profile.recommended_skills`, or overridden by
         `skills_override`). Each skill body sits in its own
         labelled section so the bounded inner LLM can refer to
         it by name.
      3. The orchestrator's scope (target URL, exclusions, opsec
         level — minimal version of §7's scope.yml)
      4. A digest of relevant prior findings from the run (so the
         specialist can chain off them without re-running prior
         specialists' work)

    Args:
      profile: the category's dispatch profile.
      scope_context: target URL + exclusions string, or None.
      relevant_findings: prior-finding digest, or None.
      skills_override: when provided, replaces
        `profile.recommended_skills` for this call. Used by
        operators / tests who want to inject custom skill bundles
        without registering a new profile. Pass `[]` to suppress
        all skill injection.
    """
    parts = [profile.system_prompt_addendum]

    # Phase 1C — auto-attach paired skill bodies. Best-effort: a
    # missing skill name / unreadable file is logged and skipped;
    # the specialist boots without it rather than failing dispatch.
    skills_to_load = (
        skills_override
        if skills_override is not None
        else profile.recommended_skills
    )
    if skills_to_load:
        try:
            from strix.skills import load_skills

            bodies = load_skills(skills_to_load, loaded_by="orchestrator")
            for name, body in bodies.items():
                if not body or not body.strip():
                    continue
                parts.append(
                    f"\n\n---\nSKILL: {name}\n---\n{body.strip()}"
                )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "skill auto-attach failed for category=%s skills=%s: %s",
                profile.category, skills_to_load, e,
            )

    if scope_context:
        parts.append(
            f"\n\nSCOPE — this scan is constrained to:\n{scope_context}"
        )

    if relevant_findings:
        finding_lines = [
            f"- [{f.get('severity', '?')}] {f.get('title', '?')} on "
            f"{f.get('endpoint') or f.get('target', '?')}"
            for f in relevant_findings[:5]
        ]
        parts.append(
            "\n\nPRIOR FINDINGS in this run (handoff context):\n"
            + "\n".join(finding_lines)
        )

    parts.append(
        "\n\nEXIT PROTOCOL: call `complete_objective(status=..., "
        "reason=..., summary=...)` to return control to the "
        "orchestrator. Do NOT just stop responding — the "
        "orchestrator's loop blocks waiting for this signal."
    )

    return "\n".join(parts)


def _count_findings_emitted_during(
    *, before_count: int,
) -> int:
    """Read the tracer's current vulnerability_reports total and
    return the delta vs `before_count`. Used to attribute findings
    to a specific specialist spawn."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return 0
        return max(0, len(tracer.vulnerability_reports) - before_count)
    except Exception:  # noqa: BLE001
        return 0


def _resolve_relevant_findings(category: str) -> list[dict[str, Any]]:
    """Pull a small set of prior findings from the tracer that
    might be relevant to this specialist. v0 heuristic: return
    findings from related categories.

    When §3 (KG) ships, replace this with a proper graph query.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return []
        all_findings = list(tracer.vulnerability_reports or [])
    except Exception:  # noqa: BLE001
        return []

    # v0: just return up to 5 most-recent findings. The system
    # prompt slot caps at 5 anyway. v1 should filter by category
    # relationships (e.g. SQLi specialist should see prior auth
    # findings; XSS specialist should see prior CSP fingerprints).
    return all_findings[-5:]


def _resolve_scope_context() -> str | None:
    """Pull the run's scope from existing primitives — the
    target URL, exclude paths, rate limit, auth state. v1
    should read from `strix.scope.yml` once §7 ships."""
    try:
        from strix.agents.security_context import get_security_context
        sc = get_security_context()
    except Exception:  # noqa: BLE001
        return None

    parts = []
    if sc.target_url:
        parts.append(f"target: {sc.target_url}")
    if sc.tech_stack and sc.tech_stack.server:
        parts.append(f"tech_stack.server: {sc.tech_stack.server}")
    if sc.auth_states:
        labels = [a.label for a in sc.auth_states]
        parts.append(f"available_auth_states: {labels}")
    return "\n".join(parts) if parts else None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def dispatch_specialist(
    *,
    category: str,
    objective: str,
    target: str | None = None,
    max_iterations: int | None = None,
    max_cost_usd: float | None = None,
    skills_override: list[str] | None = None,
    inner_call_fn: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Spawn a bounded multi-round specialist run with fresh
    context. Returns a `SpecialistRunResult.to_dict()`.

    Args:
      category: specialist category (e.g. 'sqli', 'xss', 'idor',
        'recon', 'auth'). Looked up via `get_profile`.
      objective: the specific task the specialist should
        accomplish (e.g. "Verify SQLi on POST /login with default
        username/password fields").
      target: optional target URL — included in scope_context.
      max_iterations: override the profile / env default.
      max_cost_usd: override the profile / env default.
      skills_override: Phase 1C — when provided, replaces the
        profile's `recommended_skills` list for this call. Pass
        `[]` to suppress skill auto-attach entirely; pass a
        custom list to inject specific skill bundles (useful for
        custom-stack engagements). When `None` (default), the
        category's profile-defined skills auto-attach.
      inner_call_fn: TEST HOOK — when provided, the inner LLM
        loop calls this instead of real litellm. Each call gets
        the message history and the iteration index; should
        return a dict mimicking an LLM response with optional
        `tool_calls`. Used in unit tests to drive the loop
        deterministically without real LLM cost.

    Returns:
      Dict with the structured run result.
    """
    if not isinstance(category, str) or not category.strip():
        return SpecialistRunResult(
            category="", objective=objective or "",
            status="ERROR", reason="category required",
        ).to_dict()
    if not isinstance(objective, str) or not objective.strip():
        return SpecialistRunResult(
            category=category, objective="",
            status="ERROR", reason="objective required",
        ).to_dict()

    # v2 step 2 — specialist verdict cache. If a prior dispatch on a
    # structurally-similar endpoint (same category, same canonical
    # shape, same auth state) returned a cacheable BLOCKED verdict
    # ("no SQL backend", "no XSS sink", etc.), short-circuit with
    # the cached verdict. Recall-safe because only "no-signal"
    # BLOCKED verdicts get cached — PASSED / ERROR / cap-reached
    # results never enter the cache.
    #
    # Looked up BEFORE the scan-mode dispatch counter so cache hits
    # don't consume the per-run dispatch budget.
    from strix.agents.specialist_verdict_cache import (  # noqa: PLC0415
        should_skip as _cache_should_skip,
    )
    _cached = _cache_should_skip(
        category=category, endpoint=target, auth_state=None,
    )
    if _cached is not None:
        return SpecialistRunResult(
            category=category,
            objective=objective,
            status="CACHE_HIT_BLOCKED",
            reason=(
                f"verdict cache hit: prior dispatch on similar "
                f"endpoint returned BLOCKED — '{_cached.reason}'"
            ),
            summary=_cached.summary,
        ).to_dict()

    # Phase-1 scan-mode gate. Quick / initial modes set the cap to 0
    # so the fresh-context loop is skipped entirely; standard caps at
    # 8 dispatches per run; deep is unbounded. The cap is read from
    # STRIX_SCAN_MODE (set at scan boot) — overridable via
    # STRIX_DISPATCH_CAP_OVERRIDE for wrappers that need an explicit
    # budget. Over-cap returns a no-op result rather than raising so
    # the lead can read it and adapt (e.g. fall back to deterministic
    # probes).
    global _DISPATCH_COUNT
    cap_dispatches = get_scan_mode_dispatch_cap()
    if cap_dispatches is not None and _DISPATCH_COUNT >= cap_dispatches:
        mode = (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower() or "unset"
        reason = (
            f"scan_mode={mode} caps specialist dispatch at "
            f"{cap_dispatches}; this would be #{_DISPATCH_COUNT + 1}"
        )
        logger.info(
            "dispatch_specialist denied by scan_mode: category=%s mode=%s "
            "cap=%d count=%d",
            category, mode, cap_dispatches, _DISPATCH_COUNT,
        )
        return SpecialistRunResult(
            category=category,
            objective=objective,
            status="DENIED_BY_SCAN_MODE",
            reason=reason,
        ).to_dict()
    _DISPATCH_COUNT += 1

    profile = get_profile(category)
    cap = max_iterations or profile.max_iterations or get_max_iterations()
    cost_cap = max_cost_usd or profile.max_cost_usd

    # Snapshot findings count BEFORE the specialist runs so we
    # can compute delta.
    before_count = 0
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            before_count = len(tracer.vulnerability_reports or [])
    except Exception:  # noqa: BLE001
        pass

    scope_context = _resolve_scope_context()
    if target:
        scope_context = (
            f"target: {target}\n{scope_context}"
            if scope_context else f"target: {target}"
        )
    relevant_findings = _resolve_relevant_findings(category)

    system_prompt = _build_system_prompt(
        profile=profile,
        scope_context=scope_context,
        relevant_findings=relevant_findings,
        skills_override=skills_override,
    )

    # Clear any stale exit signal from a previous dispatch. Note:
    # we DON'T call `reset_for_testing()` here even though it does
    # the same thing — it also zeroes the per-run dispatch counter,
    # which the scan-mode gate (phase 1) depends on persisting
    # across dispatches.
    global _SPECIALIST_EXIT
    _SPECIALIST_EXIT = None

    # Inner loop — bounded iterations. Each iteration is one
    # LLM call + tool execution + result back into history.
    started = time.monotonic()
    history: list[dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": objective},
    ]
    iterations_used = 0
    cost_spent = 0.0
    final_status = "ITERATION_CAP_REACHED"
    final_reason: str | None = None
    final_summary: str | None = None

    for i in range(cap):
        iterations_used = i + 1

        # Budget check.
        if cost_cap is not None and cost_spent >= cost_cap:
            final_status = "BUDGET_EXCEEDED"
            final_reason = (
                f"specialist cost ${cost_spent:.4f} >= cap ${cost_cap:.2f}"
            )
            break

        # LLM call — either real or test-injected.
        try:
            if inner_call_fn is not None:
                response = inner_call_fn(
                    history=history, iteration=i, profile=profile,
                )
            else:
                response = _real_inner_llm_call(
                    history=history, profile=profile,
                )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "specialist[%s] inner-LLM call failed at iter %d: %s",
                category, i, e,
            )
            final_status = "ERROR"
            final_reason = f"{type(e).__name__}: {e}"
            break

        if not isinstance(response, dict):
            final_status = "ERROR"
            final_reason = "inner LLM returned non-dict response"
            break

        # Accumulate cost from the response if reported.
        cost_spent += float(response.get("cost_usd") or 0.0)

        # Append assistant message.
        msg = response.get("message") or ""
        history.append({"role": "assistant", "content": str(msg)})

        # Process tool calls if any. The specialist's
        # complete_objective signal exits the loop.
        tool_calls = response.get("tool_calls") or []
        for tc in tool_calls:
            try:
                result = _execute_inner_tool_call(tc, profile=profile)
            except Exception as e:  # noqa: BLE001
                result = {
                    "success": False,
                    "error": f"{type(e).__name__}: {e}",
                }
            history.append({
                "role": "tool",
                "content": json.dumps(result, default=str)[:2000],
            })

        # Check for specialist-emitted exit signal.
        exit_signal = get_specialist_exit_signal()
        if exit_signal is not None:
            final_status = exit_signal["status"]
            final_reason = exit_signal.get("reason")
            final_summary = exit_signal.get("summary")
            break

        # If the model produced no tool calls AND no exit signal,
        # treat as implicit completion (model "ran out of things
        # to do"). Mark as PASSED with a hint.
        if not tool_calls:
            final_status = "PASSED"
            final_reason = "specialist returned no tool calls"
            break

    duration = time.monotonic() - started
    findings_count = _count_findings_emitted_during(
        before_count=before_count,
    )

    # v2 step 2 — record the verdict in the cache if it's a
    # cacheable BLOCKED with no findings emitted. See
    # specialist_verdict_cache.record for the cacheable predicate.
    try:
        from strix.agents.specialist_verdict_cache import (  # noqa: PLC0415
            record as _cache_record,
        )
        _cache_record(
            category=category,
            endpoint=target,
            auth_state=None,
            status=final_status,
            reason=final_reason,
            objective=objective,
            summary=final_summary,
            findings_count=findings_count,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("verdict_cache record failed: %s", e)

    return SpecialistRunResult(
        category=category,
        objective=objective,
        status=final_status,
        reason=final_reason,
        iterations_used=iterations_used,
        findings_count=findings_count,
        duration_s=duration,
        summary=final_summary,
    ).to_dict()


def _real_inner_llm_call(
    *, history: list[dict[str, str]],
    profile: SpecialistDispatchProfile,
) -> dict[str, Any]:
    """The production inner-LLM call. Uses litellm with the run's
    STRIX_LLM model. Returns a response dict with `message`,
    `tool_calls`, `cost_usd`.

    Kept separate from `dispatch_specialist` so tests can inject
    `inner_call_fn` without touching this code path.

    v0 — extremely minimal: makes one chat completion call,
    parses any tool_calls from the response. v1 should reuse
    strix.llm.LLM for proper cost tracking, retries, prompt
    caching, etc."""
    try:
        import litellm
    except ImportError:
        return {"message": "litellm unavailable", "tool_calls": []}

    model = os.environ.get("STRIX_LLM", "").strip() or "anthropic/claude-sonnet-4-5"

    # v0 doesn't expose tool schemas to the inner LLM — that's a
    # follow-up. For now the specialist must request tool calls
    # via plain prose, and `_execute_inner_tool_call` parses the
    # `complete_objective(...)` shape. This is intentionally
    # narrow for the MVP.
    try:
        resp = litellm.completion(
            model=model,
            messages=history,
            temperature=0.2,
            max_tokens=2000,
            timeout=60,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("specialist inner litellm call failed: %s", e)
        return {"message": "", "tool_calls": [], "error": str(e)}

    content = ""
    try:
        content = resp.choices[0].message.content or ""
    except Exception:  # noqa: BLE001
        pass

    # Parse `complete_objective(...)` calls from the content. v1
    # should use proper structured tool calling.
    tool_calls = _parse_inline_tool_calls(content)

    return {
        "message": content,
        "tool_calls": tool_calls,
        "cost_usd": _extract_cost(resp),
    }


def _extract_cost(resp: Any) -> float:
    """Best-effort cost extraction from a litellm response."""
    try:
        usage = getattr(resp, "usage", None)
        if usage is None:
            return 0.0
        # litellm puts cost on `_hidden_params` for some providers.
        hidden = getattr(resp, "_hidden_params", {}) or {}
        return float(hidden.get("response_cost") or 0.0)
    except Exception:  # noqa: BLE001
        return 0.0


def _parse_inline_tool_calls(content: str) -> list[dict[str, Any]]:
    """v0 parser — looks for `complete_objective(...)` patterns
    in the LLM's text response. Strict-JSON-args parsing not
    needed since v0 supports only the exit signal."""
    import re
    calls: list[dict[str, Any]] = []
    # complete_objective(status='PASSED', reason='...', summary='...')
    pattern = re.compile(
        r"complete_objective\s*\(\s*(.*?)\s*\)", re.DOTALL,
    )
    for match in pattern.finditer(content or ""):
        args_str = match.group(1)
        args: dict[str, Any] = {}
        for part in re.finditer(
            r"(\w+)\s*=\s*['\"]([^'\"]*)['\"]", args_str,
        ):
            args[part.group(1)] = part.group(2)
        calls.append({"tool": "complete_objective", "args": args})
    return calls


def _execute_inner_tool_call(
    tc: dict[str, Any], *,
    profile: SpecialistDispatchProfile,
) -> dict[str, Any]:
    """Execute one tool call from the specialist's response.

    v1 routes tool calls through the real strix tool registry,
    gated by `profile.allowed_tool_subset`:

      * `complete_objective` is always allowed (it's the loop's
        exit signal — every profile needs it).
      * Other tools are looked up in
        `strix.tools.registry.get_tool_by_name`; the call is
        rejected if the tool is not in the profile's allowed
        subset.

    Kill switch: `STRIX_SPECIALIST_TOOLS_DISABLED=1` reverts to
    v0 (only `complete_objective` allowed; every other tool call
    returns a `not supported` error). Useful for A/B-comparing
    the v0 and v1 paths."""
    name = tc.get("tool") or ""
    args = tc.get("args") or {}

    # complete_objective — the exit signal — never goes through
    # the registry. Profile gating is also bypassed; this is the
    # one tool every specialist must always have.
    if name == "complete_objective":
        signal_specialist_complete(
            status=args.get("status", "PASSED"),
            reason=args.get("reason"),
            summary=args.get("summary"),
        )
        return {"success": True, "signaled": "complete_objective"}

    if _is_specialist_tools_disabled():
        return {
            "success": False,
            "error": (
                f"specialist v0 mode (STRIX_SPECIALIST_TOOLS_DISABLED=1) — "
                f"only complete_objective allowed; got {name!r}."
            ),
        }

    # Profile gating — `allowed_tool_subset` is the catalog the
    # specialist can call. Empty subset = full surface (legacy v0
    # default; rarely used in practice).
    subset = list(profile.allowed_tool_subset)
    if subset and name not in subset:
        return {
            "success": False,
            "error": (
                f"tool {name!r} not in specialist profile "
                f"{profile.category!r}'s allowed_tool_subset"
            ),
        }

    # Look up + execute via the real registry.
    try:
        from strix.tools.registry import get_tool_by_name
    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"tool registry unavailable: {e}",
        }

    fn = get_tool_by_name(name)
    if fn is None:
        return {
            "success": False,
            "error": f"tool {name!r} not registered with strix",
        }

    try:
        # Tools are registered with kwargs-shaped signatures; pass
        # the parsed args dict as kwargs. Strict — if the tool
        # rejects an arg shape, we surface the TypeError as a
        # structured error instead of crashing the inner loop.
        result = fn(**(args or {}))
    except TypeError as e:
        return {
            "success": False,
            "error": f"tool {name!r} arg shape: {e}",
        }
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "specialist[%s] tool %r raised: %s",
            profile.category, name, e, exc_info=True,
        )
        return {
            "success": False,
            "error": f"tool {name!r} raised: {type(e).__name__}: {e}",
        }

    # If the tool returned something JSON-serialisable, pass it
    # through; otherwise stringify.
    if isinstance(result, dict):
        return result
    if result is None:
        return {"success": True, "result": None}
    try:
        json.dumps(result)
        return {"success": True, "result": result}
    except (TypeError, ValueError):
        return {"success": True, "result": str(result)}


def _is_specialist_tools_disabled() -> bool:
    """Kill switch — reverts the inner loop to v0 (complete_objective
    only). Set `STRIX_SPECIALIST_TOOLS_DISABLED=1`."""
    return os.environ.get(
        "STRIX_SPECIALIST_TOOLS_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")
