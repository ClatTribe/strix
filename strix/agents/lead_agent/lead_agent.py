"""`LeadAgent` — single-lead architecture (roadmap §8.5 Phase 3 /
single-agent.md §2.1).

Replaces the parent-spawns-N-specialists pattern. One agent, one
conversation, one LLM client. Tools are filtered per target type;
`create_agent` (and its sibling spawn helpers) are explicitly
removed from the catalog so the lead literally cannot spawn
sub-agents — that's the architectural commitment.

Selection is via `STRIX_AGENT_ARCHITECTURE` env var (default `legacy`):

  * `legacy` (default) — `interface/main.py` instantiates `StrixAgent`
    as today. Parent-spawns-N pattern unchanged.
  * `single-lead` — `interface/main.py` instantiates `LeadAgent`. The
    lead executes the scan with its filtered tool catalog; no sub-
    agents spawn.

Phase 3a (this PR) ships:
  * The `LeadAgent` class with `category="lead"`.
  * Per-target-type tool catalog filtering (`tool_catalog.py`).
  * Eager-emit + active-hypothesis + provenance-reasoning system
    prompt addendum applied via `LLMConfig.system_prompt_context`.
  * `category="lead"` propagated through `agent.created` event.

Phase 3b (next) wraps XSS / SQLi / IDOR specialists as `llm=True`
specialist-tools that the lead invokes instead of spawning sub-agents.

Wrapper-side impact: zero. The lead emits the same `agent.created`
event shape as a regular agent (just with `category="lead"` —
already a wrapper-known value per #33). All other events (`tool.
execution.*`, `finding.*`, `phase.*`, `hypothesis.*`) emit
unchanged. The wrapper can't tell which architecture is running
unless it inspects `actor.agent_category`.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from strix.agents.StrixAgent.strix_agent import StrixAgent
from strix.agents.lead_agent.tool_catalog import (
    get_lead_tool_catalog,
    list_blocked_tools,
)


logger = logging.getLogger(__name__)


# Lead-agent system-prompt directives — appended to the existing
# StrixAgent prompt context so the LLM understands the single-lead
# architectural commitment without rewriting the entire prompt.
# Lead-agent operating directive. Tight + behavioural — overlaying
# the existing StrixAgent system prompt without overriding its
# tool-call format instructions. Verbose drafts (the original 7-rule
# version) caused the model to hallucinate findings as prose: it
# read the rule list, tool-name references, and the user's "20
# vulnerabilities present" framing → produced markdown writeups
# from training data instead of probing the live target. The fix
# is a single short paragraph that:
#   * tells the model it can't spawn sub-agents (architectural
#     commitment),
#   * tells it to PROBE before reporting (anti-hallucination),
#   * defers to the existing StrixAgent prompt for tool-call format
#     rules (no tool names mentioned that the model could mistake
#     for Python-style function calls).
_LEAD_SYSTEM_PROMPT_ADDENDUM = (
    "You are running in single-lead mode: there are no sub-agents "
    "to spawn (those tools are intentionally absent from your "
    "catalog). Always probe the live target with the tools you "
    "have before reporting findings — never produce prose "
    "summaries of vulnerabilities from prior knowledge of the "
    "target. Every finding must come from evidence captured by a "
    "tool call you actually executed in this run.\n\n"
    "EMIT FINDINGS EAGERLY. The moment a probe gives you credible "
    "evidence of a vulnerability — a 200 OK on a request that "
    "should have been forbidden, a reflected XSS payload "
    "appearing un-escaped in the response, a SQL error revealing "
    "the database engine, a successful unauthorized admin action "
    "— your VERY NEXT action must be a `<function=create_"
    "vulnerability_report>` call with the evidence you just "
    "captured. Do NOT continue probing other surfaces before "
    "emitting; do NOT batch findings until the end of the scan; "
    "do NOT describe the vulnerability in prose and move on. "
    "Prose without an emission means the finding is lost. "
    "Use `verification_status=pattern_match` and `confidence=0.7` "
    "when you have one credible signal; bump to "
    "`verification_status=verified` and `confidence=0.95` once "
    "you've reproduced the exploit end-to-end. You can refine an "
    "already-emitted finding via `<function=update_finding>`. "
    "Treat un-emitted vulnerabilities as a budget waste: every "
    "minute you spent reaching the evidence is wasted if you "
    "don't emit before moving on.\n\n"
    "EXACT EMISSION FORMAT. Strix's parser ONLY recognises the "
    "literal opening tag `<function=create_vulnerability_report>`. "
    "Do NOT invent variants like `<vulnerability>`, "
    "`<vulnerability_report>`, `<finding>`, or any heading-derived "
    "tag — those are silently dropped and the finding is lost. "
    "The required 9 parameters are below; passing `url` instead "
    "of `target`, `severity` instead of `cvss_breakdown`, "
    "`remediation` instead of `remediation_steps`, or `type` "
    "instead of `category` will cause "
    "`TypeError: got an unexpected keyword argument` and the "
    "finding will not register. Match these names exactly. "
    "Severity is DERIVED from `cvss_breakdown`; do NOT pass "
    "`severity=` directly. Each emission must look exactly like "
    "the line below (replace the bracketed placeholders with "
    "your evidence; keep every tag name verbatim):\n\n"
    "<function=create_vulnerability_report>\n"
    "<parameter=title>{short specific title}</parameter>\n"
    "<parameter=description>{what was found and how it was "
    "discovered}</parameter>\n"
    "<parameter=impact>{what an attacker can do; data at risk; "
    "business risk}</parameter>\n"
    "<parameter=target>{affected URL/host/repo, e.g. "
    "https://example.com/api/login}</parameter>\n"
    "<parameter=technical_analysis>{vulnerability mechanism + "
    "root cause}</parameter>\n"
    "<parameter=poc_description>{numbered steps to reproduce}"
    "</parameter>\n"
    "<parameter=poc_script_code>{concrete payload / curl / "
    "script that triggers the issue}</parameter>\n"
    "<parameter=remediation_steps>{specific fix recommendations}"
    "</parameter>\n"
    "<parameter=cvss_breakdown><cvss><AV>N</AV><AC>L</AC>"
    "<PR>N</PR><UI>N</UI><S>U</S><C>H</C><I>H</I><A>N</A>"
    "</cvss></parameter>\n"
    "</function>\n\n"
    "All 9 parameters above are MANDATORY — even if your "
    "evidence for one is brief. Optional parameters that often "
    "help: `cwe` (e.g. `CWE-89` for SQL injection), `category` "
    "(e.g. `sqli`, `xss`, `idor`), `endpoint` (e.g. `/api/login`), "
    "`verification_status` (`pattern_match` for one credible "
    "signal, `verified` after end-to-end repro)."
)


# ---------------------------------------------------------------------------
# Asset-aware routing guidance.
#
# The lead's tool catalog is filtered per target type (see
# `tool_catalog.py`). That stops the LLM from invoking irrelevant tools
# but doesn't tell it *which* tools should anchor its plan for the
# specific asset(s) in scope. The blurb below renders into the prompt's
# `system_prompt_context["lead_asset_routing"]` slot — the StrixAgent
# Jinja template surfaces it just below the architectural directives.
#
# Rules:
#   * One short paragraph per asset class (web / repo / domain / ip).
#   * When MULTIPLE asset classes are present, append a "cross-asset"
#     block telling the lead to correlate findings (e.g., SCA on the
#     repo informs DAST hypotheses on the URL).
#   * No tool-call examples here — those live in the directives block
#     above. This block is *what* not *how*.
# ---------------------------------------------------------------------------


_PER_ASSET_GUIDANCE: dict[str, str] = {
    "web_application": (
        "Web target: probe the live URL. Anchor on `webapp_recon_pipeline` "
        "→ `fingerprint_tech_stack` → matching specialists "
        "(scan_sqli / scan_xss / scan_idor / scan_ssrf / scan_auth_flow / "
        "scan_business_logic / scan_oauth). Use HAR / Burp imports if the "
        "user supplied them. Prioritise authenticated surfaces: business "
        "logic + IDOR are usually the highest-impact bugs on a live app."
    ),
    "repository": (
        "Repo target: anchor on `scan_sca_lockfiles` FIRST — it's "
        "deterministic, cheap, and surfaces the #1 vuln class for modern "
        "apps (vulnerable dependencies). Phase 6.4 reachability filtering "
        "is on by default: findings carry `[reachability=...]` tags "
        "indicating whether the vulnerable package is actually imported "
        "by app code. `direct_import` keeps original severity, "
        "`transitive_only` demotes one tier, `unused` demotes two — KEV "
        "and EPSS≥0.5 always override. Then `build_code_map` + "
        "`taint_analysis` for SAST on user-input → sink flows, "
        "`secrets_scan` for credentials, and `scan_misconfig` for "
        "infra-as-code drift."
    ),
    "local_code": (
        "Local code target: same play as `repository` — `scan_sca_lockfiles` "
        "first for dependency CVEs, then SAST (`build_code_map` + "
        "`taint_analysis`), then `secrets_scan`. Lockfile presence is "
        "high-signal: if there's a `package-lock.json` / `requirements.txt` "
        "/ `Cargo.lock` / `go.sum`, SCA findings nearly always precede "
        "SAST findings in severity. SCA findings include reachability "
        "tags (Phase 6.4) so prioritise reachable / direct-import hits "
        "for cross-asset DAST follow-ups."
    ),
    "domain": (
        "Domain target: anchor on `domain_recon_pipeline` → "
        "`subdomain_enum_tool` → `subdomain_takeover_check`. Pivot to "
        "web-app probes (`send_request` + specialists) on any subdomain "
        "that returns 2xx with HTML."
    ),
    "ip_address": (
        "IP target: enumerate exposed ports and services with "
        "`terminal_execute` (nmap-style), then `tls_audit` and "
        "`websocket_audit` on anything that speaks TLS / WS. Treat any "
        "HTTP service found here as if it were a web_application target "
        "and probe it with `send_request`."
    ),
}


_CROSS_ASSET_BLOCK = (
    "CROSS-ASSET CORRELATION. You have more than one asset in scope. "
    "Treat findings on one asset as hypotheses on the others:\n"
    "  * SCA finding on repo (`scan_sca_lockfiles`) names a vulnerable "
    "dep with a known CVE class → probe the live URL for that class. "
    "Example: `lodash@<4.17.21` → prototype-pollution → look for "
    "client-side template injection / unsafe object merge endpoints. "
    "If the SCA finding's title carries `[reachability=direct_import]` "
    "(or no reachability tag), prioritise the DAST follow-up — the "
    "package is actually used in code, exploitation is realistic. "
    "If it carries `[reachability=unused]` or `[reachability="
    "transitive_only]`, the DAST probe is lower-priority but still "
    "worth a single check (a future PR may import the package; the "
    "demoted severity reflects current import graph only).\n"
    "  * SAST finding (`taint_analysis`) names a sink (e.g. `eval`, raw "
    "SQL string) → confirm it's reachable from the live URL by probing "
    "the matching endpoint with the relevant specialist.\n"
    "  * DAST finding on URL (e.g. SQL error in response) → check the "
    "repo for the offending file/sink and emit a follow-up code-level "
    "finding so the wrapper has both the runtime evidence and the fix "
    "location.\n"
    "  * Same package surfaced by SCA *and* a DAST behaviour — bump "
    "severity / confidence; it's a real exploit path, not just an "
    "advisory match. This is the strongest cross-asset signal: a "
    "reachable SCA hit + matching live exploit confirms the chain "
    "end-to-end.\n"
    "Cross-asset findings should reference both surfaces in "
    "`description` + `technical_analysis` so reviewers see the chain."
)


def _build_asset_routing_block(target_types: set[str] | list[str]) -> str:
    """Build the `lead_asset_routing` system-prompt slot from
    `target_types`. Returns "" when target_types is empty (no
    extra guidance needed)."""
    if not target_types:
        return ""
    seen: list[str] = []
    for tt in sorted(set(target_types)):
        if not isinstance(tt, str):
            continue
        guidance = _PER_ASSET_GUIDANCE.get(tt.strip().lower())
        if guidance:
            seen.append(f"[{tt}] {guidance}")
    if not seen:
        return ""
    out = "\n\n".join(seen)
    if len(seen) > 1:
        out += "\n\n" + _CROSS_ASSET_BLOCK
    return out


class LeadAgent(StrixAgent):
    """Single-lead architecture (roadmap §8.5 Phase 3).

    Subclasses `StrixAgent` so it inherits `execute_scan`. The
    constructor:
      1. Forces `category="lead"` on the AgentState (overrides any
         caller-supplied category).
      2. Computes the per-target-type tool catalog.
      3. Augments the system-prompt context with the single-lead
         directives.
      4. Inherits `agent_loop` from `BaseAgent` — no loop changes
         in Phase 3a; parallel-dispatch + watchdog land in Phase 3b
         and Phase 6 respectively.

    Selection is via `STRIX_AGENT_ARCHITECTURE=single-lead` env var.
    `interface/main.py` reads the env var and instantiates
    `LeadAgent` instead of `StrixAgent`.
    """

    def __init__(self, config: dict[str, Any]):
        # Roadmap §8.5 — force category="lead" BEFORE super().__init__
        # so the agent.created event (emitted by BaseAgent's
        # tracer.log_agent_creation call) carries the right category.
        # Two paths:
        #   1. Caller passed `state` in config → mutate in place.
        #   2. Caller did NOT (the default cli.py / tui.py path) →
        #      pre-build an AgentState with category="lead" and
        #      inject so BaseAgent's `config.get("state")` finds it
        #      instead of constructing a default Root-Agent state.
        state = config.get("state")
        if state is not None and hasattr(state, "category"):
            state.category = "lead"
        else:
            # Mirror BaseAgent's default state construction with
            # category="lead" pre-set.
            from strix.agents.state import AgentState

            state = AgentState(
                agent_name="Root Agent",  # preserved for back-compat
                category="lead",
                max_iterations=int(config.get("max_iterations", self.max_iterations)),
            )
            config["state"] = state

        # Capture target_types from scan_config when available so the
        # tool catalog is filtered correctly. The actual filtering
        # is applied via system_prompt_context (the LLM layer renders
        # the prompt from this context — we override the
        # `tool_catalog_allowlist` key).
        target_types = self._extract_target_types(config)

        # Build the system_prompt_context augmentation. StrixAgent
        # already passes a `system_scope_context` via
        # `set_system_prompt_context`; we add to it.
        system_prompt_context = dict(config.get("system_prompt_context", {}))
        system_prompt_context["lead_architecture_directives"] = (
            _LEAD_SYSTEM_PROMPT_ADDENDUM
        )
        system_prompt_context["lead_architecture_active"] = True
        system_prompt_context["target_types"] = sorted(target_types)
        system_prompt_context["tool_catalog_allowlist"] = sorted(
            get_lead_tool_catalog(target_types=target_types)
        )
        # Asset-aware routing guidance — names which tools to anchor
        # on per asset class, plus a cross-asset block when more than
        # one class is in scope. Empty string when target_types is
        # empty (the StrixAgent template treats it as no-op).
        system_prompt_context["lead_asset_routing"] = (
            _build_asset_routing_block(target_types)
        )
        system_prompt_context["tool_catalog_blocklist"] = sorted(
            list_blocked_tools()
        )
        config["system_prompt_context"] = system_prompt_context

        # Also push onto LLMConfig if it exists already so the LLM
        # client can render the directives into its system prompt.
        llm_config = config.get("llm_config")
        if llm_config is not None and hasattr(llm_config, "system_prompt_context"):
            existing = dict(getattr(llm_config, "system_prompt_context", {}) or {})
            existing.update(system_prompt_context)
            try:
                llm_config.system_prompt_context = existing
            except Exception:  # noqa: BLE001
                logger.debug("LeadAgent: could not set llm_config.system_prompt_context")

        super().__init__(config)
        self.is_lead_agent = True
        self.target_types = list(target_types)

        # Roadmap §8.5 — force category="lead" AFTER super().__init__
        # too. The pre-super assignment only fires when caller-supplied
        # state was present in config; the default cli.py / tui.py
        # path does NOT pre-build state (BaseAgent constructs it).
        # Without this post-super forcing, agent.created emits with
        # category=None and the wrapper-side per-specialist
        # filtering / synthetic-agent.created discrimination breaks.
        try:
            if hasattr(self, "state") and self.state is not None:
                self.state.category = "lead"
            # Re-emit agent metadata to the tracer so subsequent events
            # carry the corrected category. Best-effort.
            try:
                from strix.telemetry.tracer import get_global_tracer

                tracer = get_global_tracer()
                if tracer is not None and hasattr(tracer, "agents"):
                    aid = getattr(self.state, "agent_id", None)
                    if aid and aid in tracer.agents:
                        tracer.agents[aid]["category"] = "lead"
            except Exception:  # noqa: BLE001
                logger.debug("LeadAgent: tracer agent-category re-tag failed")
        except Exception:  # noqa: BLE001
            logger.debug("LeadAgent: post-super category force failed")

        # BaseAgent.__init__ created `self.llm` from llm_config. We
        # need to do TWO things:
        #
        #   1. Re-point the LLM's template lookup at StrixAgent's
        #      directory (`strix/agents/StrixAgent/system_prompt.jinja`).
        #      The `AgentMeta` metaclass overrides `agent_name` to the
        #      *class name*, so for `class LeadAgent(StrixAgent)` it
        #      becomes `"LeadAgent"`. `LLM._load_system_prompt` then
        #      hands `"LeadAgent"` to `get_strix_resource_path("agents",
        #      ...)` which fails to find a template — and the bare
        #      `except Exception` clause silently returns `""`. The
        #      LLM then sends an empty system prompt to the provider:
        #      gemini-2.5-pro receives only the user instruction, has
        #      no scope/no tool catalog/no format directives, and
        #      hallucinates the entire scan from training data using
        #      `<tool_code>` Python syntax (which strix's parser
        #      rejects). Symptom: first LLM request reports
        #      `prompt_tokens=145` instead of ~80K.
        #
        #   2. Push the lead-architecture context onto the LLM and
        #      RE-RENDER. `set_system_prompt_context` does both — it
        #      assigns the new context AND calls
        #      `_load_system_prompt(self.agent_name)` to refresh
        #      `self.system_prompt`.
        try:
            self.llm.agent_name = "StrixAgent"
            merged_ctx = dict(getattr(self.llm, "_system_prompt_context", {}) or {})
            merged_ctx.update(system_prompt_context)
            self.llm.set_system_prompt_context(merged_ctx)
            if not self.llm.system_prompt:
                logger.warning(
                    "LeadAgent: system_prompt empty after reload — "
                    "template render likely failed; LLM will receive "
                    "no scope/no format directives."
                )
        except Exception:  # noqa: BLE001
            logger.debug("LeadAgent: could not refresh self.llm.system_prompt")

        # Roadmap §8.5 Phase 6 — watchdog state for the iteration
        # hook. Tracks turns since last progress; force-exits the
        # loop when too many idle turns pass. Default
        # `max_idle_turns=8` — 3 more than single-agent.md §2.6's
        # default of 5 to give early scan iterations (recon /
        # surface mapping) some slack before declaring stuck.
        try:
            from strix.agents.lead_agent.watchdog import WatchdogState

            self._watchdog = WatchdogState(max_idle_turns=8)
        except Exception:  # noqa: BLE001
            self._watchdog = None
            logger.debug("LeadAgent: watchdog init failed")
        # Snapshot for progress detection in `_on_iteration_tick`.
        self._last_finding_count = 0
        self._last_completed_tool_count = 0
        self._watchdog_terminated_emitted = False

    # ------------------------------------------------------------------
    # Per-iteration hook (roadmap §8.5 Phase 6)
    # ------------------------------------------------------------------

    def _on_iteration_tick(self) -> bool:
        """Tick the watchdog + detect progress between iterations.

        Progress signals (any one resets the idle counter):
          * `len(tracer.vulnerability_reports)` grew since last tick
            → finding emitted (eager-emit per §B.10).
          * `completed_tool_executions` count grew → at least one
            tool ran successfully (recon / probe / specialist call).

        Returns True to force-exit the loop when watchdog signals
        max-idle-turns reached (single-agent.md §2.6). The loop
        wraps this in try/except so an override that raises is
        ignored; force-exit is the only way to halt voluntarily.
        """
        wd = getattr(self, "_watchdog", None)
        if wd is None:
            return False
        try:
            wd.tick()

            # Detect progress.
            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer is not None:
                cur_findings = len(getattr(tracer, "vulnerability_reports", []) or [])
                if cur_findings > self._last_finding_count:
                    wd.record_progress("finding")
                    self._last_finding_count = cur_findings
                # Tool-execution completed count from the tracer's
                # in-memory counter.
                cur_completed = sum(
                    int(rec.get("status") == "completed")
                    for rec in (getattr(tracer, "tool_executions", {}) or {}).values()
                    if isinstance(rec, dict)
                )
                if cur_completed > self._last_completed_tool_count:
                    wd.record_progress("endpoint")
                    self._last_completed_tool_count = cur_completed

            # Force-exit on idle threshold.
            if wd.should_force_exit():
                if not self._watchdog_terminated_emitted:
                    try:
                        from strix.agents.lead_agent.watchdog import (
                            emit_watchdog_terminated,
                        )

                        emit_watchdog_terminated(
                            reason_detail=(
                                f"{wd.max_idle_turns} consecutive iterations "
                                f"without progress (no new findings, no new "
                                f"completed tool executions)"
                            ),
                        )
                        self._watchdog_terminated_emitted = True
                    except Exception:  # noqa: BLE001
                        logger.debug("LeadAgent: watchdog emit failed")
                logger.warning(
                    "LeadAgent watchdog force-exit: %d idle iterations",
                    wd.max_idle_turns,
                )
                return True
        except Exception:  # noqa: BLE001
            # Hook must never break the agent loop.
            logger.debug("LeadAgent._on_iteration_tick failed", exc_info=True)
        return False

    @staticmethod
    def _extract_target_types(config: dict[str, Any]) -> set[str]:
        """Extract target_type values from config. Defaults to the
        union of all target types when the config doesn't supply
        scan_config (which happens in unit tests / direct
        instantiation)."""
        scan_config = config.get("scan_config") or {}
        targets = scan_config.get("targets") or []
        if isinstance(targets, list) and targets:
            out: set[str] = set()
            for t in targets:
                if isinstance(t, dict):
                    tt = t.get("type")
                    if isinstance(tt, str) and tt.strip():
                        out.add(tt.strip().lower())
            if out:
                return out
        # Fallback: every target type. This is the safest default
        # for direct-instantiation scenarios; the agent sees more
        # tools than necessary but isn't blocked.
        from strix.agents.lead_agent.tool_catalog import list_target_types

        return set(list_target_types())


def is_single_lead_architecture_enabled() -> bool:
    """Read `STRIX_AGENT_ARCHITECTURE` env var.

    Returns True when set to `single-lead` (case-insensitive,
    whitespace-tolerant). Any other value (including unset) returns
    False — `legacy` parent-spawns-N stays the default through
    Phase 7. Phase 8 flips the default after the benchmark
    acceptance gate clears.
    """
    raw = (os.environ.get("STRIX_AGENT_ARCHITECTURE") or "").strip().lower()
    return raw == "single-lead"
