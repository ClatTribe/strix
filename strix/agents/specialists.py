"""Specialist scope discipline (roadmap §8.0).

Per-specialist profiles that scope spawned sub-agents to a focused
attack class instead of the full Strix toolset. Operationalises the
**Act-stage** discipline of the OODA loop: each specialist runs a
tight Act loop scoped to its single-purpose role.

Without this, every spawned agent inherits the full skill registry
+ full conversation history; the breadth dilutes focus and burns
tokens. With it, the lead can declare `category="sqli-specialist"`
and the spawn system:

1. Loads the recommended-skills subset for that category
2. Appends a scope-discipline addendum to the agent's task
3. Applies a default per-specialist budget (cost / token cap)

Lead-team protocol:
- Spawning code reads `get_specialist_profile(category)`.
- When a profile exists AND the caller didn't override the field,
  the profile's defaults apply.
- Caller-supplied values always win (the registry is fallback,
  not enforcement).

Registry shape:

```python
SPECIALIST_REGISTRY = {
    "sqli-specialist": SpecialistProfile(
        category="sqli-specialist",
        recommended_skills="sqli,http",
        scope_addendum="You are the SQLi specialist. ...",
        default_budget={"max_cost_usd": 0.50, "max_input_tokens": 80_000},
        inherit_context_default=True,
    ),
    ...
}
```

Adding a new specialist: register a `SpecialistProfile` here. The
spawn system picks it up via `get_specialist_profile(category)`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SpecialistProfile:
    """Scope-discipline profile for a single specialist category."""

    category: str
    """Canonical category string (lowercased, kebab-case)."""

    recommended_skills: str
    """Comma-separated skill list. Maps to LLMConfig.skills.
    Smaller = more focused; one specialist = ~1-3 skills typical."""

    scope_addendum: str
    """Scope-discipline prose appended to the spawned agent's task.
    Reminds the specialist of its single-purpose role and tells it
    to defer out-of-scope findings to peer specialists rather than
    probe them itself."""

    default_budget: dict[str, Any] = field(default_factory=dict)
    """Default budget for this specialist (cost / token / time
    caps). Caller's `budget` config dict overrides per-field; this
    is the fallback so an unsupervised lead doesn't accidentally
    spawn an unbounded specialist."""

    inherit_context_default: bool = True
    """Default for `inherit_context`. Set False for specialists that
    should start from a clean conversation (e.g. a Validator agent
    that should reason fresh from the candidate finding rather than
    drift on the lead's prior chain-of-thought)."""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_SPECIALISTS: tuple[SpecialistProfile, ...] = (
    # ---- Web-application team (§8.2) ----
    SpecialistProfile(
        category="sqli-specialist",
        # Primary: sql_injection skill pack + sqlmap tool wrapper.
        recommended_skills="sql_injection,sqlmap",
        scope_addendum=(
            "You are the SQL Injection specialist. Your scope is "
            "STRICTLY SQL injection probing on the assigned endpoints. "
            "Do NOT probe XSS, SSRF, IDOR, or other classes — defer "
            "those to peer specialists by reporting the candidate "
            "endpoint without testing it. Focus: reflective error-"
            "based, blind boolean / time-based, second-order, NoSQL "
            "where applicable. Confirm exploitability via a benign "
            "data-side-channel (e.g. `version()`/`current_user()`) "
            "rather than DROP / data exfiltration."
        ),
        default_budget={
            "max_cost_usd": 0.50,
            "max_input_tokens": 80_000,
            "max_output_tokens": 20_000,
        },
    ),
    SpecialistProfile(
        category="xss-specialist",
        recommended_skills="xss",
        scope_addendum=(
            "You are the XSS specialist. Your scope is STRICTLY "
            "cross-site-scripting (reflected, stored, DOM-based). "
            "Do NOT probe SQLi, SSRF, IDOR — defer those. Focus: "
            "reflection point identification, context-aware payload "
            "selection (HTML / attribute / JS / URL), CSP-bypass "
            "evaluation. Verify execution via a benign payload "
            "(`alert(strix-<nonce>)` or post-message-back to a "
            "controlled origin)."
        ),
        default_budget={
            "max_cost_usd": 0.50,
            "max_input_tokens": 80_000,
            "max_output_tokens": 20_000,
        },
    ),
    SpecialistProfile(
        category="ssrf-scanner",
        recommended_skills="ssrf",
        scope_addendum=(
            "You are the SSRF specialist. Your scope is STRICTLY "
            "server-side request forgery probing. Do NOT probe SQLi, "
            "XSS, CSRF — defer those. Focus: discovering URL-input "
            "parameters, blind-SSRF detection via DNS / HTTP "
            "callbacks to your nonce-tagged listener, cloud-metadata "
            "endpoints (169.254.169.254), private-IP reachability."
        ),
        default_budget={
            "max_cost_usd": 0.50,
            "max_input_tokens": 80_000,
            "max_output_tokens": 20_000,
        },
    ),
    SpecialistProfile(
        category="auth-attacker",
        recommended_skills="authentication_jwt",
        scope_addendum=(
            "You are the Authentication specialist. Your scope is "
            "STRICTLY auth-flow attacks: credential stuffing posture, "
            "MFA enforcement testing, password-reset flow abuse, "
            "session-fixation, JWT misuse, OAuth / OIDC flow flaws. "
            "Do NOT probe SQLi, XSS, IDOR. Use existing tools: "
            "`session_entropy_check` for cookie randomness, "
            "`jwt_audit` for JWT exploit-classes."
        ),
        default_budget={
            "max_cost_usd": 0.50,
            "max_input_tokens": 80_000,
            "max_output_tokens": 20_000,
        },
    ),
    SpecialistProfile(
        category="idor-specialist",
        recommended_skills="idor,broken_function_level_authorization",
        scope_addendum=(
            "You are the IDOR / authorization specialist. Your scope "
            "is STRICTLY authorization-bypass probing on object-"
            "reference parameters (user_id / order_id / etc.). Use "
            "`authz_matrix_check` as primary tool. Do NOT probe SQLi, "
            "XSS, SSRF — defer those."
        ),
        default_budget={
            "max_cost_usd": 0.50,
            "max_input_tokens": 80_000,
            "max_output_tokens": 20_000,
        },
    ),
    SpecialistProfile(
        category="csrf-specialist",
        recommended_skills="csrf",
        scope_addendum=(
            "You are the CSRF specialist. Your scope is STRICTLY "
            "CSRF posture probing on state-changing forms. Use "
            "`csrf_check` as primary tool. Do NOT probe other "
            "classes — defer."
        ),
        default_budget={
            "max_cost_usd": 0.30,
            "max_input_tokens": 60_000,
            "max_output_tokens": 15_000,
        },
    ),
    # §8.2 — webapp team additions
    SpecialistProfile(
        category="authz-matrix-specialist",
        # `broken_function_level_authorization` is the matrix-style
        # authz skill; `idor` complements with object-reference
        # checks at the same time.
        recommended_skills="broken_function_level_authorization,idor",
        scope_addendum=(
            "You are the Authorization-Matrix specialist. For each "
            "(role × endpoint × verb) tuple from the surface map, "
            "use `authz_matrix_check` to probe whether the endpoint "
            "honours the documented role boundary. Always include "
            "an `unauth` role with empty headers as the floor. Emit "
            "findings with `category=improper_authorization`. Do "
            "NOT probe SQLi, XSS, SSRF, etc. — defer those."
        ),
        default_budget={
            "max_cost_usd": 0.50,
            "max_input_tokens": 80_000,
            "max_output_tokens": 20_000,
        },
    ),
    SpecialistProfile(
        category="injection-specialist",
        # Broader than sqli-specialist: covers SQLi, command,
        # SSTI, path-traversal, file-inclusion. Pairs well with
        # `path_traversal_lfi_rfi` + `rce` skill packs.
        recommended_skills="sql_injection,rce,path_traversal_lfi_rfi,xxe",
        scope_addendum=(
            "You are the Injection specialist. Your scope covers "
            "SQL injection, command injection, SSTI (server-side "
            "template injection), path traversal / LFI / RFI, "
            "XXE, and similar input-validation classes. For each "
            "endpoint with parameters from the surface map, probe "
            "context-aware payloads per parameter. Confirm via "
            "out-of-band signal (e.g. controlled DNS callback) or "
            "deterministic side-channel (e.g. SQL `version()` "
            "reflection). Defer XSS to `xss-specialist`, SSRF to "
            "`ssrf-scanner`, IDOR to `idor-specialist`."
        ),
        default_budget={
            "max_cost_usd": 0.75,
            "max_input_tokens": 120_000,
            "max_output_tokens": 30_000,
        },
    ),
    SpecialistProfile(
        category="graphql-specialist",
        recommended_skills="graphql",
        scope_addendum=(
            "You are the GraphQL specialist. For each GraphQL "
            "endpoint identified by recon, use "
            "`graphql_specialist_check` to test the four "
            "protocol-specific abuse classes: introspection "
            "exposure, query-depth abuse, alias overloading, "
            "batch abuse. Then probe field-level authz: enumerate "
            "the schema, attempt to query fields the role "
            "shouldn't access. Do NOT probe REST endpoints — "
            "defer to peer specialists."
        ),
        default_budget={
            "max_cost_usd": 0.40,
            "max_input_tokens": 70_000,
            "max_output_tokens": 18_000,
        },
    ),
    SpecialistProfile(
        category="business-logic-specialist",
        recommended_skills="business_logic,race_conditions,mass_assignment",
        scope_addendum=(
            "You are the Business-Logic specialist. Your scope is "
            "workflow-abuse and entitlement-bypass classes that "
            "deterministic probes miss: state-machine skipping, "
            "double-spend / negative-quantity, race-condition on "
            "state-changing endpoints, mass-assignment / parameter "
            "pollution, role-escalation via overlooked admin "
            "fields. Read the customer's threat model (when "
            "supplied) for domain-specific workflows. Defer "
            "deterministic classes (SQLi/XSS/SSRF/IDOR/CSRF) to "
            "peer specialists."
        ),
        default_budget={
            "max_cost_usd": 1.00,
            "max_input_tokens": 100_000,
            "max_output_tokens": 30_000,
        },
    ),
    SpecialistProfile(
        category="webapp-recon-lead",
        # Recon-lead reads surface_map; doesn't need exploit skills.
        recommended_skills="httpx,katana",
        scope_addendum=(
            "You are the Web-App Recon Lead. Your job is to ensure "
            "`webapp_recon_pipeline` ran to completion, validate "
            "the resulting `webapp_surface_map.json` against the "
            "handoff contract, and decide which specialist exploit "
            "agents to spawn next via `spawn_webapp_specialist_team`. "
            "Do NOT probe vulnerabilities yourself — your role is "
            "Decide-stage routing, not Act-stage execution."
        ),
        default_budget={
            "max_cost_usd": 0.30,
            "max_input_tokens": 60_000,
            "max_output_tokens": 15_000,
        },
    ),
    # ---- Code-target team (§8.1) ----
    SpecialistProfile(
        category="secret-agent",
        # `information_disclosure` is the closest existing skill;
        # gitleaks / trufflehog wiring lives in §8.1 future work.
        recommended_skills="information_disclosure",
        scope_addendum=(
            "You are the Secret-scan specialist. Run gitleaks / "
            "trufflehog / custom-pattern detection on the cloned "
            "repository. Output canonical findings with `category="
            "exposed_secret`, evidence (file:line + the redacted "
            "match), and `verification_status=pattern_match`. "
            "Do NOT probe runtime behaviour, dependencies, or SAST "
            "patterns — defer to peer specialists."
        ),
        default_budget={
            "max_cost_usd": 0.20,
            "max_input_tokens": 40_000,
            "max_output_tokens": 10_000,
        },
    ),
    SpecialistProfile(
        category="dependency-agent",
        # `source_aware_sast` enables the deps-aware code reasoning
        # used by `cve_lookup`-driven analysis.
        recommended_skills="source_aware_sast",
        scope_addendum=(
            "You are the Dependency / SBOM specialist. Build the "
            "SBOM (npm / pip / cargo / etc.), run `cve_lookup` / "
            "`nvd_lookup` per (package, version, ecosystem), emit "
            "`category=vulnerable_dependency` findings. Do NOT probe "
            "runtime behaviour or SAST patterns — defer."
        ),
        default_budget={
            "max_cost_usd": 0.20,
            "max_input_tokens": 40_000,
            "max_output_tokens": 10_000,
        },
    ),
    SpecialistProfile(
        category="sast-agent",
        recommended_skills="semgrep,source_aware_sast",
        scope_addendum=(
            "You are the SAST specialist. Run Semgrep + per-language "
            "packs. Emit pattern findings with `category=` matching "
            "the rule's CWE category. Don't run dependency scans or "
            "secret scans — those have their own specialists."
        ),
        default_budget={
            "max_cost_usd": 0.30,
            "max_input_tokens": 60_000,
            "max_output_tokens": 15_000,
        },
    ),
    # ---- Domain team (§8.3) ----
    SpecialistProfile(
        category="subdomain-takeover-specialist",
        recommended_skills="subdomain_takeover",
        scope_addendum=(
            "You are the Subdomain-takeover specialist. Use the "
            "60+ provider matrix in `subdomain_takeover_check` to "
            "identify dangling DNS records pointing at unclaimed "
            "third-party services. Do NOT probe other classes."
        ),
        default_budget={
            "max_cost_usd": 0.20,
            "max_input_tokens": 40_000,
            "max_output_tokens": 10_000,
        },
    ),
    # ---- IP/Network team (§8.4) ----
    SpecialistProfile(
        category="port-service-specialist",
        recommended_skills="nmap,naabu",
        scope_addendum=(
            "You are the Port / Service specialist. Probe assigned "
            "IP(s) via nmap or Shodan/Censys cache. Identify open "
            "ports, fingerprint service banners, match against "
            "`cve_lookup`. Don't probe web-app surfaces — defer."
        ),
        default_budget={
            "max_cost_usd": 0.20,
            "max_input_tokens": 40_000,
            "max_output_tokens": 10_000,
        },
    ),
    # ---- Validator (§7.1 / §17.1) ----
    SpecialistProfile(
        category="validator-agent",
        # Validator runs deterministic exploits; uses the same
        # business-logic-style reasoning skill the §15 plan-then-
        # execute mode also leans on.
        recommended_skills="business_logic",
        scope_addendum=(
            "You are the Validator. For each candidate finding "
            "supplied in your task, attempt a deterministic "
            "exploitation in an isolated context. Set "
            "`verification_status=verified` ONLY when the exploit "
            "fired and you observed the vulnerable response. Set "
            "`verification_status=could_not_verify` when the "
            "exploit was attempted but the response was ambiguous. "
            "DO NOT discover new candidates — your scope is "
            "verification of the supplied list."
        ),
        default_budget={
            "max_cost_usd": 1.00,
            "max_input_tokens": 100_000,
            "max_output_tokens": 30_000,
        },
        inherit_context_default=False,  # validator reasons fresh
    ),
)


SPECIALIST_REGISTRY: dict[str, SpecialistProfile] = {
    p.category: p for p in _SPECIALISTS
}


def get_specialist_profile(category: str | None) -> SpecialistProfile | None:
    """Return the registered profile for `category`, or None if
    `category` is unset / unknown. Match is case-insensitive on a
    canonicalised (lowercased, stripped) form."""
    if not category or not isinstance(category, str):
        return None
    key = category.strip().lower()
    if not key:
        return None
    return SPECIALIST_REGISTRY.get(key)


def list_specialist_categories() -> list[str]:
    """Return the sorted list of registered specialist categories.
    Useful for docs / wrapper UI."""
    return sorted(SPECIALIST_REGISTRY.keys())
