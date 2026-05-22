"""E2E Phase C — L2 orchestration tests.

Per `docs/E2E-test-proposal.md` §3.4. Each test exercises the REAL
Lead-orchestration code (`list_pending_findings`, dispatch budget
scaling, stealth-guidance rendering, prompt-addendum vocabulary)
against a real `Tracer` + real registry.

Mocks are limited to:
  * `_orchestrator()` for dispatch tests — we don't actually want to
    spawn an LLM specialist; we capture the args.
  * External telemetry side-effects (posthog, KG, KEV/campaign).

No mocks of L1.5 hooks, no mocks of the executor, no mocks of the
registry.
"""

from __future__ import annotations

import pytest

from strix.l15 import corroborator_ledger, hygiene_ledger, root_cause_ledger
from strix.l15.git_blame import clear_cache as _clear_blame_cache
from strix.l15.posture import (
    SecurityPosture,
    clear_cache as _clear_posture_cache,
    set_posture,
)
from strix.telemetry.tracer import Tracer


@pytest.fixture
def tracer(tmp_path, monkeypatch):
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(
        "strix.telemetry.tracer.posthog.finding", lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.telemetry.tracer._emit_kg_auto_for_finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.llm.kev_enrichment.resolve_kev_block", lambda **_k: {},
    )
    monkeypatch.setattr(
        "strix.llm.campaign_enrichment.resolve_campaign_block",
        lambda **_k: {"matched_pulse_count": 0, "matched_pulses": []},
    )
    # Make this tracer the global one so list_pending_findings finds it
    from strix.telemetry.tracer import set_global_tracer
    t = Tracer(run_name="e2e-phase-c")
    t._maybe_merge_into_existing_finding = lambda _r: None
    set_global_tracer(t)
    yield t
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()
    set_global_tracer(None)


# =========================================================================
# E2E-L2-1 — list_pending_findings ranks correctly
# =========================================================================

def test_list_pending_findings_ranks_by_l15_signals(tracer):
    """Emit 3 findings with varying surface_priority + exploitability +
    severity. Assert `list_pending_findings()` returns them in the
    correct order, noise hidden by default.

    Each finding must carry enough signal to avoid the exploitability
    auto-demote path (composite < 0.10). We do that by setting
    `verification_status=exploited` on the ones we want to surface —
    that pins both code_reachable and auth_bypassable to 1.0, putting
    composite squarely in the "leave" band.
    """
    # Critical surface, low severity — should rank FIRST (surface wins)
    tracer.add_vulnerability_report(
        title="Header on admin panel",
        severity="low",
        endpoint="https://app.example.com/admin/users",
        cwe="CWE-693",
        verification_status="exploited",
    )
    # Normal surface, critical severity — ranks below critical-surface
    tracer.add_vulnerability_report(
        title="Random API hit",
        severity="critical",
        endpoint="https://app.example.com/api/v1/products/42",
        cwe="CWE-89",
        verification_status="exploited",
    )
    # Low surface (static asset), high severity — should rank LAST
    tracer.add_vulnerability_report(
        title="Header on static page",
        severity="high",
        endpoint="https://app.example.com/static/main.css",
        cwe="CWE-693",
        verification_status="exploited",
    )

    from strix.tools.findings.list_findings import list_pending_findings
    out = list_pending_findings()
    assert out["status"] == "ok"
    rows = out["findings"]
    assert len(rows) >= 3, (
        f"all 3 visible findings must surface; got {len(rows)}"
    )
    # First row: critical surface (admin) — surface beats severity
    assert rows[0]["surface_priority"] == "critical"
    # Last visible row: low surface (static asset)
    visible_labels = [r["surface_priority"] for r in rows]
    assert visible_labels[-1] == "low"


def test_list_pending_findings_hides_noise(tracer):
    """noise=True and role=corroborator findings hidden by default;
    surfaced via include_demoted."""
    # Emit a normal finding
    tracer.add_vulnerability_report(
        title="Real finding",
        severity="high",
        endpoint="https://app.example.com/api/v1/users/1",
        cwe="CWE-89",
    )
    # Emit a SAST+DAST pair that the corroborator will demote the DAST
    # one to role=corroborator
    tracer.add_vulnerability_report(
        title="SAST sqli",
        severity="medium",
        cwe="CWE-89",
        endpoint="https://app.example.com/api/v1/search",
        discovery_source_tool="semgrep",
    )
    tracer.add_vulnerability_report(
        title="DAST sqli",
        severity="medium",
        cwe="CWE-89",
        endpoint="https://app.example.com/api/v1/search",
        discovery_source_tool="sqlmap",
    )

    from strix.tools.findings.list_findings import list_pending_findings
    out = list_pending_findings()
    assert out["demoted_hidden"] >= 1, (
        "at least the corroborator child must be hidden by default"
    )
    # include_demoted=True surfaces it
    out_all = list_pending_findings(include_demoted=True)
    assert out_all["shown"] > out["shown"]


# =========================================================================
# E2E-L2-2 — dispatch_specialist scales by surface_priority
# =========================================================================

def test_dispatch_specialist_scales_by_surface(monkeypatch):
    """Real `dispatch_specialist` call against a critical-surface
    target — captured `max_iterations` reflects the surface_priority
    × hygiene combined multiplier.
    """
    from strix.l15.hygiene import hygiene_ledger as _hyg
    _hyg.clear()  # neutral hygiene → 0.6× (high score on empty ledger)

    captured: dict = {}

    def _capture_dispatch(**kwargs):
        captured.update(kwargs)
        return {"status": "PASSED", "iterations_used": 0}

    import strix.tools.workflow.specialist_dispatch as M
    monkeypatch.setattr(
        M, "_orchestrator",
        lambda: type("F", (), {
            "dispatch_specialist": staticmethod(_capture_dispatch),
        })(),
    )

    from strix.tools.workflow.specialist_dispatch import dispatch_specialist
    dispatch_specialist(
        category="auth",
        objective="probe admin panel",
        target="https://app.example.com/admin/users",
    )

    # Critical surface (3.0) × tidy hygiene (0.6) = 1.8 → 50 × 1.8 = 90
    assert captured["max_iterations"] == 90


# =========================================================================
# E2E-L2-5 — stealth-payload addendum renders into specialist prompt
# =========================================================================

def test_stealth_addendum_renders_into_sqli_specialist_prompt():
    """Plant a WAF-flagged posture; build the SQLi specialist's system
    prompt; assert the STEALTH MODE block appears in the rendered
    prompt with the rate-limit info populated.
    """
    set_posture(SecurityPosture(
        target="https://wafd.example.com",
        waf_detected=True,
        waf_vendor="cloudflare",
        stealth_mode_required=True,
        rate_limit_rps=14,
    ))

    from strix.agents.specialist_orchestrator import (
        _build_system_prompt,
        get_profile,
    )

    prompt = _build_system_prompt(
        profile=get_profile("sqli"),
        scope_context=None,
        relevant_findings=None,
        dispatch_target="https://wafd.example.com",
    )

    assert "STEALTH MODE" in prompt
    assert "Cloudflare" in prompt or "TIME-BASED" in prompt
    # 14 rps observed → cap at 7
    assert "7 rps" in prompt

    # No stealth when posture clean
    _clear_posture_cache()
    set_posture(SecurityPosture(
        target="https://plain.example.com",
        waf_detected=False,
        stealth_mode_required=False,
    ))
    prompt_clean = _build_system_prompt(
        profile=get_profile("sqli"),
        scope_context=None,
        relevant_findings=None,
        dispatch_target="https://plain.example.com",
    )
    assert "STEALTH MODE" not in prompt_clean
    _clear_posture_cache()


# =========================================================================
# F.3 — dispatch_specialist_batch threads dispatch_target for stealth
# =========================================================================

class _BuildPromptIntercepted(Exception):
    """Sentinel raised by the intercepted `_build_system_prompt` so
    we exit the batch dispatch path cleanly after capturing the
    `dispatch_target` arg."""


def test_dispatch_batch_uses_first_target_for_stealth_guidance(monkeypatch):
    """REAL batch-path test: invoke `dispatch_specialist_batch(...)`
    and intercept `_build_system_prompt` to capture the
    `dispatch_target` it receives.

    The batch path's wiring is `_batch_target = pending[0].get("target")`
    in `dispatch_specialist_batch`. A regression that sets
    `_batch_target = None` (i.e. doesn't pick from `pending`) must
    be caught by this test. The previous version of this test bypassed
    `dispatch_specialist_batch` and called `_build_system_prompt`
    directly — which always passed regardless of the batch wiring.
    Audit caught this; this version fixes it.
    """
    from strix.l15.posture import (
        SecurityPosture,
        clear_cache as _clear_posture_cache,
        set_posture,
    )
    import strix.agents.specialist_orchestrator as so

    _clear_posture_cache()
    set_posture(SecurityPosture(
        target="https://wafd.example.com/api/v1/foo",
        waf_detected=True, waf_vendor="cloudflare",
        stealth_mode_required=True, rate_limit_rps=10,
    ))

    captured: dict = {"dispatch_target": "NOT_CAPTURED"}

    def _intercept(**kwargs):
        captured["dispatch_target"] = kwargs.get("dispatch_target")
        # Raise to bail out of the batch path cleanly; we only care
        # about what arg was passed.
        raise _BuildPromptIntercepted

    monkeypatch.setattr(so, "_build_system_prompt", _intercept)

    from strix.tools.workflow.specialist_dispatch import (
        dispatch_specialist_batch,
    )

    try:
        dispatch_specialist_batch(
            category="sqli",
            objectives=[
                {
                    "target": "https://wafd.example.com/api/v1/foo",
                    "objective": "probe foo",
                },
                {
                    "target": "https://different.example.com/bar",
                    "objective": "probe bar",
                },
            ],
        )
    except _BuildPromptIntercepted:
        pass  # expected

    # The batch path's `_batch_target = pending[0].get("target")`
    # MUST propagate the FIRST target to `_build_system_prompt`.
    # If a regression sets `_batch_target = None`, this assertion
    # fails.
    assert captured["dispatch_target"] == (
        "https://wafd.example.com/api/v1/foo"
    ), (
        f"batch dispatch_target threading broken; got "
        f"{captured['dispatch_target']!r}"
    )
    _clear_posture_cache()


# =========================================================================
# E2E-L2-6 — Lead prompt addendum mentions L1.5 vocabulary
# =========================================================================

def test_lead_prompt_addendum_contains_l15_vocabulary():
    """The Lead system prompt must explain every L1.5 field name so
    the LLM knows what to prioritize on. Per E2E-test-proposal.md §3.4.
    """
    from strix.agents.lead_agent.lead_agent import _LEAD_SYSTEM_PROMPT_ADDENDUM

    addendum = _LEAD_SYSTEM_PROMPT_ADDENDUM
    # Every L1.5 field the Lead reads must be named somewhere in the prompt
    required_terms = (
        "surface_priority",
        "exploitability",
        "corroborated_by",
        "pending_confirmations",
        "triggered_probes",
        "git_blame",
        "list_pending_findings",
        "drain_amplify_queue",
    )
    for term in required_terms:
        assert term in addendum, (
            f"Lead prompt addendum missing L1.5 vocabulary term: {term!r}"
        )
    # Also confirm the prioritization rule + amplify rule are present
    assert "PRIORITIZATION RULE" in addendum
    assert "AUTO-AMPLIFY" in addendum
