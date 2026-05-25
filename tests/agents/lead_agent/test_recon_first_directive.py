"""iter-32.2 — recon-first directive in the Lead's system prompt.

These tests verify the iter-32.2 prompt addendum that steers the L2
Lead agent to invoke recon tools before specialist scan_* tools.
Without this, the iter-32.1 endpoint-recording wiring is moot (the
agent never invokes the wired tools).
"""

from __future__ import annotations

import re

from strix.agents.lead_agent.lead_agent import (
    _RECON_FIRST_DIRECTIVE,
    _LEAD_SYSTEM_PROMPT_ADDENDUM,
)


def test_recon_first_directive_exists():
    """The directive must be defined as a non-empty string."""
    assert isinstance(_RECON_FIRST_DIRECTIVE, str)
    assert len(_RECON_FIRST_DIRECTIVE) > 100  # at least a paragraph


def test_directive_is_woven_into_final_addendum():
    """Adding the directive constant doesn't help if it's not
    actually included in the assembled addendum."""
    assert _RECON_FIRST_DIRECTIVE in _LEAD_SYSTEM_PROMPT_ADDENDUM


def test_directive_mentions_each_target_type():
    """All three primary target types must have explicit recon
    guidance so the LLM knows which tool to pick first."""
    text = _RECON_FIRST_DIRECTIVE.lower()
    for target in ("web_application", "api", "ip"):
        assert target in text, f"recon directive missing target type: {target}"


def test_directive_names_the_wired_tools():
    """The directive must reference the actual recon tools we wired
    in iter-32.1 so the LLM picks the ones whose discoveries flow
    into workflow_state."""
    text = _RECON_FIRST_DIRECTIVE
    for tool in ("crawl_with_katana", "openapi_spec_ingest", "bfs_crawl"):
        assert tool in text, f"recon directive missing wired tool: {tool}"


def test_directive_warns_against_zero_endpoint_scan_attempts():
    """Counter-pattern: invoking scan_* with raw target URL alone.
    The directive must explicitly flag this to prevent the failure
    mode observed in the v3 standard-mode bench run."""
    text = _RECON_FIRST_DIRECTIVE.lower()
    assert "counter-pattern" in text or "avoid" in text
    # Must mention scan_sqli or scan_xss as the wrong tool to call first
    assert any(t in text for t in ("scan_sqli", "scan_xss"))


def test_directive_references_workflow_status_check():
    """After recon, the LLM should query workflow_status to verify
    the inventory is non-empty. The directive enforces this loop."""
    text = _RECON_FIRST_DIRECTIVE.lower()
    assert "workflow_status" in text


def test_directive_references_iter_32_2_origin():
    """The marker must reference the iter so future maintainers can
    locate the rationale."""
    # The IDENTIFIER iter-32.2 lives in the comment block adjacent to
    # the directive (within the addendum-assembly point at minimum).
    import strix.agents.lead_agent.lead_agent as mod
    src = open(mod.__file__).read()
    assert "iter-32.2" in src


def test_directive_appears_BEFORE_fan_out_in_addendum():
    """Sequencing matters: recon-first must appear earlier in the
    prompt than fan-out, since fan-out only makes sense AFTER recon
    has produced an inventory."""
    pos_recon = _LEAD_SYSTEM_PROMPT_ADDENDUM.find(_RECON_FIRST_DIRECTIVE)
    fan_out_marker = "WEB ENDPOINTS DESERVE FAN-OUT"
    pos_fanout = _LEAD_SYSTEM_PROMPT_ADDENDUM.find(fan_out_marker)
    assert pos_recon != -1
    assert pos_fanout != -1
    assert pos_recon < pos_fanout, (
        "recon-first directive must precede fan-out directive in the addendum"
    )


# ---------------------------------------------------------------------------
# Anti-overfit: directive must NOT reference SUT-specific values
# ---------------------------------------------------------------------------

def test_directive_has_no_sut_specific_references():
    """The recon directive applies to ANY target type, not just the
    fixtures we test against. SUT-specific identifiers in the
    directive would couple the lead's behavior to one app."""
    text = _RECON_FIRST_DIRECTIVE.lower()
    forbidden = (
        "bkimminich",        # Juice Shop author handle
        "juice-sh.op",       # Juice Shop public domain
        "juice-shop",
        "/rest/user/login",  # Juice Shop specific path
        "/api/baskets",      # Juice Shop specific path
        "vampi",             # VAmPI fixture name
        "erev0s",            # VAmPI author
        "/users/v1/_debug",  # VAmPI specific path
    )
    for tok in forbidden:
        assert tok not in text, (
            f"directive contains SUT-specific value: {tok!r}"
        )
