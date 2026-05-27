"""iter-Q5.13 — customer-context per-scan config.

Per CLAUDE.md §1.5.1 (L2 audience needs customer-aware
prioritization) and the consolidated Q5 §7 Gap 1.

The customer_context dict in scan_config gets rendered into the
LLM's system_prompt_context so the lead's `customer_priority`
decisions on `create_vulnerability_report` (Q5.11) have real
signal rather than being a guess.
"""

from __future__ import annotations

import pytest

from strix.agents.StrixAgent.strix_agent import StrixAgent


def _scan_config(customer_context=None, targets=None):
    """Minimal scan_config shape."""
    cfg = {
        "targets": targets or [
            {"type": "web_application", "details": {"target_url": "https://x"}},
        ],
    }
    if customer_context is not None:
        cfg["customer_context"] = customer_context
    return cfg


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_customer_context_surfaces_in_system_prompt_context() -> None:
    cc = {
        "industry": "fintech",
        "compliance_targets": ["SOC2", "PCI-DSS"],
        "critical_assets": ["/api/transfer", "/api/balance"],
        "threat_model": "external_attacker",
    }
    out = StrixAgent._build_system_scope_context(_scan_config(cc))
    assert "customer_context" in out
    assert out["customer_context"]["industry"] == "fintech"
    assert out["customer_context"]["compliance_targets"] == [
        "SOC2", "PCI-DSS",
    ]
    assert out["customer_context"]["critical_assets"] == [
        "/api/transfer", "/api/balance",
    ]
    assert out["customer_context"]["threat_model"] == "external_attacker"


def test_partial_customer_context_works() -> None:
    """Only some keys supplied — the rest don't surface."""
    cc = {"industry": "healthcare"}
    out = StrixAgent._build_system_scope_context(_scan_config(cc))
    assert out["customer_context"] == {"industry": "healthcare"}


def test_all_documented_keys_supported() -> None:
    cc = {
        "industry": "saas",
        "compliance_targets": ["GDPR"],
        "critical_assets": [],
        "threat_model": "insider",
        "data_classifications": ["PII", "PHI"],
        "regulatory_jurisdiction": "EU",
    }
    out = StrixAgent._build_system_scope_context(_scan_config(cc))
    surfaced = out["customer_context"]
    assert "data_classifications" in surfaced
    assert "regulatory_jurisdiction" in surfaced


# ---------------------------------------------------------------------------
# Absent / empty
# ---------------------------------------------------------------------------


def test_absent_customer_context_omits_block() -> None:
    """Without customer_context, the system prompt has no
    customer_context key — falls back to intrinsic severity."""
    out = StrixAgent._build_system_scope_context(_scan_config())
    assert "customer_context" not in out


def test_empty_customer_context_dict_omits_block() -> None:
    out = StrixAgent._build_system_scope_context(_scan_config({}))
    assert "customer_context" not in out


def test_non_dict_customer_context_ignored() -> None:
    """Malformed input doesn't crash the context build."""
    out = StrixAgent._build_system_scope_context(
        _scan_config("not a dict"),  # type: ignore[arg-type]
    )
    assert "customer_context" not in out


# ---------------------------------------------------------------------------
# Anti-junk filter — only documented keys pass through
# ---------------------------------------------------------------------------


def test_undocumented_keys_filtered_out() -> None:
    """Operators can't dump arbitrary junk into the system prompt
    via customer_context — only the documented allowlist passes."""
    cc = {
        "industry": "fintech",  # valid
        "secret_api_key": "AKIA...",  # not allowlisted — must NOT surface
        "internal_notes": "do not share",  # same
        "ARBITRARY_FIELD": "x",  # same
    }
    out = StrixAgent._build_system_scope_context(_scan_config(cc))
    surfaced = out["customer_context"]
    assert "industry" in surfaced
    assert "secret_api_key" not in surfaced
    assert "internal_notes" not in surfaced
    assert "ARBITRARY_FIELD" not in surfaced


def test_only_junk_keys_omits_block() -> None:
    """If customer_context has only undocumented keys, the block is
    omitted entirely (post-filter empty → omit)."""
    cc = {"randomstuff": "junk"}
    out = StrixAgent._build_system_scope_context(_scan_config(cc))
    assert "customer_context" not in out


# ---------------------------------------------------------------------------
# Doesn't break the existing surface
# ---------------------------------------------------------------------------


def test_authorized_targets_still_present() -> None:
    """Customer_context is additive — the existing scan-scope surface
    must stay intact."""
    out = StrixAgent._build_system_scope_context(
        _scan_config({"industry": "saas"}),
    )
    assert "authorized_targets" in out
    assert "user_instructions_do_not_expand_scope" in out
