"""Tests for the §8 model fallback chain.

These tests pin:

  * Provider priority parsing from `STRIX_AUTH_PRIORITY`
  * Tier resolution from explicit arg, env override, role default, fallback
  * Credential detection — only providers with API keys in env make the chain
  * Multi-step traversal — `next_link_after` walks past the current model
  * Kill switch (`STRIX_FALLBACK_DISABLED`)
  * Telemetry shape (`get_chain_summary`)
  * Defensive: malformed env values fall back to defaults
"""

from __future__ import annotations

import pytest

from strix.llm import fallback_chain as fc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_all(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "STRIX_FALLBACK_DISABLED",
        "STRIX_AUTH_PRIORITY",
        "STRIX_FALLBACK_TIER",
        "ANTHROPIC_API_KEY",
        "STRIX_ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "STRIX_OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "STRIX_GEMINI_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        monkeypatch.delenv(key, raising=False)
    for role in ("RECON", "SQLI", "TAINT", "LEAD"):
        monkeypatch.delenv(f"STRIX_FALLBACK_TIER_{role}", raising=False)


# ---------------------------------------------------------------------------
# Priority + tier parsing
# ---------------------------------------------------------------------------


def test_default_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    assert fc._read_priority() == ("anthropic", "openai", "google")


def test_priority_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_AUTH_PRIORITY", "openai, google,anthropic")
    assert fc._read_priority() == ("openai", "google", "anthropic")


def test_priority_drops_unknown_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown providers are silently filtered, not the user-facing
    crash."""
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_AUTH_PRIORITY", "anthropic, unknown_provider, openai")
    assert fc._read_priority() == ("anthropic", "openai")


def test_priority_all_unknown_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_AUTH_PRIORITY", "bogus,fake")
    # All filtered → fall through to defaults.
    assert fc._read_priority() == ("anthropic", "openai", "google")


def test_default_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    assert fc._read_default_tier() == "MID"


def test_default_tier_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_FALLBACK_TIER", "high")  # case-insensitive
    assert fc._read_default_tier() == "HIGH"


def test_default_tier_invalid_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_FALLBACK_TIER", "ULTRA")
    assert fc._read_default_tier() == "MID"


# ---------------------------------------------------------------------------
# Role-based tier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role,expected", [
    ("taint", "HIGH"),
    ("verifier", "HIGH"),
    ("sqli", "MID"),
    ("xss", "MID"),
    ("recon", "LOW"),
    ("fingerprint", "LOW"),
])
def test_role_tier_defaults(
    role: str, expected: fc.Tier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    assert fc._read_role_tier(role) == expected


def test_role_tier_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Env-var override beats the built-in default."""
    _clear_all(monkeypatch)
    # 'recon' default is LOW; override to HIGH.
    monkeypatch.setenv("STRIX_FALLBACK_TIER_RECON", "high")
    assert fc._read_role_tier("recon") == "HIGH"


def test_role_tier_with_hyphen_converts_to_underscore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`sqli-validator` → `STRIX_FALLBACK_TIER_SQLI_VALIDATOR`."""
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_FALLBACK_TIER_SQLI_VALIDATOR", "low")
    assert fc._read_role_tier("sqli-validator") == "LOW"


def test_role_tier_unknown_role_uses_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_FALLBACK_TIER", "HIGH")
    assert fc._read_role_tier("totally_unknown_role") == "HIGH"


def test_role_tier_none_role_uses_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    assert fc._read_role_tier(None) == "MID"


# ---------------------------------------------------------------------------
# Credential detection
# ---------------------------------------------------------------------------


def test_credential_present_anthropic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    assert not fc._credential_present("anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert fc._credential_present("anthropic")


def test_credential_present_alt_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strix-prefixed alt env var also counts."""
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_ANTHROPIC_API_KEY", "sk-test")
    assert fc._credential_present("anthropic")


def test_credential_present_unknown_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    assert not fc._credential_present("not_a_real_provider")


# ---------------------------------------------------------------------------
# Chain construction
# ---------------------------------------------------------------------------


def test_chain_empty_when_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    chain = fc.pick_chain()
    assert chain == []


def test_chain_filters_to_credentialed_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-o")
    # google not set
    chain = fc.pick_chain()
    providers = [link.provider for link in chain]
    assert providers == ["anthropic", "openai"]


def test_chain_respects_priority_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_AUTH_PRIORITY", "google,openai,anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-o")
    monkeypatch.setenv("GEMINI_API_KEY", "sk-g")
    chain = fc.pick_chain()
    assert [link.provider for link in chain] == ["google", "openai", "anthropic"]


def test_chain_picks_tier_models(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    chain_high = fc.pick_chain(tier="HIGH")
    chain_low = fc.pick_chain(tier="LOW")
    assert chain_high[0].model != chain_low[0].model
    assert chain_high[0].tier == "HIGH"
    assert chain_low[0].tier == "LOW"


def test_chain_role_drives_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    chain = fc.pick_chain(role="taint")
    assert chain[0].tier == "HIGH"

    chain_recon = fc.pick_chain(role="recon")
    assert chain_recon[0].tier == "LOW"


def test_chain_include_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """`include_unavailable=True` keeps all priority entries — needed
    for telemetry / chain-visualisation."""
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    chain = fc.pick_chain(include_unavailable=True)
    assert len(chain) == 3
    assert chain[0].credential_present is True
    assert all(not link.credential_present for link in chain[1:])


# ---------------------------------------------------------------------------
# next_link_after — multi-step traversal
# ---------------------------------------------------------------------------


def test_next_link_advances_through_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_AUTH_PRIORITY", "anthropic,openai,google")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-o")
    monkeypatch.setenv("GEMINI_API_KEY", "sk-g")

    chain = fc.pick_chain()
    assert len(chain) == 3

    # Step from anthropic → openai
    nxt = fc.next_link_after(chain[0].model)
    assert nxt is not None
    assert nxt.provider == "openai"

    # Step from openai → google
    nxt2 = fc.next_link_after(chain[1].model)
    assert nxt2 is not None
    assert nxt2.provider == "google"

    # Last link → None (chain exhausted)
    nxt3 = fc.next_link_after(chain[2].model)
    assert nxt3 is None


def test_next_link_unknown_model_returns_chain_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the caller's `current_model` isn't in the chain, return the
    head — gives them a way to bootstrap into the chain."""
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    nxt = fc.next_link_after("vertex_ai/some-private-model")
    assert nxt is not None
    assert nxt.provider == "anthropic"


def test_next_link_empty_chain_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    # No credentials → empty chain.
    assert fc.next_link_after("anthropic/claude-anything") is None


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    monkeypatch.setenv("STRIX_FALLBACK_DISABLED", val)
    assert fc.pick_chain() == []
    assert fc.next_link_after("anthropic/claude-x") is None


def test_kill_switch_unset_is_falsy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    assert not fc.is_fallback_disabled()


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def test_chain_summary_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-a")
    summary = fc.get_chain_summary(role="sqli")
    assert summary["enabled"] is True
    assert summary["role"] == "sqli"
    assert summary["tier"] == "MID"
    assert "priority" in summary
    links = summary["links"]
    assert isinstance(links, list)
    assert links and links[0]["provider"] == "anthropic"


def test_chain_summary_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_all(monkeypatch)
    monkeypatch.setenv("STRIX_FALLBACK_DISABLED", "1")
    summary = fc.get_chain_summary()
    assert summary["enabled"] is False
    assert summary["links"] == []


# ---------------------------------------------------------------------------
# ChainLink — frozen dataclass invariants
# ---------------------------------------------------------------------------


def test_chain_link_is_immutable() -> None:
    link = fc.ChainLink(
        provider="anthropic",
        model="anthropic/claude-sonnet-4-5-20250929",
        tier="MID",
        credential_present=True,
    )
    with pytest.raises((AttributeError, Exception)):
        link.provider = "openai"  # type: ignore[misc]
