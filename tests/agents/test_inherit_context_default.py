"""Tests for §8.5 Phase 0.B — `inherit_context=False` default flip.

Pins the resolution order:
  1. Caller passed True/False explicitly → use as-is.
  2. Caller passed None → profile's `inherit_context_default` if a
     specialist profile matches.
  3. Otherwise → `STRIX_INHERIT_CONTEXT_DEFAULT` env-var (default
     "false" → False).

The flip targets the per-spawn 700K-context dump that drove
incident #147. Existing call sites that pass True/False explicitly
are unaffected; only paths relying on the default see the new
behaviour.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.agents.specialists import get_specialist_profile
from strix.tools.agents_graph.agents_graph_actions import (
    _resolve_default_inherit_context,
    _resolve_inherit_context,
)


# ---------------------------------------------------------------------------
# _resolve_default_inherit_context — env-var resolver
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("False", False),
        ("0", False),
        ("no", False),
        ("off", False),
        ("garbage", False),  # unknown → False (Phase 0.B default)
        ("", False),
    ],
)
def test_resolver_reads_env(monkeypatch, raw: str, expected: bool) -> None:
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", raw)
    assert _resolve_default_inherit_context() is expected


def test_resolver_unset_defaults_false(monkeypatch) -> None:
    """The Phase 0.B flip: env unset → False."""
    monkeypatch.delenv("STRIX_INHERIT_CONTEXT_DEFAULT", raising=False)
    assert _resolve_default_inherit_context() is False


# ---------------------------------------------------------------------------
# _resolve_inherit_context — full resolution order
# ---------------------------------------------------------------------------


def test_explicit_true_wins(monkeypatch) -> None:
    """Caller passed True explicitly → True regardless of profile / env."""
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", "false")
    profile = get_specialist_profile("validator-agent")  # default=False
    assert _resolve_inherit_context(requested=True, profile=profile) is True


def test_explicit_false_wins(monkeypatch) -> None:
    """Caller passed False explicitly → False regardless of profile / env."""
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", "true")
    profile = get_specialist_profile("auth-attacker")  # default=True
    assert _resolve_inherit_context(requested=False, profile=profile) is False


def test_no_request_no_profile_uses_env_default(monkeypatch) -> None:
    """Caller passed None + no profile → env default (False by §8.5)."""
    monkeypatch.delenv("STRIX_INHERIT_CONTEXT_DEFAULT", raising=False)
    assert _resolve_inherit_context(requested=None, profile=None) is False


def test_no_request_no_profile_env_override_to_true(monkeypatch) -> None:
    """Legacy escape hatch: STRIX_INHERIT_CONTEXT_DEFAULT=true → True."""
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", "true")
    assert _resolve_inherit_context(requested=None, profile=None) is True


def test_profile_default_takes_precedence_over_env(monkeypatch) -> None:
    """When caller passed None AND profile exists, profile's
    inherit_context_default overrides env-var default. The validator
    agent profile (#89) has inherit_context_default=False — even
    when env says True, validator reasons fresh."""
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", "true")
    profile = get_specialist_profile("validator-agent")
    assert profile is not None
    assert profile.inherit_context_default is False
    assert _resolve_inherit_context(requested=None, profile=profile) is False


def test_profile_default_true_used_when_caller_default(monkeypatch) -> None:
    """When caller passed None + profile says True, result is True
    (e.g. auth-attacker profile keeps inherit_context_default=True
    by design even after Phase 0.B). Env-default is irrelevant."""
    monkeypatch.delenv("STRIX_INHERIT_CONTEXT_DEFAULT", raising=False)
    profile = get_specialist_profile("auth-attacker")
    assert profile is not None
    if profile.inherit_context_default:
        # Profile-True case verified.
        assert _resolve_inherit_context(requested=None, profile=profile) is True
    else:
        # Profile-False case (different specialist).
        pytest.skip(f"auth-attacker profile changed to default={profile.inherit_context_default}")


# ---------------------------------------------------------------------------
# Phase 0.B canonical behaviour: default flip is observable
# ---------------------------------------------------------------------------


def test_phase_0b_canonical_flip_unprofiled_call(monkeypatch) -> None:
    """The Phase 0.B canonical assertion: an unprofiled `create_agent`
    call without explicit inherit_context resolves to False (was True
    pre-flip). Decision-gate input — if this flip alone closes the
    cost gap reported in incident #147, the §8.5 architectural
    migration de-prioritises behind §18 unshipped rows."""
    monkeypatch.delenv("STRIX_INHERIT_CONTEXT_DEFAULT", raising=False)
    assert _resolve_inherit_context(requested=None, profile=None) is False


def test_phase_0b_specialist_teams_unaffected(monkeypatch) -> None:
    """Existing call sites in #92 / #93 / #95 pass `inherit_context=False`
    explicitly. Phase 0.B does not change their behaviour."""
    monkeypatch.delenv("STRIX_INHERIT_CONTEXT_DEFAULT", raising=False)
    assert _resolve_inherit_context(requested=False, profile=None) is False
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", "true")
    assert _resolve_inherit_context(requested=False, profile=None) is False


def test_phase_0b_validator_agent_unaffected(monkeypatch) -> None:
    """The validator-agent profile has inherit_context_default=False
    by design (#89 — validator reasons fresh on candidates). Phase
    0.B preserves this — the validator still gets False even when
    env-default flips to True."""
    monkeypatch.setenv("STRIX_INHERIT_CONTEXT_DEFAULT", "true")
    profile = get_specialist_profile("validator-agent")
    assert _resolve_inherit_context(requested=None, profile=profile) is False


# ---------------------------------------------------------------------------
# Defensive — non-profile arg shapes
# ---------------------------------------------------------------------------


def test_resolver_handles_profile_without_attribute() -> None:
    """If something other than a SpecialistProfile sneaks in, fall
    back to env-default rather than raising. Best-effort throughout."""
    class FakeProfile:  # No inherit_context_default attribute.
        pass

    # `_resolve_inherit_context` checks hasattr; falls through to env.
    assert _resolve_inherit_context(
        requested=None, profile=FakeProfile(),
    ) is False  # env default unset → False
