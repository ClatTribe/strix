"""Tests for §8.5 Phase 0.A — cost-bisection telemetry.

Pins the per-component token classification + the aggregator surface.
Decision-gate input for the single-lead-agent migration: when these
numbers show `conversation_tokens` dominating, the §8.5 Phase 0.B
default-flip is the cheapest fix.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.llm.token_breakdown import (
    TOKEN_BREAKDOWN_SCHEMA_VERSION,
    breakdown_messages,
)


# ---------------------------------------------------------------------------
# Schema invariant
# ---------------------------------------------------------------------------


def test_schema_version_pinned() -> None:
    """Bumping signals breaking change to wrapper aggregators."""
    assert TOKEN_BREAKDOWN_SCHEMA_VERSION == 1


def test_breakdown_returns_complete_schema() -> None:
    """Every documented field present even on empty input — aggregator
    never has to handle absence."""
    out = breakdown_messages([], model="gpt-5.4")
    for field in (
        "schema_version", "system_tokens", "agent_identity_tokens",
        "conversation_tokens", "total_input_tokens_estimated", "message_count",
    ):
        assert field in out, f"missing field {field!r}"


# ---------------------------------------------------------------------------
# Classification rules
# ---------------------------------------------------------------------------


def test_system_message_classified_as_system() -> None:
    msgs = [{"role": "system", "content": "You are a security agent. " * 50}]
    out = breakdown_messages(msgs, model="gpt-5.4")
    assert out["system_tokens"] > 0
    assert out["agent_identity_tokens"] == 0
    assert out["conversation_tokens"] == 0


def test_agent_identity_block_classified_separately() -> None:
    """The `<agent_identity>` block prepended by `_prepare_messages`
    must be classified as agent_identity, NOT as conversation."""
    msgs = [
        {"role": "system", "content": "system prompt content"},
        {
            "role": "user",
            "content": (
                "<agent_identity>\n"
                "<meta>Internal</meta>\n"
                "<agent_name>auth-attacker-1</agent_name>\n"
                "<agent_id>agent_4f3a2c1b</agent_id>\n"
                "</agent_identity>"
            ),
        },
        {"role": "user", "content": "actual user task"},
    ]
    out = breakdown_messages(msgs, model="gpt-5.4")
    assert out["system_tokens"] > 0
    assert out["agent_identity_tokens"] > 0
    assert out["conversation_tokens"] > 0


def test_user_messages_without_identity_marker_are_conversation() -> None:
    msgs = [
        {"role": "user", "content": "do a security scan"},
        {"role": "assistant", "content": "starting scan..."},
        {"role": "user", "content": "check the auth flow"},
    ]
    out = breakdown_messages(msgs, model="gpt-5.4")
    assert out["agent_identity_tokens"] == 0
    assert out["conversation_tokens"] > 0


def test_total_is_sum_of_components() -> None:
    msgs = [
        {"role": "system", "content": "system content"},
        {"role": "user", "content": "<agent_identity><agent_id>x</agent_id></agent_identity>"},
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "response"},
    ]
    out = breakdown_messages(msgs, model="gpt-5.4")
    assert (
        out["total_input_tokens_estimated"]
        == out["system_tokens"] + out["agent_identity_tokens"] + out["conversation_tokens"]
    )


def test_message_count_excludes_empty_content() -> None:
    msgs = [
        {"role": "system", "content": "system content"},
        {"role": "user", "content": ""},  # skipped — empty
        {"role": "user", "content": "task"},
    ]
    out = breakdown_messages(msgs, model="gpt-5.4")
    assert out["message_count"] == 2


# ---------------------------------------------------------------------------
# Anthropic cache_control list-form handling
# ---------------------------------------------------------------------------


def test_handles_anthropic_cache_control_content_form() -> None:
    """When `_add_cache_control` wraps system content in a list, the
    classifier must still extract the text and classify correctly."""
    msgs = [
        {
            "role": "system",
            "content": [
                {"type": "text", "text": "system prompt content here", "cache_control": {"type": "ephemeral"}},
            ],
        },
    ]
    out = breakdown_messages(msgs, model="claude-sonnet-4-6")
    assert out["system_tokens"] > 0


# ---------------------------------------------------------------------------
# Defensive behaviour
# ---------------------------------------------------------------------------


def test_handles_malformed_messages_without_raising() -> None:
    """Telemetry is best-effort. Malformed inputs must not raise."""
    msgs: list[Any] = [
        None,                                       # not a dict
        {"role": "system"},                          # missing content
        {"content": "no role"},                     # missing role → conversation
        {"role": "user", "content": None},           # None content → 0 tokens
        {"role": "user", "content": 12345},          # non-string content
    ]
    out = breakdown_messages(msgs, model="gpt-5.4")
    assert out["schema_version"] == TOKEN_BREAKDOWN_SCHEMA_VERSION


def test_handles_unknown_model_via_fallback_estimator() -> None:
    """When `litellm.token_counter` fails, fall back to chars/4."""
    msgs = [{"role": "system", "content": "x" * 400}]  # ~100 tokens via fallback
    out = breakdown_messages(msgs, model="not-a-real-model/xyz")
    # Either the litellm counter handles unknown gracefully, or fallback fires.
    # Either way: non-zero, no exception.
    assert out["system_tokens"] > 0


# ---------------------------------------------------------------------------
# Aggregator on Tracer
# ---------------------------------------------------------------------------


def test_token_breakdown_summary_empty_when_no_events(tmp_path, monkeypatch) -> None:
    """When events.jsonl has no `llm.token_breakdown` events, summary
    returns the empty shape (zeros) — never raises."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")

    t = Tracer("breakdown-test")
    summary = t.token_breakdown_summary()
    assert summary["call_count"] == 0
    assert summary["totals"]["system_tokens"] == 0
    assert summary["component_fractions"]["system_fraction"] == 0.0
    assert summary["cache_hit_ratio_run"] == 0.0


def test_token_breakdown_summary_aggregates_emitted_events(tmp_path, monkeypatch) -> None:
    """Emit two synthetic `llm.token_breakdown` events; verify the
    aggregator returns correct per-component totals + cache-hit ratio
    + per-agent breakdown."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")

    t = Tracer("breakdown-test")
    # Emit two synthetic events directly via _emit_event.
    t._emit_event(
        "llm.token_breakdown",
        payload={
            "schema_version": 1,
            "model": "gpt-5.4",
            "agent_id": "lead",
            "agent_name": "lead",
            "system_tokens": 50_000,
            "agent_identity_tokens": 100,
            "conversation_tokens": 20_000,
            "total_input_tokens_estimated": 70_100,
            "message_count": 8,
            "measured_input_tokens": 71_000,
            "measured_output_tokens": 500,
            "measured_cached_tokens": 40_000,
            "measured_cost_usd": 0.025,
            "cache_hit_ratio": 0.5634,
        },
    )
    t._emit_event(
        "llm.token_breakdown",
        payload={
            "schema_version": 1,
            "model": "gpt-5.4",
            "agent_id": "spec-1",
            "agent_name": "xss-specialist-1",
            "system_tokens": 30_000,
            "agent_identity_tokens": 80,
            "conversation_tokens": 15_000,
            "total_input_tokens_estimated": 45_080,
            "message_count": 5,
            "measured_input_tokens": 45_500,
            "measured_output_tokens": 300,
            "measured_cached_tokens": 25_000,
            "measured_cost_usd": 0.012,
            "cache_hit_ratio": 0.5495,
        },
    )

    summary = t.token_breakdown_summary()
    assert summary["call_count"] == 2

    totals = summary["totals"]
    assert totals["system_tokens"] == 80_000
    assert totals["agent_identity_tokens"] == 180
    assert totals["conversation_tokens"] == 35_000
    assert totals["total_input_tokens_estimated"] == 115_180
    assert totals["measured_input_tokens"] == 116_500
    assert totals["measured_cached_tokens"] == 65_000
    assert totals["measured_cost_usd"] == pytest.approx(0.037, abs=1e-6)

    # Component fractions sum to ~1.0 (modulo rounding).
    fractions = summary["component_fractions"]
    assert sum(fractions.values()) == pytest.approx(1.0, abs=0.001)
    # System dominates in both events.
    assert fractions["system_fraction"] > fractions["conversation_fraction"]

    # Per-agent breakdown.
    per_agent = summary["per_agent"]
    assert "lead" in per_agent
    assert "xss-specialist-1" in per_agent
    assert per_agent["lead"]["calls"] == 1
    assert per_agent["xss-specialist-1"]["calls"] == 1


def test_token_breakdown_summary_cache_hit_ratio_run(tmp_path, monkeypatch) -> None:
    """Aggregate cache-hit ratio across the whole run = sum(cached) /
    sum(measured_input). Must match the §8.5 Phase 8 acceptance gate
    (≥60% target)."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")

    t = Tracer("breakdown-test")
    t._emit_event(
        "llm.token_breakdown",
        payload={
            "schema_version": 1,
            "agent_id": "lead", "agent_name": "lead",
            "system_tokens": 0, "agent_identity_tokens": 0, "conversation_tokens": 0,
            "total_input_tokens_estimated": 100_000,
            "message_count": 1,
            "measured_input_tokens": 100_000,
            "measured_output_tokens": 0,
            "measured_cached_tokens": 70_000,
            "measured_cost_usd": 0.0,
            "cache_hit_ratio": 0.7,
        },
    )
    summary = t.token_breakdown_summary()
    assert summary["cache_hit_ratio_run"] == pytest.approx(0.7, abs=1e-4)


def test_token_breakdown_summary_ignores_other_event_types(tmp_path, monkeypatch) -> None:
    """The aggregator must filter on `event_type='llm.token_breakdown'`
    and ignore `llm.request.completed` / `phase.entered` / etc."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")

    t = Tracer("breakdown-test")
    t._emit_event("llm.request.completed", payload={"input_tokens": 100, "cost": 0.01})
    t._emit_event("phase.entered", payload={"phase_name": "recon"})
    t._emit_event(
        "llm.token_breakdown",
        payload={
            "schema_version": 1,
            "system_tokens": 5_000, "agent_identity_tokens": 0,
            "conversation_tokens": 0, "total_input_tokens_estimated": 5_000,
            "message_count": 1,
            "measured_input_tokens": 5_000, "measured_output_tokens": 0,
            "measured_cached_tokens": 0, "measured_cost_usd": 0.0,
            "cache_hit_ratio": 0.0,
        },
    )
    summary = t.token_breakdown_summary()
    assert summary["call_count"] == 1  # only the breakdown event counted
    assert summary["totals"]["system_tokens"] == 5_000
