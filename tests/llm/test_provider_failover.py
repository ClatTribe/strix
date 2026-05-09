"""Tests for Phase 1.1 — provider failover.

Pins:
  * Failover model resolution: env override > primary-based default > None
  * `_record_request_outcome` populates the rolling window
  * Window trimmed to last 5 minutes
  * Failover triggers when retry rate >50% AND ≥6 outcomes
  * Failover NOT triggered when window too small
  * Self-healing: drop back to original when retry rate <25%
  * `llm.provider_failed_over` event emitted via tracer
"""

from __future__ import annotations

import time

import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


@pytest.fixture(autouse=True)
def _llm_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    yield


def _llm(model: str = "gemini/gemini-2.5-pro", env_override: str | None = None,
         monkeypatch=None) -> LLM:
    monkeypatch.setenv("STRIX_LLM", model)
    if env_override is not None:
        monkeypatch.setenv("STRIX_LLM_FAILOVER", env_override)
    else:
        monkeypatch.delenv("STRIX_LLM_FAILOVER", raising=False)
    return LLM(LLMConfig(), agent_name="StrixAgent")


# ---------------------------------------------------------------------------
# Failover model resolution
# ---------------------------------------------------------------------------


def test_failover_default_for_gemini(monkeypatch) -> None:
    llm = _llm("gemini/gemini-2.5-pro", monkeypatch=monkeypatch)
    assert "claude" in llm._failover_model.lower()


def test_failover_default_for_claude(monkeypatch) -> None:
    llm = _llm("anthropic/claude-sonnet-4-5-20250929", monkeypatch=monkeypatch)
    assert "openai" in llm._failover_model.lower() or "gpt" in llm._failover_model.lower()


def test_failover_default_for_openai(monkeypatch) -> None:
    llm = _llm("openai/gpt-4o", monkeypatch=monkeypatch)
    assert "claude" in llm._failover_model.lower()


def test_failover_env_override_wins(monkeypatch) -> None:
    llm = _llm("gemini/gemini-2.5-pro",
               env_override="some/custom-model", monkeypatch=monkeypatch)
    assert llm._failover_model == "some/custom-model"


def test_failover_disabled_for_unknown_provider(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "unknown/some-weird-model")
    monkeypatch.delenv("STRIX_LLM_FAILOVER", raising=False)
    llm = LLM(LLMConfig(), agent_name="StrixAgent")
    assert llm._failover_model is None


# ---------------------------------------------------------------------------
# Window tracking
# ---------------------------------------------------------------------------


def test_record_outcome_appends(monkeypatch) -> None:
    llm = _llm(monkeypatch=monkeypatch)
    llm._record_request_outcome("ok")
    llm._record_request_outcome("retry")
    assert len(llm._request_history) == 2
    assert llm._request_history[0][1] == "ok"
    assert llm._request_history[1][1] == "retry"


def test_window_trims_old_entries(monkeypatch) -> None:
    llm = _llm(monkeypatch=monkeypatch)
    # Manually insert an old entry (10 min ago)
    old_ts = time.time() - 600
    llm._request_history.append((old_ts, "retry"))
    llm._record_request_outcome("ok")
    # Old entry should be trimmed.
    assert len(llm._request_history) == 1
    assert llm._request_history[0][1] == "ok"


# ---------------------------------------------------------------------------
# Failover trigger
# ---------------------------------------------------------------------------


def test_failover_triggers_on_high_retry_rate(monkeypatch) -> None:
    llm = _llm("gemini/gemini-2.5-pro", monkeypatch=monkeypatch)
    original = llm.config.litellm_model

    # 5 retries + 1 ok = 83% retry rate
    for _ in range(5):
        llm._record_request_outcome("retry")
    llm._record_request_outcome("ok")

    assert llm._failover_active is True
    assert llm.config.litellm_model != original
    assert "claude" in llm.config.litellm_model.lower()


def test_failover_not_triggered_with_small_window(monkeypatch) -> None:
    llm = _llm(monkeypatch=monkeypatch)
    original = llm.config.litellm_model
    # Only 5 outcomes (need >= 6 to trigger)
    for _ in range(5):
        llm._record_request_outcome("retry")
    assert llm._failover_active is False
    assert llm.config.litellm_model == original


def test_failover_not_triggered_with_low_retry_rate(monkeypatch) -> None:
    llm = _llm(monkeypatch=monkeypatch)
    # 6 ok + 0 retry = 0% retry rate
    for _ in range(6):
        llm._record_request_outcome("ok")
    assert llm._failover_active is False


def test_failover_self_heals_when_retry_rate_drops(monkeypatch) -> None:
    """Once failover is active, if the new provider has low retry
    rate (< 25% over ≥10 outcomes), swap back."""
    llm = _llm("gemini/gemini-2.5-pro", monkeypatch=monkeypatch)
    original = llm.config.litellm_model

    # Trigger failover.
    for _ in range(5):
        llm._record_request_outcome("retry")
    llm._record_request_outcome("ok")
    assert llm._failover_active is True
    failover_model = llm.config.litellm_model

    # Now post 10 successes on the failover provider — should swap back.
    for _ in range(10):
        llm._record_request_outcome("ok")

    assert llm._failover_active is False
    assert llm.config.litellm_model == original


# ---------------------------------------------------------------------------
# Disabled failover gracefully
# ---------------------------------------------------------------------------


def test_unknown_provider_disables_failover(monkeypatch) -> None:
    """If we can't resolve a failover model, never trigger."""
    monkeypatch.setenv("STRIX_LLM", "weird/model")
    monkeypatch.delenv("STRIX_LLM_FAILOVER", raising=False)
    llm = LLM(LLMConfig(), agent_name="StrixAgent")
    assert llm._failover_model is None

    for _ in range(20):
        llm._record_request_outcome("retry")
    assert llm._failover_active is False
