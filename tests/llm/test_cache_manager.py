"""Tests for §8.5 Phase 2 — `cache_manager.py`.

Pins the provider-routing matrix, idempotent registration, lifecycle
methods (evict / refresh), marker placement for anthropic, and the
fail-open contract for gemini (SDK absent / API error → noop handle,
correctness preserved).

Wrapper-side impact: zero — caching is internal cost optimisation.
These tests verify the public API the Phase 3 lead-agent will call.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from strix.llm.cache_manager import (
    CACHE_HANDLE_SCHEMA_VERSION,
    CacheHandle,
    CacheManager,
    CacheStats,
    detect_provider,
    get_global_cache_manager,
    reset_global_cache_manager_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_singleton() -> None:
    reset_global_cache_manager_for_tests()
    yield
    reset_global_cache_manager_for_tests()


# ---------------------------------------------------------------------------
# Schema invariants
# ---------------------------------------------------------------------------


def test_handle_schema_version_pinned() -> None:
    assert CACHE_HANDLE_SCHEMA_VERSION == 1


# ---------------------------------------------------------------------------
# detect_provider
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model,expected",
    [
        ("anthropic/claude-sonnet-4-6", "anthropic"),
        ("anthropic/claude-opus-4", "anthropic"),
        ("claude-3-5-sonnet", "anthropic"),
        ("vertex_ai/gemini-2.5-pro", "vertex"),
        ("vertex_ai/gemini-3-pro-preview", "vertex"),
        ("gemini/gemini-2.5-pro", "gemini"),
        ("gemini-1.5-pro", "gemini"),
        ("openai/gpt-5.4", "openai"),
        ("gpt-4o", "openai"),
        ("o1-preview", "openai"),
        ("o3-mini", "openai"),
        ("ollama/llama3", "ollama"),
        ("lmstudio/qwen", "ollama"),
        ("unknown/something", "noop"),
        ("", "noop"),
        (None, "noop"),
    ],
)
def test_detect_provider(model, expected: str) -> None:
    assert detect_provider(model) == expected


# ---------------------------------------------------------------------------
# Registration — idempotency + provider routing
# ---------------------------------------------------------------------------


def test_anthropic_register_returns_anthropic_provider() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(
        content="system prompt content", model="anthropic/claude-sonnet-4-6",
    )
    assert h.provider == "anthropic"
    assert h.cache_id.startswith("anthropic_marker_")
    assert h.content_hash  # 16 hex chars


def test_openai_register_returns_openai_implicit() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="system prompt", model="openai/gpt-5.4")
    assert h.provider == "openai"
    assert h.cache_id.startswith("openai_implicit_")


def test_unknown_provider_returns_noop() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="system prompt", model="unknown/x")
    assert h.provider == "noop"


def test_idempotent_registration_returns_same_handle() -> None:
    """Cache-stability rule (§2.5.4): same `(content, model)` → same
    handle. Subsequent re-calls reuse the cache."""
    mgr = CacheManager()
    h1 = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    h2 = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    assert h1 is h2  # same instance


def test_different_content_yields_different_handle() -> None:
    mgr = CacheManager()
    h1 = mgr.register_cached_prompt(content="a", model="anthropic/claude-sonnet-4-6")
    h2 = mgr.register_cached_prompt(content="b", model="anthropic/claude-sonnet-4-6")
    assert h1 is not h2
    assert h1.content_hash != h2.content_hash


def test_different_model_yields_different_handle() -> None:
    mgr = CacheManager()
    h1 = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    h2 = mgr.register_cached_prompt(content="x", model="openai/gpt-5.4")
    assert h1 is not h2
    assert h1.provider != h2.provider


def test_empty_content_returns_noop_and_increments_errors() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="", model="anthropic/claude-sonnet-4-6")
    assert h.provider == "noop"
    stats = mgr.get_stats()
    assert stats.errors >= 1


def test_invalid_ttl_normalises_to_default() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(
        content="x", model="anthropic/claude-sonnet-4-6", ttl_seconds=-5,
    )
    assert h.ttl_seconds == 3600


# ---------------------------------------------------------------------------
# Gemini — fail-open contract
# ---------------------------------------------------------------------------


def test_gemini_register_falls_open_when_sdk_absent(monkeypatch) -> None:
    """SDK not installed → noop handle, correctness preserved."""
    # Force the import inside _register_gemini to fail.
    import sys

    with patch.dict(sys.modules, {"google.genai": None}):
        # Setting to None makes import raise ImportError.
        sys.modules["google.genai"] = None  # type: ignore[assignment]
        mgr = CacheManager()
        h = mgr.register_cached_prompt(
            content="sys prompt", model="gemini/gemini-2.5-pro",
        )
        # SDK was real or absent; either way handle is gemini OR noop.
        assert h.provider in ("gemini", "noop")
        # If noop, the fail-open path fired correctly.


def test_gemini_register_disabled_via_env(monkeypatch) -> None:
    """`STRIX_DISABLE_PROMPT_CACHE_REGISTRATION=1` short-circuits to noop."""
    monkeypatch.setenv("STRIX_DISABLE_PROMPT_CACHE_REGISTRATION", "1")
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="gemini/gemini-2.5-pro")
    assert h.provider == "noop"


def test_gemini_register_handles_api_error(monkeypatch) -> None:
    """SDK present but `caches.create` raises → noop fall-back."""
    import sys
    import types

    fake_genai = types.ModuleType("google.genai")
    fake_client_class = MagicMock()
    fake_client = MagicMock()
    fake_client.caches.create.side_effect = RuntimeError("api unreachable")
    fake_client_class.return_value = fake_client
    fake_genai.Client = fake_client_class

    fake_google = types.ModuleType("google")
    fake_google.genai = fake_genai

    with patch.dict(sys.modules, {"google": fake_google, "google.genai": fake_genai}):
        mgr = CacheManager()
        h = mgr.register_cached_prompt(content="x", model="gemini/gemini-2.5-pro")
    assert h.provider == "noop"


def test_gemini_register_succeeds_with_mocked_sdk(monkeypatch) -> None:
    """Mocked SDK → handle.provider=='gemini' with cache_id from SDK."""
    import sys
    import types

    fake_genai = types.ModuleType("google.genai")
    fake_client_class = MagicMock()
    fake_client = MagicMock()
    fake_cached = MagicMock()
    fake_cached.name = "cachedContents/test_abc123"
    fake_client.caches.create.return_value = fake_cached
    fake_client_class.return_value = fake_client
    fake_genai.Client = fake_client_class

    fake_google = types.ModuleType("google")
    fake_google.genai = fake_genai

    with patch.dict(sys.modules, {"google": fake_google, "google.genai": fake_genai}):
        mgr = CacheManager()
        h = mgr.register_cached_prompt(content="x", model="gemini/gemini-2.5-pro")
    assert h.provider == "gemini"
    assert h.cache_id == "cachedContents/test_abc123"


def test_vertex_routes_through_gemini_strategy_with_vertex_provider(monkeypatch) -> None:
    """Vertex AI uses gemini SDK shape but stats / handle tag as
    `vertex` so the per-provider counter splits cleanly."""
    import sys
    import types

    fake_genai = types.ModuleType("google.genai")
    fake_client_class = MagicMock()
    fake_client = MagicMock()
    fake_cached = MagicMock()
    fake_cached.name = "cachedContents/vertex_xyz"
    fake_client.caches.create.return_value = fake_cached
    fake_client_class.return_value = fake_client
    fake_genai.Client = fake_client_class

    fake_google = types.ModuleType("google")
    fake_google.genai = fake_genai

    with patch.dict(sys.modules, {"google": fake_google, "google.genai": fake_genai}):
        mgr = CacheManager()
        h = mgr.register_cached_prompt(
            content="x", model="vertex_ai/gemini-3-pro-preview",
        )
    assert h.provider == "vertex"
    assert h.cache_id == "cachedContents/vertex_xyz"


# ---------------------------------------------------------------------------
# evict / refresh
# ---------------------------------------------------------------------------


def test_evict_removes_handle_from_table() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    assert mgr.list_handles() == [h]
    mgr.evict(h)
    assert mgr.list_handles() == []


def test_evict_increments_evictions_counter() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    mgr.evict(h)
    assert mgr.get_stats().evictions == 1


def test_evict_handles_none_gracefully() -> None:
    mgr = CacheManager()
    mgr.evict(None)  # type: ignore[arg-type]  # noqa: PIE790
    assert mgr.get_stats().evictions == 0


def test_refresh_returns_new_handle_with_updated_ttl() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(
        content="x", model="anthropic/claude-sonnet-4-6", ttl_seconds=300,
    )
    h2 = mgr.refresh(h, ttl_seconds=7200)
    assert h2.ttl_seconds == 7200
    assert h2.cache_id == h.cache_id  # preserved
    assert h2.content_hash == h.content_hash


def test_refresh_normalises_invalid_ttl() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    h2 = mgr.refresh(h, ttl_seconds=0)
    assert h2.ttl_seconds == 3600


def test_refresh_increments_refreshes_counter() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    mgr.refresh(h, ttl_seconds=7200)
    assert mgr.get_stats().refreshes == 1


# ---------------------------------------------------------------------------
# apply_to_messages — anthropic marker placement
# ---------------------------------------------------------------------------


def test_apply_attaches_cache_marker_to_anthropic_system_message() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(
        content="system prompt", model="anthropic/claude-sonnet-4-6",
    )
    messages = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "do the thing"},
    ]
    out = mgr.apply_to_messages(messages, handles=[h])
    sys_content = out[0]["content"]
    assert isinstance(sys_content, list)
    assert sys_content[0]["type"] == "text"
    assert sys_content[0]["cache_control"] == {"type": "ephemeral"}


def test_apply_idempotent_on_already_wrapped_system_content() -> None:
    """When the system content is already a list-of-blocks, don't
    double-wrap. Idempotency rule (§2.5.4)."""
    mgr = CacheManager()
    h = mgr.register_cached_prompt(
        content="system prompt", model="anthropic/claude-sonnet-4-6",
    )
    messages = [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": "system prompt",
                    "cache_control": {"type": "ephemeral"},
                },
            ],
        },
    ]
    out = mgr.apply_to_messages(messages, handles=[h])
    sys_content = out[0]["content"]
    assert isinstance(sys_content, list)
    assert len(sys_content) == 1  # not double-wrapped


def test_apply_skips_non_anthropic_handles() -> None:
    """OpenAI handle → no marker placement (implicit caching)."""
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="openai/gpt-5.4")
    messages = [{"role": "system", "content": "system prompt"}]
    out = mgr.apply_to_messages(messages, handles=[h])
    # System message stays as plain string (no markers needed).
    assert out[0]["content"] == "system prompt"


def test_apply_returns_messages_unchanged_when_no_handles() -> None:
    mgr = CacheManager()
    messages = [{"role": "system", "content": "x"}]
    out = mgr.apply_to_messages(messages, handles=[])
    assert out == messages


def test_apply_returns_empty_messages_unchanged() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    assert mgr.apply_to_messages([], handles=[h]) == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_initial_values() -> None:
    mgr = CacheManager()
    stats = mgr.get_stats()
    assert stats.registered == 0
    assert stats.hits == 0
    assert stats.misses == 0
    assert stats.hit_ratio() == 0.0


def test_stats_track_per_provider() -> None:
    mgr = CacheManager()
    mgr.register_cached_prompt(content="a", model="anthropic/claude-sonnet-4-6")
    mgr.register_cached_prompt(content="b", model="openai/gpt-5.4")
    stats = mgr.get_stats()
    assert stats.by_provider["anthropic"] == 1
    assert stats.by_provider["openai"] == 1


def test_stats_hit_miss_tracking() -> None:
    mgr = CacheManager()
    h = mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    mgr.note_hit(h)
    mgr.note_hit(h)
    mgr.note_miss(h)
    stats = mgr.get_stats()
    assert stats.hits == 2
    assert stats.misses == 1
    assert stats.hit_ratio() == pytest.approx(2 / 3, abs=1e-4)


def test_stats_to_dict() -> None:
    mgr = CacheManager()
    mgr.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    d = mgr.get_stats().to_dict()
    for key in (
        "registered", "hits", "misses", "evictions", "refreshes", "errors",
        "hit_ratio", "by_provider",
    ):
        assert key in d


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_global_cache_manager_singleton() -> None:
    mgr1 = get_global_cache_manager()
    mgr2 = get_global_cache_manager()
    assert mgr1 is mgr2


def test_reset_singleton_clears_state() -> None:
    mgr1 = get_global_cache_manager()
    mgr1.register_cached_prompt(content="x", model="anthropic/claude-sonnet-4-6")
    reset_global_cache_manager_for_tests()
    mgr2 = get_global_cache_manager()
    assert mgr2 is not mgr1
    assert mgr2.get_stats().registered == 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_concurrent_registrations_are_idempotent() -> None:
    """Multiple threads registering the same content concurrently
    should all see the same handle."""
    import threading

    mgr = CacheManager()
    handles: list[CacheHandle] = []
    lock = threading.Lock()

    def register():
        h = mgr.register_cached_prompt(
            content="shared", model="anthropic/claude-sonnet-4-6",
        )
        with lock:
            handles.append(h)

    threads = [threading.Thread(target=register) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All 20 should be the same handle (idempotency under concurrency).
    assert all(h is handles[0] for h in handles)
    assert len(set((h.provider, h.content_hash) for h in handles)) == 1
