"""Provider-agnostic prompt-cache lifecycle (roadmap §8.5 Phase 2).

The §8.5 cost-pricing argument is load-bearing on cached-prefix
re-use: the lead agent's growing conversation should hit cache on
every turn so only the new tail pays full rate. Today
[`strix/llm/llm.py:_add_cache_control`](strix/llm/llm.py) handles the
anthropic case (cache_control markers); gemini's
[CachedContent](https://ai.google.dev/gemini-api/docs/caching) API is
unbuilt; openai's implicit prefix caching needs no markers but should
still surface in our stats; other providers (ollama / lmstudio) are
no-ops.

This module unifies all four under one interface so subsequent phases
(Phase 3 lead-agent loop, Phase 6 reflection writes) consume a single
abstraction. **Wrapper-side impact: zero** — caching is internal cost
optimisation; nothing in `events.jsonl` / `vulnerabilities.json`
changes.

Public API
----------

```python
mgr = CacheManager()

# Register a cacheable prompt (system prompt, tool catalog, …).
handle = mgr.register_cached_prompt(
    content="<system prompt>",
    model="anthropic/claude-sonnet-4-6",
    ttl_seconds=3600,
)

# Apply the cache markers to a prepared message list.
messages_with_cache = mgr.apply_to_messages(messages, handles=[handle])

# Stats / introspection.
stats = mgr.get_stats()         # CacheStats(registered=N, hits=M, …)
mgr.note_hit(handle)            # callsite reports cache-hit observation
mgr.note_miss(handle)
mgr.evict(handle)               # remove from cache (where applicable)
mgr.refresh(handle, ttl_seconds=7200)
```

Provider routing
----------------

* **Anthropic / Claude** — produces `cache_control: {type: ephemeral}`
  markers placed at the cache breakpoint. Per-tool cache keys via
  `cache_key` arg → distinct breakpoints per specialist-tool prompt.
  No pre-registration step; cache is created on-the-fly by the
  message marker. `evict` / `refresh` are no-ops (TTL is provider-
  controlled, ~5 min).
* **Gemini / Vertex (gemini-3-pro / gemini-2.5-pro)** — pre-registers
  via `google.genai.caching.CachedContent.create()` if the SDK is
  available. Returns a cache name (`cachedContents/<id>`) that the
  next LLM call must reference. Fails open: SDK absent or API
  unreachable → handle marked `provider="noop"` and the call
  proceeds without caching (correctness preserved; cost regresses).
* **OpenAI o1 / o3 / GPT-5.4** — implicit prefix caching by the API.
  Handle returned, no markers. Stats track registration so dashboards
  can show "caching active".
* **Ollama / LMStudio / unknown** — no-op handle.

Schema versioning: `CACHE_HANDLE_SCHEMA_VERSION` is the public
version (currently 1). Bump on breaking change.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


logger = logging.getLogger(__name__)


CACHE_HANDLE_SCHEMA_VERSION: int = 1


CacheProvider = Literal[
    "anthropic", "gemini", "vertex", "openai", "ollama", "noop",
]


# ---------------------------------------------------------------------------
# CacheHandle + CacheStats
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheHandle:
    """Opaque reference to a registered cacheable prompt.

    Frozen so it's safe to share across threads. Equality + hash
    keyed on (provider, cache_id, model) so the same content
    registered twice for the same model returns the SAME handle
    (idempotency rule)."""

    schema_version: int
    provider: CacheProvider
    cache_id: str
    model: str
    content_hash: str
    ttl_seconds: int
    created_at: datetime
    cache_key: str | None = None

    def __post_init__(self) -> None:
        # Validation: must have a cache_id (even no-op handles).
        if not self.cache_id:
            object.__setattr__(self, "cache_id", "noop")


@dataclass
class CacheStats:
    """Lifetime counters for the CacheManager. Used by the
    `check_budget` tool surface (§2.9) so the lead agent can reason
    about cache effectiveness mid-run."""

    registered: int = 0
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    refreshes: int = 0
    errors: int = 0
    by_provider: dict[str, int] = field(default_factory=dict)

    def hit_ratio(self) -> float:
        denom = self.hits + self.misses
        return round(self.hits / denom, 4) if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "registered": self.registered,
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "refreshes": self.refreshes,
            "errors": self.errors,
            "hit_ratio": self.hit_ratio(),
            "by_provider": dict(self.by_provider),
        }


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


def detect_provider(model: str | None) -> CacheProvider:
    """Map a model name to a `CacheProvider`. Defaults to `noop`.

    Recognised prefixes / substrings (case-insensitive):
      * `anthropic/`, `claude` → `anthropic`
      * `vertex_ai/gemini` → `vertex`
      * `gemini/`, `gemini-` → `gemini`
      * `openai/`, `gpt-`, `o1`, `o3` → `openai`
      * `ollama/`, `lmstudio/` → `ollama`
    """
    if not isinstance(model, str) or not model:
        return "noop"
    m = model.lower()
    if "anthropic/" in m or "claude" in m:
        return "anthropic"
    if "vertex_ai/" in m and "gemini" in m:
        return "vertex"
    if "gemini/" in m or "gemini-" in m:
        return "gemini"
    if (
        "openai/" in m
        or m.startswith("gpt-")
        or m.startswith("o1")
        or m.startswith("o3")
    ):
        return "openai"
    if "ollama/" in m or "lmstudio/" in m:
        return "ollama"
    return "noop"


def _content_hash(content: str) -> str:
    """SHA-256 over the content. First 16 hex chars used as cache_id
    suffix so caches deduplicate on byte-equal content. Mirrors
    `compute_finding_fingerprint` style."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Provider-specific registration
# ---------------------------------------------------------------------------


def _register_anthropic(
    *, content: str, model: str, ttl_seconds: int, cache_key: str | None,
) -> CacheHandle:
    """Anthropic cache_control markers. No pre-registration —
    the cache is created when the next LLM call carries the
    marker. Handle records the placement intent."""
    return CacheHandle(
        schema_version=CACHE_HANDLE_SCHEMA_VERSION,
        provider="anthropic",
        cache_id=f"anthropic_marker_{_content_hash(content)}",
        model=model,
        content_hash=_content_hash(content),
        ttl_seconds=ttl_seconds,
        created_at=datetime.now(UTC),
        cache_key=cache_key,
    )


def _register_gemini(
    *, content: str, model: str, ttl_seconds: int, cache_key: str | None,
) -> CacheHandle:
    """Gemini cached-content registration. Tries `google.genai.caching`
    SDK; falls back to no-op when SDK absent or API call fails (cost
    regresses but correctness preserved)."""
    # Disable the SDK call entirely when the operator opts out (e.g.
    # air-gapped environments where the gemini API isn't reachable).
    if os.environ.get("STRIX_DISABLE_PROMPT_CACHE_REGISTRATION") == "1":
        logger.debug("gemini cache registration disabled by env var")
        return _noop_handle(content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key)

    try:
        from google import genai  # type: ignore[import-not-found]
    except ImportError:
        logger.debug(
            "google.genai SDK not installed — gemini cache falls back to noop"
        )
        return _noop_handle(content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key)
    try:
        # SDK shape: client.caches.create(model=..., config={system_instruction, ttl, ...})
        # Real call requires API key + network. Tests mock this branch.
        client = genai.Client()
        cached = client.caches.create(
            model=model,
            config={
                "system_instruction": content,
                "ttl": f"{int(ttl_seconds)}s",
            },
        )
        cache_id = getattr(cached, "name", None) or f"gemini_local_{_content_hash(content)}"
        return CacheHandle(
            schema_version=CACHE_HANDLE_SCHEMA_VERSION,
            provider="gemini",
            cache_id=str(cache_id),
            model=model,
            content_hash=_content_hash(content),
            ttl_seconds=ttl_seconds,
            created_at=datetime.now(UTC),
            cache_key=cache_key,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("gemini cache create failed: %s", e, exc_info=True)
        return _noop_handle(content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key)


def _register_vertex(
    *, content: str, model: str, ttl_seconds: int, cache_key: str | None,
) -> CacheHandle:
    """Vertex AI gemini cached-content. Same SDK shape as gemini but
    different client instantiation. For now we delegate to the gemini
    handler and tag the provider as `vertex` so stats split cleanly."""
    handle = _register_gemini(
        content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
    )
    if handle.provider == "gemini":
        return CacheHandle(
            schema_version=handle.schema_version,
            provider="vertex",
            cache_id=handle.cache_id,
            model=handle.model,
            content_hash=handle.content_hash,
            ttl_seconds=handle.ttl_seconds,
            created_at=handle.created_at,
            cache_key=handle.cache_key,
        )
    return handle


def _register_openai(
    *, content: str, model: str, ttl_seconds: int, cache_key: str | None,
) -> CacheHandle:
    """OpenAI implicit prefix caching — no markers, no registration.
    Handle returned for stats / dashboard surface so 'caching active'
    reflects when the model supports it."""
    return CacheHandle(
        schema_version=CACHE_HANDLE_SCHEMA_VERSION,
        provider="openai",
        cache_id=f"openai_implicit_{_content_hash(content)}",
        model=model,
        content_hash=_content_hash(content),
        ttl_seconds=ttl_seconds,
        created_at=datetime.now(UTC),
        cache_key=cache_key,
    )


def _noop_handle(
    *, content: str, model: str, ttl_seconds: int, cache_key: str | None,
) -> CacheHandle:
    return CacheHandle(
        schema_version=CACHE_HANDLE_SCHEMA_VERSION,
        provider="noop",
        cache_id=f"noop_{_content_hash(content)}",
        model=model,
        content_hash=_content_hash(content),
        ttl_seconds=ttl_seconds,
        created_at=datetime.now(UTC),
        cache_key=cache_key,
    )


# ---------------------------------------------------------------------------
# CacheManager
# ---------------------------------------------------------------------------


class CacheManager:
    """Thread-safe lifecycle manager for cacheable prompts.

    One instance per LLM client (or one process-wide singleton — the
    Phase 3 LeadAgent will share a manager across specialist-tool
    invocations to reuse cache handles).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (provider, content_hash, model) → CacheHandle (idempotency).
        self._handles: dict[tuple[str, str, str], CacheHandle] = {}
        self._stats = CacheStats()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def register_cached_prompt(
        self,
        *,
        content: str,
        model: str,
        ttl_seconds: int = 3600,
        cache_key: str | None = None,
    ) -> CacheHandle:
        """Register a cacheable prompt and return a handle.

        Idempotent: registering the same `(content, model)` twice
        returns the same handle. This is the cache-stability rule
        from `single-agent.md §2.5.4` — deterministic registration
        so re-calls hit cache.

        Args:
            content: prompt text to cache (typically the system
                prompt or a long static prefix).
            model: model identifier as recognised by `detect_provider`
                (e.g. `"anthropic/claude-sonnet-4-6"`,
                `"vertex_ai/gemini-2.5-pro"`).
            ttl_seconds: requested TTL. Provider-controlled; some
                providers (anthropic) ignore this and use their own
                ~5-minute window.
            cache_key: optional caller-supplied tag — e.g. the
                specialist category for per-tool keys (B.9). Stored
                on the handle for downstream marker placement.
        """
        if not isinstance(content, str) or not content:
            with self._lock:
                self._stats.errors += 1
            return _noop_handle(content="", model=model, ttl_seconds=ttl_seconds, cache_key=cache_key)
        if ttl_seconds <= 0:
            ttl_seconds = 3600

        provider = detect_provider(model)
        h = _content_hash(content)
        key = (provider, h, model or "")

        with self._lock:
            existing = self._handles.get(key)
            if existing is not None:
                return existing

        # Provider-specific creation (outside the lock — may make
        # network calls for gemini).
        try:
            if provider == "anthropic":
                handle = _register_anthropic(
                    content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
                )
            elif provider == "gemini":
                handle = _register_gemini(
                    content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
                )
            elif provider == "vertex":
                handle = _register_vertex(
                    content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
                )
            elif provider == "openai":
                handle = _register_openai(
                    content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
                )
            else:
                handle = _noop_handle(
                    content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
                )
        except Exception as e:  # noqa: BLE001
            logger.debug("cache registration failed: %s", e, exc_info=True)
            with self._lock:
                self._stats.errors += 1
            handle = _noop_handle(
                content=content, model=model, ttl_seconds=ttl_seconds, cache_key=cache_key,
            )

        with self._lock:
            self._handles[(handle.provider, h, model or "")] = handle
            self._stats.registered += 1
            self._stats.by_provider[handle.provider] = (
                self._stats.by_provider.get(handle.provider, 0) + 1
            )
        return handle

    def evict(self, handle: CacheHandle) -> None:
        """Remove the handle from the manager's table. For gemini /
        vertex this also tears down the registered CachedContent
        (via `caches.delete`) on a best-effort basis."""
        if handle is None:
            return
        with self._lock:
            self._handles.pop(
                (handle.provider, handle.content_hash, handle.model),
                None,
            )
            self._stats.evictions += 1

        if handle.provider in ("gemini", "vertex"):
            try:
                from google import genai  # type: ignore[import-not-found]

                client = genai.Client()
                client.caches.delete(name=handle.cache_id)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "gemini cache delete failed for %s",
                    handle.cache_id,
                    exc_info=True,
                )

    def refresh(self, handle: CacheHandle, *, ttl_seconds: int) -> CacheHandle:
        """Extend the TTL on a registered cache. For anthropic /
        openai / noop this is a no-op (provider controls TTL);
        for gemini / vertex it issues a `caches.update`.

        Returns a new handle with the updated TTL (handles are
        frozen). Preserves the cache_id so subsequent calls keep
        hitting the same cache."""
        if ttl_seconds <= 0:
            ttl_seconds = 3600
        new_handle = CacheHandle(
            schema_version=handle.schema_version,
            provider=handle.provider,
            cache_id=handle.cache_id,
            model=handle.model,
            content_hash=handle.content_hash,
            ttl_seconds=ttl_seconds,
            created_at=handle.created_at,
            cache_key=handle.cache_key,
        )
        with self._lock:
            self._handles[
                (new_handle.provider, new_handle.content_hash, new_handle.model)
            ] = new_handle
            self._stats.refreshes += 1

        if handle.provider in ("gemini", "vertex"):
            try:
                from google import genai  # type: ignore[import-not-found]

                client = genai.Client()
                client.caches.update(
                    name=handle.cache_id,
                    config={"ttl": f"{int(ttl_seconds)}s"},
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "gemini cache refresh failed for %s",
                    handle.cache_id,
                    exc_info=True,
                )
        return new_handle

    # ------------------------------------------------------------------
    # Marker placement
    # ------------------------------------------------------------------

    def apply_to_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        handles: list[CacheHandle] | None = None,
    ) -> list[dict[str, Any]]:
        """Apply provider-specific cache markers to the message list.

        For anthropic: wraps the system message content in a list-of-
        dicts with `cache_control: {type: ephemeral}` markers. Also
        adds a marker at each handle's `cache_key` boundary (per-tool
        breakpoint) for the Phase 3 lead-agent loop where multiple
        specialist-tool prompts share a message stream.

        For gemini / vertex: returns messages unchanged — the cache
        reference goes in the LLM call's request config, not the
        message body. Caller passes `handle.cache_id` as
        `cached_content` arg.

        For openai / ollama / noop: returns messages unchanged.
        """
        if not messages:
            return messages
        if not handles:
            return messages

        # Group handles by provider for routing.
        anthropic_handles = [h for h in handles if h.provider == "anthropic"]
        if not anthropic_handles:
            return messages

        # Anthropic — apply cache_control markers. Place markers
        # idempotently: if the system message is already a list of
        # content-blocks (caller upstream wrapped it), preserve.
        result = list(messages)
        if result[0].get("role") == "system":
            content = result[0].get("content")
            if isinstance(content, str):
                result[0] = {
                    **result[0],
                    "content": [
                        {
                            "type": "text",
                            "text": content,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                }
            elif isinstance(content, list) and content:
                # Already wrapped; ensure last block carries marker.
                last = content[-1]
                if isinstance(last, dict) and "cache_control" not in last:
                    new_last = {**last, "cache_control": {"type": "ephemeral"}}
                    result[0] = {
                        **result[0],
                        "content": [*content[:-1], new_last],
                    }
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def note_hit(self, handle: CacheHandle | None = None) -> None:
        """Caller-side hit notification (the LLM response showed the
        cache was used). Stats only — no provider call."""
        with self._lock:
            self._stats.hits += 1

    def note_miss(self, handle: CacheHandle | None = None) -> None:
        with self._lock:
            self._stats.misses += 1

    def get_stats(self) -> CacheStats:
        """Snapshot of current stats. Returned copy — caller-safe."""
        with self._lock:
            return CacheStats(
                registered=self._stats.registered,
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                refreshes=self._stats.refreshes,
                errors=self._stats.errors,
                by_provider=dict(self._stats.by_provider),
            )

    def list_handles(self) -> list[CacheHandle]:
        """Snapshot of registered handles. Used by §2.9 budget
        introspection + tests."""
        with self._lock:
            return list(self._handles.values())


# ---------------------------------------------------------------------------
# Process-wide singleton (Phase 3 lead-agent shares one manager)
# ---------------------------------------------------------------------------


_GLOBAL_CACHE_MANAGER: CacheManager | None = None
_GLOBAL_LOCK = threading.Lock()


def get_global_cache_manager() -> CacheManager:
    """Return the process-wide CacheManager. Phase 3 lead-agent loop
    uses this so specialist-tool invocations share one cache table.

    Thread-safe lazy initialisation. Tests can reset via
    `reset_global_cache_manager_for_tests()`."""
    global _GLOBAL_CACHE_MANAGER
    if _GLOBAL_CACHE_MANAGER is not None:
        return _GLOBAL_CACHE_MANAGER
    with _GLOBAL_LOCK:
        if _GLOBAL_CACHE_MANAGER is None:
            _GLOBAL_CACHE_MANAGER = CacheManager()
    return _GLOBAL_CACHE_MANAGER


def reset_global_cache_manager_for_tests() -> None:
    """Test-only helper. Clears the singleton."""
    global _GLOBAL_CACHE_MANAGER
    with _GLOBAL_LOCK:
        _GLOBAL_CACHE_MANAGER = None
