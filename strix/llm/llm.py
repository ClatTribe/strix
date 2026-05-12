import asyncio
import logging
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import litellm

logger = logging.getLogger(__name__)
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import acompletion, completion_cost, stream_chunk_builder, supports_reasoning
from litellm.utils import supports_prompt_caching, supports_vision

from strix.config import Config
from strix.llm.config import LLMConfig
from strix.llm.memory_compressor import MemoryCompressor
from strix.llm.utils import (
    _truncate_to_first_function,
    fix_incomplete_tool_call,
    normalize_tool_format,
    parse_tool_invocations,
)
from strix.skills import load_skills
from strix.tools import get_tools_prompt
from strix.utils.resource_paths import get_strix_resource_path


litellm.drop_params = True
litellm.modify_params = True


class LLMRequestFailedError(Exception):
    def __init__(self, message: str, details: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details


@dataclass
class LLMResponse:
    content: str
    tool_invocations: list[dict[str, Any]] | None = None
    thinking_blocks: list[dict[str, Any]] | None = None


@dataclass
class RequestStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    requests: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_tokens": self.cached_tokens,
            "cost": round(self.cost, 4),
            "requests": self.requests,
        }


class LLM:
    def __init__(self, config: LLMConfig, agent_name: str | None = None):
        self.config = config
        self.agent_name = agent_name
        self.agent_id: str | None = None
        self._active_skills: list[str] = list(config.skills or [])
        self._system_prompt_context: dict[str, Any] = dict(
            getattr(config, "system_prompt_context", {}) or {}
        )
        self._total_stats = RequestStats()
        self.memory_compressor = MemoryCompressor(model_name=config.litellm_model)
        self.system_prompt = self._load_system_prompt(agent_name)
        # Roadmap §8.5 Phase 0.A — cost-bisection telemetry. Stash
        # the most-recent prepared-message breakdown so
        # `_update_usage_stats` can emit it alongside the usage event.
        # Best-effort; never blocks the LLM call.
        self._last_token_breakdown: dict[str, int] | None = None

        # Phase 1.1 — provider failover state. Track the last N
        # request outcomes (success / retry-attempted / hard-fail).
        # When the retry rate exceeds the threshold over the window,
        # swap to the configured failover model. Self-healing: a
        # subsequent window with low retry rate flips back.
        self._request_history: list[tuple[float, str]] = []  # (ts, "ok"|"retry"|"fail")
        self._failover_active = False
        self._original_model = config.litellm_model
        self._failover_model = self._resolve_failover_model()

        reasoning = Config.get("strix_reasoning_effort")
        if reasoning:
            self._reasoning_effort = reasoning
        elif config.reasoning_effort:
            self._reasoning_effort = config.reasoning_effort
        elif config.scan_mode == "quick":
            self._reasoning_effort = "medium"
        else:
            self._reasoning_effort = "high"

    def _load_system_prompt(self, agent_name: str | None) -> str:
        if not agent_name:
            return ""

        try:
            prompt_dir = get_strix_resource_path("agents", agent_name)
            skills_dir = get_strix_resource_path("skills")
            env = Environment(
                loader=FileSystemLoader([prompt_dir, skills_dir]),
                autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
            )

            skills_to_load = self._get_skills_to_load()
            skill_content = load_skills(skills_to_load)
            env.globals["get_skill"] = lambda name: skill_content.get(name, "")

            # Roadmap §8.5 — when the lead's `tool_catalog_allowlist`
            # is in `system_prompt_context`, bind `get_tools_prompt`
            # to a partial that filters by that allowlist. The
            # template's `{{ get_tools_prompt() }}` call then renders
            # only the lead's allowed tools (~30-50 of ~130) instead
            # of the full registry. Saves ~50K prompt tokens per call
            # AND removes blocked tools (`create_agent`, etc.) from
            # the model's choice space — pairs with the dispatch
            # guard in #172 for defense in depth.
            #
            # When the allowlist is absent (sub-agents, legacy mode,
            # tests), `get_tools_prompt` runs unfiltered — same as
            # before this PR.
            allowlist = self._system_prompt_context.get("tool_catalog_allowlist")

            # Phase 3d / PR-α — when the lead-architecture is active,
            # further filter the allowlist by current workflow phase.
            # This is the enforcement layer that hides probe-phase
            # tools during recon and vice-versa, reducing the lead's
            # per-turn cognitive load to "pick the right tool for THIS
            # phase" instead of "navigate the full ~85-tool catalog."
            #
            # Honours STRIX_WORKFLOW_DISABLED=1 — when set, the catalog
            # is the unfiltered target-type set (backwards-compatible
            # with pre-3d behaviour). When the lead-architecture isn't
            # active (sub-agents, legacy), `allowlist` is None and we
            # short-circuit — phase filtering doesn't apply there.
            target_types = self._system_prompt_context.get("target_types") or []
            if allowlist and target_types:
                try:
                    from strix.agents.workflow_state import (
                        get_current_phase,
                        is_workflow_disabled,
                    )
                    if not is_workflow_disabled():
                        from strix.agents.lead_agent.tool_catalog import (
                            get_lead_tool_catalog,
                        )
                        phase = get_current_phase()
                        # Re-filter from scratch each call so the
                        # phase change is honoured immediately, not
                        # latched at init.
                        allowlist = sorted(
                            get_lead_tool_catalog(
                                target_types=list(target_types),
                                phase=phase,
                            )
                        )
                except Exception:  # noqa: BLE001
                    # Any failure → keep the init-time allowlist.
                    pass

            if allowlist:
                _tp = get_tools_prompt
                def _get_tools_prompt_filtered() -> str:
                    return _tp(allowlist=allowlist)
                tool_prompt_fn: Any = _get_tools_prompt_filtered
            else:
                tool_prompt_fn = get_tools_prompt

            # Roadmap §8.5 Phase 5 — refresh the SecurityContext
            # snapshot into system_prompt_context every render so
            # the lead always sees up-to-date facts (tech stack,
            # endpoints, auth states, partial signals). Best-effort:
            # any failure leaves the context block out of the prompt
            # rather than crashing the LLM init path.
            #
            # Critical for cross-tool reasoning. Without this the
            # lead forgets what `scan_misconfig` fingerprinted by
            # turn 30 and reprobes redundantly. With it, the model
            # sees its own notebook on every turn and can correlate
            # across the full scan timeline.
            render_ctx = dict(self._system_prompt_context)
            try:
                from strix.agents.security_context import render_for_prompt as _sc_render

                render_ctx["security_context_snapshot"] = _sc_render()
            except Exception:  # noqa: BLE001
                pass

            # Roadmap §8.5 Phase 4b — expose native-tool-calls flag
            # to the jinja template so it can swap the verbose
            # `<function=...>` format-reinforcement block for a
            # native-call directive. Saves ~10K tokens per render
            # when native mode is on.
            render_ctx["native_tool_calls_enabled"] = self._native_tool_calls_enabled()

            result = env.get_template("system_prompt.jinja").render(
                get_tools_prompt=tool_prompt_fn,
                loaded_skill_names=list(skill_content.keys()),
                interactive=self.config.interactive,
                system_prompt_context=render_ctx,
                **skill_content,
            )
            return str(result)
        except Exception:  # noqa: BLE001
            return ""

    def _get_skills_to_load(self) -> list[str]:
        ordered_skills = [*self._active_skills]
        ordered_skills.append(f"scan_modes/{self.config.scan_mode}")
        if self.config.is_whitebox:
            ordered_skills.append("coordination/source_aware_whitebox")
            ordered_skills.append("custom/source_aware_sast")

        deduped: list[str] = []
        seen: set[str] = set()
        for skill_name in ordered_skills:
            if skill_name not in seen:
                deduped.append(skill_name)
                seen.add(skill_name)

        return deduped

    def add_skills(self, skill_names: list[str]) -> list[str]:
        added: list[str] = []
        for skill_name in skill_names:
            if not skill_name or skill_name in self._active_skills:
                continue
            self._active_skills.append(skill_name)
            added.append(skill_name)

        if not added:
            return []

        updated_prompt = self._load_system_prompt(self.agent_name)
        if updated_prompt:
            self.system_prompt = updated_prompt

        return added

    def set_agent_identity(self, agent_name: str | None, agent_id: str | None) -> None:
        if agent_name:
            self.agent_name = agent_name
        if agent_id:
            self.agent_id = agent_id

    def set_system_prompt_context(self, context: dict[str, Any] | None) -> None:
        self._system_prompt_context = dict(context or {})
        updated_prompt = self._load_system_prompt(self.agent_name)
        if updated_prompt:
            self.system_prompt = updated_prompt

    async def generate(
        self, conversation_history: list[dict[str, Any]]
    ) -> AsyncIterator[LLMResponse]:
        messages = self._prepare_messages(conversation_history)
        max_retries = int(Config.get("strix_llm_max_retries") or "5")

        for attempt in range(max_retries + 1):
            try:
                async for response in self._stream(messages):
                    yield response
                return  # noqa: TRY300
            except Exception as e:  # noqa: BLE001
                if attempt >= max_retries or not self._should_retry(e):
                    self._raise_error(e)
                # Roadmap §4 — exponential backoff schedule. The
                # roadmap specifies 5s / 15s / 45s for attempts
                # 0/1/2 (geometric ratio = 3) — the math is
                # `5 * 3**attempt`, capped at 90s for higher
                # attempt counts. A tiny ±20% jitter is added so
                # the retries don't lock-step against the upstream's
                # rate-limiter (helps when many strix runs are
                # retrying at once).
                import random

                base_wait = min(90, 5 * (3 ** attempt))
                jitter = base_wait * (0.8 + 0.4 * random.random())  # noqa: S311
                wait = max(1.0, jitter)

                # Emit a structured `llm.retry_attempted` event so
                # wrappers can surface "Strix is waiting on a
                # rate-limit" signals without parsing exception
                # strings. Best-effort — never fails the retry loop.
                self._emit_retry_attempted_event(
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    wait_seconds=wait,
                    exception=e,
                )

                # Phase 1.1 — track outcome for failover decision.
                self._record_request_outcome("retry")

                await asyncio.sleep(wait)

    def _emit_retry_attempted_event(
        self,
        *,
        attempt: int,
        max_retries: int,
        wait_seconds: float,
        exception: BaseException,
    ) -> None:
        """Emit a `llm.retry_attempted` event so consumers can
        render upstream-trouble UI without scraping logs.

        Payload schema (stable):
            attempt:        1-indexed retry attempt about to wait
            max_retries:    configured cap
            wait_seconds:   how long we're about to sleep before
                            the retry call
            status_code:    HTTP status from the upstream, when
                            available (litellm exposes either
                            `status_code` or `response.status_code`)
            error_type:     class name of the exception (e.g.
                            "ServiceUnavailableError")
            error_message:  short str(exception) — useful for UI
                            tooltips. Truncated at 240 chars.
        """
        try:
            from strix.telemetry.tracer import get_global_tracer
        except ImportError:
            return
        tracer = get_global_tracer()
        if tracer is None:
            return

        status_code = getattr(exception, "status_code", None) or getattr(
            getattr(exception, "response", None), "status_code", None
        )
        try:
            tracer._emit_event(  # noqa: SLF001
                "llm.retry_attempted",
                actor={
                    "agent_id": getattr(self, "agent_id", None),
                    "agent_name": self.agent_name,
                    "model": getattr(self.config, "model_name", None),
                },
                payload={
                    "attempt": int(attempt),
                    "max_retries": int(max_retries),
                    "wait_seconds": round(float(wait_seconds), 2),
                    "status_code": status_code,
                    "error_type": type(exception).__name__,
                    "error_message": str(exception)[:240],
                },
                status="retrying",
                source="strix.llm",
            )
        except Exception:  # noqa: BLE001
            # Never let bookkeeping kill the retry loop.
            pass

    async def _stream(self, messages: list[dict[str, Any]]) -> AsyncIterator[LLMResponse]:
        accumulated = ""
        chunks: list[Any] = []
        done_streaming = 0

        self._total_stats.requests += 1
        timeout = self.config.timeout
        response = await asyncio.wait_for(
            acompletion(**self._build_completion_args(messages), stream=True),
            timeout=timeout,
        )

        async_iter = response.__aiter__()
        while True:
            try:
                chunk = await asyncio.wait_for(async_iter.__anext__(), timeout=timeout)
            except StopAsyncIteration:
                break
            chunks.append(chunk)
            if done_streaming:
                done_streaming += 1
                if getattr(chunk, "usage", None) or done_streaming > 5:
                    break
                continue
            delta = self._get_chunk_content(chunk)
            if delta:
                accumulated += delta
                if "</function>" in accumulated or "</invoke>" in accumulated:
                    end_tag = "</function>" if "</function>" in accumulated else "</invoke>"
                    pos = accumulated.find(end_tag)
                    accumulated = accumulated[: pos + len(end_tag)]
                    yield LLMResponse(content=accumulated)
                    done_streaming = 1
                    continue
                yield LLMResponse(content=accumulated)

        full_response = None
        if chunks:
            full_response = stream_chunk_builder(chunks)
            self._update_usage_stats(full_response)
            # Phase 1.1 — track outcome for failover decision.
            self._record_request_outcome("ok")

        # Roadmap §8.5 Phase 4b — native tool calling. When enabled,
        # extract tool invocations from the API's structured
        # `tool_calls` field rather than parsing XML out of the
        # accumulated text. Falls back to the XML path if native
        # extraction yields nothing (e.g. model returned text only).
        native_tool_invs: list[dict[str, Any]] | None = None
        if self._native_tool_calls_enabled() and full_response is not None:
            native_tool_invs = self._extract_native_tool_invocations(full_response)

        if native_tool_invs:
            yield LLMResponse(
                content=accumulated,
                tool_invocations=native_tool_invs,
                thinking_blocks=self._extract_thinking(chunks),
            )
            return

        accumulated = normalize_tool_format(accumulated)
        accumulated = fix_incomplete_tool_call(_truncate_to_first_function(accumulated))
        yield LLMResponse(
            content=accumulated,
            tool_invocations=parse_tool_invocations(accumulated),
            thinking_blocks=self._extract_thinking(chunks),
        )

    def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Roadmap §8.5 Phase 5 — re-render the system prompt before
        # every call so the SecurityContext snapshot reflects the
        # latest tool-recorded facts. The render is cheap (jinja +
        # in-memory dict to text) and gives the lead a live view of
        # tech stack / endpoints / auth states / partial signals on
        # every turn. Without this, the SecurityContext only fires
        # at LLM-init time and stays stale through the scan.
        #
        # Best-effort: a render failure falls back to the cached
        # `self.system_prompt` from init.
        try:
            refreshed = self._load_system_prompt(self.agent_name)
            if refreshed:
                self.system_prompt = refreshed
        except Exception:  # noqa: BLE001
            pass

        messages = [{"role": "system", "content": self.system_prompt}]

        if self.agent_name:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"\n\n<agent_identity>\n"
                        f"<meta>Internal metadata: do not echo or reference.</meta>\n"
                        f"<agent_name>{self.agent_name}</agent_name>\n"
                        f"<agent_id>{self.agent_id}</agent_id>\n"
                        f"</agent_identity>\n\n"
                    ),
                }
            )

        compressed = list(self.memory_compressor.compress_history(conversation_history))
        conversation_history.clear()
        conversation_history.extend(compressed)
        messages.extend(compressed)

        if messages[-1].get("role") == "assistant" and not self.config.interactive:
            messages.append({"role": "user", "content": "<meta>Continue the task.</meta>"})

        if self._is_anthropic() and self.config.enable_prompt_caching:
            messages = self._add_cache_control(messages)

        # Roadmap §8.5 Phase 0.A — stash a per-component token
        # breakdown for `_update_usage_stats` to emit. Best-effort:
        # any failure leaves `_last_token_breakdown` as None and the
        # `llm.token_breakdown` event simply doesn't fire.
        try:
            from strix.llm.token_breakdown import breakdown_messages

            self._last_token_breakdown = breakdown_messages(
                messages, model=self.config.litellm_model,
            )
        except Exception:  # noqa: BLE001
            self._last_token_breakdown = None
            logger.debug("token_breakdown failed", exc_info=True)

        return messages

    def _build_completion_args(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        if not self._supports_vision():
            messages = self._strip_images(messages)

        args: dict[str, Any] = {
            "model": self.config.litellm_model,
            "messages": messages,
            "timeout": self.config.timeout,
            "stream_options": {"include_usage": True},
        }

        if self.config.api_key:
            args["api_key"] = self.config.api_key
        if self.config.api_base:
            args["api_base"] = self.config.api_base
        if self._supports_reasoning():
            args["reasoning_effort"] = self._reasoning_effort

        # Roadmap §8.5 Phase 4b — native tool calling. When the
        # `STRIX_TOOL_CALL_FORMAT=native` env var is set, pass the
        # tool catalog as `tools=[...]` JSON Schema. The provider's
        # API enforces the schema, so the model can't malformed-call
        # — eliminating the entire class of XML-format failures
        # that PRs #163-#175 worked around at the prompt level.
        #
        # When the flag is unset (default), behavior is unchanged:
        # the model invokes tools via the `<function=...>` XML tags
        # rendered into the system prompt by `get_tools_prompt()`.
        if self._native_tool_calls_enabled():
            try:
                from strix.tools.json_schema import get_tools_json_schema

                allowlist = self._system_prompt_context.get("tool_catalog_allowlist")
                tools_schema = get_tools_json_schema(allowlist=allowlist)
                if tools_schema:
                    args["tools"] = tools_schema
                    args["tool_choice"] = "auto"
            except Exception:  # noqa: BLE001
                logger.debug("native tool schema construction failed", exc_info=True)

        return args

    def _resolve_failover_model(self) -> str | None:
        """Phase 1.1 — failover model selection.

        Priority:
          1. `STRIX_LLM_FAILOVER` env var (explicit override).
          2. Built-in defaults: gemini → claude-sonnet-4.5; claude
             → gpt-4o; openai → claude-sonnet-4.5.
          3. None — failover disabled.
        """
        explicit = os.environ.get("STRIX_LLM_FAILOVER", "").strip()
        if explicit:
            return explicit
        primary = (self.config.litellm_model or "").lower()
        if "gemini" in primary or "vertex" in primary:
            return "anthropic/claude-sonnet-4-5-20250929"
        if "anthropic" in primary or "claude" in primary:
            return "openai/gpt-4o"
        if "openai" in primary or "gpt-" in primary:
            return "anthropic/claude-sonnet-4-5-20250929"
        return None

    def _record_request_outcome(self, outcome: str) -> None:
        """Append an outcome to the rolling window. Called from the
        retry loop and after successful completions."""
        import time as _time
        now = _time.time()
        self._request_history.append((now, outcome))
        # Trim entries older than 5 minutes.
        cutoff = now - 300
        self._request_history = [
            (t, o) for (t, o) in self._request_history if t >= cutoff
        ]
        self._maybe_failover()

    def _maybe_failover(self) -> None:
        """Phase 1.1 — when retry rate over the trailing 5-min
        window exceeds 50% AND we have at least 6 outcomes, swap to
        the failover model. Conversely if the rate drops below 25%
        AND failover is active, swap back.
        """
        if not self._failover_model:
            return
        if len(self._request_history) < 6:
            return

        retries = sum(1 for _, o in self._request_history if o == "retry")
        total = len(self._request_history)
        retry_rate = retries / total

        if not self._failover_active and retry_rate > 0.5:
            old_model = self.config.litellm_model
            self.config.litellm_model = self._failover_model
            self._failover_active = True
            logger.warning(
                "LLM provider failover: retry_rate=%.2f exceeds 0.5 over "
                "trailing window (%d outcomes). Swapping %s → %s",
                retry_rate, total, old_model, self._failover_model,
            )
            self._emit_failover_event(
                from_model=old_model,
                to_model=self._failover_model,
                retry_rate=retry_rate,
            )
            # Reset history so next window measures the new provider.
            self._request_history = []
        elif self._failover_active and retry_rate < 0.25 and total >= 10:
            old_model = self.config.litellm_model
            self.config.litellm_model = self._original_model
            self._failover_active = False
            logger.info(
                "LLM provider failover: retry_rate dropped to %.2f. "
                "Swapping back %s → %s",
                retry_rate, old_model, self._original_model,
            )
            self._emit_failover_event(
                from_model=old_model,
                to_model=self._original_model,
                retry_rate=retry_rate,
            )
            self._request_history = []

    def _emit_failover_event(
        self, *, from_model: str, to_model: str, retry_rate: float,
    ) -> None:
        """Emit a `llm.provider_failed_over` event for wrapper
        visibility. Best-effort."""
        try:
            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer is None:
                return
            tracer._emit_event(  # noqa: SLF001
                "llm.provider_failed_over",
                actor={
                    "agent_id": getattr(self, "agent_id", None),
                    "agent_name": self.agent_name,
                },
                payload={
                    "from_model": from_model,
                    "to_model": to_model,
                    "retry_rate": round(float(retry_rate), 2),
                    "window_seconds": 300,
                },
                status="failed_over",
                source="strix.llm",
            )
        except Exception:  # noqa: BLE001
            pass

    def _native_tool_calls_enabled(self) -> bool:
        """Return True when `STRIX_TOOL_CALL_FORMAT=native` is set
        (case-insensitive). Default is `xml` — preserves existing
        behaviour through Phase 4b's rollout.
        """
        return os.environ.get("STRIX_TOOL_CALL_FORMAT", "xml").strip().lower() == "native"

    def _extract_native_tool_invocations(
        self, response: Any,
    ) -> list[dict[str, Any]] | None:
        """Convert litellm's native tool_calls list to strix's
        existing `tool_invocations` shape:

            [{"toolName": "<name>", "args": {<dict>}}, ...]

        The downstream executor (`_execute_single_tool`) consumes
        this shape unchanged. So flipping native mode is internal
        to the LLM client; no executor changes needed.

        Returns None when no tool_calls present (model emitted text
        only). Best-effort: malformed entries are dropped silently.
        """
        try:
            choices = getattr(response, "choices", None) or response.get("choices", [])
            if not choices:
                return None
            message = getattr(choices[0], "message", None)
            if message is None and isinstance(choices[0], dict):
                message = choices[0].get("message")
            if message is None:
                return None
            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls is None and isinstance(message, dict):
                tool_calls = message.get("tool_calls")
            if not tool_calls:
                return None

            out: list[dict[str, Any]] = []
            import json as _json

            for tc in tool_calls:
                fn = getattr(tc, "function", None)
                if fn is None and isinstance(tc, dict):
                    fn = tc.get("function")
                if fn is None:
                    continue
                name = getattr(fn, "name", None)
                if name is None and isinstance(fn, dict):
                    name = fn.get("name")
                args_raw = getattr(fn, "arguments", None)
                if args_raw is None and isinstance(fn, dict):
                    args_raw = fn.get("arguments")
                # arguments is JSON-encoded string per OpenAI spec;
                # litellm normalises to that across providers.
                if isinstance(args_raw, str):
                    try:
                        args = _json.loads(args_raw) if args_raw else {}
                    except Exception:  # noqa: BLE001
                        args = {}
                elif isinstance(args_raw, dict):
                    args = args_raw
                else:
                    args = {}
                if name:
                    out.append({"toolName": name, "args": args})
            return out or None
        except Exception:  # noqa: BLE001
            logger.debug("native tool_calls extraction failed", exc_info=True)
            return None

    def _get_chunk_content(self, chunk: Any) -> str:
        if chunk.choices and hasattr(chunk.choices[0], "delta"):
            return getattr(chunk.choices[0].delta, "content", "") or ""
        return ""

    def _extract_thinking(self, chunks: list[Any]) -> list[dict[str, Any]] | None:
        if not chunks or not self._supports_reasoning():
            return None
        try:
            resp = stream_chunk_builder(chunks)
            if resp.choices and hasattr(resp.choices[0].message, "thinking_blocks"):
                blocks: list[dict[str, Any]] = resp.choices[0].message.thinking_blocks
                return blocks
        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass
        return None

    def _update_usage_stats(self, response: Any) -> None:
        try:
            if hasattr(response, "usage") and response.usage:
                input_tokens = getattr(response.usage, "prompt_tokens", 0) or 0
                output_tokens = getattr(response.usage, "completion_tokens", 0) or 0

                cached_tokens = 0
                if hasattr(response.usage, "prompt_tokens_details"):
                    prompt_details = response.usage.prompt_tokens_details
                    if hasattr(prompt_details, "cached_tokens"):
                        cached_tokens = prompt_details.cached_tokens or 0

                cost = self._extract_cost(response)
            else:
                input_tokens = 0
                output_tokens = 0
                cached_tokens = 0
                cost = 0.0

            self._total_stats.input_tokens += input_tokens
            self._total_stats.output_tokens += output_tokens
            self._total_stats.cached_tokens += cached_tokens
            self._total_stats.cost += cost
            self._total_stats.requests += 1

            # Roadmap §4 PR #113 — accumulate run-level totals so
            # `--max-cost` / `--max-input-tokens` self-exit can fire.
            # Cheap module-level singleton, decoupled from per-LLM
            # stats so multi-agent runs aggregate correctly.
            try:
                from strix.llm.run_budget import record_run_usage

                record_run_usage(
                    input_tokens=int(input_tokens),
                    output_tokens=int(output_tokens),
                    cached_tokens=int(cached_tokens),
                    cost_usd=float(cost),
                )
            except Exception:  # noqa: BLE001
                logger.debug("run_budget.record_run_usage failed", exc_info=True)

            # Roadmap §5 — emit per-event token usage so wrappers can
            # render live cost meters + enforce mid-flight cost caps.
            # Fail-open if the tracer isn't available.
            try:
                from strix.telemetry.tracer import get_global_tracer

                tracer = get_global_tracer()
                if tracer is not None:
                    tracer._emit_event(
                        "llm.request.completed",
                        payload={
                            "model": getattr(self.config, "canonical_model", None)
                                or getattr(self.config, "model", None),
                            "agent_id": self.agent_id,
                            "agent_name": self.agent_name,
                            "input_tokens": int(input_tokens),
                            "output_tokens": int(output_tokens),
                            "cached_tokens": int(cached_tokens),
                            "cost": round(float(cost), 6),
                            "cumulative": {
                                "input_tokens": int(self._total_stats.input_tokens),
                                "output_tokens": int(self._total_stats.output_tokens),
                                "cached_tokens": int(self._total_stats.cached_tokens),
                                "cost": round(float(self._total_stats.cost), 6),
                                "requests": int(self._total_stats.requests),
                            },
                        },
                        actor={"id": self.agent_id} if self.agent_id else None,
                        status="ok",
                        source="strix.llm",
                    )
            except Exception:  # noqa: BLE001, S110
                pass  # noqa: PIE790

            # Roadmap §8.5 Phase 0.A — emit per-component token
            # breakdown so the operator can bisect where the per-call
            # token cost lives. New event `llm.token_breakdown` is
            # additive (wrappers ignoring unknown events keep working
            # per engine-usage.md §6 versioning contract).
            try:
                breakdown = self._last_token_breakdown
                if breakdown is not None:
                    from strix.telemetry.tracer import get_global_tracer

                    tracer = get_global_tracer()
                    if tracer is not None:
                        tracer._emit_event(
                            "llm.token_breakdown",
                            payload={
                                "schema_version": breakdown.get("schema_version", 1),
                                "model": getattr(self.config, "canonical_model", None)
                                    or getattr(self.config, "model", None),
                                "agent_id": self.agent_id,
                                "agent_name": self.agent_name,
                                # Estimated per-component (tokens).
                                "system_tokens": int(breakdown.get("system_tokens", 0)),
                                "agent_identity_tokens": int(
                                    breakdown.get("agent_identity_tokens", 0)
                                ),
                                "conversation_tokens": int(
                                    breakdown.get("conversation_tokens", 0)
                                ),
                                "total_input_tokens_estimated": int(
                                    breakdown.get("total_input_tokens_estimated", 0)
                                ),
                                "message_count": int(breakdown.get("message_count", 0)),
                                # Measured (from the response — provider-reported).
                                "measured_input_tokens": int(input_tokens),
                                "measured_output_tokens": int(output_tokens),
                                "measured_cached_tokens": int(cached_tokens),
                                "measured_cost_usd": round(float(cost), 6),
                                # Cache-hit ratio for this call.
                                "cache_hit_ratio": (
                                    round(float(cached_tokens) / float(input_tokens), 4)
                                    if input_tokens > 0 else 0.0
                                ),
                            },
                            actor={"id": self.agent_id} if self.agent_id else None,
                            status="ok",
                            source="strix.llm.token_breakdown",
                        )
            except Exception:  # noqa: BLE001, S110
                pass  # noqa: PIE790

        except Exception:  # noqa: BLE001, S110  # nosec B110
            pass

    def _extract_cost(self, response: Any) -> float:
        if hasattr(response, "usage") and response.usage:
            direct_cost = getattr(response.usage, "cost", None)
            if direct_cost is not None:
                return float(direct_cost)
        try:
            if hasattr(response, "_hidden_params"):
                response._hidden_params.pop("custom_llm_provider", None)
            return completion_cost(response, model=self.config.canonical_model) or 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    def _should_retry(self, e: Exception) -> bool:
        code = getattr(e, "status_code", None) or getattr(
            getattr(e, "response", None), "status_code", None
        )
        return code is None or litellm._should_retry(code)

    def _raise_error(self, e: Exception) -> None:
        from strix.telemetry import posthog

        posthog.error("llm_error", type(e).__name__)
        raise LLMRequestFailedError(f"LLM request failed: {type(e).__name__}", str(e)) from e

    def _is_anthropic(self) -> bool:
        if not self.config.model_name:
            return False
        return any(p in self.config.model_name.lower() for p in ["anthropic/", "claude"])

    def _supports_vision(self) -> bool:
        try:
            return bool(supports_vision(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _supports_reasoning(self) -> bool:
        try:
            return bool(supports_reasoning(model=self.config.canonical_model))
        except Exception:  # noqa: BLE001
            return False

    def _strip_images(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, list):
                text_parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                    elif isinstance(item, dict) and item.get("type") == "image_url":
                        text_parts.append("[Image removed - model doesn't support vision]")
                result.append({**msg, "content": "\n".join(text_parts)})
            else:
                result.append(msg)
        return result

    def _add_cache_control(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Delegate cache marker placement to the §8.5 Phase 2
        `CacheManager` so stats track centrally. Behaviour preserved:
        same `cache_control: {type: ephemeral}` marker on the system
        message; `supports_prompt_caching(canonical_model)` gate
        unchanged."""
        if not messages or not supports_prompt_caching(self.config.canonical_model):
            return messages
        if messages[0].get("role") != "system":
            return messages

        try:
            from strix.llm.cache_manager import get_global_cache_manager

            content = messages[0].get("content", "")
            content_text = (
                content if isinstance(content, str)
                else " ".join(
                    item.get("text", "") for item in content
                    if isinstance(item, dict) and item.get("type") == "text"
                )
            )
            if not content_text:
                return messages

            mgr = get_global_cache_manager()
            handle = mgr.register_cached_prompt(
                content=content_text,
                model=self.config.model_name or self.config.canonical_model or "",
            )
            return mgr.apply_to_messages(messages, handles=[handle])
        except Exception:  # noqa: BLE001
            logger.debug("CacheManager delegation failed", exc_info=True)
            # Fallback: legacy direct marker placement.
            result = list(messages)
            content = result[0]["content"]
            result[0] = {
                **result[0],
                "content": [
                    {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}
                ]
                if isinstance(content, str)
                else content,
            }
            return result
