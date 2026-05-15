import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any, Optional


if TYPE_CHECKING:
    from strix.telemetry.tracer import Tracer

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from strix.llm import LLM, LLMConfig, LLMRequestFailedError
from strix.llm.utils import clean_content
from strix.runtime import SandboxInitializationError
from strix.tools import process_tool_invocations
from strix.utils.resource_paths import get_strix_resource_path

from .state import AgentState


logger = logging.getLogger(__name__)


class AgentMeta(type):
    agent_name: str
    jinja_env: Environment

    def __new__(cls, name: str, bases: tuple[type, ...], attrs: dict[str, Any]) -> type:
        new_cls = super().__new__(cls, name, bases, attrs)

        if name == "BaseAgent":
            return new_cls

        prompt_dir = get_strix_resource_path("agents", name)

        new_cls.agent_name = name
        new_cls.jinja_env = Environment(
            loader=FileSystemLoader(prompt_dir),
            autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
        )

        return new_cls


class BaseAgent(metaclass=AgentMeta):
    max_iterations = 300
    agent_name: str = ""
    jinja_env: Environment
    default_llm_config: LLMConfig | None = None

    def __init__(self, config: dict[str, Any]):
        self.config = config

        self.local_sources = config.get("local_sources", [])

        if "max_iterations" in config:
            self.max_iterations = config["max_iterations"]

        self.llm_config_name = config.get("llm_config_name", "default")
        self.llm_config = config.get("llm_config", self.default_llm_config)
        if self.llm_config is None:
            raise ValueError("llm_config is required but not provided")
        state_from_config = config.get("state")
        if state_from_config is not None:
            self.state = state_from_config
        else:
            self.state = AgentState(
                agent_name="Root Agent",
                max_iterations=self.max_iterations,
            )

        # Roadmap §8.0: per-sub-agent budget. Lead agents pass these
        # via the `budget` key in `config` when spawning specialists;
        # 0 / unset means "no limit".
        budget = config.get("budget") or {}
        if isinstance(budget, dict) and budget:
            self.state.set_budget(
                max_input_tokens=budget.get("max_input_tokens"),
                max_output_tokens=budget.get("max_output_tokens"),
                max_cost_usd=budget.get("max_cost_usd"),
                time_budget_seconds=budget.get("time_budget_seconds"),
            )

        self.interactive = getattr(self.llm_config, "interactive", False)
        if self.interactive and self.state.parent_id is None:
            self.state.waiting_timeout = 0
        self.llm = LLM(self.llm_config, agent_name=self.agent_name)

        with contextlib.suppress(Exception):
            self.llm.set_agent_identity(self.state.agent_name, self.state.agent_id)
        self._current_task: asyncio.Task[Any] | None = None
        self._force_stop = False

        # Roadmap §8.0: track the last LLM cumulative-stats snapshot
        # we pushed to the agent state, so we can record deltas
        # incrementally without double-counting.
        self._last_pushed_input_tokens = 0
        self._last_pushed_output_tokens = 0
        self._last_pushed_cost = 0.0

        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            tracer.log_agent_creation(
                agent_id=self.state.agent_id,
                name=self.state.agent_name,
                task=self.state.task,
                parent_id=self.state.parent_id,
                category=self.state.category,
            )
            if self.state.parent_id is None:
                scan_config = tracer.scan_config or {}
                exec_id = tracer.log_tool_execution_start(
                    agent_id=self.state.agent_id,
                    tool_name="scan_start_info",
                    args=scan_config,
                )
                tracer.update_tool_execution(execution_id=exec_id, status="completed", result={})

            else:
                exec_id = tracer.log_tool_execution_start(
                    agent_id=self.state.agent_id,
                    tool_name="subagent_start_info",
                    args={
                        "name": self.state.agent_name,
                        "task": self.state.task,
                        "parent_id": self.state.parent_id,
                    },
                )
                tracer.update_tool_execution(execution_id=exec_id, status="completed", result={})

        self._add_to_agents_graph()

    def _sync_budget_from_llm(self, tracer: Any | None) -> None:
        """Push LLM cumulative-stats deltas into the agent state and,
        if a budget was just exceeded, emit `agent.budget_exceeded`
        once. Roadmap §8.0.

        Reads `self.llm._total_stats` (RequestStats with input_tokens,
        output_tokens, cost). Computes delta vs. last-pushed totals,
        records onto `self.state`, then queries
        `state.has_exceeded_budget()` to see if the just-recorded
        usage tipped over a limit. The event is emitted only on the
        first transition (`budget_exceeded_event_emitted`)."""
        try:
            stats = getattr(self.llm, "_total_stats", None)
            if stats is None:
                return
            cur_input = int(getattr(stats, "input_tokens", 0) or 0)
            cur_output = int(getattr(stats, "output_tokens", 0) or 0)
            cur_cost = float(getattr(stats, "cost", 0.0) or 0.0)

            d_input = max(0, cur_input - self._last_pushed_input_tokens)
            d_output = max(0, cur_output - self._last_pushed_output_tokens)
            d_cost = max(0.0, cur_cost - self._last_pushed_cost)

            if d_input or d_output or d_cost:
                self.state.record_token_usage(
                    input_tokens=d_input,
                    output_tokens=d_output,
                    cost_usd=d_cost,
                )
                self._last_pushed_input_tokens = cur_input
                self._last_pushed_output_tokens = cur_output
                self._last_pushed_cost = cur_cost

            exceeded, reason = self.state.has_exceeded_budget()
            if exceeded and not self.state.budget_exceeded_event_emitted:
                self.state.budget_exceeded_event_emitted = True
                self.state.budget_exceeded_reason = reason
                if tracer is not None:
                    try:
                        tracer._emit_event(
                            "agent.budget_exceeded",
                            payload={
                                "agent_id": self.state.agent_id,
                                "agent_name": self.state.agent_name,
                                "category": self.state.category,
                                "parent_id": self.state.parent_id,
                                "reason": reason,
                                "iteration": self.state.iteration,
                                "input_tokens_consumed": self.state.input_tokens_consumed,
                                "output_tokens_consumed": self.state.output_tokens_consumed,
                                "cost_consumed_usd": round(
                                    self.state.cost_consumed_usd, 4,
                                ),
                                "limits": {
                                    "max_input_tokens": self.state.max_input_tokens,
                                    "max_output_tokens": self.state.max_output_tokens,
                                    "max_cost_usd": self.state.max_cost_usd,
                                    "time_budget_seconds": self.state.time_budget_seconds,
                                },
                            },
                            actor={"id": self.state.agent_id},
                            status="error",
                            source="strix.agents.budget",
                        )
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            # Budget tracking must NEVER break the agent loop.
            pass

    def _on_iteration_tick(self) -> bool:
        """Roadmap §8.5 Phase 6 hook — fires once per agent_loop
        iteration, AFTER `state.increment_iteration()` and BEFORE
        the LLM call.

        Default implementation is a no-op (returns False — keep
        looping). The lead agent overrides this to tick its
        watchdog + check compaction triggers.

        Returns:
            True to force the loop to stop gracefully (lead-agent
            watchdog idle threshold reached). False to continue.

        Best-effort throughout — the agent_loop wraps this in
        try/except so an override that raises won't break the loop.
        """
        return False

    def _maybe_emit_heartbeat(self, tracer: Any | None) -> None:
        """Emit `run.heartbeat` at most once every 60 seconds with
        last-activity timestamps. Roadmap §4. Wrappers tail this
        event to detect stuck scans without polling.
        """
        if tracer is None:
            return
        try:
            from datetime import UTC, datetime

            now = datetime.now(UTC)
            last_hb_str = self.state.last_heartbeat_emitted_at
            if last_hb_str:
                try:
                    last_hb = datetime.fromisoformat(last_hb_str)
                    elapsed = (now - last_hb).total_seconds()
                    if elapsed < 60.0:
                        return
                except (ValueError, TypeError):
                    pass

            # Compute seconds_idle = since the most recent meaningful
            # activity. Only tool calls + LLM requests count;
            # last_updated covers bookkeeping (state mutations /
            # message-add) and would mask genuine idleness.
            most_recent: datetime | None = None
            for ts in (
                self.state.last_tool_call_at,
                self.state.last_llm_request_at,
            ):
                if not ts:
                    continue
                try:
                    parsed = datetime.fromisoformat(ts)
                    if most_recent is None or parsed > most_recent:
                        most_recent = parsed
                except (ValueError, TypeError):
                    pass
            seconds_idle = (
                int((now - most_recent).total_seconds())
                if most_recent else 0
            )

            tracer._emit_event(
                "run.heartbeat",
                payload={
                    "agent_id": self.state.agent_id,
                    "agent_name": self.state.agent_name,
                    "iteration": self.state.iteration,
                    "last_activity_at": (
                        most_recent.isoformat() if most_recent else None
                    ),
                    "seconds_idle": seconds_idle,
                    "last_tool_call_at": self.state.last_tool_call_at,
                    "last_tool_call_name": self.state.last_tool_call_name,
                    "last_llm_request_at": self.state.last_llm_request_at,
                },
                actor={"id": self.state.agent_id},
                status="info",
                source="strix.run",
            )
            self.state.last_heartbeat_emitted_at = now.isoformat()
        except Exception:  # noqa: BLE001
            # Heartbeat must NEVER break the agent loop.
            pass

    def _add_to_agents_graph(self) -> None:
        from strix.tools.agents_graph import agents_graph_actions

        node = {
            "id": self.state.agent_id,
            "name": self.state.agent_name,
            "category": self.state.category,
            "task": self.state.task,
            "status": "running",
            "parent_id": self.state.parent_id,
            "created_at": self.state.start_time,
            "finished_at": None,
            "result": None,
            "llm_config": self.llm_config_name,
            "agent_type": self.__class__.__name__,
            "state": self.state.model_dump(),
        }
        agents_graph_actions._agent_graph["nodes"][self.state.agent_id] = node

        with agents_graph_actions._agent_llm_stats_lock:
            agents_graph_actions._agent_instances[self.state.agent_id] = self
        agents_graph_actions._agent_states[self.state.agent_id] = self.state

        if self.state.parent_id:
            agents_graph_actions._agent_graph["edges"].append(
                {"from": self.state.parent_id, "to": self.state.agent_id, "type": "delegation"}
            )

        if self.state.agent_id not in agents_graph_actions._agent_messages:
            agents_graph_actions._agent_messages[self.state.agent_id] = []

        if self.state.parent_id is None and agents_graph_actions._root_agent_id is None:
            agents_graph_actions._root_agent_id = self.state.agent_id

    async def agent_loop(self, task: str) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()

        try:
            await self._initialize_sandbox_and_state(task)
        except SandboxInitializationError as e:
            return self._handle_sandbox_error(e, tracer)

        while True:
            if self._force_stop:
                self._force_stop = False
                await self._enter_waiting_state(tracer, was_cancelled=True)
                continue

            self._check_agent_messages(self.state)

            # Roadmap §4 PR #113 — run-level cost / token cap.
            # When --max-cost / --max-input-tokens fires, every
            # agent in the run terminates cleanly and the runner
            # exits with EXIT_BUDGET_EXCEEDED (3). Belt-and-braces
            # against the per-sub-agent budget (#88).
            try:
                from strix.llm.run_budget import (
                    emit_run_terminated_event_once,
                    is_run_budget_exceeded,
                )

                exceeded, _reason = is_run_budget_exceeded()
                if exceeded:
                    emit_run_terminated_event_once()
                    self.state.request_stop()
            except Exception:  # noqa: BLE001
                # Bookkeeping failure should never break the loop.
                pass

            # Roadmap §4 PR #114 — clean SIGTERM/SIGINT handling.
            # When a wrapper hits its "cancel scan" button, the
            # signal handler latches the request; the agent loop
            # picks it up here and winds down gracefully so the
            # runner can flush events.jsonl, teardown the sandbox,
            # and exit with EXIT_SIGTERM (143) / EXIT_SIGINT (130).
            try:
                from strix.interface.cancel_handler import (
                    emit_run_cancelled_event_once,
                    is_cancellation_requested,
                )

                cancel_requested, _signum = is_cancellation_requested()
                if cancel_requested:
                    emit_run_cancelled_event_once()
                    self.state.request_stop()
            except Exception:  # noqa: BLE001
                pass

            # PR-γ — progress watchdog (5th termination criterion).
            # Inject a "stalled" message into the lead's next-turn
            # context so the LLM observes + reorients. At the
            # escalation tier, force-advance to report phase + stop.
            # Only run on the lead agent (parent_id is None) — sub-
            # agents don't need their own watchdog.
            if self.state.parent_id is None:
                try:
                    from strix.agents.progress_watchdog import (
                        get_warning_message,
                        should_escalate,
                    )

                    warning = get_warning_message()
                    if warning:
                        self.state.add_message("user", warning)
                        if should_escalate():
                            # Hard intervention — force phase to
                            # report so the next finish_scan call
                            # passes the workflow guard, and
                            # request_stop after that to bound
                            # further LLM cost.
                            try:
                                from strix.agents.workflow_state import (
                                    advance_phase,
                                )
                                advance_phase(
                                    target="report",
                                    reason="progress_watchdog escalation",
                                    force=True,
                                )
                            except Exception:  # noqa: BLE001
                                pass
                except Exception:  # noqa: BLE001
                    # Watchdog must never break the loop.
                    pass

            if self.state.is_waiting_for_input():
                await self._wait_for_input()
                continue

            if self.state.should_stop():
                if not self.interactive:
                    return self.state.final_result or {}
                await self._enter_waiting_state(tracer)
                continue

            if self.state.llm_failed:
                await self._wait_for_input()
                continue

            self.state.increment_iteration()

            # Roadmap §8.5 Phase 6 — per-iteration hook for the lead
            # agent to tick its watchdog + check compaction triggers.
            # Default implementation is a no-op (BaseAgent doesn't
            # need watchdog semantics; LeadAgent overrides).
            try:
                if self._on_iteration_tick():
                    # Hook signalled "force exit" (e.g., watchdog
                    # idle threshold reached). Treat as graceful stop.
                    self.state.request_stop()
                    continue
            except Exception:  # noqa: BLE001
                # Iteration hook must never break the agent loop.
                logger.debug("agent_loop._on_iteration_tick failed", exc_info=True)

            if (
                self.state.is_approaching_max_iterations()
                and not self.state.max_iterations_warning_sent
            ):
                self.state.max_iterations_warning_sent = True
                remaining = self.state.max_iterations - self.state.iteration
                warning_msg = (
                    f"URGENT: You are approaching the maximum iteration limit. "
                    f"Current: {self.state.iteration}/{self.state.max_iterations} "
                    f"({remaining} iterations remaining). "
                    f"Please prioritize completing your required task(s) and calling "
                    f"the appropriate finish tool (finish_scan for root agent, "
                    f"agent_finish for sub-agents) as soon as possible."
                )
                self.state.add_message("user", warning_msg)

            if self.state.iteration == self.state.max_iterations - 3:
                final_warning_msg = (
                    "CRITICAL: You have only 3 iterations left! "
                    "Your next message MUST be the tool call to the appropriate "
                    "finish tool: finish_scan if you are the root agent, or "
                    "agent_finish if you are a sub-agent. "
                    "No other actions should be taken except finishing your work "
                    "immediately."
                )
                self.state.add_message("user", final_warning_msg)

            try:
                iteration_task = asyncio.create_task(self._process_iteration(tracer))
                self._current_task = iteration_task
                should_finish = await iteration_task
                self._current_task = None

                # Roadmap §8.0: push LLM token-usage deltas into the
                # agent state so the budget check in should_stop()
                # has up-to-date counters. Emit `agent.budget_exceeded`
                # event the first time a budget is exceeded.
                self._sync_budget_from_llm(tracer)

                # Roadmap §4: emit `run.heartbeat` at most once every
                # 60 seconds so wrappers can detect stuck scans
                # without polling.
                self._maybe_emit_heartbeat(tracer)

                if should_finish is None and self.interactive:
                    await self._enter_waiting_state(tracer, text_response=True)
                    continue

                if should_finish:
                    if not self.interactive:
                        self.state.set_completed({"success": True})
                        if tracer:
                            tracer.update_agent_status(self.state.agent_id, "completed")
                        return self.state.final_result or {}
                    await self._enter_waiting_state(tracer, task_completed=True)
                    continue

            except asyncio.CancelledError:
                self._current_task = None
                if tracer:
                    partial_content = tracer.finalize_streaming_as_interrupted(self.state.agent_id)
                    if partial_content and partial_content.strip():
                        self.state.add_message(
                            "assistant", f"{partial_content}\n\n[ABORTED BY USER]"
                        )
                if not self.interactive:
                    raise
                await self._enter_waiting_state(tracer, error_occurred=False, was_cancelled=True)
                continue

            except LLMRequestFailedError as e:
                result = self._handle_llm_error(e, tracer)
                if result is not None:
                    return result
                continue

            except (RuntimeError, ValueError, TypeError) as e:
                if not await self._handle_iteration_error(e, tracer):
                    if not self.interactive:
                        self.state.set_completed({"success": False, "error": str(e)})
                        if tracer:
                            tracer.update_agent_status(self.state.agent_id, "failed")
                        raise
                    await self._enter_waiting_state(tracer, error_occurred=True)
                    continue

    async def _wait_for_input(self) -> None:
        if self._force_stop:
            return

        if self.state.has_waiting_timeout():
            self.state.resume_from_waiting()
            self.state.add_message("user", "Waiting timeout reached. Resuming execution.")

            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "running")

            try:
                from strix.tools.agents_graph.agents_graph_actions import _agent_graph

                if self.state.agent_id in _agent_graph["nodes"]:
                    _agent_graph["nodes"][self.state.agent_id]["status"] = "running"
            except (ImportError, KeyError):
                pass

            return

        await asyncio.sleep(0.5)

    async def _enter_waiting_state(
        self,
        tracer: Optional["Tracer"],
        task_completed: bool = False,
        error_occurred: bool = False,
        was_cancelled: bool = False,
        text_response: bool = False,
    ) -> None:
        self.state.enter_waiting_state()

        if tracer:
            if text_response:
                tracer.update_agent_status(self.state.agent_id, "waiting_for_input")
            elif task_completed:
                tracer.update_agent_status(self.state.agent_id, "completed")
            elif error_occurred:
                tracer.update_agent_status(self.state.agent_id, "error")
            elif was_cancelled:
                tracer.update_agent_status(self.state.agent_id, "stopped")
            else:
                tracer.update_agent_status(self.state.agent_id, "stopped")

        if text_response:
            return

        if task_completed:
            self.state.add_message(
                "assistant",
                "Task completed. I'm now waiting for follow-up instructions or new tasks.",
            )
        elif error_occurred:
            self.state.add_message(
                "assistant", "An error occurred. I'm now waiting for new instructions."
            )
        elif was_cancelled:
            self.state.add_message(
                "assistant", "Execution was cancelled. I'm now waiting for new instructions."
            )
        else:
            self.state.add_message(
                "assistant",
                "Execution paused. I'm now waiting for new instructions or any updates.",
            )

    async def _initialize_sandbox_and_state(self, task: str) -> None:
        import os

        sandbox_mode = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
        if not sandbox_mode and self.state.sandbox_id is None:
            from strix.runtime import get_runtime

            try:
                runtime = get_runtime()
                sandbox_info = await runtime.create_sandbox(
                    self.state.agent_id, self.state.sandbox_token, self.local_sources
                )
                self.state.sandbox_id = sandbox_info["workspace_id"]
                self.state.sandbox_token = sandbox_info["auth_token"]
                self.state.sandbox_info = sandbox_info

                if "agent_id" in sandbox_info:
                    self.state.sandbox_info["agent_id"] = sandbox_info["agent_id"]

                caido_port = sandbox_info.get("caido_port")
                if caido_port:
                    from strix.telemetry.tracer import get_global_tracer

                    tracer = get_global_tracer()
                    if tracer:
                        tracer.caido_url = f"localhost:{caido_port}"
            except Exception as e:
                from strix.telemetry import posthog

                posthog.error("sandbox_init_error", str(e))
                raise

        if not self.state.task:
            self.state.task = task

        self.state.add_message("user", task)

    async def _process_iteration(self, tracer: Optional["Tracer"]) -> bool | None:
        final_response = None

        async for response in self.llm.generate(self.state.get_conversation_history()):
            final_response = response
            if tracer and response.content:
                tracer.update_streaming_content(self.state.agent_id, response.content)

        if final_response is None:
            return False

        content_stripped = (final_response.content or "").strip()

        if not content_stripped:
            corrective_message = (
                "You MUST NOT respond with empty messages. "
                "If you currently have nothing to do or say, use an appropriate tool instead:\n"
                "- Use agents_graph_actions.wait_for_message to wait for messages "
                "from user or other agents\n"
                "- Use agents_graph_actions.agent_finish if you are a sub-agent "
                "and your task is complete\n"
                "- Use finish_actions.finish_scan if you are the root/main agent "
                "and the scan is complete"
            )
            self.state.add_message("user", corrective_message)
            return False

        thinking_blocks = getattr(final_response, "thinking_blocks", None)
        self.state.add_message("assistant", final_response.content, thinking_blocks=thinking_blocks)
        if tracer:
            tracer.clear_streaming_content(self.state.agent_id)
            tracer.log_chat_message(
                content=clean_content(final_response.content),
                role="assistant",
                agent_id=self.state.agent_id,
            )

        actions = (
            final_response.tool_invocations
            if hasattr(final_response, "tool_invocations") and final_response.tool_invocations
            else []
        )

        if actions:
            return await self._execute_actions(actions, tracer)

        return None

    async def _execute_actions(self, actions: list[Any], tracer: Optional["Tracer"]) -> bool:
        """Execute actions and return True if agent should finish."""
        for action in actions:
            self.state.add_action(action)

        conversation_history = self.state.get_conversation_history()

        tool_task = asyncio.create_task(
            process_tool_invocations(actions, conversation_history, self.state)
        )
        self._current_task = tool_task

        try:
            should_agent_finish = await tool_task
            self._current_task = None
        except asyncio.CancelledError:
            self._current_task = None
            self.state.add_error("Tool execution cancelled by user")
            raise

        self.state.messages = conversation_history

        if should_agent_finish:
            self.state.set_completed({"success": True})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "completed")
            if not self.interactive and self.state.parent_id is None:
                return True
            return True

        return False

    def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
        try:
            from strix.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages

            agent_id = state.agent_id
            if not agent_id or agent_id not in _agent_messages:
                return

            messages = _agent_messages[agent_id]
            if messages:
                has_new_messages = False
                for message in messages:
                    if not message.get("read", False):
                        sender_id = message.get("from")

                        if state.is_waiting_for_input():
                            if state.llm_failed:
                                if sender_id == "user":
                                    state.resume_from_waiting()
                                    has_new_messages = True

                                    from strix.telemetry.tracer import get_global_tracer

                                    tracer = get_global_tracer()
                                    if tracer:
                                        tracer.update_agent_status(state.agent_id, "running")
                            else:
                                state.resume_from_waiting()
                                has_new_messages = True

                                from strix.telemetry.tracer import get_global_tracer

                                tracer = get_global_tracer()
                                if tracer:
                                    tracer.update_agent_status(state.agent_id, "running")

                        if sender_id == "user":
                            sender_name = "User"
                            state.add_message("user", message.get("content", ""))
                        else:
                            if sender_id and sender_id in _agent_graph.get("nodes", {}):
                                sender_name = _agent_graph["nodes"][sender_id]["name"]

                            message_content = f"""<inter_agent_message>
    <delivery_notice>
        <important>You have received a message from another agent. You should acknowledge
        this message and respond appropriately based on its content. However, DO NOT echo
        back or repeat the entire message structure in your response. Simply process the
        content and respond naturally as/if needed.</important>
    </delivery_notice>
    <sender>
        <agent_name>{sender_name}</agent_name>
        <agent_id>{sender_id}</agent_id>
    </sender>
    <message_metadata>
        <type>{message.get("message_type", "information")}</type>
        <priority>{message.get("priority", "normal")}</priority>
        <timestamp>{message.get("timestamp", "")}</timestamp>
    </message_metadata>
    <content>
{message.get("content", "")}
    </content>
    <delivery_info>
        <note>This message was delivered during your task execution.
        Please acknowledge and respond if needed.</note>
    </delivery_info>
</inter_agent_message>"""
                            state.add_message("user", message_content.strip())

                        message["read"] = True

                if has_new_messages and not state.is_waiting_for_input():
                    from strix.telemetry.tracer import get_global_tracer

                    tracer = get_global_tracer()
                    if tracer:
                        tracer.update_agent_status(agent_id, "running")

        except (AttributeError, KeyError, TypeError) as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"Error checking agent messages: {e}")
            return

    def _handle_sandbox_error(
        self,
        error: SandboxInitializationError,
        tracer: Optional["Tracer"],
    ) -> dict[str, Any]:
        error_msg = str(error.message)
        error_details = error.details
        self.state.add_error(error_msg)

        if not self.interactive:
            self.state.set_completed({"success": False, "error": error_msg})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "failed", error_msg)
                if error_details:
                    exec_id = tracer.log_tool_execution_start(
                        self.state.agent_id,
                        "sandbox_error_details",
                        {"error": error_msg, "details": error_details},
                    )
                    tracer.update_tool_execution(exec_id, "failed", {"details": error_details})
            return {"success": False, "error": error_msg, "details": error_details}

        self.state.enter_waiting_state()
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "sandbox_failed", error_msg)
            if error_details:
                exec_id = tracer.log_tool_execution_start(
                    self.state.agent_id,
                    "sandbox_error_details",
                    {"error": error_msg, "details": error_details},
                )
                tracer.update_tool_execution(exec_id, "failed", {"details": error_details})

        return {"success": False, "error": error_msg, "details": error_details}

    def _handle_llm_error(
        self,
        error: LLMRequestFailedError,
        tracer: Optional["Tracer"],
    ) -> dict[str, Any] | None:
        error_msg = str(error)
        error_details = getattr(error, "details", None)
        self.state.add_error(error_msg)

        if not self.interactive:
            self.state.set_completed({"success": False, "error": error_msg})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "failed", error_msg)
                if error_details:
                    exec_id = tracer.log_tool_execution_start(
                        self.state.agent_id,
                        "llm_error_details",
                        {"error": error_msg, "details": error_details},
                    )
                    tracer.update_tool_execution(exec_id, "failed", {"details": error_details})
            return {"success": False, "error": error_msg}

        self.state.enter_waiting_state(llm_failed=True)
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "llm_failed", error_msg)
            if error_details:
                exec_id = tracer.log_tool_execution_start(
                    self.state.agent_id,
                    "llm_error_details",
                    {"error": error_msg, "details": error_details},
                )
                tracer.update_tool_execution(exec_id, "failed", {"details": error_details})

        return None

    async def _handle_iteration_error(
        self,
        error: RuntimeError | ValueError | TypeError | asyncio.CancelledError,
        tracer: Optional["Tracer"],
    ) -> bool:
        error_msg = f"Error in iteration {self.state.iteration}: {error!s}"
        logger.exception(error_msg)
        self.state.add_error(error_msg)
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "error")
        return True

    def cancel_current_execution(self) -> None:
        self._force_stop = True
        if self._current_task and not self._current_task.done():
            try:
                loop = self._current_task.get_loop()
                loop.call_soon_threadsafe(self._current_task.cancel)
            except RuntimeError:
                self._current_task.cancel()
        self._current_task = None
