import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def _generate_agent_id() -> str:
    return f"agent_{uuid.uuid4().hex[:8]}"


class AgentState(BaseModel):
    agent_id: str = Field(default_factory=_generate_agent_id)
    agent_name: str = "Strix Agent"
    # Roadmap §1: declared role for the agent. Lets downstream UIs render
    # named specialists ("auth-attacker", "ssrf-scanner") rather than
    # echoing the user's full instruction back as the agent label.
    category: str | None = None
    parent_id: str | None = None
    sandbox_id: str | None = None
    sandbox_token: str | None = None
    sandbox_info: dict[str, Any] | None = None

    task: str = ""
    iteration: int = 0
    max_iterations: int = 300
    completed: bool = False
    stop_requested: bool = False
    waiting_for_input: bool = False
    llm_failed: bool = False
    waiting_start_time: datetime | None = None
    waiting_timeout: int = 600
    final_result: dict[str, Any] | None = None
    max_iterations_warning_sent: bool = False

    # Roadmap §8.0: per-sub-agent budget enforcement.
    # Each budget is an upper bound; 0 / None means "no limit". When
    # any limit is exceeded, `should_stop()` returns True and the
    # outer loop emits an `agent.budget_exceeded` event with the
    # specific reason. This prevents one runaway specialist from
    # starving the rest of the team.
    max_input_tokens: int = 0           # 0 = unlimited
    max_output_tokens: int = 0          # 0 = unlimited
    max_cost_usd: float = 0.0           # 0.0 = unlimited
    time_budget_seconds: int = 0        # 0 = unlimited
    input_tokens_consumed: int = 0
    output_tokens_consumed: int = 0
    cost_consumed_usd: float = 0.0
    budget_exceeded_reason: str | None = None
    budget_exceeded_event_emitted: bool = False

    # Roadmap §4: run.heartbeat tracking. The agent loop checks
    # whether enough time has elapsed since the last heartbeat
    # emission and fires `run.heartbeat` with these timestamps.
    last_tool_call_at: str | None = None
    last_llm_request_at: str | None = None
    last_heartbeat_emitted_at: str | None = None
    last_tool_call_name: str | None = None

    messages: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_message(
        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None
    ) -> None:
        message = {"role": role, "content": content}
        if thinking_blocks:
            message["thinking_blocks"] = thinking_blocks
        self.messages.append(message)
        self.last_updated = datetime.now(UTC).isoformat()

    def add_action(self, action: dict[str, Any]) -> None:
        self.actions_taken.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
            }
        )

    def add_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "observation": observation,
            }
        )

    def add_error(self, error: str) -> None:
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self.last_updated = datetime.now(UTC).isoformat()

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = datetime.now(UTC).isoformat()

    def set_completed(self, final_result: dict[str, Any] | None = None) -> None:
        self.completed = True
        self.final_result = final_result
        self.last_updated = datetime.now(UTC).isoformat()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.last_updated = datetime.now(UTC).isoformat()

    def should_stop(self) -> bool:
        return (
            self.stop_requested
            or self.completed
            or self.has_reached_max_iterations()
            or self.has_exceeded_budget()[0]
        )

    # ------------------------------------------------------------------
    # Per-sub-agent budget enforcement (roadmap §8.0)
    # ------------------------------------------------------------------

    def record_token_usage(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        """Add to the running budget consumption counters. Idempotent
        in the sense that multiple calls accumulate; the budget check
        compares the cumulative total to the limits."""
        if input_tokens > 0:
            self.input_tokens_consumed += int(input_tokens)
        if output_tokens > 0:
            self.output_tokens_consumed += int(output_tokens)
        if cost_usd > 0:
            self.cost_consumed_usd += float(cost_usd)
        self.last_updated = datetime.now(UTC).isoformat()

    def has_exceeded_budget(self) -> tuple[bool, str | None]:
        """Return (exceeded, reason). When `exceeded`, `reason` is one
        of: `max_input_tokens`, `max_output_tokens`, `max_cost_usd`,
        `time_budget_seconds`. None when no budget is exceeded."""
        if self.max_input_tokens > 0 and self.input_tokens_consumed >= self.max_input_tokens:
            return (True, "max_input_tokens")
        if self.max_output_tokens > 0 and self.output_tokens_consumed >= self.max_output_tokens:
            return (True, "max_output_tokens")
        if self.max_cost_usd > 0 and self.cost_consumed_usd >= self.max_cost_usd:
            return (True, "max_cost_usd")
        if self.time_budget_seconds > 0 and self.start_time:
            try:
                started = datetime.fromisoformat(self.start_time)
                elapsed = (datetime.now(UTC) - started).total_seconds()
                if elapsed >= self.time_budget_seconds:
                    return (True, "time_budget_seconds")
            except (ValueError, TypeError):
                pass
        return (False, None)

    def set_budget(
        self,
        *,
        max_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
        max_cost_usd: float | None = None,
        time_budget_seconds: int | None = None,
    ) -> None:
        """Update budget limits. None means "leave unchanged"; 0 means
        "explicit no-limit". Lead agents call this when spawning a
        sub-agent."""
        if max_input_tokens is not None:
            self.max_input_tokens = max(0, int(max_input_tokens))
        if max_output_tokens is not None:
            self.max_output_tokens = max(0, int(max_output_tokens))
        if max_cost_usd is not None:
            self.max_cost_usd = max(0.0, float(max_cost_usd))
        if time_budget_seconds is not None:
            self.time_budget_seconds = max(0, int(time_budget_seconds))

    def is_waiting_for_input(self) -> bool:
        return self.waiting_for_input

    def enter_waiting_state(self, llm_failed: bool = False) -> None:
        self.waiting_for_input = True
        self.waiting_start_time = datetime.now(UTC)
        self.llm_failed = llm_failed
        self.last_updated = datetime.now(UTC).isoformat()

    def resume_from_waiting(self, new_task: str | None = None) -> None:
        self.waiting_for_input = False
        self.waiting_start_time = None
        self.stop_requested = False
        self.completed = False
        self.llm_failed = False
        if new_task:
            self.task = new_task
        self.last_updated = datetime.now(UTC).isoformat()

    def has_reached_max_iterations(self) -> bool:
        return self.iteration >= self.max_iterations

    def is_approaching_max_iterations(self, threshold: float = 0.85) -> bool:
        return self.iteration >= int(self.max_iterations * threshold)

    def has_waiting_timeout(self) -> bool:
        if self.waiting_timeout == 0:
            return False

        if not self.waiting_for_input or not self.waiting_start_time:
            return False

        if (
            self.stop_requested
            or self.llm_failed
            or self.completed
            or self.has_reached_max_iterations()
        ):
            return False

        elapsed = (datetime.now(UTC) - self.waiting_start_time).total_seconds()
        return elapsed > self.waiting_timeout

    def has_empty_last_messages(self, count: int = 3) -> bool:
        if len(self.messages) < count:
            return False

        last_messages = self.messages[-count:]

        for message in last_messages:
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                return False

        return True

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return self.messages

    def get_execution_summary(self) -> dict[str, Any]:
        exceeded, reason = self.has_exceeded_budget()
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "sandbox_id": self.sandbox_id,
            "sandbox_info": self.sandbox_info,
            "task": self.task,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completed": self.completed,
            "final_result": self.final_result,
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "total_actions": len(self.actions_taken),
            "total_observations": len(self.observations),
            "total_errors": len(self.errors),
            "has_errors": len(self.errors) > 0,
            "max_iterations_reached": self.has_reached_max_iterations() and not self.completed,
            # Roadmap §8.0 budget surfacing.
            "budget": {
                "max_input_tokens": self.max_input_tokens,
                "max_output_tokens": self.max_output_tokens,
                "max_cost_usd": self.max_cost_usd,
                "time_budget_seconds": self.time_budget_seconds,
                "input_tokens_consumed": self.input_tokens_consumed,
                "output_tokens_consumed": self.output_tokens_consumed,
                "cost_consumed_usd": round(self.cost_consumed_usd, 4),
                "exceeded": exceeded,
                "exceeded_reason": reason,
            },
        }
