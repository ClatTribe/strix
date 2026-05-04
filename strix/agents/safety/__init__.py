"""Agent-safety primitives.

Roadmap §17.1. Trust-boundary helpers for the agent loop:

- `output_sanitizer` — strips prompt-injection markers from tool
  output before the LLM sees it; emits `tool.output.injected`
  events when patterns are found.
"""

from .output_sanitizer import (
    InjectionDetection,
    sanitize_tool_output,
    wrap_untrusted,
)


__all__ = [
    "InjectionDetection",
    "sanitize_tool_output",
    "wrap_untrusted",
]
