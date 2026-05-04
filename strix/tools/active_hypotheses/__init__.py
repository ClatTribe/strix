"""Agent-callable tools for active-hypothesis coordination
(roadmap §17.6 / §18 row 9).

Sub-agents call these to register / confirm / dismiss / inspect
in-flight hypotheses so sister specialists don't duplicate work.
"""

from .active_hypotheses_tools import (
    confirm_hypothesis,
    dismiss_hypothesis,
    list_hypotheses,
    open_hypothesis,
)


__all__ = [
    "confirm_hypothesis",
    "dismiss_hypothesis",
    "list_hypotheses",
    "open_hypothesis",
]
