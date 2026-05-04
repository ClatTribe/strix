"""Session-cookie predictability / entropy analyzer.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
Catches dev-built session schemes that are sequential / low-entropy
/ time-based. Deterministic; no per-endpoint cost.
"""

from .session_entropy_check import session_entropy_check


__all__ = ["session_entropy_check"]
