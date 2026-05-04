"""Verbose-error / debug-bleed detector.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
Probes a deep target for parametric debug-mode toggles, framework
debug pages, and error-trigger inputs that bleed stack traces or
internal paths into the response body.
"""

from .debug_endpoint_check import debug_endpoint_check


__all__ = ["debug_endpoint_check"]
