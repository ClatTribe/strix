"""Host-header injection / cache-key trust prober.

Roadmap §7.2 web-app expert-pentester gap audit (🔴 critical).
Detects whether a target trusts attacker-controlled values in headers
that influence host / origin / cache-key routing — the primitive behind
password-reset link poisoning, cache poisoning, and SSRF-via-routing.
"""

from .host_header_check import host_header_check


__all__ = ["host_header_check"]
