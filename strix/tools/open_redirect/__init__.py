"""Open-redirect prober.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
Sweeps a target URL's redirect-shaped parameters with the standard
bypass cohort and detects attacker-host placement in 30x Location
headers, meta-refresh body redirects, and window.location body
redirects. Standard pentest deliverable; deterministic to test.
"""

from .open_redirect_check import open_redirect_check


__all__ = ["open_redirect_check"]
