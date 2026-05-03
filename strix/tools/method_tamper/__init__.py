"""HTTP verb / method tampering prober.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
Per-endpoint method matrix replay: OPTIONS (allowed-methods discovery
+ WebDAV verb leak), TRACE (XST), HEAD (cache asymmetry), and an
opt-in destructive cohort (X-HTTP-Method-Override / `_method` form
param / direct PUT/PATCH/DELETE) for staging targets where the
operator has consented to state-changing probes.
"""

from .method_tamper_check import method_tamper_check


__all__ = ["method_tamper_check"]
