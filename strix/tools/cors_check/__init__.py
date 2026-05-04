"""CORS deep-probe.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
Goes beyond the static reflection check in `http_headers` (#47) by
probing the laxity classes that exploit framework string-matching
bugs: `Origin: null`, regex-bypass variants, trailing-slash bypass,
scheme bypass, and pre-flight allow-methods/headers laxity.
"""

from .cors_deep_check import cors_deep_check


__all__ = ["cors_deep_check"]
