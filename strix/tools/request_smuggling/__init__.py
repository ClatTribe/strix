"""HTTP request smuggling / desync prober.

Roadmap §7.2 web-app expert-pentester gap audit (🔴 critical).
Differential Transfer-Encoding header detection — sends a small cohort
of obfuscated TE variants and infers parser disagreement when responses
differ from a baseline `Transfer-Encoding: chunked` request.

Safe by default: every probe sends a benign chunked-empty body
(`0\\r\\n\\r\\n`) — even if a back-end interpreted the body as a
smuggled second request, it would decode to `0\\r\\n` which isn't a
valid HTTP method/path and would be rejected with a 400. No actual
smuggled requests are dispatched.
"""

from .request_smuggling_check import request_smuggling_check


__all__ = ["request_smuggling_check"]
