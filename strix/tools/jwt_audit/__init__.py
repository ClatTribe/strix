"""JWT analyzer.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
Detects JWTs in inputs and probes them for the standard
exploit classes: alg=none, weak HMAC dictionary, kid SQLi/path-
traversal, missing aud/iss/exp validation, expired-token acceptance.
"""

from .jwt_audit import jwt_audit


__all__ = ["jwt_audit"]
