"""HTTP security-header audit.

Roadmap §7.3 expert-pentester gap audit. Per-host check of the standard
security headers (HSTS / CSP / X-Frame-Options / X-Content-Type-Options /
Referrer-Policy / Permissions-Policy / COOP / COEP / CORP / CORS / cookie
flags / version disclosure). Each missing or weak header → finding.
"""

from .http_headers import http_security_headers_audit


__all__ = ["http_security_headers_audit"]
