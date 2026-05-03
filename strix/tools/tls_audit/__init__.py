"""TLS / SSL configuration audit.

Roadmap §7.3 expert-pentester gap audit. Per-host check of:
- Protocol version acceptance (TLS 1.0 / 1.1 = finding; 1.2 / 1.3 = OK)
- Weak cipher acceptance (RC4 / 3DES / NULL / EXPORT / aNULL)
- Certificate expiry, self-signed, hostname mismatch
- SAN extraction (feeds back into the subdomain pool)
- Cert chain depth + issuer

Standard pentest deliverable; clients always expect a TLS section.
"""

from .tls_audit import tls_audit


__all__ = ["tls_audit"]
