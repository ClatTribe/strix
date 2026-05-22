"""iter-22.3 — testssl.sh TLS-audit wrapper.

Per `docs/L1-optimization.md §6 iter-22.3`: replace the
minimal in-house `tls_audit` (~5 checks) with testssl.sh
(~50 TLS-specific checks: cipher strength, protocol support,
HSTS, OCSP, vulnerability tests like Heartbleed / POODLE /
DROWN / FREAK / Logjam / ROBOT, cert chain validation, etc.).
"""

from __future__ import annotations

from strix.tools.testssl_runner.tls_audit_testssl import (  # noqa: F401
    tls_audit_testssl,
)


__all__ = ["tls_audit_testssl"]
