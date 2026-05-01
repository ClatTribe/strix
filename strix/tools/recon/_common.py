"""Shared helpers for the recon tools.

Wraps `dig` and HTTP probes, normalises output, and provides a small finding-
emission helper that routes through the global tracer when one exists. When
no tracer is set (e.g., the tool is being unit-tested in isolation) the helper
returns the would-be report dict without persisting — useful for assertions.
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any


logger = logging.getLogger(__name__)


_TIMEOUT_SECONDS = 10


def dig(query: str, record_type: str = "A", *, server: str | None = None,
        short: bool = True, extra: list[str] | None = None) -> str:
    """Run `dig` and return stdout (stripped). Empty string on failure."""
    cmd = ["dig"]
    if short:
        cmd.append("+short")
    cmd.extend(["+time=3", "+tries=2"])
    if server:
        cmd.append(f"@{server}")
    if extra:
        cmd.extend(extra)
    cmd.extend([query, record_type])
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False
        )
        return proc.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning("dig failed for %s %s: %s", query, record_type, e)
        return ""


def http_head(url: str, *, follow_redirects: bool = False) -> tuple[int, dict[str, str]]:
    """HEAD request to `url`. Returns (status_code, headers). (0, {}) on failure.

    Uses httpx if available (the sandbox has it). Falls back to stdlib.
    """
    try:
        import httpx

        with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=follow_redirects) as c:
            r = c.head(url)
            return r.status_code, dict(r.headers)
    except Exception:  # noqa: BLE001
        try:
            import urllib.request

            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as r:  # noqa: S310
                return r.status, dict(r.headers)
        except Exception:  # noqa: BLE001
            return 0, {}


def http_get_text(url: str, *, max_bytes: int = 4096) -> tuple[int, str]:
    """GET request returning (status, body[:max_bytes]). (0, '') on failure."""
    try:
        import httpx

        with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=True) as c:
            r = c.get(url)
            return r.status_code, r.text[:max_bytes]
    except Exception:  # noqa: BLE001
        return 0, ""


def emit_finding(
    *,
    title: str,
    severity: str,
    category: str | None = None,
    cwe: str | None = None,
    description: str = "",
    impact: str = "",
    target: str | None = None,
    remediation: str = "",
    technical_analysis: str = "",
    verification_status: str = "verified",
    endpoint: str | None = None,
    cvss: float | None = None,
) -> str | None:
    """Persist a finding via the global tracer. Returns the report id (or None
    if no tracer is configured — useful for direct unit testing of the tools)."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None
    return tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category=category,
        cwe=cwe,
        description=description or None,
        impact=impact or None,
        target=target,
        technical_analysis=technical_analysis or None,
        remediation_steps=remediation or None,
        verification_status=verification_status,
        endpoint=endpoint,
        cvss=cvss,
    )


_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$")


def looks_like_domain(value: str) -> bool:
    """Conservative validator for a hostname-shaped input."""
    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_RE.match(value)) and "." in value
