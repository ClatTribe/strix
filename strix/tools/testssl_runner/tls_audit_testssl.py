"""iter-22.3 — `tls_audit_testssl` subprocess wrapper.

testssl.sh (https://github.com/drwetter/testssl.sh) is the
reference TLS-posture auditor. ~50 checks across protocol
support / cipher strength / vulnerability tests / cert chain.
Output via `--jsonfile-pretty` is per-finding structured JSON
with `severity` / `id` / `finding` / `cve` fields.

Severity mapping (testssl's own field):

  * CRITICAL → critical
  * HIGH     → high
  * MEDIUM   → medium
  * LOW      → low
  * INFO/OK  → no finding
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
import tempfile
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_TESTSSL_BIN = "testssl.sh"
_DEFAULT_TIMEOUT_SECONDS = 300


_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _testssl_available() -> bool:
    if os.environ.get(
        "STRIX_TESTSSL_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_TESTSSL_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592.002"],
)
def tls_audit_testssl(
    target: str,
) -> dict[str, Any]:
    """Run testssl.sh against the supplied target host:port.

    Args:
        target: host (default port 443) OR `host:port`.

    Returns:
        `{success, status, target, total_findings, findings, reason?}`
    """
    if not target or not target.strip():
        return {
            "success": False, "status": "error", "target": target,
            "total_findings": 0, "findings": [],
            "reason": "target required",
        }
    if not _testssl_available():
        return {
            "success": True, "status": "partial", "target": target,
            "total_findings": 0, "findings": [],
            "reason": (
                "testssl.sh not on PATH (or STRIX_TESTSSL_DISABLED=1). "
                "Install: clone github.com/drwetter/testssl.sh + "
                "symlink testssl.sh to /usr/local/bin."
            ),
        }

    json_path = Path(tempfile.mkdtemp(prefix="strix-testssl-")) / "out.json"
    cmd = [
        _TESTSSL_BIN,
        "--quiet",
        "--color", "0",
        "--jsonfile-pretty", str(json_path),
        target.strip(),
    ]
    try:
        subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "target": target,
            "total_findings": 0, "findings": [],
            "reason": f"testssl invocation failed: {type(e).__name__}: {e}",
        }

    findings: list[dict[str, Any]] = []
    try:
        records = json.loads(json_path.read_text() or "[]")
    except (OSError, ValueError, TypeError):
        records = []
    if not isinstance(records, list):
        records = []

    for r in records:
        if not isinstance(r, dict):
            continue
        sev_raw = (r.get("severity") or "").upper()
        if sev_raw not in _SEV_MAP:
            continue
        check_id = r.get("id") or "(unknown)"
        finding_text = r.get("finding") or "(no detail)"
        cve = r.get("cve") or ""
        findings.append({
            "rule_id": f"testssl-{check_id}",
            "title": f"TLS issue ({check_id}): {finding_text}",
            "severity": _SEV_MAP[sev_raw],
            "cwe": "CWE-327",
            "check_id": check_id,
            "finding": finding_text,
            "cve": cve,
            "description": (
                f"testssl.sh check `{check_id}` reported "
                f"`{finding_text}` against `{target}`. "
                + (f"Tied to {cve}." if cve else "")
            ),
            "remediation": (
                "Update server TLS configuration per Mozilla's "
                "ssl-config-generator at "
                "https://ssl-config.mozilla.org/ "
                "(use the 'modern' profile when client compatibility "
                "allows; 'intermediate' otherwise)."
            ),
        })

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "total_findings": len(findings),
        "findings": findings,
    }
