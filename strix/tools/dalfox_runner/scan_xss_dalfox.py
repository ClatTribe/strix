"""iter-22.8 — `scan_xss_dalfox` subprocess wrapper.

Dalfox (https://github.com/hahwul/dalfox) is the reference Go-
based XSS scanner. Compared to strix's in-house `scan_xss`:

  * 100+ XSS payloads (vs ~15 in-house)
  * Filter-bypass mutators (WAF evasion variants)
  * BAV (Basic Application Vulnerability) checks alongside XSS
  * Headless-browser DOM-XSS confirmation
  * JSON output via `--format json`

Emits one critical finding per confirmed XSS (dalfox-confirmed
findings are post-payload-execution-verified, so we treat them
as `verified` not `pattern_match`).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_DALFOX_BIN = "dalfox"
_DEFAULT_TIMEOUT_SECONDS = 180


def _dalfox_available() -> bool:
    if os.environ.get(
        "STRIX_DALFOX_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_DALFOX_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],
)
def scan_xss_dalfox(
    target_url: str,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run dalfox against a URL + emit one finding per confirmed
    XSS.

    Args:
        target_url: URL with at least one query param (dalfox
            tests every param it discovers).
        extra_args: optional extra dalfox flags (e.g.
            ['--blind', '<callback-url>']).

    Returns:
        `{success, status, target, total_findings, findings, reason?}`
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error", "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": "target_url required",
        }
    if not _dalfox_available():
        return {
            "success": True, "status": "partial", "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": (
                "dalfox binary not on PATH (or STRIX_DALFOX_DISABLED=1). "
                "Install: `go install github.com/hahwul/dalfox/v2@latest`."
            ),
        }

    cmd = [
        _DALFOX_BIN,
        "url", target_url.strip(),
        "--format", "json",
        "--silence",
    ]
    if extra_args:
        cmd.extend([str(a) for a in extra_args])

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": f"dalfox invocation failed: {type(e).__name__}: {e}",
        }

    findings: list[dict[str, Any]] = []
    try:
        records = json.loads(result.stdout or "[]")
    except (ValueError, TypeError):
        records = []
    if not isinstance(records, list):
        records = []

    for r in records:
        if not isinstance(r, dict):
            continue
        # Dalfox JSON shape: {"type": "V|R|G", "inject_type": "...",
        # "evidence": "...", "data": "<payload>", "param": "...",
        # "severity": "L|M|H"}
        # type V = Verified (confirmed exec), R = Reflected, G = Grep
        ftype = (r.get("type") or "").upper()
        param = r.get("param") or "(unknown)"
        payload = r.get("data") or "(unknown)"
        evidence = r.get("evidence") or ""
        # Verified XSS → critical, reflected → high, grep → medium
        severity = {
            "V": "critical", "R": "high", "G": "medium",
        }.get(ftype, "medium")
        findings.append({
            "rule_id": f"dalfox-xss-{ftype.lower() or 'unknown'}",
            "title": (
                f"XSS via param `{param}` (dalfox type={ftype})"
            ),
            "severity": severity,
            "cwe": "CWE-79",
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "description": (
                f"dalfox detected XSS in param `{param}` on "
                f"`{target_url}`. Type: {ftype} "
                f"({'verified-execution' if ftype == 'V' else 'reflected/grep'}). "
                f"Payload: `{payload[:200]}`. "
                f"Evidence: `{evidence[:200]}`."
            ),
            "remediation": (
                "Output-encode untrusted data per OWASP XSS "
                "Prevention Cheat Sheet (context-aware: HTML / "
                "attribute / JS-string / URL / CSS). For React / "
                "Vue / Angular use the framework's auto-escape "
                "(dangerouslySetInnerHTML / v-html / [innerHTML] "
                "are the unsafe paths)."
            ),
        })

    return {
        "success": True,
        "status": "ok",
        "target": target_url,
        "total_findings": len(findings),
        "findings": findings,
    }
