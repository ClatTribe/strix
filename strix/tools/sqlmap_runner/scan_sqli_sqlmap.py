"""iter-23.2 — `scan_sqli_sqlmap` subprocess wrapper.

sqlmap is the de-facto SQLi automation tool — covers in-band (UNION,
error-based), boolean-blind, time-based blind, stacked queries, and OOB
across MySQL/Postgres/MSSQL/Oracle/SQLite/+. Wrapping it in batch mode
moves deterministic SQLi verification out of expensive L2 conversational
specialist loops, keeping those for complex auth / bypass logic.

Modes:
  * URL-mode    : ``-u "https://target/path?id=1"``
  * Request-mode: ``-r request.txt`` — for replaying captured raw POST
    requests (used when phase-2 wants to retest a body-param).

Stdout parsing extracts "Parameter: X (LOCATION)" / "Type: ..." /
"Title: ..." / "Payload: ..." blocks. Recall safety: ``status=partial``
when binary missing.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess  # noqa: S404
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_SQLMAP_BIN = "sqlmap"
_DEFAULT_TIMEOUT_SECONDS = 300


def _sqlmap_available() -> bool:
    if os.environ.get(
        "STRIX_SQLMAP_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_SQLMAP_BIN) is not None


# Parser regexes — match sqlmap's canonical findings block format:
#   sqlmap identified the following injection point(s) with a total of N HTTP(s)...
#   ---
#   Parameter: id (GET)
#       Type: boolean-based blind
#       Title: AND boolean-based blind - WHERE or HAVING clause
#       Payload: id=1 AND 1=1
#
#       Type: time-based blind
#       ...
#   ---
_PARAM_RE = re.compile(r"^Parameter:\s*(.+?)\s*\((.+?)\)\s*$", re.MULTILINE)
_TYPE_RE = re.compile(r"^\s*Type:\s*(.+?)\s*$", re.MULTILINE)
_TITLE_RE = re.compile(r"^\s*Title:\s*(.+?)\s*$", re.MULTILINE)
_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+?)\s*$", re.MULTILINE)
_DBMS_RE = re.compile(r"back-end DBMS:\s*([^\n]+)", re.IGNORECASE)


def _parse_findings(stdout: str) -> tuple[list[dict[str, Any]], str | None]:
    """Parse sqlmap stdout into findings + detected DBMS.

    sqlmap groups injections by parameter, then lists each distinct
    injection technique (Type/Title/Payload) underneath.
    """
    findings: list[dict[str, Any]] = []
    if not stdout:
        return findings, None

    dbms_match = _DBMS_RE.search(stdout)
    dbms = dbms_match.group(1).strip() if dbms_match else None

    # Split stdout on Parameter: lines. Each chunk after the first is one param.
    # Walk top-down so we can collect Type/Title/Payload triples per param.
    parts = re.split(r"(?=^Parameter:)", stdout, flags=re.MULTILINE)
    for chunk in parts:
        pm = _PARAM_RE.search(chunk)
        if not pm:
            continue
        param_name = pm.group(1).strip()
        location = pm.group(2).strip().upper()
        # Pull every Type / Title / Payload from this chunk (1+ techniques).
        types = _TYPE_RE.findall(chunk)
        titles = _TITLE_RE.findall(chunk)
        payloads = _PAYLOAD_RE.findall(chunk)
        # Zip — they should be in 1:1:1 order under sqlmap's standard layout
        for i, t in enumerate(types):
            title = titles[i] if i < len(titles) else ""
            payload = payloads[i] if i < len(payloads) else ""
            findings.append({
                "parameter": param_name,
                "location": location,
                "technique": t.strip(),
                "title": title.strip(),
                "payload": payload.strip(),
                "severity": "critical",
                "cwe": "CWE-89",
            })
    return findings, dbms


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def scan_sqli_sqlmap(
    target_url: str | None = None,
    request_file: str | None = None,
    data: str | None = None,
    risk: int = 1,
    level: int = 1,
    dbms_hint: str | None = None,
) -> dict[str, Any]:
    """sqlmap batch-mode SQLi verification.

    Args:
        target_url: full URL (``https://example.com/page?id=1``).
        request_file: path to a captured raw HTTP request — used when
            the parameter under test is a body/cookie/header, mutually
            exclusive with ``target_url``.
        data: ``--data`` body payload (when target_url is a POST target).
        risk: 1-3, default 1 — controls payload aggressiveness.
        level: 1-5, default 1 — controls test coverage breadth.
        dbms_hint: optionally pre-narrow the DBMS (``mysql``, ``postgres``,
            ``mssql``, ``oracle``, ``sqlite``) — much faster scan.

    Returns:
        ```
        {success, status, target, total_findings: int,
         dbms_detected?: str,
         findings: [{parameter, location, technique, title, payload,
                      severity, cwe}, ...], reason?}
        ```
    """
    if not target_url and not request_file:
        return {
            "success": False, "status": "error", "target": target_url or "",
            "total_findings": 0, "findings": [],
            "reason": "target_url or request_file required",
        }
    if request_file and not Path(request_file).is_file():
        return {
            "success": False, "status": "error",
            "target": request_file,
            "total_findings": 0, "findings": [],
            "reason": f"request_file not found: {request_file}",
        }
    if not _sqlmap_available():
        return {
            "success": True, "status": "partial",
            "target": target_url or request_file or "",
            "total_findings": 0, "findings": [],
            "reason": (
                "sqlmap binary not on PATH (or STRIX_SQLMAP_DISABLED=1). "
                "Install via apt: `apt-get install sqlmap`."
            ),
        }

    cmd: list[str] = [
        _SQLMAP_BIN,
        "--batch",       # non-interactive (auto-Y for prompts)
        "--disable-coloring",
        "--random-agent",
        "--risk", str(max(1, min(3, risk))),
        "--level", str(max(1, min(5, level))),
    ]
    if dbms_hint:
        cmd.extend(["--dbms", dbms_hint])
    if target_url:
        cmd.extend(["-u", target_url])
    if request_file:
        cmd.extend(["-r", request_file])
    if data:
        cmd.extend(["--data", data])

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "target": target_url or request_file or "",
            "total_findings": 0, "findings": [],
            "reason": f"sqlmap invocation failed: {type(e).__name__}: {e}",
        }

    findings, dbms = _parse_findings(result.stdout or "")
    out: dict[str, Any] = {
        "success": True,
        "status": "ok",
        "target": target_url or request_file or "",
        "total_findings": len(findings),
        "findings": findings,
    }
    if dbms:
        out["dbms_detected"] = dbms
    return out
