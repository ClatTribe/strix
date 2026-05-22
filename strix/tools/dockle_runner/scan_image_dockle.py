"""iter-22.4 — `scan_image_dockle` subprocess wrapper.

Dockle (https://github.com/goodwithtech/dockle) audits container
images for CIS Docker Benchmark compliance + best practices.
Complements `scan_container_image` (Trivy = vuln+secret focused) —
Dockle catches build/config issues Trivy misses (`USER root`,
missing HEALTHCHECK, exposed env vars).

Severity mapping from dockle's FATAL/WARN/INFO/SKIP/PASS:

  * FATAL → high  (CIS critical)
  * WARN  → medium
  * INFO  → low
  * SKIP/PASS → no finding
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


_DOCKLE_BIN = "dockle"
_DEFAULT_TIMEOUT_SECONDS = 180  # image pull + scan


_LEVEL_MAP = {
    "FATAL": "high",
    "WARN": "medium",
    "INFO": "low",
    # SKIP / PASS don't emit findings
}

_RULE_TO_CWE: dict[str, str] = {
    "CIS-DI-0001": "CWE-250",   # USER root
    "CIS-DI-0005": "CWE-345",   # Content trust off
    "CIS-DI-0006": "CWE-693",   # missing HEALTHCHECK
    "CIS-DI-0008": "CWE-250",   # setuid/setgid
    "DKL-DI-0002": "CWE-798",   # exposed env creds
    "DKL-DI-0003": "CWE-1104",  # missing maintainer label
    "DKL-LI-0001": "CWE-1104",  # missing labels
}


def _dockle_disabled() -> bool:
    return os.environ.get(
        "STRIX_DOCKLE_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


def _dockle_available() -> bool:
    if _dockle_disabled():
        return False
    return shutil.which(_DOCKLE_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1574", "T1611"],
)
def scan_image_dockle(
    image_ref: str,
) -> dict[str, Any]:
    """Run Dockle CIS-bench audit on a container image. Emits one
    finding per rule violation.

    Args:
        image_ref: container image reference (e.g. `nginx:1.25`).

    Returns:
        `{success, status, image_ref, total_findings, findings, reason?}`
    """
    # Input-validation BEFORE availability so the bad-input path
    # returns `error` even when the binary is also missing — keeps
    # the test contract clean.
    if not image_ref or not image_ref.strip():
        return {
            "success": False, "status": "error", "image_ref": image_ref,
            "total_findings": 0, "findings": [],
            "reason": "image_ref required",
        }
    if not _dockle_available():
        return {
            "success": True, "status": "partial", "image_ref": image_ref,
            "total_findings": 0, "findings": [],
            "reason": (
                "dockle binary not on PATH (or STRIX_DOCKLE_DISABLED=1). "
                "Install: download from github.com/goodwithtech/dockle/"
                "releases."
            ),
        }

    try:
        result = subprocess.run(  # noqa: S603
            [_DOCKLE_BIN, "-f", "json", image_ref],
            check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "image_ref": image_ref,
            "total_findings": 0, "findings": [],
            "reason": (
                f"dockle invocation failed: {type(e).__name__}: {e}"
            ),
        }

    # dockle exits non-zero when findings present — we accept any
    # non-error stdout. JSON shape: {"image":..., "details":[{...}]}
    try:
        doc = json.loads(result.stdout or "{}")
    except (ValueError, TypeError):
        doc = {}

    details = doc.get("details") or []
    if not isinstance(details, list):
        details = []

    findings: list[dict[str, Any]] = []
    for d in details:
        if not isinstance(d, dict):
            continue
        level = (d.get("level") or "INFO").upper()
        if level not in _LEVEL_MAP:
            continue
        code = (d.get("code") or "").strip()
        title = (d.get("title") or "(no title)").strip()
        alerts = d.get("alerts") or []
        # Dockle nests message detail inside `alerts`. Pull the first
        # for the per-finding message; downstream consumers can read
        # the full list from the raw output if they need it.
        msg = alerts[0] if alerts else title
        findings.append({
            "rule_id": code or "DOCKLE-UNKNOWN",
            "title": f"Dockle {code or '<unknown>'}: {title}",
            "severity": _LEVEL_MAP[level],
            "cwe": _RULE_TO_CWE.get(code, "CWE-1104"),
            "message": msg,
            "description": (
                f"Dockle rule `{code}` matched on image `{image_ref}`: "
                f"{title}. Alerts: {alerts}"
            ),
            "remediation": (
                f"See https://github.com/goodwithtech/dockle/blob/"
                f"master/CHECKPOINT.md#{code.lower()} for the "
                "remediation pattern."
            ),
        })

    # Tracer emit
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=image_ref,
                    endpoint=image_ref,
                    category="container_misconfig",
                    verification_status="pattern_match",
                    confidence=0.9,
                    description=f["description"],
                    impact=(
                        f"Dockle CIS-bench rule {f['rule_id']} "
                        f"violated on {image_ref}."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Tool: dockle\nRule: {f['rule_id']}\n"
                        f"Image: {image_ref}\nDetails: {f['message']}"
                    ),
                    reasoning_trace=[
                        f"dockle scanned image `{image_ref}`.",
                        f"Rule `{f['rule_id']}` matched.",
                    ],
                    poc_description=(
                        f"Reproduce: `dockle {image_ref}` (look for "
                        f"{f['rule_id']})."
                    ),
                    poc_script_code=f"dockle -f json {image_ref}",
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("dockle tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "image_ref": image_ref,
        "total_findings": len(findings),
        "findings": findings,
    }
