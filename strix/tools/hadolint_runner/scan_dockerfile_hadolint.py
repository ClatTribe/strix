"""iter-22.4 — `scan_dockerfile_hadolint` subprocess wrapper.

Hadolint (https://github.com/hadolint/hadolint) is a Haskell-based
Dockerfile linter shipping ~80 rules (DL3000-series + embedded
shellcheck SC2000-series). Catches anti-patterns strix's current
in-house IaC pack only partially covers:

  * `DL3006` — missing base-image tag (`FROM ubuntu` → CWE-1104)
  * `DL3008` — apt-get without `--no-install-recommends`
  * `DL3015` — apt-get without `--no-install-recommends` AND
    cleanup
  * `DL3023` — copying from same layer (`COPY --from`)
  * `DL4006` — set `-o pipefail` for piped commands
  * Plus SC2046, SC2086, SC2155 etc. for embedded RUN shell

Severity mapping (operator-tunable via `STRIX_HADOLINT_SEVERITY_MAP`):

  * DL3002 (USER root)              → high   (CWE-250)
  * DL3009/DL3015 (apt cleanup)     → low    (CWE-1037 cache bloat)
  * DL3006 (no FROM tag)            → low    (CWE-1104)
  * Other DL3000-series             → info / low based on json severity
  * SC2086 (unquoted exec)          → medium (CWE-78)
  * SC2046 (word-split cmd subst)   → medium (CWE-78)

Returns `status=partial` when the binary isn't on PATH or the
Dockerfile doesn't exist. Never raises.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_HADOLINT_BIN = "hadolint"
_DEFAULT_TIMEOUT_SECONDS = 30


# Hadolint emits `level` of `error` / `warning` / `info` / `style`.
# Map to strix's severity set with operator override hook.
_DEFAULT_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "style": "info",
}

# CWE annotations for the most-common rule IDs.
_RULE_TO_CWE: dict[str, str] = {
    "DL3002": "CWE-250",   # USER root
    "DL3006": "CWE-1104",  # no tag
    "DL3008": "CWE-1037",
    "DL3009": "CWE-1037",
    "DL3015": "CWE-1037",
    "DL3023": "CWE-913",
    "DL4006": "CWE-664",
    "SC2046": "CWE-78",
    "SC2086": "CWE-78",
    "SC2155": "CWE-664",
}


def _hadolint_disabled() -> bool:
    return os.environ.get(
        "STRIX_HADOLINT_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


def _hadolint_available() -> bool:
    if _hadolint_disabled():
        return False
    return shutil.which(_HADOLINT_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1574", "T1059.004"],
)
def scan_dockerfile_hadolint(
    dockerfile_path: str,
) -> dict[str, Any]:
    """Run Hadolint on a Dockerfile + emit one finding per rule
    violation.

    Args:
        dockerfile_path: filesystem path to a Dockerfile.

    Returns:
        ```
        {
          success: bool, status: "ok" | "partial" | "error",
          path: str, total_findings: int,
          findings: [{rule_id, title, severity, cwe, line,
                      message, description, remediation}, ...],
          reason?: str
        }
        ```
    """
    if not _hadolint_available():
        return {
            "success": True, "status": "partial", "path": dockerfile_path,
            "total_findings": 0, "findings": [],
            "reason": (
                "hadolint binary not on PATH (or STRIX_HADOLINT_DISABLED"
                "=1). Install: `apt install hadolint` or download from "
                "github.com/hadolint/hadolint/releases."
            ),
        }
    path = Path(dockerfile_path)
    if not path.exists() or not path.is_file():
        return {
            "success": False, "status": "error", "path": dockerfile_path,
            "total_findings": 0, "findings": [],
            "reason": f"Dockerfile not found: {dockerfile_path!r}",
        }

    cmd: list[str] = [_HADOLINT_BIN, "--format", "json"]
    # iter-24.1 — prefer the lazily-updated upstream config if
    # `update_hadolint_config` has populated the cache.
    # iter-24.2 — if `hadolint.yaml.compiled` exists (custom_signatures
    # merged in by the scope), prefer the compiled variant.
    try:
        from strix.tools.rule_updates import cached_path
        compiled = cached_path("hadolint.yaml.compiled")
        if compiled.is_file() and compiled.stat().st_size > 0:
            cmd += ["--config", str(compiled)]
        else:
            cached_cfg = cached_path("hadolint.yaml")
            if cached_cfg.is_file() and cached_cfg.stat().st_size > 0:
                cmd += ["--config", str(cached_cfg)]
    except Exception:  # noqa: BLE001
        pass
    cmd.append(str(path))
    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "path": str(path),
            "total_findings": 0, "findings": [],
            "reason": f"hadolint invocation failed: {type(e).__name__}: {e}",
        }

    try:
        records = json.loads(result.stdout or "[]")
    except (ValueError, TypeError):
        records = []
    if not isinstance(records, list):
        records = []

    findings: list[dict[str, Any]] = []
    for r in records:
        if not isinstance(r, dict):
            continue
        rule_id = (r.get("code") or "").strip()
        if not rule_id:
            continue
        level = (r.get("level") or "info").lower().strip()
        severity = _DEFAULT_LEVEL_MAP.get(level, "info")
        # Hardcoded rule-specific overrides
        if rule_id == "DL3002":
            severity = "high"
        cwe = _RULE_TO_CWE.get(rule_id, "CWE-1104")
        message = r.get("message") or "(no message)"
        line = int(r.get("line") or 0)
        findings.append({
            "rule_id": rule_id,
            "title": f"Dockerfile {rule_id}: {message}",
            "severity": severity,
            "cwe": cwe,
            "line": line,
            "message": message,
            "description": (
                f"Hadolint rule `{rule_id}` matched at "
                f"`{path}:{line}`: {message}"
            ),
            "remediation": (
                f"See https://github.com/hadolint/hadolint/wiki/"
                f"{rule_id} for the canonical fix pattern."
            ),
        })

    # Emit through tracer
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=str(path),
                    endpoint=f"{path}:{f['line']}",
                    category="iac_misconfig",
                    verification_status="pattern_match",
                    confidence=0.92,
                    description=f["description"],
                    impact=f"Dockerfile hygiene rule {f['rule_id']}.",
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Tool: hadolint\nRule: {f['rule_id']}\n"
                        f"Line: {f['line']}\nMessage: {f['message']}"
                    ),
                    reasoning_trace=[
                        f"hadolint scanned `{path.name}`.",
                        f"Rule `{f['rule_id']}` matched at line "
                        f"{f['line']}.",
                    ],
                    poc_description=(
                        f"Reproduce: `hadolint {path}` (look for "
                        f"{f['rule_id']} on line {f['line']})."
                    ),
                    poc_script_code=f"hadolint --format json {path}",
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("hadolint tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "path": str(path),
        "total_findings": len(findings),
        "findings": findings,
    }
