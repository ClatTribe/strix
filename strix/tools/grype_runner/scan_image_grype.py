"""iter-Q5.47 — `scan_image_grype` subprocess wrapper.

Grype (Anchore) is the second-most-popular container CVE scanner
after trivy. Uses a DIFFERENT vuln DB (Anchore's grype-db) sourced
from a different mix of feeds — catches CVEs trivy misses and
vice-versa. Ships in parallel to trivy under _ANCHORS_CONTAINER so
the L1.5 corroborator hook can mark CVEs that both engines flag as
high-confidence.

Architecture: subprocess wrapper. JSON output parsed and returned
as a `subdomains`-style structured payload (but with `vulnerabilities`
as the canonical list field). Recall safety: `status=partial` when
the binary is missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any


logger = logging.getLogger(__name__)


_GRYPE_BIN = "grype"
_DEFAULT_TIMEOUT_SECONDS = 600


def _grype_available() -> bool:
    """True iff `grype` is on PATH AND the kill switch isn't set."""
    if os.environ.get(
        "STRIX_GRYPE_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_GRYPE_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1525 Implant Internal Image (registry-side) + T1610 Deploy Container.
    mitre_techniques=["T1525", "T1610"],
)
def scan_image_grype(
    image_ref: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    only_fixed: bool = False,
    severity_floor: str | None = None,
) -> dict[str, Any]:
    """Container CVE scan via Anchore grype.

    Args:
        image_ref: image reference. Examples — `nginx:1.25`,
            `registry.example.com/foo/bar:tag`,
            `nginx@sha256:0123...abcd`. Required.
        timeout_seconds: grype invocation timeout. Default 600s.
        only_fixed: pass `--only-fixed` so only CVEs with an
            upstream patch are reported. Mirrors Q5.42's
            `STRIX_TRIVY_IGNORE_UNFIXED`. Off by default.
            Env override: `STRIX_GRYPE_ONLY_FIXED=1`.
        severity_floor: when set, passes `--fail-on <floor>` — but
            we read the floor only for filtering the parsed output;
            we don't exit non-zero on findings. Accepts: "negligible",
            "low", "medium", "high", "critical".

    Returns:
        ```
        {success, status, image_ref, total_found: int,
         vulnerabilities: [
           {id, severity, package, version, fix_state, fix_versions},
         ], reason?}
        ```

    The structured `vulnerabilities` shape pairs with the L1.5
    corroborator hook — when trivy + grype both flag the same
    `(image_ref, package, version, cve_id)` tuple, the corroborator
    promotes the finding's confidence tier.
    """
    if not isinstance(image_ref, str) or not image_ref.strip():
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "total_found": 0,
            "vulnerabilities": [],
            "reason": "image_ref required",
        }
    if not _grype_available():
        return {
            "success": True, "status": "partial",
            "image_ref": image_ref, "total_found": 0,
            "vulnerabilities": [],
            "reason": (
                "grype binary not on PATH (or STRIX_GRYPE_DISABLED=1). "
                "Install via `curl -sSfL https://raw.githubusercontent."
                "com/anchore/grype/main/install.sh | sh -s -- -b "
                "/usr/local/bin`."
            ),
        }

    image_ref = image_ref.strip()

    # Resolve only_fixed env fallback.
    if not only_fixed:
        only_fixed = os.environ.get(
            "STRIX_GRYPE_ONLY_FIXED", "",
        ).strip().lower() in {"1", "true", "yes", "on"}

    cmd = [_GRYPE_BIN, image_ref, "-o", "json", "-q"]
    if only_fixed:
        cmd.append("--only-fixed")

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "total_found": 0,
            "vulnerabilities": [],
            "reason": f"grype invocation failed: {type(e).__name__}: {e}",
        }

    if not (result.stdout or "").strip():
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "total_found": 0,
            "vulnerabilities": [],
            "reason": f"grype produced no output; stderr={(result.stderr or '').strip()[:200]}",
        }

    try:
        report = json.loads(result.stdout)
    except (ValueError, TypeError) as e:
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "total_found": 0,
            "vulnerabilities": [],
            "reason": f"grype output not valid JSON: {e}",
        }

    matches = report.get("matches") if isinstance(report, dict) else None
    if not isinstance(matches, list):
        return {
            "success": True, "status": "ok",
            "image_ref": image_ref, "total_found": 0,
            "vulnerabilities": [],
        }

    floor_rank = _severity_rank(severity_floor)
    vulns: list[dict[str, Any]] = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        vuln_block = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        severity = str(vuln_block.get("severity") or "Unknown").strip()
        if floor_rank is not None and _severity_rank(severity) < floor_rank:
            continue
        fix_block = vuln_block.get("fix") or {}
        vulns.append({
            "id": vuln_block.get("id") or "",
            "severity": severity,
            "package": artifact.get("name") or "",
            "version": artifact.get("version") or "",
            "fix_state": fix_block.get("state") or "unknown",
            "fix_versions": fix_block.get("versions") or [],
        })

    return {
        "success": True,
        "status": "ok",
        "image_ref": image_ref,
        "total_found": len(vulns),
        "vulnerabilities": vulns,
    }


_SEVERITY_ORDER = {
    "negligible": 0, "unknown": 0,
    "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _severity_rank(s: str | None) -> int | None:
    """Return integer rank for severity comparison or None when
    `s` doesn't match a known level."""
    if not s:
        return None
    return _SEVERITY_ORDER.get(s.strip().lower())
