"""iter-23.3 — `verify_credentials_trufflehog` subprocess wrapper.

trufflehog's killer feature versus a pure regex scanner like gitleaks
is `--only-verified` mode: for every candidate match, it actively
queries the upstream API (GitHub /user, AWS STS GetCallerIdentity,
Stripe /v1/balance, Slack auth.test, etc.) to confirm the credential
is still live. This drops a huge volume of false positives at L1
before any L2 specialist looks at them.

This wrapper is distinct from `secrets_scan` (which is the regex /
gitleaks corpus). Use this when:
  - secrets_scan found a candidate and we want to know it's active
  - we're scanning a third-party-mirrored repo and only care about
    LIVE risks, not historic noise

Modes:
  * git    : ``--git file://<repo>`` — scans a checked-out repo
  * filesystem: ``--filesystem <path>`` — scans a tree
  * github : ``--github --repo=<URL>`` — clones + scans a public repo

Returns one verified finding per (vendor, file, line) hit.

Recall safety: ``status=partial`` when binary missing.
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


_TRUFFLEHOG_BIN = "trufflehog"
_DEFAULT_TIMEOUT_SECONDS = 300


def _trufflehog_available() -> bool:
    if os.environ.get(
        "STRIX_TRUFFLEHOG_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_TRUFFLEHOG_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1552.001"],  # Credentials in Files
)
def verify_credentials_trufflehog(
    target: str,
    mode: str = "filesystem",
    only_verified: bool = True,
) -> dict[str, Any]:
    """Run trufflehog against ``target``; emit only live-verified hits.

    Args:
        target: path or URL depending on ``mode``:
            - ``mode=filesystem``: directory path (or single file).
            - ``mode=git``: local repo path; trufflehog will walk
              history (``file://<path>``).
            - ``mode=github``: ``https://github.com/owner/repo`` URL.
        mode: one of ``filesystem`` / ``git`` / ``github``.
        only_verified: when True (default), passes ``--only-verified``
            so the wrapper returns ONLY API-confirmed-live creds.
            Set False to also surface "unverified" matches (closer to
            gitleaks behaviour).

    Returns:
        ```
        {success, status, target, mode, total_findings: int,
         findings: [{detector, file?, line?, masked, verified,
                      severity, cwe}, ...], reason?}
        ```
    """
    if not target or not target.strip():
        return {
            "success": False, "status": "error", "target": target,
            "mode": mode, "total_findings": 0, "findings": [],
            "reason": "target required",
        }
    if mode not in {"filesystem", "git", "github"}:
        return {
            "success": False, "status": "error", "target": target,
            "mode": mode, "total_findings": 0, "findings": [],
            "reason": f"unknown mode: {mode}",
        }
    if mode == "filesystem" and not Path(target).exists():
        return {
            "success": False, "status": "error", "target": target,
            "mode": mode, "total_findings": 0, "findings": [],
            "reason": f"filesystem target not found: {target}",
        }
    if not _trufflehog_available():
        return {
            "success": True, "status": "partial", "target": target,
            "mode": mode, "total_findings": 0, "findings": [],
            "reason": (
                "trufflehog binary not on PATH (or "
                "STRIX_TRUFFLEHOG_DISABLED=1). Install via "
                "`curl -fsSL https://raw.githubusercontent.com/"
                "trufflesecurity/trufflehog/main/scripts/install.sh | sh`."
            ),
        }

    cmd: list[str] = [_TRUFFLEHOG_BIN, mode, "--json", "--no-update"]
    if only_verified:
        cmd.append("--only-verified")
    if mode == "git":
        cmd.append(target if target.startswith("file://") else f"file://{target}")
    elif mode == "github":
        cmd.extend(["--repo", target])
    else:  # filesystem
        cmd.append(target)

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "target": target,
            "mode": mode, "total_findings": 0, "findings": [],
            "reason": f"trufflehog invocation failed: {type(e).__name__}: {e}",
        }

    findings: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        detector = rec.get("DetectorName") or rec.get("detector") or "unknown"
        raw = rec.get("Raw") or ""
        verified = bool(rec.get("Verified") or False)
        # trufflehog source-metadata shape varies by mode. Normalise:
        smd = rec.get("SourceMetadata") or {}
        data = smd.get("Data") or {}
        file_path: str | None = None
        line_num: int | None = None
        for key in ("Filesystem", "Git", "Github", "Gitlab"):
            block = data.get(key)
            if not isinstance(block, dict):
                continue
            file_path = block.get("file") or block.get("path") or file_path
            line_num = block.get("line") or line_num
            break

        findings.append({
            "detector": detector,
            "file": file_path,
            "line": line_num,
            "masked": _mask(raw),
            "verified": verified,
            "severity": "critical" if verified else "high",
            "cwe": "CWE-798",  # Use of Hard-coded Credentials
        })

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "mode": mode,
        "total_findings": len(findings),
        "findings": findings,
    }


def _mask(secret: str) -> str:
    """Mask a secret value preserving first/last 3 chars."""
    if not secret:
        return ""
    s = str(secret).strip()
    if len(s) <= 8:
        return "***"
    return f"{s[:3]}...{s[-3:]}"
