"""iter-37.4 — `scan_smuggling_smuggler` subprocess wrapper.

smuggler (github.com/defparam/smuggler) is the most-cited OSS detector
for HTTP request smuggling — TE.CL / CL.TE / TE.TE / TE.0 / 0.CL.
Python tool, no native binary; invoked as ``python3 smuggler.py``
or via a `smuggler` wrapper installed into PATH.

Why this matters:
  * Front-end / back-end disagreement on Transfer-Encoding vs
    Content-Length headers is the canonical HTTP request smuggling
    vector. Exploitation can poison the request queue, hijack
    sessions, bypass front-end auth, or pivot internal admin paths.
  * nuclei has some smuggling templates but they're surface-level
    pattern matches; smuggler runs the full timing-based + response-
    splitting probes Burp Suite's "HTTP Request Smuggler" extension
    uses.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess  # noqa: S404
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_SECONDS = 120


def _smuggler_invocation() -> tuple[list[str], str] | None:
    """Return ([command, prefix...], display_name) for invoking
    smuggler, or None if it isn't available."""
    if os.environ.get(
        "STRIX_SMUGGLER_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return None
    # Try the wrapper binary first (installed via setup.py or apt).
    for binary in ("smuggler", "smuggler.py"):
        path = shutil.which(binary)
        if path:
            return ([path], binary)
    # Fall back to the python module path used in the upstream repo.
    for repo_path in (
        "/opt/smuggler/smuggler.py",
        "/usr/local/share/smuggler/smuggler.py",
        "/opt/tools/smuggler/smuggler.py",
    ):
        if os.path.isfile(repo_path):
            return (["python3", repo_path], "smuggler.py")
    return None


# smuggler stdout format on a vulnerable target (truncated):
#
#   [+] Issue Found
#       Target: https://example.com:443/
#       Technique: cl.te
#       Mutation: nameprefix1
#       Payload: ...
#
_FOUND_RE = re.compile(
    r"\[\+\]\s+Issue Found\s+"
    r"Target:\s+(?P<target>\S+)\s+"
    r"Technique:\s+(?P<technique>[\w.]+)\s+"
    r"Mutation:\s+(?P<mutation>\S+)",
    re.DOTALL,
)


def _parse_findings(stdout: str, target_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for m in _FOUND_RE.finditer(stdout or ""):
        technique = m.group("technique")
        mutation = m.group("mutation")
        findings.append({
            "title": (
                f"HTTP request smuggling ({technique.upper()}) "
                f"via `{mutation}` mutation"
            ),
            "category": "request_smuggling",
            "cwe": "CWE-444",  # Inconsistent Interpretation of HTTP Requests
            "endpoint": m.group("target") or target_url,
            "severity": "critical",
            "verification_status": "verified",
            "confidence": 0.9,
            "description": (
                f"smuggler.py detected an HTTP request smuggling vector "
                f"using the {technique.upper()} technique with the "
                f"`{mutation}` header-mutation. The front-end and back-"
                f"end HTTP servers disagree on whether to use "
                f"Transfer-Encoding or Content-Length to determine the "
                f"request body length. An attacker can poison the "
                f"request queue to hijack other users' sessions, "
                f"bypass front-end authentication, or smuggle internal "
                f"admin requests past the perimeter. Mitigate by "
                f"normalising or rejecting ambiguous header pairs at "
                f"the front-end (most modern reverse proxies have a "
                f"`reject ambiguous requests` mode)."
            ),
            "smuggler_technique": technique,
            "smuggler_mutation": mutation,
        })
    return findings


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def scan_smuggling_smuggler(
    *,
    target_url: str,
    technique: str = "exhaustive",
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """smuggler.py-backed HTTP request smuggling detection.

    Args:
        target_url: full URL of the target (typically the root, e.g.
            ``https://example.com/``). smuggler probes the front-end /
            back-end disagreement on Transfer-Encoding + Content-Length
            handling — the URL path is largely irrelevant.
        technique: smuggler's mutation set. Valid values:
            ``exhaustive`` (default — slowest, most accurate),
            ``default``, ``simple``, ``time``. Use ``simple`` for a
            fast pre-screen.
        timeout_seconds: subprocess kill timeout. Default 120s.

    Returns:
        ```
        {success, status, target, total_findings: int,
         findings: [{title, category, cwe, endpoint, severity,
                      verification_status, confidence, description,
                      smuggler_technique, smuggler_mutation}, ...],
         reason?}
        ```
    """
    if not isinstance(target_url, str) or not target_url.strip():
        return {
            "success": False, "status": "error",
            "target": target_url or "",
            "total_findings": 0, "findings": [],
            "reason": "target_url required",
        }
    target_url = target_url.strip()

    inv = _smuggler_invocation()
    if inv is None:
        return {
            "success": True, "status": "partial",
            "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": (
                "smuggler not on PATH (or STRIX_SMUGGLER_DISABLED=1). "
                "Install via: `git clone "
                "https://github.com/defparam/smuggler.git /opt/smuggler` "
                "and ensure `smuggler.py` is reachable."
            ),
        }
    cmd_prefix, _ = inv

    if technique not in ("exhaustive", "default", "simple", "time"):
        technique = "exhaustive"

    cmd: list[str] = [
        *cmd_prefix,
        "-u", target_url,
        "-m", technique,
        "-q",         # quiet — suppress banner
    ]

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": f"smuggler invocation failed: {type(e).__name__}: {e}",
        }

    findings = _parse_findings(
        (result.stdout or "") + "\n" + (result.stderr or ""),
        target_url,
    )
    return {
        "success": True,
        "status": "ok",
        "target": target_url,
        "total_findings": len(findings),
        "findings": findings,
        "technique": technique,
    }
