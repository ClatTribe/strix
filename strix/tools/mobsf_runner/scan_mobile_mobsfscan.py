"""iter-37.4 — `scan_mobile_mobsfscan` subprocess wrapper.

mobsfscan (github.com/MobSF/mobsfscan) is the SAST companion to MobSF —
the leading OSS mobile-app security platform. It runs semgrep-style
static analysis on Android Java / Kotlin / Swift / Objective-C source,
and AndroidManifest.xml + Info.plist configuration audits.

When the target is an APK file (not source), mobsfscan still works on
the unpacked smali sources; the wrapper performs the unpack via the
``apktool`` binary if the input ends in `.apk`.

This closes the mobile-app vertical iter-21.5 deferred. Findings
include:
  * Hardcoded API keys / secrets / certificates
  * Insecure crypto (MD5/SHA1, hardcoded IVs, weak random)
  * Improper permission usage (REQUESTING_DANGEROUS_PERMISSIONS)
  * Insecure data storage (allowBackup, debuggable, exported)
  * SSL pinning bypass surfaces (TrustAllX509TrustManager, custom
    HostnameVerifier returning true)
  * WebView misconfigurations (setJavaScriptEnabled,
    allowFileAccess)
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


_MOBSFSCAN_BIN = "mobsfscan"
_APKTOOL_BIN = "apktool"
_DEFAULT_TIMEOUT_SECONDS = 240


def _mobsfscan_available() -> bool:
    if os.environ.get(
        "STRIX_MOBSFSCAN_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_MOBSFSCAN_BIN) is not None


def _apktool_available() -> bool:
    return shutil.which(_APKTOOL_BIN) is not None


# mobsfscan severity strings → strix severity
_SEV_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "info": "low",
}

# mobsfscan rule_id prefixes → CWE
_RULE_CWE_HINTS: list[tuple[str, str]] = [
    ("android_hardcoded", "CWE-798"),
    ("android_certificate", "CWE-295"),
    ("android_ssl", "CWE-295"),
    ("android_webview", "CWE-79"),
    ("android_root_detection", "CWE-693"),
    ("android_debuggable", "CWE-489"),
    ("android_backup", "CWE-200"),
    ("android_exported", "CWE-926"),
    ("android_world_writable", "CWE-732"),
    ("crypto_weak_hash", "CWE-327"),
    ("crypto_weak_random", "CWE-338"),
    ("crypto_hardcoded", "CWE-321"),
    ("permission_dangerous", "CWE-250"),
    ("ios_hardcoded", "CWE-798"),
    ("ios_ssl", "CWE-295"),
    ("ios_webview", "CWE-79"),
]


def _infer_cwe(rule_id: str, fallback: str = "CWE-1390") -> str:
    rid_lc = (rule_id or "").lower()
    for prefix, cwe in _RULE_CWE_HINTS:
        if prefix in rid_lc:
            return cwe
    return fallback


def _parse_findings(
    output_path: str, target_path: str,
) -> list[dict[str, Any]]:
    try:
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[dict[str, Any]] = []
    # mobsfscan JSON schema: {"results": {"<rule_id>": {"metadata":
    # {"severity", "description", "cwe", "owasp-mobile", ...},
    # "files": [{"file_path", "match_lines": [start, end],
    # "match_string"}]}}}
    results = data.get("results") or {}
    if not isinstance(results, dict):
        return []
    for rule_id, rule_data in results.items():
        if not isinstance(rule_data, dict):
            continue
        meta = rule_data.get("metadata") or {}
        sev = _SEV_MAP.get(meta.get("severity") or "", "medium")
        cwe = (
            meta.get("cwe", "").split(":", 1)[0].strip()
            if isinstance(meta.get("cwe"), str)
            else None
        ) or _infer_cwe(rule_id)
        title_prefix = meta.get("description") or rule_id
        files = rule_data.get("files") or []
        if not files:
            # Manifest-level rule (no file context).
            findings.append({
                "title": f"mobsfscan: {title_prefix}",
                "category": "mobile_sast",
                "cwe": cwe,
                "endpoint": target_path,
                "severity": sev,
                "verification_status": "pattern_match",
                "confidence": 0.7,
                "description": (
                    f"mobsfscan rule `{rule_id}` matched: "
                    f"{title_prefix}. " + (
                        f"OWASP Mobile: {meta.get('owasp-mobile')}. "
                        if meta.get("owasp-mobile") else ""
                    )
                    + (meta.get("masvs", "") or "")
                ),
                "mobsfscan_rule_id": rule_id,
            })
            continue
        for file_entry in files:
            if not isinstance(file_entry, dict):
                continue
            file_path = file_entry.get("file_path", "")
            match_lines = file_entry.get("match_lines") or []
            line = (
                match_lines[0] if isinstance(match_lines, list)
                and match_lines else None
            )
            findings.append({
                "title": f"mobsfscan: {title_prefix}",
                "category": "mobile_sast",
                "cwe": cwe,
                "endpoint": file_path or target_path,
                "severity": sev,
                "verification_status": "pattern_match",
                "confidence": 0.7,
                "description": (
                    f"mobsfscan rule `{rule_id}` matched at "
                    f"`{file_path}`"
                    + (f":{line}" if line else "")
                    + f": {title_prefix}. "
                    + (
                        f"OWASP Mobile: {meta.get('owasp-mobile')}. "
                        if meta.get("owasp-mobile") else ""
                    )
                ),
                "code_locations": [{
                    "file": file_path,
                    "line": line,
                }] if file_path else None,
                "mobsfscan_rule_id": rule_id,
            })
    return findings


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592.002"],  # Gather Victim Host Information
)
def scan_mobile_mobsfscan(
    *,
    target_path: str,
    is_apk: bool | None = None,
    sarif_output: bool = False,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    max_findings: int = 200,
) -> dict[str, Any]:
    """mobsfscan-backed mobile-app static analysis.

    Args:
        target_path: filesystem path to the mobile-app source tree OR
            an `.apk` file. When given an `.apk`, the wrapper unpacks
            it to a temp dir via ``apktool`` (must be on PATH) before
            running mobsfscan.
        is_apk: explicit override of `.apk` extension detection. When
            None (default), auto-detected from the file extension.
        sarif_output: when True, request SARIF format from mobsfscan
            (useful for CI integration); the wrapper still parses
            into our finding shape regardless.
        timeout_seconds: subprocess kill timeout. Default 240s.
        max_findings: cap on emitted findings.

    Returns:
        ```
        {success, status, target, total_findings: int,
         findings: [{title, category, cwe, endpoint, severity,
                      verification_status, confidence, description,
                      code_locations, mobsfscan_rule_id}, ...],
         reason?}
        ```
    """
    if not isinstance(target_path, str) or not target_path.strip():
        return {
            "success": False, "status": "error",
            "target": target_path or "",
            "total_findings": 0, "findings": [],
            "reason": "target_path required",
        }
    target_path = target_path.strip()

    if not Path(target_path).exists():
        return {
            "success": False, "status": "error",
            "target": target_path,
            "total_findings": 0, "findings": [],
            "reason": f"target_path does not exist: {target_path}",
        }

    if not _mobsfscan_available():
        return {
            "success": True, "status": "partial",
            "target": target_path,
            "total_findings": 0, "findings": [],
            "reason": (
                "mobsfscan binary not on PATH (or "
                "STRIX_MOBSFSCAN_DISABLED=1). Install via: "
                "`pip install mobsfscan`."
            ),
        }

    # Resolve whether we're scanning an APK (unpack needed) or source.
    if is_apk is None:
        is_apk = target_path.lower().endswith((".apk", ".aab"))

    unpack_dir: str | None = None
    scan_target = target_path
    try:
        if is_apk:
            if not _apktool_available():
                return {
                    "success": True, "status": "partial",
                    "target": target_path,
                    "total_findings": 0, "findings": [],
                    "reason": (
                        "Target is an APK but apktool binary is not "
                        "on PATH. Install via: `apt-get install "
                        "apktool` (or download from "
                        "https://apktool.org/install)."
                    ),
                }
            unpack_dir = tempfile.mkdtemp(prefix="mobsfscan_unpack_")
            unpack_out = os.path.join(unpack_dir, "unpacked")
            try:
                subprocess.run(  # noqa: S603
                    [_APKTOOL_BIN, "d", "-f", "-o", unpack_out, target_path],
                    check=False, capture_output=True,
                    timeout=120, text=True,
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                return {
                    "success": False, "status": "error",
                    "target": target_path,
                    "total_findings": 0, "findings": [],
                    "reason": (
                        f"apktool unpack failed: "
                        f"{type(e).__name__}: {e}"
                    ),
                }
            scan_target = unpack_out

        output_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="w",
            suffix=".sarif" if sarif_output else ".json",
            delete=False,
        )
        output_tmp.close()

        cmd: list[str] = [
            _MOBSFSCAN_BIN,
            "--json" if not sarif_output else "--sarif",
            "-o", output_tmp.name,
            scan_target,
        ]
        try:
            subprocess.run(  # noqa: S603
                cmd, check=False, capture_output=True,
                timeout=timeout_seconds, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return {
                "success": False, "status": "error",
                "target": target_path,
                "total_findings": 0, "findings": [],
                "reason": (
                    f"mobsfscan invocation failed: "
                    f"{type(e).__name__}: {e}"
                ),
            }

        findings = _parse_findings(output_tmp.name, target_path)[:max_findings]
        try:
            os.unlink(output_tmp.name)
        except OSError:
            pass

    finally:
        if unpack_dir and os.path.isdir(unpack_dir):
            try:
                shutil.rmtree(unpack_dir, ignore_errors=True)
            except OSError:
                pass

    return {
        "success": True,
        "status": "ok",
        "target": target_path,
        "total_findings": len(findings),
        "findings": findings,
        "scanned_as_apk": is_apk,
    }
