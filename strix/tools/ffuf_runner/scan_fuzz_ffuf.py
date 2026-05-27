"""iter-37.4 — `scan_fuzz_ffuf` subprocess wrapper.

ffuf (Fast web fuzzer) is the canonical OSS tool for HTTP fuzzing —
content discovery (dirbuster-style), parameter discovery, vhost
enumeration, header fuzzing. Written in Go, single static binary.

Usage modes:
  * Content discovery: `ffuf -u http://target/FUZZ -w wordlist`
  * Param discovery:   `ffuf -u http://target/api?FUZZ=X -w params.txt`
  * Vhost discovery:   `ffuf -u http://target -H "Host: FUZZ.target" -w hosts.txt`

The `FUZZ` keyword in `-u` / `-H` is the substitution placeholder.
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


_FFUF_BIN = "ffuf"
_DEFAULT_TIMEOUT_SECONDS = 180


def _ffuf_available() -> bool:
    if os.environ.get(
        "STRIX_FFUF_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_FFUF_BIN) is not None


# Built-in mini wordlists. The sandbox image typically ships SecLists
# under /opt/SecLists; we prefer that when available + fall back to
# these for portability.
_BUILTIN_PATH_WORDLIST = [
    "admin", "api", "config", "backup", "test", "dev", "staging",
    ".env", ".git", ".git/config", ".git/HEAD", ".DS_Store",
    "robots.txt", "sitemap.xml", "phpinfo.php", ".htaccess",
    "wp-admin", "wp-config.php", "wp-login.php",
    "console", "actuator", "actuator/env", "actuator/health",
    "swagger", "swagger.json", "swagger-ui", "openapi.json",
    "graphql", "graphiql", "_debug", "debug", "metrics",
    "dashboard", "login", "logout", "register", "signup",
    "uploads", "files", "download", "private", "internal",
]
_BUILTIN_PARAM_WORDLIST = [
    "id", "user", "userid", "username", "user_id",
    "page", "redirect", "url", "next", "return",
    "file", "filename", "path", "dir", "folder",
    "q", "query", "search", "keyword",
    "debug", "test", "dev", "admin",
    "token", "auth", "key", "api_key",
]


def _resolve_wordlist(
    explicit_path: str | None,
    builtin: list[str],
) -> str:
    """Resolve the wordlist path to use. If explicit_path is given
    and exists, use it. Otherwise prefer SecLists when present,
    finally fall back to a temp file built from the builtin list."""
    if explicit_path and Path(explicit_path).is_file():
        return explicit_path
    # Try SecLists locations the sandbox image typically has.
    for candidate in (
        "/opt/SecLists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ):
        if Path(candidate).is_file():
            return candidate
    # Final fallback: write the builtin mini-list to a temp file.
    tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".txt", delete=False,
    )
    tmp.write("\n".join(builtin) + "\n")
    tmp.close()
    return tmp.name


_INTERESTING_STATUS_CODES = {200, 201, 204, 301, 302, 307, 401, 403}


def _parse_findings(
    json_output_path: str, target_url: str, mode: str,
) -> list[dict[str, Any]]:
    """ffuf -o foo.json writes a JSON file with `results: [...]`.
    Each result has `input` (the FUZZ value), `status`, `length`,
    `url`. We emit a finding for each interesting hit."""
    try:
        with open(json_output_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[dict[str, Any]] = []
    for hit in data.get("results") or []:
        if not isinstance(hit, dict):
            continue
        status = hit.get("status")
        if not isinstance(status, int) or status not in _INTERESTING_STATUS_CODES:
            continue
        url = hit.get("url") or target_url
        fuzz_val = ""
        if isinstance(hit.get("input"), dict):
            fuzz_val = hit["input"].get("FUZZ", "")
        # Severity: 200/201 of admin/debug/.env paths are high; 403 on
        # interesting paths is medium (existence disclosure).
        sev = "low"
        if status in (200, 201) and any(
            tok in fuzz_val.lower() for tok in (
                "admin", "config", "backup", ".env", ".git",
                "debug", "actuator", "swagger", "graphql",
            )
        ):
            sev = "high" if status == 200 else "medium"
        elif status in (200, 201, 301, 302):
            sev = "low"
        elif status == 403:
            sev = "info"

        findings.append({
            "title": f"ffuf {mode}: {status} on `{fuzz_val}`",
            "category": "misconfig" if mode == "content_discovery" else "param_discovery",
            "cwe": "CWE-200",
            "endpoint": url,
            "severity": sev,
            "verification_status": "verified" if status < 400 else "needs_review",
            "confidence": 0.7,
            "description": (
                f"ffuf discovered `{fuzz_val}` returns HTTP {status} "
                f"on {target_url}. " + (
                    "This path may expose sensitive configuration / "
                    "internal interfaces."
                    if sev in ("high", "medium")
                    else "Confirm whether this path is intentionally public."
                )
            ),
            "ffuf_status": status,
            "ffuf_length": hit.get("length"),
            "ffuf_words": hit.get("words"),
            "ffuf_input": fuzz_val,
        })
    return findings


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1083"],  # File and Directory Discovery
)
def scan_fuzz_ffuf(
    *,
    target_url: str,
    mode: str = "content_discovery",
    wordlist_path: str | None = None,
    match_codes: str = "200,201,204,301,302,307,401,403",
    extensions: str | None = None,
    extra_headers: dict[str, str] | None = None,
    threads: int = 40,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    max_findings: int = 100,
) -> dict[str, Any]:
    """ffuf-backed web fuzzing.

    Args:
        target_url: full URL containing the literal token ``FUZZ`` at
            the position to fuzz. Examples:
              * Content discovery: ``http://target/FUZZ``
              * Param discovery: ``http://target/api?FUZZ=test``
              * Vhost: ``http://target/`` + extra_headers
                ``{"Host": "FUZZ.target.com"}``
        mode: one of ``content_discovery`` / ``param_discovery`` /
            ``vhost``. Drives the default wordlist + finding category.
        wordlist_path: explicit path to wordlist. When None, the
            wrapper auto-resolves: SecLists common.txt if present,
            otherwise a built-in mini-list of 40 high-signal paths.
        match_codes: comma-separated HTTP status codes to flag.
            Default covers redirects + interesting 4xx (401/403).
        extensions: optional ``.php,.bak,.zip,.old`` style list; ffuf
            tries each FUZZ entry with these appended.
        extra_headers: dict of headers to inject (e.g. CSRF cookie,
            Host for vhost mode).
        threads: parallel-request count (`-t`). Default 40 — ffuf is
            very fast; reduce if hitting rate limits.
        timeout_seconds: subprocess kill timeout. Default 180s.
        max_findings: stop emitting findings after this many to keep
            results actionable (ffuf can find 1000+ paths).

    Returns:
        ```
        {success, status, target, total_findings: int,
         findings: [{title, category, cwe, endpoint, severity,
                      verification_status, confidence, description,
                      ffuf_status, ffuf_length, ffuf_input}, ...],
         reason?}
        ```
    """
    if not isinstance(target_url, str) or not target_url.strip():
        return {
            "success": False, "status": "error", "target": target_url or "",
            "total_findings": 0, "findings": [],
            "reason": "target_url required",
        }
    target_url = target_url.strip()

    if "FUZZ" not in target_url and not (
        extra_headers and any("FUZZ" in v for v in extra_headers.values())
    ):
        # Auto-inject /FUZZ for content_discovery if the caller forgot.
        if mode == "content_discovery":
            target_url = target_url.rstrip("/") + "/FUZZ"
        else:
            return {
                "success": False, "status": "error",
                "target": target_url,
                "total_findings": 0, "findings": [],
                "reason": (
                    "target_url must contain the literal `FUZZ` token "
                    "(or extra_headers must) to mark the fuzz position."
                ),
            }

    if not _ffuf_available():
        return {
            "success": True, "status": "partial",
            "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": (
                "ffuf binary not on PATH (or STRIX_FFUF_DISABLED=1). "
                "Install via: `go install github.com/ffuf/ffuf/v2@latest`."
            ),
        }

    builtin = (
        _BUILTIN_PATH_WORDLIST if mode in ("content_discovery", "vhost")
        else _BUILTIN_PARAM_WORDLIST
    )
    wordlist = _resolve_wordlist(wordlist_path, builtin)

    output_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".json", delete=False,
    )
    output_tmp.close()

    try:
        cmd: list[str] = [
            _FFUF_BIN,
            "-u", target_url,
            "-w", wordlist,
            "-mc", match_codes,
            "-t", str(max(1, min(200, threads))),
            "-of", "json",
            "-o", output_tmp.name,
            "-s",        # silent (no banner)
            "-noninteractive",
        ]
        if extensions:
            cmd.extend(["-e", extensions])
        if extra_headers:
            for hk, hv in extra_headers.items():
                cmd.extend(["-H", f"{hk}: {hv}"])

        try:
            subprocess.run(  # noqa: S603
                cmd, check=False, capture_output=True,
                timeout=timeout_seconds, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return {
                "success": False, "status": "error",
                "target": target_url,
                "total_findings": 0, "findings": [],
                "reason": f"ffuf invocation failed: {type(e).__name__}: {e}",
            }

        findings = _parse_findings(output_tmp.name, target_url, mode)
        findings = findings[:max_findings]
    finally:
        try:
            os.unlink(output_tmp.name)
        except OSError:
            pass

    return {
        "success": True,
        "status": "ok",
        "target": target_url,
        "total_findings": len(findings),
        "findings": findings,
        "mode": mode,
        "wordlist": wordlist,
    }
