"""iter-37.4 — `probe_default_creds_hydra` subprocess wrapper.

Replaces the pure-python `probe_default_creds` (iter-28.6) with a
hydra-backed implementation. hydra is the de-facto OSS credential-
bruteforce tool — it supports HTTP-POST-FORM, HTTP-GET-FORM, HTTP
basic-auth, HTTP digest-auth, plus dozens of network-service modules.

Why hydra over the in-house implementation:
  * Hardened against rate limits and connection errors with built-in
    retry / parallelism controls (`-t`, `-W`).
  * Supports cookie capture via `c=<cookie>` and CSRF-token re-use via
    H= header injection.
  * Battle-tested credential corpora (SecLists, top-1000) — strix
    ships those wordlists in the sandbox image.
  * Wider protocol coverage (SSH/FTP/SNMP/SMB/IMAP/POP3/+) when the
    target isn't a web login.

This wrapper focuses on the common case: HTTP-POST-FORM logins. Other
services route through hydra's `<service>://` syntax via the
`service` kwarg.
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


_HYDRA_BIN = "hydra"
_DEFAULT_TIMEOUT_SECONDS = 180
_DEFAULT_PARALLEL_TASKS = 4


def _hydra_available() -> bool:
    if os.environ.get(
        "STRIX_HYDRA_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_HYDRA_BIN) is not None


# hydra prints findings on lines like:
#   [80][http-post-form] host: 10.0.0.5  login: admin  password: admin
# (sometimes split across lines with extra whitespace).
_FOUND_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[\w\-]+)\]\s+"
    r"host:\s+(?P<host>\S+)\s+"
    r"login:\s+(?P<login>\S+)\s+"
    r"password:\s+(?P<password>\S+)",
)


def _parse_findings(stdout: str, target_url: str) -> list[dict[str, Any]]:
    """Extract `[port][service] host: X login: Y password: Z` lines
    from hydra's stdout."""
    findings: list[dict[str, Any]] = []
    for m in _FOUND_RE.finditer(stdout or ""):
        login = m.group("login")
        password = m.group("password")
        findings.append({
            "title": f"Default credentials accepted: {login}/{password}",
            "category": "auth",
            "cwe": "CWE-521",
            "endpoint": target_url,
            "severity": "high",
            "verification_status": "verified",
            "confidence": 1.0,
            "description": (
                f"hydra confirmed login as `{login}` with password "
                f"`{password}` against {target_url}. Default / well-"
                f"known credentials are the most-exploited bug class "
                f"on the internet — rotate the password and enforce "
                f"a strong-password policy immediately."
            ),
            "service": m.group("service"),
            "host": m.group("host"),
            "port": int(m.group("port")),
            "credential_login": login,
            "credential_password": password,
        })
    return findings


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1110.001"],  # Brute Force: Password Guessing
)
def probe_default_creds_hydra(
    *,
    target_url: str,
    username_list: list[str] | None = None,
    password_list: list[str] | None = None,
    service: str = "http-post-form",
    login_path: str | None = None,
    form_template: str | None = None,
    failure_marker: str = "incorrect",
    extra_headers: dict[str, str] | None = None,
    tasks: int = _DEFAULT_PARALLEL_TASKS,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """hydra-backed credential bruteforce.

    Args:
        target_url: full login URL (e.g.
            ``https://example.com/login``). For non-HTTP services
            pass ``ssh://host:22`` style + leave `login_path`/
            `form_template` unset.
        username_list: usernames to try. When None, uses the built-in
            top-20 corpus (admin/root/test/user/+).
        password_list: passwords to try. When None, uses the built-in
            top-20 corpus (admin/password/123456/+).
        service: hydra service module. Default `http-post-form`.
            Other common: `http-get`, `http-post`, `https-post-form`,
            `ssh`, `ftp`, `mysql`, `postgres`.
        login_path: URI path of the login endpoint (e.g. `/login`).
            Required for http-*-form services.
        form_template: hydra-style POST body template with `^USER^`
            and `^PASS^` placeholders (e.g.
            `username=^USER^&password=^PASS^`). Required for
            http-*-form. The wrapper auto-builds a default if missing.
        failure_marker: substring that appears in the response body
            on FAILED logins. Hydra uses this to distinguish success
            from failure. Default "incorrect".
        extra_headers: dict of headers to inject (e.g. CSRF token,
            session cookie). Sent via hydra's `H=` syntax.
        tasks: parallel-task count (`-t`). Higher = faster, more
            aggressive. Default 4 to play nice with rate limits.
        timeout_seconds: subprocess kill timeout. Default 180s.

    Returns:
        ```
        {success, status, target, total_findings: int,
         findings: [{title, category, cwe, endpoint, severity,
                      verification_status, confidence, description,
                      service, host, port, credential_login,
                      credential_password}, ...], reason?}
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

    if not _hydra_available():
        return {
            "success": True, "status": "partial",
            "target": target_url,
            "total_findings": 0, "findings": [],
            "reason": (
                "hydra binary not on PATH (or STRIX_HYDRA_DISABLED=1). "
                "Install via apt: `apt-get install hydra` (or "
                "hydra-gtk for the GUI variant)."
            ),
        }

    # Default credential corpora — keep small enough to avoid
    # bench-time blowups; lead can pass explicit lists for deeper runs.
    usernames = username_list or [
        "admin", "administrator", "root", "user", "test",
        "guest", "demo", "info", "operator", "support",
    ]
    passwords = password_list or [
        "admin", "password", "123456", "admin123", "root",
        "letmein", "welcome", "changeme", "qwerty", "12345678",
    ]

    # Build the hydra command. For http-*-form services, the URL is
    # split: host:port + path + form_template + failure_marker.
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    host_port = parsed.netloc
    path = login_path or parsed.path or "/login"

    if service.endswith("-form"):
        form_tmpl = form_template or (
            f"username=^USER^&password=^PASS^:F={failure_marker}"
        )
        if ":F=" not in form_tmpl and ":S=" not in form_tmpl:
            form_tmpl = f"{form_tmpl}:F={failure_marker}"
        # hydra http-post-form syntax: <path>:<body>:<F=marker>
        target_spec = f"{host_port}"
        # Use the http(s)-post-form service as the trailing arg
        endpoint = f"{path}:{form_tmpl}"
    else:
        target_spec = host_port
        endpoint = ""

    # hydra invocation uses `-L` for user-list FILE and `-l` for a
    # single login; we use the in-memory list via `-l` repeats. The
    # cleanest portable approach: write temp wordlists.
    import tempfile
    user_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".txt", delete=False,
    )
    pwd_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".txt", delete=False,
    )
    try:
        user_tmp.write("\n".join(usernames) + "\n")
        user_tmp.close()
        pwd_tmp.write("\n".join(passwords) + "\n")
        pwd_tmp.close()

        cmd: list[str] = [
            _HYDRA_BIN,
            "-L", user_tmp.name,
            "-P", pwd_tmp.name,
            "-t", str(max(1, min(16, tasks))),
            "-I",        # ignore restore file
            "-f",        # stop after first success per host
        ]
        if extra_headers:
            for hk, hv in extra_headers.items():
                cmd.extend(["-H", f"{hk}: {hv}"])
        cmd.append(target_spec)
        cmd.append(service)
        if endpoint:
            cmd.append(endpoint)

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
                "reason": f"hydra invocation failed: {type(e).__name__}: {e}",
            }
    finally:
        # Clean up temp wordlist files.
        for tmp in (user_tmp, pwd_tmp):
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

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
        "candidates_tried": len(usernames) * len(passwords),
        "service": service,
    }
