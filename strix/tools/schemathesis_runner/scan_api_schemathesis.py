"""iter-37.4 — `scan_api_schemathesis` subprocess wrapper.

schemathesis (Kiwi-CMS) is the leading OSS property-based API fuzzer.
It reads an OpenAPI / Swagger / GraphQL schema, generates structurally-
valid test cases via Hypothesis, fires them at the API, and reports:
  * Schema conformance violations (server returned a shape that
    doesn't match its declared response schema)
  * Server errors (5xx) on inputs the schema considers valid
  * Auth boundary issues (unauthenticated 200 on `security: bearer`
    endpoints)
  * Content-type / media-type mismatches
  * Reproducible failure cases (Hypothesis minimisation)

This complements nuclei's template-driven scanning by exercising the
API's PROPER SPEC — anything the API claims it does must hold under
random structurally-valid inputs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess  # noqa: S404
import tempfile
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_SCHEMATHESIS_BIN = "schemathesis"
_ST_FALLBACK_BIN = "st"  # newer versions ship a shorter alias
_DEFAULT_TIMEOUT_SECONDS = 240


def _schemathesis_available() -> tuple[str, bool]:
    """Return (binary_path, available) — falls back to `st` alias
    if `schemathesis` isn't on PATH."""
    if os.environ.get(
        "STRIX_SCHEMATHESIS_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return ("", False)
    for binary in (_SCHEMATHESIS_BIN, _ST_FALLBACK_BIN):
        path = shutil.which(binary)
        if path:
            return (binary, True)
    return ("", False)


# schemathesis Cassette/JSON output gives one entry per failed check.
# Each has `request: {method, uri}`, `response: {status_code, body}`,
# `checks: [{name, message, value}]` for the failing checks.

_CHECK_TO_FINDING_CATEGORY: dict[str, tuple[str, str, str]] = {
    # check_name → (category, cwe, severity)
    "status_code_conformance": ("schema_violation", "CWE-707", "medium"),
    "content_type_conformance": ("schema_violation", "CWE-707", "low"),
    "response_schema_conformance": ("schema_violation", "CWE-707", "medium"),
    "response_headers_conformance": ("schema_violation", "CWE-707", "low"),
    "not_a_server_error": ("server_error", "CWE-755", "high"),
    "ignored_auth": ("missing_auth", "CWE-862", "high"),
    "negative_data_rejection": ("input_validation", "CWE-20", "medium"),
}


def _parse_findings(
    output_path: str, target_url: str,
) -> list[dict[str, Any]]:
    """Parse schemathesis's JSON report file into our finding shape."""
    try:
        with open(output_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[dict[str, Any]] = []
    # schemathesis JSON shape: {"results": [{"errors": [...],
    # "checks": [...]}], ...}
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        for check in result.get("checks") or []:
            if not isinstance(check, dict):
                continue
            if check.get("value") == "SUCCESS":
                continue
            name = check.get("name") or "unknown"
            cat, cwe, sev = _CHECK_TO_FINDING_CATEGORY.get(
                name, ("schema_violation", "CWE-707", "low"),
            )
            req = check.get("request") or {}
            resp = check.get("response") or {}
            method = req.get("method", "GET")
            url = req.get("uri") or target_url
            status = resp.get("status_code")
            message = check.get("message") or name

            findings.append({
                "title": (
                    f"schemathesis {name}: {method} {url}"
                    + (f" → HTTP {status}" if status else "")
                ),
                "category": cat,
                "cwe": cwe,
                "endpoint": url,
                "method": method,
                "severity": sev,
                "verification_status": "verified",
                "confidence": 0.85,
                "description": (
                    f"schemathesis fired a structurally-valid request "
                    f"per the OpenAPI spec but the server's response "
                    f"failed the `{name}` check: {message[:300]}. "
                    + (
                        f"The endpoint returned HTTP {status}. "
                        if status else ""
                    )
                    + "Either the spec is wrong (update it) or the "
                    "implementation diverges from the contract "
                    "(fix the handler)."
                ),
                "schemathesis_check": name,
                "schemathesis_status_code": status,
            })
    return findings


# Fallback: when schemathesis's JSON report isn't usable, scrape the
# `FAIL` lines from stdout. Format:
#   FAIL: GET /users/{id} [status_code_conformance] Received: 500
_STDOUT_FAIL_RE = re.compile(
    r"^FAIL:\s+(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+"
    r"\[(?P<check>[\w_]+)\](?:\s+(?P<message>.+))?$",
    re.MULTILINE,
)


def _parse_findings_from_stdout(
    stdout: str, target_url: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for m in _STDOUT_FAIL_RE.finditer(stdout or ""):
        name = m.group("check")
        cat, cwe, sev = _CHECK_TO_FINDING_CATEGORY.get(
            name, ("schema_violation", "CWE-707", "low"),
        )
        method = m.group("method")
        path = m.group("path")
        url = (
            target_url.rstrip("/") + "/" + path.lstrip("/")
            if not path.startswith("http") else path
        )
        findings.append({
            "title": f"schemathesis {name}: {method} {path}",
            "category": cat,
            "cwe": cwe,
            "endpoint": url,
            "method": method,
            "severity": sev,
            "verification_status": "verified",
            "confidence": 0.8,
            "description": (
                f"schemathesis {name} check failed for {method} "
                f"{path}: {m.group('message') or '(see report)'}"
            ),
            "schemathesis_check": name,
        })
    return findings


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def scan_api_schemathesis(
    *,
    schema_url: str,
    base_url: str | None = None,
    checks: list[str] | None = None,
    max_examples: int = 50,
    workers: int = 4,
    auth_bearer: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    max_findings: int = 100,
) -> dict[str, Any]:
    """schemathesis-backed property-based API fuzzing.

    Args:
        schema_url: URL to the OpenAPI / Swagger / GraphQL schema
            (e.g. ``http://target/openapi.json``).
        base_url: override the schema's declared servers — useful when
            the spec says `http://localhost:8080` but the bench target
            is `http://host.docker.internal:3001`.
        checks: subset of conformance checks to run. Default: all.
            Common subset: ``["not_a_server_error",
            "response_schema_conformance", "status_code_conformance"]``.
        max_examples: Hypothesis test cases per operation. Default
            50 (good balance of coverage vs runtime).
        workers: parallel-request count (`--workers`). Default 4.
        auth_bearer: optional bearer token to inject as
            ``Authorization: Bearer <token>``. Auth-boundary tests
            (`ignored_auth` check) need an UN-authed run too — this
            is the authed phase.
        extra_headers: additional headers (e.g. tenant-id, csrf).
        timeout_seconds: subprocess kill timeout. Default 240s.
        max_findings: cap on emitted findings — schemathesis can find
            hundreds when the API is broken.

    Returns:
        ```
        {success, status, target, total_findings: int,
         findings: [{title, category, cwe, endpoint, method, severity,
                      verification_status, confidence, description,
                      schemathesis_check, schemathesis_status_code},
                     ...],
         reason?}
        ```
    """
    if not isinstance(schema_url, str) or not schema_url.strip():
        return {
            "success": False, "status": "error", "target": schema_url or "",
            "total_findings": 0, "findings": [],
            "reason": "schema_url required",
        }
    schema_url = schema_url.strip()

    binary, available = _schemathesis_available()
    if not available:
        return {
            "success": True, "status": "partial",
            "target": schema_url,
            "total_findings": 0, "findings": [],
            "reason": (
                "schemathesis binary not on PATH (or "
                "STRIX_SCHEMATHESIS_DISABLED=1). Install via: "
                "`pip install schemathesis`."
            ),
        }

    output_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".json", delete=False,
    )
    output_tmp.close()

    try:
        cmd: list[str] = [
            binary, "run", schema_url,
            "--hypothesis-max-examples", str(max(1, max_examples)),
            "--workers", str(max(1, min(16, workers))),
            "--report", output_tmp.name,
            "--no-stats",
            "--no-color",
        ]
        if base_url:
            cmd.extend(["--base-url", base_url])
        if checks:
            for chk in checks:
                cmd.extend(["--checks", chk])
        if auth_bearer:
            cmd.extend([
                "-H", f"Authorization: Bearer {auth_bearer}",
            ])
        if extra_headers:
            for hk, hv in extra_headers.items():
                cmd.extend(["-H", f"{hk}: {hv}"])

        try:
            result = subprocess.run(  # noqa: S603
                cmd, check=False, capture_output=True,
                timeout=timeout_seconds, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return {
                "success": False, "status": "error",
                "target": schema_url,
                "total_findings": 0, "findings": [],
                "reason": (
                    f"schemathesis invocation failed: "
                    f"{type(e).__name__}: {e}"
                ),
            }

        # Prefer the JSON report when present, fall back to stdout grep.
        findings = _parse_findings(output_tmp.name, schema_url)
        if not findings:
            findings = _parse_findings_from_stdout(
                result.stdout or "", schema_url,
            )
        findings = findings[:max_findings]
    finally:
        try:
            os.unlink(output_tmp.name)
        except OSError:
            pass

    return {
        "success": True,
        "status": "ok",
        "target": schema_url,
        "total_findings": len(findings),
        "findings": findings,
        "max_examples": max_examples,
    }
