"""Nuclei template auto-update at scan start.

Pulls the latest Nuclei templates from
`projectdiscovery/nuclei-templates` so CVE coverage doesn't degrade
between sandbox image rebuilds. Nuclei templates ship daily; the
image-baked snapshot goes stale within weeks. Designed to be invoked
once at scan start (or default-on for `deep` mode).

Mechanism: shells out to `nuclei -update-templates -silent` (or the
modern shortcut `nuclei -ut -silent`). The Nuclei CLI handles the
git-pull / cache-management / template-checksum verification
internally. We capture stdout + stderr, parse the version markers,
and return a structured summary.

Why subprocess over a Python git-pull: Nuclei's update path is the
authoritative one — it verifies template checksums, prunes deprecated
templates, and reports a definitive version. Re-implementing it via
git would drift.

Process discipline:
- `nuclei` binary located via `shutil.which`. If not found, returns
  `success=False` with a clear error so the caller knows the sandbox
  image wasn't built with the Nuclei tool.
- Subprocess invoked with a hard timeout (default 120s; bigger than
  most tools because templates can be ~50MB and the upstream API can
  rate-limit slow connections).
- Output captured in memory, capped at 64 KiB (truncated suffix
  marked).
- Update is idempotent — if templates are already current, the tool
  reports `updated=False` and returns quickly.

Throttling:
- Per-process throttle: refuses to run more than once every 30
  minutes against the local Nuclei templates directory (cached
  state on disk under `~/.strix/nuclei_template_meta.json`). The
  agent can pass `force=True` to override.
- This avoids redundant updates within a single multi-target scan
  while keeping the data fresh enough to matter.

Findings: this tool emits a single info-level finding with the
update status. Mainly useful for the run report / coverage
assertions ("templates were refreshed at scan start; coverage is
current as of <timestamp>") rather than for triage.

Composes with cluster-A safety: the `--exclude-path` flag is a no-op
(the URL endpoints belong to GitHub / nuclei-templates, not the
customer's domain). `--rate-limit` doesn't affect the subprocess
call directly (Nuclei manages its own outbound rate).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess  # noqa: S404 — well-scoped subprocess use, see _run_nuclei docstring
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "nuclei_template_update"
_DEFAULT_TIMEOUT = 120.0
_DEFAULT_THROTTLE_SECONDS = 30 * 60
_MAX_OUTPUT_BYTES = 64 * 1024

# `nuclei -ut -silent` and `nuclei -update-templates -silent` are
# both supported by recent Nuclei versions. We try the modern
# shortcut first.
_NUCLEI_UPDATE_ARGS_PRIMARY = ("-ut", "-silent")
_NUCLEI_UPDATE_ARGS_FALLBACK = ("-update-templates", "-silent")


# Patterns Nuclei prints during template updates. Matched against
# the merged stdout+stderr; case-insensitive.
_TEMPLATE_VERSION_RE = re.compile(
    r"templates\s*v?(\d+(?:\.\d+){0,3})", re.IGNORECASE,
)
_TEMPLATE_COUNT_RE = re.compile(
    r"loaded\s+(\d+)\s+templates", re.IGNORECASE,
)
_NO_UPDATE_NEEDED_RE = re.compile(
    r"no\s+new\s+updates|already\s+up[\s-]to[\s-]date|currently\s+at\s+the\s+latest",
    re.IGNORECASE,
)
_UPDATE_APPLIED_RE = re.compile(
    r"successfully\s+updated|updated\s+to\s+v?\d|new\s+version\s+v?\d",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Throttle metadata
# ---------------------------------------------------------------------------


def _meta_path() -> Path:
    return Path.home() / ".strix" / "nuclei_template_meta.json"


def _read_meta() -> dict[str, Any]:
    path = _meta_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, TypeError) as e:
        logger.debug("nuclei_template meta read failed: %s", e)
    return {}


def _write_meta(payload: dict[str, Any]) -> None:
    try:
        _meta_path().parent.mkdir(parents=True, exist_ok=True)
        with _meta_path().open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("nuclei_template meta write failed: %s", e)


def _within_throttle_window(meta: dict[str, Any], throttle_seconds: int) -> bool:
    last = meta.get("last_run_at")
    if not isinstance(last, (int, float)):
        return False
    age = time.time() - last
    return 0 <= age < throttle_seconds


# ---------------------------------------------------------------------------
# Subprocess invocation
# ---------------------------------------------------------------------------


def _locate_nuclei_binary() -> str | None:
    """Return path to the `nuclei` executable, or None when missing.

    `STRIX_NUCLEI_BIN` env override lets users point at a non-default
    install path (e.g. when running tests / non-standard sandbox images).
    """
    override = (os.environ.get("STRIX_NUCLEI_BIN") or "").strip()
    if override:
        if Path(override).is_file():
            return override
        return None
    return shutil.which("nuclei")


def _run_nuclei(
    binary: str, args: tuple[str, ...], timeout: float
) -> dict[str, Any]:
    """Execute `nuclei` with the given args and return
    {returncode, stdout, stderr, duration_seconds, error?}.

    Uses `subprocess.run` with `shell=False` and a list-form argv so
    no shell interpretation occurs. The `binary` argument comes from
    `shutil.which` or an explicit env override — both vetted paths.
    `timeout` is enforced at the OS level via the `timeout` kwarg.
    """
    cmd = [binary, *args]
    start = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 — argv-form, no shell, vetted binary path
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": _truncate(e.stdout or ""),
            "stderr": _truncate(e.stderr or ""),
            "duration_seconds": round(time.monotonic() - start, 2),
            "error": f"nuclei update timed out after {timeout}s",
        }
    except (OSError, ValueError) as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "duration_seconds": round(time.monotonic() - start, 2),
            "error": f"nuclei subprocess failed: {type(e).__name__}: {e}",
        }
    return {
        "returncode": completed.returncode,
        "stdout": _truncate(completed.stdout or ""),
        "stderr": _truncate(completed.stderr or ""),
        "duration_seconds": round(time.monotonic() - start, 2),
    }


def _truncate(text: str) -> str:
    if len(text) <= _MAX_OUTPUT_BYTES:
        return text
    return text[:_MAX_OUTPUT_BYTES] + "\n... [output truncated]"


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def _parse_nuclei_output(stdout: str, stderr: str) -> dict[str, Any]:
    """Extract version + count + update-applied signal from merged
    nuclei output."""
    merged = (stdout or "") + "\n" + (stderr or "")

    version: str | None = None
    m_version = _TEMPLATE_VERSION_RE.search(merged)
    if m_version:
        version = m_version.group(1)

    template_count: int | None = None
    m_count = _TEMPLATE_COUNT_RE.search(merged)
    if m_count:
        try:
            template_count = int(m_count.group(1))
        except ValueError:
            template_count = None

    no_update = bool(_NO_UPDATE_NEEDED_RE.search(merged))
    update_applied = bool(_UPDATE_APPLIED_RE.search(merged))

    return {
        "version": version,
        "template_count": template_count,
        "no_update_needed": no_update,
        "update_applied": update_applied,
    }


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity="info",
        category="info_disclosure",
        cwe="CWE-200",
        target="nuclei-templates",
        endpoint="local://nuclei-templates",
        description=description,
        impact=(
            "Nuclei templates are the deterministic-CVE-detection "
            "layer of the scan. Templates ship daily; image-baked "
            "snapshots go stale within weeks. This finding records "
            "whether the templates were refreshed at scan start and "
            "what version is in use, so the run report / coverage "
            "assertions can quote the template version that backed "
            "the findings."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1588.006"],  # Obtain Capabilities: Vulnerabilities
)
def nuclei_template_update(
    timeout: float = _DEFAULT_TIMEOUT,
    force: bool = False,
    throttle_seconds: int = _DEFAULT_THROTTLE_SECONDS,
) -> dict[str, Any]:
    """Refresh the local Nuclei template database.

    Args:
        timeout: Hard timeout for the nuclei subprocess (default 120s;
            templates can be ~50MB and upstream may rate-limit slow
            connections).
        force: When True, bypasses the throttle window and always
            invokes nuclei. Default False (re-runs within the
            `throttle_seconds` window are skipped to avoid redundant
            updates within a multi-target scan).
        throttle_seconds: Skip-update window in seconds. Default
            1800s (30 minutes).

    Returns:
        {
          success, ran, throttled, updated,
          binary_path, args_used,
          version_before, version_after,
          template_count_after,
          duration_seconds,
          stdout, stderr, returncode,
          findings_emitted,
          error?,
        }

    Findings:
        Single info-severity finding (CWE-200, info_disclosure) with
        the update status. Useful for the run report / coverage
        assertions ("templates were refreshed at scan start; coverage
        is current as of <timestamp>") rather than for triage.

    Notes:
        - Looks up `nuclei` via `shutil.which` (or `STRIX_NUCLEI_BIN`
          env override). Returns `success=False` with a clear error
          when the binary isn't installed.
        - Subprocess runs with `shell=False` and a list-form argv;
          no shell interpretation; vetted binary path.
        - Per-process throttle (~30 min default) avoids redundant
          updates within a multi-target scan. Pass `force=True` to
          override.
        - Composes with cluster-A safety: `--exclude-path` doesn't
          apply (Nuclei talks to GitHub / projectdiscovery, not the
          customer's domain).
    """
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        timeout = _DEFAULT_TIMEOUT

    cev = _start_check("nuclei_template_update", "sandbox")

    binary = _locate_nuclei_binary()
    if binary is None:
        _complete_check(
            cev,
            result="inconclusive",
            evidence="nuclei binary not found in PATH",
        )
        return {
            "success": False,
            "ran": False,
            "throttled": False,
            "updated": False,
            "binary_path": None,
            "error": (
                "nuclei binary not found in PATH (set STRIX_NUCLEI_BIN to "
                "override)"
            ),
            "findings_emitted": 0,
        }

    meta = _read_meta()

    if not force and _within_throttle_window(meta, throttle_seconds):
        _complete_check(
            cev,
            result="not_vulnerable",
            evidence="nuclei templates updated recently; throttled",
        )
        return {
            "success": True,
            "ran": False,
            "throttled": True,
            "updated": False,
            "binary_path": binary,
            "version_after": meta.get("last_version"),
            "template_count_after": meta.get("last_template_count"),
            "last_run_at": meta.get("last_run_at"),
            "findings_emitted": 0,
        }

    # Try the modern flag first; on a hard error (returncode != 0
    # AND no version-version markers in output), fall back to the
    # legacy flag.
    primary = _run_nuclei(binary, _NUCLEI_UPDATE_ARGS_PRIMARY, timeout)
    args_used = _NUCLEI_UPDATE_ARGS_PRIMARY
    parsed = _parse_nuclei_output(primary.get("stdout", ""), primary.get("stderr", ""))
    if (
        primary.get("returncode") != 0
        and parsed.get("version") is None
        and parsed.get("template_count") is None
        and not primary.get("error")
    ):
        # The primary args may not be supported on this Nuclei build
        # — try the legacy flag.
        fallback = _run_nuclei(binary, _NUCLEI_UPDATE_ARGS_FALLBACK, timeout)
        fallback_parsed = _parse_nuclei_output(
            fallback.get("stdout", ""), fallback.get("stderr", "")
        )
        if (
            fallback.get("returncode") == 0
            or fallback_parsed.get("version")
            or fallback_parsed.get("template_count")
        ):
            primary = fallback
            parsed = fallback_parsed
            args_used = _NUCLEI_UPDATE_ARGS_FALLBACK

    returncode = primary.get("returncode")
    error = primary.get("error")
    if error:
        _complete_check(cev, "inconclusive", f"nuclei subprocess failed: {error}")
        return {
            "success": False,
            "ran": True,
            "throttled": False,
            "updated": False,
            "binary_path": binary,
            "args_used": list(args_used),
            "version_before": meta.get("last_version"),
            "version_after": None,
            "template_count_after": None,
            "duration_seconds": primary.get("duration_seconds"),
            "stdout": primary.get("stdout"),
            "stderr": primary.get("stderr"),
            "returncode": returncode,
            "error": error,
            "findings_emitted": 0,
        }

    # Treat the run as successful when returncode==0 OR when we
    # extracted version/template-count from the output (Nuclei
    # sometimes returns non-zero on "no update needed" depending on
    # the build).
    succeeded = (
        returncode == 0
        or parsed.get("version") is not None
        or parsed.get("template_count") is not None
    )
    if not succeeded:
        _complete_check(
            cev,
            "inconclusive",
            f"nuclei returned {returncode} with no recognisable output",
        )
        return {
            "success": False,
            "ran": True,
            "throttled": False,
            "updated": False,
            "binary_path": binary,
            "args_used": list(args_used),
            "version_before": meta.get("last_version"),
            "version_after": None,
            "template_count_after": None,
            "duration_seconds": primary.get("duration_seconds"),
            "stdout": primary.get("stdout"),
            "stderr": primary.get("stderr"),
            "returncode": returncode,
            "error": (
                f"nuclei returned {returncode} with no parseable "
                "output (binary may be too old or output format changed)"
            ),
            "findings_emitted": 0,
        }

    version_before = meta.get("last_version")
    version_after = parsed.get("version") or version_before
    template_count_after = parsed.get("template_count")

    if parsed.get("update_applied"):
        updated = True
    elif parsed.get("no_update_needed"):
        updated = False
    elif version_before and version_after and version_before != version_after:
        updated = True
    else:
        updated = False

    # Record fresh meta.
    new_meta = dict(meta)
    new_meta.update({
        "last_run_at": int(time.time()),
        "last_version": version_after,
        "last_template_count": template_count_after,
        "last_args_used": list(args_used),
    })
    _write_meta(new_meta)

    # Emit info finding with the current state.
    findings_emitted = 0
    if updated:
        title = (
            f"Nuclei templates refreshed (now v{version_after or '?'})"
            if version_after
            else "Nuclei templates refreshed at scan start"
        )
        description = (
            f"Nuclei template database updated from v{version_before or '?'} "
            f"to v{version_after or '?'} ({template_count_after or '?'} "
            f"templates loaded). Update took "
            f"{primary.get('duration_seconds')}s."
        )
        description_plain = (
            "We refreshed the Nuclei vulnerability-template database "
            "before scanning. Nuclei ships new CVE templates daily; "
            "running this refresh ensures the scan uses the latest "
            "detection signatures."
        )
        recommended_action = (
            "No action required — this is informational. The run report "
            "/ coverage assertions will quote the template version "
            f"(v{version_after or '?'}) backing the scan's CVE "
            "findings."
        )
    else:
        title = (
            f"Nuclei templates already current (v{version_after or '?'})"
            if version_after
            else "Nuclei templates already current"
        )
        description = (
            f"Nuclei template database already up to date "
            f"(v{version_after or 'unknown'}, "
            f"{template_count_after or 'unknown'} templates). "
            f"Update check took {primary.get('duration_seconds')}s."
        )
        description_plain = (
            "We checked the Nuclei vulnerability-template database "
            "and confirmed it's already at the latest version. The "
            "scan will use these templates for CVE detection."
        )
        recommended_action = (
            "No action required — this is informational. The run "
            f"report will quote the template version "
            f"(v{version_after or '?'}) backing the scan."
        )
    _emit_finding(
        title=title,
        description=description,
        description_plain=description_plain,
        recommended_action=recommended_action,
    )
    findings_emitted = 1

    _complete_check(
        cev,
        result="not_vulnerable",
        evidence=(
            f"templates {'updated to' if updated else 'already at'} "
            f"v{version_after or '?'} "
            f"({template_count_after or '?'} templates)"
        ),
    )
    return {
        "success": True,
        "ran": True,
        "throttled": False,
        "updated": updated,
        "binary_path": binary,
        "args_used": list(args_used),
        "version_before": version_before,
        "version_after": version_after,
        "template_count_after": template_count_after,
        "duration_seconds": primary.get("duration_seconds"),
        "stdout": primary.get("stdout"),
        "stderr": primary.get("stderr"),
        "returncode": returncode,
        "findings_emitted": findings_emitted,
    }
