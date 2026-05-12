"""Celery worker — invokes strix as a subprocess.

One Celery task = one strix CLI invocation = one scan. The task
chdir's to a per-scan run directory before invoking strix (because
the run-dir is hardcoded to `cwd/strix_runs/<run_id>/`), captures
the resulting artefacts, and returns a manifest of where they
landed.

This is intentionally minimal — it's the "floor" that a real
wrapper builds up from. See README.md for the K8s / S3 /
per-tenant upgrade path.

The contract this enforces is documented at
docs/wrapper-integration.md in the strix repo.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

from celery import Celery


# ---------------------------------------------------------------------------
# Celery setup
# ---------------------------------------------------------------------------

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.environ.get(
    "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
)

app = Celery("strix_runner", broker=BROKER_URL, backend=RESULT_BACKEND)
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # Each scan can take 30 min. Don't let Celery's default 30s
    # soft-limit kick in.
    task_soft_time_limit=60 * 35,
    task_time_limit=60 * 40,
    # Acknowledge AFTER the task completes — otherwise a worker
    # crash mid-scan loses the job.
    task_acks_late=True,
    # Don't auto-retry on failure; the wrapper layer decides.
    task_default_retry_delay=0,
)


# ---------------------------------------------------------------------------
# Strix invocation
# ---------------------------------------------------------------------------

# Where this worker stages run-dirs. One subdir per scan.
RUN_STORAGE = Path(
    os.environ.get("STRIX_RUN_STORAGE", "/home/strix/runs")
).resolve()

# Default per-scan caps. Overridable per request via the
# `max_cost_usd` / `max_input_tokens` fields on `run_scan`.
DEFAULT_MAX_COST_USD = float(
    os.environ.get("STRIX_DEFAULT_MAX_COST_USD", "2.50")
)
DEFAULT_MAX_INPUT_TOKENS = int(
    os.environ.get("STRIX_DEFAULT_MAX_INPUT_TOKENS", "1500000")
)


# Exit codes per docs/wrapper-integration.md §1.
EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_ARGPARSE = 2
EXIT_BUDGET_EXCEEDED = 3


@app.task(bind=True, name="run_scan")
def run_scan(
    self,
    target: str,
    scan_mode: str = "standard",
    *,
    tenant_id: str = "default",
    max_cost_usd: float | None = None,
    max_input_tokens: int | None = None,
    login_creds: list[dict[str, str]] | None = None,
    extra_args: list[str] | None = None,
) -> dict:
    """Run one strix scan.

    Returns a manifest describing the run:

        {
          "scan_id":     "...",
          "tenant_id":   "...",
          "target":      "...",
          "scan_mode":   "...",
          "exit_code":   0,
          "status":      "completed" | "budget_capped" | "error",
          "duration_s":  123.4,
          "run_dir":     "/home/strix/runs/<tenant>/<scan_id>",
          "artefacts":   {"vulnerabilities.json": "...", ...},
          "summary":     <parsed run_summary.json> | None,
          "error":       str | None,
        }
    """
    scan_id = self.request.id or str(uuid.uuid4())
    run_dir = RUN_STORAGE / tenant_id / scan_id
    run_dir.mkdir(parents=True, exist_ok=True)

    max_cost_usd = (
        max_cost_usd if max_cost_usd is not None else DEFAULT_MAX_COST_USD
    )
    max_input_tokens = (
        max_input_tokens
        if max_input_tokens is not None
        else DEFAULT_MAX_INPUT_TOKENS
    )

    cmd = [
        "strix",
        "-n",                                # non-interactive
        "--quiet",                           # JSONL logs only
        "-t", target,
        "-m", scan_mode,
        "--max-cost", str(max_cost_usd),
        "--max-input-tokens", str(max_input_tokens),
    ]
    # PR-β / Phase 3d — tenant-supplied login credentials. Each
    # `{username, password}` becomes one `--login-creds 'u:p'`
    # flag. Strix's main.py validates + assembles them into
    # STRIX_LOGIN_CREDS env for scan_auth_flow to consume.
    if login_creds:
        for entry in login_creds:
            try:
                u = (entry.get("username") or "").strip()
                p = (entry.get("password") or "").strip()
            except AttributeError:
                continue
            if u and p:
                cmd.extend(["--login-creds", f"{u}:{p}"])
    cmd.extend(extra_args or [])

    # Tenant scoping happens via env vars + cwd. The wrapper layer
    # is responsible for choosing what to pass:
    #   * LLM_API_KEY scoped to the tenant's account
    #   * STRIX_THREAT_INTEL_CACHE → shared RO mount
    #   * cwd → per-scan run_dir (because strix writes to
    #     cwd/strix_runs/<run_id>/)
    env = os.environ.copy()
    # Per-tenant LLM key would be injected here in a real wrapper:
    #   env["LLM_API_KEY"] = tenant_secrets.get_llm_key(tenant_id)

    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(run_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=60 * 35,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start
        return _error_manifest(
            scan_id, tenant_id, target, scan_mode, run_dir,
            duration, error=f"timeout after {duration:.0f}s: {e}",
            exit_code=-1,
        )
    duration = time.time() - start

    # Strix writes to <cwd>/strix_runs/<auto-named-run>/. The
    # subdir name is auto-generated; pick it up by scanning.
    inner = run_dir / "strix_runs"
    inner_runs = sorted(inner.glob("*")) if inner.exists() else []
    canonical_run = inner_runs[-1] if inner_runs else run_dir

    status = _classify_exit(proc.returncode)
    artefacts = _index_artefacts(canonical_run)
    summary = _read_json_safe(canonical_run / "run_summary.json")

    return {
        "scan_id":      scan_id,
        "tenant_id":    tenant_id,
        "target":       target,
        "scan_mode":    scan_mode,
        "exit_code":    proc.returncode,
        "status":       status,
        "duration_s":   round(duration, 2),
        "run_dir":      str(canonical_run),
        "artefacts":    artefacts,
        "summary":      summary,
        "stderr_tail":  (proc.stderr or "")[-2000:] if proc.stderr else None,
        # When strix detects a config problem (missing docker, bad
        # LLM key, etc.) it prints the banner to stdout, not stderr.
        # Capture both for diagnosis.
        "stdout_tail":  (proc.stdout or "")[-2000:] if proc.stdout else None,
        "error":        None if status != "error" else
                        _combined_error(proc.stdout, proc.stderr),
    }


def _combined_error(stdout: str | None, stderr: str | None) -> str:
    """Build a useful error message from whichever stream had content.
    strix's startup-config errors go to stdout; runtime exceptions
    typically to stderr. Either alone can be empty."""
    parts = []
    if stderr:
        parts.append(f"stderr: {stderr[-400:].strip()}")
    if stdout:
        parts.append(f"stdout: {stdout[-400:].strip()}")
    return " | ".join(parts) or "unknown error"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_exit(code: int) -> str:
    if code == EXIT_OK:
        return "completed"
    if code == EXIT_BUDGET_EXCEEDED:
        return "budget_capped"
    return "error"


def _index_artefacts(run_dir: Path) -> dict[str, str]:
    """Build a flat index of the structured artefacts the wrapper
    will want to ingest. Other files (per-finding markdown, logs,
    etc.) are left on disk and accessible via the run_dir path."""
    if not run_dir.is_dir():
        return {}
    interesting = [
        "vulnerabilities.json",
        "vulnerabilities.csv",
        "finding_chains.json",
        "compliance_evidence.json",
        "behavioural_baselines.jsonl",
        "event_stream.jsonl",
        "surface_map.json",
        "webapp_surface_map.json",
        "run_meta.json",
        "run_summary.json",
        "checks_summary.json",
        "coverage.json",
        "penetration_test_report.md",
    ]
    out: dict[str, str] = {}
    for name in interesting:
        p = run_dir / name
        if p.exists():
            out[name] = str(p)
    # GRC exports + SARIF — glob-pattern.
    for path in run_dir.glob("grc_export_*.json"):
        out[path.name] = str(path)
    for path in run_dir.glob("*.sarif"):
        out[path.name] = str(path)
    return out


def _read_json_safe(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _error_manifest(scan_id, tenant_id, target, scan_mode, run_dir,
                    duration, *, error, exit_code) -> dict:
    return {
        "scan_id":     scan_id,
        "tenant_id":   tenant_id,
        "target":      target,
        "scan_mode":   scan_mode,
        "exit_code":   exit_code,
        "status":      "error",
        "duration_s":  round(duration, 2),
        "run_dir":     str(run_dir),
        "artefacts":   {},
        "summary":     None,
        "stderr_tail": None,
        "error":       error,
    }
