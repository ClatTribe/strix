"""FastAPI control plane for the strix-runner example.

Three endpoints:
  * POST /scans         enqueue a scan, return scan_id
  * GET  /scans/{id}    poll status + (when complete) artefact paths
  * GET  /healthz       liveness

Auth is intentionally not modelled here — the example is
single-tenant. In a real wrapper, every endpoint enforces:
  * Tenant identity (from JWT / API key / session)
  * Per-tenant quota / concurrency cap
  * Per-tenant cost-budget allocation
  * Audit-log emission
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from celery import Celery
from celery.result import AsyncResult
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field


BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.environ.get(
    "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
)
RUN_STORAGE = Path(
    os.environ.get("STRIX_RUN_STORAGE", "/home/strix/runs")
).resolve()

celery_client = Celery("strix_runner", broker=BROKER_URL, backend=RESULT_BACKEND)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        description="URL, IP, domain, or local path. The string is passed "
                    "to strix's `-t` flag verbatim.",
        examples=["https://demo.testfire.net", "192.0.2.10",
                  "https://github.com/owner/repo.git"],
    )
    scan_mode: Literal["quick", "standard", "deep"] = Field(
        default="standard",
        description="Maps to strix's `-m`. `quick` ~5min/<$0.50, "
                    "`standard` ~15min/<$2, `deep` ~30min/<$5.",
    )
    tenant_id: str = Field(
        default="default",
        description="Tenant scope. Single-tenant example uses 'default'. "
                    "In a multi-tenant wrapper this comes from the auth "
                    "context, not the request body.",
    )
    max_cost_usd: float | None = Field(
        default=None,
        ge=0.01,
        le=100.0,
        description="Override the worker's default `--max-cost`. The "
                    "wrapper should set this per-tenant based on plan tier.",
    )
    max_input_tokens: int | None = Field(
        default=None,
        ge=10_000,
        description="Override the worker's default `--max-input-tokens`.",
    )
    login_creds: list[dict[str, str]] | None = Field(
        default=None,
        description=(
            "PR-β / Phase 3d — tenant-supplied login credentials the "
            "lead should TRY against discovered login forms. Each "
            "entry is `{\"username\": ..., \"password\": ...}`. "
            "Strix's `scan_auth_flow` tries these first before the "
            "built-in default-creds corpus. A user-supplied success "
            "captures the session but does NOT emit a finding "
            "(those creds aren't \"weak defaults\"). NEVER LOGGED. "
            "Wrapper UX should mask in the UI; transport must be "
            "TLS-only."
        ),
        examples=[[{"username": "admin", "password": "secret123"}]],
    )
    extra_args: list[str] | None = Field(
        default=None,
        description="Escape-hatch for arbitrary strix flags. Use sparingly; "
                    "prefer adding first-class fields to this model.",
    )


class ScanQueued(BaseModel):
    scan_id: str
    status: Literal["queued"]


class ScanStatus(BaseModel):
    scan_id: str
    state: str            # Celery state (PENDING / STARTED / SUCCESS / FAILURE)
    ready: bool
    result: dict | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


app = FastAPI(
    title="strix-runner (example)",
    version="0.1.0",
    summary="Minimal control plane for invoking strix as a unit of compute. "
            "See docs/wrapper-integration.md in the strix repo for the "
            "production-grade contract.",
)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.post("/scans", response_model=ScanQueued,
          status_code=status.HTTP_202_ACCEPTED)
def submit_scan(req: ScanRequest) -> ScanQueued:
    """Enqueue a scan. Returns immediately with a scan_id.

    In a real wrapper this would additionally:
      * Authenticate the tenant (JWT / API key)
      * Check per-tenant concurrency cap (reject 429 if over)
      * Allocate from the per-tenant cost budget
      * Emit an audit-log entry
    """
    async_result: AsyncResult = celery_client.send_task(
        "run_scan",
        kwargs={
            "target":           req.target,
            "scan_mode":        req.scan_mode,
            "tenant_id":        req.tenant_id,
            "max_cost_usd":     req.max_cost_usd,
            "max_input_tokens": req.max_input_tokens,
            "login_creds":      req.login_creds,
            "extra_args":       req.extra_args,
        },
    )
    return ScanQueued(scan_id=async_result.id, status="queued")


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str) -> ScanStatus:
    """Return the current state of a scan.

    Polling pattern: client polls every 5–10s until `ready=True`,
    then reads `result.artefacts` for the structured findings.

    Real wrappers replace this with:
      * SSE or WebSocket subscription to `event_stream.jsonl`
        (live updates as findings emerge)
      * Webhook fire-and-forget on completion
    """
    async_result = celery_client.AsyncResult(scan_id)
    state = async_result.state  # PENDING / STARTED / SUCCESS / FAILURE / ...
    ready = async_result.ready()
    payload: dict | None = None
    err: str | None = None
    if ready:
        try:
            payload = async_result.result if state == "SUCCESS" else None
            if state == "FAILURE":
                err = str(async_result.result)
        except Exception as e:  # noqa: BLE001 — surface to client
            err = f"failed to read result: {e}"
    return ScanStatus(
        scan_id=scan_id,
        state=state,
        ready=ready,
        result=payload,
        error=err,
    )


@app.get("/scans/{scan_id}/artefacts/{artefact_name}")
def fetch_artefact(scan_id: str, artefact_name: str) -> dict:
    """Return one artefact's contents (JSON / JSONL only).

    Whitelisted by extension because this is an example; a real
    wrapper would either:
      * Stream the file directly from S3 (signed URL), or
      * Render the wrapper's UI from the structured shape and
        never expose raw artefacts over HTTP.
    """
    result = celery_client.AsyncResult(scan_id)
    if not result.ready() or result.state != "SUCCESS":
        raise HTTPException(409, "scan not ready or failed")
    artefacts = (result.result or {}).get("artefacts") or {}
    path_str = artefacts.get(artefact_name)
    if not path_str:
        raise HTTPException(
            404, f"artefact '{artefact_name}' not in this scan's manifest"
        )
    path = Path(path_str)
    if not path.exists():
        raise HTTPException(404, f"artefact path {path} does not exist")
    # Whitelisted suffixes.
    if path.suffix not in (".json", ".jsonl"):
        raise HTTPException(
            415, f"this endpoint only serves .json / .jsonl; got {path.suffix}"
        )
    try:
        return {
            "scan_id": scan_id,
            "artefact": artefact_name,
            "path": str(path),
            # For .jsonl we return as a list of records.
            "body": _load_artefact(path),
        }
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"failed to read artefact: {e}") from e


def _load_artefact(path: Path) -> dict | list:
    import json
    if path.suffix == ".jsonl":
        with path.open("r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
