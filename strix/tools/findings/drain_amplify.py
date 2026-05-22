"""iter-26.5 + 26.6 — `drain_amplify_queue` Lead-facing tool.

Wraps `strix.l15.amplify_orchestrator.drain_amplify_queue_async` as a
@register_tool so the Lead Orchestrator can fire all the pending
SAST→DAST confirmations and finding-triggered probe bundles in one
call. Returns a compact summary per fired tool so the LLM can decide
whether to follow up.

This is the **dequeue side** of L1.5's amplify plan. The plan side
(pending_confirmations[] + triggered_probes[]) is populated at
finding-emission time by iter-25 hooks. Until this tool runs, those
arrays just sit on findings as plans; this tool turns plans into
actual probe invocations and stitches the results back onto the
findings.

Idempotent: each (finding_id, tool, target) tuple is fired at most
once per scan. Calling this tool repeatedly is safe (and recommended:
the Lead can call it after each finding emission cycle).
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


@register_tool(sandbox_execution=False, provenance="framework")
def drain_amplify_queue() -> dict[str, Any]:
    """Fire all queued L1.5 auto-confirmations and probe bundles.

    iter-25 attached `pending_confirmations[]` (SAST→DAST confirmation
    requests) and `triggered_probes[]` (finding-triggered probe
    bundles) to every applicable finding. This tool dequeues those
    arrays and dispatches the named tools, stitching results back
    onto the source findings:

      * Confirmation returns findings → source finding's
        `confirmed_by_dast=True`, severity bumped one tier.
      * Confirmation returns no findings → demoted to `info` with
        `noise=True` (so it's hidden from the default catalog).
      * Bundle step returns successfully → output summary appended to
        source finding's `bundle_results[]`.

    Idempotent: each `(finding_id, tool, target)` tuple fires at most
    once per scan (tracked in a process-local ledger). Safe to call
    repeatedly.

    Bounded: global per-scan cap of 100 invocations across all
    confirmations + bundle steps. Calls beyond the cap return
    `status=cap_exceeded` so the LLM can decide whether to clear
    older queued items.

    Returns:
        ```
        {
          success: bool, status: "ok",
          total_requests: int,
          fired: int,       # status=fired count
          skipped: int,     # status=skipped (idempotent)
          errors: int,      # status=error count
          cap_exceeded: bool,
          results: [<AmplifyResult.to_dict()>, ...],
        }
        ```
    """
    try:
        from strix.l15.amplify_orchestrator import drain_amplify_queue_async
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return {
                "success": True, "status": "partial",
                "reason": "tracer not initialised yet",
                "total_requests": 0, "fired": 0, "skipped": 0,
                "errors": 0, "cap_exceeded": False, "results": [],
            }
        findings = list(getattr(tracer, "vulnerability_reports", []) or [])

        # Run inside the existing event loop if any, otherwise spin up
        # a new one. We use the sync wrapper from the orchestrator.
        from strix.l15.amplify_orchestrator import drain_amplify_queue as _drain
        results = _drain(findings)

        fired = sum(1 for r in results if r.status == "fired")
        skipped = sum(1 for r in results if r.status == "skipped")
        errors = sum(1 for r in results if r.status == "error")
        cap_exceeded = any(r.status == "cap_exceeded" for r in results)

        return {
            "success": True,
            "status": "ok",
            "total_requests": len(results),
            "fired": fired,
            "skipped": skipped,
            "errors": errors,
            "cap_exceeded": cap_exceeded,
            "results": [r.to_dict() for r in results],
        }
    except Exception as e:  # noqa: BLE001
        logger.debug("drain_amplify_queue failed: %s", e)
        return {
            "success": False, "status": "error",
            "reason": f"{type(e).__name__}: {e}",
            "total_requests": 0, "fired": 0, "skipped": 0,
            "errors": 0, "cap_exceeded": False, "results": [],
        }
