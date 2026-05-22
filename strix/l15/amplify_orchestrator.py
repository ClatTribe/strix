"""iter-26.5 + 26.6 — amplify orchestrator (auto-fire L1.5 follow-ups).

L1.5 plans two kinds of deterministic follow-ups on every finding:

  * `pending_confirmations[]` — SAST-sink → DAST-confirm requests
    (e.g. semgrep flagged SQLi sink → fire `scan_sqli_sqlmap` with
    the extracted param name).
  * `triggered_probes[]` — finding-kind probe bundles (admin-burst,
    sqli-burst, verified-secret-burst, tech-burst).

Until iter-26 these arrays sat on findings unread. This module is the
**dequeue + execute** path that closes the loop: the lead orchestrator
calls `drain_amplify_queue()` after every emit cycle (or
periodically), and any unhandled requests get dispatched via
`execute_tool` exactly once. Results are stitched back onto the
source finding so the LLM sees the confirmed/refuted outcome on the
next pass.

Design contract:
  * Deterministic — no LLM reasoning required.
  * Recall-safe — failure in one queue item never blocks the others.
  * Idempotent — every request carries a stable hash; we never fire
    the same probe twice for the same finding.
  * Posture-aware — `posture.stealth_required(target)` re-checked at
    fire time (the L1.5 plan was made earlier and the posture cache
    may have updated since).
  * Bounded — global per-scan call budget (default 100 across all
    auto-fires) so a 60-finding noisy run doesn't blow through cost
    by firing 200 confirmations.

This module exposes a SYNC API; tools that want to drive it
asynchronously can call `drain_amplify_queue_async()`.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from typing import Any

from strix.l15.posture import rate_limit_cap, stealth_required


logger = logging.getLogger(__name__)


# Global call cap — across pending_confirmations + triggered_probes.
# Lower than the LLM-driven adaptive probe cap (10) because these
# are mostly auto-firings; we still want to bound the cost when L1
# emits a flood of findings.
_GLOBAL_AMPLIFY_CAP = 100


@dataclass(frozen=True)
class AmplifyResult:
    """One amplify-queue invocation outcome."""
    request_kind: str  # "confirmation" or "probe_bundle"
    finding_id: str
    tool: str
    target: str | None
    status: str  # "fired", "skipped", "error", "cap_exceeded"
    reason: str = ""
    output_summary: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_kind": self.request_kind,
            "finding_id": self.finding_id,
            "tool": self.tool,
            "target": self.target,
            "status": self.status,
            "reason": self.reason,
            "output_summary": self.output_summary,
        }


class _AmplifyLedger:
    """Tracks fired hashes + global call count per scan."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fired: set[tuple[str, str, str]] = set()
        self._calls = 0

    def clear(self) -> None:
        with self._lock:
            self._fired.clear()
            self._calls = 0

    def has_fired(
        self, finding_id: str, tool: str, target: str | None,
    ) -> bool:
        key = (finding_id or "", tool or "", (target or "").lower())
        with self._lock:
            return key in self._fired

    def mark_fired(
        self, finding_id: str, tool: str, target: str | None,
    ) -> None:
        key = (finding_id or "", tool or "", (target or "").lower())
        with self._lock:
            self._fired.add(key)
            self._calls += 1

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls


_ledger = _AmplifyLedger()


def clear_amplify_ledger() -> None:
    """Wipe the amplify ledger. Tests use this between cases."""
    _ledger.clear()


def amplify_calls_so_far() -> int:
    return _ledger.calls


def _summarise_tool_output(out: Any) -> dict[str, Any]:
    """Tool outputs are big dicts. Project to the fields the Lead
    needs to know about: status, total findings, key list elements.
    """
    if not isinstance(out, dict):
        return {"raw": str(out)[:200]}
    summary: dict[str, Any] = {}
    for k in ("status", "success", "total_findings", "total_found",
              "endpoints_discovered", "total_open_ports",
              "live_hosts", "dbms_detected"):
        if k in out:
            summary[k] = out[k]
    # Findings list — keep only count + per-row severity.
    findings = out.get("findings")
    if isinstance(findings, list):
        summary["findings_count"] = len(findings)
        if findings and isinstance(findings[0], dict):
            summary["findings_top_severity"] = (
                findings[0].get("severity") or "info"
            )
    return summary


async def _invoke_tool(
    tool_name: str,
    target: str | None,
    args: dict[str, Any] | None,
    stealth: bool,
    agent_state: Any | None = None,
) -> Any:
    """Dispatch the tool through the existing executor.

    `agent_state` is REQUIRED for sandbox-resident tools (almost
    every L1 specialist — scan_sqli_sqlmap, scan_xss_dalfox,
    discover_paths_feroxbuster, etc.). Without it, the executor's
    `_execute_tool_in_sandbox` will raise ValueError. The caller
    (`drain_amplify_queue`) plumbs it from the framework-injected
    `agent_state` parameter on its own signature.

    iter-26-fix correctness fix: the original implementation passed
    `agent_state=None` unconditionally, so EVERY sandbox-resident
    auto-confirmation silently errored at runtime. The mocked tests
    didn't catch it because `execute_tool` itself was the mock.
    """
    from strix.tools.executor import execute_tool
    kwargs = dict(args or {})
    if target and "target" not in kwargs and "target_url" not in kwargs:
        # Most tools accept either `target` or `target_url` — pick
        # whichever the tool's signature has.
        from strix.tools.registry import get_tool_by_name
        tool = get_tool_by_name(tool_name)
        if tool is not None:
            try:
                import inspect
                sig = inspect.signature(tool)
                if "target_url" in sig.parameters:
                    kwargs["target_url"] = target
                elif "target" in sig.parameters:
                    kwargs["target"] = target
            except (TypeError, ValueError):
                kwargs["target"] = target
    if stealth and "stealth" not in kwargs:
        # Best-effort: pass stealth flag along; tools that don't
        # accept it will ignore via **kwargs handling or error
        # cleanly (the caller catches).
        pass  # left for iter-26.8 to wire per-specialist
    return await execute_tool(tool_name, agent_state=agent_state, **kwargs)


async def _fire_confirmation(
    finding: dict[str, Any], req: dict[str, Any],
    agent_state: Any | None = None,
) -> AmplifyResult:
    tool = (req.get("tool") or "").strip()
    target = req.get("target_url") or req.get("target")
    finding_id = finding.get("id") or ""
    if not tool:
        return AmplifyResult(
            request_kind="confirmation", finding_id=finding_id,
            tool="", target=target, status="error",
            reason="tool name missing from confirmation request",
        )
    if _ledger.calls >= _GLOBAL_AMPLIFY_CAP:
        return AmplifyResult(
            request_kind="confirmation", finding_id=finding_id,
            tool=tool, target=target, status="cap_exceeded",
            reason=f"global amplify cap reached ({_GLOBAL_AMPLIFY_CAP})",
        )
    if _ledger.has_fired(finding_id, tool, target):
        return AmplifyResult(
            request_kind="confirmation", finding_id=finding_id,
            tool=tool, target=target, status="skipped",
            reason="already fired (idempotent)",
        )

    # Re-check posture at fire time
    is_stealth = stealth_required(target) if target else False
    args: dict[str, Any] = {}
    if req.get("param"):
        args["param"] = req["param"]

    try:
        out = await _invoke_tool(
            tool, target, args, is_stealth, agent_state=agent_state,
        )
        _ledger.mark_fired(finding_id, tool, target)
        summary = _summarise_tool_output(out)

        # Stitch a `confirmed_by_dast` flag onto the source finding so
        # the LLM sees the outcome on its next list_pending_findings.
        # Promotion / demotion handled here per L2-optimization §4 Gap 8:
        #   confirmed → promote one tier
        #   not confirmed but tool ran cleanly → demote to info
        confirmed = bool(summary.get("findings_count", 0))
        finding["confirmed_by_dast"] = confirmed
        finding["dast_confirmer"] = tool
        finding["dast_summary"] = summary
        if confirmed:
            _bump_severity(finding, +1)
            trace = finding.get("reasoning_trace") or []
            if isinstance(trace, str):
                trace = [trace]
            finding["reasoning_trace"] = list(trace) + [
                f"l1.5: auto-confirmed by {tool}; severity promoted"
            ]
        else:
            # Don't demote findings the LLM marked exploited; only
            # demote unverified SAST hits.
            vstat = (finding.get("verification_status") or "").lower()
            if vstat not in ("exploited", "verified"):
                finding["severity"] = "info"
                finding["noise"] = True
                trace = finding.get("reasoning_trace") or []
                if isinstance(trace, str):
                    trace = [trace]
                finding["reasoning_trace"] = list(trace) + [
                    f"l1.5: auto-confirm by {tool} returned no findings; "
                    f"demoted to info"
                ]

        return AmplifyResult(
            request_kind="confirmation", finding_id=finding_id,
            tool=tool, target=target, status="fired",
            output_summary=summary,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("auto-confirm fire failed: %s", e)
        return AmplifyResult(
            request_kind="confirmation", finding_id=finding_id,
            tool=tool, target=target, status="error",
            reason=f"{type(e).__name__}: {e}",
        )


async def _fire_bundle_step(
    finding: dict[str, Any], step: dict[str, Any],
    agent_state: Any | None = None,
) -> AmplifyResult:
    tool = (step.get("tool") or "").strip()
    args = dict(step.get("args") or {})
    target = (
        args.get("target_url")
        or args.get("target")
        or finding.get("endpoint")
        or finding.get("url")
    )
    finding_id = finding.get("id") or ""
    if not tool:
        return AmplifyResult(
            request_kind="probe_bundle", finding_id=finding_id,
            tool="", target=target, status="error",
            reason="tool name missing from bundle step",
        )
    if _ledger.calls >= _GLOBAL_AMPLIFY_CAP:
        return AmplifyResult(
            request_kind="probe_bundle", finding_id=finding_id,
            tool=tool, target=target, status="cap_exceeded",
            reason=f"global amplify cap reached ({_GLOBAL_AMPLIFY_CAP})",
        )
    if _ledger.has_fired(finding_id, tool, target):
        return AmplifyResult(
            request_kind="probe_bundle", finding_id=finding_id,
            tool=tool, target=target, status="skipped",
            reason="already fired (idempotent)",
        )

    is_stealth = bool(step.get("stealth")) or (
        stealth_required(target) if target else False
    )

    try:
        out = await _invoke_tool(
            tool, target, args, is_stealth, agent_state=agent_state,
        )
        _ledger.mark_fired(finding_id, tool, target)
        summary = _summarise_tool_output(out)
        # Stitch the result onto the source finding under bundle_results
        results = list(finding.get("bundle_results") or [])
        results.append({
            "tool": tool, "target": target,
            "summary": summary, "stealth": is_stealth,
        })
        finding["bundle_results"] = results
        return AmplifyResult(
            request_kind="probe_bundle", finding_id=finding_id,
            tool=tool, target=target, status="fired",
            output_summary=summary,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("bundle step fire failed: %s", e)
        return AmplifyResult(
            request_kind="probe_bundle", finding_id=finding_id,
            tool=tool, target=target, status="error",
            reason=f"{type(e).__name__}: {e}",
        )


# ---- Public API ------------------------------------------------------

async def drain_amplify_queue_async(
    findings: list[dict[str, Any]],
    agent_state: Any | None = None,
) -> list[AmplifyResult]:
    """Walk the findings list, fire pending_confirmations[] and
    triggered_probes[] entries that haven't fired yet, return one
    AmplifyResult per attempted invocation.

    Mutates findings in place: each fired confirmation may flip
    `confirmed_by_dast`, adjust severity, append to `reasoning_trace`.
    Bundle results land on `bundle_results[]`.

    `agent_state` is required for sandbox-resident tools (most L1
    specialists). Pass the framework-provided agent state through
    from the calling tool.
    """
    results: list[AmplifyResult] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for req in (f.get("pending_confirmations") or []):
            if not isinstance(req, dict):
                continue
            r = await _fire_confirmation(f, req, agent_state=agent_state)
            results.append(r)
            if r.status == "cap_exceeded":
                return results  # short-circuit
        for step in (f.get("triggered_probes") or []):
            if not isinstance(step, dict):
                continue
            r = await _fire_bundle_step(f, step, agent_state=agent_state)
            results.append(r)
            if r.status == "cap_exceeded":
                return results
    return results


def drain_amplify_queue(
    findings: list[dict[str, Any]],
    agent_state: Any | None = None,
) -> list[AmplifyResult]:
    """Sync wrapper for `drain_amplify_queue_async`."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Cannot use asyncio.run from inside a running loop.
            # Schedule via ensure_future + run_until_complete on a
            # fresh loop in a thread.
            import concurrent.futures

            def _run_in_thread() -> list[AmplifyResult]:
                return asyncio.run(
                    drain_amplify_queue_async(findings, agent_state),
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(_run_in_thread).result()
    except RuntimeError:
        pass
    return asyncio.run(drain_amplify_queue_async(findings, agent_state))


# ---- Severity adjustment ---------------------------------------------

_SEVERITY_TIER = ["info", "low", "medium", "high", "critical"]


def _bump_severity(finding: dict[str, Any], delta: int) -> None:
    """In-place severity adjustment by ``delta`` tiers (positive =
    promote)."""
    try:
        cur = (finding.get("severity") or "info").lower().strip()
        if cur not in _SEVERITY_TIER:
            cur = "info"
        idx = _SEVERITY_TIER.index(cur)
        new_idx = max(0, min(len(_SEVERITY_TIER) - 1, idx + delta))
        finding["severity"] = _SEVERITY_TIER[new_idx]
    except Exception as e:  # noqa: BLE001
        logger.debug("severity bump failed: %s", e)
