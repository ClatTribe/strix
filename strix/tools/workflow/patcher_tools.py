"""Lead-facing patcher tools — Strix's `patch_propose` / `patch_verify`
pair (§4 follow-up, closes EXPLOITED → PATCHED).

Three tools matching Decepticon's patcher shape:

  * `propose_patch(finding_id, diff, commit_message, applied=False)` —
    record a candidate fix.
  * `mark_patch_applied(patch_id)` — caller wrote the diff to disk.
  * `verify_patch(patch_id, ...)` — run the original detector / probe
    again; accept the patch only if the vuln no longer fires.
  * `list_patches(status=, finding_id=)` — query registry.

Key invariant: `verify_patch` only accepts the patch when an
independent re-run of the original detection signal confirms the
vulnerability has been closed. On success the §4 pipeline finding
is advanced EXPLOITED → PATCHED automatically.

Same lazy-import pattern as the other workflow tools.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


def _registry():
    from strix.agents.patcher import get_registry  # noqa: PLC0415
    return get_registry()


@register_tool(sandbox_execution=False, mitre_techniques=[])
def propose_patch(
    finding_id: str,
    diff: str,
    commit_message: str,
    applied: bool = False,
) -> dict[str, Any]:
    """Record a candidate patch for a verified finding.

    Idempotent on `(finding_id, sha1(diff))` — re-proposing the
    same diff returns the existing record. Capped at 16KB of
    diff text so the persisted log stays small.

    Args:
      finding_id: the finding being patched. Must match the ID
        used by the tracer / §4 verification pipeline.
      diff: unified-diff text of the proposed fix. Keep it minimal
        — no unrelated formatting, no doc changes, no new
        abstractions.
      commit_message: conventional-commit-style summary
        (e.g. "fix(auth): use parameterised query in /login").
      applied: True if the diff has already been written to disk
        via Edit/git apply. The verifier uses this flag to decide
        whether re-running the detector is meaningful.

    Returns:
      `{"success": True, "patch": {...}}` with the deterministic
      patch_id (`PATCH-<sha1[:12]>`).
    """
    proposal = _registry().propose(
        finding_id=finding_id,
        diff=diff,
        commit_message=commit_message,
        applied=applied,
    )
    return {"success": True, "patch": proposal.to_dict()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def mark_patch_applied(patch_id: str) -> dict[str, Any]:
    """Flip the `applied` flag on a proposed patch — caller has
    written the diff to disk via Edit/git-apply. Pairs with
    `verify_patch` which re-runs the detector against the patched
    state.

    Returns the updated proposal or `error=not_found`.
    """
    p = _registry().mark_applied(patch_id)
    if p is None:
        return {"success": False, "error": "not_found", "patch_id": patch_id}
    return {"success": True, "patch": p.to_dict()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def verify_patch(
    patch_id: str,
    probe_result_still_fires: bool,
    probe_evidence: str = "",
) -> dict[str, Any]:
    """Mark a patch as `verified` or `regressed` based on a caller-
    supplied probe outcome.

    The patcher specialist is expected to:
      1. Apply the diff (or have set `applied=True` on propose).
      2. Re-run the original detector against the patched target
         (e.g. re-call `scan_sqli` on the same URL+param, re-run
         `semgrep` against the patched file).
      3. Pass `probe_result_still_fires=False` if the detection
         no longer fires (patch worked), `True` if it does (patch
         is a regression).

    On `still_fires=False` the §4 pipeline finding is auto-advanced
    EXPLOITED → PATCHED via the `advance_finding_to_patched`
    callback.

    Args:
      patch_id: the proposal to verify.
      probe_result_still_fires: True when the original vuln still
        fires against the patched target; False when the patch
        closed it.
      probe_evidence: optional short string describing the probe
        outcome (logged on the proposal record).

    Returns:
      `{"success": <bool>, "reason": str, "patch": {...}}`.
      `success=True` means the patch was accepted; the §4 finding
      transitioned to PATCHED.
    """
    from strix.agents.patcher import advance_finding_to_patched

    def _probe_fn() -> bool:
        return bool(probe_result_still_fires)

    ok, reason, proposal = _registry().verify(
        patch_id,
        probe_fn=_probe_fn,
        on_verified=advance_finding_to_patched,
    )

    if proposal and probe_evidence:
        # Best-effort: attach evidence even on success, so the
        # audit trail captures what made the patcher confident.
        proposal.last_failure_reason = (
            "" if ok else proposal.last_failure_reason
        )
        if not ok and probe_evidence:
            proposal.last_failure_reason = probe_evidence

    return {
        "success": ok,
        "reason": reason,
        "patch": proposal.to_dict() if proposal else None,
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def list_patches(
    status: str | None = None,
    finding_id: str | None = None,
) -> dict[str, Any]:
    """Read the patch registry.

    Args:
      status: filter by status — one of `proposed`, `applied`,
        `verified`, `regressed`.
      finding_id: filter by linked finding.

    Returns:
      `{"total": <int>, "patches": [<dict>, ...]}`.
    """
    patches = _registry().list_patches(
        status=status,  # type: ignore[arg-type]
        finding_id=finding_id,
    )
    return {
        "total": len(patches),
        "patches": [p.to_dict() for p in patches],
    }
