"""Patcher / patch_verify — closes the §4 EXPLOITED → PATCHED gap.

The §4 verification pipeline ships SCANNED → DETECTED → VERIFYING →
VERIFIED → EXPLOITED → PATCHED stages, but no *runtime* fills
EXPLOITED → PATCHED — there was no Patcher specialist that writes
a diff and re-runs the PoC against the patched code.

Decepticon's `patch.py` shows the right shape: an explicit
`patch_propose` + `patch_verify` pair, where verify re-runs the
original PoC command and the patch is accepted only if the
success signals no longer fire.

This module is strix's equivalent. It deliberately stays *thinner*
than Decepticon's:

  * No sandbox-PoC-runner integration in this MVP — that's a
    bigger lift and most strix-detected findings have deterministic
    Python re-runs (scan_sqli, scan_xss) that don't need a full
    PoC sandbox.
  * Verification is via a caller-provided callable: the patcher
    proposes the fix and records it; the caller (whose code knows
    how to re-run the original detector) invokes `verify_patch`
    with a probe function.
  * On success, the patch state flips to `verified` AND the §4
    pipeline is advanced VERIFIED → EXPLOITED → PATCHED so the
    canonical finding state stays consistent.

## State machine

```
proposed → verified   (verify_patch saw no regression)
proposed → regressed  (verify_patch saw the PoC still fire)
proposed → applied    (caller wrote the diff to disk; intermediate)
```

`verified` is terminal in the happy path. `regressed` is recoverable
— a new proposal supersedes it.

## Persistence

`<run_dir>/patches.jsonl` append-only. Same shape as
`objectives.jsonl` / `verification.jsonl` / `events.jsonl`.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_PATCHER_DISABLED` | unset | Kill switch — propose/verify no-op |
| `STRIX_PATCHER_PERSIST` | "1" | Set to "0" to skip jsonl append |
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal


logger = logging.getLogger(__name__)


PatchStatus = Literal["proposed", "applied", "verified", "regressed"]


_VALID_STATUS_TRANSITIONS: dict[PatchStatus, frozenset[PatchStatus]] = {
    "proposed": frozenset({"applied", "verified", "regressed"}),
    "applied":  frozenset({"verified", "regressed"}),
    # `verified` and `regressed` are terminal except via a NEW
    # proposal (different diff hash) — we don't transition between
    # them on the same patch record.
    "verified": frozenset(),
    "regressed": frozenset(),
}


@dataclass
class PatchProposal:
    """One proposed fix for one finding."""
    patch_id: str            # `PATCH-<sha1[:12]>` — dedup-friendly
    finding_id: str
    diff: str
    commit_message: str
    diff_hash: str           # hex digest of `diff` for dedup
    applied: bool = False
    status: PatchStatus = "proposed"
    created_at: float = field(default_factory=time.time)
    verified_at: float | None = None
    last_failure_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PatchRegistry:
    """Process-global singleton tracking all patch proposals.

    `verify_patch` accepts a caller-provided `probe_fn() → bool`
    that returns True when the original vulnerability still fires
    against the (now-patched) target. The registry doesn't know
    how to run probes — that's a domain-specific concern (re-run
    scan_sqli, re-run semgrep, etc.) — so the caller is responsible
    for supplying the right probe function for the finding category."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._patches: dict[str, PatchProposal] = {}

    def propose(
        self,
        *,
        finding_id: str,
        diff: str,
        commit_message: str,
        applied: bool = False,
    ) -> PatchProposal:
        """Record a new patch proposal. Idempotent on `(finding_id,
        diff_hash)` — re-proposing the same diff returns the
        existing record.

        Args:
          finding_id: the finding being patched. Should match the
            id used by `tracer.add_vulnerability_report` /
            `verification_pipeline.register`.
          diff: unified-diff text of the proposed fix. Capped at
            16KB to keep the jsonl small.
          commit_message: conventional-commit-style summary.
          applied: True when the diff has already been written to
            disk (caller used Edit / git apply).
        """
        diff_hash = hashlib.sha1(
            diff.encode("utf-8", errors="replace"),
            usedforsecurity=False,
        ).hexdigest()[:12]
        patch_id = f"PATCH-{diff_hash}"

        with self._lock:
            existing = self._patches.get(patch_id)
            if existing is not None:
                # Idempotent: same diff already proposed.
                # Bump `applied` if caller now says it's on disk.
                if applied and not existing.applied:
                    existing.applied = True
                return existing

            proposal = PatchProposal(
                patch_id=patch_id,
                finding_id=finding_id,
                diff=diff[:16384],
                commit_message=commit_message,
                diff_hash=diff_hash,
                applied=bool(applied),
            )
            self._patches[patch_id] = proposal
        _persist_event("proposed", proposal)
        return proposal

    def mark_applied(self, patch_id: str) -> PatchProposal | None:
        """Flip the `applied` flag — caller has written the diff to
        disk. Returns the proposal or None when unknown."""
        with self._lock:
            p = self._patches.get(patch_id)
            if p is None:
                return None
            if p.status != "proposed":
                return p  # already past `proposed`, idempotent
            p.applied = True
        _persist_event("applied", p)
        return p

    def verify(
        self,
        patch_id: str,
        *,
        probe_fn: Callable[[], bool],
        on_verified: Callable[[PatchProposal], None] | None = None,
    ) -> tuple[bool, str, PatchProposal | None]:
        """Run the caller-supplied probe; if it returns False (PoC
        no longer fires) the patch is `verified`. If True (PoC
        still fires) it's `regressed`.

        Returns `(success, reason, proposal)` — `success=True` means
        the patch held; the proposal is in `verified` state and the
        §4 pipeline advancement is triggered via `on_verified` (if
        supplied).

        Args:
          patch_id: the proposal to verify.
          probe_fn: zero-arg callable. Must return True when the
            ORIGINAL vulnerability still fires against the patched
            target. The patcher calls this AFTER the diff is on disk.
          on_verified: optional callback fired only when the patch
            is accepted. Used by tool wrappers to chain into §4
            pipeline advancement (EXPLOITED → PATCHED).
        """
        with self._lock:
            p = self._patches.get(patch_id)
            if p is None:
                return False, "patch not found", None
            if p.status in ("verified", "regressed"):
                return p.status == "verified", f"already {p.status}", p
            allowed = _VALID_STATUS_TRANSITIONS.get(p.status, frozenset())
            if "verified" not in allowed and "regressed" not in allowed:
                return False, (
                    f"cannot verify from status {p.status}"
                ), p

        try:
            still_fires = bool(probe_fn())
        except Exception as e:  # noqa: BLE001
            with self._lock:
                p.status = "regressed"
                p.last_failure_reason = (
                    f"probe_fn raised: {type(e).__name__}: {e}"
                )
            _persist_event("regressed", p)
            return False, p.last_failure_reason, p

        with self._lock:
            if still_fires:
                p.status = "regressed"
                p.last_failure_reason = "probe_fn reported still firing"
                _persist_event("regressed", p)
                return False, "patch did not close the vuln", p

            p.status = "verified"
            p.verified_at = time.time()
        _persist_event("verified", p)

        if on_verified is not None:
            try:
                on_verified(p)
            except Exception as e:  # noqa: BLE001
                # on_verified is a side-effect callback (typically
                # §4 pipeline advancement). Logging-only; do NOT
                # un-verify the patch.
                logger.debug("on_verified callback failed: %s", e, exc_info=True)

        return True, "verified", p

    def get(self, patch_id: str) -> PatchProposal | None:
        return self._patches.get(patch_id)

    def list_patches(
        self,
        *,
        status: PatchStatus | None = None,
        finding_id: str | None = None,
    ) -> list[PatchProposal]:
        with self._lock:
            patches = list(self._patches.values())
        if status is not None:
            patches = [p for p in patches if p.status == status]
        if finding_id is not None:
            patches = [p for p in patches if p.finding_id == finding_id]
        return sorted(patches, key=lambda p: p.created_at)

    def reset(self) -> None:
        with self._lock:
            self._patches = {}


# ---------------------------------------------------------------------------
# Singleton + helpers
# ---------------------------------------------------------------------------


_registry: PatchRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> PatchRegistry:
    global _registry  # noqa: PLW0603
    with _registry_lock:
        if _registry is None:
            _registry = PatchRegistry()
        return _registry


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_PATCHER_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _persistence_enabled() -> bool:
    raw = os.environ.get("STRIX_PATCHER_PERSIST", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def reset_for_testing() -> None:
    global _registry  # noqa: PLW0603
    with _registry_lock:
        _registry = None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _resolve_run_dir() -> Path | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None and hasattr(tracer, "get_run_dir"):
            d = tracer.get_run_dir()
            if d is not None:
                return Path(d)
    except Exception:  # noqa: BLE001
        pass
    env_dir = os.environ.get("STRIX_RUN_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return None


def _persist_event(event_kind: str, proposal: PatchProposal) -> None:
    if not _persistence_enabled():
        return
    run_dir = _resolve_run_dir()
    if run_dir is None:
        return
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / "patches.jsonl"
        record = {
            "event": event_kind,
            "ts": time.time(),
            "patch": proposal.to_dict(),
        }
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError as e:
        logger.debug("could not append patches.jsonl: %s", e)


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def get_registry_stats() -> dict[str, Any]:
    if is_disabled():
        return {"enabled": False, "patches": 0}
    patches = get_registry().list_patches()
    counts: dict[str, int] = {}
    for p in patches:
        counts[p.status] = counts.get(p.status, 0) + 1
    return {
        "enabled": True,
        "patches": len(patches),
        "status_counts": counts,
    }


# ---------------------------------------------------------------------------
# §4 pipeline integration
# ---------------------------------------------------------------------------


def advance_finding_to_patched(proposal: PatchProposal) -> None:
    """Default `on_verified` callback for `verify()` — advances the
    §4 pipeline EXPLOITED → PATCHED on the linked finding.

    Best-effort: when the finding isn't registered with the
    verification pipeline (e.g. tracer-only findings), this is a
    no-op. When it IS registered but not at EXPLOITED, the
    transition is attempted via the pipeline's normal forward
    rules — failures are logged, not raised."""
    try:
        from strix.agents.verification_pipeline import get_pipeline
        pipeline = get_pipeline()
        ok, reason, _ = pipeline.advance(
            proposal.finding_id,
            target_stage="PATCHED",
            reason=(
                f"patch {proposal.patch_id} verified "
                f"({proposal.commit_message[:80]})"
            ),
        )
        if not ok:
            logger.debug(
                "patch verified but §4 advance failed: %s", reason,
            )
    except Exception as e:  # noqa: BLE001
        logger.debug("§4 advance callback failed: %s", e, exc_info=True)
