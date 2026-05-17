"""Orchestrator for §5 skip-if-unchanged.

engine-wishlist.md §5. Plumbs `target_fingerprint.compute_fingerprint`
+ `find_prior_run_for_target` into the CLI entry path:

  1. Caller (CLI main) computes the current target's fingerprint.
  2. Caller looks up the prior successful run for the same target.
  3. If both exist AND digests match, this module:
     a. Creates the new run directory.
     b. Writes a minimal `run_meta.json` with
        `status: "skipped_unchanged"`, `prior_run_id`,
        `target_fingerprint`.
     c. Mirrors the prior run's `findings.jsonl` /
        `vulnerabilities.json` / `events.jsonl` references into
        the new run dir as relative-path pointers (not copies —
        wrappers shouldn't have to dedup storage).

The wrapper consumes `run_meta.json["status"] == "skipped_unchanged"`
+ `run_meta.json["prior_run_id"]` to surface "No changes since
last scan — reused finding set from <run_id>" in the UI.

## Why pointers and not copies

For 200-target orgs with a 95% skip rate, every skipped scan
that COPIES the prior findings doubles storage cost per scan.
Pointer files (`prior_artifact: "../<prior_run_id>/findings.jsonl"`)
keep storage flat. Wrappers that need a hard copy can resolve the
pointer + materialise once at ingest time.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.telemetry.target_fingerprint import TargetFingerprint


logger = logging.getLogger(__name__)


# Files the wrapper consumes per scan. When we skip we point each
# at its prior-run equivalent so the wrapper's ingest code path
# doesn't have to special-case skipped runs.
_PRIOR_ARTEFACT_FILES = (
    "events.jsonl",
    "vulnerabilities.json",
    "vulnerabilities",       # directory with vuln-NNNN.md files
    "findings.jsonl",
    "compliance_evidence.json",
    "run.signature.json",
    "assets.discovered.jsonl",
    "kg_delta.jsonl",
)


@dataclass
class SkipDecision:
    """Result of checking whether to skip the current run.

    `should_skip=True` → caller exits cleanly after writing the
    skipped run dir. `should_skip=False` → caller proceeds with a
    full scan and stamps the new fingerprint into run_meta.json
    at end (see `stamp_fingerprint_on_completion`).
    """

    should_skip: bool
    current_fingerprint: TargetFingerprint | None = None
    prior_run_dir: Path | None = None
    prior_fingerprint: TargetFingerprint | None = None
    reason: str = ""


def decide(
    target_type: str,
    target_value: str,
    *,
    runs_root: Path = Path("strix_runs"),
    explicit_prior_run_dir: Path | None = None,
    # DI hooks forwarded to compute_fingerprint
    _subprocess_run: Any = None,
    _tls_get: Any = None,
    _http_get: Any = None,
) -> SkipDecision:
    """Compute the current fingerprint, look up prior run,
    return the decision."""
    from strix.telemetry.target_fingerprint import (  # noqa: PLC0415
        compute_fingerprint,
        find_prior_run_for_target,
    )
    import subprocess  # noqa: PLC0415

    kwargs: dict[str, Any] = {}
    if _subprocess_run is not None:
        kwargs["_subprocess_run"] = _subprocess_run
    else:
        kwargs["_subprocess_run"] = subprocess.run
    if _tls_get is not None:
        kwargs["_tls_get"] = _tls_get
    if _http_get is not None:
        kwargs["_http_get"] = _http_get

    current = compute_fingerprint(
        target_type, target_value, **kwargs,
    )
    if current is None:
        return SkipDecision(
            should_skip=False,
            reason="fingerprint_unavailable",
        )

    prior = find_prior_run_for_target(
        target_value,
        runs_root=runs_root,
        explicit_prior_run_dir=explicit_prior_run_dir,
    )
    if prior is None:
        return SkipDecision(
            should_skip=False,
            current_fingerprint=current,
            reason="no_prior_run",
        )

    prior_dir, prior_fp = prior
    if prior_fp.digest != current.digest:
        return SkipDecision(
            should_skip=False,
            current_fingerprint=current,
            prior_run_dir=prior_dir,
            prior_fingerprint=prior_fp,
            reason="fingerprint_changed",
        )

    return SkipDecision(
        should_skip=True,
        current_fingerprint=current,
        prior_run_dir=prior_dir,
        prior_fingerprint=prior_fp,
        reason="fingerprint_matches_prior",
    )


def emit_skipped_run(
    *,
    run_dir: Path,
    run_id: str,
    run_name: str,
    target_value: str,
    target_type: str,
    decision: SkipDecision,
    extra_metadata: dict[str, Any] | None = None,
) -> Path:
    """Write a minimal `run_meta.json` + artefact pointers to
    `run_dir`. Returns the path to the written run_meta.json.

    Idempotent — re-running creates a fresh directory; pre-existing
    files are overwritten.
    """
    assert decision.should_skip
    assert decision.current_fingerprint is not None
    assert decision.prior_run_dir is not None
    assert decision.prior_fingerprint is not None

    run_dir.mkdir(parents=True, exist_ok=True)

    # Pointer file per consumed artefact. We resolve relative
    # paths against `run_dir.parent` so wrappers can move the
    # whole strix_runs tree without breaking the chain.
    prior_dir = decision.prior_run_dir
    try:
        prior_relative = prior_dir.relative_to(run_dir.parent)
    except ValueError:
        prior_relative = prior_dir  # absolute fallback

    prior_pointers: dict[str, str] = {}
    for name in _PRIOR_ARTEFACT_FILES:
        prior_artefact = prior_dir / name
        if prior_artefact.exists():
            prior_pointers[name] = str(prior_relative / name)

    meta: dict[str, Any] = {
        "run_id": run_id,
        "run_name": run_name,
        "start_time": _now_iso(),
        "end_time": _now_iso(),
        "status": "skipped_unchanged",
        "skip_reason": decision.reason,
        "targets": [
            {"original": target_value, "type": target_type},
        ],
        "target_fingerprint": decision.current_fingerprint.to_dict(),
        "prior_run_id": prior_dir.name,
        "prior_run_dir": str(prior_relative),
        "prior_artifacts": prior_pointers,
    }
    if extra_metadata:
        # Caller-supplied additions (model_name, scope_mode, etc.)
        # are merged but never override the load-bearing keys above.
        for k, v in extra_metadata.items():
            meta.setdefault(k, v)

    meta_path = run_dir / "run_meta.json"
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    # Single-line marker file the wrapper's existence-check can
    # short-circuit on without parsing JSON.
    (run_dir / "SKIPPED_UNCHANGED").write_text(
        decision.current_fingerprint.digest, encoding="utf-8",
    )

    logger.info(
        "skip-if-unchanged: skipped run %s (target=%s); prior_run=%s",
        run_name, target_value, prior_dir.name,
    )
    return meta_path


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
