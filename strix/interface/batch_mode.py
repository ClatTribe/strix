"""engine-wishlist §1 — multi-target batch mode.

A wrapper org with 200 targets on daily cadence is 200 sandbox
cold-starts, 200 separate MOAK Researcher phases, 200 LLM-
context warmups per day. Every per-scan cost multiplies linearly
with target count. Batch mode lets the wrapper send N targets
in a single invocation; subsequent (deeper) optimizations
(single shared sandbox, single shared Researcher) compose on
top of this dispatcher.

## Scope of this v1

This v1 ships the **dispatch-layer minimum-viable batch mode**:

  * `--target-list <PATH>` (JSONL, one target per line) → load +
    validate.
  * Sequential dispatch across targets, calling the existing
    single-target code path for each. Per-target run directories
    nested under the batch run dir.
  * `--batch-cost-cap <USD>` enforcement between target runs —
    when the cumulative cost crosses the cap, the engine finishes
    the in-flight target and exits with `status:
    cost_cap_reached`.
  * `batch_meta.json` summary at the batch run dir with per-
    target outcomes (run dir, status, cost).
  * `target_id` + `batch_id` stamped into every per-target
    `events.jsonl` / `run_meta.json` via env-var injection.

## Deferred to follow-up

  * **Single shared sandbox** across the batch. Requires
    reaching into the StrixAgent / docker_runtime lifecycle;
    bigger change than this PR. v1 spins per-target sandboxes
    (same as today's single-target path).
  * **Single shared MOAK Researcher** invocation across the
    batch. Pairs with the §7 researcher_cache (which IS in
    this PR — `strix/interface/researcher_cache.py`); when
    that cache is populated, follow-up batch versions can read
    instead of re-running.

The wishlist itself anticipates additive shipping ("Existing
single-target CLI usage keeps working"). v1 keeps the contract;
follow-ups optimise the per-target cost further.

## File format

`targets.jsonl` — one JSON object per line:

```jsonl
{"id": "tgt_a1", "type": "repository", "value": "https://github.com/acme/payments-api", "metadata": {...}}
{"id": "tgt_b2", "type": "web_application", "value": "https://payments.acme.com", "metadata": {...}}
```

Required fields per row: `id`, `type`, `value`. Optional:
`metadata` (forwarded as `STRIX_TARGET_METADATA` per §3),
`scan_mode`, `scan_profile`, `scope_mode`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


logger = logging.getLogger(__name__)


# Hard cap on batch size — prevents accidentally feeding a 10k-
# target file. The wrapper can override per call.
_DEFAULT_MAX_TARGETS = 500


@dataclass
class BatchTarget:
    """One row from a targets.jsonl file."""

    id: str
    type: str
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    scan_mode: str | None = None
    scope_mode: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "value": self.value,
        }
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        if self.scan_mode:
            out["scan_mode"] = self.scan_mode
        if self.scope_mode:
            out["scope_mode"] = self.scope_mode
        return out


@dataclass
class BatchTargetResult:
    """Outcome of one target's run within a batch."""

    target_id: str
    run_dir: str
    status: str  # completed / failed / cost_cap_reached / skipped
    cost_usd: float = 0.0
    findings_count: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "target_id": self.target_id,
            "run_dir": self.run_dir,
            "status": self.status,
            "cost_usd": self.cost_usd,
            "findings_count": self.findings_count,
        }
        if self.error:
            out["error"] = self.error
        return out


@dataclass
class BatchManifest:
    """Parsed batch context."""

    batch_id: str
    targets: list[BatchTarget]
    cost_cap_usd: float | None = None
    output_dir: Path = field(default_factory=lambda: Path("strix_runs"))

    @property
    def batch_dir(self) -> Path:
        return self.output_dir / f"batch_{self.batch_id}"


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_target_list(
    path: str | Path,
    *,
    max_targets: int = _DEFAULT_MAX_TARGETS,
) -> list[BatchTarget]:
    """Parse a targets.jsonl file into BatchTarget dataclasses.

    Raises ValueError on malformed rows or oversized files. Blank
    lines + lines starting with `#` are skipped.
    """
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"targets.jsonl not found: {p}")

    targets: list[BatchTarget] = []
    line_no = 0
    with p.open(encoding="utf-8") as f:
        for raw in f:
            line_no += 1
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{p}:{line_no}: malformed JSON: {e}"
                ) from e
            if not isinstance(row, dict):
                raise ValueError(
                    f"{p}:{line_no}: row must be a JSON object",
                )
            for required in ("id", "type", "value"):
                if not row.get(required):
                    raise ValueError(
                        f"{p}:{line_no}: missing required field "
                        f"{required!r}",
                    )
            targets.append(BatchTarget(
                id=str(row["id"]),
                type=str(row["type"]),
                value=str(row["value"]),
                metadata=dict(row.get("metadata") or {}),
                scan_mode=row.get("scan_mode"),
                scope_mode=row.get("scope_mode"),
            ))
            if len(targets) >= max_targets:
                raise ValueError(
                    f"{p}: batch exceeds max_targets={max_targets}; "
                    "split the file or override the cap",
                )

    if not targets:
        raise ValueError(f"{p}: zero valid targets")
    return targets


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def run_batch(
    manifest: BatchManifest,
    *,
    single_target_runner: Callable[[BatchTarget, Path], BatchTargetResult],
) -> dict[str, Any]:
    """Sequential dispatch across `manifest.targets`. Returns the
    `batch_meta.json` summary dict.

    Args:
        manifest: parsed batch context.
        single_target_runner: callable that takes `(BatchTarget,
            per_target_run_dir)` and returns a BatchTargetResult.
            Real production: wraps the existing single-target CLI
            entry. Tests stub this.

    Behaviour:
      * Per-target run dir: `<batch_dir>/target_<id>/`.
      * Cost cap enforcement: if cumulative cost exceeds
        `manifest.cost_cap_usd`, remaining targets are recorded
        as `skipped` and the batch exits with overall status
        `cost_cap_reached`.
      * Per-target errors don't stop the batch — they're recorded
        and the next target runs.
    """
    manifest.batch_dir.mkdir(parents=True, exist_ok=True)
    results: list[BatchTargetResult] = []
    total_cost = 0.0
    cap_reached = False

    for target in manifest.targets:
        if cap_reached:
            results.append(BatchTargetResult(
                target_id=target.id,
                run_dir="",
                status="skipped",
                error="batch_cost_cap_reached_before_target",
            ))
            continue

        per_dir = manifest.batch_dir / f"target_{target.id}"
        try:
            result = single_target_runner(target, per_dir)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "batch: target %s raised %s",
                target.id, type(e).__name__,
            )
            result = BatchTargetResult(
                target_id=target.id,
                run_dir=str(per_dir),
                status="failed",
                error=f"{type(e).__name__}: {e}",
            )
        results.append(result)
        total_cost += result.cost_usd
        if (
            manifest.cost_cap_usd is not None
            and total_cost >= manifest.cost_cap_usd
        ):
            cap_reached = True

    # Aggregate status. If ANY target hit cost_cap_reached OR the
    # accumulator tripped, the batch status reflects it.
    statuses = {r.status for r in results}
    if cap_reached or "cost_cap_reached" in statuses:
        batch_status = "cost_cap_reached"
    elif statuses == {"completed"}:
        batch_status = "completed"
    elif "failed" in statuses or "skipped" in statuses:
        batch_status = "partial"
    else:
        batch_status = "completed"

    summary: dict[str, Any] = {
        "batch_id": manifest.batch_id,
        "status": batch_status,
        "total_targets": len(manifest.targets),
        "targets_completed": sum(
            1 for r in results if r.status == "completed"
        ),
        "targets_failed": sum(
            1 for r in results if r.status == "failed"
        ),
        "targets_skipped": sum(
            1 for r in results if r.status == "skipped"
        ),
        "cumulative_cost_usd": total_cost,
        "cost_cap_usd": manifest.cost_cap_usd,
        "results": [r.to_dict() for r in results],
    }

    # Write batch_meta.json for the wrapper to consume.
    try:
        meta_path = manifest.batch_dir / "batch_meta.json"
        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logger.warning(
            "batch: failed to write batch_meta.json: %s", e,
        )

    return summary
