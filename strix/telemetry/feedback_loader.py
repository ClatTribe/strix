"""Wrapper-feedback ingestion (RLHF Phase 1 / A3 from docs/rlhf-design.md).

Reads a `feedback.jsonl` file the wrapper writes and exposes a
fingerprint → verdict map the agent loop polls when emitting
findings (A4 auto-dismiss path).

`feedback.jsonl` schema (one line per labeled finding):

```json
{
  "schema_version": 1,
  "finding_fingerprint": "a1b2c3d4...",
  "verdict": "tp" | "fp" | "partial_tp" | "needs_review" | "out_of_scope",
  "fp_reason": "framework_default_blocked",     // optional
  "severity_correction": null,                   // optional
  "notes": "...",                                // optional
  "labeler": {"id": "alice@...", "role": "..."}, // optional
  "labeled_at": "2026-05-04T...",                // optional
  "scan_run_id": "run-abc123",                   // optional
  "label_id": "lbl_..."                          // optional
}
```

Discovery order
---------------

1. Explicit path passed to `load_feedback(...)` (CLI flag).
2. `<run_dir>/feedback.jsonl` (most recent — wrapper writes here).
3. `~/.strix/feedback.jsonl` (cross-run cumulative).

Latest-label-per-fingerprint wins. When a fingerprint has both
TP and FP labels in history, the auto-dismiss policy
(`is_auto_dismissable`) treats it as ambiguous and refuses to
auto-dismiss.

Composes with #118 `dismiss_finding` — `fp_reason` mirrors the
13-value closed enum. Composes with #138 active-hypotheses —
the wrapper feedback writeback is the long-loop counterpart to
the in-flight hypothesis lifecycle.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Closed-enum verdict values. Mirrors docs/rlhf-design.md.
_VALID_VERDICTS = frozenset({
    "tp", "fp", "partial_tp", "needs_review", "out_of_scope",
})

# Same 13-value FP reason set as #118 dismiss_finding.
_VALID_FP_REASONS = frozenset({
    "input_properly_encoded",
    "framework_default_blocked",
    "csrf_token_validated",
    "auth_enforced",
    "not_reflected",
    "different_origin",
    "out_of_scope",
    "false_positive_signature",
    "compensating_control",
    "intended_behavior",
    "test_fixture",
    "deprecated_path",
    "other",
})


def _validate_label(record: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate a single feedback line. Returns `(valid, reason)`.
    Best-effort — invalid records are skipped, not raised."""
    if not isinstance(record, dict):
        return False, "not a dict"
    fp = record.get("finding_fingerprint")
    if not isinstance(fp, str) or not fp.strip():
        return False, "missing finding_fingerprint"
    verdict = record.get("verdict")
    if verdict not in _VALID_VERDICTS:
        return False, f"verdict {verdict!r} not in allow-list"
    fp_reason = record.get("fp_reason")
    if fp_reason is not None and fp_reason not in _VALID_FP_REASONS:
        return False, f"fp_reason {fp_reason!r} not in allow-list"
    return True, None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read JSONL records from `path`. Tolerant — malformed lines
    silently skipped."""
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        logger.debug("feedback_loader: read failed for %s", path, exc_info=True)
    return out


def _candidate_paths(
    *,
    explicit: str | None,
    run_dir: Path | None,
) -> list[Path]:
    """Discovery order: explicit → STRIX_FEEDBACK_FROM env →
    run_dir/feedback.jsonl → ~/.strix/feedback.jsonl."""
    import os

    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit).expanduser().resolve())
    env_path = os.environ.get("STRIX_FEEDBACK_FROM")
    if env_path and env_path.strip():
        paths.append(Path(env_path.strip()).expanduser().resolve())
    if run_dir is not None:
        paths.append(run_dir / "feedback.jsonl")
    home_path = Path.home() / ".strix" / "feedback.jsonl"
    paths.append(home_path)
    # Dedup while preserving order.
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        s = str(p)
        if s not in seen:
            seen.add(s)
            out.append(p)
    return out


def load_feedback(
    *,
    explicit_path: str | None = None,
    run_dir: Path | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Load all feedback records and return a
    `fingerprint → list[label]` map (history preserved per
    fingerprint, ordered by file-of-origin then file-line-order).

    Discovery order: explicit → run_dir → home. The map is the
    UNION across discovered paths — wrapper-side cross-run feedback
    + this-run feedback both apply.

    Returns an empty dict when no feedback is found anywhere.
    """
    by_fp: dict[str, list[dict[str, Any]]] = defaultdict(list)
    invalid_count = 0
    valid_count = 0

    for path in _candidate_paths(explicit=explicit_path, run_dir=run_dir):
        records = _read_jsonl(path)
        for rec in records:
            valid, _reason = _validate_label(rec)
            if not valid:
                invalid_count += 1
                continue
            valid_count += 1
            by_fp[rec["finding_fingerprint"]].append(rec)

    if invalid_count:
        logger.debug(
            "feedback_loader: skipped %d invalid records (loaded %d)",
            invalid_count, valid_count,
        )
    return dict(by_fp)


def get_latest_verdict(
    history: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Return the latest record from a fingerprint's history.
    Latest = most recent `labeled_at` if present; falls back to
    last-in-file order. Returns None for empty history."""
    if not history:
        return None

    def _key(rec: dict[str, Any]) -> str:
        return rec.get("labeled_at") or ""

    return max(history, key=_key)


def is_auto_dismissable(
    history: list[dict[str, Any]],
    *,
    policy: str = "conservative",
) -> tuple[bool, dict[str, Any] | None]:
    """Decide whether to auto-dismiss a fingerprint based on its
    label history.

    Policies:
      * `conservative` (default): auto-dismiss when ≥1 prior FP
        label AND zero TP labels. Mixed history → don't dismiss.
      * `aggressive`: auto-dismiss when latest verdict is FP
        regardless of prior TPs. Useful when the wrapper supports
        an explicit "force-show" override.
      * `off`: never auto-dismiss.

    Returns `(should_dismiss, attribution_record)`. The
    attribution record is the FP-labeled history entry that
    drove the decision (so the auto-dismiss event can carry
    `prior_label_attribution`)."""
    if policy == "off":
        return False, None
    if not history:
        return False, None

    fp_labels = [r for r in history if r.get("verdict") == "fp"]
    tp_labels = [r for r in history if r.get("verdict") == "tp"]

    if policy == "aggressive":
        latest = get_latest_verdict(history)
        if latest and latest.get("verdict") == "fp":
            return True, latest
        return False, None

    # conservative
    if fp_labels and not tp_labels:
        return True, fp_labels[-1]
    return False, None


def env_policy() -> str:
    """Read the `STRIX_FP_AUTO_DISMISS` env var.
    Returns `conservative` / `aggressive` / `off`."""
    import os

    raw = (os.environ.get("STRIX_FP_AUTO_DISMISS") or "").strip().lower()
    if raw in ("conservative", "aggressive", "off"):
        return raw
    return "conservative"
