"""iter-28.2 — Multi-fixture validation harness for L1/L2 changes.

The anti-overfit guardrail. Every L1/L2 improvement must show
measurable lift on ≥3 unrelated fixtures before merge — without this,
every iter risks Juice Shop-tuning that doesn't transfer to real
customer apps.

How it works:

  1. Run the L1-only bench against a fixed fixture set
     (`_VALIDATION_FIXTURES`) at the current `HEAD~1` commit
     (the "before" baseline).
  2. Run the same bench at `HEAD` (after the change).
  3. Compute per-fixture recall deltas.
  4. PASS only if:
       a. At least 2 fixtures show positive delta (≥+0.05 recall), AND
       b. No fixture regresses (delta < -0.05 recall).
     Otherwise FAIL with the offending fixture(s) listed.

Usage:

    # Validate the current uncommitted change vs main
    python -m benchmarks.per_target.bench_validate_change

    # Validate a specific commit vs its parent
    python -m benchmarks.per_target.bench_validate_change \\
        --before-rev v1.0.0 --after-rev main

    # Use a specific subset (still requires ≥3)
    python -m benchmarks.per_target.bench_validate_change \\
        --fixtures code/flask-vuln api/vampi web/juiceshop

    # Sandbox image override (default: strix-sandbox:local)
    python -m benchmarks.per_target.bench_validate_change \\
        --sandbox-image strix-sandbox:local

Exit codes:
    0 — change passed validation
    1 — change regressed or only helped a single fixture (overfit risk)
    2 — invocation error
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

# Fixtures the validation harness runs against. These MUST be
# stack-diverse — if all 3 are SPAs (or all 3 are container images),
# the validator becomes a SPA-overfit detector, not a real overfit
# guardrail. Current spread:
#
#   code/flask-vuln        — Python/Flask vulnerable code (SAST)
#   api/vampi              — Python/Flask API (DAST API specialists)
#   web+code/vibe-app      — React+Node SPA (DAST web + SAST code)
#   ip/vulnerable-services — raw services (network probes)
#   container/nginx-vuln   — container CVE scan (SCA path)
#   web/juiceshop          — Angular SPA (DAST web)
#
# Default validation set picks one from each major asset class.
_VALIDATION_FIXTURES_DEFAULT = [
    "code/flask-vuln",
    "api/vampi",
    "web/juiceshop",
    "container/nginx-vuln",
]

# Recall delta thresholds. Tuned for L1-only-bench precision floor.
# Bench has fixture-level noise of ~±0.02-0.03; the gates below sit
# safely above noise.
_DELTA_IMPROVEMENT_THRESHOLD = 0.05    # +5pp recall counts as "improved"
_DELTA_REGRESSION_THRESHOLD = -0.05    # -5pp recall counts as "regressed"
_MIN_FIXTURES_IMPROVED = 2             # ≥2 fixtures must improve


@dataclass
class FixtureResult:
    fixture: str
    recall: float
    found: int
    matched: int
    expected: int
    wall_seconds: float
    error: str | None = None


@dataclass
class ValidationReport:
    before_rev: str
    after_rev: str
    fixtures: list[str]
    before: dict[str, FixtureResult]
    after: dict[str, FixtureResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "before_rev": self.before_rev,
            "after_rev": self.after_rev,
            "fixtures": self.fixtures,
            "deltas": {
                f: {
                    "before_recall": self.before[f].recall,
                    "after_recall": self.after[f].recall,
                    "delta_recall": self.after[f].recall - self.before[f].recall,
                    "before_matched": f"{self.before[f].matched}/{self.before[f].expected}",
                    "after_matched": f"{self.after[f].matched}/{self.after[f].expected}",
                    "wall_delta_s": (
                        self.after[f].wall_seconds - self.before[f].wall_seconds
                    ),
                } for f in self.fixtures
                if f in self.before and f in self.after
            },
        }

    def verdict(self) -> tuple[bool, list[str]]:
        """Returns (passed, reasons). passed=True means safe to merge."""
        reasons: list[str] = []
        improved = 0
        regressed: list[str] = []
        for f in self.fixtures:
            if f not in self.before or f not in self.after:
                continue
            delta = self.after[f].recall - self.before[f].recall
            if delta >= _DELTA_IMPROVEMENT_THRESHOLD:
                improved += 1
            if delta <= _DELTA_REGRESSION_THRESHOLD:
                regressed.append(
                    f"{f}: {self.before[f].recall:.3f} → "
                    f"{self.after[f].recall:.3f} ({delta:+.3f})"
                )

        if regressed:
            reasons.append(
                f"REGRESSED on {len(regressed)} fixture(s): " + "; ".join(regressed)
            )
        if improved < _MIN_FIXTURES_IMPROVED:
            reasons.append(
                f"IMPROVED on only {improved} fixture(s); "
                f"need ≥{_MIN_FIXTURES_IMPROVED} to rule out overfit "
                f"(threshold +{_DELTA_IMPROVEMENT_THRESHOLD*100:.0f}pp)"
            )
        passed = not regressed and improved >= _MIN_FIXTURES_IMPROVED
        return passed, reasons


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------

def _git_current_rev() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()


def _git_has_uncommitted() -> bool:
    return bool(subprocess.run(
        ["git", "diff", "--quiet"],
        cwd=REPO_ROOT, capture_output=True,
    ).returncode)


def _git_stash_push(label: str) -> str | None:
    """Stash uncommitted changes (incl. untracked) under a label.
    Returns the stash ref or None if nothing to stash."""
    if not _git_has_uncommitted():
        return None
    result = subprocess.run(
        ["git", "stash", "push", "-u", "-m", label],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    return "stash@{0}" if "Saved working directory" in result.stdout else None


def _git_stash_pop(stash_ref: str | None) -> None:
    if stash_ref is None:
        return
    subprocess.run(
        ["git", "stash", "pop"],
        cwd=REPO_ROOT, capture_output=True, check=False,
    )


def _git_checkout(rev: str) -> None:
    subprocess.run(
        ["git", "checkout", rev],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )


# ---------------------------------------------------------------------------
# Bench invocation
# ---------------------------------------------------------------------------

def _run_l1_bench(
    fixtures: list[str], sandbox_image: str | None,
) -> dict[str, FixtureResult]:
    """Run bench_l1_only with --with-sandbox against the given fixtures.

    Parses the markdown summary table for per-fixture recall.
    """
    cmd = [
        sys.executable, "-m", "benchmarks.per_target.bench_l1_only",
        "--with-sandbox",
    ]
    if sandbox_image:
        cmd += ["--sandbox-image", sandbox_image]
    # The bench accepts no fixture-filter flag today — it runs the FAST
    # set unconditionally. The validator's fixture list is a subset of
    # the FAST set, so we just parse the output for the rows we care about.
    start = time.monotonic()
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True,
    )
    wall = time.monotonic() - start
    if proc.returncode != 0:
        raise RuntimeError(
            f"bench_l1_only exited {proc.returncode} after {wall:.0f}s\n"
            f"stderr (last 2000c): {proc.stderr[-2000:] if proc.stderr else ''}"
        )

    # Find the most recent baseline file written
    baseline_dir = REPO_ROOT / "benchmarks" / "per_target" / "baseline"
    md_files = sorted(
        baseline_dir.glob("l1_only_*.md"),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    if not md_files:
        raise RuntimeError("no l1_only_*.md produced by bench")
    return _parse_md(md_files[0], fixtures)


def _parse_md(md_path: Path, want_fixtures: list[str]) -> dict[str, FixtureResult]:
    """Parse the summary table from a bench_l1_only markdown file."""
    out: dict[str, FixtureResult] = {}
    text = md_path.read_text()
    # Table row shape:
    # | benchmarks/per_target/fixtures/code/flask-vuln | local_code | 0.900 | 0.474 | 9/10 | 19 | 18.2s |
    for line in text.splitlines():
        if not line.startswith("| benchmarks/per_target/fixtures/"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 7:
            continue
        fpath = cells[0].replace("benchmarks/per_target/fixtures/", "")
        if fpath not in want_fixtures:
            continue
        try:
            recall = float(cells[2])
            matched_cell = cells[4]  # e.g. "9/10"
            matched, expected = matched_cell.split("/")
            found = int(cells[5])
            wall = float(cells[6].rstrip("s"))
        except (ValueError, IndexError):
            continue
        out[fpath] = FixtureResult(
            fixture=fpath, recall=recall,
            found=found, matched=int(matched), expected=int(expected),
            wall_seconds=wall,
        )
    return out


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--before-rev", default="HEAD~1",
        help="git ref for baseline (default: HEAD~1)",
    )
    parser.add_argument(
        "--after-rev", default=None,
        help=(
            "git ref for the change (default: current working tree, "
            "including uncommitted edits)"
        ),
    )
    parser.add_argument(
        "--fixtures", nargs="+", default=None,
        help=(
            f"fixture paths under benchmarks/per_target/fixtures/ "
            f"(default: {_VALIDATION_FIXTURES_DEFAULT}). "
            f"Must be ≥3 to satisfy the anti-overfit guardrail."
        ),
    )
    parser.add_argument(
        "--sandbox-image", default="strix-sandbox:local",
        help="strix-sandbox image (default: strix-sandbox:local)",
    )
    parser.add_argument(
        "--output", help="JSON report path",
    )
    parser.add_argument(
        "--no-stash", action="store_true",
        help=(
            "skip git stash before before-rev checkout (use if you've "
            "already committed your change and just want to diff "
            "two refs cleanly)"
        ),
    )
    args = parser.parse_args()

    fixtures = args.fixtures or _VALIDATION_FIXTURES_DEFAULT
    if len(fixtures) < 3:
        print(
            f"error: --fixtures must list ≥3 fixtures "
            f"(got {len(fixtures)}); fewer can't rule out overfit",
            file=sys.stderr,
        )
        return 2

    # Resolve refs
    after_rev = args.after_rev or "WORKING_TREE"
    before_rev = args.before_rev

    print(f"[validate] before_rev={before_rev}  after_rev={after_rev}", flush=True)
    print(f"[validate] fixtures: {fixtures}", flush=True)

    # Stash any uncommitted changes so we can cleanly checkout before_rev.
    # If after_rev=WORKING_TREE, those changes ARE the after state — pop them later.
    stash_ref: str | None = None
    original_rev: str | None = None
    if not args.no_stash and after_rev == "WORKING_TREE":
        original_rev = _git_current_rev()
        if _git_has_uncommitted():
            stash_ref = _git_stash_push("bench_validate_change_autosave")
            print(f"[validate] stashed uncommitted changes ({stash_ref})", flush=True)
        else:
            print(
                "[validate] WARN: no uncommitted changes — after_rev=WORKING_TREE "
                "is identical to current HEAD; comparison will be no-op",
                file=sys.stderr,
            )

    try:
        # ===== BEFORE =====
        print(f"\n[validate] === BEFORE: checking out {before_rev} ===", flush=True)
        _git_checkout(before_rev)
        try:
            before_results = _run_l1_bench(fixtures, args.sandbox_image)
        finally:
            pass  # keep checkout for now; will switch back below

        # ===== AFTER =====
        print(f"\n[validate] === AFTER: restoring {after_rev} ===", flush=True)
        if after_rev == "WORKING_TREE":
            assert original_rev is not None
            _git_checkout(original_rev)
            if stash_ref is not None:
                _git_stash_pop(stash_ref)
                stash_ref = None  # don't double-pop in finally
        else:
            _git_checkout(after_rev)
        after_results = _run_l1_bench(fixtures, args.sandbox_image)

    finally:
        # Always restore the user's working state on exit
        if original_rev:
            _git_checkout(original_rev)
        if stash_ref:
            _git_stash_pop(stash_ref)

    # ===== Verdict =====
    report = ValidationReport(
        before_rev=before_rev,
        after_rev=after_rev,
        fixtures=fixtures,
        before=before_results,
        after=after_results,
    )

    print("\n=== validation report ===", flush=True)
    for f in fixtures:
        b = before_results.get(f)
        a = after_results.get(f)
        if b is None or a is None:
            print(f"  {f}: MISSING ({'before' if b is None else 'after'})", flush=True)
            continue
        delta = a.recall - b.recall
        marker = (
            "✓ improved" if delta >= _DELTA_IMPROVEMENT_THRESHOLD else
            "✗ regressed" if delta <= _DELTA_REGRESSION_THRESHOLD else
            "·  neutral"
        )
        print(
            f"  {f:40s}  {b.recall:.3f} → {a.recall:.3f}  "
            f"({delta:+.3f}pp)  {marker}",
            flush=True,
        )

    passed, reasons = report.verdict()
    print(f"\nverdict: {'PASS' if passed else 'FAIL'}", flush=True)
    for r in reasons:
        print(f"  - {r}", flush=True)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(
            {**report.to_dict(), "passed": passed, "reasons": reasons},
            indent=2,
        ))
        print(f"[validate] wrote {out}", flush=True)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
