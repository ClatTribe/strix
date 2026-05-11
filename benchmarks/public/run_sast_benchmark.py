"""Public-SAST benchmark runner.

Invokes `scan_sast()` directly (no agent, no LLM) against a fixture's
target directory and scores findings against the fixture's
`expected.yaml`.

Same pattern as run_sca_benchmark.py — thin, deterministic,
comparable to Snyk Code / Semgrep / CodeQL direct-CLI invocations.

Usage:
    python benchmarks/public/run_sast_benchmark.py <fixture-dir> \
        [--output result.json]

Pre-condition: Semgrep must be installed. Without it,
`tool_metadata.engine_available=False` and 0 findings — the
runner records that as a FLOOR run rather than crashing.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import time
from pathlib import Path
from typing import Any


def _require_yaml():
    try:
        import yaml
        return yaml
    except ImportError:
        print("error: pyyaml not installed. run: pip install pyyaml",
              file=sys.stderr)
        sys.exit(2)


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_expected(fixture_dir: Path) -> dict[str, Any]:
    yaml = _require_yaml()
    manifest = fixture_dir / "expected.yaml"
    if not manifest.exists():
        raise FileNotFoundError(f"missing {manifest}")
    with manifest.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _engine_state(result: dict[str, Any]) -> dict[str, Any]:
    """Capture the SAST engine state so FLOOR vs CEILING is unambiguous
    in each captured baseline JSON."""
    tm = result.get("tool_metadata", {}) or {}
    return {
        "engine": tm.get("engine"),
        "engine_available": tm.get("engine_available", False),
        "files_scanned": tm.get("files_scanned"),
        "diff_aware": tm.get("diff_aware",
                             tm.get("diff_scope", {}).get("applied", False)),
        "config_paths": tm.get("config_paths", []),
        "rules_run": tm.get("rules_run"),
        "calibration": tm.get("calibration", {}),
    }


def _endpoint_to_file(endpoint: str | None) -> tuple[str, int | None]:
    """SAST findings carry `endpoint: '/abs/path/file.js:42'`. Extract
    the (relative_file, line) tuple. We strip everything up to a
    fixture-clone marker so the matcher works for any clone path."""
    if not endpoint:
        return "", None
    # Strip line suffix.
    if ":" in endpoint:
        # Last colon is the line; the rest is the path.
        path, _, maybe_line = endpoint.rpartition(":")
        try:
            line: int | None = int(maybe_line)
        except ValueError:
            path = endpoint
            line = None
    else:
        path = endpoint
        line = None
    # Strip absolute prefix down to the first useful path marker. We
    # try the common roots in order.
    for marker in ("nodegoat/src/", "/fixtures/", "/src/"):
        if marker in path:
            path = path.split(marker, 1)[1]
            break
    return path, line


def _score_against_expected(
    findings: list[dict[str, Any]],
    expected_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Match on (category, file). Line number is informational only —
    the same logical bug can flow through multiple Semgrep rules at
    slightly different lines (eval-with-user-input fires at the eval
    call site, code-string-concat fires at the assignment); we don't
    want to double-penalise scoring for that."""
    matched: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []
    must_find_matched = 0
    must_find_total = 0

    # Precompute (category, file_basename) → list of findings.
    finding_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for f in findings:
        cat = f.get("category", "")
        path, _line = _endpoint_to_file(f.get("endpoint"))
        finding_index.setdefault((cat, path), []).append(f)

    for exp in expected_findings:
        exp_cat = exp.get("category", "")
        exp_file = exp.get("file", "")
        candidates = finding_index.get((exp_cat, exp_file), [])
        title_match = bool(candidates)
        must_find = exp.get("must_find", True)
        if must_find:
            must_find_total += 1
        entry = {
            "id": exp["id"],
            "must_find": must_find,
            "expected_category": exp_cat,
            "expected_file": exp_file,
            "matched_finding_count": len(candidates),
        }
        if title_match:
            matched.append(entry)
            if must_find:
                must_find_matched += 1
        else:
            missed.append(entry)

    total = len(expected_findings)
    recall_all = (len(matched) / total) if total else 0.0
    recall_must_find = (
        (must_find_matched / must_find_total) if must_find_total else 0.0
    )

    return {
        "expected_total": total,
        "must_find_total": must_find_total,
        "matched": matched,
        "missed": missed,
        "must_find_matched": must_find_matched,
        "must_find_missed": must_find_total - must_find_matched,
        "recall_all": round(recall_all, 3),
        "recall_must_find": round(recall_must_find, 3),
    }


def _raw_counts(result: dict[str, Any]) -> dict[str, Any]:
    findings = result.get("findings", []) or []
    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for f in findings:
        by_cat[f.get("category", "unknown")] = (
            by_cat.get(f.get("category", "unknown"), 0) + 1
        )
        by_sev[f.get("severity", "unknown")] = (
            by_sev.get(f.get("severity", "unknown"), 0) + 1
        )
        path, _ = _endpoint_to_file(f.get("endpoint"))
        if path:
            by_file[path] = by_file.get(path, 0) + 1
    return {
        "total_findings": len(findings),
        "by_category": by_cat,
        "by_severity": by_sev,
        "by_file": dict(sorted(by_file.items(),
                               key=lambda kv: (-kv[1], kv[0]))),
    }


def run_fixture(fixture_dir: Path, output: Path | None) -> dict[str, Any]:
    manifest = _parse_expected(fixture_dir)
    target_rel = manifest.get("target", "src")
    target_dir = (fixture_dir / target_rel).resolve()
    if not target_dir.exists():
        raise FileNotFoundError(
            f"target dir {target_dir} not found — did you run the matching "
            f"fixture's setup.sh?"
        )

    from strix.sast.tools import scan_sast

    print(f"[runner] fixture: {fixture_dir.name}")
    print(f"[runner] target:  {target_dir}")
    start = time.time()
    result = scan_sast(repo_path=str(target_dir))
    duration = time.time() - start
    print(f"[runner] scan done in {duration:.2f}s")

    engine = _engine_state(result)
    print(f"[runner] engine:  available={engine['engine_available']} "
          f"files={engine['files_scanned']}")

    raw = _raw_counts(result)
    print(f"[runner] raw:     {raw['total_findings']} findings "
          f"({', '.join(f'{k}={v}' for k, v in raw['by_category'].items())})")

    expected_list = manifest.get("expected_findings", []) or []
    ground = _score_against_expected(
        result.get("findings", []), expected_list
    )
    print(f"[runner] recall:  must_find={ground['recall_must_find']:.1%} "
          f"({ground['must_find_matched']}/{ground['must_find_total']})")

    out = {
        "fixture": fixture_dir.name,
        "asset_class": "sast",
        "ran_at": _utc_now_iso(),
        "duration_s": round(duration, 3),
        "engine_state": engine,
        "raw_counts": raw,
        "ground_truth": ground,
        "tool_status": result.get("status"),
        "tool_error": result.get("error"),
    }

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=False)
        print(f"[runner] wrote {output}")

    return out


def main() -> int:
    p = argparse.ArgumentParser(
        prog="run_sast_benchmark",
        description="Run strix SAST against a public benchmark fixture.",
    )
    p.add_argument("fixture", type=Path,
                   help="Path to fixture dir (must contain expected.yaml)")
    p.add_argument("--output", "-o", type=Path, default=None)
    args = p.parse_args()

    fixture_dir = args.fixture.resolve()
    if not fixture_dir.is_dir():
        print(f"error: {fixture_dir} is not a directory", file=sys.stderr)
        return 2

    out = run_fixture(fixture_dir, args.output)
    if args.output is None:
        print(json.dumps(out, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
