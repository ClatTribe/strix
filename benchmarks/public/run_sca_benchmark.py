"""Public-SCA benchmark runner.

Invokes `scan_sca_lockfiles()` directly (no agent, no LLM) against a
fixture's `src/` directory and scores the resulting findings against
the fixture's `expected.yaml`.

This is intentionally **thinner than `benchmarks/per_target/runner.py`**.
The per-target runner exists for agentic-scan benchmarks — it spawns
the full strix CLI and parses markdown findings. For SCA, that's
unnecessary noise: SCA detection is deterministic, the result shape
is structured, and we want a number directly comparable to Snyk's
`snyk test` (also a direct, non-agentic SCA call).

Usage:
    python benchmarks/public/run_sca_benchmark.py <fixture-dir> \
        [--output result.json] [--threat-intel-cache PATH]

Output JSON shape:
    {
      "fixture": "nodegoat",
      "ran_at": "2026-05-11T18:32:00Z",
      "duration_s": 1.23,
      "cache_state": {
        "cves": 1590,
        "ghsa_seeded": false,
        "popular_seeded": false,
        "ossf_malicious_seeded": false
      },
      "raw_counts": {
        "total_findings": 629,
        "by_category": {"malicious_dependency": 322, ...},
        "by_severity": {"low": 307, ...},
        "packages_scanned": 1091
      },
      "ground_truth": {
        "expected_total": 8,
        "must_find_total": 5,
        "matched": [...],   # id list
        "missed": [...],
        "must_find_matched": 0,
        "must_find_missed": 5,
        "recall_all": 0.0,
        "recall_must_find": 0.0
      },
      "heuristic": {
        "license_inventory_coverage": 0.94,
        "by_family": {"permissive": 800, ...}
      }
    }
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
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


def _cache_state() -> dict[str, Any]:
    """Inspect the threat-intel cache to record whether it's seeded.
    The benchmark score makes sense in the context of which feeds are
    populated.
    """
    from strix.threat_intel import cache as ti_cache
    try:
        meta_rows = ti_cache.fetch_feed_meta()
    except Exception:
        meta_rows = []
    meta = {m["feed_name"]: m for m in meta_rows}

    # No public counter API; introspect the feed-meta `records` columns
    # for the seeded-feed signal and the KEV list for a CVE floor.
    kev_records = _safe_count(lambda: len(ti_cache.fetch_kev_list()))

    return {
        "kev_cves_in_cache": kev_records,
        "ghsa_seeded": meta.get("ghsa", {}).get("status") == "ok",
        "popular_seeded": meta.get("popular_packages", {}).get("status") == "ok",
        "ossf_malicious_seeded": (
            meta.get("ossf_malicious", {}).get("status") in ("ok", "partial")
        ),
        "kev_seeded": meta.get("kev", {}).get("status") == "ok",
        "feed_meta": {k: {"status": v.get("status"),
                          "records": v.get("records"),
                          "last_polled": v.get("last_polled")}
                      for k, v in meta.items()},
    }


def _safe_count(fn) -> int:
    try:
        return int(fn())
    except Exception:
        return -1


def _score_against_expected(
    findings: list[dict[str, Any]],
    expected_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Category-aware scoring.

    An expected `vulnerable_dependency` only matches against actual
    `vulnerable_dependency` findings — not against
    `malicious_dependency` / `license_violation` findings for the
    same package. Without this, an empty threat-intel cache would
    score 100% just because the heuristic categories surface every
    direct dep by name.

    Match criteria (within the right category):
      * Package name from the `id` slug appears in the finding title.
        e.g. expected id `nodegoat-marked` → finding title must
        contain `marked`.
    """
    matched: list[dict[str, Any]] = []
    missed: list[dict[str, Any]] = []
    must_find_matched = 0
    must_find_total = 0

    for exp in expected_findings:
        exp_id = exp["id"]
        pkg = exp_id.split("-", 1)[1] if "-" in exp_id else exp_id
        exp_cat = exp.get("category", "")
        # Restrict the finding pool to the expected category only.
        candidates = [
            f for f in findings if f.get("category") == exp_cat
        ]
        title_match = any(
            pkg.lower() in (f.get("title") or "").lower()
            for f in candidates
        )
        must_find = exp.get("must_find", True)
        if must_find:
            must_find_total += 1
        entry = {
            "id": exp_id,
            "must_find": must_find,
            "expected_category": exp_cat,
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
    for f in findings:
        by_cat[f.get("category", "unknown")] = (
            by_cat.get(f.get("category", "unknown"), 0) + 1
        )
        by_sev[f.get("severity", "unknown")] = (
            by_sev.get(f.get("severity", "unknown"), 0) + 1
        )
    tm = result.get("tool_metadata", {}) or {}
    return {
        "total_findings": len(findings),
        "by_category": by_cat,
        "by_severity": by_sev,
        "packages_scanned": tm.get("packages_total"),
    }


def _heuristic_aggregates(result: dict[str, Any]) -> dict[str, Any]:
    tm = result.get("tool_metadata", {}) or {}
    licenses = tm.get("licenses", {}) or {}
    malicious = tm.get("malicious", {}) or {}
    return {
        "by_family": licenses.get("by_family", {}),
        "by_indicator": malicious.get("by_indicator", {}),
    }


def run_fixture(fixture_dir: Path, output: Path | None) -> dict[str, Any]:
    manifest = _parse_expected(fixture_dir)
    target_rel = manifest.get("target", "src")
    target_dir = (fixture_dir / target_rel).resolve()
    if not target_dir.exists():
        raise FileNotFoundError(
            f"target dir {target_dir} not found — did you run setup.sh?"
        )

    # Lazy import so cli help works without strix installed.
    from strix.sca.tools import scan_sca_lockfiles

    print(f"[runner] fixture: {fixture_dir.name}")
    print(f"[runner] target:  {target_dir}")
    cache_before = _cache_state()
    print(f"[runner] cache:   kev={cache_before['kev_cves_in_cache']} "
          f"ghsa={cache_before['ghsa_seeded']} "
          f"popular={cache_before['popular_seeded']} "
          f"ossf={cache_before['ossf_malicious_seeded']}")
    start = time.time()
    result = scan_sca_lockfiles(repo_path=str(target_dir))
    duration = time.time() - start
    print(f"[runner] scan done in {duration:.2f}s")

    raw = _raw_counts(result)
    print(f"[runner] raw: {raw['total_findings']} findings "
          f"({', '.join(f'{k}={v}' for k, v in raw['by_category'].items())})")

    expected_list = manifest.get("expected_findings", []) or []
    ground = _score_against_expected(result.get("findings", []), expected_list)
    print(f"[runner] recall_all={ground['recall_all']:.1%} "
          f"recall_must_find={ground['recall_must_find']:.1%} "
          f"({ground['must_find_matched']}/{ground['must_find_total']})")

    heuristic = _heuristic_aggregates(result)

    out = {
        "fixture": fixture_dir.name,
        "ran_at": _utc_now_iso(),
        "duration_s": round(duration, 3),
        "cache_state": cache_before,
        "raw_counts": raw,
        "ground_truth": ground,
        "heuristic": heuristic,
    }

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=False)
        print(f"[runner] wrote {output}")

    return out


def main() -> int:
    p = argparse.ArgumentParser(
        prog="run_sca_benchmark",
        description="Run strix SCA against a public benchmark fixture.",
    )
    p.add_argument("fixture", type=Path,
                   help="Path to fixture dir (must contain expected.yaml + src/)")
    p.add_argument("--output", "-o", type=Path, default=None,
                   help="Write result JSON here (default: stdout only)")
    p.add_argument("--threat-intel-cache", default=None,
                   help="Override STRIX_THREAT_INTEL_CACHE for this run")
    args = p.parse_args()

    if args.threat_intel_cache:
        os.environ["STRIX_THREAT_INTEL_CACHE"] = args.threat_intel_cache

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
