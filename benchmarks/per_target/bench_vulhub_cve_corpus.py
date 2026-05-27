"""iter-Q1.3 — Vulhub CVE corpus-freshness bench harness.

Per docs/proposals/2026-05-27-benchmark-suite-strategy.md: runs
nuclei against each curated Vulhub lab, scores per-CVE detection,
reports KEV-coverage + EPSS-weighted hit rate. Intended for a
weekly cron — corpus drifts behind upstream disclosures faster than
any other bench dimension.

Usage:

    # Run the full corpus (clones vulhub repo, brings up each lab)
    python -m benchmarks.per_target.bench_vulhub_cve_corpus

    # Subset by category
    python -m benchmarks.per_target.bench_vulhub_cve_corpus \\
        --category rce

    # Score pre-recorded results
    python -m benchmarks.per_target.bench_vulhub_cve_corpus \\
        --no-docker --existing-results results.json

Requires:
    * docker + docker-compose
    * vulhub repo cloned (auto-cloned to /tmp/vulhub if missing)
    * nuclei binary on host PATH (or accessible via sandbox)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess  # noqa: S404
import sys
import time
from pathlib import Path
from typing import Any

from benchmarks.per_target.vulhub_cve_scoring import (
    CveDetectionResult,
    CuratedCve,
    load_curated_cves,
    nuclei_flagged_template,
    render_report,
    score,
)


logger = logging.getLogger(__name__)


_FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "web" / "vulhub-cve-corpus"
)
_DEFAULT_YAML = _FIXTURE_DIR / "curated_cves.yaml"
_DEFAULT_VULHUB_ROOT = os.environ.get(
    "VULHUB_ROOT", "/tmp/vulhub",
)
_BASELINE_DIR = Path(__file__).parent / "baseline"
_BASELINE_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Vulhub repo bootstrap
# ---------------------------------------------------------------------------


def _ensure_vulhub_cloned(vulhub_root: str) -> bool:
    """Clone https://github.com/vulhub/vulhub at the given path if
    not already present. Returns True if vulhub is available."""
    if Path(vulhub_root).is_dir() and any(Path(vulhub_root).iterdir()):
        return True
    try:
        print(f"[bench] cloning vulhub → {vulhub_root}")
        subprocess.run(  # noqa: S603
            ["git", "clone", "--depth", "1",
             "https://github.com/vulhub/vulhub.git", vulhub_root],
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"[bench] FAIL: vulhub clone: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Per-CVE lab lifecycle + nuclei probe
# ---------------------------------------------------------------------------


def _bring_lab_up(
    lab_dir: Path, timeout: int = 120,
) -> tuple[bool, str | None]:
    """`docker compose up -d --wait` in the lab dir. Returns
    (success, error_or_None)."""
    if not (lab_dir / "docker-compose.yml").is_file():
        return (False, f"no docker-compose.yml in {lab_dir}")
    try:
        subprocess.run(  # noqa: S603
            ["docker", "compose", "up", "-d", "--wait"],
            cwd=str(lab_dir),
            check=True, timeout=timeout,
        )
        return (True, None)
    except subprocess.TimeoutExpired:
        return (False, "compose up timed out")
    except subprocess.CalledProcessError as e:
        return (False, f"compose up failed: rc={e.returncode}")
    except OSError as e:
        return (False, f"OSError: {e}")


def _bring_lab_down(lab_dir: Path) -> None:
    """Best-effort teardown."""
    try:
        subprocess.run(  # noqa: S603
            ["docker", "compose", "down", "-v", "--remove-orphans"],
            cwd=str(lab_dir),
            check=False, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        pass


def _run_nuclei(
    *, target_url: str, template: str, timeout: int = 60,
) -> tuple[str, str]:
    """Invoke `nuclei -u <target> -t <template> -duc -silent -jsonl`.
    Returns (stdout, stderr).

    Falls back to a no-op when the nuclei binary isn't on PATH —
    the resulting empty stdout will be scored as a miss."""
    import shutil
    if shutil.which("nuclei") is None:
        return ("", "nuclei binary not on PATH")
    try:
        result = subprocess.run(  # noqa: S603
            [
                "nuclei",
                "-u", target_url,
                "-t", template,
                "-duc",       # disable update check
                "-silent",
                "-jsonl",
            ],
            check=False, capture_output=True,
            timeout=timeout, text=True,
        )
        return (result.stdout or "", result.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return ("", f"nuclei invocation: {type(e).__name__}: {e}")


def _scan_one_cve(
    cve: CuratedCve, *, vulhub_root: str,
    lab_up_timeout: int, nuclei_timeout: int,
) -> CveDetectionResult:
    """Bring up the lab, run nuclei, tear down, return the result."""
    lab_dir = Path(vulhub_root) / cve.vulhub_path
    if not lab_dir.is_dir():
        return CveDetectionResult(
            cve_id=cve.cve_id, detected=False,
            error=f"vulhub lab missing: {lab_dir}",
        )
    ok, err = _bring_lab_up(lab_dir, timeout=lab_up_timeout)
    if not ok:
        return CveDetectionResult(
            cve_id=cve.cve_id, detected=False, error=err,
        )
    try:
        target = (
            f"http://localhost:{cve.target_port}{cve.target_path}"
        )
        stdout, stderr = _run_nuclei(
            target_url=target,
            template=cve.expected_template,
            timeout=nuclei_timeout,
        )
        detected = nuclei_flagged_template(stdout, cve.expected_template)
        return CveDetectionResult(
            cve_id=cve.cve_id,
            detected=detected,
            nuclei_stdout=stdout,
            error=stderr if (not detected and stderr) else None,
        )
    finally:
        _bring_lab_down(lab_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--curated-yaml", default=str(_DEFAULT_YAML),
        help="curated_cves.yaml path",
    )
    parser.add_argument(
        "--vulhub-root", default=_DEFAULT_VULHUB_ROOT,
        help="path to vulhub repo checkout (auto-cloned if missing)",
    )
    parser.add_argument(
        "--category",
        help="filter to one category (rce / auth_bypass / sqli / ...)",
    )
    parser.add_argument(
        "--cve",
        help="run a single CVE by ID (e.g. CVE-2021-44228)",
    )
    parser.add_argument(
        "--lab-up-timeout", type=int, default=180,
        help="seconds to wait for each lab's docker compose up --wait",
    )
    parser.add_argument(
        "--nuclei-timeout", type=int, default=60,
        help="seconds per nuclei scan",
    )
    parser.add_argument("--no-docker", action="store_true")
    parser.add_argument("--existing-results")
    parser.add_argument("--output")
    args = parser.parse_args()

    yaml_path = Path(args.curated_yaml)
    if not yaml_path.is_file():
        print(
            f"[bench] FAIL: curated_cves.yaml not found at {yaml_path}",
            file=sys.stderr,
        )
        return 2

    cves = load_curated_cves(yaml_path)
    if args.category:
        cves = [c for c in cves if c.category == args.category]
    if args.cve:
        cves = [c for c in cves if c.cve_id == args.cve]
    if not cves:
        print("[bench] no CVEs matched filter — nothing to do.",
              file=sys.stderr)
        return 2

    results: list[CveDetectionResult] = []
    start = time.monotonic()

    if args.no_docker:
        if not args.existing_results:
            print(
                "[bench] FAIL: --no-docker requires --existing-results",
                file=sys.stderr,
            )
            return 2
        try:
            raw = json.loads(
                Path(args.existing_results).read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as e:
            print(f"[bench] FAIL: existing-results: {e}", file=sys.stderr)
            return 2
        for entry in raw if isinstance(raw, list) else []:
            if not isinstance(entry, dict):
                continue
            results.append(CveDetectionResult(
                cve_id=str(entry.get("cve_id", "")),
                detected=bool(entry.get("detected", False)),
                nuclei_stdout=str(entry.get("nuclei_stdout", "")),
                error=entry.get("error"),
            ))
    else:
        if not _ensure_vulhub_cloned(args.vulhub_root):
            return 1
        for cve in cves:
            print(
                f"[bench] {cve.cve_id} ({cve.category}, "
                f"epss={cve.epss}, kev={cve.kev})",
            )
            results.append(_scan_one_cve(
                cve,
                vulhub_root=args.vulhub_root,
                lab_up_timeout=args.lab_up_timeout,
                nuclei_timeout=args.nuclei_timeout,
            ))

    wall = time.monotonic() - start

    sc = score(cves, results)
    metadata = {
        "scan_count": len(cves),
        "wall_seconds": round(wall, 1),
        "category_filter": args.category or "all",
    }
    ts = time.strftime("%Y%m%d_%H%M%S")
    report_md = render_report(
        sc, run_id=ts, wall_seconds=wall,
        extra_metadata=metadata,
    )

    output_json = (
        Path(args.output) if args.output
        else _BASELINE_DIR / f"vulhub_cve_corpus_{ts}.json"
    )
    output_md = output_json.with_suffix(".md")
    payload = {
        "schema_version": 1,
        "timestamp": ts,
        "scorecard": sc.to_dict(),
        "results": [
            {
                "cve_id": r.cve_id,
                "detected": r.detected,
                "error": r.error,
                # Don't serialize raw stdout (can be huge) — only on
                # debug; keep the JSON small.
            }
            for r in results
        ],
        "metadata": metadata,
    }
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    output_md.write_text(report_md, encoding="utf-8")

    print(f"[bench] wrote {output_json}")
    print(f"[bench] wrote {output_md}")
    print()
    print(report_md)

    # Non-zero exit when KEV hit rate < 90% — the cron's pager
    # threshold.
    if sc.kev_hit_rate < 0.90 and sc.kev_total > 0:
        print(
            f"[bench] KEV hit rate {sc.kev_hit_rate:.0%} below 90% "
            f"threshold — exiting non-zero to alert cron.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
