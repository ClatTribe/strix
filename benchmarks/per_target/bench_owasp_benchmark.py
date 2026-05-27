"""iter-Q1.1 — OWASP Benchmark Project v1.2 bench harness.

The neutral L1-detection benchmark per
docs/proposals/2026-05-27-benchmark-suite-strategy.md. Measures
strix's L1 layer against ~3000 BenchmarkJava test cases (each tagged
with a real_vulnerability flag + CWE). Reports per-CWE precision /
recall / F1 / Youden index alongside published competitor scores
(Veracode, Checkmarx, Fortify, SonarQube, ZAP).

Why this bench:

  * Juice Shop's binary-per-challenge scoring conflates "found the
    vuln" with "executed the specific exploit chain". OWASP
    Benchmark scores PURELY on detection — no exploit-completion
    requirement — making it the canonical L1 measurement.

  * Per-CWE ground truth + per-CWE scoring lets us attribute
    regressions to a specific detector (sqlmap, dalfox, nuclei,
    semgrep) rather than handwave "L2 got worse."

  * Has a public competitor leaderboard. Strix's number is directly
    comparable to commercial / OSS SAST + DAST tools.

Usage:

    # Run against the deployed BenchmarkJava fixture
    python -m benchmarks.per_target.bench_owasp_benchmark

    # With a specific scan mode
    python -m benchmarks.per_target.bench_owasp_benchmark --scan-mode quick

    # Custom output path
    python -m benchmarks.per_target.bench_owasp_benchmark \\
        --output /tmp/owasp_bench_run1.json

Environment:

    STRIX_LLM, LLM_API_KEY     — required (LLM provider config)
    STRIX_IMAGE                — override sandbox image
    OWASP_BENCH_EXPECTED_CSV   — path to expectedresults-1.2.csv
                                 (default: fixture's bundled subset)
    OWASP_BENCH_FIXTURE_URL    — target URL (default:
                                 http://host.docker.internal:8080)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # noqa: S404
import sys
import time
from pathlib import Path
from typing import Any

from benchmarks.per_target.owasp_benchmark_scoring import (
    BenchmarkExpectation,
    BenchmarkScorecard,
    findings_to_flags,
    load_expected_results,
    render_report,
    score,
)


_FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "web" / "owasp-benchmark"
)
_DEFAULT_TARGET_URL = os.environ.get(
    "OWASP_BENCH_FIXTURE_URL", "http://host.docker.internal:8080",
)
_DEFAULT_EXPECTED_CSV = os.environ.get(
    "OWASP_BENCH_EXPECTED_CSV",
    str(_FIXTURE_DIR / "expectedresults-1.2.csv"),
)
_BASELINE_DIR = Path(__file__).parent / "baseline"
_BASELINE_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Docker compose wrapper for the BenchmarkJava fixture
# ---------------------------------------------------------------------------


def _compose_up() -> None:
    """Bring up the BenchmarkJava docker-compose stack. Builds the
    image on first run (~10 min); subsequent runs reuse the cached
    image (~5s)."""
    compose_file = _FIXTURE_DIR / "docker-compose.yml"
    if not compose_file.is_file():
        raise FileNotFoundError(
            f"missing fixture docker-compose: {compose_file}",
        )
    print(f"[bench] docker compose up -d -f {compose_file}")
    subprocess.run(  # noqa: S603
        ["docker", "compose", "-f", str(compose_file), "up", "-d", "--wait"],
        check=True,
    )


def _compose_down() -> None:
    """Best-effort teardown — never raise."""
    compose_file = _FIXTURE_DIR / "docker-compose.yml"
    if not compose_file.is_file():
        return
    try:
        subprocess.run(  # noqa: S603
            [
                "docker", "compose", "-f", str(compose_file),
                "down", "-v", "--remove-orphans",
            ],
            check=False,
        )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Strix invocation
# ---------------------------------------------------------------------------


def _run_strix(
    *, target_url: str, scan_mode: str, run_dir: Path,
    extra_args: list[str],
) -> tuple[int, float]:
    """Spawn the strix CLI against the deployed fixture.

    Returns (exit_code, wall_seconds). Findings are read from the
    run_dir's vulnerabilities.json afterwards.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "STRIX_RUN_DIR": str(run_dir)}
    # Conservative defaults — bench takes long enough already.
    cmd = [
        sys.executable, "-m", "strix.cli", "scan",
        "--target-type", "web_application",
        "--target", target_url,
        "--scan-mode", scan_mode,
        "--run-name", run_dir.name,
        *extra_args,
    ]
    print(f"[bench] {' '.join(cmd)}")
    start = time.monotonic()
    proc = subprocess.run(  # noqa: S603
        cmd, env=env, check=False,
    )
    wall = time.monotonic() - start
    return (proc.returncode, wall)


def _load_findings(run_dir: Path) -> list[dict]:
    """Read vulnerabilities.json from the run dir. Returns the
    `vulnerability_reports` list (possibly empty)."""
    p = run_dir / "vulnerabilities.json"
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return list(data.get("vulnerability_reports") or [])
    if isinstance(data, list):
        return data
    return []


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--scan-mode", default="standard",
        choices=["quick", "standard", "deep"],
        help="strix scan mode (default: standard)",
    )
    parser.add_argument(
        "--target-url", default=_DEFAULT_TARGET_URL,
        help=(
            f"BenchmarkJava base URL (default: {_DEFAULT_TARGET_URL}). "
            f"Sandbox sees host.docker.internal; host sees localhost."
        ),
    )
    parser.add_argument(
        "--expected-csv", default=_DEFAULT_EXPECTED_CSV,
        help=(
            "Path to expectedresults-1.2.csv. The fixture ships a "
            "small subset for CI; for the full ~3000-case run, fetch "
            "from https://github.com/OWASP-Benchmark/BenchmarkJava/"
            "blob/master/expectedresults-1.2.csv"
        ),
    )
    parser.add_argument(
        "--output",
        help=(
            "Output JSON path (default: "
            "benchmarks/per_target/baseline/owasp_bench_<timestamp>.json)"
        ),
    )
    parser.add_argument(
        "--no-compose", action="store_true",
        help="Skip docker-compose up/down (assume fixture already deployed)",
    )
    parser.add_argument(
        "--no-strix", action="store_true",
        help=(
            "Skip the strix invocation; load findings from "
            "--existing-findings instead. Useful for scoring a prior run."
        ),
    )
    parser.add_argument(
        "--existing-findings",
        help=(
            "Path to a vulnerabilities.json from a prior run. Required "
            "when --no-strix is set."
        ),
    )
    parser.add_argument(
        "--strix-arg", action="append", default=[],
        help="Extra argv to pass through to the strix CLI (repeatable)",
    )
    args = parser.parse_args()

    expected_csv = Path(args.expected_csv)
    if not expected_csv.is_file():
        print(
            f"[bench] FAIL: expected-results CSV not found: {expected_csv}",
            file=sys.stderr,
        )
        print(
            "         Download from "
            "https://github.com/OWASP-Benchmark/BenchmarkJava/"
            "blob/master/expectedresults-1.2.csv",
            file=sys.stderr,
        )
        return 2

    expectations = load_expected_results(str(expected_csv))
    print(
        f"[bench] loaded {len(expectations)} test-case expectations "
        f"from {expected_csv}",
    )

    findings: list[dict] = []
    wall = 0.0
    exit_code = 0

    if args.no_strix:
        if not args.existing_findings:
            print(
                "[bench] FAIL: --no-strix requires --existing-findings",
                file=sys.stderr,
            )
            return 2
        ep = Path(args.existing_findings)
        if not ep.is_file():
            print(f"[bench] FAIL: not a file: {ep}", file=sys.stderr)
            return 2
        try:
            raw = json.loads(ep.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[bench] FAIL: invalid JSON in {ep}: {e}", file=sys.stderr)
            return 2
        if isinstance(raw, dict):
            findings = list(raw.get("vulnerability_reports") or [])
        elif isinstance(raw, list):
            findings = raw
    else:
        if not args.no_compose:
            try:
                _compose_up()
            except Exception as e:  # noqa: BLE001
                print(
                    f"[bench] FAIL: docker compose up failed: {e}",
                    file=sys.stderr,
                )
                return 1

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        run_dir = _BASELINE_DIR / f"owasp_bench_run_{timestamp}"
        try:
            exit_code, wall = _run_strix(
                target_url=args.target_url,
                scan_mode=args.scan_mode,
                run_dir=run_dir,
                extra_args=args.strix_arg,
            )
            findings = _load_findings(run_dir)
        finally:
            if not args.no_compose:
                _compose_down()

    # Score.
    flags = findings_to_flags(findings)
    scorecard = score(expectations, flags)

    # Report.
    metadata = {
        "strix_exit_code": exit_code,
        "scan_mode": args.scan_mode,
        "target_url": args.target_url,
        "expectations_total": len(expectations),
        "strix_findings_total": len(findings),
        "benchmarkjava_flags_matched": len(flags),
    }
    report_md = render_report(
        scorecard,
        run_id=time.strftime("%Y%m%d_%H%M%S"),
        wall_seconds=wall if wall else None,
        extra_metadata=metadata,
    )

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_json = (
        Path(args.output) if args.output
        else _BASELINE_DIR / f"owasp_bench_{timestamp}.json"
    )
    output_md = output_json.with_suffix(".md")
    payload = {
        "schema_version": 1,
        "timestamp": timestamp,
        "scorecard": scorecard.to_dict(),
        "metadata": metadata,
    }
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    output_md.write_text(report_md, encoding="utf-8")

    print(f"[bench] wrote {output_json}")
    print(f"[bench] wrote {output_md}")
    print()
    print(report_md)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
