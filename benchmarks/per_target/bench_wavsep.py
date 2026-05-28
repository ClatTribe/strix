"""iter-Q5.34 — WAVSEP bench harness (L1-DAST headline).

The neutral DAST benchmark called out in CLAUDE.md §6.1: pairs with
`bench_owasp_benchmark.py` (the SAST headline) so strix's L1 layer has
a published competitor comparison for both detection technologies.

WAVSEP (Web Application Vulnerability Scanner Evaluation Project) is
a deliberately-vulnerable Java webapp covering SQL injection, reflected
XSS, LFI / path traversal, open redirect, and other classes. Each test
case is a JSP page with a deterministic URL the harness can match
against findings.

Comparators (Shay Chen's published WAVSEP scorecard — sectoolmarket.com):

    Acunetix:         87% Youden
    Netsparker:       87% Youden
    Burp Active Scan: 78% Youden
    HP WebInspect:    76% Youden
    IBM AppScan:      69% Youden
    ZAP:              56% Youden

Usage:

    # Run end-to-end (boots the fixture, runs strix, scores)
    python -m benchmarks.per_target.bench_wavsep

    # Quick mode
    python -m benchmarks.per_target.bench_wavsep --scan-mode quick

    # Score an existing run without re-running strix
    python -m benchmarks.per_target.bench_wavsep --no-strix \\
        --existing-findings strix_runs/.../vulnerabilities.json

Environment:

    STRIX_LLM, LLM_API_KEY     — required when strix is invoked
    WAVSEP_FIXTURE_URL         — target URL (default:
                                 http://host.docker.internal:8098/)
    WAVSEP_EXPECTED_CSV        — path to expected-cases.csv override
    WAVSEP_IMAGE               — override the docker image (see
                                 fixture's docker-compose.yml)
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

from benchmarks.per_target.wavsep_scoring import (
    findings_to_flags,
    load_expected_cases,
    render_report,
    score,
)


_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "web" / "wavsep"
_DEFAULT_TARGET_URL = os.environ.get(
    "WAVSEP_FIXTURE_URL",
    # Sandbox tools reach the host fixture via host.docker.internal.
    "http://host.docker.internal:8098/wavsep/",
)
_DEFAULT_EXPECTED_CSV = os.environ.get(
    "WAVSEP_EXPECTED_CSV",
    str(_FIXTURE_DIR / "expected-cases.csv"),
)
_BASELINE_DIR = Path(__file__).parent / "baseline"
_BASELINE_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Docker compose wrapper for the WAVSEP fixture
# ---------------------------------------------------------------------------


def _compose_up() -> None:
    """Bring up the WAVSEP docker-compose stack. First pull is fast
    (small image); subsequent runs reuse the cached layer."""
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
    compose_file = _FIXTURE_DIR / "docker-compose.yml"
    if not compose_file.is_file():
        return
    print(f"[bench] docker compose down -f {compose_file}")
    subprocess.run(  # noqa: S603
        ["docker", "compose", "-f", str(compose_file), "down"],
        check=False,
    )


# ---------------------------------------------------------------------------
# Strix invocation
# ---------------------------------------------------------------------------


def _run_strix(
    *, target_url: str, scan_mode: str, run_dir: Path,
    extra_args: list[str],
) -> tuple[int, float]:
    """Invoke the strix CLI against the WAVSEP fixture.

    Returns (exit_code, wall_seconds). Findings land in
    `<run_dir>/strix_runs/<run_id>/vulnerabilities.json`.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "STRIX_RUN_DIR": str(run_dir)}
    # iter-Q5.30 — same sandbox-init speed-up that bench_owasp uses.
    env.setdefault("STRIX_SKIP_CACHE_INIT", "1")
    target_arg = f"web_application:{target_url}"
    cmd = [
        "strix", "-n",
        "-t", target_arg,
        "-m", scan_mode,
        "--no-preflight",
        *extra_args,
    ]
    print(f"[bench] {' '.join(cmd)}")
    start = time.monotonic()
    proc = subprocess.run(  # noqa: S603
        cmd, cwd=run_dir, env=env, check=False,
    )
    wall = time.monotonic() - start
    return (proc.returncode, wall)


def _load_findings(run_dir: Path) -> list[dict]:
    """Read vulnerabilities.json from the latest strix_runs subdir.

    Mirrors `bench_owasp_benchmark._load_findings` — same JSON shape
    handling (`findings` key first, `vulnerability_reports` fallback).
    """
    strix_runs = run_dir / "strix_runs"
    if strix_runs.is_dir():
        candidates = sorted(
            (p for p in strix_runs.iterdir() if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for candidate in candidates:
            vp = candidate / "vulnerabilities.json"
            if vp.is_file():
                p = vp
                break
        else:
            p = run_dir / "vulnerabilities.json"
    else:
        p = run_dir / "vulnerabilities.json"
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return list(
            data.get("findings")
            or data.get("vulnerability_reports")
            or [],
        )
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
            f"WAVSEP base URL (default: {_DEFAULT_TARGET_URL}). "
            f"Sandbox sees host.docker.internal; host sees localhost."
        ),
    )
    parser.add_argument(
        "--expected-csv", default=_DEFAULT_EXPECTED_CSV,
        help=(
            "Path to expected-cases.csv. Default ships a starter set "
            "(~50 cases across sqli/xss/pathtraver/redirect); expand by "
            "appending rows for finer-grained scoring."
        ),
    )
    parser.add_argument(
        "--output",
        help=(
            "Output JSON path (default: "
            "benchmarks/per_target/baseline/wavsep_bench_<timestamp>.json)"
        ),
    )
    parser.add_argument(
        "--no-compose", action="store_true",
        help="Skip docker-compose up/down (assume fixture already running)",
    )
    parser.add_argument(
        "--no-strix", action="store_true",
        help=(
            "Skip the strix invocation; score `--existing-findings` "
            "instead. Useful for re-scoring a prior run."
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
            f"[bench] FAIL: expected-cases CSV not found: {expected_csv}",
            file=sys.stderr,
        )
        return 2
    expectations = load_expected_cases(str(expected_csv))
    print(
        f"[bench] loaded {len(expectations)} test-case expectations "
        f"from {expected_csv}",
    )

    findings: list[dict] = []
    wall = 0.0
    exit_code = 0
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    if args.no_strix:
        if not args.existing_findings:
            print(
                "[bench] FAIL: --no-strix requires --existing-findings",
                file=sys.stderr,
            )
            return 2
        ef = Path(args.existing_findings)
        if not ef.is_file():
            print(
                f"[bench] FAIL: existing findings not found: {ef}",
                file=sys.stderr,
            )
            return 2
        try:
            data = json.loads(ef.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(
                f"[bench] FAIL: existing findings JSON decode error: {exc}",
                file=sys.stderr,
            )
            return 2
        if isinstance(data, dict):
            findings = list(
                data.get("findings")
                or data.get("vulnerability_reports")
                or [],
            )
        elif isinstance(data, list):
            findings = data
        else:
            findings = []
        print(f"[bench] loaded {len(findings)} pre-existing findings")
    else:
        run_dir = _BASELINE_DIR / f"wavsep_bench_run_{timestamp}"
        try:
            if not args.no_compose:
                try:
                    _compose_up()
                except subprocess.CalledProcessError as exc:
                    print(
                        f"[bench] FAIL: docker compose up failed: {exc}",
                        file=sys.stderr,
                    )
                    return 2
            try:
                exit_code, wall = _run_strix(
                    target_url=args.target_url,
                    scan_mode=args.scan_mode,
                    run_dir=run_dir,
                    extra_args=args.strix_arg,
                )
                findings = _load_findings(run_dir)
            except FileNotFoundError as exc:
                print(f"[bench] FAIL: strix not on PATH: {exc}", file=sys.stderr)
                return 2
        finally:
            if not args.no_compose:
                _compose_down()

    # Score.
    expected_paths = [e.url_path for e in expectations]
    flags = findings_to_flags(findings, expected_paths)
    print(
        f"[bench] strix emitted {len(findings)} findings; "
        f"{len(flags)} mapped to WAVSEP test cases",
    )
    scorecard = score(expectations, flags)

    extra_metadata: dict[str, Any] = {
        "strix_exit_code": exit_code,
        "scan_mode": args.scan_mode,
        "target_url": args.target_url,
        "expectations_total": len(expectations),
        "strix_findings_total": len(findings),
        "wavsep_flags_matched": len(flags),
    }

    out_path = (
        Path(args.output)
        if args.output
        else _BASELINE_DIR / f"wavsep_bench_{timestamp}.json"
    )
    out_payload = {
        "schema_version": 1,
        "timestamp": timestamp,
        "scorecard": scorecard.to_dict(),
        "metadata": extra_metadata,
    }
    out_path.write_text(json.dumps(out_payload, indent=2), encoding="utf-8")
    md_path = out_path.with_suffix(".md")
    md_path.write_text(
        render_report(
            scorecard,
            run_id=timestamp,
            wall_seconds=wall if wall else None,
            extra_metadata=extra_metadata,
        ),
        encoding="utf-8",
    )
    print(f"[bench] wrote {out_path}")
    print(f"[bench] wrote {md_path}")
    print(render_report(
        scorecard, run_id=timestamp,
        wall_seconds=wall if wall else None,
        extra_metadata=extra_metadata,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
