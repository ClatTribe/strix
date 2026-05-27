"""iter-Q1.2 — WebGoat dual-mode bench harness.

Per docs/proposals/2026-05-27-benchmark-suite-strategy.md: scores
strix against OWASP WebGoat in TWO modes against the SAME fixture:

  * **detection rate** — did strix's L1 layer emit findings for the
    must-find lessons?
  * **completion rate** — did strix's actions trip WebGoat's
    internal lesson-checker (polled at /lessonprogress.mvc)?

The delta (detection − completion) is the exact L2 chain-execution
gap: lessons L1 found but L2 didn't chain into a real exploit.

Usage:

    python -m benchmarks.per_target.bench_webgoat_dual

    # Score an existing strix run without re-running
    python -m benchmarks.per_target.bench_webgoat_dual \\
        --no-compose --no-strix \\
        --existing-findings /path/to/vulnerabilities.json \\
        --existing-progress /path/to/webgoat_progress.json
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

from benchmarks.per_target.webgoat_dual_scoring import (
    LessonExpectation,
    WEBGOAT_BENCH_LESSONS,
    render_report,
    score_dual,
)


logger = logging.getLogger(__name__)


_FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "web" / "webgoat"
)
_DEFAULT_TARGET_URL = os.environ.get(
    "WEBGOAT_BENCH_TARGET_URL", "http://localhost:8082",
)
_DEFAULT_USER = os.environ.get("WEBGOAT_BENCH_USER", "strix-bench")
_DEFAULT_PASS = os.environ.get("WEBGOAT_BENCH_PASS", "Strix-Bench-2026!")
_BASELINE_DIR = Path(__file__).parent / "baseline"
_BASELINE_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Docker compose + WebGoat user-registration
# ---------------------------------------------------------------------------


def _compose_up() -> None:
    compose_file = _FIXTURE_DIR / "docker-compose.yml"
    if not compose_file.is_file():
        raise FileNotFoundError(f"missing fixture compose: {compose_file}")
    print(f"[bench] docker compose up -d -f {compose_file}")
    subprocess.run(  # noqa: S603
        ["docker", "compose", "-f", str(compose_file), "up", "-d", "--wait"],
        check=True,
    )


def _compose_down() -> None:
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


def _register_webgoat_user(
    target_url: str, user: str, password: str, timeout: int = 30,
) -> bool:
    """Register a test user via WebGoat's registration endpoint.

    WebGoat's `/register.mvc` is a POST with form fields:
        username, password, matchingPassword, agree
    Returns True on success (200 with 'register' redirect)."""
    try:
        import urllib.parse
        import urllib.request

        body = urllib.parse.urlencode({
            "username": user,
            "password": password,
            "matchingPassword": password,
            "agree": "agree",
        }).encode("ascii")
        req = urllib.request.Request(
            f"{target_url.rstrip('/')}/register.mvc",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 400
    except Exception as e:  # noqa: BLE001
        logger.debug("WebGoat user registration failed: %s", e, exc_info=True)
        return False


def _fetch_lesson_progress(
    target_url: str, user: str, password: str, timeout: int = 30,
) -> dict[str, Any]:
    """Login as the registered user + fetch
    `/service/lessonprogress.mvc`. Returns the parsed JSON or {}
    on any failure (graceful degradation — completion rate falls
    to 0 with a documented reason)."""
    try:
        import urllib.parse
        import urllib.request
        from http.cookiejar import CookieJar

        cj = CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
        )

        # Login (form-based; CSRF-token may be required in newer
        # WebGoat releases; the bench is best-effort).
        login_body = urllib.parse.urlencode({
            "username": user,
            "password": password,
        }).encode("ascii")
        login_req = urllib.request.Request(
            f"{target_url.rstrip('/')}/login",
            data=login_body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with opener.open(login_req, timeout=timeout):
            pass

        # Fetch lesson progress.
        prog_req = urllib.request.Request(
            f"{target_url.rstrip('/')}/service/lessonprogress.mvc",
            headers={"Accept": "application/json"},
        )
        with opener.open(prog_req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body) or {}
    except Exception as e:  # noqa: BLE001
        logger.debug("lesson-progress fetch failed: %s", e, exc_info=True)
        return {}


# ---------------------------------------------------------------------------
# Strix invocation
# ---------------------------------------------------------------------------


def _run_strix(
    *, target_url: str, scan_mode: str, run_dir: Path,
    extra_args: list[str],
) -> tuple[int, float]:
    run_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "STRIX_RUN_DIR": str(run_dir)}
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
    proc = subprocess.run(env=env, check=False, args=cmd)  # noqa: S603
    return (proc.returncode, time.monotonic() - start)


def _load_findings(run_dir: Path) -> list[dict]:
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
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--scan-mode", default="standard",
        choices=["quick", "standard", "deep"],
    )
    parser.add_argument(
        "--target-url", default=_DEFAULT_TARGET_URL,
        help=f"WebGoat base URL (default: {_DEFAULT_TARGET_URL})",
    )
    parser.add_argument(
        "--webgoat-user", default=_DEFAULT_USER,
    )
    parser.add_argument(
        "--webgoat-pass", default=_DEFAULT_PASS,
    )
    parser.add_argument(
        "--output",
        help="Output JSON path (default: baseline/webgoat_dual_<ts>.json)",
    )
    parser.add_argument("--no-compose", action="store_true")
    parser.add_argument("--no-strix", action="store_true")
    parser.add_argument("--existing-findings")
    parser.add_argument(
        "--existing-progress",
        help=(
            "Path to a pre-fetched lessonprogress.mvc JSON for offline "
            "scoring. Required when --no-strix is set."
        ),
    )
    parser.add_argument(
        "--strix-arg", action="append", default=[],
    )
    args = parser.parse_args()

    findings: list[dict] = []
    progress: dict[str, Any] = {}
    wall = 0.0
    exit_code = 0

    if args.no_strix:
        if not args.existing_findings or not args.existing_progress:
            print(
                "[bench] FAIL: --no-strix requires --existing-findings "
                "AND --existing-progress",
                file=sys.stderr,
            )
            return 2
        try:
            raw = json.loads(
                Path(args.existing_findings).read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as e:
            print(f"[bench] FAIL: bad findings JSON: {e}", file=sys.stderr)
            return 2
        findings = (
            raw.get("vulnerability_reports") or []
            if isinstance(raw, dict) else (raw if isinstance(raw, list) else [])
        )
        try:
            progress = json.loads(
                Path(args.existing_progress).read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as e:
            print(f"[bench] FAIL: bad progress JSON: {e}", file=sys.stderr)
            return 2
    else:
        if not args.no_compose:
            try:
                _compose_up()
            except Exception as e:  # noqa: BLE001
                print(f"[bench] FAIL: compose: {e}", file=sys.stderr)
                return 1

        registered = _register_webgoat_user(
            args.target_url, args.webgoat_user, args.webgoat_pass,
        )
        if not registered:
            print(
                "[bench] WARN: WebGoat user registration failed — "
                "lesson-progress polling will return empty (completion "
                "rate falls to 0).",
                file=sys.stderr,
            )

        ts = time.strftime("%Y%m%d_%H%M%S")
        run_dir = _BASELINE_DIR / f"webgoat_dual_run_{ts}"
        try:
            exit_code, wall = _run_strix(
                target_url=args.target_url,
                scan_mode=args.scan_mode,
                run_dir=run_dir,
                extra_args=args.strix_arg,
            )
            findings = _load_findings(run_dir)
            # Poll WebGoat's lesson-progress AFTER strix runs — that's
            # where the completion-rate signal lives.
            progress = _fetch_lesson_progress(
                args.target_url, args.webgoat_user, args.webgoat_pass,
            )
        finally:
            if not args.no_compose:
                _compose_down()

    lessons = [
        LessonExpectation(
            lesson_id=l["lesson_id"],
            cwe=l["cwe"],
            exploit_endpoint=l["exploit_endpoint"],
        )
        for l in WEBGOAT_BENCH_LESSONS
    ]
    scorecard = score_dual(findings, progress, lessons)

    metadata = {
        "strix_exit_code": exit_code,
        "scan_mode": args.scan_mode,
        "target_url": args.target_url,
        "lessons_in_bench": len(lessons),
        "strix_findings_total": len(findings),
        "webgoat_progress_lessons_returned": (
            len(progress) if isinstance(progress, (dict, list)) else 0
        ),
    }
    ts = time.strftime("%Y%m%d_%H%M%S")
    report_md = render_report(
        scorecard, run_id=ts,
        wall_seconds=wall if wall else None,
        extra_metadata=metadata,
    )
    output_json = (
        Path(args.output) if args.output
        else _BASELINE_DIR / f"webgoat_dual_{ts}.json"
    )
    output_md = output_json.with_suffix(".md")
    payload = {
        "schema_version": 1,
        "timestamp": ts,
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
