"""L2 benchmark — OWASP Juice Shop full challenge.json scoring.

The existing per_target Juice Shop fixture (`fixtures/web/juiceshop`)
scores against 9 curated must_find entries. Juice Shop ships with
109 internal challenges across 6 difficulty tiers and 17+ vuln
categories — each challenge auto-marks as `solved` in its REST API
(`GET /api/Challenges/`) when its exploit pattern fires.

This bench:

  1. Brings up Juice Shop via docker compose.
  2. Snapshots the baseline solved set (should be all-false on fresh
     container).
  3. Runs `strix` against Juice Shop in the requested scan mode (L2
     full Lead-Agent + specialist loop, pays real LLM cost).
  4. Polls `/api/Challenges/` again, computes the delta — newly-
     solved challenges are what L2 *naturally tripped* during
     probing.
  5. Emits a JSON result + markdown report with:
       * total_solved / 109
       * solved_by_difficulty: 1★ x/14, 2★ y/15, ..., 6★ z/12
       * solved_by_category
       * difficulty-weighted score (rewards harder tiers more)
       * raw newly-solved challenge list

Why this is a better L2 metric than the 9-must_find expected.yaml:

  * Simple recon (port scan / sbom) solves 0 challenges → forces
    the score to actually reflect L2's probing depth.
  * Tier-1 challenges trip on naive payloads (xss `<script>`) →
    measures whether specialist tools fire correctly.
  * Tier-4+ challenges need chain reasoning (SSRF → IDOR → admin
    register) → measures L2's planning depth, not L1's recall.
  * No curation bias — Juice Shop's grader is the source of truth.

Usage:
    # standard L2 mode (default — runs real strix CLI, $ cost)
    python -m benchmarks.per_target.bench_l2_juiceshop_full

    # deep mode (more iterations, more cost)
    python -m benchmarks.per_target.bench_l2_juiceshop_full --scan-mode deep

    # custom output path
    python -m benchmarks.per_target.bench_l2_juiceshop_full \\
        --output /tmp/juiceshop_l2_run1.json

Environment:
    STRIX_LLM, LLM_API_KEY — required (LLM provider config)
    STRIX_IMAGE            — override sandbox image (default: env)
    STRIX_SKIP_CACHE_INIT  — recommended `1` for bench, avoids the
                             entrypoint's 60-90s lazy-init.
    JUICESHOP_PORT         — override port (default 3001)

Exit codes:
    0 — bench ran cleanly (any score)
    1 — bench infrastructure failure (docker / strix crash / api
        unreachable)
    2 — invocation error (missing env, missing binaries)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "benchmarks" / "per_target" / "fixtures" / "web" / "juiceshop"
COMPOSE_FILE = FIXTURE_DIR / "docker-compose.yml"
BASELINE_DIR = REPO_ROOT / "benchmarks" / "per_target" / "baseline"

DEFAULT_PORT = int(os.environ.get("JUICESHOP_PORT", "3001"))
JUICESHOP_BASE = f"http://localhost:{DEFAULT_PORT}"
CHALLENGES_API = f"{JUICESHOP_BASE}/api/Challenges/"
HEALTH_API = f"{JUICESHOP_BASE}/rest/admin/application-version"

DOCKER_READY_TIMEOUT_S = 120
POLL_INTERVAL_S = 2


# ---------------------------------------------------------------------------
# Docker lifecycle
# ---------------------------------------------------------------------------

def docker_up() -> None:
    print(f"[bench] docker compose up -d -f {COMPOSE_FILE}", flush=True)
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
        check=True, capture_output=True,
    )


def docker_down() -> None:
    print(f"[bench] docker compose down -f {COMPOSE_FILE}", flush=True)
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "down"],
        check=False, capture_output=True,
    )


def wait_for_juiceshop_ready() -> None:
    """Poll the application-version endpoint until 200 or timeout."""
    deadline = time.time() + DOCKER_READY_TIMEOUT_S
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_API, timeout=3) as r:
                if r.status == 200:
                    print(f"[bench] juiceshop ready at {JUICESHOP_BASE}", flush=True)
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(POLL_INTERVAL_S)
    raise RuntimeError(
        f"juiceshop didn't become ready within {DOCKER_READY_TIMEOUT_S}s "
        f"({HEALTH_API} unreachable)"
    )


# ---------------------------------------------------------------------------
# Challenge snapshot
# ---------------------------------------------------------------------------

def fetch_challenges() -> list[dict[str, Any]]:
    """GET /api/Challenges/ → list of challenge dicts.

    Each entry has at least: id, key, name, category, description,
    difficulty (1-6), solved (bool).
    """
    with urllib.request.urlopen(CHALLENGES_API, timeout=10) as r:
        payload = json.loads(r.read().decode("utf-8"))
    return list(payload.get("data") or [])


def snapshot_solved(challenges: list[dict[str, Any]]) -> set[str]:
    """Set of `key` values for challenges currently marked solved."""
    return {c["key"] for c in challenges if c.get("solved")}


# ---------------------------------------------------------------------------
# Strix invocation + cost extraction
# ---------------------------------------------------------------------------

# Matches strix CLI's summary panel:
#   "Input Tokens 772.6K  ·  Cached Tokens 300.8K"
#   "Output Tokens 8.1K · Cost  $0.1709"
_TOKEN_LINE_RE = re.compile(
    r"(Input|Output|Cached)\s+Tokens\s+([\d.]+)(K|M)?",
    re.IGNORECASE,
)
_COST_LINE_RE = re.compile(r"Cost\s+\$([\d.]+)", re.IGNORECASE)
_AGENTS_LINE_RE = re.compile(r"Agents\s+(\d+)", re.IGNORECASE)
_TOOLS_LINE_RE = re.compile(r"Tools\s+(\d+)", re.IGNORECASE)
_VULNS_LINE_RE = re.compile(r"Vulnerabilities\s+(\d+)", re.IGNORECASE)


def _parse_humanised_count(value: str, suffix: str | None) -> float:
    """`772.6K` → 772600.0, `1.2M` → 1200000.0, `42` → 42.0."""
    base = float(value)
    if suffix and suffix.upper() == "K":
        return base * 1000
    if suffix and suffix.upper() == "M":
        return base * 1_000_000
    return base


def parse_strix_stats(output_text: str) -> dict[str, Any]:
    """Pull token / cost / agents / tools / vuln counts from the strix
    CLI's summary panel. Returns zeros when absent so callers can
    treat the dict as always-present."""
    tokens: dict[str, float] = {"input": 0.0, "output": 0.0, "cached": 0.0}
    for kind, value, suffix in _TOKEN_LINE_RE.findall(output_text):
        tokens[kind.lower()] = _parse_humanised_count(value, suffix)

    cost = 0.0
    cost_match = _COST_LINE_RE.search(output_text)
    if cost_match:
        cost = float(cost_match.group(1))

    def _int_or_zero(rx: re.Pattern[str]) -> int:
        m = rx.search(output_text)
        return int(m.group(1)) if m else 0

    return {
        "input_tokens": int(tokens["input"]),
        "output_tokens": int(tokens["output"]),
        "cached_tokens": int(tokens["cached"]),
        "cost_usd": cost,
        "agents": _int_or_zero(_AGENTS_LINE_RE),
        "tools": _int_or_zero(_TOOLS_LINE_RE),
        "strix_reported_vulns": _int_or_zero(_VULNS_LINE_RE),
    }


def run_strix(
    scan_mode: str, run_dir: Path, extra_args: list[str],
    strix_bin: str = "strix",
) -> tuple[int, float, str]:
    """Invoke strix CLI against juice-shop. Returns (exit_code, wall_s, stdout).

    Captures stdout so we can parse the summary panel for token/cost
    stats. stderr is forwarded (errors visible immediately).
    """
    target = f"web_application:http://host.docker.internal:{DEFAULT_PORT}"
    cmd = [strix_bin, "-n", "-t", target, "-m", scan_mode] + extra_args
    print(f"[bench] {' '.join(cmd)}", flush=True)
    start = time.monotonic()
    # Capture stdout so we can parse it; let stderr stream live to console.
    proc = subprocess.run(
        cmd, cwd=run_dir, env=os.environ.copy(),
        capture_output=True, text=True,
    )
    wall = time.monotonic() - start
    # Echo strix's stdout to our own stdout so the operator sees the
    # rich panel + progress; we keep the captured copy for parsing.
    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print(proc.stderr, file=sys.stderr)
    print(f"[bench] strix exit={proc.returncode}  wall={wall:.1f}s", flush=True)
    return proc.returncode, wall, (proc.stdout or "")


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score(
    challenges: list[dict[str, Any]],
    baseline_solved: set[str],
    final_solved: set[str],
) -> dict[str, Any]:
    """Compute the L2 score against the natural-exploitation metric.

    Returns a dict with:
      * total_solved          — count of newly-solved challenges
      * total_challenges      — 109
      * recall                — newly_solved / total
      * weighted_score        — Σ(difficulty * solved) / Σ(difficulty * total)
      * solved_by_difficulty  — {1: "x/14", 2: "y/15", ...}
      * solved_by_category    — {"XSS": "x/9", ...}
      * newly_solved_keys     — sorted list of challenge keys
      * regressions           — keys that went from solved→unsolved (should be empty)
    """
    newly_solved = final_solved - baseline_solved
    regressions = baseline_solved - final_solved

    by_diff_total: Counter[int] = Counter()
    by_diff_solved: Counter[int] = Counter()
    by_cat_total: Counter[str] = Counter()
    by_cat_solved: Counter[str] = Counter()

    weighted_total = 0
    weighted_solved = 0

    for c in challenges:
        key = c.get("key")
        diff = c.get("difficulty", 1)
        cat = c.get("category", "Unknown")
        by_diff_total[diff] += 1
        by_cat_total[cat] += 1
        weighted_total += diff
        if key in newly_solved:
            by_diff_solved[diff] += 1
            by_cat_solved[cat] += 1
            weighted_solved += diff

    def fmt(s: int, t: int) -> str:
        pct = (s / t * 100) if t else 0.0
        return f"{s}/{t} ({pct:.0f}%)"

    return {
        "total_solved": len(newly_solved),
        "total_challenges": len(challenges),
        "recall": (len(newly_solved) / len(challenges)) if challenges else 0.0,
        "weighted_score": (weighted_solved / weighted_total) if weighted_total else 0.0,
        "solved_by_difficulty": {
            int(d): fmt(by_diff_solved[d], by_diff_total[d])
            for d in sorted(by_diff_total)
        },
        "solved_by_category": {
            cat: fmt(by_cat_solved[cat], by_cat_total[cat])
            for cat in sorted(by_cat_total)
        },
        "newly_solved_keys": sorted(newly_solved),
        "regressions": sorted(regressions),
    }


def compare_to_prior(
    current_score: dict[str, Any],
    current_stats: dict[str, Any],
    prior_json_path: Path,
) -> dict[str, Any]:
    """Diff this run against a prior bench JSON. Returns a dict with
    new-solved keys, regressed keys, and cost / recall deltas.

    Used by run-over-run comparisons: did the latest strix improve
    Juice Shop coverage vs last week's baseline? Did it cost more?
    """
    try:
        prior = json.loads(prior_json_path.read_text())
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not load prior: {e}"}

    prior_score = prior.get("score") or {}
    prior_stats = prior.get("strix_stats") or {}

    prior_keys = set(prior_score.get("newly_solved_keys") or [])
    current_keys = set(current_score.get("newly_solved_keys") or [])

    return {
        "prior_path": str(prior_json_path),
        "prior_timestamp": prior.get("timestamp"),
        "prior_scan_mode": prior.get("scan_mode"),
        "newly_solved_gained": sorted(current_keys - prior_keys),
        "newly_solved_lost": sorted(prior_keys - current_keys),
        "delta_total_solved": current_score.get("total_solved", 0) - prior_score.get("total_solved", 0),
        "delta_recall": (
            current_score.get("recall", 0.0) - prior_score.get("recall", 0.0)
        ),
        "delta_weighted_score": (
            current_score.get("weighted_score", 0.0)
            - prior_score.get("weighted_score", 0.0)
        ),
        "delta_cost_usd": (
            current_stats.get("cost_usd", 0.0)
            - prior_stats.get("cost_usd", 0.0)
        ),
        "delta_input_tokens": (
            current_stats.get("input_tokens", 0)
            - prior_stats.get("input_tokens", 0)
        ),
    }


def render_markdown(
    result: dict[str, Any],
    scan_mode: str,
    wall_seconds: float,
    strix_exit_code: int,
    timestamp: str,
    strix_stats: dict[str, Any] | None = None,
    comparison: dict[str, Any] | None = None,
) -> str:
    """Markdown report alongside the JSON for human reading."""
    lines = [
        f"# L2 Juice Shop (full challenge.json) — {timestamp}",
        "",
        f"- **Scan mode**: {scan_mode}",
        f"- **Strix exit**: {strix_exit_code}",
        f"- **Wall time**: {wall_seconds:.1f}s",
        f"- **Newly solved**: {result['total_solved']} / "
        f"{result['total_challenges']} = "
        f"{result['recall']*100:.1f}%",
        f"- **Weighted score** (Σ difficulty × solved / Σ difficulty × total): "
        f"{result['weighted_score']*100:.1f}%",
    ]
    if strix_stats:
        lines.append(
            f"- **LLM cost**: ${strix_stats.get('cost_usd', 0.0):.4f}  "
            f"(input {strix_stats.get('input_tokens', 0):,}, "
            f"output {strix_stats.get('output_tokens', 0):,}, "
            f"cached {strix_stats.get('cached_tokens', 0):,})"
        )
        lines.append(
            f"- **Agents**: {strix_stats.get('agents', 0)}, "
            f"**tools called**: {strix_stats.get('tools', 0)}"
        )
        # Cost per solved — the L2-economics headline
        if result["total_solved"] > 0 and strix_stats.get("cost_usd", 0) > 0:
            cps = strix_stats["cost_usd"] / result["total_solved"]
            lines.append(f"- **Cost per challenge solved**: ${cps:.4f}")

    if comparison and "error" not in comparison:
        lines += [
            "",
            "## Comparison vs prior run",
            "",
            f"- **Prior**: `{comparison['prior_path']}` "
            f"({comparison.get('prior_timestamp', '?')}, "
            f"mode={comparison.get('prior_scan_mode', '?')})",
            f"- **Δ solved**: {comparison['delta_total_solved']:+d}",
            f"- **Δ recall**: {comparison['delta_recall']*100:+.1f}pp",
            f"- **Δ weighted**: {comparison['delta_weighted_score']*100:+.1f}pp",
            f"- **Δ cost**: ${comparison['delta_cost_usd']:+.4f}",
            f"- **Gained**: {len(comparison['newly_solved_gained'])} keys "
            + (f"({', '.join(comparison['newly_solved_gained'][:5])}"
               + ("..." if len(comparison['newly_solved_gained']) > 5 else "") + ")"
               if comparison['newly_solved_gained'] else ""),
            f"- **Lost**: {len(comparison['newly_solved_lost'])} keys "
            + (f"({', '.join(comparison['newly_solved_lost'][:5])}"
               + ("..." if len(comparison['newly_solved_lost']) > 5 else "") + ")"
               if comparison['newly_solved_lost'] else ""),
        ]

    lines += [
        "",
        "## Solved by difficulty",
        "",
        "| Tier | Solved |",
        "|---:|---|",
    ]
    for d, s in result["solved_by_difficulty"].items():
        lines.append(f"| {d}★ | {s} |")
    lines += [
        "",
        "## Solved by category",
        "",
        "| Category | Solved |",
        "|---|---|",
    ]
    for cat, s in result["solved_by_category"].items():
        lines.append(f"| {cat} | {s} |")
    if result["newly_solved_keys"]:
        lines += [
            "",
            "## Newly-solved challenge keys",
            "",
        ]
        for key in result["newly_solved_keys"]:
            lines.append(f"- `{key}`")
    if result["regressions"]:
        lines += [
            "",
            "## ⚠ Regressions (solved → unsolved)",
            "",
            "Should be empty. If non-empty, juice-shop state was dirty at baseline.",
            "",
        ]
        for key in result["regressions"]:
            lines.append(f"- `{key}`")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--scan-mode", default="standard",
        choices=["quick", "standard", "deep"],
        help="strix scan mode (default: standard)",
    )
    parser.add_argument(
        "--output",
        help="JSON result path (default: benchmarks/per_target/baseline/...)",
    )
    parser.add_argument(
        "--markdown",
        help="markdown report path (default: alongside JSON)",
    )
    parser.add_argument(
        "--keep-up", action="store_true",
        help="don't tear down juice-shop after the scan",
    )
    parser.add_argument(
        "--strix-arg", action="append", default=[],
        help="extra arg to pass to strix (repeatable)",
    )
    parser.add_argument(
        "--skip-strix", action="store_true",
        help=(
            "don't invoke strix — just snapshot baseline + final challenge "
            "state (useful for testing the scoring path with a manual scan "
            "in another shell)"
        ),
    )
    parser.add_argument(
        "--strix-bin", default="strix",
        help="strix CLI binary (default: 'strix' on PATH)",
    )
    parser.add_argument(
        "--compare-to", metavar="PRIOR_JSON",
        help=(
            "path to a prior bench JSON; if set, the markdown report "
            "includes a diff (new-solved, regressed, cost delta)"
        ),
    )
    args = parser.parse_args()

    # ----- preflight -----
    if not args.skip_strix:
        if not (os.environ.get("STRIX_LLM") and os.environ.get("LLM_API_KEY")):
            print(
                "error: STRIX_LLM + LLM_API_KEY must be set "
                "(or pass --skip-strix to test scoring only)",
                file=sys.stderr,
            )
            return 2

    if not COMPOSE_FILE.exists():
        print(f"error: compose file not found: {COMPOSE_FILE}", file=sys.stderr)
        return 2

    # ----- bring up juice-shop -----
    docker_running = False
    try:
        docker_up()
        docker_running = True
        wait_for_juiceshop_ready()

        # ----- baseline snapshot -----
        challenges = fetch_challenges()
        baseline_solved = snapshot_solved(challenges)
        print(
            f"[bench] baseline: {len(baseline_solved)} / "
            f"{len(challenges)} challenges already solved",
            flush=True,
        )
        if baseline_solved:
            print(
                f"[bench] WARN: non-empty baseline — juice-shop state was "
                f"dirty; scoring will subtract baseline. "
                f"({sorted(baseline_solved)})",
                flush=True,
            )

        # ----- run strix -----
        run_dir = FIXTURE_DIR / ".strix-l2-bench-work" / f"run-{int(time.time())}"
        run_dir.mkdir(parents=True, exist_ok=True)

        strix_stats: dict[str, Any] = {}
        if args.skip_strix:
            print("[bench] --skip-strix — pausing 5s before final snapshot", flush=True)
            time.sleep(5)
            exit_code, wall = 0, 0.0
        else:
            exit_code, wall, stdout = run_strix(
                args.scan_mode, run_dir, args.strix_arg,
                strix_bin=args.strix_bin,
            )
            strix_stats = parse_strix_stats(stdout)

        # ----- final snapshot + scoring -----
        challenges_final = fetch_challenges()
        final_solved = snapshot_solved(challenges_final)
        result = score(challenges, baseline_solved, final_solved)

        # ----- optional: comparison to prior run -----
        comparison: dict[str, Any] | None = None
        if args.compare_to:
            comparison = compare_to_prior(result, strix_stats, Path(args.compare_to))

        # ----- print summary -----
        print("", flush=True)
        print(f"=== L2 Juice Shop bench summary ===", flush=True)
        print(
            f"newly_solved={result['total_solved']}/"
            f"{result['total_challenges']}  "
            f"recall={result['recall']*100:.1f}%  "
            f"weighted={result['weighted_score']*100:.1f}%  "
            f"wall={wall:.1f}s",
            flush=True,
        )
        print(
            f"by tier: " + ", ".join(
                f"{d}★={s}" for d, s in result["solved_by_difficulty"].items()
            ),
            flush=True,
        )

        # ----- persist -----
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_json = (
            Path(args.output) if args.output
            else BASELINE_DIR / f"l2_juiceshop_full_{timestamp}_{args.scan_mode}.json"
        )
        out_md = (
            Path(args.markdown) if args.markdown
            else out_json.with_suffix(".md")
        )

        record = {
            "schema_version": 2,
            "bench": "l2_juiceshop_full",
            "timestamp": timestamp,
            "scan_mode": args.scan_mode,
            "strix_exit_code": exit_code,
            "wall_seconds": round(wall, 2),
            "score": result,
            "strix_stats": strix_stats,
            "comparison": comparison,
            "env": {
                "STRIX_LLM": os.environ.get("STRIX_LLM"),
                "STRIX_IMAGE": os.environ.get("STRIX_IMAGE"),
                "STRIX_SKIP_CACHE_INIT": os.environ.get("STRIX_SKIP_CACHE_INIT"),
            },
        }
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(record, indent=2))
        out_md.write_text(
            render_markdown(
                result, args.scan_mode, wall, exit_code, timestamp,
                strix_stats=strix_stats, comparison=comparison,
            ),
        )
        print(f"[bench] wrote {out_json}", flush=True)
        print(f"[bench] wrote {out_md}", flush=True)
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"[bench] FAIL: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    finally:
        if docker_running and not args.keep_up:
            docker_down()


if __name__ == "__main__":
    sys.exit(main())
