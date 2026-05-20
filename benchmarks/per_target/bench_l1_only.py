"""L1-only benchmark harness — measures the OSS-anchor prepass
directly against each fixture, no LLM cost.

## Why this exists

The full per-target bench (runner.py) shells to strix CLI which uses
the LLM for the lead loop. That makes the bench's measurement
unreliable on LLM providers with tight per-minute RPM caps (Gemini
free tier — observed 2026-05-20: each fixture after the first
fails fast on 429 because the previous fixture's tail exhausted the
quota).

L1 alone is deterministic — it's strix's OSS anchor pre-pass
(`strix.agents.lead_agent.anchor_prepass.run_oss_anchor_prepass`).
For tools with `sandbox_execution=False` (scan_sast / scan_sca_lockfiles
/ scan_iac), L1 runs entirely on the host with zero LLM cost. We can
measure exactly what L1 catches per fixture in ~30 seconds each.

## What this measures

For each fixture:
  1. Parse expected.yaml (must_finds + categories + per-finding
     location metadata).
  2. Resolve `target_value` from the manifest (same logic as runner.py).
  3. Bring up docker compose if `docker.compose_file` is set + wait for
     the health URL.
  4. Run `run_oss_anchor_prepass(target_type, target_value, ...)` —
     this is the L1 detection layer ONLY.
  5. Map prepass findings to the strix canonical Found shape (category,
     file, line, endpoint, etc.).
  6. Score against expected.yaml using the same scoring layer that
     runner.py uses.
  7. Emit per-fixture L1 recall + precision.
  8. Tear down docker compose.

## What this does NOT measure

  * LLM lead-loop reasoning (L2)
  * Specialist dispatch (L3)
  * Cross-tool dedupe / FP demotion
  * Attack-path chain construction

Those layers are tested by runner.py with a real LLM. Use this
harness when you need a deterministic L1-only number per fixture
(e.g. when iterating on the anchor sequence, kwarg builders, or
ruleset coverage in semgrep/nuclei/trivy/grype).

## Usage

  $ python benchmarks/per_target/bench_l1_only.py
  $ python benchmarks/per_target/bench_l1_only.py --fixture flask-vuln
  $ python benchmarks/per_target/bench_l1_only.py --output /tmp/l1.md

Defaults to running the 5 representative fixtures from the per-asset-
type bench (flask-vuln / vampi / vibe-app / ip-vulnerable / juiceshop).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


# Import the scoring + expected-yaml parser from runner.py's sibling
# scoring module. Reuse means our L1-only numbers are directly
# comparable to runner.py's full-pipeline numbers.
sys.path.insert(0, str(Path(__file__).parent))
from scoring import Expected, Found, score  # noqa: E402

# Import the L1 prepass.
sys.path.insert(0, str(Path(__file__).parents[2]))
from strix.agents.lead_agent.anchor_prepass import run_oss_anchor_prepass  # noqa: E402


REPO_ROOT = Path(__file__).parents[2]


def _require_yaml():
    import yaml
    return yaml


class _FakeAgentState:
    """Minimal agent_state for the prepass — has the attrs the
    tool registry checks but no real sandbox. Tools with
    sandbox_execution=True will error out (acceptable for L1
    measurement; sandbox-dependent tools are L2/L3 territory)."""
    sandbox_id = None
    sandbox_token = None
    sandbox_info: dict = {}
    agent_id = "l1-bench"
    findings: list = []


def parse_expected(fixture_dir: Path) -> tuple[dict[str, Any], list[Expected]]:
    yaml = _require_yaml()
    manifest = yaml.safe_load((fixture_dir / "expected.yaml").read_text())
    raw = manifest.get("expected_findings", []) or []
    expected = [
        Expected(
            id=e["id"],
            category=e.get("category", ""),
            cwe=e.get("cwe"),
            file=e.get("file"),
            line=e.get("line"),
            endpoint=e.get("endpoint"),
            port=e.get("port"),
            severity=e.get("severity"),
            description=e.get("description", ""),
            must_find=bool(e.get("must_find", True)),
        )
        for e in raw
    ]
    return manifest, expected


def resolve_target(fixture_dir: Path, manifest: dict[str, Any]) -> tuple[str, str]:
    """Pick (target_type, target_value) the prepass should scan.

    For network targets (api / web_application / ip_address) we prefer
    the manifest's `docker.wait_url` over the bare `target` field when
    available. Fixtures typically set `target` to a sandbox-internal
    URL like `http://host.docker.internal:5001` — that doesn't resolve
    from host Python, but `wait_url` is the host-accessible equivalent
    (`http://localhost:5001`).
    """
    target_type = manifest.get("target_type", "")
    if target_type in ("local_code", "repository"):
        rel = manifest.get("target", "")
        full = (fixture_dir / rel).resolve()
        return target_type, str(full)
    if target_type in ("web_application", "api"):
        # Prefer the host-accessible wait_url. Fall back to target.
        docker_cfg = manifest.get("docker") or {}
        wait_url = docker_cfg.get("wait_url")
        if isinstance(wait_url, str) and wait_url:
            return target_type, wait_url.rstrip("/")
        target = manifest.get("target", "")
        # Last-ditch: rewrite host.docker.internal → localhost so
        # the host harness can reach a sandbox-style URL.
        target = (target or "").replace("host.docker.internal", "localhost")
        return target_type, target
    if target_type == "ip_address":
        # Same host-rewrite logic.
        target = manifest.get("target", "")
        target = (target or "").replace("host.docker.internal", "localhost")
        return target_type, target
    if target_type == "container_image":
        return target_type, manifest.get("target", "")
    return target_type, manifest.get("target", "")


def docker_up(fixture_dir: Path, manifest: dict[str, Any]) -> bool:
    """Bring up docker compose if specified; wait for health URL."""
    docker_cfg = manifest.get("docker") or {}
    compose_file = docker_cfg.get("compose_file")
    if not compose_file:
        return False
    compose_path = fixture_dir / compose_file
    if not compose_path.exists():
        return False
    print(f"  [docker] up -f {compose_path.relative_to(REPO_ROOT)}", flush=True)
    subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "up", "-d"],
        check=False, capture_output=True,
    )
    wait_url = docker_cfg.get("wait_url")
    if wait_url:
        deadline = time.time() + int(docker_cfg.get("wait_timeout_seconds", 60))
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(wait_url, timeout=2):
                    print(f"  [docker] {wait_url} healthy", flush=True)
                    return True
            except Exception:  # noqa: BLE001
                time.sleep(2)
        print(f"  [docker] WARN: {wait_url} never became healthy", flush=True)
    return True


def docker_down(fixture_dir: Path, manifest: dict[str, Any]) -> None:
    docker_cfg = manifest.get("docker") or {}
    compose_file = docker_cfg.get("compose_file")
    if not compose_file:
        return
    compose_path = fixture_dir / compose_file
    subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "down"],
        check=False, capture_output=True,
    )


def _finding_to_found(raw: dict[str, Any]) -> Found:
    """Map a prepass-tool finding dict to the canonical Found shape.

    Tool-emitted findings vary in field names; we extract the common
    ones the scoring layer needs (category, cwe, file, line, endpoint).
    """
    if not isinstance(raw, dict):
        return Found(title=str(raw)[:80])
    title = (
        raw.get("title")
        or raw.get("name")
        or raw.get("description", "")[:120]
        or raw.get("rule_id", "")
        or "unnamed"
    )
    location = raw.get("location") or {}
    if isinstance(location, dict):
        file_ = location.get("file") or location.get("path")
        line = location.get("line") or location.get("line_start")
    else:
        file_ = None
        line = None
    return Found(
        title=str(title)[:200],
        category=raw.get("category"),
        cwe=raw.get("cwe"),
        file=raw.get("file") or file_,
        line=raw.get("line") or line,
        endpoint=raw.get("endpoint") or raw.get("url"),
        port=raw.get("port"),
        severity=raw.get("severity"),
        raw=raw,
    )


async def run_one_fixture(
    fixture_dir: Path,
    *,
    skip_docker: bool = False,
) -> dict[str, Any]:
    """Run L1 prepass against one fixture; return scored result dict."""
    manifest, expected = parse_expected(fixture_dir)
    target_type, target_value = resolve_target(fixture_dir, manifest)
    rel = fixture_dir.relative_to(REPO_ROOT) if str(fixture_dir).startswith(str(REPO_ROOT)) else fixture_dir
    print(f"\n=== {rel} ({target_type}) ===", flush=True)
    print(f"  target: {target_value}", flush=True)

    docker_up_ok = False
    try:
        if not skip_docker:
            docker_up_ok = docker_up(fixture_dir, manifest)
        # Run the L1 prepass.
        agent_state = _FakeAgentState()
        start = time.monotonic()
        summary = await run_oss_anchor_prepass(
            target_type=target_type,
            target_value=target_value,
            workspace_path="",
            agent_state=agent_state,
        )
        wall = time.monotonic() - start

        # Flatten all findings from all tool results into a single list.
        all_findings: list[Found] = []
        for r in summary.tool_results:
            raw = r.raw_result
            if not isinstance(raw, dict):
                continue
            for f in (raw.get("findings") or raw.get("vulnerabilities") or []):
                if isinstance(f, dict):
                    all_findings.append(_finding_to_found(f))

        score_result = score(expected, all_findings)

        result = {
            "fixture": str(rel),
            "target_type": target_type,
            "target_value": target_value,
            "wall_seconds": round(wall, 2),
            "expected_count": score_result.expected_count,
            "found_count": score_result.found_count,
            "matched_count": score_result.matched_count,
            "recall": score_result.recall,
            "precision": score_result.precision,
            "matched": list(score_result.matches),
            "missed": list(score_result.missed),
            "tools_run": len(summary.tools_run),
            "tools_succeeded": len(summary.tools_succeeded),
            "tools_failed": len(summary.tools_failed),
            "tool_breakdown": [
                {
                    "tool": r.tool_name,
                    "status": r.status,
                    "findings": r.findings_count,
                    "note": (r.error_reason or "")[:120],
                }
                for r in summary.tool_results
            ],
        }
        print(
            f"  recall={result['recall']:.3f} ({result['matched_count']}/{result['expected_count']}) "
            f"found={result['found_count']} wall={result['wall_seconds']:.1f}s",
            flush=True,
        )
        return result
    finally:
        if docker_up_ok and not skip_docker:
            docker_down(fixture_dir, manifest)


_DEFAULT_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web+code/vibe-app",
    "ip/vulnerable-services",
    "web/juiceshop",
]


async def amain(args: argparse.Namespace) -> int:
    fixtures_root = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"
    if args.fixture:
        targets = [fixtures_root / args.fixture]
    else:
        targets = [fixtures_root / f for f in _DEFAULT_FIXTURES]

    results: list[dict[str, Any]] = []
    for fx in targets:
        if not (fx / "expected.yaml").exists():
            print(f"  [skip] {fx.name}: no expected.yaml", flush=True)
            continue
        try:
            results.append(await run_one_fixture(fx, skip_docker=args.skip_docker))
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            results.append({
                "fixture": str(fx.relative_to(REPO_ROOT)),
                "error": f"{type(e).__name__}: {e}",
            })

    # Emit markdown summary.
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = args.output or f"benchmarks/per_target/baseline/l1_only_{ts}.md"
    lines = [
        f"# L1-only baseline @ {ts}",
        "",
        "Pure prepass measurement — no LLM cost. Tools that need a real",
        "sandbox (`sandbox_execution=True`) fail in this harness; they",
        "work in the full bench via runner.py.",
        "",
        "| Fixture | target_type | recall | precision | matched | found | wall |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        if "error" in r:
            lines.append(
                f"| {r['fixture']} | — | — | — | — | — | ERROR: {r['error']} |"
            )
            continue
        lines.append(
            f"| {r['fixture']} | {r['target_type']} | "
            f"{r['recall']:.3f} | {r['precision']:.3f} | "
            f"{r['matched_count']}/{r['expected_count']} | "
            f"{r['found_count']} | {r['wall_seconds']:.1f}s |"
        )
    lines.append("")
    # Append per-fixture tool breakdowns for diagnostics.
    for r in results:
        if "error" in r:
            continue
        lines.append(f"## {r['fixture']} — tool breakdown")
        lines.append("")
        lines.append(f"- matched: {r['matched']}")
        lines.append(f"- missed: {r['missed']}")
        lines.append("")
        lines.append("| Tool | Status | Findings | Note |")
        lines.append("|---|---|---:|---|")
        for t in r["tool_breakdown"]:
            note = (t["note"] or "").replace("|", "\\|")
            lines.append(
                f"| {t['tool']} | {t['status']} | {t['findings']} | {note} |"
            )
        lines.append("")

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("\n".join(lines))
    print(f"\nDONE. Wrote {out_path}", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--fixture", default=None,
        help="single fixture relative path (e.g. 'code/flask-vuln'). "
             "Default: runs all 5 representatives.",
    )
    parser.add_argument(
        "--output", default=None,
        help="path to markdown summary (default: timestamped under baseline/)",
    )
    parser.add_argument(
        "--skip-docker", action="store_true",
        help="don't bring up docker compose (assume target is already up)",
    )
    args = parser.parse_args()
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
