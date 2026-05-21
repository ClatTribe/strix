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
(`strix.agents.lead_agent.anchor_prepass.run_oss_anchor_prepass`),
no LLM cost.

**Sandbox vs bench gap (post PR #384):** every L1 anchor specialist
now runs inside the strix-sandbox container in production. The
bench harness here has NO sandbox — tools with
`sandbox_execution=True` error cleanly with "Agent state with a
valid sandbox_id is required" and contribute 0 findings.

That's by design: the bench measures the LOWER BOUND of L1 (what
runs without the sandbox infrastructure). Production sees the full
anchor coverage including jwt_audit, webapp_recon_pipeline,
http_security_headers_audit, tls_audit, cors_deep_check,
csrf_check, dom_xss_static_probe, scan_cache_deception,
scan_websocket_auth, scan_prototype_pollution, scan_container_image,
scan_sast, scan_sca_lockfiles, scan_iac, secrets_scan, etc.

The bench's job is to validate L1's NON-sandbox-resident probes +
the orchestration logic. Sandbox-resident specialists are
validated separately (unit tests + production runs).

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
    sandbox_execution=True will error out cleanly. The bench
    captures the LOWER BOUND of L1 recall (what runs without
    sandbox infrastructure); production sees the full anchor
    coverage."""
    sandbox_id = None
    sandbox_token = None
    sandbox_info: dict = {}
    agent_id = "l1-bench"
    findings: list = []


def _ensure_tracer() -> None:
    """Set up a minimal global tracer so tools that emit via
    `get_global_tracer()` (scan_container_image, scan_sast, etc.)
    can actually persist findings.

    Without this, scan_container_image silently no-ops on the L1
    bench harness — trivy finds 400+ CVEs in nginx:1.18 but
    `_emit_image_finding` returns None because tracer is None,
    so 0 findings make it into the result dict.

    The tracer writes events to a tempdir; not used by the bench
    but required by the emission layer.
    """
    try:
        from strix.telemetry import tracer as tracer_module
        if getattr(tracer_module, "_global_tracer", None) is not None:
            return
        from strix.telemetry.tracer import Tracer, set_global_tracer
        t = Tracer("l1-bench")
        set_global_tracer(t)
    except Exception:  # noqa: BLE001
        # Don't crash the bench on tracer setup failure — some tools
        # still emit findings without a tracer.
        pass


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


def resolve_all_targets(
    fixture_dir: Path, manifest: dict[str, Any],
) -> list[tuple[str, str]]:
    """Returns a list of (target_type, target_value) the prepass
    should scan. Handles primary + `additional_targets` (paired-asset
    fixtures like vibe-app where the same app is scanned as web URL
    AND local source tree).

    The primary target comes first; additional targets follow in
    manifest order. Each target gets its own prepass invocation; the
    bench unions the findings across all targets before scoring.
    """
    out: list[tuple[str, str]] = []
    # Primary target via the single-target resolver.
    primary = resolve_target(fixture_dir, manifest)
    if primary[0] and primary[1]:
        out.append(primary)

    # Additional targets: each has its own {type, target} pair.
    for entry in (manifest.get("additional_targets") or []):
        if not isinstance(entry, dict):
            continue
        tt = (entry.get("type") or "").strip()
        tg = entry.get("target")
        if not tt or tg is None:
            continue
        if tt in ("local_code", "repository"):
            full = (fixture_dir / tg).resolve()
            out.append((tt, str(full)))
        else:
            out.append((tt, str(tg)))
    return out


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
        # Prefer the manifest's `target` field (with host.docker.internal
        # → localhost rewrite). Fall back to wait_url if no target.
        #
        # We deliberately DON'T use docker.wait_url as the primary —
        # wait_url is a health-check endpoint that may point deep into
        # the app (juiceshop's wait_url is /rest/admin/application-version,
        # not the app root). Probes appended to that URL would all go to
        # the wrong place.
        target = manifest.get("target", "")
        target = (target or "").replace("host.docker.internal", "localhost")
        if target:
            return target_type, target.rstrip("/")
        # Last-ditch: take scheme://netloc from wait_url (strip the path).
        docker_cfg = manifest.get("docker") or {}
        wait_url = docker_cfg.get("wait_url")
        if isinstance(wait_url, str) and wait_url:
            try:
                from urllib.parse import urlparse
                p = urlparse(wait_url)
                if p.scheme and p.netloc:
                    return target_type, f"{p.scheme}://{p.netloc}"
            except Exception:  # noqa: BLE001
                pass
            return target_type, wait_url.rstrip("/")
        return target_type, ""
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
    targets = resolve_all_targets(fixture_dir, manifest)
    rel = fixture_dir.relative_to(REPO_ROOT) if str(fixture_dir).startswith(str(REPO_ROOT)) else fixture_dir
    primary_type, primary_value = targets[0] if targets else ("", "")
    print(f"\n=== {rel} ({primary_type}) ===", flush=True)
    for tt, tv in targets:
        print(f"  target: [{tt}] {tv}", flush=True)

    docker_up_ok = False
    try:
        if not skip_docker:
            docker_up_ok = docker_up(fixture_dir, manifest)
        agent_state = _FakeAgentState()

        # Run the L1 prepass against EACH target and union findings.
        # Paired-asset fixtures (vibe-app) need this so SCA / SAST
        # against the source tree run alongside DAST against the
        # web URL.
        start = time.monotonic()
        all_findings: list[Found] = []
        merged_tool_results: list[dict[str, Any]] = []
        total_tools_run = 0
        total_tools_succeeded = 0
        total_tools_failed = 0
        for tt, tv in targets:
            summary = await run_oss_anchor_prepass(
                target_type=tt,
                target_value=tv,
                workspace_path="",
                agent_state=agent_state,
            )
            for r in summary.tool_results:
                raw = r.raw_result
                if isinstance(raw, dict):
                    for f in (raw.get("findings") or raw.get("vulnerabilities") or []):
                        if isinstance(f, dict):
                            all_findings.append(_finding_to_found(f))
                merged_tool_results.append({
                    "tool": f"[{tt}] {r.tool_name}",
                    "status": r.status,
                    "findings": r.findings_count,
                    "note": (r.error_reason or "")[:120],
                })
            total_tools_run += len(summary.tools_run)
            total_tools_succeeded += len(summary.tools_succeeded)
            total_tools_failed += len(summary.tools_failed)
        wall = time.monotonic() - start

        score_result = score(expected, all_findings)

        result = {
            "fixture": str(rel),
            "target_type": primary_type,
            "target_value": primary_value,
            "wall_seconds": round(wall, 2),
            "expected_count": score_result.expected_count,
            "found_count": score_result.found_count,
            "matched_count": score_result.matched_count,
            "recall": score_result.recall,
            "precision": score_result.precision,
            "matched": list(score_result.matches),
            "missed": list(score_result.missed),
            "tools_run": total_tools_run,
            "tools_succeeded": total_tools_succeeded,
            "tools_failed": total_tools_failed,
            "tool_breakdown": merged_tool_results,
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


# Default fixture list. Two tiers:
#   * _FAST_FIXTURES — original 6 used during iter-11..iter-15
#     iteration. ~10 min total wall, one fixture per asset type.
#   * _ALL_FIXTURES  — every fixture under fixtures/ that has an
#     expected.yaml. Triggered via `--full`.
#
# Why two tiers (caught 2026-05-21): iter-15 surfaced that 5+
# fixtures with expected.yaml had NEVER been measured because they
# weren't in the default list (code/sast-vibe, code/iac-vibe,
# code/sca-*, api/crapi). The selection bias meant new probes /
# rules were tuned to the 6, not to the breadth. `--full` makes
# "forgot to measure a fixture" structurally impossible.
_FAST_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web+code/vibe-app",
    "ip/vulnerable-services",
    "web/juiceshop",
    "container/nginx-vuln",
]

# Heavy; ~30-45 min when all containers come up cleanly. Order is
# asset-type-grouped so a partial run still gives you per-type signal.
_ALL_FIXTURES = [
    # code / repository targets — host execution, fastest
    "code/flask-vuln",
    "code/sast-vibe",
    "code/iac-vibe",
    "code/sca-vuln-deps",
    "code/sca-reachability",
    "code/sca-supply-chain",
    # api targets
    "api/vampi",
    "api/crapi",
    # web_application targets (some heavy)
    "web+code/vibe-app",
    "web/juiceshop",
    "web/webgoat",
    "web/apache-cve-2021-41773",
    # ip_address
    "ip/vulnerable-services",
    # container_image
    "container/nginx-vuln",
]

# Backwards-compatible name for any caller that referenced this
# directly. Fast set is still the default for `python -m
# benchmarks.per_target.bench_l1_only` with no flags.
_DEFAULT_FIXTURES = _FAST_FIXTURES


async def amain(args: argparse.Namespace) -> int:
    _ensure_tracer()
    fixtures_root = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"
    if args.fixture:
        targets = [fixtures_root / args.fixture]
    elif args.full:
        targets = [fixtures_root / f for f in _ALL_FIXTURES]
    else:
        targets = [fixtures_root / f for f in _FAST_FIXTURES]

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
             "Default: runs the FAST tier (6 fixtures, ~10 min). Use "
             "`--full` for every fixture with an expected.yaml.",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="run the full fixture set instead of the fast tier. ~30-45 min "
             "when all containers come up cleanly. Covers every fixture under "
             "fixtures/ that has an expected.yaml — added 2026-05-21 after "
             "iter-15 surfaced that the fast tier had been silently missing "
             "5+ measurable fixtures (sast-vibe, iac-vibe, sca-*, crapi).",
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
