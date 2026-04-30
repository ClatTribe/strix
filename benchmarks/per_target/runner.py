"""Per-target benchmark runner.

Runs strix against a fixture, parses the resulting findings, scores them
against the fixture's expected.yaml, and emits a JSON result document.

Usage:
    python runner.py <fixture-dir> [--scan-mode quick|standard|deep] [--output result.json]

Fixture layout:
    <fixture-dir>/
        expected.yaml              required — see below for schema
        docker-compose.yml         optional — runner brings it up + tears it down
        ...                        target source / config files

expected.yaml schema (minimal):
    target_type: local_code | repository | web_application | ip_address | domain
    target: ./app.py        # for code targets, relative to fixture dir
                            # for web/ip, the URL/IP/host:port the runner uses
    description: "..."
    docker:
        compose_file: docker-compose.yml   # optional; runner brings up + waits
        wait_url: http://localhost:3000    # optional; HTTP probe to confirm ready
        wait_timeout_seconds: 60
    expected_findings:
        - id: <stable-slug>
          category: sqli
          cwe: CWE-89
          file: app.py        # for code targets
          line: 42
          endpoint: /search   # for web targets
          port: 6379          # for ip targets
          severity: high
          must_find: true
          description: "..."
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict
from pathlib import Path
from typing import Any

# Allow importing scoring.py without packaging this dir.
sys.path.insert(0, str(Path(__file__).parent))
from scoring import Expected, Found, score  # noqa: E402


def _require_yaml():
    try:
        import yaml  # noqa: F401
        return yaml
    except ImportError:
        print("error: pyyaml not installed. run: pip install pyyaml", file=sys.stderr)
        sys.exit(2)


def parse_expected(fixture_dir: Path) -> tuple[dict[str, Any], list[Expected]]:
    yaml = _require_yaml()
    manifest_path = fixture_dir / "expected.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing {manifest_path}")
    with manifest_path.open("r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f) or {}
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
            must_find=e.get("must_find", True),
        )
        for e in raw
    ]
    return manifest, expected


def docker_up(fixture_dir: Path, manifest: dict[str, Any]) -> bool:
    docker_cfg = manifest.get("docker") or {}
    compose_file = docker_cfg.get("compose_file")
    if not compose_file:
        return False
    compose_path = fixture_dir / compose_file
    if not compose_path.exists():
        raise FileNotFoundError(f"docker compose file not found: {compose_path}")
    print(f"[runner] docker compose -f {compose_path} up -d")
    subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "up", "-d"], check=True
    )
    wait_url = docker_cfg.get("wait_url")
    timeout = int(docker_cfg.get("wait_timeout_seconds", 60))
    if wait_url:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(wait_url, timeout=2)
                print(f"[runner] {wait_url} is ready")
                return True
            except Exception:
                time.sleep(1)
        raise TimeoutError(f"{wait_url} did not respond within {timeout}s")
    # Default: small wait so services finish boot.
    time.sleep(int(docker_cfg.get("wait_seconds", 5)))
    return True


def docker_down(fixture_dir: Path, manifest: dict[str, Any]) -> None:
    docker_cfg = manifest.get("docker") or {}
    compose_file = docker_cfg.get("compose_file")
    if not compose_file:
        return
    compose_path = fixture_dir / compose_file
    print(f"[runner] docker compose -f {compose_path} down")
    subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "down", "--remove-orphans"],
        check=False,
    )


def resolve_target(fixture_dir: Path, manifest: dict[str, Any]) -> str:
    target = manifest.get("target")
    if target is None:
        raise ValueError("expected.yaml missing 'target'")
    target_type = manifest.get("target_type", "")
    if target_type in ("local_code", "repository"):
        # Resolve relative to fixture dir.
        candidate = (fixture_dir / target).resolve()
        if candidate.exists():
            return str(candidate)
    return str(target)


def run_strix(
    target: str, scan_mode: str, run_dir: Path, extra_args: list[str]
) -> tuple[int, float]:
    cmd = ["strix", "-n", "-t", target, "-m", scan_mode] + extra_args
    print(f"[runner] {' '.join(cmd)}")
    start = time.time()
    proc = subprocess.run(cmd, cwd=run_dir, env=os.environ.copy())
    duration = time.time() - start
    return proc.returncode, duration


_SEVERITY_LINE = re.compile(r"^\*\*Severity:\*\*\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_CATEGORY_LINE = re.compile(r"^\*\*Category:\*\*\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_CWE_LINE = re.compile(r"\bCWE[- ]?(\d+)\b", re.IGNORECASE)
_FILE_LINE = re.compile(
    r"^\*\*(?:File|Affected\s+File|Location)[:\*\s]*\s*([^\s:]+)(?::(\d+))?",
    re.IGNORECASE | re.MULTILINE,
)
_ENDPOINT_LINE = re.compile(
    r"^\*\*(?:Endpoint|URL|Path)[:\*\s]*\s*([^\s]+)", re.IGNORECASE | re.MULTILINE
)
_PORT_LINE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)


def parse_finding_md(md_text: str) -> Found:
    title = ""
    for line in md_text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    sev = _SEVERITY_LINE.search(md_text)
    cat = _CATEGORY_LINE.search(md_text)
    cwe = _CWE_LINE.search(md_text)
    file_m = _FILE_LINE.search(md_text)
    endpoint_m = _ENDPOINT_LINE.search(md_text)
    port_m = _PORT_LINE.search(md_text)
    line_no = int(file_m.group(2)) if file_m and file_m.group(2) else None
    return Found(
        title=title or "(untitled)",
        category=cat.group(1) if cat else None,
        cwe=("CWE-" + cwe.group(1)) if cwe else None,
        file=file_m.group(1) if file_m else None,
        line=line_no,
        endpoint=endpoint_m.group(1) if endpoint_m else None,
        port=int(port_m.group(1)) if port_m else None,
        severity=sev.group(1) if sev else None,
    )


def collect_findings(run_dir: Path) -> list[Found]:
    """Find the most recent strix_runs/*/vulnerabilities/ dir and parse all md files."""
    runs_root = run_dir / "strix_runs"
    if not runs_root.exists():
        return []
    # Pick the run dir most recently modified (we just created it).
    candidates = [p for p in runs_root.iterdir() if p.is_dir()]
    if not candidates:
        return []
    run = max(candidates, key=lambda p: p.stat().st_mtime)
    vulns_dir = run / "vulnerabilities"
    if not vulns_dir.exists():
        # Fallback: prefer vulnerabilities.json once §5 lands.
        vulns_json = run / "vulnerabilities.json"
        if vulns_json.exists():
            try:
                data = json.loads(vulns_json.read_text())
                if isinstance(data, list):
                    return [
                        Found(
                            title=item.get("title", "(untitled)"),
                            category=item.get("category"),
                            cwe=item.get("cwe"),
                            file=item.get("file"),
                            line=item.get("line"),
                            endpoint=item.get("endpoint"),
                            port=item.get("port"),
                            severity=item.get("severity"),
                            raw=item,
                        )
                        for item in data
                    ]
            except Exception:
                pass
        return []
    findings: list[Found] = []
    for md in sorted(vulns_dir.glob("*.md")):
        try:
            findings.append(parse_finding_md(md.read_text(encoding="utf-8", errors="replace")))
        except Exception as e:
            print(f"[runner] warn: could not parse {md}: {e}", file=sys.stderr)
    return findings


def collect_stats(run_dir: Path) -> dict[str, Any]:
    """Best-effort pull of cost/iterations from events.jsonl."""
    runs_root = run_dir / "strix_runs"
    if not runs_root.exists():
        return {}
    candidates = [p for p in runs_root.iterdir() if p.is_dir()]
    if not candidates:
        return {}
    run = max(candidates, key=lambda p: p.stat().st_mtime)
    events_path = run / "events.jsonl"
    cost = 0.0
    iterations = 0
    if events_path.exists():
        for line in events_path.read_text().splitlines():
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if "iteration" in ev or ev.get("type", "").startswith("agent.iteration"):
                iterations += 1
            payload = ev.get("payload") or {}
            for key in ("cost", "total_cost", "usd"):
                if key in payload and isinstance(payload[key], (int, float)):
                    cost = max(cost, float(payload[key]))
    return {
        "cost_usd": round(cost, 4) if cost else None,
        "iterations": iterations or None,
        "run_dir": str(run),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("fixture", help="path to fixture directory")
    parser.add_argument(
        "--scan-mode", default="standard", choices=["quick", "standard", "deep"]
    )
    parser.add_argument("--output", help="write JSON result here (default: stdout)")
    parser.add_argument(
        "--keep-up",
        action="store_true",
        help="don't tear docker compose down after the scan",
    )
    parser.add_argument(
        "--strix-arg",
        action="append",
        default=[],
        help="extra arg to pass to strix (repeatable)",
    )
    args = parser.parse_args()

    fixture_dir = Path(args.fixture).resolve()
    if not fixture_dir.is_dir():
        print(f"error: fixture dir not found: {fixture_dir}", file=sys.stderr)
        return 2

    if not shutil.which("strix"):
        print("error: 'strix' binary not on PATH", file=sys.stderr)
        return 2

    manifest, expected = parse_expected(fixture_dir)

    # Run from a clean tmp working dir so strix_runs/ doesn't pollute the fixture.
    work_root = fixture_dir / ".strix-bench-work"
    work_root.mkdir(exist_ok=True)
    # Each invocation gets its own subdir to keep multiple runs separable.
    run_dir = work_root / f"run-{int(time.time())}"
    run_dir.mkdir()

    docker_running = False
    try:
        docker_running = docker_up(fixture_dir, manifest)
        target = resolve_target(fixture_dir, manifest)
        exit_code, duration = run_strix(
            target, args.scan_mode, run_dir, args.strix_arg
        )
        findings = collect_findings(run_dir)
        stats = collect_stats(run_dir)
    finally:
        if docker_running and not args.keep_up:
            docker_down(fixture_dir, manifest)

    result_score = score(expected, findings)

    result = {
        "fixture": str(fixture_dir.relative_to(Path.cwd()))
        if str(fixture_dir).startswith(str(Path.cwd()))
        else str(fixture_dir),
        "target": target,
        "target_type": manifest.get("target_type"),
        "scan_mode": args.scan_mode,
        "model": os.environ.get("STRIX_LLM"),
        "strix_exit_code": exit_code,
        "duration_seconds": round(duration, 1),
        **stats,
        **{k: v for k, v in asdict(result_score).items() if k != "matches"},
        "matches": result_score.matches,
    }

    out = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"[runner] wrote {args.output}")
        # Still print a one-line summary to stdout.
        print(
            f"recall={result_score.recall} precision={result_score.precision} "
            f"matched={result_score.matched_count}/{result_score.expected_count} "
            f"duration={result['duration_seconds']}s cost={result.get('cost_usd')}"
        )
    else:
        print(out)
    return 0 if result_score.recall > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
