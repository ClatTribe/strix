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
    """Single-target resolver. Kept for back-compat with all existing
    fixtures (`flask-vuln`, `juiceshop`, `sca-vuln-deps`)."""
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


def resolve_targets(
    fixture_dir: Path, manifest: dict[str, Any],
) -> list[tuple[str, str]]:
    """Multi-target resolver. Returns a list of (target_type, target)
    tuples. Three accepted manifest shapes:

      1. **Single-target legacy.** `target_type:` + `target:` → one
         tuple. Existing fixtures use this; nothing changes.

      2. **Paired-asset.** `target_type:` + `target:` (the primary)
         PLUS an `additional_targets:` list of `{type, target}` →
         multiple tuples. Path-typed targets (local_code / repository)
         are resolved relative to the fixture dir like the single-target
         path; URL / IP / domain targets pass through.

      3. **All-list.** `targets:` is a list of `{type, target}` →
         multiple tuples. No primary. Reserved for future fixtures
         that don't have an obvious primary asset.

    Examples:
      # legacy (single):
      target_type: web_application
      target: http://localhost:3000

      # paired (web + code):
      target_type: web_application
      target: http://localhost:3000
      additional_targets:
        - type: local_code
          target: src/

      # all-list:
      targets:
        - type: web_application
          target: http://localhost:3000
        - type: local_code
          target: src/
    """
    out: list[tuple[str, str]] = []

    def resolve_one(tt: str, t: str) -> str:
        if tt in ("local_code", "repository"):
            cand = (fixture_dir / t).resolve()
            if cand.exists():
                return str(cand)
        return str(t)

    if isinstance(manifest.get("targets"), list) and manifest["targets"]:
        for entry in manifest["targets"]:
            if not isinstance(entry, dict):
                continue
            tt = (entry.get("type") or "").strip()
            tg = entry.get("target")
            if tt and tg:
                out.append((tt, resolve_one(tt, tg)))
        if out:
            return out

    primary_type = (manifest.get("target_type") or "").strip()
    primary_target = manifest.get("target")
    if primary_type and primary_target is not None:
        out.append((primary_type, resolve_one(primary_type, primary_target)))

    for entry in (manifest.get("additional_targets") or []):
        if not isinstance(entry, dict):
            continue
        tt = (entry.get("type") or "").strip()
        tg = entry.get("target")
        if tt and tg:
            out.append((tt, resolve_one(tt, tg)))

    if not out:
        raise ValueError(
            "expected.yaml missing 'target' / 'target_type' (or 'targets' list)"
        )
    return out


def run_strix(
    targets: str | list[tuple[str, str]],
    scan_mode: str,
    run_dir: Path,
    extra_args: list[str],
) -> tuple[int, float]:
    """Invoke the strix CLI.

    `targets` accepts either:
      * a bare string (legacy single-target path used by every fixture
        before the paired-asset benchmark), OR
      * a list of (target_type, target) tuples — passed as repeated
        `-t` flags. The CLI accepts `--target` / `-t` with
        `action="append"`, so multiple flags route into
        `LeadAgent`'s scan_config and the per-target-type catalog
        filter unions across all of them.
    """
    # Use the `<type>:<value>` prefix on every target so strix's
    # per-target-type catalog filter sees the right type. The plain
    # URL form defaults to `web_application` regardless of the
    # fixture manifest's `target_type:` — breaks api/domain/ip_address
    # benchmarks silently (they ran with the web_application catalog).
    if isinstance(targets, str):
        target_args = ["-t", targets]
        printable = targets
    else:
        target_args = []
        printable_parts: list[str] = []
        for tt, t in targets:
            # When the target already has a recognised <type>: prefix,
            # leave it alone. Otherwise prepend the manifest's tt.
            type_aware = (
                t if any(t.startswith(f"{p}:") for p in (
                    "api", "web_application", "repository", "local_code",
                    "ip_address", "domain", "cloud_account", "container_image",
                )) else (f"{tt}:{t}" if tt else t)
            )
            target_args += ["-t", type_aware]
            printable_parts.append(type_aware)
        printable = " + ".join(printable_parts)
    cmd = ["strix", "-n", *target_args, "-m", scan_mode] + extra_args
    print(f"[runner] {' '.join(cmd)}")
    start = time.time()
    proc = subprocess.run(cmd, cwd=run_dir, env=os.environ.copy())
    duration = time.time() - start
    print(f"[runner] target(s): {printable}  duration={duration:.1f}s")
    return proc.returncode, duration


_SEVERITY_LINE = re.compile(r"^\*\*Severity:\*\*\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_CATEGORY_LINE = re.compile(r"^\*\*Category:\*\*\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_CWE_LINE = re.compile(r"\bCWE[- ]?(\d+)\b", re.IGNORECASE)

_FILE_EXTS = r"py|js|ts|tsx|jsx|java|go|rb|php|c|cpp|h|hpp|cs|rs|yml|yaml|toml|json"

# Strix uses several patterns to mention file:line; we try each in order.
# (1) Strict bold field — only when the keyword is *immediately* followed by colon.
#     "**File:** app.py:50"  /  "**Affected File:** src/app.py"
_FILE_PATTERNS = [
    re.compile(
        rf"^\*\*(?:File|Affected\s+File)\*\*\s*:\s*`?([\w\-./]+\.(?:{_FILE_EXTS}))`?(?::(\d+))?",
        re.IGNORECASE | re.MULTILINE,
    ),
    # (2) "**Location N:** `app.py` (line 55)" — strix's actual format for code findings.
    re.compile(
        rf"^\*\*Location\s+\d+:\*\*\s*`?([\w\-./]+\.(?:{_FILE_EXTS}))`?\s*\(\s*lines?\s+(\d+)",
        re.IGNORECASE | re.MULTILINE,
    ),
    # (3) "Vulnerable Code Snippet (app.py:117-119):" — first line of the affected-code block.
    re.compile(
        rf"(?:Vulnerable\s+Code\s+Snippet|Code\s+Snippet|Affected\s+Code)\s*\(\s*([\w\-./]+\.(?:{_FILE_EXTS}))\s*:\s*(\d+)",
        re.IGNORECASE,
    ),
    # (4) Prose: "in `app.py` (lines 61-68)" / "in `app.py` around lines 65-66".
    re.compile(
        rf"\bin\s+`([\w\-./]+\.(?:{_FILE_EXTS}))`\s*(?:\(|around\s+)?lines?\s+(\d+)",
        re.IGNORECASE,
    ),
    # (5) Reverse prose: "(lines 61-68) of `app.py`" / "lines 50-55 in `app.py`".
    re.compile(
        rf"lines?\s+(\d+)(?:-\d+)?\s*\)?\s+(?:of|in)\s+`([\w\-./]+\.(?:{_FILE_EXTS}))`",
        re.IGNORECASE,
    ),
    # (6) "on line N of `app.py`" / "at line N in `app.py`".
    re.compile(
        rf"(?:on|at)\s+lines?\s+(\d+)\s+(?:of|in)\s+`([\w\-./]+\.(?:{_FILE_EXTS}))`",
        re.IGNORECASE,
    ),
    # (7) Bare "app.py:50" anywhere.
    re.compile(
        rf"\b([\w\-./]+\.(?:{_FILE_EXTS}))\s*:\s*(\d+)\b",
        re.IGNORECASE,
    ),
    # (8) Last resort — file mentioned anywhere, no line. Better than nothing.
    re.compile(
        rf"`([\w\-./]+\.(?:{_FILE_EXTS}))`",
        re.IGNORECASE,
    ),
]
# Patterns 5 and 6 capture (line, file) — reverse of the others. The parser
# detects this by index.
_FILE_PATTERN_LINE_FIRST = {4, 5}
_ENDPOINT_FIELD = re.compile(
    r"^\*\*(?:Endpoint|URL|Path)[:\*\s]*\s*([^\s]+)", re.IGNORECASE | re.MULTILINE
)
# Strix often puts the endpoint in the title or in a "## Endpoint" / Method line.
_ENDPOINT_INLINE = re.compile(r"\b(/[\w\-./?=&%]+)", re.MULTILINE)
_PORT_LINE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)


# Map CWE → semantic category (matches the enum in roadmap §1).
_CWE_TO_CATEGORY = {
    "CWE-22": "path_traversal",
    "CWE-78": "cmd_injection",
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-94": "cmd_injection",
    "CWE-200": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-269": "authz",
    "CWE-285": "authz",
    "CWE-287": "auth",
    "CWE-306": "misconfig",
    "CWE-319": "crypto",
    "CWE-326": "crypto",
    "CWE-327": "crypto",
    "CWE-347": "jwt",
    "CWE-352": "csrf",
    "CWE-434": "misconfig",
    "CWE-489": "misconfig",
    "CWE-502": "deserialization",
    "CWE-548": "misconfig",
    "CWE-601": "open_redirect",
    "CWE-611": "xxe",
    "CWE-639": "idor",
    "CWE-732": "misconfig",
    "CWE-798": "info_disclosure",
    "CWE-862": "authz",
    "CWE-918": "ssrf",
    "CWE-943": "sqli",
    "CWE-1104": "misconfig",
    "CWE-1278": "misconfig",
    "CWE-1390": "subdomain_takeover",
}


# Title-keyword → category, fallback when CWE isn't present.
_TITLE_KEYWORDS = [
    ("sql injection", "sqli"),
    ("nosql injection", "sqli"),
    ("command injection", "cmd_injection"),
    ("os command", "cmd_injection"),
    ("rce", "cmd_injection"),
    ("remote code execution", "cmd_injection"),
    ("xss", "xss"),
    ("cross-site scripting", "xss"),
    ("ssrf", "ssrf"),
    ("server-side request forgery", "ssrf"),
    ("idor", "idor"),
    ("insecure direct object", "idor"),
    ("path traversal", "path_traversal"),
    ("directory traversal", "path_traversal"),
    ("open redirect", "open_redirect"),
    ("deserialization", "deserialization"),
    ("pickle", "deserialization"),
    ("hardcoded", "info_disclosure"),
    ("secret", "info_disclosure"),
    ("api key", "info_disclosure"),
    ("md5", "crypto"),
    ("weak hash", "crypto"),
    ("insecure hash", "crypto"),
    ("weak crypto", "crypto"),
    ("authorization", "authz"),
    ("missing auth", "authz"),
    ("broken access control", "authz"),
    ("authentication", "auth"),
    ("session", "auth"),
    ("jwt", "jwt"),
    ("csrf", "csrf"),
    ("xxe", "xxe"),
    ("subdomain takeover", "subdomain_takeover"),
    ("graphql", "graphql"),
    ("oauth", "oauth"),
    ("cors", "cors"),
]


def _infer_category(title: str | None, cwe: str | None) -> str | None:
    if cwe and cwe.upper() in _CWE_TO_CATEGORY:
        return _CWE_TO_CATEGORY[cwe.upper()]
    if title:
        t = title.lower()
        for kw, cat in _TITLE_KEYWORDS:
            if kw in t:
                return cat
    return None


def parse_finding_md(md_text: str) -> Found:
    title = ""
    for line in md_text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    sev = _SEVERITY_LINE.search(md_text)
    cat_field = _CATEGORY_LINE.search(md_text)
    cwe_m = _CWE_LINE.search(md_text)
    cwe_value = ("CWE-" + cwe_m.group(1)) if cwe_m else None

    # File:line — try each pattern in order; first hit wins.
    # Patterns marked in _FILE_PATTERN_LINE_FIRST capture (line, file) instead of (file, line).
    file_val: str | None = None
    line_val: int | None = None
    for idx, pat in enumerate(_FILE_PATTERNS):
        m = pat.search(md_text)
        if not m:
            continue
        if idx in _FILE_PATTERN_LINE_FIRST:
            line_val = int(m.group(1))
            file_val = m.group(2)
        else:
            file_val = m.group(1)
            line_val = int(m.group(2)) if m.lastindex and m.lastindex >= 2 and m.group(2) else None
        break

    # Endpoint — top-level field if present, otherwise infer from the title's first /path token.
    endpoint_m = _ENDPOINT_FIELD.search(md_text)
    if endpoint_m:
        endpoint_val: str | None = endpoint_m.group(1)
    else:
        title_endpoint = _ENDPOINT_INLINE.search(title or "")
        endpoint_val = title_endpoint.group(1) if title_endpoint else None

    port_m = _PORT_LINE.search(md_text)
    category = cat_field.group(1) if cat_field else _infer_category(title, cwe_value)

    return Found(
        title=title or "(untitled)",
        category=category,
        cwe=cwe_value,
        file=file_val,
        line=line_val,
        endpoint=endpoint_val,
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


def _oss_tool_check(name: str, args: list[str], timeout: int = 180,
                    cwd: Path | None = None) -> tuple[int | None, str]:
    """Run an OSS scanner and return (finding_count, note).

    Returns (None, reason) when the tool errored, isn't installed, or
    timed out. Returns (n, "") on success, where n is the raw
    finding count parsed from the tool's JSON output.

    This is best-effort and never raises — a partial floor (e.g. only
    semgrep + trivy succeeding) is more useful than no floor data.
    """
    if not shutil.which(name):
        return None, f"{name} not on PATH"
    try:
        r = subprocess.run(
            args, capture_output=True, timeout=timeout, cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return None, f"{name} timed out after {timeout}s"
    except Exception as e:
        return None, f"{name}: {type(e).__name__}: {e}"
    # Per-tool exit-code convention:
    #   semgrep: 0 = no findings, 1 = findings emitted (NOT an error)
    #   trivy:   0 = success
    #   grype:   0 = success
    #   osv-scanner: 0 = no vulns, 1 = vulns found
    #   checkov: 0 = no fails, 1 = fails found, 2 = error
    if r.returncode not in (0, 1):
        return None, f"{name} exit={r.returncode}"
    try:
        d = json.loads(r.stdout or b"{}")
    except json.JSONDecodeError as e:
        return None, f"{name}: stdout not JSON ({e})"
    if name == "semgrep":
        return len(d.get("results", []) or []), ""
    if name == "trivy":
        # Sum HIGH+CRITICAL vulns across all Results.
        n = sum(len(rr.get("Vulnerabilities") or [])
                for rr in (d.get("Results") or []))
        return n, ""
    if name == "grype":
        matches = d.get("matches", []) or []
        hc = [m for m in matches
              if (m.get("vulnerability") or {}).get("severity", "").lower()
                  in ("high", "critical")]
        return len(hc), ""
    if name == "osv-scanner":
        n = 0
        for rr in d.get("results", []) or []:
            for p in rr.get("packages", []) or []:
                n += len(p.get("vulnerabilities", []) or [])
        return n, ""
    if name == "checkov":
        if isinstance(d, list):
            return sum(len((x.get("results") or {}).get("failed_checks", []))
                       for x in d if isinstance(x, dict)), ""
        return len((d.get("results") or {}).get("failed_checks", [])), ""
    return None, f"unknown tool {name}"


def compute_oss_floor(fixture_dir: Path, target_type: str | None) -> dict[str, Any]:
    """Compute the OSS-tool finding floor for a fixture.

    For code/repo fixtures, runs semgrep (p/python+p/javascript+p/security-audit),
    trivy fs (HIGH+CRITICAL), grype dir (HIGH+CRITICAL), osv-scanner (recursive),
    and checkov (all frameworks). Returns per-tool counts plus a naive_sum
    upper-bound and a `backends_present` map.

    For non-source target_types (api, ip_address, domain, container_image),
    returns a short stub indicating the floor doesn't apply directly to the
    fixture root.

    Best-effort: missing binaries, timeouts, and parse errors all degrade
    gracefully — every tool gets recorded as either `count: int` or
    `note: str` describing why it didn't run.

    Why this exists: R1 (2026-05-19) ran the full per_target baseline with
    every OSS scanner backend missing from PATH, producing data that
    measured "strix LLM with no scanners" instead of strix-with-scanners.
    This helper guarantees every future baseline records the OSS floor
    alongside strix's numbers — if `oss_floor.naive_sum > strix_found_count`
    on a code fixture, the run is signalling that the LLM layer is adding
    negative value vs a $0 OSS pipeline.
    """
    source_types = {"local_code", "repository", "web+code", "code"}
    if target_type not in source_types:
        return {
            "applicable": False,
            "reason": f"target_type={target_type!r} — OSS scanners don't "
                      f"map directly to the fixture root",
        }

    p = str(fixture_dir)
    tools: dict[str, dict[str, Any]] = {}
    for tname, targs, timeout in (
        ("semgrep", [
            "semgrep", "--config", "p/python",
            "--config", "p/javascript",
            "--config", "p/security-audit",
            "--json", "--quiet", p,
        ], 180),
        ("trivy", [
            "trivy", "fs", "--quiet",
            "--severity", "HIGH,CRITICAL",
            "--format", "json", p,
        ], 120),
        ("grype", ["grype", f"dir:{p}", "-o", "json", "--quiet"], 120),
        ("osv-scanner", [
            "osv-scanner", "scan", "source", "-r",
            "--format=json", p,
        ], 120),
        ("checkov", [
            "checkov", "-d", p, "--quiet", "--compact",
            "-o", "json", "--skip-download",
        ], 300),
    ):
        n, note = _oss_tool_check(tname, targs, timeout=timeout)
        if n is None:
            tools[tname] = {"count": None, "note": note}
        else:
            tools[tname] = {"count": n}
    backends_present = {
        t: shutil.which(t) is not None
        for t in ("semgrep", "trivy", "grype", "osv-scanner", "checkov")
    }
    naive_sum = sum(
        v["count"] for v in tools.values()
        if isinstance(v.get("count"), int)
    )
    return {
        "applicable": True,
        "tools": tools,
        "backends_present": backends_present,
        "naive_sum": naive_sum,
        "note": (
            "naive_sum over-counts duplicates across tools; treat as an "
            "upper bound on signature-detectable findings, not a precision "
            "comparison."
        ),
    }


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
    parser.add_argument(
        "--rescore",
        metavar="RUN_DIR",
        help=(
            "skip strix, re-score the existing strix_runs/ output under the given dir. "
            "Useful after a parser fix, or to regenerate baselines without paying the LLM cost."
        ),
    )
    parser.add_argument(
        "--skip-oss-floor",
        action="store_true",
        help=(
            "Skip the OSS-tool floor scan (semgrep / trivy / grype / "
            "osv-scanner / checkov). The floor is the bar strix has to "
            "beat — leaving it out hides whether the LLM layer is "
            "adding value. Only set this when you genuinely don't have "
            "the OSS binaries available and want a strix-only number."
        ),
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

    # Resolve all targets up-front. Single-target manifests yield a
    # one-element list; paired-asset manifests yield N elements. The
    # primary `target` field below stays a string for back-compat with
    # baseline result files that index it as a scalar.
    target_tuples = resolve_targets(fixture_dir, manifest)
    primary_target = target_tuples[0][1]
    primary_type = target_tuples[0][0]
    additional_targets = [
        {"type": tt, "target": t} for tt, t in target_tuples[1:]
    ]

    if args.rescore:
        # Skip strix entirely; just parse + score the existing run output.
        run_dir = Path(args.rescore).resolve()
        if not run_dir.exists():
            print(f"error: --rescore dir not found: {run_dir}", file=sys.stderr)
            return 2
        exit_code = 0
        duration = 0.0
        findings = collect_findings(run_dir)
        stats = collect_stats(run_dir)
    else:
        # Run from a clean tmp working dir so strix_runs/ doesn't pollute the fixture.
        work_root = fixture_dir / ".strix-bench-work"
        work_root.mkdir(exist_ok=True)
        # Each invocation gets its own subdir to keep multiple runs separable.
        run_dir = work_root / f"run-{int(time.time())}"
        run_dir.mkdir()

        docker_running = False
        try:
            docker_running = docker_up(fixture_dir, manifest)
            # Single target → still route through the typed-tuple path
            # so the `<type>:<value>` prefix lands in the CLI args.
            # Without this, single-target fixtures with target_type=api /
            # domain / ip_address etc. silently get the
            # web_application catalog (PR #333 fixed this for the
            # multi-target list path; the single-target string path
            # was missed).
            #
            # Paired → pass the (type, target) list so the CLI receives
            # repeated -t flags.
            run_targets: list[tuple[str, str]] = target_tuples
            exit_code, duration = run_strix(
                run_targets, args.scan_mode, run_dir, args.strix_arg
            )
            findings = collect_findings(run_dir)
            stats = collect_stats(run_dir)
        finally:
            if docker_running and not args.keep_up:
                docker_down(fixture_dir, manifest)

    result_score = score(expected, findings)

    # Compute the OSS-tool finding floor — the bar strix has to beat.
    # Skipped when --skip-oss-floor is set or when the target_type
    # doesn't have a meaningful source path to scan.
    target_type_resolved = primary_type or manifest.get("target_type")
    if args.skip_oss_floor:
        oss_floor = {"applicable": False, "reason": "--skip-oss-floor set"}
    else:
        try:
            oss_floor = compute_oss_floor(fixture_dir, target_type_resolved)
        except Exception as e:  # noqa: BLE001
            # Never let the floor scan break the benchmark run.
            oss_floor = {
                "applicable": False,
                "reason": f"compute_oss_floor raised {type(e).__name__}: {e}",
            }

    result = {
        "fixture": str(fixture_dir.relative_to(Path.cwd()))
        if str(fixture_dir).startswith(str(Path.cwd()))
        else str(fixture_dir),
        "target": primary_target,
        "target_type": target_type_resolved,
        "additional_targets": additional_targets,
        "scan_mode": args.scan_mode,
        "model": os.environ.get("STRIX_LLM"),
        "strix_exit_code": exit_code,
        "duration_seconds": round(duration, 1),
        **stats,
        **{k: v for k, v in asdict(result_score).items() if k != "matches"},
        "matches": result_score.matches,
        "oss_floor": oss_floor,
    }

    out = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"[runner] wrote {args.output}")
        # Still print a one-line summary to stdout. Includes the OSS
        # floor delta so the operator immediately sees whether the LLM
        # layer beat the $0 signature pipeline.
        floor_summary = ""
        if oss_floor.get("applicable"):
            ns = oss_floor.get("naive_sum")
            backends = oss_floor.get("backends_present") or {}
            missing = [t for t, present in backends.items() if not present]
            floor_summary = f" oss_naive_sum={ns}"
            if missing:
                floor_summary += f" missing_backends={','.join(missing)}"
        print(
            f"recall={result_score.recall} precision={result_score.precision} "
            f"matched={result_score.matched_count}/{result_score.expected_count} "
            f"duration={result['duration_seconds']}s cost={result.get('cost_usd')}"
            f"{floor_summary}"
        )
    else:
        print(out)
    return 0 if result_score.recall > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
