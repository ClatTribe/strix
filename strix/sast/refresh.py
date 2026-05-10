"""SAST refresh CLI (roadmap §6a / Phase 7 dynamic).

Keeps Semgrep's registry-pack cache fresh. The registry packs
(`p/owasp-top-ten`, `p/javascript`, `p/python`, ...) are
server-maintained by r2c and update continuously; running
`semgrep --update` pulls the latest pack contents into the local
Semgrep cache so subsequent `scan_sast` invocations use them.

Usage:
    python -m strix.sast.refresh           # refresh registry
    python -m strix.sast.refresh --status  # show local rule + bundled-rule counts

Designed to be run alongside `python -m strix.threat_intel.refresh`
on a daily / hourly cron.

What this DOESN'T do (honest):

  * Update strix's bundled `vibe_coded/` rules. Those are
    code-shipped — adding rules is a PR. A future iteration
    could pull from a `strix-rules` community repo on a similar
    schedule, but that needs the corpus to exist first.
  * Validate rules against a target. `semgrep --update` only
    refreshes the local cache — actual rule execution happens
    in `scan_sast` per scan.

Exit codes:
  0 — refresh succeeded
  1 — semgrep CLI not available OR update failed
  2 — bad arguments
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

from strix.sast.semgrep_runner import (
    VIBE_CODED_RULES_DIR,
    is_semgrep_available,
)


def _bundled_rule_count() -> int:
    """Count YAML files in the bundled `vibe_coded/` rule dir."""
    if not VIBE_CODED_RULES_DIR.exists():
        return 0
    return len(list(VIBE_CODED_RULES_DIR.glob("*.yml")))


def refresh_semgrep_registry(
    *,
    timeout: int = 120,
    runner: Callable | None = None,
) -> dict:
    """Run `semgrep --update` to refresh the registry-pack cache.

    Returns:
        {"status": "ok" | "unavailable" | "error",
         "stdout": ..., "stderr": ..., "returncode": int}

    "unavailable" means semgrep CLI isn't on PATH; caller should
    surface "install semgrep" rather than a hard failure (same
    contract as `scan_sast`).
    """
    run = runner or subprocess.run
    if not is_semgrep_available(run=run):
        return {
            "status": "unavailable",
            "error": (
                "semgrep CLI not on PATH. Install via "
                "`pip install semgrep` or visit "
                "https://semgrep.dev/docs/getting-started."
            ),
            "stdout": "",
            "stderr": "",
            "returncode": -1,
        }
    try:
        proc = run(
            ["semgrep", "--update"],
            capture_output=True, text=True, timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "status": "error",
            "error": f"semgrep --update failed: {type(e).__name__}: {e}",
            "stdout": "", "stderr": "", "returncode": -1,
        }
    rc = getattr(proc, "returncode", -1)
    return {
        "status": "ok" if rc == 0 else "error",
        "error": None if rc == 0 else (
            (getattr(proc, "stderr", "") or
             getattr(proc, "stdout", ""))[:500]
        ),
        "stdout": (getattr(proc, "stdout", "") or "")[:1000],
        "stderr": (getattr(proc, "stderr", "") or "")[:1000],
        "returncode": rc,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="strix.sast.refresh",
        description=(
            "Refresh Semgrep's registry-pack cache. The bundled "
            "vibe_coded/ rules are code-shipped (manual update); "
            "this only refreshes the registry packs that ship "
            "with Semgrep."
        ),
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Print rule corpus status (bundled count, semgrep "
             "availability, registry-pack cache location) and exit.",
    )
    parser.add_argument(
        "--timeout", type=int, default=120,
        help="Hard timeout (seconds) for `semgrep --update`. "
             "Default 120s.",
    )
    args = parser.parse_args(argv)

    if args.status:
        print(f"Bundled vibe_coded/ rules: {_bundled_rule_count()}")
        print(f"Bundled rules dir: {VIBE_CODED_RULES_DIR}")
        print(f"Semgrep available: {is_semgrep_available()}")
        if shutil.which("semgrep"):
            print(f"Semgrep binary: {shutil.which('semgrep')}")
        return 0

    print("[refresh] running `semgrep --update` ...")
    result = refresh_semgrep_registry(timeout=args.timeout)
    print(f"  status={result['status']} returncode={result['returncode']}")
    if result.get("stdout"):
        print(f"  stdout: {result['stdout'][:300]}")
    if result["status"] != "ok":
        if result.get("error"):
            print(f"  error: {result['error']}", file=sys.stderr)
        return 1
    print(f"[refresh] bundled vibe_coded/ rules: "
          f"{_bundled_rule_count()} (manually maintained)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
