"""Semgrep CLI wrapper (Phase 7.1).

Shells out to `semgrep --json --config <rules>` and parses the
output into our `SastFinding` shape. Two design constraints:

  1. **Graceful degradation when Semgrep isn't installed.**
     `is_semgrep_available()` checks `semgrep --version` exit code.
     When False, `run_semgrep()` returns `SemgrepResult(status=
     "unavailable", ...)` rather than raising — the LLM-facing tool
     can then return `partial` with a clear "install semgrep" hint
     instead of erroring out the scan.

  2. **Test-injectable.** `run_semgrep` accepts a `runner` callable
     so unit tests can inject a fake subprocess wrapper returning
     canned JSON. Tests don't need Semgrep installed.

Output mapping. Semgrep's JSON shape is:

    {"results": [{"check_id": "...", "path": "...",
                  "start": {"line": N}, "end": {"line": M},
                  "extra": {"message": "...", "severity": "ERROR",
                             "metadata": {"cwe": ["CWE-89"], ...}}}]}

We translate to:

    SastFinding(
        rule_id, file, line_start, line_end, message,
        severity (one of info|low|medium|high|critical),
        cwe (str or None), category (semantic, derived from CWE),
        language, raw (full Semgrep dict for debug)
    )

Severity mapping. Semgrep uses ERROR / WARNING / INFO. We map:
  * ERROR    → high     (most rules; SQLi, RCE, hardcoded creds)
  * WARNING  → medium   (style + risk-suspicious patterns)
  * INFO     → low      (advisory)
The actual emit-time severity gets calibrated further by
`calibrate.py` (route-reachability bump, test-file demote).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


logger = logging.getLogger(__name__)


# Path to the bundled custom rule corpus. Resolved at import time.
RULES_DIR = Path(__file__).parent / "rules"
VIBE_CODED_RULES_DIR = RULES_DIR / "vibe_coded"


# CWE → semantic category, matching `benchmarks/per_target/runner.py`'s
# scoring map so SAST findings score against the same expected.yaml
# categories as DAST findings. Keep additions narrow.
_CWE_TO_CATEGORY: dict[str, str] = {
    "CWE-22": "path_traversal",
    "CWE-78": "cmd_injection",
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-90": "ldap_injection",
    "CWE-94": "cmd_injection",
    "CWE-200": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-269": "authz",
    "CWE-285": "authz",
    "CWE-287": "auth",
    "CWE-295": "crypto",
    "CWE-306": "authz",
    "CWE-326": "crypto",
    "CWE-327": "crypto",
    "CWE-338": "crypto",
    "CWE-345": "ssrf",
    # Canonical SSRF CWE; was missing — caused dynamic-urllib-use
    # findings on flask-vuln to be categorized as "sast" instead of
    # "ssrf". 2026-05-20.
    "CWE-918": "ssrf",
    # CWE-939 (Improper URL Handler Authz) is what semgrep's
    # `python.lang.security.audit.dynamic-urllib-use-detected` rule
    # reports — treat as ssrf for category-routing purposes since
    # the rule fires on the exact urllib.urlopen(user_input) shape
    # that's classic SSRF.
    "CWE-939": "ssrf",
    "CWE-347": "jwt",
    "CWE-352": "csrf",
    "CWE-400": "misconfig",
    "CWE-434": "misconfig",
    "CWE-489": "misconfig",
    "CWE-502": "deserialization",
    "CWE-601": "open_redirect",
    "CWE-611": "xxe",
    "CWE-614": "misconfig",
    "CWE-639": "idor",
    "CWE-643": "xpath_injection",
    "CWE-732": "misconfig",
    "CWE-798": "info_disclosure",
    "CWE-862": "authz",
    "CWE-915": "mass_assignment",
    "CWE-916": "crypto",
    "CWE-918": "ssrf",
    "CWE-922": "info_disclosure",
    "CWE-943": "sqli",
    "CWE-1004": "misconfig",
    "CWE-1333": "misconfig",
    "CWE-1336": "ssti",
}


_SEMGREP_TO_TIER: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


@dataclass
class SastFinding:
    """One SAST finding, normalised across analysers (Semgrep today;
    other engines could be added later behind the same shape)."""
    rule_id: str
    file: str               # path relative to repo root
    line_start: int
    line_end: int
    message: str
    severity: str           # info|low|medium|high|critical
    cwe: str | None = None
    category: str | None = None  # canonical category (matches DAST scoring)
    language: str | None = None
    metadata: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "message": self.message,
            "severity": self.severity,
            "cwe": self.cwe,
            "category": self.category,
            "language": self.language,
            "metadata": dict(self.metadata),
        }


@dataclass
class SemgrepResult:
    """Aggregate result of one Semgrep invocation."""
    status: str             # "ok" | "unavailable" | "error" | "partial"
    findings: list[SastFinding] = field(default_factory=list)
    error: str | None = None
    files_scanned: int = 0
    rules_run: int = 0
    config_paths: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------


def is_semgrep_available(*, run: Callable[..., Any] | None = None) -> bool:
    """Return True iff `semgrep --version` exits 0.

    Test-injectable via `run` (must accept the same args as
    `subprocess.run`)."""
    runner = run or subprocess.run
    if shutil.which("semgrep") is None and run is None:
        # Fast path — binary not on PATH at all.
        return False
    try:
        proc = runner(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


# iter-Q5.32 — file extensions we use as a stand-in for "language is
# present in this target". A few representative files per extension
# are enough; we don't need to count every file. The detection walks
# at most _LANG_PROBE_MAX_FILES files and stops as soon as a hit
# lands, so even a 50k-file repo costs <100ms.
_LANG_EXT_MAP: dict[str, str] = {
    ".java": "java",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".rs": "rust",
}

_LANG_PROBE_MAX_FILES: int = 5000

# Per-language semgrep registry packs. Picked for OWASP-tier coverage
# of the dominant taint sinks per ecosystem. Java in particular gets
# the `p/findsecbugs` port for the high-recall Java-specific
# patterns — without it, semgrep on a Java corpus tops out around
# 1-2% Youden (OWASP Benchmark v1.2, iter-Q5.27→Q5.31c measurement)
# because the multi-language packs only carry shallow Java coverage.
_LANG_PACKS: dict[str, list[str]] = {
    # iter-Q5.32 — Java packs. `p/java` is semgrep's flagship Java
    # pack (~150 rules across the OWASP Top-10 categories plus
    # Java-specific sinks: JDBC, JNDI, ProcessBuilder, XMLDecoder,
    # ObjectInputStream). `p/findsecbugs` is the semgrep port of the
    # SpotBugs FindSecBugs rules — strong on deserialization, LDAP
    # injection, XPath injection, weak crypto. `p/cwe-top-25` adds
    # the cross-language CWE-top-25 coverage with Java-specific rules.
    "java": ["p/java", "p/findsecbugs", "p/cwe-top-25"],
    # JS / TS share the same packs (semgrep treats both via the
    # javascript ecosystem; ts rules live alongside js).
    "javascript": ["p/javascript", "p/nodejsscan"],
    "typescript": ["p/typescript", "p/javascript"],
    # Python — semgrep has strong native coverage. `p/python` is
    # the language-tag pack; `p/django` + `p/flask` are framework
    # packs but require detection of those frameworks (out of
    # scope for this iter — operators can wire via extra_configs).
    "python": ["p/python"],
    "go": ["p/golang", "p/gosec"],
    "ruby": ["p/ruby"],
    "php": ["p/php"],
    "csharp": ["p/csharp"],
    "kotlin": ["p/kotlin"],
    "scala": ["p/scala"],
    "rust": [],  # no canonical semgrep Rust pack yet
    "swift": [],
}


def _detect_languages(targets: list[str]) -> set[str]:
    """iter-Q5.32 — walk `targets` and return the set of source
    languages present. Used to drive `_resolve_configs`'s pack
    selection so a Java-only corpus gets `p/java + p/findsecbugs`
    (vs the pre-Q5.32 hardcoded `p/javascript` that was tuned for
    flask-vuln + sast-vibe and useless on BenchmarkJava).

    Caps the walk at `_LANG_PROBE_MAX_FILES` to bound the cost on
    monorepos. Returns the empty set if no recognized source files
    are found — caller falls back to a language-agnostic default.
    """
    found: set[str] = set()
    seen = 0
    for t in targets:
        try:
            p = Path(t).resolve()
        except (OSError, ValueError):
            continue
        if p.is_file():
            ext = p.suffix.lower()
            lang = _LANG_EXT_MAP.get(ext)
            if lang:
                found.add(lang)
            seen += 1
            continue
        if not p.is_dir():
            continue
        for child in p.rglob("*"):
            if seen >= _LANG_PROBE_MAX_FILES:
                return found
            if not child.is_file():
                continue
            seen += 1
            ext = child.suffix.lower()
            lang = _LANG_EXT_MAP.get(ext)
            if lang:
                found.add(lang)
    return found


def _resolve_configs(
    configs: list[str | Path] | None,
    targets: list[str] | None = None,
) -> list[str]:
    """Resolve config arguments into Semgrep `--config` values.

    iter-Q5.32: language-aware defaults. Always-on packs:
      * Bundled `vibe-coded` rules (in-house, fixture-tuned).
      * `p/owasp-top-ten` — CWE-mapped injection-class, multi-lang.
      * `p/security-audit` — defense-in-depth: deserialization /
        SSRF / open-redirect / pickle / dynamic-urllib — categories
        owasp-top-ten misses.

    Plus per-language packs (from `_LANG_PACKS`) for every language
    detected in `targets`. On a Java-only corpus, that adds
    `p/java + p/findsecbugs + p/cwe-top-25` — the load-bearing fix
    for the iter-Q5.27→Q5.31c 1.42% Youden floor. Expected uplift
    to 15-25% Youden on OWASP Benchmark v1.2.

    When `targets` is None or empty, falls back to the legacy
    multi-language default (vibe + owasp-top-ten + security-audit +
    javascript) so callers that haven't been updated keep working.

    Historic notes (kept for context — these measurements drove the
    legacy defaults):

      Live measurement on 2026-05-20 (flask-vuln fixture):
        * `p/owasp-top-ten` alone: 11 findings — sqli / cmd_injection
          / xss / crypto must_finds (4/10 recall).
        * `p/security-audit` alone: 6 findings — ssrf / deserialization
          / open_redirect (the OTHER must_find categories).
        * Adding both → ~all 10 must_find categories.

      iter-15-late (2026-05-21) — added `p/javascript` after sast-vibe
      caught template-literal SQLi + `Math.random()` insecure-random
      that owasp-top-ten + security-audit missed.

    Registry packs require internet + Semgrep's auth-by-default
    behaviour on first use; cached after that.
    """
    if configs is not None:
        # Explicit caller override — pass through verbatim, no
        # language probing. Preserves the test-seam + lets operators
        # force a specific config set.
        return [str(c) for c in configs]

    # iter-Q5.32 — language-aware default selection.
    out: list[str] = [
        str(VIBE_CODED_RULES_DIR),
        "p/owasp-top-ten",
        "p/security-audit",
    ]
    detected: set[str] = set()
    if targets:
        detected = _detect_languages(targets)
    if not detected:
        # Pre-Q5.32 default — preserved as the fallback so target
        # types that don't carry source files (e.g. caller passes an
        # empty repo, or `targets` is None) keep the legacy behavior.
        out.append("p/javascript")
        return out
    # Add the per-language packs for every detected language. Stable
    # ordering by sorted language name so the resolved config list
    # is reproducible across runs (test pinning + caching).
    for lang in sorted(detected):
        out.extend(_LANG_PACKS.get(lang, []))
    return out


def _normalise_finding(raw_result: dict, language_hint: str | None = None) -> SastFinding:
    """Convert one Semgrep JSON result entry into our SastFinding."""
    rule_id = str(raw_result.get("check_id") or "unknown")
    path = str(raw_result.get("path") or "")
    start = (raw_result.get("start") or {}).get("line") or 0
    end = (raw_result.get("end") or {}).get("line") or start
    extra = raw_result.get("extra") or {}
    message = str(extra.get("message") or "")
    sg_sev = str(extra.get("severity") or "WARNING").upper()
    severity = _SEMGREP_TO_TIER.get(sg_sev, "medium")
    metadata = dict(extra.get("metadata") or {})

    # CWE is sometimes a list, sometimes a string. Take first entry.
    cwe_field = metadata.get("cwe")
    cwe: str | None = None
    if isinstance(cwe_field, list) and cwe_field:
        cwe_raw = str(cwe_field[0])
    elif isinstance(cwe_field, str):
        cwe_raw = cwe_field
    else:
        cwe_raw = ""
    if cwe_raw:
        # Normalise to "CWE-NNN".
        if cwe_raw.upper().startswith("CWE-"):
            cwe = cwe_raw.upper().split(":", 1)[0].strip()
        elif cwe_raw.isdigit():
            cwe = f"CWE-{cwe_raw}"
        else:
            # "CWE-79: Cross-site Scripting" → "CWE-79"
            head = cwe_raw.split(":", 1)[0].strip().upper()
            cwe = head if head.startswith("CWE-") else None

    category = _CWE_TO_CATEGORY.get(cwe or "", None)

    return SastFinding(
        rule_id=rule_id,
        file=path,
        line_start=int(start),
        line_end=int(end),
        message=message,
        severity=severity,
        cwe=cwe,
        category=category,
        language=language_hint or _infer_language_from_path(path),
        metadata=metadata,
        raw=raw_result,
    )


_LANG_BY_EXT: dict[str, str] = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".go": "go", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".kt": "kotlin", ".swift": "swift",
}


def _infer_language_from_path(path: str) -> str | None:
    if not path:
        return None
    ext = Path(path).suffix.lower()
    return _LANG_BY_EXT.get(ext)


def run_semgrep(
    targets: list[str | Path] | str | Path,
    *,
    configs: list[str | Path] | None = None,
    timeout: int = 600,
    extra_args: list[str] | None = None,
    runner: Callable[..., Any] | None = None,
) -> SemgrepResult:
    """Run Semgrep against `targets` with `configs` rule packs.

    Args:
        targets: file or directory paths to analyse. Single path or
            list. Resolved to absolute strings before exec.
        configs: rule sources — directory paths, file paths, or
            registry refs like `"p/owasp-top-ten"`. Defaults to our
            bundled vibe-coded rules + the OWASP registry pack.
        timeout: hard wall-clock cap (seconds). Semgrep is fast but
            on monorepos can blow past 60s; default 600s.
        extra_args: extra CLI args appended verbatim. Use for
            `--exclude-rule`, `--severity`, `--max-target-bytes`,
            etc.
        runner: optional `subprocess.run`-compatible injection
            point for tests.

    Returns:
        `SemgrepResult`. `status` is:
          * "ok"          — Semgrep ran, exit 0 or 1 (1 = findings exist).
          * "unavailable" — Semgrep binary not on PATH.
          * "error"       — exec failure / non-finding non-zero exit.
          * "partial"     — Semgrep emitted parser-error rows; we
                            took the findings it produced anyway.
    """
    run = runner or subprocess.run
    if not is_semgrep_available(run=run):
        return SemgrepResult(
            status="unavailable",
            error=(
                "semgrep CLI not found on PATH. Install with "
                "`pip install semgrep` or visit "
                "https://semgrep.dev/docs/getting-started for "
                "system instructions."
            ),
        )

    if isinstance(targets, (str, Path)):
        target_list = [str(targets)]
    else:
        target_list = [str(t) for t in targets]
    if not target_list:
        return SemgrepResult(status="error", error="no targets supplied")

    # iter-Q5.32 — pass targets so language-aware pack selection can
    # fire. Without this, `_resolve_configs` falls back to the legacy
    # multi-lang default (javascript-biased), which is the bug we're
    # fixing.
    config_list = _resolve_configs(configs, targets=target_list)
    cmd = ["semgrep", "scan", "--json", "--metrics=off", "--quiet"]
    for c in config_list:
        cmd += ["--config", c]
    if extra_args:
        cmd += list(extra_args)
    cmd += target_list

    try:
        proc = run(
            cmd, capture_output=True, text=True, timeout=timeout,
            check=False, env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
    except subprocess.TimeoutExpired as e:
        return SemgrepResult(
            status="error",
            error=f"semgrep timed out after {timeout}s: {e}",
            config_paths=config_list,
        )
    except (FileNotFoundError, OSError) as e:
        return SemgrepResult(
            status="error",
            error=f"semgrep exec failed: {type(e).__name__}: {e}",
            config_paths=config_list,
        )

    # Semgrep exit codes (per docs):
    #   0 = ok, no findings
    #   1 = findings present (still success)
    #   2 = errors (parse failures etc.) but may include partial findings
    #   anything else = hard failure
    rc = getattr(proc, "returncode", -1)
    stdout = getattr(proc, "stdout", "") or ""
    stderr = getattr(proc, "stderr", "") or ""

    if rc not in (0, 1, 2):
        return SemgrepResult(
            status="error",
            error=(
                f"semgrep exited with code {rc}: "
                f"{stderr[:500] or stdout[:500]}"
            ),
            config_paths=config_list,
        )

    try:
        doc = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError as e:
        return SemgrepResult(
            status="error",
            error=f"semgrep produced invalid JSON: {e}",
            config_paths=config_list,
        )

    findings: list[SastFinding] = []
    for r in (doc.get("results") or []):
        if not isinstance(r, dict):
            continue
        try:
            findings.append(_normalise_finding(r))
        except Exception as e:  # noqa: BLE001
            logger.debug("sast: failed to parse semgrep result: %s", e,
                         exc_info=True)

    paths_scanned = doc.get("paths") or {}
    files_scanned = len(paths_scanned.get("scanned") or []) if isinstance(paths_scanned, dict) else 0

    status = "ok"
    if rc == 2 or doc.get("errors"):
        status = "partial"
    return SemgrepResult(
        status=status,
        findings=findings,
        files_scanned=files_scanned,
        rules_run=len(doc.get("rules") or []) if isinstance(doc.get("rules"), list) else 0,
        config_paths=config_list,
        error=None if status != "error" else (stderr[:500] or stdout[:500]),
    )
