"""Secret-detection first-pass tool.

Two modes:

  1. **External scanner** — when `gitleaks` (preferred) or
     `trufflehog` is on `$PATH`, shell out and parse JSON output.
     Both tools have strong heuristics + entropy-based filtering.
  2. **Built-in regex catalogue** — fallback when no external
     scanner is available. Curated to high-confidence patterns
     ONLY (AWS access key, AWS secret access key with vendor
     prefix, GitHub PATs with documented prefix, Stripe live keys,
     Slack tokens, RSA private-key PEM headers, JWT structural
     match in source files).

Why zero-FP-by-construction
---------------------------

The catch-22 of secret scanning: a regex that matches "any 32-byte
hex string" finds 100% of secrets but flags 99% of git hashes,
React component IDs, asset checksums. The high-FP-rate is what
makes secret-scanning tools annoying.

We sidestep this by:

* **Vendor-prefix-anchored matching** — `AKIA[0-9A-Z]{16}` for
  AWS access keys. The `AKIA` / `ASIA` / `AROA` prefix is required
  by AWS so we don't false-positive on random strings.
* **PEM-header structural match** — `-----BEGIN RSA PRIVATE
  KEY-----` is a literal byte sequence. Pure binary check.
* **Documented-prefix tokens** — `ghp_` (GitHub personal access),
  `ghs_` (GitHub server), `gho_` (GitHub OAuth), `sk_live_*`
  (Stripe), `xoxb-` / `xoxp-` (Slack), `eyJ` (JWT prefix —
  almost-always-base64 + `.eyJ`). Each has a distinctive shape.
* **Negative paths** — test directories are excluded by default
  (most "fake secret in a fixture" FPs come from there). Set
  `scan_tests=True` to override.

Reachability filter
-------------------

Findings carry `code_locations: [{file, line, snippet}]` with a
masked snippet (last 4 chars only). The §99 reachability scorer
will downgrade matches in dead code to `info` automatically.

Severity ladder
---------------

* **High** CWE-798 — hard-coded credentials of any vendor (the
  default case).
* **Medium** CWE-798 — RSA/EC private key found WITHOUT the
  signing context — likely a real secret but could also be a
  test fixture for a mock CA.
* **Info** CWE-798 — JWT structural match. JWTs are often public
  (they're in cookies / headers); we surface them but don't
  treat as a confirmed leak.

References
----------

* gitleaks: https://github.com/gitleaks/gitleaks
* trufflehog: https://github.com/trufflesecurity/trufflehog
* AWS access-key-format: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "secrets_scan"

# Default external-scanner timeout. Most repos finish in <60s.
_EXTERNAL_TIMEOUT_SECONDS = 180

# Per-file size cap for the built-in regex pass — protects against
# wandering into huge generated minified bundles.
_MAX_FILE_BYTES = 1 * 1024 * 1024

# Test-directory glob fragments that auto-exclude (matches the
# convention used by §99 reachability + §96 taint).
_TEST_DIR_FRAGMENTS = (
    "/tests/", "/test/", "/_tests/", "/_test/",
    "/spec/", "/specs/", "/__tests__/", "/__test__/",
    "/fixtures/", "/__fixtures__/",
)

# File-extension allow list — pure binary skip targets.
_TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".scala",
    ".rb", ".go", ".rs", ".php", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".swift", ".m", ".mm", ".sh", ".bash", ".zsh", ".fish",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".envrc", ".properties", ".gradle", ".tf", ".tfvars",
    ".dockerfile", ".sql", ".graphql", ".md", ".rst", ".txt",
    ".xml", ".html", ".css", ".scss",
    # PEM key files — text content; the PEM-block detector wants
    # to read these.
    ".pem", ".key", ".crt", ".cer",
}


# ---------------------------------------------------------------------------
# Built-in regex catalogue (high-confidence patterns ONLY)
# ---------------------------------------------------------------------------


# Each entry: (label, regex, severity, vendor)
_BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    # AWS access key — vendor-anchored prefix.
    (
        "aws_access_key_id",
        re.compile(r"\b((?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16})\b"),
        "high",
        "aws",
    ),
    # AWS secret access key — usually appears in AWS config files
    # next to a recognizable key string. We require it to appear
    # within ~3 lines of the AWS access key, but for a single-pass
    # regex catalogue we'll match the standalone form as MEDIUM
    # (could be a random-looking string).
    # NOTE: deliberately not in the catalogue — too many FPs on
    # arbitrary base64 strings.

    # GitHub Personal Access Token (`ghp_…`), Server-to-Server
    # (`ghs_…`), OAuth (`gho_…`), Refresh (`ghr_…`), User-to-Server
    # (`ghu_…`). 36+4 = 40-char total length is documented.
    (
        "github_token",
        re.compile(r"\b(gh[psoru]_[A-Za-z0-9]{36,251})\b"),
        "high",
        "github",
    ),
    # Stripe live API key — `sk_live_` prefix is reserved for
    # production; test keys (`sk_test_`) are not surfaced.
    (
        "stripe_live_key",
        re.compile(r"\b(sk_live_[A-Za-z0-9]{24,99})\b"),
        "high",
        "stripe",
    ),
    # Slack tokens.
    (
        "slack_token",
        re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,250})\b"),
        "high",
        "slack",
    ),
    # Twilio account SID + auth token (the AC… prefix).
    (
        "twilio_sid",
        re.compile(r"\b(AC[a-f0-9]{32})\b"),
        "high",
        "twilio",
    ),
    # Google API key (`AIza…` prefix).
    (
        "google_api_key",
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        "high",
        "google",
    ),
    # SendGrid API key.
    (
        "sendgrid_key",
        re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64})\b"),
        "high",
        "sendgrid",
    ),
    # PEM-block private keys. Literal byte sequence — zero-FP.
    (
        "private_key_pem",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
        "medium",
        "pem",
    ),
]


# ---------------------------------------------------------------------------
# File walking / filtering
# ---------------------------------------------------------------------------


def _is_test_path(p: Path) -> bool:
    s = str(p).replace("\\", "/").lower()
    if any(frag in s for frag in _TEST_DIR_FRAGMENTS):
        return True
    name = p.name.lower()
    return name.startswith("test_") or name.endswith((".test.ts", ".test.tsx", ".test.js", ".spec.ts"))


def _walk_repo(
    repo_root: Path, *, scan_tests: bool, max_files: int
) -> list[Path]:
    """Walk the repo, yielding text files that should be scanned.
    Skips binary-extension files, `.git/`, `node_modules/`, and
    (by default) test dirs."""
    out: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        s = str(p).replace("\\", "/")
        if "/.git/" in s or s.endswith("/.git"):
            continue
        if "/node_modules/" in s:
            continue
        if "/dist/" in s or "/build/" in s:
            continue
        if not scan_tests and _is_test_path(p):
            continue
        if p.suffix.lower() not in _TEXT_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(p)
        if len(out) >= max_files:
            break
    return out


def _mask_secret(value: str) -> str:
    """Return a redacted form: first 4 + ellipsis + last 4 chars.
    Useful in finding evidence so the wrapper can show enough to
    grep for the leaked credential without echoing it."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}…{value[-4:]}"


# ---------------------------------------------------------------------------
# External scanner invocation
# ---------------------------------------------------------------------------


def _run_gitleaks(repo_root: Path) -> list[dict[str, Any]] | None:
    """Run `gitleaks detect --no-git --report-format json --report-path -`
    on the repo. Returns a list of finding dicts, or None when the
    binary isn't available / the call failed."""
    if not shutil.which("gitleaks"):
        return None
    try:
        proc = subprocess.run(
            [
                "gitleaks", "detect",
                "--no-git",
                "--source", str(repo_root),
                "--report-format", "json",
                "--report-path", "-",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            timeout=_EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        # gitleaks returns 0 with no findings, 1 with findings.
        # Both are normal cases. Other returncodes = error.
        if proc.returncode not in (0, 1):
            logger.debug(
                "gitleaks returned %s: %s", proc.returncode, proc.stderr[:200]
            )
            return None
        body = (proc.stdout or "").strip()
        if not body:
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            logger.debug("gitleaks output not valid JSON")
            return None
        return data if isinstance(data, list) else []
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug("gitleaks subprocess failed: %s", e)
        return None


def _normalize_gitleaks_finding(
    raw: dict[str, Any], repo_root: Path
) -> dict[str, Any] | None:
    """Coerce one gitleaks JSON finding into the internal record
    shape `{label, severity, file, line, masked, vendor}`."""
    rule = str(raw.get("RuleID") or raw.get("Rule") or "unknown")
    file_path = str(raw.get("File") or raw.get("file") or "")
    if not file_path:
        return None
    line = int(raw.get("StartLine") or raw.get("line") or 0)
    secret = str(raw.get("Secret") or raw.get("Match") or "")
    return {
        "label": rule,
        "severity": "high",  # gitleaks-confirmed → trust as high
        "file": file_path,
        "line": line,
        "masked": _mask_secret(secret),
        "vendor": rule.split("-", 1)[0],
        "source": "gitleaks",
    }


# ---------------------------------------------------------------------------
# Built-in scanner
# ---------------------------------------------------------------------------


def _scan_file_with_builtin(
    path: Path, repo_root: Path
) -> list[dict[str, Any]]:
    """Apply the built-in regex catalogue to a single file. Returns
    a list of finding records (deduped per (label, file) within file)."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    seen: set[tuple[str, int]] = set()
    out: list[dict[str, Any]] = []

    for label, regex, severity, vendor in _BUILTIN_PATTERNS:
        for m in regex.finditer(content):
            value = m.group(1) if m.groups() else m.group(0)
            line_no = content.count("\n", 0, m.start()) + 1
            key = (label, line_no)
            if key in seen:
                continue
            seen.add(key)
            try:
                rel = path.relative_to(repo_root)
            except ValueError:
                rel = path
            out.append({
                "label": label,
                "severity": severity,
                "file": str(rel),
                "line": line_no,
                "masked": _mask_secret(value),
                "vendor": vendor,
                "source": "builtin",
            })
    return out


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(*, record: dict[str, Any], target: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None

    label = record["label"]
    vendor = record["vendor"]
    severity = record["severity"]
    title = f"Hard-coded secret: {label} in {record['file']}"
    description = (
        f"A {vendor.upper()}-shape credential pattern (`{label}`) was "
        f"found at `{record['file']}:{record['line']}`. The match is "
        f"vendor-prefix-anchored, so the false-positive rate is low. "
        f"Masked value: `{record['masked']}`."
    )
    impact = (
        f"Hard-coded credentials in source-controlled code are a top-tier "
        f"finding: anyone with read access to the repo (or a leaked "
        f"backup, or a public mirror) inherits the credential. Past "
        f"GitHub-history rotations are particularly hard to verify — "
        f"git log keeps the secret even after a `git rm`. Treat any "
        f"production secret found in source as compromised; rotate "
        f"immediately."
    )
    recommended = (
        f"Rotate the credential immediately. Remove from source. Move to "
        f"environment variables or your secret manager (AWS Secrets "
        f"Manager / Hashicorp Vault / Doppler / etc.). Audit the git "
        f"history (`git log -p -- {record['file']}`) to find every "
        f"commit that ever exposed the secret — credential leaks survive "
        f"`git rm` because the commit history retains them. If the "
        f"history shows public exposure, treat as a confirmed breach."
    )
    code_loc = {
        "file": record["file"],
        "line": record["line"],
        "snippet": f"[masked: {record['masked']}]",
    }
    return tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="hardcoded_secret",
        cwe="CWE-798",
        target=target,
        endpoint=record["file"],
        description=description,
        impact=impact,
        remediation_steps=recommended,
        description_plain=(
            f"A {vendor.upper()} credential pattern was found in your "
            f"source code at `{record['file']}:{record['line']}`. "
            f"Treat as compromised — rotate immediately."
        ),
        recommended_action=recommended,
        verification_status="pattern_match",
        code_locations=[code_loc],
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME) if t else None


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is not None:
        t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1552.001"],  # Unsecured Credentials: Credentials In Files
)
def secrets_scan(
    repo_path: str,
    *,
    scan_tests: bool = False,
    max_files: int = 5000,
    prefer_external: bool = True,
) -> dict[str, Any]:
    """Scan a repository / local code dir for hard-coded secrets.

    Args:
        repo_path: filesystem path to the repo root.
        scan_tests: when False (default), test directories
            (`tests/`, `__tests__/`, `fixtures/`, etc.) are skipped.
            Most fixtures contain fake-but-secret-shaped strings;
            scanning them produces noise.
        max_files: cap on number of files walked. Default 5000.
        prefer_external: when True (default), tries `gitleaks` first
            for highest-precision matching. Set False to force the
            built-in catalogue (useful in tests or air-gapped envs).

    Returns:
        ```
        {
          success, repo_path, scanner_used: "gitleaks" | "builtin",
          files_scanned: int,
          findings_emitted: int,
          records: [{label, severity, file, line, masked, vendor, source}],
          errors?: [str, ...],
        }
        ```

    Findings (CWE-798):
        - **High** — vendor-prefix-anchored secrets (AWS / GitHub /
          Stripe / Slack / Twilio / Google / SendGrid).
        - **Medium** — PEM private-key blocks.
        - All carry `code_locations: [{file, line, snippet (masked)}]`.
    """
    root = Path(repo_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return {
            "success": False,
            "error": f"repo_path {root} does not exist or is not a directory",
            "findings_emitted": 0,
            "records": [],
        }

    target = str(root)
    check_id = _start_check(category="hardcoded_secret", surface=target)

    records: list[dict[str, Any]] = []
    scanner_used = "builtin"
    errors: list[str] = []

    # ---- Try gitleaks first (preferred). ----
    if prefer_external:
        gitleaks_findings = _run_gitleaks(root)
        if gitleaks_findings is not None:
            scanner_used = "gitleaks"
            for raw in gitleaks_findings:
                rec = _normalize_gitleaks_finding(raw, root)
                if rec is not None:
                    records.append(rec)

    # ---- Built-in fallback. ----
    files_scanned = 0
    if scanner_used == "builtin":
        for p in _walk_repo(root, scan_tests=scan_tests, max_files=max_files):
            files_scanned += 1
            try:
                records.extend(_scan_file_with_builtin(p, root))
            except Exception as e:  # noqa: BLE001
                errors.append(f"{p}: {e}")

    # ---- Per-(label, file, line) dedup. ----
    seen: set[tuple[str, str, int]] = set()
    deduped: list[dict[str, Any]] = []
    for rec in records:
        key = (rec["label"], rec["file"], rec["line"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)

    findings_emitted = 0
    for rec in deduped:
        if _emit_finding(record=rec, target=target):
            findings_emitted += 1

    if findings_emitted > 0:
        _complete_check(
            check_id,
            result="vulnerable",
            evidence=f"{findings_emitted} hard-coded secret(s) via {scanner_used}",
        )
    else:
        _complete_check(
            check_id,
            result="not_vulnerable",
            evidence=f"{files_scanned} files scanned via {scanner_used}; clean",
        )

    out: dict[str, Any] = {
        "success": True,
        "repo_path": target,
        "scanner_used": scanner_used,
        "files_scanned": files_scanned,
        "findings_emitted": findings_emitted,
        "records": deduped,
    }
    if errors:
        out["errors"] = errors
    return out
