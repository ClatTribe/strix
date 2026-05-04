"""Tests for secrets_scan (roadmap §8.1 — secret-detection first-pass).

Hermetic — no shell-out to gitleaks (we force `prefer_external=False`).
External-scanner integration is exercised by a separate test that
monkeypatches `_run_gitleaks`.

Coverage:

  * Each high-confidence pattern in the catalogue
  * Vendor-prefix anchoring (no FP on lookalike strings)
  * PEM private-key block detection
  * Test directories excluded by default; --scan_tests overrides
  * .git / node_modules / dist / build dirs always skipped
  * Binary-extension files skipped
  * Per-(label, file, line) dedup
  * Masked snippet in code_locations
  * gitleaks JSON output normalization
  * gitleaks-not-installed → falls back to builtin
  * Schema + MITRE
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.secrets_scan.secrets_scan  # noqa: F401

ss_module = sys.modules["strix.tools.secrets_scan.secrets_scan"]
secrets_scan = ss_module.secrets_scan


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("secrets-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a fake repo at tmp_path/repo with the given files."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return repo


# ---------------------------------------------------------------------------
# Vendor-prefix-anchored patterns
# ---------------------------------------------------------------------------


def test_aws_access_key_emits_high(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)

    assert out["success"] is True
    assert out["scanner_used"] == "builtin"
    assert out["findings_emitted"] == 1

    findings = _findings()
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-798"
    assert f["category"] == "hardcoded_secret"
    assert "config.py" in f["title"]
    # Masked snippet — only first 4 + last 4 chars.
    assert f["code_locations"][0]["snippet"].startswith("[masked: AKIA")


def test_github_token_emits_high(tmp_path) -> None:
    fake = "ghp_" + "a" * 36  # 40-char total
    repo = _make_repo(tmp_path, {
        "deploy.sh": f'export GITHUB_TOKEN="{fake}"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)

    assert out["findings_emitted"] == 1
    findings = _findings()
    assert findings[0]["severity"] == "high"
    assert "github" in findings[0]["title"].lower()


def test_stripe_live_key_emits_high(tmp_path) -> None:
    # Stripe regex requires 24+ chars after the prefix. Construct
    # the test fixture at runtime so the literal doesn't appear in
    # git history (GitHub's push-protection scans for vendor-shape
    # strings even in test fixtures).
    prefix = "sk_" + "live_"
    fake = prefix + "abcdefghijk1234567890zZAB"  # 25 chars
    repo = _make_repo(tmp_path, {
        "billing.py": f'stripe.api_key = "{fake}"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 1
    assert _findings()[0]["severity"] == "high"


def test_stripe_test_key_NOT_emitted(tmp_path) -> None:
    """`sk_test_` keys are not surfaced (test keys, not production)."""
    prefix = "sk_" + "test_"
    fake = prefix + "abcdefghijk1234567890zZAB"
    repo = _make_repo(tmp_path, {
        "billing.py": f'stripe.api_key = "{fake}"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0


def test_slack_token_emits_high(tmp_path) -> None:
    fake = "xoxb-" + "1" * 12 + "-" + "abcd" * 8
    repo = _make_repo(tmp_path, {
        "bot.js": f'const token = "{fake}";\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 1


def test_google_api_key_emits_high(tmp_path) -> None:
    fake = "AIza" + "abcdefghij" * 3 + "ABCDE"  # 4 + 35 = 39 chars
    repo = _make_repo(tmp_path, {
        "maps.js": f'const apiKey = "{fake}";\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 1


def test_pem_private_key_emits_medium(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "secrets/key.pem": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEogIBAAKCAQEA1234567890fakecontent\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
    })

    out = secrets_scan(str(repo), prefer_external=False)
    findings = _findings()
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Negative cases — vendor-prefix discipline prevents FPs
# ---------------------------------------------------------------------------


def test_random_string_no_aws_match(tmp_path) -> None:
    """Random 16+ char base32 strings without AKIA prefix → no match."""
    repo = _make_repo(tmp_path, {
        "data.py": 'token = "ABCDEFGHIJKLMNOPQRSTUVWX"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0


def test_git_hash_not_flagged(tmp_path) -> None:
    """A git hash looks like hex but doesn't match any vendor prefix."""
    repo = _make_repo(tmp_path, {
        "history.md": "Commit: 1a2b3c4d5e6f7890abcdef1234567890abcdef12\n",
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0


def test_random_uuid_not_flagged(tmp_path) -> None:
    """UUID v4 looks distinctive but doesn't match any vendor prefix."""
    repo = _make_repo(tmp_path, {
        "ids.py": 'uid = "550e8400-e29b-41d4-a716-446655440000"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Test-directory exclusion
# ---------------------------------------------------------------------------


def test_secret_in_test_dir_excluded_by_default(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "tests/fixtures.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0
    assert out["files_scanned"] == 0  # the only file was a test file


def test_secret_in_fixtures_dir_excluded(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "fixtures/keys.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })
    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0


def test_secret_in_test_dir_emitted_with_scan_tests(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "tests/fixtures.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False, scan_tests=True)
    assert out["findings_emitted"] == 1


# ---------------------------------------------------------------------------
# Always-skipped dirs
# ---------------------------------------------------------------------------


def test_git_dir_skipped(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        ".git/config": '[user]\n  email = "AKIAIOSFODNN7EXAMPLE"\n',
    })
    out = secrets_scan(str(repo), prefer_external=False, scan_tests=True)
    assert out["findings_emitted"] == 0


def test_node_modules_skipped(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "node_modules/some-lib/lib.js": 'const k = "AKIAIOSFODNN7EXAMPLE";\n',
    })
    out = secrets_scan(str(repo), prefer_external=False, scan_tests=True)
    assert out["findings_emitted"] == 0


def test_dist_dir_skipped(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "dist/bundle.js": 'const k = "AKIAIOSFODNN7EXAMPLE";\n',
    })
    out = secrets_scan(str(repo), prefer_external=False, scan_tests=True)
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# File-extension allow list
# ---------------------------------------------------------------------------


def test_binary_extension_skipped(tmp_path) -> None:
    """A file with .bin / .png / .jpg extension is skipped (text
    secrets in a JPEG would never be loaded as text anyway)."""
    repo = _make_repo(tmp_path, {
        "image.png": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })
    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Dedup + multi-secret behaviour
# ---------------------------------------------------------------------------


def test_multiple_secrets_in_one_file(tmp_path) -> None:
    # Build the Stripe-shape fixture at runtime; see comment in
    # test_stripe_live_key_emits_high about push-protection.
    stripe_fake = "sk_" + "live_" + "abcdefghijk1234567890zZAB"
    repo = _make_repo(tmp_path, {
        "config.py": (
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            f'STRIPE = "{stripe_fake}"\n'
        ),
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 2
    assert out["files_scanned"] == 1


def test_same_secret_same_line_dedup(tmp_path) -> None:
    """The same secret appearing twice on the same line should
    emit ONE finding (per-(label, file, line) dedup)."""
    repo = _make_repo(tmp_path, {
        "x.py": 'k1 = "AKIAIOSFODNN7EXAMPLE"; k2 = "AKIAIOSFODNN7EXAMPLE"\n',
    })

    out = secrets_scan(str(repo), prefer_external=False)
    # The dedup is per-(label, file, line) — both matches are on
    # line 1 with the same label, so they collapse to one finding.
    assert out["findings_emitted"] == 1


def test_same_pattern_different_lines_each_finding(tmp_path) -> None:
    """Same vendor prefix on different lines → separate findings."""
    # AWS keys: `AKIA` + exactly 16 alphanumeric chars (UPPERCASE +
    # digits per spec). Use two distinct 16-char suffixes that
    # both terminate on a non-word boundary (the `\b` anchor).
    key1 = "AKIA" + "IOSFODNN7EXAMPLE"  # 20 chars
    key2 = "AKIA" + "ABCDEFGH123456ZX"  # 20 chars
    repo = _make_repo(tmp_path, {
        "x.py": (
            f'k1 = "{key1}"\n'
            f'k2 = "{key2}"\n'
        ),
    })

    out = secrets_scan(str(repo), prefer_external=False)
    assert out["findings_emitted"] == 2


# ---------------------------------------------------------------------------
# Code locations + masked
# ---------------------------------------------------------------------------


def test_code_location_carries_file_line_masked_snippet(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "lib/auth.py": (
            "# header comment\n"
            'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        ),
    })
    secrets_scan(str(repo), prefer_external=False)

    findings = _findings()
    f = findings[0]
    loc = f["code_locations"][0]
    assert "lib/auth.py" in loc["file"]
    assert loc["line"] == 2  # the API_KEY line
    # Masked: prefix + ellipsis + last 4 chars; never the full secret.
    assert "[masked:" in loc["snippet"]
    assert "AKIAIOSFODNN7EXAMPLE" not in loc["snippet"]
    assert loc["snippet"].endswith("MPLE]")  # last 4 chars of the example key


# ---------------------------------------------------------------------------
# gitleaks integration
# ---------------------------------------------------------------------------


def test_gitleaks_findings_normalised(monkeypatch, tmp_path) -> None:
    """When gitleaks is "available" (mocked), its JSON output is
    parsed and normalized into the internal record shape."""
    repo = _make_repo(tmp_path, {
        "src/cfg.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })

    fake_gitleaks_output = [
        {
            "RuleID": "aws-access-key",
            "File": "src/cfg.py",
            "StartLine": 1,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
        },
    ]
    monkeypatch.setattr(ss_module, "_run_gitleaks", lambda _root: fake_gitleaks_output)

    out = secrets_scan(str(repo), prefer_external=True)
    assert out["scanner_used"] == "gitleaks"
    assert out["findings_emitted"] == 1
    assert out["records"][0]["source"] == "gitleaks"
    findings = _findings()
    assert findings[0]["severity"] == "high"


def test_gitleaks_not_installed_falls_back(monkeypatch, tmp_path) -> None:
    """When _run_gitleaks returns None (binary not installed), the
    builtin scanner runs."""
    repo = _make_repo(tmp_path, {
        "src/cfg.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    })

    monkeypatch.setattr(ss_module, "_run_gitleaks", lambda _root: None)

    out = secrets_scan(str(repo), prefer_external=True)
    assert out["scanner_used"] == "builtin"
    assert out["findings_emitted"] == 1


# ---------------------------------------------------------------------------
# Schema + MITRE
# ---------------------------------------------------------------------------


def test_invalid_repo_path_returns_failure(tmp_path) -> None:
    out = secrets_scan(str(tmp_path / "does-not-exist"))
    assert out["success"] is False
    assert "error" in out


def test_repo_path_must_be_dir_not_file(tmp_path) -> None:
    f = tmp_path / "not-a-dir.txt"
    f.write_text("hi")
    out = secrets_scan(str(f))
    assert out["success"] is False


def test_result_schema(tmp_path) -> None:
    repo = _make_repo(tmp_path, {"empty.py": "# nothing here\n"})
    out = secrets_scan(str(repo), prefer_external=False)
    assert set(out.keys()) >= {
        "success", "repo_path", "scanner_used",
        "files_scanned", "findings_emitted", "records",
    }


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("secrets_scan")
    assert "T1552.001" in techniques


# ---------------------------------------------------------------------------
# Helper-function unit tests
# ---------------------------------------------------------------------------


def test_mask_secret_short() -> None:
    assert ss_module._mask_secret("abc") == "****"
    assert ss_module._mask_secret("12345678") == "****"


def test_mask_secret_long() -> None:
    masked = ss_module._mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in masked


def test_is_test_path_recognises_common_dirs() -> None:
    assert ss_module._is_test_path(Path("/repo/tests/foo.py")) is True
    assert ss_module._is_test_path(Path("/repo/__tests__/bar.ts")) is True
    assert ss_module._is_test_path(Path("/repo/spec/baz.rb")) is True
    assert ss_module._is_test_path(Path("/repo/fixtures/x.py")) is True
    assert ss_module._is_test_path(Path("/repo/test_foo.py")) is True
    assert ss_module._is_test_path(Path("/repo/foo.test.ts")) is True
    # Non-test paths.
    assert ss_module._is_test_path(Path("/repo/src/foo.py")) is False
    assert ss_module._is_test_path(Path("/repo/lib/auth.py")) is False
