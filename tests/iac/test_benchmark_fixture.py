"""End-to-end test for the `iac-vibe/` benchmark fixture.

Pins every must-find finding from `expected.yaml` against the
output of `scan_iac_repo`. No threat-intel cache needed — IaC
scanning is offline pure-Python.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.iac.scanner import scan_iac_repo


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target" / "fixtures"
    / "code" / "iac-vibe"
)


def test_fixture_files_exist() -> None:
    assert FIXTURE.exists()
    assert (FIXTURE / "expected.yaml").exists()
    for f in ("vercel.json", "wrangler.toml", "Dockerfile",
              "docker-compose.yml"):
        assert (FIXTURE / "src" / f).exists(), f


def test_scan_finds_expected_rule_ids() -> None:
    """Pin the must-find rule IDs from the manifest's intent."""
    report = scan_iac_repo(FIXTURE / "src")
    rule_ids = {f.rule_id for f in report.findings}

    must_find = {
        # Vercel
        "vercel-cors-wildcard-with-credentials",
        "vercel-redirect-external-host",
        "vercel-cron-no-auth-marker",
        "vercel-env-hardcoded-secret",
        # Cloudflare
        "cloudflare-vars-hardcoded-secret",
        "cloudflare-r2-public-binding",
        "cloudflare-route-overly-broad",
        # Dockerfile
        "dockerfile-no-user-directive",
        "dockerfile-latest-tag",
        "dockerfile-env-hardcoded-secret",
        "dockerfile-add-from-url",
        # docker-compose
        "compose-privileged-container",
        "compose-docker-socket-mount",
        "compose-db-port-exposed",
        "compose-environment-hardcoded-secret",
    }
    missing = must_find - rule_ids
    assert not missing, f"missing rule hits: {missing}"


def test_scan_finds_all_4_platforms() -> None:
    report = scan_iac_repo(FIXTURE / "src")
    platforms = report.findings_by_platform
    assert "vercel" in platforms
    assert "cloudflare" in platforms
    assert "docker" in platforms
    assert "docker-compose" in platforms


def test_scan_critical_count_matches_planted_secrets() -> None:
    """Hardcoded-secret findings should all be critical: vercel
    env, wrangler vars, Dockerfile ENV, compose environment.
    That's 4 critical-tier findings minimum (more if other
    rules emit critical)."""
    report = scan_iac_repo(FIXTURE / "src")
    assert report.critical_count >= 4, (
        f"expected >= 4 critical findings (4 hardcoded secrets) "
        f"but got {report.critical_count}"
    )


def test_scan_emits_categories_for_cross_asset_routing() -> None:
    """Cross-asset routing depends on `category` to dispatch the
    matching DAST specialist. Pin the categories the fixture
    exercises."""
    report = scan_iac_repo(FIXTURE / "src")
    cats = {f.category for f in report.findings}
    # Misconfig (CORS), open_redirect, info_disclosure (secrets),
    # authz (cron auth) all expected.
    assert "misconfig" in cats
    assert "open_redirect" in cats
    assert "info_disclosure" in cats
    assert "authz" in cats
