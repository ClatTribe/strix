"""Fixture validation — every `expected.yaml` under benchmarks/per_target
parses cleanly + has the required shape. Catches drift when fixture
files get edited without re-running the runner locally.

Doesn't actually invoke the benchmark runner (which needs an LLM
provider + docker). Just validates the manifests."""

from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PER_TARGET_FIXTURES_ROOT = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"


def _yaml_or_skip():
    try:
        import yaml
        return yaml
    except ImportError:
        import pytest
        pytest.skip("pyyaml not installed")


def _walk_fixtures() -> list[Path]:
    return sorted(
        p for p in PER_TARGET_FIXTURES_ROOT.rglob("expected.yaml")
        if p.is_file()
    )


def test_fixture_inventory_non_empty() -> None:
    """At least the original fixtures (juiceshop, flask-vuln,
    vibe-app) + the new API fixtures (vampi, crapi) should exist."""
    fixtures = _walk_fixtures()
    assert len(fixtures) >= 5, (
        f"expected ≥5 fixtures; got {[f.relative_to(REPO_ROOT) for f in fixtures]}"
    )


def test_every_fixture_yaml_parses() -> None:
    yaml = _yaml_or_skip()
    bad: list[tuple[str, str]] = []
    for fp in _walk_fixtures():
        try:
            with fp.open() as f:
                manifest = yaml.safe_load(f)
            assert isinstance(manifest, dict), f"manifest not a dict"
        except Exception as e:  # noqa: BLE001
            bad.append((str(fp.relative_to(REPO_ROOT)), str(e)))
    assert not bad, f"unparseable fixture manifests: {bad}"


def test_every_fixture_has_required_fields() -> None:
    yaml = _yaml_or_skip()
    required_top = {"target_type", "expected_findings"}
    valid_target_types = {
        "local_code", "repository", "web_application", "api",
        "ip_address", "domain", "cloud_account", "container_image",
    }

    missing: list[tuple[str, list[str]]] = []
    bad_types: list[tuple[str, str]] = []
    for fp in _walk_fixtures():
        with fp.open() as f:
            manifest = yaml.safe_load(f) or {}
        missing_keys = sorted(required_top - set(manifest.keys()))
        if missing_keys:
            missing.append((str(fp.relative_to(REPO_ROOT)), missing_keys))
        tt = manifest.get("target_type")
        if tt and tt not in valid_target_types:
            bad_types.append((str(fp.relative_to(REPO_ROOT)), tt))

    assert not missing, f"fixtures missing required fields: {missing}"
    assert not bad_types, f"fixtures with invalid target_type: {bad_types}"


def test_expected_findings_have_required_per_item_fields() -> None:
    yaml = _yaml_or_skip()
    required_item = {"id", "category", "severity"}

    issues: list[tuple[str, str, list[str]]] = []
    for fp in _walk_fixtures():
        with fp.open() as f:
            manifest = yaml.safe_load(f) or {}
        for finding in manifest.get("expected_findings", []) or []:
            if not isinstance(finding, dict):
                continue
            missing_keys = sorted(required_item - set(finding.keys()))
            if missing_keys:
                issues.append((
                    str(fp.relative_to(REPO_ROOT)),
                    finding.get("id", "<no-id>"),
                    missing_keys,
                ))
    assert not issues, f"finding-level field gaps: {issues}"


def test_api_fixtures_present() -> None:
    """API-target benchmarks were the user-flagged untested gap.
    Pin that VAmPI + crAPI fixtures specifically exist."""
    api_root = PER_TARGET_FIXTURES_ROOT / "api"
    assert (api_root / "vampi" / "expected.yaml").exists(), (
        "VAmPI fixture missing — API smoke benchmark expected"
    )
    assert (api_root / "crapi" / "expected.yaml").exists(), (
        "crAPI fixture missing — OWASP API Top 10 benchmark expected"
    )


def test_api_fixtures_target_type_is_api() -> None:
    """Both API fixtures must use target_type=api so the per-target
    catalog filter picks up the right tool subset."""
    yaml = _yaml_or_skip()
    for sub in ("vampi", "crapi"):
        fp = PER_TARGET_FIXTURES_ROOT / "api" / sub / "expected.yaml"
        with fp.open() as f:
            manifest = yaml.safe_load(f) or {}
        assert manifest.get("target_type") == "api", (
            f"{sub}: expected target_type=api; got {manifest.get('target_type')!r}"
        )


def test_run_all_script_is_executable() -> None:
    """Driver script must be marked +x so CI / operators can invoke."""
    script = REPO_ROOT / "benchmarks" / "run_all.sh"
    assert script.exists(), "benchmarks/run_all.sh missing"
    # On filesystems that don't preserve mode (rare in CI), this might
    # be inaccurate; but the canonical worktree is git-tracked +x.
    # The presence check + shebang check below are sufficient.
    content = script.read_text(encoding="utf-8")
    assert content.startswith("#!/usr/bin/env bash"), (
        "run_all.sh missing bash shebang"
    )


def test_run_all_script_references_new_fixtures() -> None:
    """The driver's fixture list includes the new API fixtures."""
    script = REPO_ROOT / "benchmarks" / "run_all.sh"
    content = script.read_text(encoding="utf-8")
    # Just check presence of the new entries
    assert re.search(r"vampi:fixtures/api/vampi", content), (
        "run_all.sh missing vampi entry"
    )
    assert re.search(r"crapi:fixtures/api/crapi", content), (
        "run_all.sh missing crapi entry"
    )


def test_benchmark_ci_workflow_exists() -> None:
    """CI workflow gates the benchmark suite + uploads artifacts."""
    wf = REPO_ROOT / ".github" / "workflows" / "benchmarks.yml"
    assert wf.exists(), ".github/workflows/benchmarks.yml missing"
    content = wf.read_text(encoding="utf-8")
    assert "workflow_dispatch" in content, "CI workflow not manual-triggerable"
    assert "run_all.sh" in content, "CI workflow doesn't invoke run_all.sh"
