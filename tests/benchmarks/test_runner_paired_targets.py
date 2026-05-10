"""Tests for the per-target benchmark runner's paired-target
plumbing (`benchmarks/per_target/runner.py::resolve_targets` +
`run_strix`).

Validates the §4a single-lead asset-aware planning + cross-asset
correlation work — specifically that the benchmark runner can pass
multiple `-t` flags to strix in a single invocation so the
LeadAgent unions catalogs across `web_application` + `local_code`.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest


# Add benchmark runner to path; it isn't packaged.
RUNNER_DIR = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target"
)
sys.path.insert(0, str(RUNNER_DIR))

from runner import resolve_targets, run_strix  # noqa: E402


FIXTURE_ROOT = RUNNER_DIR / "fixtures"


# ---------------------------------------------------------------------------
# resolve_targets — manifest → list[(type, target)] dispatch
# ---------------------------------------------------------------------------


def test_legacy_single_target_manifest_yields_one_tuple(tmp_path: Path) -> None:
    """Existing `target_type:` + `target:` shape — must keep working
    so flask-vuln / juiceshop / sca-vuln-deps fixtures don't regress."""
    manifest = {
        "target_type": "web_application",
        "target": "http://localhost:3000",
    }
    out = resolve_targets(tmp_path, manifest)
    assert out == [("web_application", "http://localhost:3000")]


def test_legacy_path_target_resolved_relative_to_fixture(tmp_path: Path) -> None:
    """Path-typed targets (local_code / repository) get resolved
    relative to the fixture dir when the relative path exists."""
    src = tmp_path / "src"
    src.mkdir()
    manifest = {"target_type": "local_code", "target": "src"}
    out = resolve_targets(tmp_path, manifest)
    assert out[0][0] == "local_code"
    assert out[0][1] == str(src.resolve())


def test_legacy_path_target_passes_through_when_no_local_match(
    tmp_path: Path,
) -> None:
    """A path target that doesn't resolve locally should pass through
    untouched (e.g. `git@github.com:user/repo.git` for a `repository`)."""
    manifest = {
        "target_type": "repository",
        "target": "git@github.com:user/repo.git",
    }
    out = resolve_targets(tmp_path, manifest)
    assert out[0] == ("repository", "git@github.com:user/repo.git")


def test_paired_manifest_with_additional_targets(tmp_path: Path) -> None:
    """The paired-asset shape: primary + `additional_targets[]`.
    This is what `web+code/vibe-app/` uses."""
    src = tmp_path / "src"
    src.mkdir()
    manifest = {
        "target_type": "web_application",
        "target": "http://localhost:3030",
        "additional_targets": [
            {"type": "local_code", "target": "src"},
        ],
    }
    out = resolve_targets(tmp_path, manifest)
    assert len(out) == 2
    assert out[0] == ("web_application", "http://localhost:3030")
    assert out[1][0] == "local_code"
    assert out[1][1] == str(src.resolve())


def test_paired_manifest_supports_three_targets(tmp_path: Path) -> None:
    """Three-asset case (e.g. URL + repo + IaC dir): all three
    should round-trip."""
    repo = tmp_path / "repo"
    repo.mkdir()
    iac = tmp_path / "iac"
    iac.mkdir()
    manifest = {
        "target_type": "web_application",
        "target": "https://app.example.com",
        "additional_targets": [
            {"type": "local_code", "target": "repo"},
            {"type": "local_code", "target": "iac"},
        ],
    }
    out = resolve_targets(tmp_path, manifest)
    assert len(out) == 3
    types = [tt for tt, _ in out]
    assert types == ["web_application", "local_code", "local_code"]


def test_all_list_manifest_shape(tmp_path: Path) -> None:
    """`targets:` list as the only shape (no primary) — reserved for
    fixtures that don't have an obvious primary asset."""
    src = tmp_path / "src"
    src.mkdir()
    manifest = {
        "targets": [
            {"type": "web_application", "target": "http://x"},
            {"type": "local_code", "target": "src"},
        ],
    }
    out = resolve_targets(tmp_path, manifest)
    assert len(out) == 2
    assert out[0][0] == "web_application"
    assert out[1][0] == "local_code"


def test_missing_target_raises_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing 'target'"):
        resolve_targets(tmp_path, {})


def test_additional_targets_skipped_when_invalid(tmp_path: Path) -> None:
    """Malformed `additional_targets` entries are silently skipped —
    the primary still wins. Defensive: shouldn't error the runner
    just because a manifest field is wrong."""
    manifest = {
        "target_type": "web_application",
        "target": "http://x",
        "additional_targets": [
            "not-a-dict",
            {"type": "", "target": "x"},   # missing type
            {"type": "local_code"},        # missing target
        ],
    }
    out = resolve_targets(tmp_path, manifest)
    assert out == [("web_application", "http://x")]


# ---------------------------------------------------------------------------
# run_strix — paired-target CLI invocation
# ---------------------------------------------------------------------------


def test_run_strix_string_target_passes_single_t_flag(
    tmp_path: Path, monkeypatch,
) -> None:
    """Legacy single-target call site passes a bare string — must
    still translate to a single `-t <target>` CLI arg."""
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        captured["cmd"] = cmd

        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("runner.subprocess.run", fake_run)
    rc, _dur = run_strix("http://localhost:3000", "standard", tmp_path, [])
    assert rc == 0
    assert captured["cmd"][0] == "strix"
    # Exactly one `-t` flag for a string target.
    assert captured["cmd"].count("-t") == 1
    assert "http://localhost:3000" in captured["cmd"]


def test_run_strix_paired_targets_pass_repeated_t_flags(
    tmp_path: Path, monkeypatch,
) -> None:
    """The whole point of this PR: paired targets → repeated `-t` flags."""
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        captured["cmd"] = cmd

        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("runner.subprocess.run", fake_run)
    rc, _dur = run_strix(
        [
            ("web_application", "http://localhost:3030"),
            ("local_code", "/tmp/some/src"),
        ],
        "standard", tmp_path, [],
    )
    assert rc == 0
    cmd = captured["cmd"]
    # Two `-t` flags, in order.
    assert cmd.count("-t") == 2
    # Each flag is followed by its value.
    t_positions = [i for i, a in enumerate(cmd) if a == "-t"]
    assert cmd[t_positions[0] + 1] == "http://localhost:3030"
    assert cmd[t_positions[1] + 1] == "/tmp/some/src"


def test_run_strix_passes_scan_mode_after_targets(
    tmp_path: Path, monkeypatch,
) -> None:
    """Sanity: scan mode arrives via `-m <mode>` like the legacy path."""
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        captured["cmd"] = cmd

        class R:
            returncode = 0
        return R()

    monkeypatch.setattr("runner.subprocess.run", fake_run)
    run_strix(
        [("web_application", "http://x"), ("local_code", "/y")],
        "deep", tmp_path, ["--instruction", "focus on auth"],
    )
    cmd = captured["cmd"]
    assert "-m" in cmd
    m_idx = cmd.index("-m")
    assert cmd[m_idx + 1] == "deep"
    # Custom strix-args appended.
    assert "--instruction" in cmd
    assert "focus on auth" in cmd


# ---------------------------------------------------------------------------
# vibe-app fixture wiring (the actual paired-asset benchmark)
# ---------------------------------------------------------------------------


VIBE_APP = FIXTURE_ROOT / "web+code" / "vibe-app"


def test_vibe_app_fixture_exists() -> None:
    """The paired-asset fixture is checked in."""
    assert VIBE_APP.exists()
    assert (VIBE_APP / "expected.yaml").exists()
    assert (VIBE_APP / "docker-compose.yml").exists()
    assert (VIBE_APP / "src" / "package-lock.json").exists()
    assert (VIBE_APP / "src" / "app.js").exists()


def test_vibe_app_manifest_resolves_to_two_targets() -> None:
    """The whole point: the manifest must produce both a
    web_application target AND a local_code target so strix sees
    both via `-t` flags."""
    import yaml
    manifest = yaml.safe_load((VIBE_APP / "expected.yaml").read_text())
    out = resolve_targets(VIBE_APP, manifest)
    assert len(out) == 2
    types = {tt for tt, _ in out}
    assert types == {"web_application", "local_code"}


def test_vibe_app_local_code_target_resolves_to_src_dir() -> None:
    import yaml
    manifest = yaml.safe_load((VIBE_APP / "expected.yaml").read_text())
    out = resolve_targets(VIBE_APP, manifest)
    local_code = [t for tt, t in out if tt == "local_code"]
    assert len(local_code) == 1
    assert local_code[0].endswith("/src")
    assert Path(local_code[0]).is_dir()


def test_vibe_app_expected_findings_split_sca_dast_secrets() -> None:
    """The manifest must cover all three categories so a regression
    in any one (SCA missed / DAST missed / SAST missed) fails the
    benchmark distinctly. The §4a routing work should make all
    three reachable in a single run."""
    import yaml
    manifest = yaml.safe_load((VIBE_APP / "expected.yaml").read_text())
    findings = manifest["expected_findings"]
    must_find = [f for f in findings if f.get("must_find")]
    cats = {f["category"] for f in must_find}
    assert "vulnerable_dependency" in cats   # SCA
    assert "info_disclosure" in cats          # secret-scan / SAST
    # DAST hits are tagged with the live-exploit class.
    dast_cats = cats - {"vulnerable_dependency", "info_disclosure"}
    assert dast_cats, (
        "no DAST findings in must_find — the cross-asset benchmark "
        "becomes a pure SCA fixture if DAST entries get filtered out"
    )


def test_vibe_app_cross_asset_findings_are_tagged() -> None:
    """`cross_asset: true` flag identifies entries that need BOTH
    sides to count. Used by the future scoring logic that wants to
    distinguish "SCA found the package" from "single-lead actually
    correlated SCA → DAST". For now we just pin that the flag is
    present so scoring can evolve."""
    import yaml
    manifest = yaml.safe_load((VIBE_APP / "expected.yaml").read_text())
    cross_asset = [
        f for f in manifest["expected_findings"]
        if f.get("cross_asset")
    ]
    # At least the lodash and ejs DAST entries should be tagged.
    assert len(cross_asset) >= 2
    cross_endpoints = {f.get("endpoint") for f in cross_asset}
    assert "/api/merge" in cross_endpoints
    assert "/api/render" in cross_endpoints


def test_vibe_app_lockfile_pins_known_vulnerable_versions() -> None:
    """Anti-rot test: if someone bumps the lockfile to a patched
    version, the benchmark stops measuring what it claims to. The
    versions here must stay vulnerable."""
    import strix.sca.parsers  # noqa: F401 — register parsers
    from strix.sca.parsers.base import parse_lockfile

    pkgs = parse_lockfile(VIBE_APP / "src" / "package-lock.json")
    by = {p.name: p.version for p in pkgs}
    # These versions are pinned because they're known-vulnerable.
    # If you bump them, you've broken the benchmark.
    assert by.get("lodash") == "4.17.20", by
    assert by.get("ejs") == "3.1.6", by
    assert by.get("express") == "4.16.0", by
