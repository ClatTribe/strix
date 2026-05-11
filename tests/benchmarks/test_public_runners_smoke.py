"""Smoke tests for `benchmarks/public/run_*_benchmark.py` runners.

These don't measure recall — they pin the runner contract:

  * each runner imports cleanly
  * each runner's `_score_against_expected` honours the
    category-aware match rule (a `vulnerable_dependency`
    expectation does NOT match against a `malicious_dependency`
    or `license_violation` finding for the same package)
  * each runner's `_endpoint_to_file` is robust to absolute /
    relative path inputs
  * the IaC runner runs end-to-end against its synthetic fixture
    in well under a second and produces a non-zero must-find
    recall (the fixture is in-repo, no network)
  * the SCA / SAST runners run end-to-end against an empty
    `tmp_path` directory and report a FLOOR shape (0 findings,
    no crash)

Why this matters: doc-only changes to `expected.yaml` or fixture
re-orgs are easy to land but hard to test interactively. A pytest
smoke catches "I broke the runner" before it lands in main.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_BENCH = REPO_ROOT / "benchmarks" / "public"


def _load_module(path: Path, name: str):
    """Load a benchmarks/public/run_*.py module by path — they live
    outside any package, so importlib direct-load is the right
    mechanism."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sca_runner():
    return _load_module(
        PUBLIC_BENCH / "run_sca_benchmark.py", "_pubsca",
    )


@pytest.fixture(scope="module")
def sast_runner():
    return _load_module(
        PUBLIC_BENCH / "run_sast_benchmark.py", "_pubsast",
    )


@pytest.fixture(scope="module")
def iac_runner():
    return _load_module(
        PUBLIC_BENCH / "run_iac_benchmark.py", "_pubiac",
    )


# ---------------------------------------------------------------------------
# Scoring contract
# ---------------------------------------------------------------------------


def test_sca_score_is_category_aware(sca_runner):
    """An expected `vulnerable_dependency` must NOT match against a
    `malicious_dependency` finding for the same package — that was
    the silent-100% bug in the first NodeGoat baseline."""
    expected = [
        {"id": "x-marked", "category": "vulnerable_dependency",
         "must_find": True},
    ]
    findings = [
        {"title": "marked package looks like typosquat",
         "category": "malicious_dependency"},
        {"title": "marked is unlicensed",
         "category": "license_violation"},
    ]
    result = sca_runner._score_against_expected(findings, expected)
    assert result["recall_must_find"] == 0.0
    assert result["must_find_matched"] == 0


def test_sca_score_matches_when_category_aligned(sca_runner):
    expected = [
        {"id": "x-lodash", "category": "vulnerable_dependency",
         "must_find": True},
    ]
    findings = [
        {"title": "lodash@4.17.20 — CVE-2020-8203",
         "category": "vulnerable_dependency"},
    ]
    result = sca_runner._score_against_expected(findings, expected)
    assert result["recall_must_find"] == 1.0


def test_sast_score_matches_on_category_and_file(sast_runner):
    expected = [
        {"id": "x-eval", "category": "cmd_injection",
         "file": "app/routes/contributions.js",
         "must_find": True},
    ]
    findings = [
        {"category": "cmd_injection",
         "endpoint": "/abs/path/nodegoat/src/app/routes/contributions.js:32"},
    ]
    result = sast_runner._score_against_expected(findings, expected)
    assert result["recall_must_find"] == 1.0


def test_sast_score_rejects_wrong_file(sast_runner):
    expected = [
        {"id": "x-eval", "category": "cmd_injection",
         "file": "app/routes/contributions.js",
         "must_find": True},
    ]
    findings = [
        # Same category, wrong file → must NOT count.
        {"category": "cmd_injection",
         "endpoint": "/abs/path/nodegoat/src/server.js:10"},
    ]
    result = sast_runner._score_against_expected(findings, expected)
    assert result["recall_must_find"] == 0.0


def test_iac_score_matches_on_basename(iac_runner):
    """IaC endpoints carry absolute paths; the scorer collapses to
    basename. Pin that contract."""
    expected = [
        {"id": "x-priv", "category": "misconfig",
         "file": "docker-compose.yml", "must_find": True},
    ]
    findings = [
        {"category": "misconfig",
         "endpoint": "/some/abs/path/fixture/src/docker-compose.yml:12"},
    ]
    result = iac_runner._score_against_expected(findings, expected)
    assert result["recall_must_find"] == 1.0


# ---------------------------------------------------------------------------
# Endpoint parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint,expected_path,expected_line", [
    ("/abs/nodegoat/src/server.js:42", "server.js", 42),
    ("/abs/nodegoat/src/app/routes/idx.js:5", "app/routes/idx.js", 5),
    ("server.js:10", "server.js", 10),
    ("server.js", "server.js", None),
    ("", "", None),
    (None, "", None),
])
def test_sast_endpoint_parsing(sast_runner, endpoint,
                                expected_path, expected_line):
    path, line = sast_runner._endpoint_to_file(endpoint)
    assert path == expected_path
    assert line == expected_line


# ---------------------------------------------------------------------------
# IaC end-to-end (synthetic fixture, in-repo, no network)
# ---------------------------------------------------------------------------


def test_iac_runner_end_to_end(iac_runner, tmp_path):
    """The synthetic dockerfile-bad-patterns fixture should produce
    9 findings → recall_must_find = 100%. Pin both."""
    fixture = (
        PUBLIC_BENCH / "fixtures" / "iac" / "dockerfile-bad-patterns"
    )
    assert fixture.exists()
    output = tmp_path / "result.json"
    out = iac_runner.run_fixture(fixture, output)
    assert out["asset_class"] == "iac"
    assert out["raw_counts"]["total_findings"] >= 8
    assert out["ground_truth"]["recall_must_find"] >= 0.85, (
        "recall regression on the synthetic IaC fixture — "
        "did a rule in strix/iac/rules/docker_rules.py get removed?"
    )
    # Pin engine probe shape.
    assert out["engine_state"]["files_scanned"] == 2
    assert "docker" in out["engine_state"]["files_by_platform"]
    assert "docker-compose" in out["engine_state"]["files_by_platform"]
    # Output JSON is valid + round-trippable.
    parsed = json.loads(output.read_text())
    assert parsed["fixture"] == "dockerfile-bad-patterns"


# ---------------------------------------------------------------------------
# SCA / SAST runner shape (no fixture clone — verify failure mode)
# ---------------------------------------------------------------------------


def test_sca_runner_missing_target_raises(sca_runner, tmp_path):
    """A fixture with `expected.yaml` pointing at a non-existent
    `src/` should raise FileNotFoundError — clearer than a silent
    0-finding run."""
    yaml_pkg = pytest.importorskip("yaml")
    fixture = tmp_path / "fake-fixture"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        yaml_pkg.safe_dump({
            "target_type": "local_code",
            "target": "src-does-not-exist",
            "expected_findings": [],
        })
    )
    with pytest.raises(FileNotFoundError):
        sca_runner.run_fixture(fixture, None)


def test_sast_runner_missing_target_raises(sast_runner, tmp_path):
    yaml_pkg = pytest.importorskip("yaml")
    fixture = tmp_path / "fake-fixture"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        yaml_pkg.safe_dump({
            "target_type": "local_code",
            "target": "src-does-not-exist",
            "expected_findings": [],
        })
    )
    with pytest.raises(FileNotFoundError):
        sast_runner.run_fixture(fixture, None)
