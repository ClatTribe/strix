"""Tests for `run_prowler` — subprocess invocation logic via
dependency-injected `_subprocess_run`. No real `prowler` binary
needed; the fake captures argv + writes a canned OCSF file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.cspm import prowler as prowler_module
from strix.cspm.prowler import run_prowler


FIXTURE = (
    Path(__file__).parent / "fixtures" / "prowler_ocsf_sample.json"
)


def _fixture_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


class FakeCompletedProcess:
    def __init__(self, returncode: int = 3, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _make_fake_run(*, returncode: int, content_to_write: str | None,
                   capture: dict[str, Any]):
    """Build a fake `subprocess.run` that captures argv + writes a
    canned OCSF file at the path Prowler was told to use."""

    def _fake_run(argv, **kwargs):
        capture["argv"] = list(argv)
        capture["env"] = kwargs.get("env", {})
        # Find --output-directory + --output-filename in the argv
        # so we can drop the canned file where Prowler would.
        if content_to_write is not None and "--output-directory" in argv:
            i = argv.index("--output-directory") + 1
            j = argv.index("--output-filename") + 1
            out_dir = Path(argv[i])
            basename = argv[j]
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"{basename}.ocsf.json").write_text(content_to_write)
        return FakeCompletedProcess(returncode=returncode)

    return _fake_run


@pytest.fixture(autouse=True)
def _force_prowler_available(monkeypatch):
    """Pretend prowler is installed without actually shelling out."""
    monkeypatch.setattr(
        prowler_module, "is_prowler_available", lambda: True,
    )
    monkeypatch.setattr(
        prowler_module, "get_prowler_version", lambda: "4.5.0-test",
    )


def test_run_prowler_parses_canned_output(monkeypatch) -> None:
    capture: dict[str, Any] = {}
    result = run_prowler(
        provider="aws",
        _subprocess_run=_make_fake_run(
            returncode=3, content_to_write=_fixture_text(),
            capture=capture,
        ),
    )
    assert result.provider == "aws"
    assert len(result.findings) == 4   # 4 FAIL in fixture
    assert result.errors == []
    assert result.metadata.get("prowler_version") == "4.5.0-test"
    assert result.metadata.get("prowler_returncode") == 3


def test_run_prowler_returncode_zero_is_no_findings(monkeypatch) -> None:
    """Exit 0 means Prowler ran clean — empty findings list, not
    an error."""
    capture: dict[str, Any] = {}
    result = run_prowler(
        provider="aws",
        _subprocess_run=_make_fake_run(
            returncode=0, content_to_write="[]",
            capture=capture,
        ),
    )
    assert result.errors == []
    assert result.findings == []


def test_run_prowler_non_standard_returncode_is_error(monkeypatch) -> None:
    """Any exit code other than 0 / 3 is a real failure (auth,
    bad args, crash). Surface as an error."""
    capture: dict[str, Any] = {}
    result = run_prowler(
        provider="aws",
        _subprocess_run=_make_fake_run(
            returncode=1, content_to_write=None,
            capture=capture,
        ),
    )
    assert result.findings == []
    assert len(result.errors) == 1
    assert "non-zero exit" in result.errors[0]["error"]


def test_run_prowler_no_output_file_is_error(monkeypatch) -> None:
    """Prowler exited cleanly but wrote no OCSF file → fail loudly
    rather than silently returning []."""
    capture: dict[str, Any] = {}
    result = run_prowler(
        provider="aws",
        _subprocess_run=_make_fake_run(
            returncode=0, content_to_write=None,
            capture=capture,
        ),
    )
    assert result.findings == []
    assert any("no OCSF" in e["error"] for e in result.errors)


def test_run_prowler_when_not_available(monkeypatch) -> None:
    """When the binary isn't installed, return an error without
    attempting to spawn subprocess.run."""
    monkeypatch.setattr(
        prowler_module, "is_prowler_available", lambda: False,
    )

    def _should_not_be_called(*_args, **_kwargs):
        raise AssertionError("subprocess.run must not be called")

    result = run_prowler(
        provider="aws",
        _subprocess_run=_should_not_be_called,
    )
    assert result.findings == []
    assert any("not on PATH" in e["error"] for e in result.errors)


def test_run_prowler_passes_aws_auth_flags(monkeypatch) -> None:
    capture: dict[str, Any] = {}
    run_prowler(
        provider="aws",
        profile="prod",
        role_arn="arn:aws:iam::1:role/audit",
        regions=["us-east-1"],
        compliance=["cis_3.0_aws"],
        _subprocess_run=_make_fake_run(
            returncode=0, content_to_write="[]", capture=capture,
        ),
    )
    argv = capture["argv"]
    assert "--profile" in argv and "prod" in argv
    assert "--role" in argv and "arn:aws:iam::1:role/audit" in argv
    assert "--filter-region" in argv and "us-east-1" in argv
    assert "--compliance" in argv and "cis_3.0_aws" in argv


def test_run_prowler_env_overrides_propagate(monkeypatch) -> None:
    capture: dict[str, Any] = {}
    run_prowler(
        provider="azure",
        env_overrides={
            "AZURE_CLIENT_ID": "id-123",
            "AZURE_TENANT_ID": "tenant-456",
        },
        _subprocess_run=_make_fake_run(
            returncode=0, content_to_write="[]", capture=capture,
        ),
    )
    env = capture["env"]
    assert env.get("AZURE_CLIENT_ID") == "id-123"
    assert env.get("AZURE_TENANT_ID") == "tenant-456"
