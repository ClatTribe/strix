"""Tests for the refresh CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.tools.nuclei_runner.refresh import main as refresh_main
from strix.tools.nuclei_runner.refresh import status, templates_dir


def test_templates_dir_env_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_NUCLEI_TEMPLATES_DIR", str(tmp_path / "x"))
    assert templates_dir() == tmp_path / "x"


def test_status_no_dir(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(
        "STRIX_NUCLEI_TEMPLATES_DIR", str(tmp_path / "missing"),
    )
    s = status()
    assert s["exists"] is False
    assert s["is_git_repo"] is False


def test_status_existing_dir_with_yaml(monkeypatch, tmp_path) -> None:
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.yaml").write_text("id: x\n")
    (d / "b.yml").write_text("id: y\n")
    monkeypatch.setenv("STRIX_NUCLEI_TEMPLATES_DIR", str(d))
    s = status()
    assert s["exists"] is True
    assert s["template_count"] == 2


def test_main_status_prints_path(
    monkeypatch, tmp_path, capsys,
) -> None:
    monkeypatch.setenv("STRIX_NUCLEI_TEMPLATES_DIR", str(tmp_path))
    rc = refresh_main(["--status"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Path:" in out
