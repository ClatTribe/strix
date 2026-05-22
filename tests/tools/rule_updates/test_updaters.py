"""Tests for iter-24.1 updater tools (gitleaks / wappalyzer / hadolint)."""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIX_RULES_CACHE_DIR", str(tmp_path / "rules"))
    # Reload _common so the env var takes effect.
    from strix.tools.rule_updates import _common
    importlib.reload(_common)
    yield tmp_path / "rules"


def _mock_resp(body: bytes, etag: str = "W/\"x\""):
    resp = MagicMock()
    resp.read.return_value = body
    resp.headers.get = lambda k, default=None: (
        etag if k.lower() == "etag" else default
    )
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_update_gitleaks_rules_updated(monkeypatch):
    import urllib.request
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: _mock_resp(b"# gitleaks v8.18 rules"),
    )
    from strix.tools.rule_updates import update_gitleaks_rules
    out = update_gitleaks_rules()
    assert out["status"] == "updated"
    assert out["path"].endswith("gitleaks.toml")
    assert out["size_bytes"] > 0


def test_update_wappalyzer_signatures_updated(monkeypatch):
    import urllib.request
    body = b'{"Apache": {"cats": [22]}, "nginx": {"cats": [22]}}'
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: _mock_resp(body),
    )
    from strix.tools.rule_updates import update_wappalyzer_signatures
    out = update_wappalyzer_signatures()
    assert out["status"] == "updated"
    assert out["path"].endswith("wappalyzer-technologies.json")


def test_update_hadolint_config_updated(monkeypatch):
    import urllib.request
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: _mock_resp(
            b"---\nignored: [DL3008]\nfailure-threshold: warning\n",
        ),
    )
    from strix.tools.rule_updates import update_hadolint_config
    out = update_hadolint_config()
    assert out["status"] == "updated"
    assert out["path"].endswith("hadolint.yaml")


def test_updaters_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("update_gitleaks_rules"))
    assert callable(get_tool_by_name("update_wappalyzer_signatures"))
    assert callable(get_tool_by_name("update_hadolint_config"))


def test_network_fail_is_partial_not_error(monkeypatch):
    """Network failure must NOT raise — recall-safe per §5.1."""
    import urllib.error
    import urllib.request

    def _raise(*a, **k):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(urllib.request, "urlopen", _raise)
    from strix.tools.rule_updates import update_gitleaks_rules
    out = update_gitleaks_rules(force=True)
    assert out["status"] == "partial"
    # Original file (if any) untouched — but there's no original here,
    # so just confirm we didn't crash.
    assert out["success"] is True


def test_secrets_scan_picks_up_cached_config(tmp_path, monkeypatch):
    """If cache file exists, secrets_scan gitleaks subprocess argv gets
    ``--config <cached_path>`` injected."""
    # Pre-populate cached gitleaks.toml
    from strix.tools.rule_updates import cached_path
    cfg = cached_path("gitleaks.toml")
    cfg.write_text("# fake gitleaks rules")

    # Stub shutil.which to "find" gitleaks (else _run_gitleaks bails
    # before issuing the subprocess call).
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/gitleaks" if b == "gitleaks" else None,
    )

    # Stub subprocess.run to capture argv
    import subprocess
    captured = {}

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = "[]"
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)

    # Call the internal gitleaks runner directly.
    # NOTE: the symbol `strix.tools.secrets_scan.secrets_scan` resolves
    # to the @register_tool-decorated function (re-exported via __init__);
    # the module is at strix.tools.secrets_scan.secrets_scan but Python
    # binds the function first. Import the module by sys.modules lookup.
    import sys
    import strix.tools.secrets_scan.secrets_scan  # noqa: F401
    ss_mod = sys.modules["strix.tools.secrets_scan.secrets_scan"]
    ss_mod._run_gitleaks(tmp_path, scan_git_history=False)
    cmd = captured.get("cmd")
    assert cmd is not None
    assert "--config" in cmd
    assert str(cfg) in cmd


def test_hadolint_picks_up_cached_config(tmp_path, monkeypatch):
    """If cache file exists, scan_dockerfile_hadolint adds ``--config``."""
    from strix.tools.rule_updates import cached_path
    cfg = cached_path("hadolint.yaml")
    cfg.write_text("---\nignored: []")

    # Create a fake Dockerfile
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3\n")

    # Stub shutil.which to "find" hadolint
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/hadolint" if b == "hadolint" else None,
    )

    captured = {}
    import subprocess

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = "[]"
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)
    from strix.tools.hadolint_runner.scan_dockerfile_hadolint import (
        scan_dockerfile_hadolint,
    )
    scan_dockerfile_hadolint(str(df))
    cmd = captured.get("cmd")
    assert cmd is not None
    assert "--config" in cmd
    assert str(cfg) in cmd
